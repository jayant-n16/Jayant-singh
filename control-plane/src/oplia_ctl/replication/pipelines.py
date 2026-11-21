"""CDC pipeline management through the Kafka Connect REST API (Debezium connectors).

Status is read-only. pause / resume / restart are gated ``dr.pipeline`` proposals; the executor
re-reads the connector afterwards and reports the state it actually reached.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from oplia_ctl.http import ResilientClient
from oplia_ctl.secrets import SecretProvider

ACTIONS = ("pause", "resume", "restart")


class KafkaConnect:
    def __init__(self, url: str, client: ResilientClient, secrets: SecretProvider | None = None,
                 auth_secret: str = "") -> None:  # nosec B107 - the NAME of a secret, not a value
        self._url = url.rstrip("/")
        self._client = client
        self._secrets = secrets
        self._auth_secret = auth_secret

    def _auth(self) -> dict[str, Any]:
        if not self._auth_secret:
            return {}
        if self._secrets is None:
            raise RuntimeError("auth secret configured but no secret provider")
        user, _, pw = self._secrets.get(self._auth_secret).partition(":")
        return {"auth": (user, pw)}

    def connectors(self) -> list[dict[str, Any]]:
        r = self._client.request("GET", f"{self._url}/connectors", params=[("expand", "status"), ("expand", "info")],
                                 expected={200}, **self._auth())
        out = []
        for name, c in sorted((r.json() or {}).items()):
            st, info = c.get("status", {}), c.get("info", {})
            tasks = st.get("tasks", [])
            cfg = info.get("config", {})
            out.append({"name": name, "type": info.get("type", st.get("type", "")),
                        "class": cfg.get("connector.class", ""),
                        "state": st.get("connector", {}).get("state", "UNKNOWN"),
                        "worker": st.get("connector", {}).get("worker_id", ""),
                        "tasks": [{"id": t.get("id"), "state": t.get("state"),
                                   "trace": (t.get("trace") or "")[:500]} for t in tasks],
                        "failed_tasks": sum(1 for t in tasks if t.get("state") == "FAILED")})
        return out

    def state(self, name: str) -> dict[str, Any]:
        r = self._client.request("GET", f"{self._url}/connectors/{quote(name, safe='')}/status",
                                 expected={200}, **self._auth())
        body: dict[str, Any] = r.json()
        return body

    def put_config(self, name: str, config: dict[str, str]) -> None:
        """Create the connector, or update its configuration (idempotent: PUT /connectors/{name}/config)."""
        self._client.request("PUT", f"{self._url}/connectors/{quote(name, safe='')}/config", json=config,
                             expected={200, 201}, **self._auth())

    def act(self, name: str, action: str) -> None:
        n = quote(name, safe="")
        if action == "pause":
            self._client.request("PUT", f"{self._url}/connectors/{n}/pause", expected={202}, **self._auth())
        elif action == "resume":
            self._client.request("PUT", f"{self._url}/connectors/{n}/resume", expected={202}, **self._auth())
        elif action == "restart":
            self._client.request("POST", f"{self._url}/connectors/{n}/restart",
                                 params={"includeTasks": "true", "onlyFailed": "true"},
                                 expected={200, 202, 204}, **self._auth())
        else:
            raise ValueError(f"action must be one of {ACTIONS}")


class PipelineExecutor:
    def __init__(self, kc: KafkaConnect) -> None:
        self._kc = kc

    def describe(self, payload: dict[str, Any]) -> str:
        if payload.get("action") not in ACTIONS:
            raise ValueError(f"action must be one of {ACTIONS}")
        return f"{payload['action']} Kafka Connect connector '{payload.get('connector')}'"

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.describe(payload)
        name = str(payload["connector"])
        self._kc.act(name, str(payload["action"]))
        st = self._kc.state(name)
        return {"connector": name, "action": payload["action"],
                "state_after": st.get("connector", {}).get("state"),
                "tasks_after": [t.get("state") for t in st.get("tasks", [])]}
