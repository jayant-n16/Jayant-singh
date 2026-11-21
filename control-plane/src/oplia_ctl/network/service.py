"""Global Accelerator traffic dial, Direct Connect, Consul and Linkerd status.

Traffic dial safety (checked when the proposal is made *and* again when it is executed):

* the proposal records the dial it was based on; execution refuses if the live dial differs
  (somebody else changed it - the approval was for a different step);
* an increase is limited to ``max_increase`` percentage points per step and must wait
  ``min_hold_minutes`` after the previous executed change of that group (runbook Phase 4);
* an increase is refused while any endpoint of the group is not HEALTHY;
* decreases (rollback) are never limited by step size, hold time or health;
* after UpdateEndpointGroup the dial is read back and must equal the requested value.

Every status section is read independently: one failing source is reported as that section's
error and never hides the others. No credential value is returned.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from oplia_ctl.http import ResilientClient
from oplia_ctl.network.models import TrafficDialChangeRow
from oplia_ctl.secrets import SecretProvider
from oplia_ctl.timeutil import iso_utc

GA_API_REGION = "us-west-2"   # the Global Accelerator API is served only from us-west-2
LINKERD_GROUP, LINKERD_VERSION = "multicluster.linkerd.io", "v1alpha3"   # Link CRD storage version


class NetworkSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPLIA_NETWORK_", extra="ignore")

    # key (cloud name) -> endpoint group ARN, from the aws-global-accelerator module output
    endpoint_groups: dict[str, str] = Field(default_factory=dict)
    max_increase: float = 25.0
    min_hold_minutes: int = 30
    dx_regions: list[str] = Field(default_factory=list)
    consul_addr: str = ""                       # e.g. https://consul-server.consul:8501
    consul_token_secret: str = ""               # secret name, never the token
    linkerd_links: bool = False                 # read Link resources with the in-cluster identity

    def enabled(self) -> bool:
        return bool(self.endpoint_groups or self.dx_regions or self.consul_addr or self.linkerd_links)


def _ga_client() -> Any:
    import boto3

    return boto3.client("globalaccelerator", region_name=GA_API_REGION)


def _dx_client(region: str) -> Any:
    import boto3

    return boto3.client("directconnect", region_name=region)


def _linkerd_links() -> list[dict[str, Any]]:  # pragma: no cover - needs a cluster
    from kubernetes import client, config

    try:
        config.load_incluster_config()  # type: ignore[no-untyped-call]
    except config.ConfigException:
        config.load_kube_config()  # type: ignore[no-untyped-call]
    resp = client.CustomObjectsApi().list_cluster_custom_object(LINKERD_GROUP, LINKERD_VERSION, "links")
    if not isinstance(resp, dict):
        raise TypeError(f"unexpected Link list response: {type(resp).__name__}")
    return list(resp.get("items", []))


def _group_view(key: str, eg: dict[str, Any]) -> dict[str, Any]:
    eps = [{"endpoint_id": e.get("EndpointId", ""), "weight": e.get("Weight"),
            "health": e.get("HealthState", "UNKNOWN"), "health_reason": e.get("HealthReason", ""),
            "client_ip_preservation": e.get("ClientIPPreservationEnabled")}
           for e in eg.get("EndpointDescriptions", [])]
    return {"key": key, "arn": eg.get("EndpointGroupArn", ""), "region": eg.get("EndpointGroupRegion", ""),
            "traffic_dial": float(eg.get("TrafficDialPercentage", 0.0)),
            "health_check": f"{eg.get('HealthCheckProtocol', '')}:{eg.get('HealthCheckPort', '')}"
                            f"{eg.get('HealthCheckPath', '') or ''}",
            "endpoints": eps, "all_healthy": bool(eps) and all(e["health"] == "HEALTHY" for e in eps)}


class NetworkService:
    def __init__(self, cfg: NetworkSettings, session_factory: sessionmaker[Session],
                 secrets: SecretProvider | None = None, client: ResilientClient | None = None,
                 ga_client: Callable[[], Any] = _ga_client, dx_client: Callable[[str], Any] = _dx_client,
                 linkerd_links: Callable[[], list[dict[str, Any]]] = _linkerd_links,
                 now: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self.cfg = cfg
        self._sf = session_factory
        self._secrets = secrets
        self._client = client
        self._ga = ga_client
        self._dx = dx_client
        self._links = linkerd_links
        self._now = now

    # ------------------------------------------------------------------ reads
    def arn(self, key: str) -> str:
        if key not in self.cfg.endpoint_groups:
            raise KeyError(key)
        return self.cfg.endpoint_groups[key]

    def endpoint_group(self, key: str) -> dict[str, Any]:
        eg = self._ga().describe_endpoint_group(EndpointGroupArn=self.arn(key))["EndpointGroup"]
        return _group_view(key, eg)

    def _section(self, fn: Callable[[], Any]) -> dict[str, Any]:
        t0 = time.monotonic()
        try:
            return {"ok": True, "items": fn(), "error": None, "latency_ms": round((time.monotonic() - t0) * 1000)}
        except Exception as exc:
            return {"ok": False, "items": [], "error": f"{type(exc).__name__}: {str(exc)[:300]}",
                    "latency_ms": round((time.monotonic() - t0) * 1000)}

    def _groups(self) -> list[dict[str, Any]]:
        out = []
        for key in sorted(self.cfg.endpoint_groups):
            try:
                out.append(self.endpoint_group(key))
            except Exception as exc:
                out.append({"key": key, "arn": self.cfg.endpoint_groups[key], "error":
                            f"{type(exc).__name__}: {str(exc)[:300]}", "endpoints": [], "all_healthy": False})
        return out

    def _direct_connect(self) -> list[dict[str, Any]]:
        out = []
        for region in self.cfg.dx_regions:
            dx = self._dx(region)
            vifs: dict[str, list[dict[str, Any]]] = {}
            for v in dx.describe_virtual_interfaces().get("virtualInterfaces", []):
                peers = v.get("bgpPeers", [])
                vifs.setdefault(v.get("connectionId", ""), []).append({
                    "id": v.get("virtualInterfaceId"), "name": v.get("virtualInterfaceName"),
                    "type": v.get("virtualInterfaceType"), "state": v.get("virtualInterfaceState"),
                    "vlan": v.get("vlan"),
                    "bgp": [p.get("bgpStatus", "unknown") for p in peers]})
            for c in dx.describe_connections().get("connections", []):
                out.append({"region": region, "id": c.get("connectionId"), "name": c.get("connectionName"),
                            "state": c.get("connectionState"), "partner": c.get("partnerName") or
                            c.get("providerName") or "", "bandwidth": c.get("bandwidth"),
                            "location": c.get("location"), "vlan": c.get("vlan"),
                            "virtual_interfaces": vifs.get(c.get("connectionId", ""), [])})
        return out

    def _consul(self) -> list[dict[str, Any]]:
        if self._client is None:
            raise RuntimeError("no HTTP client configured")
        headers = {}
        if self.cfg.consul_token_secret:
            if self._secrets is None:
                raise RuntimeError("consul_token_secret set but no secret provider")
            headers["X-Consul-Token"] = self._secrets.get(self.cfg.consul_token_secret)
        resp = self._client.request("GET", self.cfg.consul_addr.rstrip("/") + "/v1/peerings",
                                    expected={200}, headers=headers)
        out = []
        for p in resp.json() or []:
            st = p.get("StreamStatus") or {}
            out.append({"name": p.get("Name"), "state": p.get("State"),
                        "peer_server_name": p.get("PeerServerName", ""),
                        "imported_services": len(st.get("ImportedServices") or []),
                        "exported_services": len(st.get("ExportedServices") or []),
                        "last_heartbeat": st.get("LastHeartbeat")})
        return out

    def _linkerd(self) -> list[dict[str, Any]]:
        out = []
        for link in self._links():
            spec, status = link.get("spec", {}), link.get("status", {})
            mirrored = status.get("mirrorServices") or []
            not_ready = [m.get("remoteRef", {}).get("name", "?") for m in mirrored
                         if any(c.get("status") != "True" for c in m.get("conditions") or [])]
            out.append({"name": link.get("metadata", {}).get("name"),
                        "namespace": link.get("metadata", {}).get("namespace"),
                        "target_cluster": spec.get("targetClusterName"),
                        "gateway": f"{spec.get('gatewayAddress', '')}:{spec.get('gatewayPort', '')}",
                        "mirrored_services": len(mirrored), "not_ready": not_ready})
        return out

    def status(self) -> dict[str, Any]:
        off = {"ok": True, "items": [], "error": None, "latency_ms": 0, "configured": False}
        return {
            "global_accelerator": ({**self._section(self._groups), "configured": True}
                                   if self.cfg.endpoint_groups else off),
            "direct_connect": ({**self._section(self._direct_connect), "configured": True}
                               if self.cfg.dx_regions else off),
            "consul": ({**self._section(self._consul), "configured": True} if self.cfg.consul_addr else off),
            "linkerd": ({**self._section(self._linkerd), "configured": True} if self.cfg.linkerd_links else off),
            "dial_history": self.history(limit=50),
            "policy": {"max_increase": self.cfg.max_increase, "min_hold_minutes": self.cfg.min_hold_minutes},
        }

    def history(self, limit: int = 50, group: str | None = None) -> list[dict[str, Any]]:
        with self._sf() as s:
            q = select(TrafficDialChangeRow).order_by(TrafficDialChangeRow.executed_at.desc()).limit(limit)
            if group:
                q = q.where(TrafficDialChangeRow.group_key == group)
            return [{"group": r.group_key, "from": r.from_percent, "to": r.to_percent,
                     "executed_at": iso_utc(r.executed_at), "request_id": r.request_id}
                    for r in s.scalars(q)]

    # ---------------------------------------------------------------- policy
    def check_step(self, key: str, current: float, target: float, healthy: bool) -> None:
        """Raise ValueError when the change is not allowed now. Decreases are always allowed."""
        if not 0.0 <= target <= 100.0:
            raise ValueError("traffic dial must be between 0 and 100")
        if target == current:
            raise ValueError(f"traffic dial of {key} is already {current:g} %")
        if target < current:
            return
        if target - current > self.cfg.max_increase:
            raise ValueError(f"increase of {target - current:g} points exceeds the step limit of "
                             f"{self.cfg.max_increase:g} (OPLIA_NETWORK_MAX_INCREASE)")
        if not healthy:
            raise ValueError(f"not every endpoint of {key} is HEALTHY; increases are refused")
        last = self.history(limit=1, group=key)
        if last:
            at = datetime.fromisoformat(last[0]["executed_at"])
            if at.tzinfo is None:
                at = at.replace(tzinfo=UTC)
            wait = at + timedelta(minutes=self.cfg.min_hold_minutes) - self._now()
            if wait.total_seconds() > 0:
                raise ValueError(f"hold time: the previous change of {key} was executed at {at.isoformat()}; "
                                 f"next increase allowed in {int(wait.total_seconds() // 60) + 1} min")

    def record(self, key: str, arn: str, frm: float, to: float, request_id: str | None) -> None:
        with self._sf() as s, s.begin():
            s.add(TrafficDialChangeRow(id=str(uuid.uuid4()), group_key=key, endpoint_group_arn=arn,
                                       from_percent=frm, to_percent=to, executed_at=self._now(),
                                       request_id=request_id))


class TrafficDialExecutor:
    """Executes approved ``network.traffic_dial`` proposals through UpdateEndpointGroup."""

    def __init__(self, svc: NetworkService) -> None:
        self._svc = svc

    @staticmethod
    def _parse(payload: dict[str, Any]) -> tuple[str, float, float]:
        try:
            return str(payload["group"]), float(payload["from"]), float(payload["to"])
        except (KeyError, TypeError, ValueError):
            raise ValueError("payload needs group, from and to") from None

    def describe(self, payload: dict[str, Any]) -> str:
        key, frm, to = self._parse(payload)
        return (f"Set the Global Accelerator traffic dial of endpoint group '{key}' from {frm:g} % to {to:g} % "
                f"(UpdateEndpointGroup, then read back)")

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        key, frm, to = self._parse(payload)
        arn = self._svc.arn(key)
        if payload.get("arn") and payload["arn"] != arn:
            raise ValueError("endpoint group ARN changed since the proposal; re-propose")
        live = self._svc.endpoint_group(key)
        if abs(live["traffic_dial"] - frm) > 1e-9:
            raise RuntimeError(f"live dial of {key} is {live['traffic_dial']:g} %, the approval was for a change "
                               f"from {frm:g} %; re-propose")
        self._svc.check_step(key, frm, to, live["all_healthy"])
        ga = self._svc._ga()
        ga.update_endpoint_group(EndpointGroupArn=arn, TrafficDialPercentage=to)
        after = _group_view(key, ga.describe_endpoint_group(EndpointGroupArn=arn)["EndpointGroup"])
        if abs(after["traffic_dial"] - to) > 1e-9:
            raise RuntimeError(f"read-back dial of {key} is {after['traffic_dial']:g} %, expected {to:g} %")
        self._svc.record(key, arn, frm, to, payload.get("request_id"))
        return {"group": key, "arn": arn, "from": frm, "to": to, "verified": True,
                "endpoints": [{"endpoint_id": e["endpoint_id"], "health": e["health"]} for e in after["endpoints"]]}
