"""SIEM sinks with a dead-letter file so no event is silently lost.

Formats:

* ``splunk_hec`` - Splunk HTTP Event Collector (``Authorization: Splunk <token>``,
  body ``{"time", "sourcetype", "source", "event"}``).
* ``generic`` - any HTTPS JSON receiver (Sentinel/Logic App, Elastic ingest
  pipeline, QRadar HTTP receiver, ...) with ``Authorization: Bearer <token>``.
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import httpx

from oplia_ctl.http import HttpError, ResilientClient
from oplia_ctl.secrets import SecretProvider


class SIEMSink:
    def __init__(
        self,
        *,
        endpoint: str,
        fmt: Literal["splunk_hec", "generic"],
        token_secret: str,
        secrets: SecretProvider,
        client: ResilientClient,
        dead_letter_path: str,
        sourcetype: str = "oplia:runtime-threat",
    ) -> None:
        if not endpoint.startswith("https://"):
            raise ValueError("SIEM endpoint must use https")
        self._endpoint = endpoint
        self._fmt = fmt
        self._token_secret = token_secret
        self._secrets = secrets
        self._client = client
        self._dlq = Path(dead_letter_path)
        self._dlq_lock = threading.Lock()
        self._sourcetype = sourcetype

    def _body_and_headers(self, event: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
        token = self._secrets.get(self._token_secret)
        if self._fmt == "splunk_hec":
            return ({"time": time.time(), "sourcetype": self._sourcetype, "source": "oplia", "event": event},
                    {"Authorization": f"Splunk {token}"})
        return event, {"Authorization": f"Bearer {token}"}

    def send(self, event: dict[str, Any]) -> bool:
        """Deliver one event. Returns False (and dead-letters it) on failure."""
        try:
            body, headers = self._body_and_headers(event)
            self._client.request("POST", self._endpoint, json=body, headers=headers, expected={200, 201, 202, 204})
            return True
        except (HttpError, httpx.HTTPError, LookupError) as exc:
            self._dead_letter(event, f"{type(exc).__name__}: {str(exc)[:200]}")
            return False

    def _dead_letter(self, event: dict[str, Any], error: str) -> None:
        line = json.dumps({"failed_at": datetime.now(UTC).isoformat(), "error": error, "event": event},
                          default=str)
        with self._dlq_lock:
            self._dlq.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self._dlq, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
