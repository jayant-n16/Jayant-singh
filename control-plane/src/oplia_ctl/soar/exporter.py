"""SOAR exporter daemon.

For every runtime threat event:

1. export it to the SIEM (failures go to the dead-letter file), and
2. if confidence is **above** the threshold (default 0.85) and the event names
   a resolvable resource, record an isolation proposal in the safety gate.

Isolation is never performed directly here: it runs only when the proposal is
approved and executed (or automatically, if an operator has deliberately
switched the gate to autonomous mode).

Run as a daemon that follows a Falco JSON-lines file::

    oplia-soar-exporter

Configuration via ``OPLIA_SOAR_*`` environment variables (see SOARSettings).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import signal
import threading
import time
from collections.abc import Callable, Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from oplia_ctl.safety import SafetyGate
from oplia_ctl.soar.events import parse_event
from oplia_ctl.soar.siem import SIEMSink

log = logging.getLogger("oplia.soar")


class SOARExporter:
    def __init__(
        self,
        *,
        gate: SafetyGate,
        sink: SIEMSink,
        threshold: float = 0.85,
        requested_by: str = "soar-exporter",
    ) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be between 0 and 1")
        self._gate = gate
        self._sink = sink
        self._threshold = threshold
        self._requested_by = requested_by

    def process(self, raw: dict[str, Any]) -> dict[str, Any]:
        ev = parse_event(raw)
        exported = self._sink.send({
            "event_id": ev.event_id,
            "rule": ev.rule,
            "priority": ev.priority,
            "confidence": ev.confidence,
            "time": ev.time,
            "target": ev.target.label if ev.target else None,
            "raw": ev.raw,
        })
        proposal_id: str | None = None
        if ev.confidence > self._threshold and ev.target is not None:
            key = "soar:" + hashlib.sha256(f"{ev.event_id}|{ev.target.label}".encode()).hexdigest()[:40]
            proposal = self._gate.propose(
                action_type=ev.target.action_type,
                target=ev.target.label,
                payload=dict(ev.target.params),
                reason=(f"Runtime threat '{ev.rule}' (priority {ev.priority}, confidence "
                        f"{ev.confidence:.2f} > {self._threshold:.2f}) at {ev.time}"),
                requested_by=self._requested_by,
                idempotency_key=key,
            )
            proposal_id = proposal.id
        return {"event_id": ev.event_id, "exported": exported, "confidence": ev.confidence,
                "proposal_id": proposal_id}


class FileFollower:
    """Follows a JSON-lines file across rotation/truncation, persisting its offset."""

    def __init__(self, path: str, state_path: str, poll_seconds: float = 1.0,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self._path = Path(path)
        self._state = Path(state_path)
        self._poll = poll_seconds
        self._sleep = sleep

    def _load_state(self) -> tuple[int, int]:
        try:
            data = json.loads(self._state.read_text())
            return int(data["inode"]), int(data["offset"])
        except (FileNotFoundError, ValueError, KeyError):
            return -1, 0

    def _save_state(self, inode: int, offset: int) -> None:
        tmp = self._state.with_suffix(".tmp")
        tmp.write_text(json.dumps({"inode": inode, "offset": offset}))
        os.replace(tmp, self._state)

    def lines(self, stop: threading.Event) -> Iterator[str]:
        saved_inode, saved_offset = self._load_state()
        fh = None
        buffer = ""
        while not stop.is_set():
            if fh is None:
                try:
                    fh = open(self._path, encoding="utf-8", errors="replace")
                except FileNotFoundError:
                    self._sleep(self._poll)
                    continue
                st = os.fstat(fh.fileno())
                if st.st_ino == saved_inode and saved_offset <= st.st_size:
                    fh.seek(saved_offset)
                buffer = ""
            chunk = fh.readline()
            if chunk:
                buffer += chunk
                if buffer.endswith("\n"):
                    line, buffer = buffer.rstrip("\n"), ""
                    yield line
                    saved_inode, saved_offset = os.fstat(fh.fileno()).st_ino, fh.tell()
                    self._save_state(saved_inode, saved_offset)
                continue
            # No new data: detect rotation (new inode) or truncation (file shrank).
            try:
                st_path = os.stat(self._path)
            except FileNotFoundError:
                st_path = None
            current = os.fstat(fh.fileno())
            if st_path is None or st_path.st_ino != current.st_ino or st_path.st_size < fh.tell():
                fh.close()
                fh = None
                saved_inode, saved_offset = -1, 0
                continue
            self._sleep(self._poll)
        if fh is not None:
            fh.close()


class SOARSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPLIA_SOAR_", extra="ignore")

    input_path: str = "/var/log/falco/events.json"
    state_path: str = "/var/lib/oplia/soar-offset.json"
    siem_endpoint: str = ""
    siem_format: Literal["splunk_hec", "generic"] = "generic"
    siem_token_secret: str = "siem_token"  # noqa: S105 - name of the secret, not its value
    dead_letter_path: str = "/var/lib/oplia/soar-dead-letter.jsonl"
    threshold: float = Field(default=0.85, ge=0.0, le=1.0)


def main() -> None:  # pragma: no cover - process wiring, exercised in deployment
    from oplia_ctl.config import get_settings
    from oplia_ctl.db import Base, make_engine, make_session_factory
    from oplia_ctl.http import ResilientClient
    from oplia_ctl.secrets import build_secret_provider

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    settings.assert_production_safe()
    soar = SOARSettings()
    if not soar.siem_endpoint:
        raise SystemExit("OPLIA_SOAR_SIEM_ENDPOINT is required")

    engine = make_engine(settings.database_url)
    if settings.environment == "dev":
        Base.metadata.create_all(engine)
    gate = SafetyGate(make_session_factory(engine), dry_run=settings.dry_run,
                      require_approval=settings.require_approval, four_eyes=settings.four_eyes,
                      proposal_ttl=timedelta(minutes=settings.proposal_ttl_minutes))
    client = ResilientClient(timeout=settings.http_timeout_seconds, max_retries=settings.http_max_retries)
    sink = SIEMSink(endpoint=soar.siem_endpoint, fmt=soar.siem_format, token_secret=soar.siem_token_secret,
                    secrets=build_secret_provider(settings.secret_provider), client=client,
                    dead_letter_path=soar.dead_letter_path)
    exporter = SOARExporter(gate=gate, sink=sink, threshold=soar.threshold)

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    log.info("following %s (threshold %.2f, dry_run=%s)", soar.input_path, soar.threshold, settings.dry_run)
    for line in FileFollower(soar.input_path, soar.state_path).lines(stop):
        if not line.strip():
            continue
        try:
            result = exporter.process(json.loads(line))
            log.info("event %s exported=%s proposal=%s", result["event_id"], result["exported"],
                     result["proposal_id"])
        except (ValueError, json.JSONDecodeError) as exc:
            log.warning("skipping malformed event: %s", exc)
    client.close()
