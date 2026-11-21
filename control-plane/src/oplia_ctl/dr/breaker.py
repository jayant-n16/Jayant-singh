"""The replication circuit breaker (the document's ``dr_replication_circuit_breaker``).

It sits between the source change stream and the DR destination; DR replicas consume only
the destination, so withholding a bundle guarantees it never reaches another cloud.

For every bundle: decode -> static rules -> rate rule. On a match it **trips**:

A. **Sever** - the bundle is not forwarded, the destination connection is closed and the relay
   stops consuming. The source position is *not* committed past the bundle, so nothing is lost:
   after review the held bundle is released (forwarded) or discarded.
B. **Alert** - the complete incident (findings + every record of the bundle, never truncated) is
   written to a quarantine file and POSTed to the configured incident webhooks (HMAC-signed);
   PagerDuty/Slack receive a critical summary with the dump's SHA-256.
C. **Lock** - every configured DR target is switched to read-only and verified (see ``lockers``).
   This changes remote databases, so it honours the safety gate's dry-run switch.

The state (OPEN/CLOSED) is persisted; a reset by an approver closes it again, optionally
unlocking the targets, and the relay resumes. Every step is written to the audit chain.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session, sessionmaker

from oplia_ctl.aiops.notify import Incident, IncidentNotifier
from oplia_ctl.db import session_scope
from oplia_ctl.dr.decode import Mutation, Record, decode, payload_for_dump
from oplia_ctl.dr.lockers import TargetLocker
from oplia_ctl.dr.models import BreakerStateRow, DrIncidentRow
from oplia_ctl.dr.rules import Finding, RateMonitor, static_findings
from oplia_ctl.http import HttpError, ResilientClient
from oplia_ctl.safety import SafetyGate
from oplia_ctl.secrets import SecretProvider

log = logging.getLogger("oplia.dr")

State = Literal["CLOSED", "OPEN"]


class WebhookSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url_secret: str = Field(min_length=1, max_length=128)    # the URL may embed a token
    hmac_secret: str = Field(min_length=1, max_length=128)


class Sink(Protocol):
    def send(self, records: list[Record]) -> None:
        """Forward and wait for acknowledgement (raise on failure)."""
        ...

    def close(self) -> None: ...


@dataclass
class InspectResult:
    mutations: list[Mutation]
    findings: list[Finding]


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return (dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)).isoformat()


class BreakerStore:
    def __init__(self, session_factory: sessionmaker[Session], clock: Callable[[], datetime]) -> None:
        self._sf = session_factory
        self._clock = clock

    def state(self, stream: str) -> tuple[State, str | None, str | None]:
        with session_scope(self._sf) as s:
            row = s.get(BreakerStateRow, stream)
            if row is None:
                return "CLOSED", None, None
            return row.state, row.incident_id, row.pending_decision  # type: ignore[return-value]

    def set(self, stream: str, state: State, actor: str, incident_id: str | None,
            decision: str | None = None) -> None:
        with session_scope(self._sf) as s:
            row = s.get(BreakerStateRow, stream)
            if row is None:
                row = BreakerStateRow(stream=stream)
                s.add(row)
            row.state, row.incident_id, row.changed_at, row.changed_by = state, incident_id, self._clock(), actor
            row.pending_decision = decision

    def consume_decision(self, stream: str) -> str | None:
        with session_scope(self._sf) as s:
            row = s.get(BreakerStateRow, stream)
            if row is None or row.pending_decision is None:
                return None
            decision, row.pending_decision = row.pending_decision, None
            return decision


class CircuitBreaker:
    def __init__(
        self,
        *,
        stream: str,
        gate: SafetyGate,
        session_factory: sessionmaker[Session],
        secrets: SecretProvider,
        client: ResilientClient,
        lockers: list[TargetLocker],
        webhooks: list[WebhookSpec],
        notifier: IncidentNotifier | None,
        quarantine_dir: str,
        rate: RateMonitor | None = None,
        block_undecodable: bool = True,
        lock_timeout_seconds: float = 60.0,
        protector: Any = None,     # TransitProtector: encrypt + HMAC incident dumps with Vault Transit
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not stream or len(stream) > 64:
            raise ValueError("stream name must be 1..64 characters")
        self.stream = stream
        self._gate = gate
        self._store = BreakerStore(session_factory, clock)
        self._sf = session_factory
        self._secrets = secrets
        self._http = client
        self._lockers = lockers
        self._webhooks = webhooks
        self._notifier = notifier
        self._qdir = Path(quarantine_dir)
        self._rate = rate or RateMonitor()
        self._block_undecodable = block_undecodable
        self._lock_timeout = lock_timeout_seconds
        self._protector = protector
        self._clock = clock

    @property
    def store(self) -> BreakerStore:
        return self._store

    @property
    def session_factory(self) -> sessionmaker[Session]:
        return self._sf

    def new_rate_monitor(self, monitor: RateMonitor) -> None:
        self._rate = monitor

    def inspect(self, bundle: list[Record]) -> InspectResult:
        mutations = [m for r in bundle for m in decode(r)]
        findings = static_findings(mutations, block_undecodable=self._block_undecodable)
        spike = self._rate.observe(mutations)
        if spike is not None:
            findings.append(spike)
        return InspectResult(mutations, findings)

    # ------------------------------------------------------------------------ trip
    def trip(self, bundle: list[Record], findings: list[Finding], sink: Sink | None,
             actor: str = "dr-breaker") -> str:
        """A + B + C. Returns the incident id. Never raises because one action failed."""
        started = time.monotonic()
        incident_id = str(uuid.uuid4())
        trigger = findings[0].rule if findings else "manual"
        actions: dict[str, Any] = {}

        # A. sever first: nothing else may delay it
        try:
            if sink is not None:
                sink.close()
            actions["sever"] = {"ok": True, "detail": "bundle withheld; destination connection closed"}
        except Exception as exc:  # the bundle is still withheld even if closing failed
            actions["sever"] = {"ok": False, "detail": f"bundle withheld; close failed: {type(exc).__name__}: {exc}"}
        self._store.set(self.stream, "OPEN", actor, incident_id)
        actions["sever"]["seconds"] = round(time.monotonic() - started, 3)

        # B. full dump: file first (durable), then webhooks and chat/paging
        dump = {
            "incident_id": incident_id, "stream": self.stream, "opened_at": self._clock().isoformat(),
            "trigger": trigger, "findings": [_finding_json(f) for f in findings],
            "records": [{"format": r.format, "engine": r.engine, "position": r.position,
                         "payload": payload_for_dump(r)} for r in bundle],
        }
        plain = json.dumps(dump, sort_keys=True, default=str).encode()
        digest = hashlib.sha256(plain).hexdigest()
        body = plain
        share = True  # whether the dump may leave this process (webhooks)
        if self._protector is not None:
            try:
                body = self._protector.protect(plain)
                actions["dump_protection"] = f"vault transit {self._protector.mount}/{self._protector.key}"
            except Exception as exc:
                # keep the evidence locally (0600) but do not send unencrypted data off the host
                share = False
                actions["dump_protection"] = f"failed ({type(exc).__name__}): plaintext kept locally, not sent"
        dump_path: str | None = None
        try:
            self._qdir.mkdir(parents=True, exist_ok=True)
            path = self._qdir / f"{self.stream}-{incident_id}.json"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(body)
                fh.flush()
                os.fsync(fh.fileno())
            dump_path = str(path)
        except OSError as exc:
            actions["quarantine_file"] = f"failed: {exc}"
        actions["webhooks"] = (self._post_dump(body, incident_id) if share else self._post_dump(
            json.dumps({"incident_id": incident_id, "stream": self.stream, "trigger": trigger,
                        "dump_sha256": digest, "dump": "withheld: encryption unavailable, see quarantine file"
                        }).encode(), incident_id))
        actions["notify"] = self._notify(incident_id, trigger, findings, digest)

        # C. lock DR targets read-only (in parallel, bounded), honouring dry-run
        actions["locks"] = self._lock_all()

        summary = "; ".join(f.message for f in findings)[:4000] or "manual trip"
        with session_scope(self._sf) as s:
            s.add(DrIncidentRow(
                id=incident_id, stream=self.stream, opened_at=self._clock(), trigger=trigger, summary=summary,
                findings_json=json.dumps([_finding_json(f) for f in findings], default=str),
                positions_json=json.dumps([r.position for r in bundle]), dump_path=dump_path,
                dump_sha256=digest, actions_json=json.dumps(actions, default=str)))
        self._gate.record_event(actor=actor, event="dr_breaker_tripped", detail={
            "stream": self.stream, "incident_id": incident_id, "trigger": trigger, "dump_sha256": digest,
            "locks": {k: v.get("ok") for k, v in actions["locks"].items()}})
        log.critical("DR breaker %s tripped (%s): %s", self.stream, trigger, summary)
        return incident_id

    def _post_dump(self, body: bytes, incident_id: str) -> dict[str, str]:
        out: dict[str, str] = {}
        ts = str(int(time.time()))
        for i, wh in enumerate(self._webhooks):
            key = f"webhook-{i}"
            try:
                url = self._secrets.get(wh.url_secret)
                if not url.startswith("https://"):
                    raise ValueError("incident webhook URL must use https")
                sig = hmac.new(self._secrets.get(wh.hmac_secret).encode(), ts.encode() + b"." + body,
                               hashlib.sha256).hexdigest()
                self._http.request("POST", url, content=body, expected={200, 201, 202, 204}, headers={
                    "Content-Type": "application/json", "X-OPLIA-Timestamp": ts,
                    "X-OPLIA-Signature": f"sha256={sig}", "X-OPLIA-Incident": incident_id})
                out[key] = "delivered"
            except (HttpError, LookupError, ValueError, OSError) as exc:  # never echo the URL
                out[key] = f"failed: {type(exc).__name__}{' ' + str(exc.status) if isinstance(exc, HttpError) else ''}"
            except Exception as exc:
                out[key] = f"failed: {type(exc).__name__}"
        return out

    def _notify(self, incident_id: str, trigger: str, findings: list[Finding], digest: str) -> dict[str, str]:
        if self._notifier is None:
            return {}
        details: dict[str, Any] = {"stream": self.stream, "incident_id": incident_id, "trigger": trigger,
                                   "dump_sha256": digest, "targets": ", ".join(lk.name for lk in self._lockers)}
        for i, f in enumerate(findings[:10], 1):
            details[f"finding_{i}"] = f.message
        return self._notifier.notify(Incident(
            dedup_key=f"oplia-dr-{incident_id}", severity="critical",
            summary=(f"DR replication HALTED on {self.stream}: {trigger} - "
                     f"{findings[0].message if findings else ''}")[:900],
            source=f"oplia-dr-breaker/{self.stream}", klass="dr-circuit-breaker", component=self.stream,
            group="disaster-recovery", details=details), "opened")

    def _lock_all(self) -> dict[str, dict[str, Any]]:
        if not self._lockers:
            return {}
        if self._gate.dry_run:
            return {lk.name: {"ok": True, "dry_run": True, "detail": "would switch to read-only (dry-run)"}
                    for lk in self._lockers}
        results: dict[str, dict[str, Any]] = {}
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(self._lockers)))
        try:
            futures = {pool.submit(lk.lock): lk.name for lk in self._lockers}
            done, pending = concurrent.futures.wait(futures, timeout=self._lock_timeout)
            for fut in done:
                name = futures[fut]
                try:
                    results[name] = {"ok": True, **fut.result()}
                except Exception as exc:
                    results[name] = {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:300]}"}
            for fut in pending:
                results[futures[fut]] = {"ok": False, "error": f"timed out after {self._lock_timeout}s"}
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        return results

    # ----------------------------------------------------------------------- reset
    def reset(self, *, actor: str, decision: Literal["release", "discard"], unlock_targets: bool,
              note: str) -> dict[str, Any]:
        state, incident_id, _ = self._store.state(self.stream)
        if state != "OPEN" or incident_id is None:
            raise ValueError(f"breaker {self.stream} is {state}; nothing to reset")
        unlocked: dict[str, Any] = {}
        if unlock_targets and not self._gate.dry_run:
            with session_scope(self._sf) as s:
                row = s.get(DrIncidentRow, incident_id)
                locks = json.loads(row.actions_json).get("locks", {}) if row else {}
            for lk in self._lockers:
                st = locks.get(lk.name) or {}
                if not st.get("ok") or st.get("dry_run"):
                    unlocked[lk.name] = {"skipped": "was not locked by this incident"}
                    continue
                try:
                    unlocked[lk.name] = {"ok": True, **lk.unlock(st)}
                except Exception as exc:
                    unlocked[lk.name] = {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:300]}"}
        with session_scope(self._sf) as s:
            row = s.get(DrIncidentRow, incident_id)
            if row is not None:
                row.resolved_at, row.resolved_by = self._clock(), actor
                row.resolution = json.dumps({"decision": decision, "unlock_targets": unlock_targets,
                                             "unlocked": unlocked, "note": note}, default=str)
        self._store.set(self.stream, "CLOSED", actor, incident_id, decision=decision)
        self._gate.record_event(actor=actor, event="dr_breaker_reset", detail={
            "stream": self.stream, "incident_id": incident_id, "decision": decision,
            "unlock_targets": unlock_targets, "note": note})
        return {"stream": self.stream, "incident_id": incident_id, "decision": decision, "unlocked": unlocked}


def _finding_json(f: Finding) -> dict[str, Any]:
    out: dict[str, Any] = {"rule": f.rule, "message": f.message, "numbers": f.numbers}
    if f.mutation is not None:
        out["mutation"] = {"engine": f.mutation.engine, "kind": f.mutation.kind, "target": f.mutation.target,
                           "statement": f.mutation.statement, "unconstrained": f.mutation.unconstrained,
                           "detail": f.mutation.detail}
    return out


def list_incidents(sf: sessionmaker[Session], stream: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    from sqlalchemy import select

    with session_scope(sf) as s:
        q = select(DrIncidentRow).order_by(DrIncidentRow.opened_at.desc()).limit(max(1, min(limit, 500)))
        if stream:
            q = q.where(DrIncidentRow.stream == stream)
        return [{"id": r.id, "stream": r.stream, "opened_at": _iso(r.opened_at),
                 "trigger": r.trigger, "summary": r.summary, "findings": json.loads(r.findings_json),
                 "positions": json.loads(r.positions_json), "dump_path": r.dump_path, "dump_sha256": r.dump_sha256,
                 "actions": json.loads(r.actions_json),
                 "resolved_at": _iso(r.resolved_at),
                 "resolved_by": r.resolved_by, "resolution": json.loads(r.resolution) if r.resolution else None}
                for r in s.execute(q).scalars()]
