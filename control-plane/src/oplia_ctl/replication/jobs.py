"""Persisted step machines for long-running DR jobs.

A gate executor queues a job (``queue``); a CronJob worker calls ``run_pending`` which advances
each job one persisted step at a time, so a restart resumes where it stopped. ``_step_<name>``
methods return the next step name (the same name = still waiting, ``DONE`` = finished). When a
step raises, ``on_failure`` runs (subclasses clean up, e.g. tear down a drill VM) and the job is
FAILED with the error. ``finish`` hooks record the final result (e.g. in the audit log).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from oplia_ctl.replication.models import DrJobRow

TERMINAL = ("SUCCEEDED", "FAILED")


class JobMachine:
    """Base for DR modules. Subclasses set ``kind``, ``action``, ``title`` and implement ``fields``
    (console form), ``parse`` (form values -> validated payload), ``describe`` and ``summary``."""

    kind = "job"
    action = "dr.job"
    title = "DR job"
    first_step = "START"
    secret_state_keys: tuple[str, ...] = ()

    def fields(self) -> list[dict[str, Any]]:
        return []

    def parse(self, params: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def target_of(self, payload: dict[str, Any]) -> str:
        return str(payload.get("target") or self.kind)

    def summary(self) -> dict[str, Any]:
        return {}

    def describe(self, payload: dict[str, Any]) -> str:
        raise NotImplementedError

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Gate executor: validate again (the payload was approved earlier) and queue the job."""
        clean = self.parse(payload)
        self.describe(clean)
        return self.queue(self.target_of(clean), clean, str(payload.get("requested_by", "")))

    def __init__(self, session_factory: sessionmaker[Session],
                 now: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self._sf = session_factory
        self._now = now

    # ---------------------------------------------------------------- queue / read
    def queue(self, target: str, payload: dict[str, Any], requested_by: str) -> dict[str, Any]:
        jid = str(uuid.uuid4())
        now = self._now()
        with self._sf() as s, s.begin():
            s.add(DrJobRow(id=jid, kind=self.kind, target=target[:512], status="QUEUED", step=self.first_step,
                           payload_json=json.dumps(payload), state_json="{}", created_at=now, updated_at=now,
                           requested_by=requested_by[:256]))
        return {"job_id": jid, "status": "QUEUED", "step": self.first_step}

    def jobs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._sf() as s:
            rows = s.scalars(select(DrJobRow).where(DrJobRow.kind == self.kind)
                             .order_by(DrJobRow.created_at.desc()).limit(limit))
            return [self._public(r) for r in rows]

    def _public(self, r: DrJobRow) -> dict[str, Any]:
        st = {k: v for k, v in json.loads(r.state_json).items() if k not in self.secret_state_keys}
        return {"id": r.id, "kind": r.kind, "target": r.target, "status": r.status, "step": r.step,
                "payload": json.loads(r.payload_json), "state": st, "error": r.error,
                "requested_by": r.requested_by, "created_at": r.created_at.isoformat(),
                "updated_at": r.updated_at.isoformat()}

    def get(self, jid: str) -> dict[str, Any]:
        return self._public(self._load(jid))

    # ---------------------------------------------------------------- worker
    def run_pending(self, max_steps: int = 20) -> list[dict[str, Any]]:
        with self._sf() as s:
            ids = [r.id for r in s.scalars(select(DrJobRow).where(DrJobRow.kind == self.kind,
                                                                  DrJobRow.status.in_(("QUEUED", "RUNNING"))))]
        out = []
        for jid in ids:
            for _ in range(max_steps):
                before = self._load(jid)
                self.advance(jid)
                after = self._load(jid)
                if after.status in TERMINAL or after.step == before.step:
                    break
            r = self._load(jid)
            out.append({"id": jid, "status": r.status, "step": r.step, "error": r.error})
        return out

    def advance(self, jid: str) -> None:
        job = self._load(jid)
        if job.status in TERMINAL:
            return
        payload: dict[str, Any] = json.loads(job.payload_json)
        state: dict[str, Any] = json.loads(job.state_json)
        try:
            nxt = getattr(self, f"_step_{job.step.lower()}")(job, payload, state)
        except Exception as exc:
            error = f"{type(exc).__name__}: {str(exc)[:1000]}"
            state["failed_step"] = job.step
            try:
                self.on_failure(job, payload, state, error)
            except Exception as cexc:  # cleanup failure is recorded, never hides the original error
                state["cleanup_error"] = f"{type(cexc).__name__}: {str(cexc)[:300]}"
            self._save(jid, job.step, state, "FAILED", error)
            self.finish(self._load(jid))
            return
        done = nxt == "DONE"
        self._save(jid, nxt, state, "SUCCEEDED" if done else "RUNNING")
        if done:
            self.finish(self._load(jid))

    def on_failure(self, job: DrJobRow, payload: dict[str, Any], state: dict[str, Any], error: str) -> None:
        """Subclasses release cloud resources here."""

    def finish(self, job: DrJobRow) -> None:
        """Subclasses record the final result here."""

    # ---------------------------------------------------------------- persistence
    def _load(self, jid: str) -> DrJobRow:
        with self._sf() as s:
            row = s.get(DrJobRow, jid)
            if row is None:
                raise KeyError(jid)
            s.expunge(row)
            return row

    def _save(self, jid: str, step: str, state: dict[str, Any], status: str, error: str | None = None) -> None:
        with self._sf() as s, s.begin():
            row = s.get(DrJobRow, jid)
            if row is None:
                raise KeyError(jid)
            row.step, row.status, row.error = step, status, error
            row.state_json, row.updated_at = json.dumps(state, default=str), self._now()
