"""The safety gate.

Every action that changes real infrastructure, identities or data goes through
this gate. The lifecycle is::

    propose -> (approve | reject | expire) -> execute -> (EXECUTED | DRY_RUN | FAILED)

Guarantees:

* With ``require_approval`` (default) nothing executes without an explicit
  approval, and with ``four_eyes`` (default) the approver must not be the
  requester.
* With ``dry_run`` (default) an approved action records what it *would* do and
  never calls the executor.
* The kill switch blocks all execution immediately.
* A proposal executes at most once: execution is claimed with a
  compare-and-set status update, so concurrent workers cannot double-run it.
* Every transition is written to a hash-chained audit log; tampering with any
  stored event breaks :meth:`SafetyGate.verify_audit_chain`.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from oplia_ctl.db import session_scope
from oplia_ctl.safety.models import (
    AuditEventRow,
    AuditHeadRow,
    ControlFlagRow,
    ProposalRow,
    ProposalStatus,
)

GENESIS_HASH = "0" * 64
KILL_SWITCH_KEY = "kill_switch"
_MAX_ERROR_LEN = 500
MAX_PROPOSAL_TTL = timedelta(days=30)


class GateError(Exception):
    """Base class for refusals by the safety gate."""


class NotFoundError(GateError):
    pass


class NotApprovedError(GateError):
    pass


class InvalidTransitionError(GateError):
    pass


class FourEyesViolationError(GateError):
    pass


class KillSwitchEngagedError(GateError):
    pass


class ExpiredError(GateError):
    pass


class Executor(Protocol):
    """Performs one kind of action. ``describe`` must not have side effects."""

    def describe(self, payload: dict[str, Any]) -> str: ...

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]: ...


@dataclass(frozen=True)
class Proposal:
    id: str
    action_type: str
    target: str
    payload: dict[str, Any]
    reason: str
    requested_by: str
    status: ProposalStatus
    created_at: datetime
    expires_at: datetime
    decided_by: str | None
    decided_at: datetime | None
    decision_note: str | None
    executed_at: datetime | None
    result: dict[str, Any] | None


def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _req_utc(dt: datetime | None) -> datetime:
    """Like _utc, for columns that are never NULL; raises instead of relying on assert."""
    value = _utc(dt)
    if value is None:
        raise ValueError("required timestamp is missing")
    return value


def _now() -> datetime:
    return datetime.now(UTC)


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _to_proposal(row: ProposalRow) -> Proposal:
    created = _req_utc(row.created_at)
    expires = _req_utc(row.expires_at)
    return Proposal(
        id=row.id,
        action_type=row.action_type,
        target=row.target,
        payload=json.loads(row.payload_json),
        reason=row.reason,
        requested_by=row.requested_by,
        status=ProposalStatus(row.status),
        created_at=created,
        expires_at=expires,
        decided_by=row.decided_by,
        decided_at=_utc(row.decided_at),
        decision_note=row.decision_note,
        executed_at=_utc(row.executed_at),
        result=json.loads(row.result_json) if row.result_json else None,
    )


class SafetyGate:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        dry_run: bool = True,
        require_approval: bool = True,
        four_eyes: bool = True,
        proposal_ttl: timedelta = timedelta(minutes=60),
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self._sf = session_factory
        self.dry_run = dry_run
        self.require_approval = require_approval
        self.four_eyes = four_eyes
        self._ttl = proposal_ttl
        self._clock = clock

    # ---------------------------------------------------------------- audit
    def _audit(
        self,
        session: Session,
        *,
        actor: str,
        event: str,
        proposal_id: str | None,
        detail: dict[str, Any],
    ) -> None:
        head = session.execute(
            select(AuditHeadRow).where(AuditHeadRow.id == 1).with_for_update()
        ).scalar_one_or_none()
        if head is None:
            head = AuditHeadRow(id=1, last_hash=GENESIS_HASH)
            session.add(head)
            session.flush()
        ts = _req_utc(self._clock())
        body = _canonical(
            {"ts": ts.isoformat(), "actor": actor, "event": event, "proposal_id": proposal_id, "detail": detail}
        )
        digest = hashlib.sha256((head.last_hash + body).encode()).hexdigest()
        session.add(
            AuditEventRow(
                ts=ts,
                actor=actor,
                event=event,
                proposal_id=proposal_id,
                detail_json=_canonical(detail),
                prev_hash=head.last_hash,
                hash=digest,
            )
        )
        head.last_hash = digest

    def verify_audit_chain(self) -> bool:
        with session_scope(self._sf) as s:
            prev = GENESIS_HASH
            for row in s.execute(select(AuditEventRow).order_by(AuditEventRow.seq)).scalars():
                ts = _req_utc(row.ts)
                body = _canonical(
                    {
                        "ts": ts.isoformat(),
                        "actor": row.actor,
                        "event": row.event,
                        "proposal_id": row.proposal_id,
                        "detail": json.loads(row.detail_json),
                    }
                )
                if row.prev_hash != prev:
                    return False
                if hashlib.sha256((prev + body).encode()).hexdigest() != row.hash:
                    return False
                prev = row.hash
            head = s.get(AuditHeadRow, 1)
            return head is None or head.last_hash == prev

    # ----------------------------------------------------------- kill switch
    def kill_switch_engaged(self) -> bool:
        with session_scope(self._sf) as s:
            flag = s.get(ControlFlagRow, KILL_SWITCH_KEY)
            return flag is not None and flag.value == "on"

    def set_kill_switch(self, *, engaged: bool, actor: str, reason: str) -> None:
        with session_scope(self._sf) as s:
            flag = s.get(ControlFlagRow, KILL_SWITCH_KEY)
            value = "on" if engaged else "off"
            if flag is None:
                s.add(ControlFlagRow(key=KILL_SWITCH_KEY, value=value, set_by=actor,
                                     set_at=self._clock(), reason=reason))
            else:
                flag.value, flag.set_by, flag.set_at, flag.reason = value, actor, self._clock(), reason
            self._audit(s, actor=actor, event=f"kill_switch_{value}", proposal_id=None,
                        detail={"reason": reason})

    # -------------------------------------------------------------- proposals
    def propose(
        self,
        *,
        action_type: str,
        target: str,
        payload: dict[str, Any],
        reason: str,
        requested_by: str,
        idempotency_key: str | None = None,
        ttl: timedelta | None = None,
    ) -> Proposal:
        """Create a proposal. With an idempotency key, a repeat returns the original.

        ``ttl`` overrides the gate's default lifetime for this proposal (e.g. clean-ups that must
        survive until the next maintenance window); it is bounded to 1 minute .. 30 days.
        """
        if ttl is not None and not timedelta(minutes=1) <= ttl <= MAX_PROPOSAL_TTL:
            raise ValueError("ttl must be between 1 minute and 30 days")
        now = self._clock()
        row = ProposalRow(
            id=str(uuid.uuid4()),
            action_type=action_type,
            target=target[:512],
            payload_json=_canonical(payload),
            reason=reason,
            requested_by=requested_by,
            status=ProposalStatus.PENDING.value,
            created_at=now,
            expires_at=now + (ttl or self._ttl),
            idempotency_key=idempotency_key,
        )
        try:
            with session_scope(self._sf) as s:
                s.add(row)
                s.flush()
                self._audit(s, actor=requested_by, event="proposed", proposal_id=row.id,
                            detail={"action_type": action_type, "target": target, "reason": reason})
                return _to_proposal(row)
        except IntegrityError:
            if idempotency_key is None:
                raise
            with session_scope(self._sf) as s:
                existing = s.execute(
                    select(ProposalRow).where(ProposalRow.idempotency_key == idempotency_key)
                ).scalar_one()
                return _to_proposal(existing)

    def get(self, proposal_id: str) -> Proposal:
        with session_scope(self._sf) as s:
            row = s.get(ProposalRow, proposal_id)
            if row is None:
                raise NotFoundError(proposal_id)
            return _to_proposal(row)

    def find_by_idempotency_key(self, idempotency_key: str) -> Proposal | None:
        """Look up a proposal by key, applying expiry first so a stale PENDING reads as EXPIRED."""
        with session_scope(self._sf) as s:
            row = s.execute(
                select(ProposalRow).where(ProposalRow.idempotency_key == idempotency_key)
            ).scalar_one_or_none()
            if row is None:
                return None
            self._expire_if_due(s, row)
            s.flush()
            return _to_proposal(row)

    def latest_by_idempotency_prefix(self, prefix: str) -> tuple[Proposal, str] | None:
        """Most recent proposal whose idempotency key starts with ``prefix`` (and that key)."""
        if not prefix:
            raise ValueError("prefix must not be empty")
        with session_scope(self._sf) as s:
            row = s.execute(
                select(ProposalRow)
                .where(ProposalRow.idempotency_key.startswith(prefix, autoescape=True))
                .order_by(ProposalRow.created_at.desc(), ProposalRow.idempotency_key.desc())
                .limit(1)
            ).scalar_one_or_none()
            if row is None:
                return None
            self._expire_if_due(s, row)
            s.flush()
            return _to_proposal(row), str(row.idempotency_key)

    def list(self, status: ProposalStatus | None = None, limit: int = 100) -> list[Proposal]:
        with session_scope(self._sf) as s:
            q = select(ProposalRow).order_by(ProposalRow.created_at.desc()).limit(min(limit, 500))
            if status is not None:
                q = q.where(ProposalRow.status == status.value)
            return [_to_proposal(r) for r in s.execute(q).scalars()]

    def _expire_if_due(self, s: Session, row: ProposalRow) -> bool:
        expires = _req_utc(row.expires_at)
        if row.status in (ProposalStatus.PENDING.value, ProposalStatus.APPROVED.value) and self._clock() >= expires:
            row.status = ProposalStatus.EXPIRED.value
            self._audit(s, actor="system", event="expired", proposal_id=row.id, detail={})
            return True
        return False

    def _decide(self, proposal_id: str, approver: str, approve: bool, note: str) -> Proposal:
        expired = False
        with session_scope(self._sf) as s:
            row = s.get(ProposalRow, proposal_id)
            if row is None:
                raise NotFoundError(proposal_id)
            if self._expire_if_due(s, row):
                expired = True
            elif row.status != ProposalStatus.PENDING.value:
                raise InvalidTransitionError(f"proposal is {row.status}, not PENDING")
            elif approve and self.four_eyes and approver.strip().lower() == row.requested_by.strip().lower():
                raise FourEyesViolationError("approver must be different from requester")
            else:
                new_status = ProposalStatus.APPROVED if approve else ProposalStatus.REJECTED
                res = s.execute(
                    update(ProposalRow)
                    .where(ProposalRow.id == proposal_id, ProposalRow.status == ProposalStatus.PENDING.value)
                    .values(status=new_status.value, decided_by=approver, decided_at=self._clock(),
                            decision_note=note)
                )
                if res.rowcount != 1:  # type: ignore[attr-defined]
                    raise InvalidTransitionError("proposal was decided concurrently")
                self._audit(s, actor=approver, event=new_status.value.lower(), proposal_id=proposal_id,
                            detail={"note": note})
        if expired:
            raise ExpiredError(proposal_id)
        return self.get(proposal_id)

    def approve(self, proposal_id: str, approver: str, note: str = "") -> Proposal:
        return self._decide(proposal_id, approver, True, note)

    def reject(self, proposal_id: str, approver: str, note: str = "") -> Proposal:
        return self._decide(proposal_id, approver, False, note)

    def execute(self, proposal_id: str, executor: Executor, actor: str) -> Proposal:
        if self.kill_switch_engaged():
            with session_scope(self._sf) as s:
                self._audit(s, actor=actor, event="execution_blocked_kill_switch",
                            proposal_id=proposal_id, detail={})
            raise KillSwitchEngagedError("kill switch is engaged")

        allowed = [ProposalStatus.APPROVED.value]
        if not self.require_approval:
            allowed.append(ProposalStatus.PENDING.value)

        expired = False
        with session_scope(self._sf) as s:
            row = s.get(ProposalRow, proposal_id)
            if row is None:
                raise NotFoundError(proposal_id)
            if self._expire_if_due(s, row):
                expired = True
            elif row.status == ProposalStatus.PENDING.value and self.require_approval:
                raise NotApprovedError("proposal has not been approved")
            elif row.status not in allowed:
                raise InvalidTransitionError(f"proposal is {row.status}; cannot execute")
            else:
                claim = s.execute(
                    update(ProposalRow)
                    .where(ProposalRow.id == proposal_id, ProposalRow.status.in_(allowed))
                    .values(status=ProposalStatus.EXECUTING.value)
                )
                if claim.rowcount != 1:  # type: ignore[attr-defined]
                    raise InvalidTransitionError("proposal is already being executed")
                self._audit(s, actor=actor, event="execution_started", proposal_id=proposal_id,
                            detail={"dry_run": self.dry_run})
                payload = json.loads(row.payload_json)
        if expired:
            raise ExpiredError(proposal_id)

        if self.dry_run:
            status = ProposalStatus.DRY_RUN
            result: dict[str, Any] = {"dry_run": True, "plan": executor.describe(payload)}
        else:
            try:
                result = executor(payload)
                status = ProposalStatus.EXECUTED
            except Exception as exc:  # executor failures are recorded, never swallowed silently
                status = ProposalStatus.FAILED
                result = {"error_type": type(exc).__name__, "error": str(exc)[:_MAX_ERROR_LEN]}

        with session_scope(self._sf) as s:
            s.execute(
                update(ProposalRow)
                .where(ProposalRow.id == proposal_id)
                .values(status=status.value, executed_at=self._clock(), result_json=_canonical(result))
            )
            self._audit(s, actor=actor, event=status.value.lower(), proposal_id=proposal_id, detail=result)
        return self.get(proposal_id)
