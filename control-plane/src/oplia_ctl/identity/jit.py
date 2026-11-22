"""Just-in-time privileged access.

Lifecycle of a request::

    request (operator)  -> PENDING            safety-gate proposal "jit.grant" (requested_by = requester)
    approve (approver)  -> APPROVED + grant   four-eyes: approver != requester; kill switch; dry-run
                           access ACTIVE      expires_at = granted_at + expiration_minutes
    worker (every 60 s) -> access REVOKED     membership removed, then verified absent; audited
    reject              -> REJECTED
    nobody decides      -> EXPIRED            (gate proposal lifetime)

Revocation never goes through approval or the kill switch: it only *reduces* privilege and must
happen on time. If a revocation fails it is retried every tick; after 3 failures an alert is sent
(PagerDuty/Slack) and retries continue.

Roles come from an operator-defined catalog, so a requester can only ask for a known role, on an
allowed account, for at most the role's maximum duration. Only one open request or active grant
per user and group is allowed.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter
from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session, sessionmaker

from oplia_ctl.aiops.notify import Incident, IncidentNotifier
from oplia_ctl.db import session_scope
from oplia_ctl.identity.models import JitRequestRow
from oplia_ctl.identity.providers.base import IdentityProvider, IdpName
from oplia_ctl.safety import ProposalStatus, SafetyGate

log = logging.getLogger("oplia.identity.jit")

ACTION_JIT_GRANT = "jit.grant"
ALERT_AFTER_FAILURES = 3
LEASE = timedelta(minutes=2)


class RoleSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")]
    description: Annotated[str, Field(min_length=1, max_length=300)]
    idp: IdpName
    group_ref: Annotated[str, Field(min_length=1, max_length=512)]
    max_minutes: Annotated[int, Field(ge=15, le=24 * 60)] = 240
    target_cloud_accounts: list[Annotated[str, Field(min_length=1, max_length=128)]] = Field(min_length=1)

    def allows_account(self, account: str) -> bool:
        return "*" in self.target_cloud_accounts or account in self.target_cloud_accounts


_ROLES = TypeAdapter(list[RoleSpec])


def load_catalog(path: str, providers: dict[str, IdentityProvider]) -> dict[str, RoleSpec]:
    if not path:
        return {}
    catalog: dict[str, RoleSpec] = {}
    for spec in _ROLES.validate_python(json.loads(Path(path).read_text(encoding="utf-8"))):
        if spec.role in catalog:
            raise ValueError(f"duplicate role {spec.role!r}")
        prov = providers.get(spec.idp)
        if prov is None:
            raise ValueError(f"role {spec.role!r} uses identity provider {spec.idp!r}, which is not configured")
        prov.validate_group_ref(spec.group_ref)
        catalog[spec.role] = spec
    return catalog


class JitRequestError(ValueError):
    """The request is not allowed by the catalog or conflicts with an existing one."""


class JitConflictError(JitRequestError):
    pass


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    # SQLite returns naive UTC, PostgreSQL returns the session time zone: always report UTC
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _row_json(r: JitRequestRow) -> dict[str, Any]:
    def iso(d: datetime | None) -> str | None:
        a = _aware(d)
        return a.isoformat() if a else None

    return {
        "id": r.id, "user_id": r.user_id, "requested_role": r.requested_role,
        "target_cloud_account": r.target_cloud_account, "expiration_minutes": r.expiration_minutes,
        "approval_status": r.approval_status, "access_status": r.access_status, "idp": r.idp,
        "group_ref": r.group_ref, "justification": r.justification, "requested_by": r.requested_by,
        "proposal_id": r.proposal_id, "created_at": iso(r.created_at), "decided_at": iso(r.decided_at),
        "decided_by": r.decided_by, "granted_at": iso(r.granted_at), "expires_at": iso(r.expires_at),
        "revoked_at": iso(r.revoked_at), "revoked_by": r.revoked_by, "revoke_attempts": r.revoke_attempts,
        "last_error": r.last_error,
    }


class JitGrantExecutor:
    """Executed by the safety gate after approval."""

    def __init__(self, service: JitService) -> None:
        self._svc = service

    def describe(self, payload: dict[str, Any]) -> str:
        return (f"Add {payload['idp']} user {payload['user_id']} to {payload['group_ref']} for "
                f"{payload['expiration_minutes']} minutes (role {payload['requested_role']}, account "
                f"{payload['target_cloud_account']}); removed automatically when it expires")

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._svc._grant(payload)


class JitService:
    def __init__(
        self,
        *,
        gate: SafetyGate,
        session_factory: sessionmaker[Session],
        providers: dict[str, IdentityProvider],
        catalog: dict[str, RoleSpec],
        notifier: IncidentNotifier | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        worker_id: str = "jit-worker",
    ) -> None:
        self._gate = gate
        self._sf = session_factory
        self._providers = providers
        self._catalog = catalog
        self._notifier = notifier
        self._clock = clock
        self._worker = worker_id

    @property
    def catalog(self) -> dict[str, RoleSpec]:
        return self._catalog

    # ------------------------------------------------------------------ requests
    def request(self, *, requester: str, user_id: str, requested_role: str, target_cloud_account: str,
                expiration_minutes: int, justification: str) -> dict[str, Any]:
        spec = self._catalog.get(requested_role)
        if spec is None:
            raise JitRequestError(f"unknown role {requested_role!r}")
        if not spec.allows_account(target_cloud_account):
            raise JitRequestError(f"role {requested_role!r} is not available for account {target_cloud_account!r}")
        if not 1 <= expiration_minutes <= spec.max_minutes:
            raise JitRequestError(f"expiration_minutes must be 1..{spec.max_minutes} for role {requested_role!r}")
        if not 10 <= len(justification.strip()) <= 1000:
            raise JitRequestError("justification must be 10..1000 characters")
        user_id = self._providers[spec.idp].validate_user_id(user_id)
        now = self._clock()
        rid = str(uuid.uuid4())
        with session_scope(self._sf) as s:
            clash = s.execute(select(JitRequestRow.id).where(
                JitRequestRow.idp == spec.idp, JitRequestRow.user_id == user_id,
                JitRequestRow.group_ref == spec.group_ref,
                or_(JitRequestRow.approval_status == "PENDING", JitRequestRow.access_status == "ACTIVE"),
            )).scalars().first()
            if clash is not None:
                raise JitConflictError(f"user already has an open request or active grant for this access ({clash})")
            s.add(JitRequestRow(
                id=rid, user_id=user_id, requested_role=spec.role, target_cloud_account=target_cloud_account,
                expiration_minutes=expiration_minutes, approval_status="PENDING", idp=spec.idp,
                group_ref=spec.group_ref, justification=justification.strip(), requested_by=requester,
                access_status="NONE", created_at=now, revoke_attempts=0, alerted=0))
        proposal = self._gate.propose(
            action_type=ACTION_JIT_GRANT, target=f"{spec.idp}:{spec.group_ref}",
            payload={"request_id": rid, "user_id": user_id, "idp": spec.idp, "group_ref": spec.group_ref,
                     "requested_role": spec.role, "target_cloud_account": target_cloud_account,
                     "expiration_minutes": expiration_minutes},
            reason=f"JIT {spec.role} for {user_id} on {target_cloud_account} for {expiration_minutes} min: "
                   f"{justification.strip()}",
            requested_by=requester, idempotency_key=f"jit:{rid}")
        with session_scope(self._sf) as s:
            row = s.get(JitRequestRow, rid)
            if row is not None:
                row.proposal_id = proposal.id
        return self.get(rid)

    def _sync_pending(self, s: Session, row: JitRequestRow) -> None:
        if row.approval_status != "PENDING" or row.proposal_id is None:
            return
        p = self._gate.get(row.proposal_id)
        if p.status is ProposalStatus.EXPIRED:
            row.approval_status = "EXPIRED"
        elif p.status is ProposalStatus.REJECTED:
            row.approval_status, row.decided_at, row.decided_by = "REJECTED", p.decided_at, p.decided_by
        elif p.status is ProposalStatus.APPROVED:  # approved through the generic /proposals route
            row.approval_status, row.decided_at, row.decided_by = "APPROVED", p.decided_at, p.decided_by

    def get(self, request_id: str) -> dict[str, Any]:
        with session_scope(self._sf) as s:
            row = s.get(JitRequestRow, request_id)
            if row is None:
                raise LookupError(request_id)
            self._sync_pending(s, row)
            return _row_json(row)

    def list_requests(self, *, approval_status: str | None = None, access_status: str | None = None,
             limit: int = 100) -> list[dict[str, Any]]:
        with session_scope(self._sf) as s:
            q = select(JitRequestRow).order_by(JitRequestRow.created_at.desc()).limit(max(1, min(limit, 500)))
            if approval_status:
                q = q.where(JitRequestRow.approval_status == approval_status)
            if access_status:
                q = q.where(JitRequestRow.access_status == access_status)
            rows = list(s.execute(q).scalars())
            for r in rows:
                self._sync_pending(s, r)
            return [_row_json(r) for r in rows]

    def approve(self, request_id: str, approver: str, note: str = "") -> dict[str, Any]:
        with session_scope(self._sf) as s:
            row = s.get(JitRequestRow, request_id)
            if row is None:
                raise LookupError(request_id)
            self._sync_pending(s, row)
            if row.approval_status != "PENDING" or row.proposal_id is None:
                raise JitConflictError(f"request is {row.approval_status}")
            pid = row.proposal_id
        self._gate.approve(pid, approver, note)  # four-eyes enforced here
        with session_scope(self._sf) as s:
            row = s.get(JitRequestRow, request_id)
            if row is not None:
                row.approval_status, row.decided_at, row.decided_by = "APPROVED", self._clock(), approver
        return self.execute_approved(request_id, approver)

    def execute_approved(self, request_id: str, actor: str) -> dict[str, Any]:
        """Run the grant of an approved request (also used to retry, e.g. after the kill switch was released)."""
        with session_scope(self._sf) as s:
            row = s.get(JitRequestRow, request_id)
            if row is None:
                raise LookupError(request_id)
            if row.approval_status != "APPROVED" or row.access_status != "NONE" or row.proposal_id is None:
                raise JitConflictError(f"request is {row.approval_status}/{row.access_status}; nothing to grant")
            pid = row.proposal_id
        done = self._gate.execute(pid, JitGrantExecutor(self), actor)
        with session_scope(self._sf) as s:
            row = s.get(JitRequestRow, request_id)
            if row is not None and row.access_status == "NONE":
                if done.status is ProposalStatus.DRY_RUN:
                    row.access_status = "DRY_RUN"
                elif done.status is ProposalStatus.FAILED:
                    row.access_status = "GRANT_FAILED"
                    row.last_error = str((done.result or {}).get("error", ""))[:2000]
        return self.get(request_id)

    def reject(self, request_id: str, approver: str, note: str = "") -> dict[str, Any]:
        with session_scope(self._sf) as s:
            row = s.get(JitRequestRow, request_id)
            if row is None:
                raise LookupError(request_id)
            if row.approval_status != "PENDING" or row.proposal_id is None:
                raise JitConflictError(f"request is {row.approval_status}")
            pid = row.proposal_id
        self._gate.reject(pid, approver, note)
        with session_scope(self._sf) as s:
            row = s.get(JitRequestRow, request_id)
            if row is not None:
                row.approval_status, row.decided_at, row.decided_by = "REJECTED", self._clock(), approver
        return self.get(request_id)

    # --------------------------------------------------------------------- grant
    def _grant(self, payload: dict[str, Any]) -> dict[str, Any]:
        rid = str(payload["request_id"])
        with session_scope(self._sf) as s:
            row = s.get(JitRequestRow, rid)
            if row is None or row.approval_status != "APPROVED" or row.access_status != "NONE":
                raise JitConflictError("request is not in a grantable state")
            idp, group, user, minutes = row.idp, row.group_ref, row.user_id, row.expiration_minutes
        prov = self._providers[idp]
        prov.add_member(group, user)
        try:
            if not prov.has_access(group, user):
                raise RuntimeError(f"{idp} did not report the membership after adding it")
        except Exception:
            # never leave an unverified grant behind without an expiry: undo it, then fail
            try:
                prov.remove_member(group, user)
            except Exception as undo_exc:  # reported with the original failure
                log.error("could not undo unverified JIT grant %s: %s", rid, undo_exc)
            raise
        now = self._clock()
        expires = now + timedelta(minutes=minutes)
        with session_scope(self._sf) as s:
            row = s.get(JitRequestRow, rid)
            if row is not None:
                row.access_status, row.granted_at, row.expires_at = "ACTIVE", now, expires
        return {"granted": f"{idp}:{user}->{group}", "expires_at": expires.isoformat()}

    # -------------------------------------------------------------------- revoke
    def revoke_now(self, request_id: str, actor: str) -> dict[str, Any]:
        with session_scope(self._sf) as s:
            row = s.get(JitRequestRow, request_id)
            if row is None:
                raise LookupError(request_id)
            if row.access_status != "ACTIVE":
                raise JitConflictError(f"access is {row.access_status}, nothing to revoke")
            row.expires_at = self._clock()
            row.lease_until = None
        self._revoke_one(request_id, actor)
        return self.get(request_id)

    def _claim(self, request_id: str, now: datetime) -> bool:
        with session_scope(self._sf) as s:
            res = s.execute(update(JitRequestRow).where(
                JitRequestRow.id == request_id, JitRequestRow.access_status == "ACTIVE",
                or_(JitRequestRow.lease_until.is_(None), JitRequestRow.lease_until < now),
            ).values(lease_until=now + LEASE))
            return int(res.rowcount) == 1  # type: ignore[attr-defined]

    def _revoke_one(self, request_id: str, actor: str) -> str:
        now = self._clock()
        if not self._claim(request_id, now):
            return "skipped"
        with session_scope(self._sf) as s:
            row = s.get(JitRequestRow, request_id)
            if row is None:
                return "skipped"
            idp, group, user = row.idp, row.group_ref, row.user_id
            other = s.execute(select(JitRequestRow.id).where(
                JitRequestRow.id != request_id, JitRequestRow.idp == idp, JitRequestRow.user_id == user,
                JitRequestRow.group_ref == group, JitRequestRow.access_status == "ACTIVE",
                JitRequestRow.expires_at > now)).scalars().first()
        if other is not None:
            self._finish(request_id, actor, now, note=f"membership kept: still covered by grant {other}")
            return "superseded"
        prov = self._providers[idp]
        try:
            prov.remove_member(group, user)
            if prov.has_access(group, user):
                raise RuntimeError("user still has the access after removal (nested group or another path)")
        except Exception as exc:
            self._failed(request_id, exc, now)
            return "failed"
        self._finish(request_id, actor, now)
        return "revoked"

    def _finish(self, request_id: str, actor: str, now: datetime, note: str | None = None) -> None:
        with session_scope(self._sf) as s:
            row = s.get(JitRequestRow, request_id)
            if row is None:
                return
            row.access_status, row.revoked_at, row.revoked_by = "REVOKED", now, actor
            row.lease_until, row.last_error = None, note
            detail = {"request_id": row.id, "idp": row.idp, "user_id": row.user_id, "group_ref": row.group_ref,
                      "role": row.requested_role, "granted_at": (_aware(row.granted_at) or now).isoformat(),
                      "note": note}
            pid = row.proposal_id
        self._gate.record_event(actor=actor, event="jit_revoked", detail=detail, proposal_id=pid)

    def _failed(self, request_id: str, exc: Exception, now: datetime) -> None:
        msg = f"{type(exc).__name__}: {str(exc)[:500]}"
        log.warning("JIT revocation %s failed: %s", request_id, msg)
        alert: Incident | None = None
        with session_scope(self._sf) as s:
            row = s.get(JitRequestRow, request_id)
            if row is None:
                return
            row.revoke_attempts += 1
            row.last_error, row.lease_until = msg, None
            if row.revoke_attempts >= ALERT_AFTER_FAILURES and not row.alerted:
                row.alerted = 1
                alert = Incident(
                    dedup_key=f"oplia-jit-revoke-{row.id}", severity="critical",
                    summary=f"JIT access NOT revoked: {row.idp} user {row.user_id} still in {row.group_ref} "
                            f"after {row.revoke_attempts} attempts",
                    source="oplia-jit-worker", klass="jit-revocation", component=row.idp, group="identity",
                    details={"request_id": row.id, "role": row.requested_role, "error": msg,
                             "expired_at": (_aware(row.expires_at) or now).isoformat()})
        if alert is not None and self._notifier is not None:
            self._notifier.notify(alert, "opened")

    # -------------------------------------------------------------------- worker
    def tick(self) -> dict[str, int]:
        now = self._clock()
        report = {"revoked": 0, "failed": 0, "superseded": 0, "skipped": 0, "pending_expired": 0}
        with session_scope(self._sf) as s:
            for row in s.execute(select(JitRequestRow).where(JitRequestRow.approval_status == "PENDING")).scalars():
                before = row.approval_status
                self._sync_pending(s, row)
                if before != row.approval_status and row.approval_status == "EXPIRED":
                    report["pending_expired"] += 1
            due = list(s.execute(select(JitRequestRow.id).where(
                JitRequestRow.access_status == "ACTIVE", JitRequestRow.expires_at <= now)
                .order_by(JitRequestRow.expires_at)).scalars())
        for rid in due:
            report[self._revoke_one(rid, self._worker)] += 1
        return report

    def reconcile(self, standing_allowlist: dict[str, list[str]] | None = None,
                  remove: bool = False) -> dict[str, Any]:
        """Find members of catalog groups that hold the access without an active JIT grant."""
        allow = {k: set(v) for k, v in (standing_allowlist or {}).items()}
        now = self._clock()
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        seen: set[tuple[str, str]] = set()
        for spec in self._catalog.values():
            key = (spec.idp, spec.group_ref)
            if key in seen:
                continue
            seen.add(key)
            try:
                members = self._providers[spec.idp].list_members(spec.group_ref)
            except Exception as exc:
                errors.append(f"{spec.idp}:{spec.group_ref}: {type(exc).__name__}: {str(exc)[:200]}")
                continue
            with session_scope(self._sf) as s:
                active = set(s.execute(select(JitRequestRow.user_id).where(
                    JitRequestRow.idp == spec.idp, JitRequestRow.group_ref == spec.group_ref,
                    JitRequestRow.access_status == "ACTIVE")).scalars())
            permitted = active | allow.get(f"{spec.idp}:{spec.group_ref}", set())
            for m in members:
                if m in permitted:
                    continue
                item = {"idp": spec.idp, "group_ref": spec.group_ref, "user_id": m, "removed": False}
                if remove:
                    try:
                        self._providers[spec.idp].remove_member(spec.group_ref, m)
                        item["removed"] = True
                        self._gate.record_event(actor=self._worker, event="jit_standing_access_removed",
                                                detail={k: v for k, v in item.items() if k != "removed"})
                    except Exception as exc:
                        item["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
                findings.append(item)
        if findings and self._notifier is not None:
            self._notifier.notify(Incident(
                dedup_key=f"oplia-jit-standing-{now.strftime('%Y%m%d')}", severity="warning",
                summary=f"{len(findings)} standing privileged memberships without an active JIT grant",
                source="oplia-jit-worker", klass="jit-standing-access", component="identity", group="identity",
                details={f"{i:02d}": f"{f['idp']} {f['user_id']} in {f['group_ref']}"
                                      f"{' (removed)' if f['removed'] else ''}"
                         for i, f in enumerate(findings[:20], 1)}), "opened")
        return {"standing": findings, "errors": errors}
