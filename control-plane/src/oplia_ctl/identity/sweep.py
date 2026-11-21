"""Inactive-account sweep (90 days by default) across Entra ID, Okta and Active Directory.

``oplia-identity-sweep`` (daily CronJob):

1. asks each directory for enabled users whose last sign-in - or creation, if they never signed
   in - is older than the threshold;
2. drops exempt accounts (break-glass, service accounts you list) and accounts the driver marks
   as not to be disabled there (e.g. Entra users synchronised from AD);
3. **circuit breaker**: if one directory returns more than ``max_per_run`` accounts the data is
   treated as suspect (e.g. sign-in logs missing) - nothing is proposed and an alert is sent;
4. otherwise records one ``identity.disable_inactive`` proposal per directory in the safety gate.

When executed, every account is re-checked first: anyone who signed in since the sweep is
skipped. Disabling is reversible everywhere (Entra ``accountEnabled=false``, Okta *suspend*,
AD ``ACCOUNTDISABLE``). With ``require_approval`` switched off (and not dry-run) the sweep
executes its proposals immediately - the document's fully automatic mode.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from oplia_ctl.aiops.notify import Incident, IncidentNotifier
from oplia_ctl.identity.providers.base import IdentityProvider
from oplia_ctl.safety import ProposalStatus, SafetyGate

log = logging.getLogger("oplia.identity.sweep")

ACTION_DISABLE_INACTIVE = "identity.disable_inactive"


@dataclass
class SweepReport:
    cutoff: str = ""
    per_idp: dict[str, dict[str, Any]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class DisableInactiveExecutor:
    def __init__(self, providers: dict[str, IdentityProvider], *, inactive_days: int,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self._providers = providers
        self._days = inactive_days
        self._clock = clock

    def describe(self, payload: dict[str, Any]) -> str:
        users = payload.get("users") or []
        return (f"Disable {len(users)} {payload.get('idp')} accounts inactive for more than {self._days} days "
                f"(each re-checked first; reversible)")

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        idp = str(payload["idp"])
        prov = self._providers[idp]
        cutoff = self._clock() - timedelta(days=self._days)
        results: dict[str, str] = {}
        for u in payload.get("users") or []:
            uid = prov.validate_user_id(str(u["user_id"]))
            try:
                last = prov.last_login(uid)
                if last is not None and last > cutoff:
                    results[uid] = f"skipped: signed in {last.isoformat()}"
                    continue
                prov.disable_user(uid)
                results[uid] = "disabled"
            except Exception as exc:
                results[uid] = f"error: {type(exc).__name__}: {str(exc)[:200]}"
        disabled = sum(1 for v in results.values() if v == "disabled")
        errors = sum(1 for v in results.values() if v.startswith("error"))
        if errors and not disabled and errors == len(results):
            raise RuntimeError(f"all {errors} disable calls failed: {next(iter(results.values()))}")
        return {"idp": idp, "disabled": disabled, "errors": errors, "results": results}


class InactivitySweeper:
    def __init__(
        self,
        *,
        gate: SafetyGate,
        providers: dict[str, IdentityProvider],
        inactive_days: int = 90,
        exempt: dict[str, list[str]] | None = None,
        max_per_run: int = 25,
        notifier: IncidentNotifier | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        requested_by: str = "identity-sweeper",
    ) -> None:
        if not 30 <= inactive_days <= 3650:
            raise ValueError("inactive_days must be between 30 and 3650")
        if not 1 <= max_per_run <= 10000:
            raise ValueError("max_per_run must be between 1 and 10000")
        self._gate = gate
        self._providers = providers
        self._days = inactive_days
        self._exempt = {k: {x.lower() for x in v} for k, v in (exempt or {}).items()}
        self._max = max_per_run
        self._notifier = notifier
        self._clock = clock
        self._requested_by = requested_by

    def run(self) -> SweepReport:
        now = self._clock()
        cutoff = now - timedelta(days=self._days)
        report = SweepReport(cutoff=cutoff.isoformat())
        executor = DisableInactiveExecutor(self._providers, inactive_days=self._days, clock=self._clock)
        for name, prov in self._providers.items():
            try:
                found = prov.list_inactive_users(cutoff)
            except Exception as exc:
                report.errors.append(f"{name}: {type(exc).__name__}: {str(exc)[:300]}")
                continue
            exempt = self._exempt.get(name, set())
            excluded = [u for u in found if u.exclude_reason]
            exempted = [u for u in found if not u.exclude_reason
                        and (u.user_id.lower() in exempt or u.display.lower() in exempt)]
            targets = [u for u in found if u not in excluded and u not in exempted]
            entry: dict[str, Any] = {
                "inactive": len(found), "exempt": len(exempted), "targets": len(targets),
                "excluded": [{"user": u.display, "reason": u.exclude_reason} for u in excluded][:50],
            }
            report.per_idp[name] = entry
            if not targets:
                continue
            if len(targets) > self._max:
                entry["outcome"] = f"circuit breaker: {len(targets)} > {self._max}; nothing proposed"
                if self._notifier is not None:
                    self._notifier.notify(Incident(
                        dedup_key=f"oplia-sweep-breaker-{name}-{now.strftime('%Y%m%d')}", severity="error",
                        summary=f"Inactive-account sweep stopped for {name}: {len(targets)} accounts exceed the "
                                f"limit of {self._max} - check sign-in data before raising the limit",
                        source="oplia-identity-sweeper", klass="identity-sweep", component=name, group="identity",
                        details={"cutoff": cutoff.isoformat(), "sample": ", ".join(u.display for u in targets[:10])}),
                        "opened")
                continue
            ids = sorted(u.user_id for u in targets)
            key = (f"sweep:{name}:{now.strftime('%Y%m%d')}:"
                   + hashlib.sha256("|".join(ids).encode()).hexdigest()[:16])
            proposal = self._gate.propose(
                action_type=ACTION_DISABLE_INACTIVE, target=f"{name}:{len(ids)} accounts",
                payload={"idp": name, "cutoff": cutoff.isoformat(), "users": [
                    {"user_id": u.user_id, "display": u.display,
                     "last_login": u.last_login.isoformat() if u.last_login else None,
                     "created": u.created.isoformat() if u.created else None} for u in targets]},
                reason=f"{len(ids)} {name} accounts with no sign-in for more than {self._days} days "
                       f"(cutoff {cutoff.date().isoformat()})",
                requested_by=self._requested_by, idempotency_key=key, ttl=timedelta(hours=24))
            entry["proposal_id"] = proposal.id
            entry["outcome"] = "proposed"
            if not self._gate.require_approval and proposal.status is ProposalStatus.PENDING:
                done = self._gate.execute(proposal.id, executor, self._requested_by)
                entry["outcome"] = done.status.value
        return report
