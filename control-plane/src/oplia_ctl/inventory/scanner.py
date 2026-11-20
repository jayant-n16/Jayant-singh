"""Scan compute resources from the FinOps inventory sources and cache them.

Only the ``compute`` category is kept (EC2 instances, Azure VMs / scale sets / AKS, GCE instances /
GKE, IBM VPC instances / clusters). Size and state are stored where the listing API returns them
(EC2: instance type and state; GCP Cloud Asset: state); otherwise they are left empty rather than
guessed. A resource that is no longer listed is marked ``gone`` - but only when its source answered
completely, so a failing cloud API never makes machines "disappear".
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from oplia_ctl.db import session_scope
from oplia_ctl.finops.compliance import TagPolicy, evaluate
from oplia_ctl.finops.inventory import InventorySource
from oplia_ctl.inventory.models import InventoryInstanceRow, InventoryScanRow

log = logging.getLogger("oplia.inventory")


def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


class InventoryScanner:
    def __init__(self, sf: sessionmaker[Session], sources: list[InventorySource], policy: TagPolicy,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self._sf = sf
        self._sources = sources
        self._policy = policy
        self._clock = clock

    def run(self) -> dict[str, Any]:
        scan_id = str(uuid.uuid4())
        started = self._clock()
        errors: list[dict[str, str]] = []
        seen = new = gone = 0
        for src in self._sources:
            try:
                items = [r for r in src.list_resources() if r.category == "compute"]
            except Exception as exc:  # one cloud failing must not stop the others
                log.exception("inventory source %s failed", src.name)
                errors.append({"source": src.name, "error": f"{type(exc).__name__}: {str(exc)[:300]}"})
                continue
            now = self._clock()
            ids: set[str] = set()
            with session_scope(self._sf) as s:
                for r in items:
                    ids.add(r.resource_id)
                    ev = evaluate(self._policy, r)
                    issues = ev.missing + ev.wrong_case + ev.invalid
                    values = {"scope": r.scope, "region": r.region, "resource_type": r.resource_type,
                              "name": r.name[:512], "size": r.size, "state": r.state,
                              "tags_json": json.dumps({**r.labels, **r.tags}, sort_keys=True),
                              "tag_compliant": ev.compliant, "tag_issues_json": json.dumps(issues),
                              "last_seen_at": now, "gone_at": None}
                    row = s.execute(select(InventoryInstanceRow).where(
                        InventoryInstanceRow.cloud == r.cloud,
                        InventoryInstanceRow.resource_id == r.resource_id)).scalar_one_or_none()
                    if row is None:
                        s.add(InventoryInstanceRow(id=str(uuid.uuid4()), cloud=r.cloud, resource_id=r.resource_id,
                                                   first_seen_at=now, **values))
                        new += 1
                    else:
                        for k, v in values.items():
                            setattr(row, k, v)
                seen += len(items)
                scopes = src.scopes()
                stale = s.execute(select(InventoryInstanceRow).where(
                    InventoryInstanceRow.cloud == src.name, InventoryInstanceRow.scope.in_(scopes),
                    InventoryInstanceRow.gone_at.is_(None))).scalars().all()
                for row in stale:
                    if row.resource_id not in ids:
                        row.gone_at = now
                        gone += 1
        with session_scope(self._sf) as s:
            s.add(InventoryScanRow(id=scan_id, started_at=started, finished_at=self._clock(),
                                   instances_seen=seen, new_instances=new, gone_instances=gone,
                                   source_errors_json=json.dumps(errors)))
        return {"id": scan_id, "instances_seen": seen, "new_instances": new, "gone_instances": gone,
                "source_errors": errors}


def list_instances(sf: sessionmaker[Session], *, cloud: str | None = None, region: str | None = None,
                   state: str | None = None, include_gone: bool = False, limit: int = 500) -> list[dict[str, Any]]:
    q = select(InventoryInstanceRow).order_by(InventoryInstanceRow.cloud, InventoryInstanceRow.name)
    if cloud:
        q = q.where(InventoryInstanceRow.cloud == cloud)
    if region:
        q = q.where(InventoryInstanceRow.region == region)
    if state:
        q = q.where(InventoryInstanceRow.state == state)
    if not include_gone:
        q = q.where(InventoryInstanceRow.gone_at.is_(None))
    q = q.limit(max(1, min(limit, 2000)))
    with session_scope(sf) as s:
        return [{"id": r.id, "cloud": r.cloud, "scope": r.scope, "region": r.region,
                 "resource_type": r.resource_type, "resource_id": r.resource_id, "name": r.name,
                 "size": r.size, "state": r.state, "tags": json.loads(r.tags_json),
                 "tag_compliant": r.tag_compliant, "tag_issues": json.loads(r.tag_issues_json),
                 "first_seen_at": _utc(r.first_seen_at).isoformat(),  # type: ignore[union-attr]
                 "last_seen_at": _utc(r.last_seen_at).isoformat(),  # type: ignore[union-attr]
                 "gone_at": _iso(r.gone_at)} for r in s.execute(q).scalars()]


def _iso(dt: datetime | None) -> str | None:
    u = _utc(dt)
    return u.isoformat() if u else None


def list_scans(sf: sessionmaker[Session], limit: int = 20) -> list[dict[str, Any]]:
    q = select(InventoryScanRow).order_by(InventoryScanRow.started_at.desc()).limit(max(1, min(limit, 200)))
    with session_scope(sf) as s:
        return [{"id": r.id, "started_at": _iso(r.started_at), "finished_at": _iso(r.finished_at),
                 "instances_seen": r.instances_seen, "new_instances": r.new_instances,
                 "gone_instances": r.gone_instances, "source_errors": json.loads(r.source_errors_json)}
                for r in s.execute(q).scalars()]


def main() -> None:  # pragma: no cover - process wiring, exercised in deployment
    from oplia_ctl.config import get_settings
    from oplia_ctl.db import Base, make_engine, make_session_factory
    from oplia_ctl.finops.config import FinOpsSettings, build_sources
    from oplia_ctl.http import ResilientClient
    from oplia_ctl.secrets import build_secret_provider

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    settings.assert_production_safe()
    engine = make_engine(settings.database_url)
    if settings.environment == "dev":
        Base.metadata.create_all(engine)
    cfg = FinOpsSettings()
    client = ResilientClient(timeout=settings.http_timeout_seconds, max_retries=settings.http_max_retries)
    sources = build_sources(cfg, build_secret_provider(settings.secret_provider), client)
    if not sources:
        raise SystemExit("configure at least one of OPLIA_FINOPS_AWS_REGIONS / _AZURE_SUBSCRIPTIONS / "
                         "_GCP_SCOPES / _IBM_ACCOUNT_ID")
    report = InventoryScanner(make_session_factory(engine), sources, cfg.policy).run()
    print(json.dumps(report, indent=2))
    if report["source_errors"]:
        raise SystemExit(2)


__all__ = ["InventoryScanner", "list_instances", "list_scans"]
