"""Every stored timestamp leaves the API as timezone-aware UTC, also on SQLite (which drops the offset)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

from oplia_ctl.db import Base, make_engine, make_session_factory
from oplia_ctl.replication.jobs import JobMachine
from oplia_ctl.safety import SafetyGate
from oplia_ctl.timeutil import iso_utc

IST = timezone(timedelta(hours=5, minutes=30))


def test_iso_utc():
    assert iso_utc(None) is None
    assert iso_utc(datetime(2026, 11, 21, 12, 31)) == "2026-11-21T12:31:00+00:00"            # naive = UTC
    assert iso_utc(datetime(2026, 11, 21, 18, 1, tzinfo=IST)) == "2026-11-21T12:31:00+00:00"


def _sqlite(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'tz.db'}")
    Base.metadata.create_all(engine)
    return make_session_factory(engine)


def test_dr_and_migration_jobs_keep_utc_on_sqlite(tmp_path):
    sf = _sqlite(tmp_path)
    ran_at = datetime(2026, 11, 21, 12, 31, tzinfo=UTC)       # 6:01 PM in IST; the app writes UTC

    class Probe(JobMachine):
        kind = "parity_check"

    m = Probe(sf, now=lambda: ran_at)
    m.queue("src -> dst", {}, "bob")
    (job,) = m.jobs()
    assert job["created_at"] == job["updated_at"] == "2026-11-21T12:31:00+00:00"
    # a browser parsing this shows 18:01 in IST, not 12:31
    assert datetime.fromisoformat(job["created_at"]).astimezone(IST).strftime("%H:%M") == "18:01"


def test_proposals_keep_utc_on_sqlite(tmp_path):
    from oplia_ctl.api import _proposal_json

    sf = _sqlite(tmp_path)
    gate = SafetyGate(sf, dry_run=True, require_approval=True, four_eyes=True, proposal_ttl=timedelta(hours=1),
                      clock=lambda: datetime(2026, 11, 21, 12, 31, tzinfo=UTC))
    p = gate.propose(action_type="x", target="t", payload={}, reason="r", requested_by="bob")
    out = _proposal_json(gate.get(p.id))
    assert out["created_at"] == "2026-11-21T12:31:00+00:00" and out["expires_at"].endswith("+00:00")


def test_network_history_is_utc_on_sqlite(tmp_path):
    from oplia_ctl.network.models import TrafficDialChangeRow
    from oplia_ctl.network.service import NetworkService

    sf = _sqlite(tmp_path)
    with sf.begin() as s:
        s.add(TrafficDialChangeRow(id="1", group_key="g", endpoint_group_arn="arn:aws:ga::1:x", from_percent=100,
                                   to_percent=50, request_id="r",
                                   executed_at=datetime(2026, 11, 21, 12, 31, tzinfo=UTC)))
    svc = NetworkService.__new__(NetworkService)
    svc._sf = sf
    (row,) = svc.history()
    assert row["executed_at"] == "2026-11-21T12:31:00+00:00"
