from __future__ import annotations

import threading
from datetime import timedelta

import pytest
from sqlalchemy import update

from oplia_ctl.db import session_scope
from oplia_ctl.safety import (
    ExpiredError,
    FourEyesViolationError,
    InvalidTransitionError,
    KillSwitchEngagedError,
    NotApprovedError,
    ProposalStatus,
    SafetyGate,
)
from oplia_ctl.safety.models import AuditEventRow
from tests.conftest import RecordingExecutor


def _propose(gate: SafetyGate, key: str | None = None):
    return gate.propose(action_type="test.act", target="t1", payload={"x": 1}, reason="because",
                        requested_by="alice", idempotency_key=key)


def test_happy_path_requires_approval_then_executes(gate, executor):
    p = _propose(gate)
    assert p.status is ProposalStatus.PENDING
    with pytest.raises(NotApprovedError):
        gate.execute(p.id, executor, "ops")
    assert executor.calls == []
    gate.approve(p.id, "bob", "looks right")
    done = gate.execute(p.id, executor, "ops")
    assert done.status is ProposalStatus.EXECUTED
    assert done.result == {"ok": True}
    assert executor.calls == [{"x": 1}]


def test_four_eyes_blocks_self_approval_case_insensitive(gate):
    p = _propose(gate)
    with pytest.raises(FourEyesViolationError):
        gate.approve(p.id, " ALICE ")
    assert gate.get(p.id).status is ProposalStatus.PENDING


def test_reject_is_terminal(gate, executor):
    p = _propose(gate)
    gate.reject(p.id, "bob", "no")
    with pytest.raises(InvalidTransitionError):
        gate.approve(p.id, "carol")
    with pytest.raises(InvalidTransitionError):
        gate.execute(p.id, executor, "ops")
    assert executor.calls == []


def test_dry_run_never_calls_executor(session_factory, clock, executor):
    gate = SafetyGate(session_factory, dry_run=True, clock=clock)
    p = _propose(gate)
    gate.approve(p.id, "bob")
    done = gate.execute(p.id, executor, "ops")
    assert done.status is ProposalStatus.DRY_RUN
    assert done.result == {"dry_run": True, "plan": "would act on {'x': 1}"}
    assert executor.calls == []


def test_kill_switch_blocks_and_releases(gate, executor):
    p = _propose(gate)
    gate.approve(p.id, "bob")
    gate.set_kill_switch(engaged=True, actor="sec", reason="incident")
    with pytest.raises(KillSwitchEngagedError):
        gate.execute(p.id, executor, "ops")
    assert executor.calls == []
    assert gate.get(p.id).status is ProposalStatus.APPROVED
    gate.set_kill_switch(engaged=False, actor="sec", reason="resolved")
    assert gate.execute(p.id, executor, "ops").status is ProposalStatus.EXECUTED


def test_expired_proposal_cannot_be_approved_or_executed(gate, clock, executor):
    p = _propose(gate)
    clock.advance(minutes=61)
    with pytest.raises(ExpiredError):
        gate.approve(p.id, "bob")
    assert gate.get(p.id).status is ProposalStatus.EXPIRED
    p2 = _propose(gate)
    gate.approve(p2.id, "bob")
    clock.advance(minutes=61)
    with pytest.raises(ExpiredError):
        gate.execute(p2.id, executor, "ops")
    assert executor.calls == []


def test_executes_at_most_once(gate, executor):
    p = _propose(gate)
    gate.approve(p.id, "bob")
    gate.execute(p.id, executor, "ops")
    with pytest.raises(InvalidTransitionError):
        gate.execute(p.id, executor, "ops")
    assert len(executor.calls) == 1


def test_concurrent_execute_runs_once(session_factory, clock):
    gate = SafetyGate(session_factory, dry_run=False, clock=clock)
    p = _propose(gate)
    gate.approve(p.id, "bob")
    ex = RecordingExecutor()
    errors: list[Exception] = []

    def run() -> None:
        try:
            gate.execute(p.id, ex, "ops")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=run) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(ex.calls) == 1
    assert len(errors) == 7


def test_executor_failure_is_recorded(gate):
    p = _propose(gate)
    gate.approve(p.id, "bob")
    done = gate.execute(p.id, RecordingExecutor(fail=True), "ops")
    assert done.status is ProposalStatus.FAILED
    assert done.result == {"error_type": "RuntimeError", "error": "boom"}


def test_idempotency_key_returns_original(gate):
    a = _propose(gate, key="drift:abc")
    b = _propose(gate, key="drift:abc")
    assert a.id == b.id
    assert len(gate.list()) == 1


def test_no_approval_mode_executes_pending(session_factory, clock, executor):
    gate = SafetyGate(session_factory, dry_run=False, require_approval=False, clock=clock)
    p = _propose(gate)
    assert gate.execute(p.id, executor, "auto").status is ProposalStatus.EXECUTED


def test_audit_chain_verifies_and_detects_tampering(gate, executor, session_factory):
    p = _propose(gate)
    gate.approve(p.id, "bob")
    gate.execute(p.id, executor, "ops")
    assert gate.verify_audit_chain() is True
    with session_scope(session_factory) as s:
        s.execute(update(AuditEventRow).where(AuditEventRow.event == "approved")
                  .values(actor="mallory"))
    assert gate.verify_audit_chain() is False


def test_ttl_is_applied(gate, clock):
    p = _propose(gate)
    assert p.expires_at - p.created_at == timedelta(minutes=60)


def test_reads_show_expiry_for_every_lapsed_proposal(gate, clock):
    ids = [gate.propose(action_type="x", target=f"t{i}", payload={}, reason="r", requested_by="bot").id
           for i in range(3)]
    gate.approve(ids[1], "alice")
    clock.advance(minutes=61)
    assert gate.list(ProposalStatus.PENDING) == []          # lapsed proposals are not shown as pending
    assert {p.status for p in gate.list()} == {ProposalStatus.EXPIRED}  # all three, approved one included
    assert gate.get(ids[0]).status is ProposalStatus.EXPIRED
    assert gate.verify_audit_chain()
