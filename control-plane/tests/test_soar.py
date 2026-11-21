from __future__ import annotations

import json
import os
import threading

import httpx
import pytest
import respx

from oplia_ctl.http import ResilientClient
from oplia_ctl.safety import ProposalStatus
from oplia_ctl.secrets import StaticSecretProvider
from oplia_ctl.soar.events import parse_event
from oplia_ctl.soar.exporter import FileFollower, SOARExporter
from oplia_ctl.soar.siem import SIEMSink

SIEM = "https://siem.example.com/services/collector/event"


def _sink(tmp_path, fmt="splunk_hec"):
    return SIEMSink(endpoint=SIEM, fmt=fmt, token_secret="siem_token",
                    secrets=StaticSecretProvider({"siem_token": "hec-tok"}),
                    client=ResilientClient(max_retries=0, sleep=lambda _s: None),
                    dead_letter_path=str(tmp_path / "dlq.jsonl"))


def _falco(priority="Critical", ns="payments", **extra):
    ev = {"uuid": "e-1", "rule": "Terminal shell in container", "priority": priority,
          "time": "2026-11-19T10:00:00Z", "output_fields": {"k8s.ns.name": ns, "k8s.pod.name": "api-1"}}
    ev.update(extra)
    return ev


def test_confidence_from_priority_and_explicit_field():
    assert parse_event(_falco("Critical")).confidence == 0.9
    assert parse_event(_falco("Warning")).confidence == 0.6
    assert parse_event(_falco("Warning", confidence=0.97)).confidence == 0.97
    assert parse_event(_falco("Warning", confidence=7)).confidence == 0.6  # out of range ignored
    assert parse_event(_falco("Warning", confidence=True)).confidence == 0.6  # bool is not a score


def test_target_resolution_prefers_explicit_cloud_target():
    ev = parse_event(_falco(oplia_target={"cloud": "aws", "region": "us-east-1",
                                          "instance_id": "i-0123456789abcdef0"}))
    assert ev.target.action_type == "isolate.aws"
    assert parse_event(_falco()).target.action_type == "isolate.k8s"
    assert parse_event({"rule": "x", "priority": "Critical"}).target is None


@respx.mock
def test_high_confidence_creates_one_proposal_and_exports(gate, tmp_path):
    route = respx.post(SIEM).mock(return_value=httpx.Response(200))
    exp = SOARExporter(gate=gate, sink=_sink(tmp_path))
    r1 = exp.process(_falco("Critical"))
    r2 = exp.process(_falco("Critical"))  # duplicate delivery
    assert r1["exported"] and r1["proposal_id"] == r2["proposal_id"]
    p = gate.get(r1["proposal_id"])
    assert p.action_type == "isolate.k8s" and p.payload == {"namespace": "payments"}
    assert p.status is ProposalStatus.PENDING  # never executed automatically
    sent = route.calls.last.request
    assert sent.headers["Authorization"] == "Splunk hec-tok"
    assert json.loads(sent.content)["event"]["rule"] == "Terminal shell in container"


@respx.mock
def test_threshold_is_strictly_above(gate, tmp_path):
    respx.post(SIEM).mock(return_value=httpx.Response(200))
    exp = SOARExporter(gate=gate, sink=_sink(tmp_path), threshold=0.85)
    assert exp.process(_falco("Warning", confidence=0.85))["proposal_id"] is None
    assert exp.process(_falco("Warning", confidence=0.851, uuid="e-2"))["proposal_id"] is not None
    assert exp.process(_falco("Error"))["proposal_id"] is None  # 0.8


@respx.mock
def test_siem_failure_goes_to_dead_letter(gate, tmp_path):
    respx.post(SIEM).mock(return_value=httpx.Response(500))
    exp = SOARExporter(gate=gate, sink=_sink(tmp_path, fmt="generic"))
    res = exp.process(_falco("Critical"))
    assert res["exported"] is False and res["proposal_id"] is not None
    lines = (tmp_path / "dlq.jsonl").read_text().splitlines()
    assert json.loads(lines[0])["event"]["event_id"] == "e-1"
    assert oct(os.stat(tmp_path / "dlq.jsonl").st_mode)[-3:] == "600"


def test_siem_requires_https(tmp_path):
    with pytest.raises(ValueError):
        SIEMSink(endpoint="http://siem", fmt="generic", token_secret="t",
                 secrets=StaticSecretProvider({}), client=ResilientClient(),
                 dead_letter_path=str(tmp_path / "d"))


def _collect(follower, stop, out, n):
    for line in follower.lines(stop):
        out.append(line)
        if len(out) >= n:
            stop.set()


def test_file_follower_handles_partial_lines_rotation_and_resume(tmp_path):
    log, state = tmp_path / "falco.json", tmp_path / "state.json"
    log.write_text('{"a":1}\n{"b":')
    out: list[str] = []
    stop = threading.Event()
    calls = {"n": 0}

    def sleep(_s):
        calls["n"] += 1
        if calls["n"] == 1:
            with open(log, "a") as fh:
                fh.write('2}\n')
        elif calls["n"] == 2:
            os.rename(log, tmp_path / "falco.json.1")
            log.write_text('{"c":3}\n')
        elif calls["n"] > 50:
            stop.set()

    _collect(FileFollower(str(log), str(state), sleep=sleep), stop, out, 3)
    assert out == ['{"a":1}', '{"b":2}', '{"c":3}']

    # Restart: nothing is re-delivered, new lines are picked up.
    with open(log, "a") as fh:
        fh.write('{"d":4}\n')
    out2: list[str] = []
    stop2 = threading.Event()
    _collect(FileFollower(str(log), str(state), sleep=lambda _s: stop2.set()), stop2, out2, 1)
    assert out2 == ['{"d":4}']
