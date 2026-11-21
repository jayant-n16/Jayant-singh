from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs

import boto3
import httpx
import pytest
import respx
from moto import mock_aws

from oplia_ctl.config import CICDTarget
from oplia_ctl.drivers.cicd import RemediationRequest, build_cicd_driver
from oplia_ctl.http import ResilientClient
from oplia_ctl.lifecycle.manager import ACTION_IAC_DESTROY, IaCLifecycleManager
from oplia_ctl.lifecycle.sources import AwsTaggedSource, AzureTaggedSource
from oplia_ctl.lifecycle.stacks import TaggedResource, TTLError, group_stacks, parse_created_at, parse_ttl
from oplia_ctl.remediation.drift import PipelineDispatchExecutor
from oplia_ctl.safety import ProposalStatus
from oplia_ctl.secrets import StaticSecretProvider

ACCOUNT = "123456789012"
CREATED = "2026-11-19T00:00:00Z"
ALLOWED = ["control-tower-standard", "alz-hybrid"]


def tags(ttl="8h", created=CREATED, zone="feature-42", blueprint="control-tower-standard", **extra):
    t = {"LifecycleTTL": ttl, "CreatedAt": created, "OpliaZone": zone, "OpliaBlueprint": blueprint}
    t.update(extra)
    return t


def res(rid, **kw):
    return TaggedResource("aws", ACCOUNT, f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/{rid}", tags(**kw))


class StaticSource:
    def __init__(self, items):
        self.items = items

    def list_resources(self):
        return list(self.items)


class BrokenSource:
    def list_resources(self):
        raise RuntimeError("AccessDenied")


# ---------------------------------------------------------------- parsing


@pytest.mark.parametrize("value,expected", [
    ("15m", timedelta(minutes=15)), ("8h", timedelta(hours=8)), ("3d", timedelta(days=3)),
    ("2w", timedelta(weeks=2)), (" 90D ", timedelta(days=90)),
])
def test_parse_ttl_valid(value, expected):
    assert parse_ttl(value) == expected


@pytest.mark.parametrize("value", ["", "8", "8 hours", "-1h", "0m", "14m", "91d", "1y", "1h30m", "8h;rm"])
def test_parse_ttl_rejects(value):
    with pytest.raises(TTLError):
        parse_ttl(value)


def test_parse_created_at_requires_timezone():
    assert parse_created_at("2026-11-19T05:30:00+05:30") == datetime(2026, 11, 19, 0, 0, tzinfo=UTC)
    with pytest.raises(ValueError, match="timezone"):
        parse_created_at("2026-11-19T00:00:00")
    with pytest.raises(ValueError):
        parse_created_at("yesterday")


# --------------------------------------------------------------- grouping


def test_groups_resources_into_one_stack():
    g = group_stacks([res("i-1"), res("i-2")])
    assert len(g.stacks) == 1 and not g.skipped
    s = g.stacks[0]
    assert s.key == f"aws:{ACCOUNT}:control-tower-standard:feature-42"
    assert s.expires_at == datetime(2026, 11, 19, 8, 0, tzinfo=UTC)
    assert len(s.resource_ids) == 2


def test_tag_keys_are_case_insensitive():
    r = TaggedResource("azure", "sub", "/x", {"lifecycleTTL": "8h", "createdat": CREATED,
                                                "opliazone": "z1", "OPLIABLUEPRINT": "alz-hybrid"})
    assert len(group_stacks([r]).stacks) == 1


@pytest.mark.parametrize("env", ["prod", "PRODUCTION", "prd"])
def test_production_stacks_are_protected_even_if_one_resource_says_so(env):
    g = group_stacks([res("i-1"), res("i-2", Environment=env)])
    assert g.stacks == [] and "protected" in g.skipped[0][1]


def test_inconsistent_tags_skip_whole_stack():
    g = group_stacks([res("i-1", ttl="8h"), res("i-2", ttl="2d")])
    assert g.stacks == [] and "inconsistent" in g.skipped[0][1]


def test_missing_and_invalid_tags_are_skipped_not_expired():
    no_zone = TaggedResource("aws", ACCOUNT, "arn:x", {"LifecycleTTL": "1h", "CreatedAt": CREATED})
    g = group_stacks([no_zone, res("i-1", ttl="forever"), res("i-2", zone="z2", created="garbage")])
    assert g.stacks == []
    assert len(g.skipped) == 3


# ---------------------------------------------------------------- manager


def manager(gate, items, now, **kw):
    return IaCLifecycleManager(gate=gate, sources=[StaticSource(items)], target_cicd="github",
                               allowed_blueprints=ALLOWED, clock=lambda: now, **kw)


def test_expired_stack_gets_destroy_proposal(gate):
    now = datetime(2026, 11, 19, 9, 0, tzinfo=UTC)  # created 00:00 + 8h = 08:00 -> expired
    report = manager(gate, [res("i-1"), res("i-2")], now).run_once()
    assert len(report.proposed) == 1
    p = gate.get(report.proposed[0])
    assert p.action_type == ACTION_IAC_DESTROY and p.status is ProposalStatus.PENDING
    assert p.payload["request"]["operation"] == "destroy"
    assert p.payload["request"]["zone_name"] == "feature-42"
    assert p.payload["resource_count"] == 2
    assert "overdue by 1:00:00" in p.reason


def test_not_expired_stack_is_left_alone(gate):
    now = datetime(2026, 11, 19, 7, 59, tzinfo=UTC)
    report = manager(gate, [res("i-1")], now).run_once()
    assert report.proposed == [] and report.not_expired == 1


def test_repeat_runs_do_not_duplicate(gate):
    now = datetime(2026, 11, 19, 9, 0, tzinfo=UTC)
    first = manager(gate, [res("i-1")], now).run_once()
    second = manager(gate, [res("i-1")], now).run_once()
    assert second.proposed == [] and second.already_proposed == first.proposed


def test_expired_proposal_is_reproposed(gate, clock):
    # Proposal TTL is 60 min (conftest). Nobody acts; on the next run a new attempt is created.
    clock.now = datetime(2026, 11, 19, 9, 0, tzinfo=UTC)
    first = manager(gate, [res("i-1")], clock.now).run_once()
    clock.advance(minutes=61)
    second = manager(gate, [res("i-1")], clock.now).run_once()
    assert len(second.proposed) == 1 and second.proposed != first.proposed
    assert gate.get(first.proposed[0]).status is ProposalStatus.EXPIRED


def test_rejected_teardown_is_respected(gate):
    now = datetime(2026, 11, 19, 9, 0, tzinfo=UTC)
    first = manager(gate, [res("i-1")], now).run_once()
    gate.reject(first.proposed[0], "lead", "still testing")
    second = manager(gate, [res("i-1")], now).run_once()
    assert second.proposed == [] and "rejected by lead" in second.skipped[0][1]
    # Re-tagging (new CreatedAt = new incarnation) re-arms it.
    third = manager(gate, [res("i-1", created="2026-11-19T00:30:00Z")], now).run_once()
    assert len(third.proposed) == 1


def test_one_failing_source_does_not_stop_others(gate):
    now = datetime(2026, 11, 19, 9, 0, tzinfo=UTC)
    m = IaCLifecycleManager(gate=gate, sources=[BrokenSource(), StaticSource([res("i-1")])],
                            target_cicd="github", allowed_blueprints=ALLOWED, clock=lambda: now)
    report = m.run_once()
    assert len(report.proposed) == 1 and "AccessDenied" in report.source_errors[0]


def test_unsafe_or_unknown_values_are_skipped(gate):
    now = datetime(2026, 11, 19, 9, 0, tzinfo=UTC)
    report = manager(gate, [res("i-1", zone="z;rm -rf"), res("i-2", zone="ok", blueprint="unknown-bp")],
                     now).run_once()
    assert report.proposed == []
    reasons = " ".join(r for _, r in report.skipped)
    assert "not safe" in reasons and "not in allowed list" in reasons


# ---------------------------------------------------------------- sources


def test_aws_source_with_moto(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "t", "AWS_SECRET_ACCESS_KEY": "t", "AWS_DEFAULT_REGION": "us-east-1"}.items():
        monkeypatch.setenv(k, v)
    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1, TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": k, "Value": v} for k, v in tags().items()]}])
        ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1)  # untagged: ignored
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="feature-42-artifacts")
        s3.put_bucket_tagging(Bucket="feature-42-artifacts",
                              Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in tags().items()]})
        src = AwsTaggedSource(["us-east-1"], client_factory=lambda svc, region: boto3.client(svc, region_name=region))
        found = src.list_resources()
    arns = sorted(r.resource_id for r in found)
    assert len(found) == 2, arns
    assert any(":instance/" in a for a in arns) and any(a.startswith("arn:aws:s3:::") for a in arns)
    accounts = {r.account_id for r in found}
    assert len(accounts) == 1 and accounts.pop().isdigit()  # S3 ARN has no account -> caller account used
    assert len(group_stacks(found).stacks) == 1


def test_azure_source_uses_tag_filter():
    seen = {}

    class FakeResources:
        def list(self, filter):
            seen["filter"] = filter
            return [SimpleNamespace(id="/subscriptions/s/rg/x", tags=tags(blueprint="alz-hybrid"))]

    src = AzureTaggedSource(["sub-1"], client_factory=lambda sub: SimpleNamespace(resources=FakeResources()))
    found = src.list_resources()
    assert seen["filter"] == "tagName eq 'LifecycleTTL'"
    assert found[0].cloud == "azure" and found[0].account_id == "sub-1"


# --------------------------------------------- destroy routing per CI/CD driver
SECRETS = StaticSecretProvider({"github_dispatch_token": "g", "gitlab_trigger_token": "l",
                                "jenkins_user": "u", "jenkins_api_token": "t"})
DESTROY = RemediationRequest(zone_name="feature-42", cloud="aws", account_id=ACCOUNT,
                             blueprint="control-tower-standard", correlation_id="ttl-abc", operation="destroy")


@respx.mock
def test_github_destroy_uses_separate_event_type():
    route = respx.post("https://api.github.com/repos/acme/infra/dispatches").mock(return_value=httpx.Response(204))
    drv = build_cicd_driver("github", CICDTarget(github_repository="acme/infra"), SECRETS, ResilientClient())
    assert "DESTROY" in drv.describe(DESTROY)
    drv.trigger(DESTROY)
    body = json.loads(route.calls.last.request.content)
    assert body["event_type"] == "oplia-ttl-destroy" and body["client_payload"]["operation"] == "destroy"


@respx.mock
def test_gitlab_and_jenkins_pass_operation_variable():
    gl = respx.post("https://gitlab.com/api/v4/projects/7/trigger/pipeline").mock(
        return_value=httpx.Response(201, json={"id": 1}))
    build_cicd_driver("gitlab", CICDTarget(gitlab_project_id="7"), SECRETS, ResilientClient()).trigger(DESTROY)
    assert parse_qs(gl.calls.last.request.content.decode())["variables[OPERATION]"] == ["destroy"]

    respx.get("https://ci.example.com/crumbIssuer/api/json").mock(return_value=httpx.Response(404))
    jk = respx.post("https://ci.example.com/job/infra/buildWithParameters").mock(return_value=httpx.Response(201))
    build_cicd_driver("jenkins", CICDTarget(jenkins_url="https://ci.example.com", jenkins_job="infra"),
                      SECRETS, ResilientClient()).trigger(DESTROY)
    assert parse_qs(jk.calls.last.request.content.decode())["OPERATION"] == ["destroy"]


def test_github_driver_refuses_same_event_for_both_operations():
    with pytest.raises(ValueError, match="different"):
        build_cicd_driver("github", CICDTarget(github_repository="a/b", github_event_type="x",
                                               github_destroy_event_type="x"), SECRETS, ResilientClient())


def test_old_proposals_without_operation_still_mean_remediate():
    legacy = {"zone_name": "z", "cloud": "aws", "account_id": ACCOUNT, "blueprint": "alz-hybrid",
              "correlation_id": "c"}
    assert RemediationRequest(**legacy).operation == "remediate"


@respx.mock
def test_end_to_end_ttl_teardown_through_gate(gate):
    route = respx.post("https://api.github.com/repos/acme/infra/dispatches").mock(return_value=httpx.Response(204))
    now = datetime(2026, 11, 19, 9, 0, tzinfo=UTC)
    pid = manager(gate, [res("i-1")], now).run_once().proposed[0]
    ex = PipelineDispatchExecutor(lambda n: build_cicd_driver(n, CICDTarget(github_repository="acme/infra"),
                                                              SECRETS, ResilientClient()))
    gate.approve(pid, "platform-lead")
    assert gate.execute(pid, ex, "operator").status is ProposalStatus.EXECUTED
    assert json.loads(route.calls.last.request.content)["event_type"] == "oplia-ttl-destroy"
