from __future__ import annotations

from datetime import UTC, datetime, timedelta

import boto3
import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from moto import mock_aws

from oplia_ctl.api import create_app
from oplia_ctl.auth import OIDCVerifier
from oplia_ctl.cloud.power import IBM_IAM_URL, ComputePowerExecutor, parse_target
from oplia_ctl.finops.compliance import TagPolicy
from oplia_ctl.finops.inventory import Resource
from oplia_ctl.http import ResilientClient
from oplia_ctl.inventory.scanner import InventoryScanner, list_instances, list_scans
from oplia_ctl.secrets import StaticSecretProvider
from tests.test_api import AUD, ISS, KEY, SECRETS, bearer

AZ_VM = ("/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-prod"
         "/providers/Microsoft.Compute/virtualMachines/vm-web-1")
GCP_VM = "//compute.googleapis.com/projects/acme-prod-123/zones/asia-south1-a/instances/web-1"
IBM_VM = ("crn:v1:bluemix:public:is:us-south-1:a/0123456789abcdef0123456789abcdef::instance:"
          "0717_11111111-2222-3333-4444-555555555555")
TAGS = {"Owner": "team-a", "CostCenter": "cc1", "Environment": "prod"}


class FakeSource:
    def __init__(self, name, scope, resources, fail=False):
        self.name, self._scope, self.resources, self.fail = name, scope, resources, fail

    def scopes(self):
        return [self._scope]

    def list_resources(self):
        if self.fail:
            raise RuntimeError("cloud API down")
        return iter(self.resources)


def aws_vm(i, state="running", tags=TAGS):
    return Resource("aws", "123456789012", "ap-south-1", "compute", "ec2:instance",
                    f"arn:aws:ec2:ap-south-1:123456789012:instance/i-0000000000000000{i}", f"web-{i}",
                    dict(tags), size="t3.medium", state=state)


class Clock:
    def __init__(self):
        self.now = datetime(2026, 11, 20, 10, 0, tzinfo=UTC)

    def __call__(self):
        return self.now


def test_scan_keeps_compute_only_and_tracks_new_and_gone(session_factory):
    clock = Clock()
    disk = Resource("aws", "123456789012", "ap-south-1", "storage", "ec2:volume", "arn:...:volume/vol-1", "d", {})
    src = FakeSource("aws", "123456789012", [aws_vm(1), aws_vm(2, "stopped", {"Owner": "x"}), disk])
    scanner = InventoryScanner(session_factory, [src], TagPolicy(), clock=clock)
    r1 = scanner.run()
    assert (r1["instances_seen"], r1["new_instances"], r1["gone_instances"]) == (2, 2, 0)
    rows = list_instances(session_factory)
    assert [(r["name"], r["state"], r["size"], r["tag_compliant"]) for r in rows] == [
        ("web-1", "running", "t3.medium", True), ("web-2", "stopped", "t3.medium", False)]
    assert set(rows[1]["tag_issues"]) == {"CostCenter", "Environment"}

    clock.now += timedelta(hours=1)
    src.resources = [aws_vm(1)]
    r2 = scanner.run()
    assert (r2["new_instances"], r2["gone_instances"]) == (0, 1)
    assert [r["name"] for r in list_instances(session_factory)] == ["web-1"]
    gone = [r for r in list_instances(session_factory, include_gone=True) if r["gone_at"]]
    assert [r["name"] for r in gone] == ["web-2"]
    assert [s["gone_instances"] for s in list_scans(session_factory)] == [1, 0]


def test_failing_source_never_marks_its_machines_gone(session_factory):
    clock = Clock()
    src = FakeSource("aws", "123456789012", [aws_vm(1)])
    scanner = InventoryScanner(session_factory, [src], TagPolicy(), clock=clock)
    scanner.run()
    src.fail = True
    report = scanner.run()
    assert report["gone_instances"] == 0 and report["source_errors"][0]["source"] == "aws"
    assert [r["name"] for r in list_instances(session_factory)] == ["web-1"]


def test_filters(session_factory):
    gcp = Resource("gcp", "projects/acme-prod-123", "asia-south1-a", "compute", "compute.googleapis.com/Instance",
                   GCP_VM, "web-1", {}, {"owner": "a", "costcenter": "b", "environment": "prod"}, state="RUNNING")
    InventoryScanner(session_factory, [FakeSource("aws", "123456789012", [aws_vm(1), aws_vm(2, "stopped")]),
                                       FakeSource("gcp", "projects/acme-prod-123", [gcp])], TagPolicy()).run()
    assert {r["cloud"] for r in list_instances(session_factory, cloud="gcp")} == {"gcp"}
    assert [r["name"] for r in list_instances(session_factory, state="stopped")] == ["web-2"]
    assert list_instances(session_factory, region="ap-south-1", cloud="gcp") == []


@pytest.mark.parametrize("cloud,rid,region", [
    ("aws", "arn:aws:ec2:ap-south-1:123456789012:instance/i-0123456789abcdef0", "ap-south-1"),
    ("azure", AZ_VM, ""), ("gcp", GCP_VM, "asia-south1"), ("ibm", IBM_VM, "us-south")])
def test_parse_target(cloud, rid, region):
    assert parse_target(cloud, rid).region == region


@pytest.mark.parametrize("cloud,rid", [
    ("aws", "arn:aws:ec2:ap-south-1:123456789012:volume/vol-1"),
    ("aws", "arn:aws:ec2:ap-south-1:123456789012:instance/i-0123456789abcdef0;rm"),
    ("azure", AZ_VM.replace("virtualMachines", "disks")),
    ("gcp", GCP_VM + "/../x"), ("ibm", "crn:v1:bluemix:public:is:us-south-1:a/x::volume:1"), ("oci", "x")])
def test_parse_target_rejects(cloud, rid):
    with pytest.raises(ValueError):
        parse_target(cloud, rid)


@mock_aws
def test_aws_stop_and_start_with_moto():
    ec2 = boto3.client("ec2", region_name="ap-south-1")
    iid = ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
    ex = ComputePowerExecutor()
    payload = {"cloud": "aws", "resource_id": f"arn:aws:ec2:ap-south-1:123456789012:instance/{iid}",
               "operation": "stop"}
    assert "stop aws instance" in ex.describe(payload)
    out = ex(payload)
    assert out["previous_state"] == "running" and out["current_state"] in ("stopping", "stopped")
    assert ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]["State"]["Name"] == "stopped"
    assert ex(payload | {"operation": "start"})["current_state"] in ("pending", "running")


class _Poller:
    def __init__(self, log, what):
        self.log, self.what = log, what

    def result(self, timeout=None):
        self.log.append((self.what, timeout))


def test_azure_stop_deallocates():
    log = []

    class Vms:
        def begin_deallocate(self, rg, vm):
            log.append(("deallocate", rg, vm))
            return _Poller(log, "wait")

        def begin_start(self, rg, vm):
            raise AssertionError("not expected")

        def instance_view(self, rg, vm):
            class S:
                code = "PowerState/deallocated"
            return type("V", (), {"statuses": [type("P", (), {"code": "ProvisioningState/succeeded"})(), S()]})()

    class Compute:
        virtual_machines = Vms()

    subs = []
    ex = ComputePowerExecutor(azure_factory=lambda sub: subs.append(sub) or Compute(), timeout_seconds=30)
    payload = {"cloud": "azure", "resource_id": AZ_VM, "operation": "stop"}
    assert ex.describe(payload).startswith("deallocate azure instance")
    assert ex(payload)["power_state"] == "PowerState/deallocated"
    assert subs == ["11111111-1111-1111-1111-111111111111"]
    assert log == [("deallocate", "rg-prod", "vm-web-1"), ("wait", 30)]


def test_gcp_start_waits_and_reports_status():
    calls = []

    class Instances:
        def start(self, **kw):
            calls.append(("start", kw))
            return _Poller(calls, "wait")

        def get(self, **kw):
            return type("I", (), {"status": "RUNNING"})()

    out = ComputePowerExecutor(gcp_factory=Instances)({"cloud": "gcp", "resource_id": GCP_VM, "operation": "start"})
    assert out["status"] == "RUNNING"
    assert calls[0] == ("start", {"project": "acme-prod-123", "zone": "asia-south1-a", "instance": "web-1"})


@respx.mock
def test_ibm_stop_calls_vpc_action():
    respx.post(IBM_IAM_URL).mock(return_value=httpx.Response(200, json={"access_token": "iam-tok"}))
    act = respx.post("https://us-south.iaas.cloud.ibm.com/v1/instances/"
                     "0717_11111111-2222-3333-4444-555555555555/actions").mock(
        return_value=httpx.Response(201, json={"id": "act-1", "status": "pending"}))
    ex = ComputePowerExecutor(secrets=StaticSecretProvider({"ibm_cloud_api_key": "k"}),
                              client=ResilientClient(sleep=lambda _s: None))
    out = ex({"cloud": "ibm", "resource_id": IBM_VM, "operation": "stop"})
    assert out == {"cloud": "ibm", "instance_id": "0717_11111111-2222-3333-4444-555555555555", "operation": "stop",
                   "action_id": "act-1", "action_status": "pending"}
    req = act.calls.last.request
    assert req.url.params["version"] and req.url.params["generation"] == "2"
    assert req.headers["Authorization"] == "Bearer iam-tok" and b'"type":"stop"' in req.content.replace(b" ", b"")


def _app(gate, session_factory, executor):
    return TestClient(create_app(
        gate=gate, secrets=SECRETS,
        verifier=OIDCVerifier(issuer=ISS, audience=AUD, jwks_url="", key_resolver=lambda _t: KEY.public_key()),
        executors={"compute.power": executor}, webhook_secret_name="webhook_hmac_secret",
        webhook_max_skew_seconds=300, allowed_blueprints=["control-tower-standard"],
        approver_role="oplia-approver", operator_role="oplia-operator", inventory_sf=session_factory))


@mock_aws
def test_api_power_goes_through_the_gate(gate, session_factory):
    ec2 = boto3.client("ec2", region_name="ap-south-1")
    iid = ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
    vm = aws_vm(1)
    vm = Resource(vm.cloud, vm.scope, vm.region, vm.category, vm.resource_type,
                  f"arn:aws:ec2:ap-south-1:123456789012:instance/{iid}", "web-1", dict(TAGS), state="running")
    InventoryScanner(session_factory, [FakeSource("aws", "123456789012", [vm])], TagPolicy()).run()
    client = _app(gate, session_factory, ComputePowerExecutor())
    op = bearer("bob", "oplia-operator")
    assert client.get("/inventory/instances").status_code == 401
    inst = client.get("/inventory/instances", params={"cloud": "aws"}, headers=op).json()[0]
    assert client.get("/inventory/instances", params={"cloud": "oci"}, headers=op).status_code == 400
    assert client.post(f"/inventory/instances/{inst['id']}/power", json={"operation": "reboot", "reason": "testing"},
                       headers=op).status_code == 422
    assert client.post("/inventory/instances/nope/power", json={"operation": "stop", "reason": "testing"},
                       headers=op).status_code == 404
    p = client.post(f"/inventory/instances/{inst['id']}/power", json={"operation": "stop", "reason": "cost saving"},
                    headers=op).json()
    assert p["status"] == "PENDING" and p["action_type"] == "compute.power" and p["requested_by"] == "bob"
    # nothing happened yet
    assert ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]["State"]["Name"] == "running"
    approved = client.post(f"/proposals/{p['id']}/approve", json={}, headers=bearer("alice", "oplia-approver"))
    assert approved.status_code == 200
    done = client.post(f"/proposals/{p['id']}/execute", headers=op).json()
    assert done["status"] == "EXECUTED", done
    assert ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]["State"]["Name"] == "stopped"


def test_inventory_not_configured_is_503(gate, session_factory):
    client = TestClient(create_app(
        gate=gate, secrets=SECRETS,
        verifier=OIDCVerifier(issuer=ISS, audience=AUD, jwks_url="", key_resolver=lambda _t: KEY.public_key()),
        executors={}, webhook_secret_name="webhook_hmac_secret", webhook_max_skew_seconds=300,
        allowed_blueprints=["control-tower-standard"], approver_role="oplia-approver", operator_role="oplia-operator"))
    r = client.get("/inventory/instances", headers=bearer("bob", "oplia-operator"))
    assert r.status_code == 503
    assert client.get("/me", headers=bearer("bob", "oplia-operator")).json()["features"]["inventory"] is False
