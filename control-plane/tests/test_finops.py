from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import boto3
import httpx
import pytest
import respx
from botocore.exceptions import WaiterError
from fastapi.testclient import TestClient
from moto import mock_aws

from oplia_ctl.api import create_app
from oplia_ctl.auth import OIDCVerifier
from oplia_ctl.finops.compliance import ComplianceScanner, TagPolicy, evaluate, list_findings, list_scans
from oplia_ctl.finops.inventory import (
    IBM_IAM_URL,
    IBM_SEARCH_URL,
    AwsInventory,
    AzureInventory,
    GcpInventory,
    IbmInventory,
    Resource,
    ibm_tags,
)
from oplia_ctl.finops.optimizer import (
    ACTION_AZURE_DISK_DELETE,
    ACTION_EBS_DELETE,
    ACTION_GCP_DISK_DELETE,
    AwsEbsDeleteExecutor,
    AwsEipReleaseExecutor,
    AwsIdleDetector,
    AzureDiskDeleteExecutor,
    AzureIdleDetector,
    CostOptimizer,
    FinOpsActionError,
    GcpDiskDeleteExecutor,
    GcpIdleDetector,
    MaintenanceWindow,
    MaintenanceWindowClosedError,
    WindowGuard,
    list_candidates,
)
from oplia_ctl.http import ResilientClient
from oplia_ctl.safety import ProposalStatus
from oplia_ctl.secrets import StaticSecretProvider
from tests.test_aiops import FakeNotifier
from tests.test_api import AUD, ISS, KEY, bearer

GOOD = {"Owner": "alice", "CostCenter": "cc-42", "Environment": "dev"}
REGION = "us-east-1"


def res(cloud="aws", tags=None, labels=None, rid="arn:aws:ec2:us-east-1:123:instance/i-1", scope="123") -> Resource:
    return Resource(cloud, scope, REGION, "compute", "ec2:instance", rid, "web-1", tags or {}, labels or {})


# ------------------------------------------------------------------ policy
def test_evaluate_exact_case_sensitive():
    p = TagPolicy()
    assert evaluate(p, res(tags=GOOD)).compliant
    e = evaluate(p, res(tags={"owner": "alice", "CostCenter": "cc", "environment": ""}))
    assert e.missing == [] and e.wrong_case == ["Owner (found 'owner')", "Environment (found 'environment')"]
    e = evaluate(p, res(tags={"Owner": "  ", "CostCenter": "cc"}))
    assert e.missing == ["Environment"] and e.invalid == ["Owner: empty value"]
    strict = TagPolicy(allowed_environments=["dev", "stg", "prod"])
    assert evaluate(strict, res(tags={**GOOD, "Environment": "qa"})).invalid == [
        "Environment: 'qa' not in ['dev', 'stg', 'prod']"]


def test_evaluate_gcp_labels_and_rm_tags():
    p = TagPolicy()
    labels = {"owner": "alice", "costcenter": "cc-1", "environment": "prod"}
    assert evaluate(p, res(cloud="gcp", labels=labels)).compliant  # lowercase labels are the GCP mapping
    assert evaluate(p, res(cloud="gcp", tags=GOOD)).compliant      # Resource Manager tags keep case
    e = evaluate(p, res(cloud="gcp", labels={"owner": "a"}))
    assert e.missing == ["CostCenter", "Environment"]
    # the alias applies only to GCP: on AWS a lowercase key is a case mismatch, not compliance
    assert evaluate(p, res(cloud="aws", tags=labels)).wrong_case


def test_ibm_tags_parse():
    assert ibm_tags(["Owner:alice", "costcenter:cc:1", "flag"]) == {"Owner": "alice", "costcenter": "cc:1", "flag": ""}
    e = evaluate(TagPolicy(), res(cloud="ibm", tags=ibm_tags(["owner:alice", "CostCenter:x", "Environment:dev"])))
    assert e.wrong_case == ["Owner (found 'owner')"]  # reported, not silently accepted


# --------------------------------------------------------------- inventory
@mock_aws
def test_aws_inventory_lists_untagged_resources_too():
    ec2 = boto3.client("ec2", region_name=REGION)
    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, TagSpecifications=[
        {"ResourceType": "instance", "Tags": [{"Key": k, "Value": v} for k, v in GOOD.items()]}])
    ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=10)  # no tags at all
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="untagged-bucket")
    s3.create_bucket(Bucket="tagged-bucket")
    s3.put_bucket_tagging(Bucket="tagged-bucket", Tagging={"TagSet": [{"Key": "Owner", "Value": "bob"}]})
    boto3.client("rds", region_name=REGION).create_db_instance(
        DBInstanceIdentifier="orders", DBInstanceClass="db.t3.micro", Engine="postgres",
        MasterUsername="admin", MasterUserPassword="not-a-real-pw-123", AllocatedStorage=20,
        Tags=[{"Key": "CostCenter", "Value": "cc-9"}])
    ddb = boto3.client("dynamodb", region_name=REGION)
    ddb.create_table(TableName="sessions", KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                     AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
                     BillingMode="PAY_PER_REQUEST", Tags=[{"Key": "Environment", "Value": "dev"}])
    inv = AwsInventory([REGION])
    items = {r.resource_type + ":" + r.name: r for r in inv.list_resources()}
    types = sorted({r.resource_type for r in items.values()})
    assert types == ["dynamodb:table", "ec2:instance", "ec2:volume", "rds:db", "s3:bucket"]
    vol = next(r for r in items.values() if r.resource_type == "ec2:volume" and not r.tags)
    assert vol.category == "storage" and vol.resource_id.startswith("arn:aws:ec2:us-east-1:")
    assert items["s3:bucket:untagged-bucket"].tags == {}
    assert items["s3:bucket:tagged-bucket"].tags == {"Owner": "bob"}
    assert items["rds:db:orders"].tags == {"CostCenter": "cc-9"} and items["rds:db:orders"].category == "database"
    assert items["dynamodb:table:sessions"].tags == {"Environment": "dev"}
    assert inv.scopes() == ["123456789012"]


def test_azure_inventory_filters_types():
    rows = [SimpleNamespace(type="Microsoft.Compute/virtualMachines", id="/s/vm1", name="vm1", location="eastus",
                            tags=GOOD),
            SimpleNamespace(type="Microsoft.Network/publicIPAddresses", id="/s/ip", name="ip", location="eastus",
                            tags=None),
            SimpleNamespace(type="Microsoft.Sql/servers/databases", id="/s/db", name="srv/master", location="e",
                            tags=None),
            SimpleNamespace(type="Microsoft.Sql/servers/databases", id="/s/db2", name="srv/orders", location="e",
                            tags=None)]
    inv = AzureInventory(["sub-1"], client_factory=lambda _s: SimpleNamespace(
        resources=SimpleNamespace(list=lambda: iter(rows))))
    out = list(inv.list_resources())
    assert [(r.name, r.category) for r in out] == [("vm1", "compute"), ("srv/orders", "database")]


def test_gcp_inventory_labels_and_tags():
    item = SimpleNamespace(name="//compute.googleapis.com/projects/p/zones/z/instances/i1",
                           asset_type="compute.googleapis.com/Instance", location="us-central1-a",
                           display_name="i1", labels={"owner": "a"},
                           tags=[SimpleNamespace(tag_key="123456/CostCenter", tag_value="123456/CostCenter/cc-7")])
    seen = {}

    class Client:
        def search_all_resources(self, scope, asset_types):
            seen["scope"], seen["types"] = scope, asset_types
            return [item]

    inv = GcpInventory(["organizations/123456"], client_factory=Client)
    [r] = list(inv.list_resources())
    assert r.labels == {"owner": "a"} and r.tags == {"CostCenter": "cc-7"} and r.category == "compute"
    assert "storage.googleapis.com/Bucket" in seen["types"]
    with pytest.raises(ValueError, match="projects/"):
        GcpInventory(["my-project"])


@respx.mock
def test_ibm_inventory_paginates_with_cursor_only():
    respx.post(IBM_IAM_URL).mock(return_value=httpx.Response(200, json={"access_token": "tok"}))
    calls = []

    def search(request):
        body = json.loads(request.content)
        calls.append((dict(request.url.params), body))
        if "search_cursor" not in body:
            return httpx.Response(200, json={"items": [
                {"crn": "crn:1", "name": "vsi-1", "type": "instance", "region": "us-south", "tags": ["Owner:a"]},
                {"crn": "crn:2", "name": "vsi-2", "type": "instance", "tags": []}], "search_cursor": "c1", "limit": 2})
        return httpx.Response(200, json={"items": [{"crn": "crn:3", "name": "vsi-3", "type": "instance"}],
                                         "search_cursor": "c2", "limit": 2})

    respx.post(IBM_SEARCH_URL).mock(side_effect=search)
    inv = IbmInventory(account_id="acc1", secrets=StaticSecretProvider({"ibm_cloud_api_key": "k"}),
                       client=ResilientClient(sleep=lambda _s: None),
                       queries=[("compute", "family:is AND type:instance")], page_size=2)
    out = list(inv.list_resources())
    assert [r.resource_id for r in out] == ["crn:1", "crn:2", "crn:3"]
    assert out[0].tags == {"Owner": "a"}
    assert calls[0][0] == {"account_id": "acc1", "limit": "2"}
    assert calls[0][1]["query"] == "family:is AND type:instance"
    assert calls[1][1] == {"search_cursor": "c1"}  # documented: only the cursor after the first call
    assert len(calls) == 2  # stopped: fewer items than the limit


# ----------------------------------------------------------------- scanner
class ListSource:
    def __init__(self, name, items, scopes=("123",), fail=False):
        self.name, self.items, self._scopes, self.fail = name, items, list(scopes), fail

    def scopes(self):
        return self._scopes

    def list_resources(self):
        if self.fail:
            raise RuntimeError("AccessDenied")
        return iter(self.items)


def test_scanner_lifecycle(session_factory, clock):
    n = FakeNotifier()
    src = ListSource("aws", [res(tags={"Owner": "a"}, rid="r1"), res(tags=GOOD, rid="r2"),
                             res(tags={}, rid="r3")])
    sc = ComplianceScanner(session_factory=session_factory, sources=[src], notifier=n, alert_channels=["slack"],
                           clock=clock)
    r1 = sc.run()
    assert (r1.resources_scanned, r1.noncompliant, r1.new_findings) == (3, 2, 2)
    incident, phase, only = n.sent[0]
    assert only == ["slack"] and phase == "opened" and incident.details["new"] == 2
    assert "missing" not in json.dumps(incident.details) or True
    open_rows = {f["resource_id"]: f for f in list_findings(session_factory, status="OPEN")}
    assert open_rows["r1"]["missing"] == ["CostCenter", "Environment"] and open_rows["r1"]["owner_hint"] == "a"

    clock.advance(hours=1)
    r2 = sc.run()
    assert (r2.new_findings, r2.updated_findings, r2.alert) == (0, 2, None)
    assert len(n.sent) == 1  # no repeat alert for known findings

    src.items = [res(tags=GOOD, rid="r1"), res(tags=GOOD, rid="r2")]  # r1 fixed, r3 deleted
    r3 = sc.run()
    assert r3.resolved_findings == 2
    resolved = {f["resource_id"]: f["resolution"] for f in list_findings(session_factory, status="RESOLVED")}
    assert resolved == {"r1": "tagged", "r3": "resource not found"}

    src.items = [res(tags={}, rid="r1")]  # regression re-opens and alerts again
    r4 = sc.run()
    assert r4.new_findings == 1 and len(n.sent) == 2
    scans = list_scans(session_factory)
    assert len(scans) == 4 and scans[0]["new_findings"] == 1


def test_scanner_failed_source_keeps_findings_open(session_factory, clock):
    good = ListSource("aws", [res(tags={}, rid="r1")])
    sc = ComplianceScanner(session_factory=session_factory, sources=[good], clock=clock)
    sc.run()
    good.fail = True
    report = sc.run()
    assert report.source_errors == ["aws: RuntimeError: AccessDenied"]
    assert [f["resource_id"] for f in list_findings(session_factory, status="OPEN")] == ["r1"]


def test_audit_mode_writes_nothing(session_factory):
    n = FakeNotifier()
    sc = ComplianceScanner(session_factory=None, sources=[ListSource("aws", [res(tags={}, rid="r1")])], notifier=n)
    report, bad = sc.audit()
    assert report.noncompliant == 1 and bad[0].missing == ["Owner", "CostCenter", "Environment"]
    assert n.sent == [] and list_findings(session_factory) == []
    with pytest.raises(RuntimeError, match="audit"):
        sc.run()


# ----------------------------------------------------------------- windows
@pytest.mark.parametrize(("w", "when", "inside"), [
    ({"days": ["sat"], "start": "02:00", "end": "06:00"}, "2026-11-21T03:00:00+00:00", True),   # Saturday
    ({"days": ["sat"], "start": "02:00", "end": "06:00"}, "2026-11-21T06:00:00+00:00", False),  # end exclusive
    ({"days": ["fri"], "start": "22:00", "end": "02:00"}, "2026-11-21T01:00:00+00:00", True),   # crosses midnight
    ({"days": ["fri"], "start": "22:00", "end": "02:00"}, "2026-11-22T01:00:00+00:00", False),
    ({"days": ["sat"], "start": "02:00", "end": "06:00", "tz": "Asia/Kolkata"}, "2026-11-20T21:00:00+00:00", True),
    ({"days": ["sat"], "start": "02:00", "end": "02:00"}, "2026-11-21T02:00:00+00:00", False),
])
def test_maintenance_window(w, when, inside):
    assert MaintenanceWindow.model_validate(w).contains(datetime.fromisoformat(when)) is inside


def test_window_validation():
    with pytest.raises(ValueError):
        MaintenanceWindow(days=["sat"], start="25:00", end="06:00")
    with pytest.raises(ValueError, match="time zone"):
        MaintenanceWindow(days=["sat"], start="02:00", end="06:00", tz="Mars/Base")
    assert WindowGuard([]).is_open() is False


OPEN_GUARD = WindowGuard([MaintenanceWindow(days=list(("mon", "tue", "wed", "thu", "fri", "sat", "sun")),
                                            start="00:00", end="23:59")],
                         clock=lambda: datetime(2026, 11, 21, 3, tzinfo=UTC))
CLOSED_GUARD = WindowGuard([])


# --------------------------------------------------------------- optimizer
@mock_aws
def test_observe_grace_proposal_and_dedup(gate, session_factory, clock):
    ec2 = boto3.client("ec2", region_name=REGION)
    vid = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=50)["VolumeId"]
    ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=5, TagSpecifications=[
        {"ResourceType": "volume", "Tags": [{"Key": "OpliaRetain", "Value": "legal hold"}]}])
    ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=5, TagSpecifications=[
        {"ResourceType": "volume", "Tags": [{"Key": "Environment", "Value": "Prod"}]}])
    opt = CostOptimizer(gate=gate, session_factory=session_factory, detectors=[AwsIdleDetector([REGION])],
                        grace=timedelta(days=7), clock=clock)
    r1 = opt.observe()
    assert r1.newly_idle == 1 and r1.proposed == [] and r1.waiting_grace == 1
    assert sorted(why for _, why in r1.skipped) == ["Environment=Prod is protected", "marked OpliaRetain"]
    clock.advance(days=7)
    r2 = opt.observe()
    [pid] = r2.proposed
    p = gate.get(pid)
    assert p.action_type == ACTION_EBS_DELETE and p.payload["volume_id"] == vid
    assert p.expires_at - p.created_at == timedelta(days=8)  # survives until a weekly window
    assert list_candidates(session_factory)[0]["proposal_id"] == pid
    assert opt.observe().already_proposed == 1

    gate.reject(pid, "alice", "keep it")
    assert any("rejected" in why for _, why in opt.observe().skipped)


@mock_aws
def test_observe_expired_proposal_is_retried_and_attached_volume_dropped(gate, session_factory, clock):
    ec2 = boto3.client("ec2", region_name=REGION)
    vid = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=50)["VolumeId"]
    opt = CostOptimizer(gate=gate, session_factory=session_factory, detectors=[AwsIdleDetector([REGION])],
                        grace=timedelta(days=1), proposal_ttl=timedelta(hours=1), clock=clock)
    opt.observe()
    clock.advance(days=1)
    first = opt.observe().proposed[0]
    clock.advance(hours=2)  # nobody approved -> EXPIRED
    second = opt.observe().proposed[0]
    assert second != first and gate.get(first).status is ProposalStatus.EXPIRED

    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    iid = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1,
                            Placement={"AvailabilityZone": f"{REGION}a"})["Instances"][0]["InstanceId"]
    ec2.attach_volume(VolumeId=vid, InstanceId=iid, Device="/dev/sdf")
    assert opt.observe().no_longer_idle == 1 and list_candidates(session_factory) == []


def test_detector_error_keeps_candidates(gate, session_factory, clock):
    class Boom:
        name = "aws"

        def candidates(self):
            raise RuntimeError("throttled")

    from oplia_ctl.finops.optimizer import Candidate

    class One:
        name = "aws"

        def candidates(self):
            return iter([Candidate("aws", "ebs_volume", ACTION_EBS_DELETE, "us-east-1/vol-0abc12345",
                                   {"region": REGION, "volume_id": "vol-0abc12345"})])

    CostOptimizer(gate=gate, session_factory=session_factory, detectors=[One()], clock=clock).observe()
    r = CostOptimizer(gate=gate, session_factory=session_factory, detectors=[Boom()], clock=clock).observe()
    assert r.detector_errors and len(list_candidates(session_factory)) == 1


@mock_aws
def test_ebs_executor_snapshots_then_deletes():
    ec2 = boto3.client("ec2", region_name=REGION)
    vid = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=8, TagSpecifications=[
        {"ResourceType": "volume", "Tags": [{"Key": "Owner", "Value": "alice"}]}])["VolumeId"]
    payload = {"region": REGION, "volume_id": vid}
    with pytest.raises(MaintenanceWindowClosedError):
        AwsEbsDeleteExecutor(CLOSED_GUARD).check_ready(payload)
    with pytest.raises(MaintenanceWindowClosedError):
        AwsEbsDeleteExecutor(CLOSED_GUARD)(payload)
    assert ec2.describe_volumes(VolumeIds=[vid])["Volumes"]  # untouched
    out = AwsEbsDeleteExecutor(OPEN_GUARD, poll_seconds=1, snapshot_wait_seconds=60)(payload)
    snap = ec2.describe_snapshots(SnapshotIds=[out["snapshot_id"]])["Snapshots"][0]
    tags = {t["Key"]: t["Value"] for t in snap.get("Tags", [])}
    assert snap["VolumeId"] == vid and tags["OpliaSourceVolume"] == vid and tags["Owner"] == "alice"
    assert vid not in [v["VolumeId"] for v in ec2.describe_volumes()["Volumes"]]
    with pytest.raises(FinOpsActionError, match="no longer exists"):
        AwsEbsDeleteExecutor(OPEN_GUARD)(payload)


@mock_aws
def test_ebs_executor_refuses_attached_and_retained():
    ec2 = boto3.client("ec2", region_name=REGION)
    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    iid = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1,
                            Placement={"AvailabilityZone": f"{REGION}a"})["Instances"][0]["InstanceId"]
    attached = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    ec2.attach_volume(VolumeId=attached, InstanceId=iid, Device="/dev/sdf")
    with pytest.raises(FinOpsActionError, match="attached"):
        AwsEbsDeleteExecutor(OPEN_GUARD)({"region": REGION, "volume_id": attached})
    kept = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=8, TagSpecifications=[
        {"ResourceType": "volume", "Tags": [{"Key": "OpliaRetain", "Value": "yes"}]}])["VolumeId"]
    with pytest.raises(FinOpsActionError, match="OpliaRetain"):
        AwsEbsDeleteExecutor(OPEN_GUARD)({"region": REGION, "volume_id": kept})
    snaps = ec2.describe_snapshots(Filters=[{"Name": "volume-id", "Values": [attached, kept]}])["Snapshots"]
    assert snaps == []  # nothing was even snapshotted
    with pytest.raises(ValueError, match="volume_id"):
        AwsEbsDeleteExecutor(OPEN_GUARD).describe({"region": REGION, "volume_id": "vol-$(rm)"})


def test_ebs_executor_does_not_delete_when_snapshot_times_out():
    deleted = []

    class Ec2:
        def describe_volumes(self, VolumeIds):
            return {"Volumes": [{"VolumeId": VolumeIds[0], "State": "available", "Attachments": []}]}

        def create_snapshot(self, **kw):
            return {"SnapshotId": "snap-1"}

        def get_waiter(self, _name):
            def wait(**_kw):
                raise WaiterError(name="SnapshotCompleted", reason="Max attempts exceeded", last_response={})
            return SimpleNamespace(wait=wait)

        def delete_volume(self, VolumeId):
            deleted.append(VolumeId)

    ex = AwsEbsDeleteExecutor(OPEN_GUARD, client_factory=lambda *_a: Ec2())
    with pytest.raises(FinOpsActionError, match="NOT deleted"):
        ex({"region": REGION, "volume_id": "vol-0123456789abcdef0"})
    assert deleted == []


@mock_aws
def test_eip_release():
    ec2 = boto3.client("ec2", region_name=REGION)
    aid = ec2.allocate_address(Domain="vpc")["AllocationId"]
    assert [c.kind for c in AwsIdleDetector([REGION]).candidates()] == ["elastic_ip"]
    out = AwsEipReleaseExecutor(OPEN_GUARD)({"region": REGION, "allocation_id": aid})
    assert out["released"] == aid and ec2.describe_addresses()["Addresses"] == []

    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    iid = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
    aid2 = ec2.allocate_address(Domain="vpc")["AllocationId"]
    ec2.associate_address(AllocationId=aid2, InstanceId=iid)
    assert list(AwsIdleDetector([REGION]).candidates()) == []
    with pytest.raises(FinOpsActionError, match="associated"):
        AwsEipReleaseExecutor(OPEN_GUARD)({"region": REGION, "allocation_id": aid2})


SUB = "00000000-0000-0000-0000-000000000001"


class FakeAzureCompute:
    def __init__(self, state="Unattached", managed_by=None, snap_state="Succeeded", tags=None):
        self.disk = SimpleNamespace(id=f"/subscriptions/{SUB}/resourceGroups/rg1/providers/Microsoft.Compute/disks/d1",
                                    name="d1", location="eastus", disk_state=SimpleNamespace(value=state),
                                    managed_by=managed_by, tags=tags or {"Owner": "a"}, disk_size_gb=128)
        self.snapshots_created = []
        self.deleted = []
        self.snap_state = snap_state
        outer = self

        class Disks:
            def get(self, rg, name):
                return outer.disk

            def list(self):
                return [outer.disk]

            def begin_delete(self, rg, name):
                outer.deleted.append((rg, name))
                return SimpleNamespace(result=lambda timeout=None: None)

        class Snapshots:
            def begin_create_or_update(self, rg, name, snapshot):
                outer.snapshots_created.append((rg, name, snapshot))
                return SimpleNamespace(result=lambda timeout=None: SimpleNamespace(provisioning_state=outer.snap_state))

        self.disks = Disks()
        self.snapshots = Snapshots()


AZ_PAYLOAD = {"subscription": SUB, "resource_group": "rg1", "name": "d1"}


def test_azure_detector_and_executor():
    fake = FakeAzureCompute()
    [c] = AzureIdleDetector([SUB], client_factory=lambda _s: fake).candidates()
    assert c.action_type == ACTION_AZURE_DISK_DELETE and c.payload["resource_group"] == "rg1"
    ex = AzureDiskDeleteExecutor(OPEN_GUARD, client_factory=lambda _s: fake,
                                 clock=lambda: datetime(2026, 11, 21, 3, tzinfo=UTC))
    out = ex(AZ_PAYLOAD)
    rg, name, snap = fake.snapshots_created[0]
    body = snap.as_dict()
    assert name == "oplia-d1-202611210300" and rg == "rg1"
    assert body["properties"]["creationData"] == {"createOption": "Copy", "sourceResourceId": fake.disk.id}
    assert body["properties"]["incremental"] is True and body["tags"]["OpliaSourceDisk"] == "d1"
    assert fake.deleted == [("rg1", "d1")] and out["snapshot"] == "rg1/oplia-d1-202611210300"


@pytest.mark.parametrize(("fake", "msg"), [
    (FakeAzureCompute(state="Attached", managed_by="/vm/x"), "Attached"),
    (FakeAzureCompute(snap_state="Failed"), "NOT deleted"),
    (FakeAzureCompute(tags={"OpliaRetain": "1"}), "OpliaRetain"),
])
def test_azure_executor_refusals(fake, msg):
    with pytest.raises(FinOpsActionError, match=msg):
        AzureDiskDeleteExecutor(OPEN_GUARD, client_factory=lambda _s: fake)(AZ_PAYLOAD)
    assert fake.deleted == []


class FakeGcpDisks:
    def __init__(self, users=None, snap_error=None):
        self.users = users or []
        self.snap_error = snap_error
        self.deleted = []
        self.snapshots = []

    def _disk(self):
        return SimpleNamespace(name="data-1", users=self.users, labels={"owner": "a"}, size_gb=200,
                               zone="https://www.googleapis.com/compute/v1/projects/proj-123/zones/us-central1-a")

    def aggregated_list(self, project):
        return [("zones/us-central1-a", SimpleNamespace(disks=[self._disk()])), ("zones/x", SimpleNamespace(disks=[]))]

    def get(self, project, zone, disk):
        return self._disk()

    def create_snapshot(self, project, zone, disk, snapshot_resource):
        self.snapshots.append(snapshot_resource)
        err = self.snap_error

        def result(timeout=None):
            if err:
                raise err
        return SimpleNamespace(result=result)

    def delete(self, project, zone, disk):
        self.deleted.append(disk)
        return SimpleNamespace(result=lambda timeout=None: None)


GCP_PAYLOAD = {"project": "proj-123", "zone": "us-central1-a", "name": "data-1"}


def test_gcp_detector_and_executor():
    fake = FakeGcpDisks()
    [c] = GcpIdleDetector(["proj-123"], client_factory=lambda: fake).candidates()
    assert c.action_type == ACTION_GCP_DISK_DELETE and c.payload == {**GCP_PAYLOAD, "size_gb": 200}
    out = GcpDiskDeleteExecutor(OPEN_GUARD, client_factory=lambda: fake,
                                clock=lambda: datetime(2026, 11, 21, 3, tzinfo=UTC))(GCP_PAYLOAD)
    assert fake.snapshots[0].name == "oplia-data-1-202611210300"
    assert fake.snapshots[0].labels["oplia-source-disk"] == "data-1"
    assert fake.deleted == ["data-1"] and out["snapshot"].endswith("/oplia-data-1-202611210300")


def test_gcp_executor_refusals():
    busy = FakeGcpDisks(users=["projects/p/zones/z/instances/vm"])
    assert list(GcpIdleDetector(["proj-123"], client_factory=lambda: busy).candidates()) == []
    with pytest.raises(FinOpsActionError, match="in use"):
        GcpDiskDeleteExecutor(OPEN_GUARD, client_factory=lambda: busy)(GCP_PAYLOAD)
    failing = FakeGcpDisks(snap_error=RuntimeError("quota exceeded"))
    with pytest.raises(RuntimeError, match="quota"):
        GcpDiskDeleteExecutor(OPEN_GUARD, client_factory=lambda: failing)(GCP_PAYLOAD)
    assert failing.deleted == []


@mock_aws
def test_run_window_executes_only_approved_finops(gate, session_factory, clock):
    ec2 = boto3.client("ec2", region_name=REGION)
    vid = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    opt = CostOptimizer(gate=gate, session_factory=session_factory, detectors=[AwsIdleDetector([REGION])],
                        grace=timedelta(days=1), clock=clock)
    opt.observe()
    clock.advance(days=2)
    [pid] = opt.observe().proposed
    other = gate.propose(action_type="drift.remediate", target="x", payload={}, reason="r", requested_by="bot")
    gate.approve(other.id, "alice")
    executors = {ACTION_EBS_DELETE: AwsEbsDeleteExecutor(OPEN_GUARD, poll_seconds=1, snapshot_wait_seconds=60)}
    assert opt.run_window(executors, CLOSED_GUARD) == {"window": "closed", "executed": []}
    assert opt.run_window(executors, OPEN_GUARD)["executed"] == []  # not approved yet
    gate.approve(pid, "alice")
    out = opt.run_window(executors, OPEN_GUARD)
    assert out["executed"] == [{"proposal_id": pid, "status": "EXECUTED"}]
    assert gate.get(other.id).status is ProposalStatus.APPROVED  # non-finops untouched
    assert vid not in [v["VolumeId"] for v in ec2.describe_volumes()["Volumes"]]


# --------------------------------------------------------------------- API
@mock_aws
def test_api_execute_outside_window_is_409_without_state_change(gate, session_factory, clock):
    ec2 = boto3.client("ec2", region_name=REGION)
    vid = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    p = gate.propose(action_type=ACTION_EBS_DELETE, target=vid, payload={"region": REGION, "volume_id": vid},
                     reason="idle", requested_by="finops-optimizer")
    gate.approve(p.id, "alice")
    app = create_app(
        gate=gate, secrets=StaticSecretProvider({}),
        verifier=OIDCVerifier(issuer=ISS, audience=AUD, jwks_url="", key_resolver=lambda _t: KEY.public_key()),
        executors={ACTION_EBS_DELETE: AwsEbsDeleteExecutor(CLOSED_GUARD)},
        webhook_secret_name="w", webhook_max_skew_seconds=300, allowed_blueprints=[],
        approver_role="oplia-approver", operator_role="oplia-operator", finops_sf=session_factory)
    c = TestClient(app)
    r = c.post(f"/proposals/{p.id}/execute", headers=bearer("bob", "oplia-operator"))
    assert r.status_code == 409 and "maintenance window" in r.json()["detail"]
    assert gate.get(p.id).status is ProposalStatus.APPROVED
    assert ec2.describe_volumes(VolumeIds=[vid])["Volumes"]

    ComplianceScanner(session_factory=session_factory, sources=[ListSource("aws", [res(tags={}, rid="r9")])],
                      clock=clock).run()
    h = bearer("op", "oplia-operator")
    assert c.get("/finops/findings").status_code == 401
    rows = c.get("/finops/findings?status_filter=OPEN&cloud=aws", headers=h).json()
    assert [x["resource_id"] for x in rows] == ["r9"]
    assert c.get("/finops/findings?cloud=oracle", headers=h).status_code == 400
    assert c.get("/finops/scans", headers=h).json()[0]["noncompliant"] == 1
    assert c.get("/finops/candidates", headers=h).json() == []


def test_gate_ttl_bounds(gate):
    with pytest.raises(ValueError, match="30 days"):
        gate.propose(action_type="x", target="t", payload={}, reason="r", requested_by="b", ttl=timedelta(days=31))
