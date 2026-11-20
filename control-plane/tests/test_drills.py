"""Automated DR restore drills: gated proposal -> persisted worker steps -> teardown -> audit event.

AWS calls go through botocore's Stubber (parameters are checked against the real EC2 API model);
Azure and GCP use fakes that receive the real SDK model objects. No cloud account is used.
"""

from __future__ import annotations

from types import SimpleNamespace

import boto3
import pytest
from botocore.stub import ANY, Stubber
from fastapi.testclient import TestClient

from oplia_ctl.api import create_app
from oplia_ctl.auth import OIDCVerifier
from oplia_ctl.replication.config import ReplicationSettings, build_job_machines, gate_audit
from oplia_ctl.replication.drills import Check, DrillSettings, RestoreDrills, parse_checks
from tests.test_api import AUD, ISS, KEY, SECRETS, bearer

AMI = "ami-0123456789abcdef0"
IID = "i-0123456789abcdef0"
GCP_IMG = "projects/oplia-dr-123/global/images/web-img"
AZ_IMG = ("/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/dr/providers/"
          "Microsoft.Compute/images/web-img")

CFG = DrillSettings.model_validate({
    "aws": {"region": "eu-west-1", "subnet_id": "subnet-0abc1234", "security_group_id": "sg-0abc1234"},
    "gcp": {"project": "oplia-dr-123", "zone": "europe-west1-b",
            "subnetwork": "projects/oplia-dr-123/regions/europe-west1/subnetworks/drill"},
    "azure": {"subscription_id": "00000000-0000-0000-0000-000000000001", "resource_group": "dr",
              "location": "westeurope", "subnet_id": "/subscriptions/x/subnets/drill",
              "ssh_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample drill"},
    "boot_timeout_seconds": 600, "check_window_seconds": 120, "teardown_timeout_seconds": 300})


@pytest.fixture(autouse=True)
def _aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")


class Ec2Clients:
    def __init__(self) -> None:
        self.ec2 = boto3.client("ec2", region_name="eu-west-1")
        self.stub = Stubber(self.ec2)
        self.stub.activate()

    def ec2_client(self, region: str):
        assert region == "eu-west-1"
        return self.ec2


def _clients(ec2=None, gcp=None, az=None):
    return SimpleNamespace(ec2=(ec2.ec2_client if ec2 else None), gcp_instances=lambda: gcp,
                           azure_compute=lambda sub: az.compute, azure_network=lambda sub: az.network)


def _inst(state, ip="10.20.0.5"):
    return {"Reservations": [{"Instances": [{"InstanceId": IID, "State": {"Name": state, "Code": 0},
                                             "PrivateIpAddress": ip}]}]}


def _status(sys_s, inst_s):
    return {"InstanceStatuses": [{"InstanceId": IID, "SystemStatus": {"Status": sys_s},
                                  "InstanceStatus": {"Status": inst_s}}]}


class Prober:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def __call__(self, ip, check: Check):
        self.calls.append((ip, check.type, check.port))
        return self.results.pop(0) if self.results else (False, "closed")


def _drills(session_factory, clock, clients, prober, events):
    return RestoreDrills(CFG, session_factory, clients=clients, prober=prober, now=clock,
                         audit=lambda e, d: events.append((e, d)))


def _app(gate, machines):
    return TestClient(create_app(
        gate=gate, secrets=SECRETS,
        verifier=OIDCVerifier(issuer=ISS, audience=AUD, jwks_url="", key_resolver=lambda _t: KEY.public_key()),
        executors={m.action: m for m in machines.values()}, webhook_secret_name="webhook_hmac_secret",
        webhook_max_skew_seconds=300, allowed_blueprints=["control-tower-standard"],
        approver_role="oplia-approver", operator_role="oplia-operator", dr_jobs=machines))


def test_parse_checks():
    assert parse_checks("tcp:22, http:8080/healthz=204") == [
        {"type": "tcp", "port": 22, "path": "/", "expect_status": 200},
        {"type": "http", "port": 8080, "path": "/healthz", "expect_status": 204}]
    assert parse_checks("http:80")[0]["path"] == "/"
    for bad in ("udp:53", "http:abc", "tcp:70000"):
        with pytest.raises(ValueError):
            parse_checks(bad)


def test_aws_drill_through_the_gate_passes_and_tears_down(gate, session_factory, clock):
    c = Ec2Clients()
    prober = Prober([(False, "tcp 22: ConnectionRefusedError"), (True, "tcp 22 open")])
    drills = _drills(session_factory, clock, _clients(ec2=c), prober, [])
    drills._audit = gate_audit(gate)                  # the real audit chain
    api = _app(gate, {drills.kind: drills})
    op, ap = bearer("olga", "oplia-operator"), bearer("ann", "oplia-approver")

    assert api.get("/me", headers=op).json()["features"]["dr_jobs"] is True
    mods = api.get("/dr/jobs", headers=op).json()["modules"]
    assert mods[0]["kind"] == "restore_drill" and mods[0]["summary"]["sandboxes"] == ["aws", "azure", "gcp"]

    r = api.post("/dr/jobs/restore_drill", headers=op,
                 json={"params": {"cloud": "aws", "image": AMI, "checks": "tcp:22"}, "reason": "monthly drill"})
    assert r.status_code == 201, r.text
    prop = r.json()
    assert prop["action_type"] == "dr.restore_drill" and prop["status"] == "PENDING"
    assert "no public IP" in prop["reason"]
    assert api.post(f"/proposals/{prop['id']}/approve", headers=ap, json={"note": "ok"}).status_code == 200
    r = api.post(f"/proposals/{prop['id']}/execute", headers=op)
    assert r.status_code == 200 and r.json()["status"] == "EXECUTED", r.text
    job_id = r.json()["result"]["job_id"]

    c.stub.add_response("run_instances", {"Instances": [{"InstanceId": IID}]}, {
        "ImageId": AMI, "InstanceType": "t3.small", "MinCount": 1, "MaxCount": 1,
        "NetworkInterfaces": [{"DeviceIndex": 0, "SubnetId": "subnet-0abc1234", "Groups": ["sg-0abc1234"],
                               "AssociatePublicIpAddress": False, "DeleteOnTermination": True}],
        "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
        "ClientToken": job_id, "TagSpecifications": ANY})
    c.stub.add_response("describe_instances", _inst("pending"), {"InstanceIds": [IID]})
    drills.run_pending()
    assert drills.get(job_id)["step"] == "WAIT_RUNNING"

    clock.advance(seconds=60)
    c.stub.add_response("describe_instances", _inst("running"), {"InstanceIds": [IID]})
    c.stub.add_response("describe_instance_status", _status("ok", "initializing"), {"InstanceIds": [IID]})
    drills.run_pending()
    assert drills.get(job_id)["step"] == "WAIT_RUNNING"

    clock.advance(seconds=60)
    c.stub.add_response("describe_instances", _inst("running"), {"InstanceIds": [IID]})
    c.stub.add_response("describe_instance_status", _status("ok", "ok"), {"InstanceIds": [IID]})
    drills.run_pending()                             # running -> first check fails (retried next run)
    assert drills.get(job_id)["step"] == "CHECK"

    clock.advance(seconds=30)
    c.stub.add_response("terminate_instances", {}, {"InstanceIds": [IID]})
    c.stub.add_response("describe_instances", _inst("shutting-down"), {"InstanceIds": [IID]})
    drills.run_pending()
    assert drills.get(job_id)["step"] == "WAIT_GONE"
    c.stub.add_response("describe_instances", _inst("terminated"), {"InstanceIds": [IID]})
    drills.run_pending()
    c.stub.assert_no_pending_responses()

    job = api.get(f"/dr/jobs/restore_drill/{job_id}", headers=op).json()
    assert job["status"] == "SUCCEEDED" and job["state"]["verdict"] == "PASSED" and job["state"]["torn_down"]
    assert job["state"]["boot_seconds"] == 120.0 and prober.calls == [("10.20.0.5", "tcp", 22)] * 2
    ev = [e for e in gate.list_audit(limit=50) if e["event"] == "dr_restore_drill"]
    assert ev and ev[0]["detail"]["verdict"] == "PASSED" and ev[0]["detail"]["torn_down"] is True
    assert gate.verify_audit_chain()


def test_failed_checks_still_tear_down_and_fail_the_job(session_factory, clock):
    c = Ec2Clients()
    events: list = []
    drills = _drills(session_factory, clock, _clients(ec2=c), Prober([]), events)
    jid = drills.queue(AMI, {"cloud": "aws", "image": AMI, "checks": parse_checks("http:80/health")}, "ann")["job_id"]
    c.stub.add_response("run_instances", {"Instances": [{"InstanceId": IID}]}, None)
    c.stub.add_response("describe_instances", _inst("running"), {"InstanceIds": [IID]})
    c.stub.add_response("describe_instance_status", _status("ok", "ok"), {"InstanceIds": [IID]})
    drills.run_pending()
    assert drills.get(jid)["step"] == "CHECK"
    clock.advance(seconds=121)                       # check window (120 s) is over
    c.stub.add_response("terminate_instances", {}, {"InstanceIds": [IID]})
    c.stub.add_response("describe_instances", _inst("terminated"), {"InstanceIds": [IID]})
    drills.run_pending()
    job = drills.get(jid)
    assert job["status"] == "FAILED" and job["state"]["verdict"] == "FAILED" and job["state"]["torn_down"]
    assert "health checks did not pass" in job["error"]
    assert events[-1][0] == "dr_restore_drill" and events[-1][1]["status"] == "FAILED"


def test_boot_timeout_terminates_the_instance(session_factory, clock):
    c = Ec2Clients()
    events: list = []
    drills = _drills(session_factory, clock, _clients(ec2=c), Prober([]), events)
    jid = drills.queue(AMI, {"cloud": "aws", "image": AMI, "checks": parse_checks("tcp:22")}, "ann")["job_id"]
    c.stub.add_response("run_instances", {"Instances": [{"InstanceId": IID}]}, None)
    c.stub.add_response("describe_instances", _inst("pending"), {"InstanceIds": [IID]})
    drills.run_pending()
    clock.advance(seconds=601)
    c.stub.add_response("describe_instances", _inst("pending"), {"InstanceIds": [IID]})
    c.stub.add_response("terminate_instances", {}, {"InstanceIds": [IID]})
    c.stub.add_response("describe_instances", _inst("terminated"), {"InstanceIds": [IID]})
    drills.run_pending()
    job = drills.get(jid)
    assert job["status"] == "FAILED" and "TimeoutError" in job["error"]
    assert job["state"]["teardown_requested_after_failure"] and job["state"]["torn_down"]
    c.stub.assert_no_pending_responses()


def test_worker_restart_resumes_from_the_persisted_step(session_factory, clock):
    c = Ec2Clients()
    d1 = _drills(session_factory, clock, _clients(ec2=c), Prober([]), [])
    jid = d1.queue(AMI, {"cloud": "aws", "image": AMI, "checks": parse_checks("tcp:22")}, "ann")["job_id"]
    c.stub.add_response("run_instances", {"Instances": [{"InstanceId": IID}]}, None)
    c.stub.add_response("describe_instances", _inst("pending"), {"InstanceIds": [IID]})
    d1.run_pending()
    d2 = _drills(session_factory, clock, _clients(ec2=c), Prober([(True, "ok")]), [])  # new process
    c.stub.add_response("describe_instances", _inst("running"), {"InstanceIds": [IID]})
    c.stub.add_response("describe_instance_status", _status("ok", "ok"), {"InstanceIds": [IID]})
    c.stub.add_response("terminate_instances", {}, {"InstanceIds": [IID]})
    c.stub.add_response("describe_instances", _inst("terminated"), {"InstanceIds": [IID]})
    d2.run_pending()
    assert d2.get(jid)["status"] == "SUCCEEDED"
    c.stub.assert_no_pending_responses()                 # run_instances was not called twice


class FakeGcp:
    def __init__(self):
        self.inserted = None
        self.status = ["PROVISIONING", "RUNNING"]
        self.deleted = False

    def insert(self, project, zone, instance_resource, request_id):
        self.inserted = (project, zone, instance_resource, request_id)

    def get(self, project, zone, instance):
        from google.api_core.exceptions import NotFound
        if self.deleted:
            raise NotFound("gone")
        st = self.status.pop(0) if len(self.status) > 1 else self.status[0]
        return SimpleNamespace(status=st, network_interfaces=[SimpleNamespace(network_i_p="10.30.0.7")])

    def delete(self, project, zone, instance):
        self.deleted = True


def test_gcp_drill_has_no_external_ip(session_factory, clock):
    g = FakeGcp()
    events: list = []
    drills = _drills(session_factory, clock, _clients(gcp=g), Prober([(True, "ok")]), events)
    jid = drills.queue(GCP_IMG, {"cloud": "gcp", "image": GCP_IMG, "checks": parse_checks("tcp:22")}, "a")["job_id"]
    drills.run_pending()
    drills.run_pending()
    project, zone, inst, _ = g.inserted
    assert (project, zone) == ("oplia-dr-123", "europe-west1-b")
    assert list(inst.network_interfaces[0].access_configs) == []
    assert inst.disks[0].auto_delete and inst.disks[0].initialize_params.source_image == GCP_IMG
    assert dict(inst.labels)["oplia-purpose"] == "dr-restore-drill"
    assert drills.get(jid)["status"] == "SUCCEEDED" and g.deleted
    assert events[-1][1]["verdict"] == "PASSED"


class FakeAzure:
    def __init__(self):
        self.vm = None
        self.nic = None
        self.vm_deleted = False
        outer = self

        class Poller:
            def __init__(self, v=None):
                self.v = v

            def result(self):
                return self.v

        class Nics:
            def begin_create_or_update(self, rg, name, nic):
                outer.nic = nic
                return Poller(SimpleNamespace(id=f"/subscriptions/s/resourceGroups/{rg}/providers/x/{name}"))

            def get(self, rg, name):
                return SimpleNamespace(properties=SimpleNamespace(ip_configurations=[
                    SimpleNamespace(properties=SimpleNamespace(private_ip_address="10.40.0.9"))]))

            def begin_delete(self, rg, name):
                from azure.core.exceptions import ResourceNotFoundError
                raise ResourceNotFoundError("deleted with the VM")

        class Vms:
            def begin_create_or_update(self, rg, name, vm):
                outer.vm = vm
                return Poller()

            def get(self, rg, name, expand=None):
                from azure.core.exceptions import ResourceNotFoundError
                if outer.vm_deleted:
                    raise ResourceNotFoundError("gone")
                return SimpleNamespace(properties=SimpleNamespace(
                    provisioning_state="Succeeded",
                    instance_view=SimpleNamespace(statuses=[SimpleNamespace(code="PowerState/running")])))

            def begin_delete(self, rg, name):
                outer.vm_deleted = True
                return Poller()

        self.network = SimpleNamespace(network_interfaces=Nics())
        self.compute = SimpleNamespace(virtual_machines=Vms())


def test_azure_drill_uses_ssh_key_no_public_ip_and_cleans_up(session_factory, clock):
    az = FakeAzure()
    drills = _drills(session_factory, clock, _clients(az=az), Prober([(True, "ok")]), [])
    jid = drills.queue(AZ_IMG, {"cloud": "azure", "image": AZ_IMG, "checks": parse_checks("tcp:22")}, "a")["job_id"]
    drills.run_pending()
    drills.run_pending()
    props = az.vm.properties
    assert props.os_profile.linux_configuration.disable_password_authentication is True
    assert props.storage_profile.os_disk.delete_option == "Delete"
    assert props.network_profile.network_interfaces[0].properties.delete_option == "Delete"
    ipc = az.nic.properties.ip_configurations[0].properties
    assert ipc.public_ip_address is None and ipc.subnet.id == "/subscriptions/x/subnets/drill"
    job = drills.get(jid)
    assert job["status"] == "SUCCEEDED" and job["state"]["private_ip"] == "10.40.0.9" and az.vm_deleted


def test_api_validation_and_not_configured(gate, session_factory, clock):
    only_aws = DrillSettings.model_validate({"aws": CFG.aws.model_dump()})
    drills = RestoreDrills(only_aws, session_factory, now=clock)
    api = _app(gate, {drills.kind: drills})
    op = bearer("olga", "oplia-operator")
    for params, msg in (({"cloud": "gcp", "image": GCP_IMG, "checks": "tcp:22"}, "no gcp drill sandbox"),
                        ({"cloud": "aws", "image": "ami-zz", "checks": "tcp:22"}, "AMI id"),
                        ({"cloud": "aws", "image": AMI, "checks": "smtp:25"}, "bad check"),
                        ({"cloud": "aws", "image": AMI, "checks": ""}, "1 to 10")):
        r = api.post("/dr/jobs/restore_drill", headers=op, json={"params": params, "reason": "monthly drill"})
        assert r.status_code == 422 and msg in r.json()["detail"], (params, r.text)
    assert api.post("/dr/jobs/nope", headers=op, json={"params": {}, "reason": "x" * 5}).status_code == 404
    assert api.get("/dr/jobs/restore_drill/does-not-exist", headers=op).status_code == 404
    assert api.get("/dr/jobs", headers=bearer("dave")).status_code == 403
    assert _app(gate, {}).get("/dr/jobs", headers=op).status_code == 503


def test_settings_build_the_module(monkeypatch, session_factory):
    monkeypatch.setenv("OPLIA_REPLICATION_DRILLS", CFG.model_dump_json())
    cfg = ReplicationSettings()
    assert cfg.enabled() and cfg.job_modules_configured()
    assert list(build_job_machines(cfg, session_factory)) == ["restore_drill"]
    monkeypatch.delenv("OPLIA_REPLICATION_DRILLS")
    assert build_job_machines(ReplicationSettings(), session_factory) == {}


def test_probe_against_real_local_servers():
    """The real probe (no fake): TCP connect and HTTP status against servers on 127.0.0.1."""
    import socket
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from oplia_ctl.replication.drills import probe

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(204 if self.path == "/healthz" else 500)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        assert probe("127.0.0.1", Check(type="tcp", port=port))[0] is True
        assert probe("127.0.0.1", Check(type="http", port=port, path="/healthz", expect_status=204)) == (
            True, f"http {port}/healthz: 204")
        ok, detail = probe("127.0.0.1", Check(type="http", port=port, path="/other", expect_status=200))
        assert not ok and detail.endswith(": 500")
    finally:
        srv.shutdown()
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    closed = s.getsockname()[1]
    s.close()
    ok, detail = probe("127.0.0.1", Check(type="tcp", port=closed), timeout=1)
    assert not ok and "ConnectionRefusedError" in detail
