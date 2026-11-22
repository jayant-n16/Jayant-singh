"""Network layer: Global Accelerator traffic dial (gated), Direct Connect, Consul and Linkerd status.

AWS calls go through real boto3 clients with botocore's Stubber, which checks every request
against the service's API model (operation names, parameter names and types). Consul is
mocked with respx; Linkerd Link resources are passed in as data. Nothing here talks to a real
account or cluster.
"""

from __future__ import annotations

import boto3
import httpx
import pytest
import respx
from botocore.stub import Stubber
from fastapi.testclient import TestClient

from oplia_ctl.api import create_app
from oplia_ctl.auth import OIDCVerifier
from oplia_ctl.http import ResilientClient
from oplia_ctl.network.service import NetworkService, NetworkSettings, TrafficDialExecutor
from oplia_ctl.secrets import StaticSecretProvider
from tests.test_api import AUD, ISS, KEY, SECRETS, bearer

ARN_AWS = ("arn:aws:globalaccelerator::123456789012:accelerator/1234abcd-abcd-1234-abcd-1234abcdefgh/"
           "listener/0123vxyz/endpoint-group/098765zyxwvu")
ARN_AZ = ARN_AWS.replace("098765zyxwvu", "111111aaaaaa")
CONSUL = "https://consul.example.test:8501"


def _eg(arn: str, dial: float, health: str = "HEALTHY", region: str = "ap-south-1") -> dict:
    return {"EndpointGroup": {
        "EndpointGroupArn": arn, "EndpointGroupRegion": region, "TrafficDialPercentage": dial,
        "HealthCheckProtocol": "HTTPS", "HealthCheckPort": 443, "HealthCheckPath": "/healthz",
        "EndpointDescriptions": [{"EndpointId": "arn:aws:elasticloadbalancing:ap-south-1:123456789012:"
                                                "loadbalancer/net/fwd/abc", "Weight": 128,
                                  "HealthState": health, "ClientIPPreservationEnabled": False}]}}


@pytest.fixture
def ga():
    client = boto3.client("globalaccelerator", region_name="us-west-2",
                          aws_access_key_id="test", aws_secret_access_key="test")
    with Stubber(client) as stub:
        yield client, stub
        stub.assert_no_pending_responses()


class Clock:
    def __init__(self, now):
        self.now = now

    def __call__(self):
        return self.now


def _svc(session_factory, ga_client, clock, **cfg):
    settings = NetworkSettings(endpoint_groups={"aws": ARN_AWS, "azure": ARN_AZ}, **cfg)
    return NetworkService(settings, session_factory, ga_client=lambda: ga_client, now=clock)


# ------------------------------------------------------------------- step policy
def test_step_policy(session_factory, ga, clock):
    client, _ = ga
    svc = _svc(session_factory, client, clock)
    svc.check_step("aws", 10, 35, healthy=True)                     # +25 is the limit
    with pytest.raises(ValueError, match="step limit"):
        svc.check_step("aws", 10, 36, healthy=True)
    with pytest.raises(ValueError, match="HEALTHY"):
        svc.check_step("aws", 10, 20, healthy=False)
    svc.check_step("aws", 50, 0, healthy=False)                     # rollback: always allowed
    with pytest.raises(ValueError, match="already"):
        svc.check_step("aws", 10, 10, healthy=True)
    with pytest.raises(ValueError, match="between 0 and 100"):
        svc.check_step("aws", 90, 101, healthy=True)
    # hold time after an executed change, increases only
    svc.record("aws", ARN_AWS, 0, 10, "r1")
    with pytest.raises(ValueError, match="hold time"):
        svc.check_step("aws", 10, 25, healthy=True)
    svc.check_step("aws", 10, 5, healthy=True)
    svc.check_step("azure", 0, 10, healthy=True)                    # hold is per group
    clock.advance(minutes=30)
    svc.check_step("aws", 10, 25, healthy=True)


# ---------------------------------------------------------------------- executor
def test_executor_updates_and_reads_back(session_factory, ga, clock):
    client, stub = ga
    svc = _svc(session_factory, client, clock)
    stub.add_response("describe_endpoint_group", _eg(ARN_AWS, 10.0), {"EndpointGroupArn": ARN_AWS})
    stub.add_response("update_endpoint_group", {"EndpointGroup": _eg(ARN_AWS, 25.0)["EndpointGroup"]},
                      {"EndpointGroupArn": ARN_AWS, "TrafficDialPercentage": 25.0})
    stub.add_response("describe_endpoint_group", _eg(ARN_AWS, 25.0), {"EndpointGroupArn": ARN_AWS})
    ex = TrafficDialExecutor(svc)
    payload = {"group": "aws", "arn": ARN_AWS, "from": 10.0, "to": 25.0, "request_id": "req-1"}
    assert "from 10 % to 25 %" in ex.describe(payload)
    out = ex(payload)
    assert out["verified"] is True and out["to"] == 25.0
    hist = svc.history()
    assert [(h["group"], h["from"], h["to"], h["request_id"]) for h in hist] == [("aws", 10.0, 25.0, "req-1")]


def test_executor_refuses_when_live_dial_moved(session_factory, ga, clock):
    client, stub = ga
    svc = _svc(session_factory, client, clock)
    stub.add_response("describe_endpoint_group", _eg(ARN_AWS, 15.0), {"EndpointGroupArn": ARN_AWS})
    with pytest.raises(RuntimeError, match="live dial of aws is 15 %"):
        TrafficDialExecutor(svc)({"group": "aws", "arn": ARN_AWS, "from": 10.0, "to": 25.0})
    assert svc.history() == []                                      # and no UpdateEndpointGroup call


def test_executor_refuses_increase_when_unhealthy_at_execution(session_factory, ga, clock):
    client, stub = ga
    svc = _svc(session_factory, client, clock)
    stub.add_response("describe_endpoint_group", _eg(ARN_AWS, 10.0, health="UNHEALTHY"),
                      {"EndpointGroupArn": ARN_AWS})
    with pytest.raises(ValueError, match="HEALTHY"):
        TrafficDialExecutor(svc)({"group": "aws", "arn": ARN_AWS, "from": 10.0, "to": 20.0})


def test_executor_read_back_mismatch_is_a_failure(session_factory, ga, clock):
    client, stub = ga
    svc = _svc(session_factory, client, clock)
    stub.add_response("describe_endpoint_group", _eg(ARN_AWS, 10.0), {"EndpointGroupArn": ARN_AWS})
    stub.add_response("update_endpoint_group", {"EndpointGroup": _eg(ARN_AWS, 10.0)["EndpointGroup"]},
                      {"EndpointGroupArn": ARN_AWS, "TrafficDialPercentage": 20.0})
    stub.add_response("describe_endpoint_group", _eg(ARN_AWS, 10.0), {"EndpointGroupArn": ARN_AWS})
    with pytest.raises(RuntimeError, match="read-back"):
        TrafficDialExecutor(svc)({"group": "aws", "arn": ARN_AWS, "from": 10.0, "to": 20.0})
    assert svc.history() == []


def test_executor_rejects_changed_arn(session_factory, ga, clock):
    client, _ = ga
    with pytest.raises(ValueError, match="ARN changed"):
        TrafficDialExecutor(_svc(session_factory, client, clock))({"group": "aws", "arn": ARN_AZ,
                                                                    "from": 0, "to": 10})


# ------------------------------------------------------------------------ status
@respx.mock
def test_status_reads_every_source_and_isolates_failures(session_factory, ga, clock):
    client, stub = ga
    stub.add_response("describe_endpoint_group", _eg(ARN_AWS, 100.0), {"EndpointGroupArn": ARN_AWS})
    stub.add_client_error("describe_endpoint_group", "EndpointGroupNotFoundException", "not found",
                          expected_params={"EndpointGroupArn": ARN_AZ})
    dx = boto3.client("directconnect", region_name="ap-south-1", aws_access_key_id="test",
                      aws_secret_access_key="test")
    dx_stub = Stubber(dx)
    dx_stub.add_response("describe_virtual_interfaces", {"virtualInterfaces": [{
        "virtualInterfaceId": "dxvif-1", "virtualInterfaceName": "oplia-equinix", "connectionId": "dxcon-abc",
        "virtualInterfaceType": "private", "virtualInterfaceState": "available", "vlan": 101,
        "bgpPeers": [{"bgpStatus": "up"}, {"bgpStatus": "down"}]}]}, {})
    dx_stub.add_response("describe_connections", {"connections": [{
        "connectionId": "dxcon-abc", "connectionName": "equinix-pri", "connectionState": "available",
        "partnerName": "Equinix", "bandwidth": "1Gbps", "location": "EqSE2", "vlan": 101}]}, {})
    dx_stub.activate()
    respx.get(f"{CONSUL}/v1/peerings").mock(side_effect=lambda req: httpx.Response(
        200 if req.headers.get("X-Consul-Token") == "consul-tok" else 403,
        json=[{"Name": "azure-cin", "State": "ACTIVE", "PeerServerName": "server.azure.peering.consul",
               "StreamStatus": {"ImportedServices": ["web", "api"], "ExportedServices": ["db"],
                                "LastHeartbeat": "2026-11-20T10:00:00Z"}}]))
    links = [{"metadata": {"name": "gcp-mum", "namespace": "linkerd-multicluster"},
              "spec": {"targetClusterName": "gcp-mum", "gatewayAddress": "10.20.0.5", "gatewayPort": 4143},
              "status": {"mirrorServices": [
                  {"remoteRef": {"name": "web"}, "conditions": [{"type": "Mirrored", "status": "True"}]},
                  {"remoteRef": {"name": "api"}, "conditions": [{"type": "Mirrored", "status": "False"}]}]}}]
    settings = NetworkSettings(endpoint_groups={"aws": ARN_AWS, "azure": ARN_AZ}, dx_regions=["ap-south-1"],
                               consul_addr=CONSUL, consul_token_secret="consul_token", linkerd_links=True)
    svc = NetworkService(settings, session_factory, secrets=StaticSecretProvider({"consul_token": "consul-tok"}),
                         client=ResilientClient(max_retries=0), ga_client=lambda: client,
                         dx_client=lambda _r: dx, linkerd_links=lambda: links, now=clock)
    st = svc.status()
    groups = {g["key"]: g for g in st["global_accelerator"]["items"]}
    assert groups["aws"]["traffic_dial"] == 100.0 and groups["aws"]["all_healthy"] is True
    assert "EndpointGroupNotFoundException" in groups["azure"]["error"]          # one group fails, other shown
    conn = st["direct_connect"]["items"][0]
    assert conn["partner"] == "Equinix" and conn["virtual_interfaces"][0]["bgp"] == ["up", "down"]
    assert st["consul"]["items"] == [{"name": "azure-cin", "state": "ACTIVE",
                                      "peer_server_name": "server.azure.peering.consul", "imported_services": 2,
                                      "exported_services": 1, "last_heartbeat": "2026-11-20T10:00:00Z"}]
    assert st["linkerd"]["items"][0]["not_ready"] == ["api"]
    assert "consul-tok" not in str(st)
    dx_stub.deactivate()


@respx.mock
def test_status_section_error_does_not_hide_others(session_factory, ga, clock):
    client, _ = ga
    respx.get(f"{CONSUL}/v1/peerings").mock(return_value=httpx.Response(500, text="boom"))
    settings = NetworkSettings(consul_addr=CONSUL, linkerd_links=True)

    def broken_links():
        raise RuntimeError("no cluster credentials")

    svc = NetworkService(settings, session_factory, client=ResilientClient(max_retries=0),
                         ga_client=lambda: client, linkerd_links=broken_links, now=clock)
    st = svc.status()
    assert st["consul"]["ok"] is False and st["consul"]["error"]
    assert st["linkerd"]["ok"] is False and "no cluster credentials" in st["linkerd"]["error"]
    assert st["global_accelerator"]["configured"] is False and st["direct_connect"]["configured"] is False


# --------------------------------------------------------------------------- API
def _app(gate, network, executors=None):
    return TestClient(create_app(
        gate=gate, secrets=SECRETS,
        verifier=OIDCVerifier(issuer=ISS, audience=AUD, jwks_url="", key_resolver=lambda _t: KEY.public_key()),
        executors=executors or {}, webhook_secret_name="webhook_hmac_secret", webhook_max_skew_seconds=300,
        allowed_blueprints=["control-tower-standard"], approver_role="oplia-approver",
        operator_role="oplia-operator", network=network))


def test_api_traffic_dial_goes_through_the_gate(gate, session_factory, ga, clock):
    client, stub = ga
    svc = _svc(session_factory, client, clock)
    api = _app(gate, svc, {"network.traffic_dial": TrafficDialExecutor(svc)})
    op, ap1 = bearer("olga", "oplia-operator"), bearer("ann", "oplia-approver")
    assert api.get("/me", headers=op).json()["features"]["network"] is True

    # a too-large step is refused before a proposal exists
    stub.add_response("describe_endpoint_group", _eg(ARN_AZ, 0.0), {"EndpointGroupArn": ARN_AZ})
    r = api.post("/network/endpoint-groups/azure/traffic-dial", headers=op,
                 json={"percentage": 50, "reason": "phase 4 step"})
    assert r.status_code == 409 and "step limit" in r.json()["detail"]
    assert api.post("/network/endpoint-groups/nope/traffic-dial", headers=op,
                    json={"percentage": 10, "reason": "phase 4 step"}).status_code == 404

    stub.add_response("describe_endpoint_group", _eg(ARN_AZ, 0.0), {"EndpointGroupArn": ARN_AZ})
    r = api.post("/network/endpoint-groups/azure/traffic-dial", headers=op,
                 json={"percentage": 10, "reason": "phase 4 step 1"})
    assert r.status_code == 201, r.text
    prop = r.json()
    assert prop["action_type"] == "network.traffic_dial" and prop["status"] == "PENDING"
    pid = prop["id"]
    # the operator cannot approve; an approver other than the requester must (four eyes)
    assert api.post(f"/proposals/{pid}/approve", headers=op, json={"note": "x"}).status_code == 403
    assert api.post(f"/proposals/{pid}/approve", headers=ap1, json={"note": "ok"}).status_code == 200

    stub.add_response("describe_endpoint_group", _eg(ARN_AZ, 0.0), {"EndpointGroupArn": ARN_AZ})
    stub.add_response("update_endpoint_group", {"EndpointGroup": _eg(ARN_AZ, 10.0)["EndpointGroup"]},
                      {"EndpointGroupArn": ARN_AZ, "TrafficDialPercentage": 10.0})
    stub.add_response("describe_endpoint_group", _eg(ARN_AZ, 10.0), {"EndpointGroupArn": ARN_AZ})
    r = api.post(f"/proposals/{pid}/execute", headers=op)   # execution is an operator action
    assert r.status_code == 200 and r.json()["status"] == "EXECUTED", r.text
    assert svc.history()[0]["to"] == 10.0

    # next increase inside the hold time is refused at proposal time
    stub.add_response("describe_endpoint_group", _eg(ARN_AZ, 10.0), {"EndpointGroupArn": ARN_AZ})
    r = api.post("/network/endpoint-groups/azure/traffic-dial", headers=op,
                 json={"percentage": 25, "reason": "phase 4 step 2"})
    assert r.status_code == 409 and "hold time" in r.json()["detail"]
    events = [e["event"] for e in gate.list_audit(limit=50)]
    assert {"proposed", "approved", "execution_started", "executed"} <= set(events)


def test_api_network_not_configured(gate):
    api = _app(gate, None)
    hdr = bearer("olga", "oplia-operator")
    assert api.get("/network/status", headers=hdr).status_code == 503
    assert api.get("/me", headers=hdr).json()["features"]["network"] is False
