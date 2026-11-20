"""Forced DNS failover / failback: Route 53 via botocore Stubber (requests checked against the API
model), Traffic Manager via a fake operations object that receives the real SDK models
(azure-mgmt-trafficmanager 2.0.0). No cloud account is used."""

from __future__ import annotations

from types import SimpleNamespace

import boto3
import pytest
from azure.mgmt.trafficmanager import models as tm
from botocore.stub import Stubber

from oplia_ctl.replication.dns_failover import DnsFailover, DnsSettings

HC = "abcdef01-2345-6789-abcd-ef0123456789"
CFG = DnsSettings.model_validate({"records": [
    {"name": "app-aws", "provider": "route53", "fqdn": "app.example.com", "primary_health_check_id": HC,
     "wait_timeout_seconds": 120},
    {"name": "app-azure", "provider": "traffic_manager", "fqdn": "app.example.net", "subscription_id": "sub-1",
     "resource_group": "dr", "profile": "app-tm"}]})


@pytest.fixture(autouse=True)
def _aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")


def _hc(inverted):
    return {"HealthCheck": {"Id": HC, "CallerReference": "c", "HealthCheckVersion": 2,
                            "HealthCheckConfig": {"Type": "HTTPS", "Inverted": inverted}}}


def _obs(statuses):
    return {"HealthCheckObservations": [{"Region": "us-east-1", "IPAddress": f"10.0.0.{i}",
                                         "StatusReport": {"Status": s}} for i, s in enumerate(statuses)]}


class Clients:
    def __init__(self):
        self.r53 = boto3.client("route53")
        self.stub = Stubber(self.r53)
        self.stub.activate()
        self.ep = tm.Endpoint(properties=tm.EndpointProperties(target="primary.example.net", priority=1,
                                                               endpoint_status="Enabled",
                                                               endpoint_monitor_status="Online"))
        self.updates = []
        outer = self

        class Endpoints:
            def get(self, rg, profile, etype, name):
                assert (rg, profile, etype, name) == ("dr", "app-tm", "ExternalEndpoints", "primary")
                cur = outer.ep.properties
                return tm.Endpoint(properties=tm.EndpointProperties(
                    target=cur.target, priority=cur.priority, endpoint_status=cur.endpoint_status,
                    endpoint_monitor_status=cur.endpoint_monitor_status))

            def update(self, rg, profile, etype, name, parameters):
                outer.updates.append(parameters.as_dict())
                outer.ep = parameters
                return parameters

        self.tm = SimpleNamespace(endpoints=Endpoints())

    def route53(self):
        return self.r53

    def traffic_manager(self, sub):
        assert sub == "sub-1"
        return self.tm


def test_route53_failover_inverts_and_waits_for_checkers(session_factory, clock):
    c = Clients()
    events: list = []
    d = DnsFailover(CFG, session_factory, clients=c, now=clock, audit=lambda e, x: events.append((e, x)))
    p = d.parse({"record": "app-aws", "direction": "failover"})
    assert "Inverted=true" in d.describe(p)
    jid = d.queue(d.target_of(p), p, "ann")["job_id"]
    c.stub.add_response("update_health_check", _hc(True), {"HealthCheckId": HC, "Inverted": True})
    c.stub.add_response("get_health_check_status", _obs(["Success: HTTP 200", "Success: HTTP 200", "Failure: x"]),
                        {"HealthCheckId": HC})
    d.run_pending()
    assert d.get(jid)["step"] == "WAIT" and d.get(jid)["state"]["inverted"] is True
    clock.advance(seconds=30)
    c.stub.add_response("get_health_check_status", _obs(["Failure: inverted", "Failure: inverted", "Success: x"]),
                        {"HealthCheckId": HC})
    d.run_pending()
    job = d.get(jid)
    assert job["status"] == "SUCCEEDED" and job["state"]["checkers"] == {"total": 3, "reporting_healthy": 1}
    assert events[-1][0] == "dr_dns_failover" and events[-1][1]["direction"] == "failover"
    c.stub.assert_no_pending_responses()


def test_route53_failback_timeout(session_factory, clock):
    c = Clients()
    d = DnsFailover(CFG, session_factory, clients=c, now=clock)
    jid = d.queue("t", d.parse({"record": "app-aws", "direction": "failback"}), "a")["job_id"]
    c.stub.add_response("update_health_check", _hc(False), {"HealthCheckId": HC, "Inverted": False})
    c.stub.add_response("get_health_check_status", _obs(["Failure: down"] * 3), {"HealthCheckId": HC})
    d.run_pending()
    clock.advance(seconds=121)
    c.stub.add_response("get_health_check_status", _obs(["Failure: down"] * 3), {"HealthCheckId": HC})
    d.run_pending()
    job = d.get(jid)
    assert job["status"] == "FAILED" and "not confirmed within 120s" in job["error"]


def test_traffic_manager_disable_then_enable(session_factory, clock):
    c = Clients()
    d = DnsFailover(CFG, session_factory, clients=c, now=clock)
    jid = d.queue("t", d.parse({"record": "app-azure", "direction": "failover"}), "a")["job_id"]
    d.run_pending()
    assert c.updates[-1]["properties"]["endpointStatus"] == "Disabled"
    assert d.get(jid)["status"] == "SUCCEEDED" and d.get(jid)["state"]["before"] == "Enabled"
    jid2 = d.queue("t", d.parse({"record": "app-azure", "direction": "failback"}), "a")["job_id"]
    d.run_pending()
    assert c.updates[-1]["properties"]["endpointStatus"] == "Enabled"
    assert d.get(jid2)["status"] == "SUCCEEDED"


def test_validation():
    d = DnsFailover(CFG, session_factory=None, clients=None)
    with pytest.raises(ValueError, match="unknown DNS failover record"):
        d.parse({"record": "x", "direction": "failover"})
    with pytest.raises(ValueError, match="direction"):
        d.parse({"record": "app-aws", "direction": "sideways"})
    with pytest.raises(ValueError, match="primary_health_check_id"):
        DnsSettings.model_validate({"records": [{"name": "a", "provider": "route53", "fqdn": "a.example.com"}]})
    assert [f["name"] for f in d.fields()] == ["record", "direction"]
