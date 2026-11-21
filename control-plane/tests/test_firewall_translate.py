"""Firewall / IAM translation between clouds. AWS uses moto's EC2 (real request/response shapes);
Azure and GCP use fakes that receive and return the real SDK models (azure-mgmt-network,
google-cloud-compute). No cloud account is used."""

from __future__ import annotations

from types import SimpleNamespace

import boto3
import pytest
from azure.mgmt.network.models import NetworkSecurityGroup, SecurityRule
from google.cloud import compute_v1
from moto import mock_aws

from oplia_ctl.replication.firewall import (
    FirewallSettings,
    FirewallTranslator,
    IamBinding,
    from_aws,
    from_azure,
    from_gcp,
    to_aws,
    to_azure,
    to_gcp,
    translate,
    translate_iam,
)


@pytest.fixture(autouse=True)
def _aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")


def _azure_nsg(rules):
    return NetworkSecurityGroup(security_rules=[SecurityRule(**r) for r in rules]).as_dict()


AZ_RULES = [
    {"name": "https-in", "priority": 100, "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
     "source_address_prefixes": ["10.1.0.0/16", "192.168.5.0/24"], "destination_address_prefix": "*",
     "source_port_range": "*", "destination_port_ranges": ["443", "8000-8010"]},
    {"name": "deny-telnet", "priority": 200, "direction": "Inbound", "access": "Deny", "protocol": "Tcp",
     "source_address_prefix": "0.0.0.0/0", "destination_address_prefix": "*", "source_port_range": "*",
     "destination_port_range": "23"},
    {"name": "lb-probe", "priority": 300, "direction": "Inbound", "access": "Allow", "protocol": "*",
     "source_address_prefix": "AzureLoadBalancer", "destination_address_prefix": "*", "source_port_range": "*",
     "destination_port_range": "*"},
]


def test_azure_to_aws_drops_deny_and_service_tags_and_reports_them():
    res = translate("azure", _azure_nsg(AZ_RULES), "aws")
    reasons = {x["rule"]: x["reason"] for x in res["lossy"]}
    assert "service tag" in reasons["lb-probe"] and "cannot deny" in reasons["deny-telnet"]
    ing = res["target_rules"]["ingress"]
    assert [(p["FromPort"], p["ToPort"]) for p in ing] == [(443, 443), (8000, 8010)]
    assert {r["CidrIp"] for r in ing[0]["IpRanges"]} == {"10.1.0.0/16", "192.168.5.0/24"}


def test_aws_rules_round_trip_through_moto_and_to_azure_and_gcp():
    with mock_aws():
        ec2 = boto3.client("ec2")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        other = ec2.create_security_group(GroupName="o", Description="o", VpcId=vpc)["GroupId"]
        sg = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": "10.9.0.0/16", "Description": "ssh"}]},
            {"IpProtocol": "udp", "FromPort": 53, "ToPort": 53, "Ipv6Ranges": [{"CidrIpv6": "2001:db8::/32"}]},
            {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "UserIdGroupPairs": [{"GroupId": other}]},
        ])
        live = ec2.describe_security_groups(GroupIds=[sg])["SecurityGroups"][0]
    rules, lossy = from_aws(live)
    assert any("security-group reference" in x["reason"] for x in lossy)
    ingress = [r for r in rules if r.direction == "ingress"]
    assert {(r.protocol, tuple(r.ports)) for r in ingress} == {("tcp", ((22, 22),)), ("udp", ((53, 53),))}
    az, _ = to_azure(rules, priority_base=500)
    assert all(500 <= r["priority"] <= 4096 for r in az)
    SecurityRule(**az[0])  # accepted by the real SDK model
    # Azure rules read back give the same neutral rules
    back, _ = from_azure(_azure_nsg(az))
    assert {r.key() for r in back} == {r.key() for r in rules}
    gcp, _ = to_gcp(rules, "projects/p/global/networks/dr")
    fw = [compute_v1.Firewall(g) for g in gcp]  # accepted by the real proto
    back2, _ = from_gcp([compute_v1.Firewall.to_dict(f, preserving_proto_field_name=True) for f in fw])
    assert {r.key() for r in back2} == {r.key() for r in rules}
    assert all(len(g["name"]) <= 63 and g["name"][0].isalpha() for g in gcp)


def test_gcp_tags_and_disabled_rules_are_refused():
    src = [{"name": "tagged", "network": "n", "direction": "INGRESS", "allowed": [{"I_p_protocol": "tcp"}],
            "source_ranges": ["0.0.0.0/0"], "target_tags": ["web"]},
           {"name": "off", "disabled": True, "network": "n", "direction": "INGRESS"},
           {"name": "egress-dns", "network": "n", "direction": "EGRESS",
            "denied": [{"I_p_protocol": "udp", "ports": ["53"]}],
            "destination_ranges": ["8.8.8.8/32"], "priority": 900}]
    rules, lossy = from_gcp(src)
    assert {x["rule"] for x in lossy} == {"tagged", "off"}
    assert rules[0].action == "deny" and rules[0].direction == "egress" and rules[0].ports == [(53, 53)]
    out, more = to_aws(rules)
    assert out == {"ingress": [], "egress": []} and "cannot deny" in more[0]["reason"]


def test_priority_range_overflow_is_an_error():
    rules, _ = from_azure(_azure_nsg(AZ_RULES[:1]))
    with pytest.raises(ValueError, match="priority range"):
        to_azure(rules * 401, priority_base=100)  # 100 + 400*10 = 4100 > 4096


def test_iam_uses_only_explicit_mappings():
    res = translate_iam(
        [IamBinding(principal="arn:aws:iam::1:role/ops", role="arn:aws:iam::aws:policy/ReadOnlyAccess"),
         IamBinding(principal="arn:aws:iam::1:role/dev", role="arn:aws:iam::aws:policy/PowerUserAccess")],
        "gcp", role_map={"arn:aws:iam::aws:policy/ReadOnlyAccess": {"gcp": "roles/viewer"}},
        principal_map={"arn:aws:iam::1:role/ops": {"gcp": "group:ops@example.com"}})
    assert res["bindings"] == [{"principal": "group:ops@example.com", "role": "roles/viewer",
                                "from": {"principal": "arn:aws:iam::1:role/ops",
                                         "role": "arn:aws:iam::aws:policy/ReadOnlyAccess", "scope": ""}}]
    assert res["unmapped"][0]["reason"] == "no role mapping and no principal mapping"


class Fakes:
    """Azure NSG source, GCP firewall target; both hold real SDK objects."""

    def __init__(self):
        self.nsg = _azure_nsg(AZ_RULES)
        self.gcp: list[compute_v1.Firewall] = []
        outer = self

        class Op:
            def result(self):
                return None

        class Fws:
            def list(self, project):
                assert project == "dr-proj"
                return list(outer.gcp)

            def insert(self, project, firewall_resource):
                assert isinstance(firewall_resource, compute_v1.Firewall)
                outer.gcp.append(firewall_resource)
                return Op()

        self.fws = Fws()
        self.net = SimpleNamespace(network_security_groups=SimpleNamespace(
            get=lambda rg, name: NetworkSecurityGroup(security_rules=[SecurityRule(**r) for r in AZ_RULES])))

    def network(self, sub):
        assert sub == "sub-1"
        return self.net

    def gcp_firewalls(self):
        return self.fws


CFG = FirewallSettings.model_validate({"pairs": [{
    "name": "web-azure-gcp",
    "source": {"cloud": "azure", "subscription_id": "sub-1", "resource_group": "rg", "nsg": "web"},
    "target": {"cloud": "gcp", "project": "dr-proj", "network": "dr"}}]})


def test_gated_job_applies_verifies_and_audits(session_factory, clock):
    f = Fakes()
    events: list = []
    t = FirewallTranslator(CFG, session_factory, clients=f, now=clock, audit=lambda e, d: events.append((e, d)))
    p = t.parse({"pair": "web-azure-gcp"})
    assert "nothing is deleted" in t.describe(p)
    jid = t.queue(t.target_of(p), p, "ann")["job_id"]
    t.run_pending()
    job = t.get(jid)
    assert job["status"] == "SUCCEEDED", job["error"]
    assert job["state"]["verified"] == {"expected": 2, "missing": []}
    assert [x["rule"] for x in job["state"]["lossy"]] == ["lb-probe"]
    assert {fw.name for fw in f.gcp} == {"https-in", "deny-telnet"}
    assert events[-1][0] == "dr_firewall_translate" and events[-1][1]["status"] == "SUCCEEDED"


def test_verify_fails_when_target_did_not_keep_the_rules(session_factory, clock):
    f = Fakes()
    f.fws.insert = lambda project, firewall_resource: SimpleNamespace(result=lambda: None)  # silently lost
    t = FirewallTranslator(CFG, session_factory, clients=f, now=clock)
    jid = t.queue("x", {"pair": "web-azure-gcp"}, "a")["job_id"]
    t.run_pending()
    job = t.get(jid)
    assert job["status"] == "FAILED" and "not found on the target" in job["error"]


def test_validation():
    with pytest.raises(ValueError, match="needs security_group_id"):
        FirewallSettings.model_validate({"pairs": [{"name": "a", "source": {"cloud": "aws", "region": "x"},
                                                    "target": {"cloud": "gcp", "project": "p", "network": "n"}}]})
    t = FirewallTranslator(CFG, session_factory=None, clients=None)
    with pytest.raises(ValueError, match="unknown firewall pair"):
        t.parse({"pair": "nope"})
