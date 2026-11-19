from __future__ import annotations

from types import SimpleNamespace

import boto3
import pytest
from moto import mock_aws

from oplia_ctl.cloud.aws_isolation import QUARANTINE_SG_NAME, AwsInstanceIsolationExecutor
from oplia_ctl.cloud.azure_isolation import AzureNicIsolationExecutor, parse_nic_id
from oplia_ctl.cloud.k8s_isolation import POLICY_NAME, K8sNamespaceIsolationExecutor

# ----------------------------------------------------------------- AWS (moto)


@pytest.fixture
def aws_env(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_DEFAULT_REGION": "us-east-1"}.items():
        monkeypatch.setenv(k, v)
    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
        web_sg = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
        # Note: moto (unlike AWS) keeps launch-time SecurityGroupIds after ModifyNetworkInterfaceAttribute,
        # so the workload SG is attached to the ENI after launch instead. The executor's verify-after-act
        # check is tested separately below with a client that does not apply the change.
        instance = ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1,
                                     SubnetId=subnet)["Instances"][0]
        eni = instance["NetworkInterfaces"][0]["NetworkInterfaceId"]
        ec2.modify_network_interface_attribute(NetworkInterfaceId=eni, Groups=[web_sg])
        yield ec2, vpc, instance["InstanceId"], web_sg


def test_aws_isolation_moves_eni_into_quarantine(aws_env):
    ec2, _vpc, inst, web_sg = aws_env
    ex = AwsInstanceIsolationExecutor(lambda region: boto3.client("ec2", region_name=region))
    res = ex({"region": "us-east-1", "instance_id": inst})
    sg = ec2.describe_security_groups(GroupIds=[res["quarantine_security_group"]])["SecurityGroups"][0]
    assert sg["GroupName"] == QUARANTINE_SG_NAME
    assert sg["IpPermissions"] == [] and sg["IpPermissionsEgress"] == []
    eni_id = next(iter(res["previous_groups"]))
    eni = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])["NetworkInterfaces"][0]
    assert [g["GroupId"] for g in eni["Groups"]] == [res["quarantine_security_group"]]
    assert res["previous_groups"][eni_id] == [web_sg]


class _StickyEc2:
    """EC2 stub whose ModifyNetworkInterfaceAttribute silently does not take effect."""

    def describe_instances(self, InstanceIds):
        return {"Reservations": [{"Instances": [{"VpcId": "vpc-1", "NetworkInterfaces": [
            {"NetworkInterfaceId": "eni-1", "Groups": [{"GroupId": "sg-web"}]}]}]}]}

    def describe_security_groups(self, **kw):
        return {"SecurityGroups": [{"GroupId": "sg-q", "IpPermissionsEgress": []}]}

    def modify_network_interface_attribute(self, **kw):
        pass

    def describe_network_interfaces(self, NetworkInterfaceIds):
        return {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-1", "Groups": [{"GroupId": "sg-web"}]}]}


def test_aws_isolation_fails_loudly_if_change_did_not_apply():
    ex = AwsInstanceIsolationExecutor(lambda region: _StickyEc2())
    with pytest.raises(RuntimeError, match="isolation not effective"):
        ex({"region": "us-east-1", "instance_id": "i-0123456789abcdef0"})


def test_aws_isolation_is_repeatable(aws_env):
    _, _, inst, _ = aws_env
    ex = AwsInstanceIsolationExecutor(lambda region: boto3.client("ec2", region_name=region))
    first = ex({"region": "us-east-1", "instance_id": inst})
    second = ex({"region": "us-east-1", "instance_id": inst})
    assert first["quarantine_security_group"] == second["quarantine_security_group"]


@pytest.mark.parametrize("payload", [
    {"region": "us-east-1", "instance_id": "i-xyz; rm"},
    {"region": "not a region", "instance_id": "i-0123456789abcdef0"},
])
def test_aws_isolation_validates_input(payload):
    with pytest.raises(ValueError):
        AwsInstanceIsolationExecutor(lambda r: None).describe(payload)


# ----------------------------------------------------------- Azure (fakes)
NIC_ID = ("/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-prod"
          "/providers/Microsoft.Network/networkInterfaces/vm1-nic")


class _Poller:
    def __init__(self, value):
        self._v = value

    def result(self):
        return self._v


class FakeNetworkClient:
    def __init__(self):
        self.nic = SimpleNamespace(location="eastus", network_security_group=SimpleNamespace(id="/old/nsg"))
        self.created_nsg = None
        self.updated_nic = None
        self.network_interfaces = SimpleNamespace(get=self._get_nic, begin_create_or_update=self._update_nic)
        self.network_security_groups = SimpleNamespace(begin_create_or_update=self._create_nsg)

    def _get_nic(self, rg, name):
        assert (rg, name) == ("rg-prod", "vm1-nic")
        return self.nic

    def _create_nsg(self, rg, name, nsg):
        self.created_nsg = (rg, name, nsg)
        return _Poller(SimpleNamespace(id=f"/nsg/{name}"))

    def _update_nic(self, rg, name, nic):
        self.updated_nic = nic
        return _Poller(nic)


def test_azure_isolation_attaches_deny_all_nsg():
    fake = FakeNetworkClient()
    res = AzureNicIsolationExecutor(lambda sub: fake)({"nic_id": NIC_ID})
    _, name, nsg = fake.created_nsg
    assert name == "oplia-quarantine-eastus"
    rules = {(r.direction, r.access, r.priority) for r in nsg.security_rules}
    assert rules == {("Inbound", "Deny", 100), ("Outbound", "Deny", 100)}
    assert fake.updated_nic.network_security_group.id == "/nsg/oplia-quarantine-eastus"
    assert res["previous_nsg"] == "/old/nsg"


@pytest.mark.parametrize("bad", ["/subscriptions/x/resourceGroups/rg", NIC_ID + "/../x", ""])
def test_azure_nic_id_validation(bad):
    with pytest.raises(ValueError):
        parse_nic_id(bad)


# ------------------------------------------------------------ K8s (fakes)


class FakeNetApi:
    def __init__(self, conflict=False):
        self.conflict = conflict
        self.created = []
        self.replaced = []

    def create_namespaced_network_policy(self, namespace, body):
        if self.conflict:
            from kubernetes.client.exceptions import ApiException

            raise ApiException(status=409)
        self.created.append((namespace, body))

    def replace_namespaced_network_policy(self, name, namespace, body):
        self.replaced.append((name, namespace, body))


def test_k8s_isolation_creates_deny_all():
    api = FakeNetApi()
    res = K8sNamespaceIsolationExecutor(lambda: api)({"namespace": "payments"})
    ns, body = api.created[0]
    assert ns == "payments" and body["metadata"]["name"] == POLICY_NAME
    assert body["spec"] == {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}
    assert res["created"] is True


def test_k8s_isolation_reasserts_existing_policy():
    api = FakeNetApi(conflict=True)
    res = K8sNamespaceIsolationExecutor(lambda: api)({"namespace": "payments"})
    assert res["created"] is False and api.replaced[0][0] == POLICY_NAME


@pytest.mark.parametrize("ns", ["kube-system", "openshift-monitoring", "default", "Bad_NS"])
def test_k8s_refuses_protected_or_invalid_namespaces(ns):
    with pytest.raises(ValueError):
        K8sNamespaceIsolationExecutor(lambda: None).describe({"namespace": ns})
