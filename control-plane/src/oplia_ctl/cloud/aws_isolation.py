"""AWS containment: move every network interface of an EC2 instance into a
quarantine security group that allows no ingress and no egress.

Notes recorded in every result so operators are not misled:

* Security groups are stateful. Connections already tracked before the change
  can continue until they close; new connections are blocked immediately.
* The previous security groups are returned so the change can be reverted.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

QUARANTINE_SG_NAME = "oplia-quarantine"
_INSTANCE_RE = re.compile(r"^i-[0-9a-f]{8,17}$")
_REGION_RE = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-\d$")

Ec2ClientFactory = Callable[[str], Any]  # region -> boto3 EC2 client


def _default_factory(region: str) -> Any:
    import boto3

    return boto3.client("ec2", region_name=region)


class AwsInstanceIsolationExecutor:
    def __init__(self, client_factory: Ec2ClientFactory = _default_factory) -> None:
        self._factory = client_factory

    @staticmethod
    def _validate(payload: dict[str, Any]) -> tuple[str, str]:
        region, instance_id = str(payload.get("region", "")), str(payload.get("instance_id", ""))
        if not _REGION_RE.fullmatch(region):
            raise ValueError(f"invalid AWS region {region!r}")
        if not _INSTANCE_RE.fullmatch(instance_id):
            raise ValueError(f"invalid EC2 instance id {instance_id!r}")
        return region, instance_id

    def describe(self, payload: dict[str, Any]) -> str:
        region, instance_id = self._validate(payload)
        return (f"Replace security groups on all ENIs of {instance_id} ({region}) with "
                f"'{QUARANTINE_SG_NAME}' (no ingress, no egress)")

    def _quarantine_sg(self, ec2: Any, vpc_id: str) -> str:
        found = ec2.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                     {"Name": "group-name", "Values": [QUARANTINE_SG_NAME]}]
        )["SecurityGroups"]
        if found:
            sg_id = str(found[0]["GroupId"])
            perms = found[0].get("IpPermissionsEgress", [])
        else:
            sg_id = str(ec2.create_security_group(
                GroupName=QUARANTINE_SG_NAME,
                Description="OPLIA quarantine - no ingress, no egress",
                VpcId=vpc_id,
                TagSpecifications=[{"ResourceType": "security-group",
                                    "Tags": [{"Key": "ManagedBy", "Value": "oplia"}]}],
            )["GroupId"])
            perms = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0].get(
                "IpPermissionsEgress", [])
        if perms:  # new SGs get a default allow-all egress rule; remove every egress rule
            ec2.revoke_security_group_egress(GroupId=sg_id, IpPermissions=perms)
        return sg_id

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        region, instance_id = self._validate(payload)
        ec2 = self._factory(region)
        reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
        if not reservations or not reservations[0]["Instances"]:
            raise LookupError(f"instance {instance_id} not found in {region}")
        inst = reservations[0]["Instances"][0]
        sg_id = self._quarantine_sg(ec2, inst["VpcId"])
        previous: dict[str, list[str]] = {}
        for eni in inst.get("NetworkInterfaces", []):
            eni_id = eni["NetworkInterfaceId"]
            previous[eni_id] = [g["GroupId"] for g in eni.get("Groups", [])]
            ec2.modify_network_interface_attribute(NetworkInterfaceId=eni_id, Groups=[sg_id])
        if not previous:
            raise LookupError(f"instance {instance_id} has no network interfaces to isolate")
        # Verify after acting: never report success unless every ENI holds only the quarantine group.
        check = ec2.describe_network_interfaces(NetworkInterfaceIds=list(previous))["NetworkInterfaces"]
        not_isolated = sorted(
            n["NetworkInterfaceId"] for n in check if [g["GroupId"] for g in n.get("Groups", [])] != [sg_id]
        )
        if not_isolated or len(check) != len(previous):
            raise RuntimeError(f"isolation not effective on network interfaces {not_isolated or 'unknown'}; "
                               f"previous groups: {previous}")
        return {
            "cloud": "aws",
            "instance_id": instance_id,
            "region": region,
            "quarantine_security_group": sg_id,
            "previous_groups": previous,
            "note": "Stateful SGs: already-established connections may persist until closed.",
        }
