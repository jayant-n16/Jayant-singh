"""Azure containment: attach a deny-all NSG to a network interface.

The quarantine NSG holds two custom rules at priority 100 (deny all inbound,
deny all outbound), which override Azure's default allow rules (65000+). The
previous NSG id is returned so the change can be reverted.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

QUARANTINE_NSG_PREFIX = "oplia-quarantine"
_NIC_ID_RE = re.compile(
    r"^/subscriptions/(?P<sub>[0-9a-fA-F-]{36})/resourceGroups/(?P<rg>[A-Za-z0-9_.()-]{1,90})"
    r"/providers/Microsoft\.Network/networkInterfaces/(?P<nic>[A-Za-z0-9_.-]{1,80})$"
)

NetworkClientFactory = Callable[[str], Any]  # subscription id -> NetworkManagementClient


def _default_factory(subscription_id: str) -> Any:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.network import NetworkManagementClient

    return NetworkManagementClient(DefaultAzureCredential(), subscription_id)


def parse_nic_id(nic_id: str) -> tuple[str, str, str]:
    m = _NIC_ID_RE.fullmatch(nic_id)
    if not m:
        raise ValueError("nic_id must be a full Azure network interface resource id")
    return m["sub"], m["rg"], m["nic"]


class AzureNicIsolationExecutor:
    def __init__(self, client_factory: NetworkClientFactory = _default_factory) -> None:
        self._factory = client_factory

    def describe(self, payload: dict[str, Any]) -> str:
        _, rg, nic = parse_nic_id(str(payload.get("nic_id", "")))
        return f"Attach deny-all NSG '{QUARANTINE_NSG_PREFIX}-<location>' to NIC {nic} in resource group {rg}"

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        from azure.mgmt.network.models import (
            NetworkSecurityGroup,
            NetworkSecurityGroupPropertiesFormat,
            SecurityRule,
            SecurityRulePropertiesFormat,
        )

        sub, rg, nic_name = parse_nic_id(str(payload.get("nic_id", "")))
        client = self._factory(sub)
        nic = client.network_interfaces.get(rg, nic_name)
        nsg_name = f"{QUARANTINE_NSG_PREFIX}-{nic.location}"

        def deny_all(name: str, direction: str) -> SecurityRule:
            return SecurityRule(name=name, properties=SecurityRulePropertiesFormat(
                priority=100, direction=direction, access="Deny", protocol="*",
                source_address_prefix="*", source_port_range="*",
                destination_address_prefix="*", destination_port_range="*"))

        rules = [deny_all("oplia-deny-all-inbound", "Inbound"), deny_all("oplia-deny-all-outbound", "Outbound")]
        nsg = client.network_security_groups.begin_create_or_update(
            rg, nsg_name,
            NetworkSecurityGroup(location=nic.location, tags={"ManagedBy": "oplia"},
                                 properties=NetworkSecurityGroupPropertiesFormat(security_rules=rules)),
        ).result()
        previous = nic.network_security_group.id if nic.network_security_group else None
        nic.network_security_group = NetworkSecurityGroup(id=nsg.id)
        client.network_interfaces.begin_create_or_update(rg, nic_name, nic).result()
        return {
            "cloud": "azure",
            "nic_id": payload["nic_id"],
            "quarantine_nsg": nsg.id,
            "previous_nsg": previous,
            "note": "A subnet-level NSG still applies as well; the NIC-level deny blocks traffic regardless.",
        }
