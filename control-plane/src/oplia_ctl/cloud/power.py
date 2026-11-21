"""Start / stop a compute instance in AWS, Azure, GCP or IBM Cloud VPC (gated action ``compute.power``).

The payload carries the resource id exactly as the inventory stored it; it is parsed strictly, so
an executor can never act on anything but one named instance:

* AWS  ``arn:aws:ec2:<region>:<account>:instance/i-...``      -> StartInstances / StopInstances
* Azure ``/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Compute/virtualMachines/<vm>``
        -> begin_start / begin_deallocate ("stop" deallocates, so compute billing stops)
* GCP  ``//compute.googleapis.com/projects/<p>/zones/<z>/instances/<name>`` -> instances.start / stop
* IBM  ``crn:v1:bluemix:public:is:<zone>:a/<account>::instance:<id>`` -> POST /v1/instances/<id>/actions
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from oplia_ctl.http import ResilientClient
from oplia_ctl.secrets import SecretProvider

Operation = Literal["start", "stop"]

_AWS = re.compile(r"^arn:aws:ec2:(?P<region>[a-z]{2}(-gov)?-[a-z]+-\d):(?P<acct>\d{12})"
                  r":instance/(?P<id>i-[0-9a-f]{8,17})$")
_AZURE = re.compile(
    r"^/subscriptions/(?P<sub>[0-9a-fA-F-]{36})/resourceGroups/(?P<rg>[A-Za-z0-9_.()-]{1,90})"
    r"/providers/Microsoft\.Compute/virtualMachines/(?P<vm>[A-Za-z0-9_.-]{1,64})$", re.IGNORECASE)
_GCP = re.compile(r"^//compute\.googleapis\.com/projects/(?P<project>[a-z][a-z0-9-]{4,28}[a-z0-9])"
                  r"/zones/(?P<zone>[a-z]+-[a-z]+\d+-[a-z])/instances/(?P<name>[a-z]([-a-z0-9]{0,61}[a-z0-9])?)$")
_IBM = re.compile(r"^crn:v1:bluemix:public:is:(?P<zone>[a-z]{2}-[a-z]+-\d):a/(?P<acct>[0-9a-f]{32})::instance:"
                  r"(?P<id>[0-9a-z]{4}_[0-9a-f-]{36})$")
IBM_VPC_API_VERSION = "2024-04-30"
IBM_IAM_URL = "https://iam.cloud.ibm.com/identity/token"


@dataclass(frozen=True)
class Target:
    cloud: str
    resource_id: str
    region: str
    parts: dict[str, str]


def parse_target(cloud: str, resource_id: str) -> Target:
    pattern = {"aws": _AWS, "azure": _AZURE, "gcp": _GCP, "ibm": _IBM}.get(cloud)
    if pattern is None:
        raise ValueError(f"unsupported cloud {cloud!r}")
    m = pattern.fullmatch(resource_id)
    if not m:
        raise ValueError(f"{cloud}: not an instance resource id this executor supports: {resource_id[:200]!r}")
    parts = {k: v for k, v in m.groupdict().items() if v is not None}
    if cloud == "aws":
        region = parts["region"]
    elif cloud == "gcp":
        region = parts["zone"].rsplit("-", 1)[0]
    elif cloud == "ibm":
        region = parts["zone"].rsplit("-", 1)[0]
    else:
        region = ""
    return Target(cloud, resource_id, region, parts)


def _op(payload: dict[str, Any]) -> Operation:
    op = payload.get("operation")
    if op == "start":
        return "start"
    if op == "stop":
        return "stop"
    raise ValueError("operation must be start or stop")


def _aws_client(region: str) -> Any:
    import boto3

    return boto3.client("ec2", region_name=region)


def _azure_compute(subscription: str) -> Any:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.compute import ComputeManagementClient

    return ComputeManagementClient(DefaultAzureCredential(), subscription)


def _gcp_instances() -> Any:
    from google.cloud import compute_v1

    return compute_v1.InstancesClient()


class ComputePowerExecutor:
    def __init__(self, *, secrets: SecretProvider | None = None, client: ResilientClient | None = None,
                 ibm_api_key_secret: str = "ibm_cloud_api_key",  # noqa: S107 - secret NAME
                 aws_factory: Callable[[str], Any] = _aws_client,
                 azure_factory: Callable[[str], Any] = _azure_compute,
                 gcp_factory: Callable[[], Any] = _gcp_instances,
                 timeout_seconds: float = 600) -> None:
        self._secrets = secrets
        self._client = client
        self._ibm_key = ibm_api_key_secret
        self._aws = aws_factory
        self._azure = azure_factory
        self._gcp = gcp_factory
        self._timeout = timeout_seconds

    def describe(self, payload: dict[str, Any]) -> str:
        t = parse_target(str(payload.get("cloud", "")), str(payload.get("resource_id", "")))
        op = _op(payload)
        verb = "deallocate" if (t.cloud == "azure" and op == "stop") else op
        return f"{verb} {t.cloud} instance {t.resource_id}"

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        t = parse_target(str(payload.get("cloud", "")), str(payload.get("resource_id", "")))
        op = _op(payload)
        if t.cloud == "aws":
            ec2 = self._aws(t.region)
            ids = [t.parts["id"]]
            out = ec2.start_instances(InstanceIds=ids) if op == "start" else ec2.stop_instances(InstanceIds=ids)
            changes = out.get("StartingInstances" if op == "start" else "StoppingInstances") or []
            if not changes:
                raise RuntimeError(f"AWS returned no state change for {ids[0]}")
            ch = changes[0]
            return {"cloud": "aws", "instance_id": ids[0], "operation": op,
                    "previous_state": ch["PreviousState"]["Name"], "current_state": ch["CurrentState"]["Name"]}
        if t.cloud == "azure":
            compute = self._azure(t.parts["sub"])
            vms = compute.virtual_machines
            poller = (vms.begin_start(t.parts["rg"], t.parts["vm"]) if op == "start"
                      else vms.begin_deallocate(t.parts["rg"], t.parts["vm"]))
            poller.result(timeout=self._timeout)
            view = vms.instance_view(t.parts["rg"], t.parts["vm"])
            power = [s.code for s in (view.statuses or []) if str(s.code).startswith("PowerState/")]
            return {"cloud": "azure", "vm": t.parts["vm"], "resource_group": t.parts["rg"], "operation": op,
                    "power_state": power[0] if power else None}
        if t.cloud == "gcp":
            client = self._gcp()
            fn = client.start if op == "start" else client.stop
            operation = fn(project=t.parts["project"], zone=t.parts["zone"], instance=t.parts["name"])
            operation.result(timeout=self._timeout)
            inst = client.get(project=t.parts["project"], zone=t.parts["zone"], instance=t.parts["name"])
            return {"cloud": "gcp", "instance": t.parts["name"], "zone": t.parts["zone"], "operation": op,
                    "status": str(inst.status)}
        if self._secrets is None or self._client is None:
            raise RuntimeError("IBM power actions need a secret provider and HTTP client")
        token = self._client.request(
            "POST", IBM_IAM_URL, expected={200},
            data={"grant_type": "urn:ibm:params:oauth:grant-type:apikey", "apikey": self._secrets.get(self._ibm_key)},
            headers={"Accept": "application/json"}).json()["access_token"]
        base = f"https://{t.region}.iaas.cloud.ibm.com/v1/instances/{t.parts['id']}"
        resp = self._client.request("POST", f"{base}/actions",
                                    params={"version": IBM_VPC_API_VERSION, "generation": "2"},
                                    json={"type": op}, headers={"Authorization": f"Bearer {token}"},
                                    expected={201})
        body = resp.json()
        return {"cloud": "ibm", "instance_id": t.parts["id"], "operation": op, "action_id": body.get("id"),
                "action_status": body.get("status")}
