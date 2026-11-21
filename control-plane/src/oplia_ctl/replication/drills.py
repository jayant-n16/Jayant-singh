"""Automated DR restore drills: boot a replicated image in an isolated sandbox, check it, tear it down.

A drill is a gated ``dr.restore_drill`` proposal (four-eyes, kill switch). Executing it queues a
job; the ``oplia-dr-drill-worker`` CronJob advances it one persisted step at a time:

``LAUNCH`` -> ``WAIT_RUNNING`` -> ``CHECK`` -> ``TEARDOWN`` -> ``WAIT_GONE`` -> ``DONE``

* AWS: ``RunInstances`` in the sandbox subnet and security group, no public IP, IMDSv2 required,
  tagged; running when the instance is ``running`` and both status checks are ``ok``.
  Teardown: ``TerminateInstances``.
* Azure: a NIC in the sandbox subnet (no public IP) and a VM from the image (managed image or
  gallery image version) with ``delete_option=Delete`` on the OS disk and NIC; running when
  provisioning succeeded and the power state is ``running``. Teardown deletes the VM (disk and NIC
  go with it) and then the NIC if it is still there.
* GCP: ``instances.insert`` in the sandbox subnetwork without an access config (no external IP),
  boot disk ``auto_delete``; running when status is ``RUNNING``. Teardown: ``instances.delete``.

Health checks run from the control plane against the instance's *private* IP (the control plane
must be able to reach the sandbox subnet): ``tcp`` (connect to a port) and ``http`` (GET a path,
expect a status). They are retried each worker run until ``check_window_seconds`` has passed.
Teardown always happens, also when launching or checking fails. Every drill ends with a
``dr_restore_drill`` audit event holding the per-check results.
"""

from __future__ import annotations

import re
import socket
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from oplia_ctl.replication.jobs import JobMachine
from oplia_ctl.replication.models import DrJobRow

ACTION_RESTORE_DRILL = "dr.restore_drill"
_AMI = re.compile(r"^ami-[0-9a-f]{8,17}$")
_AZ_IMAGE = re.compile(r"^/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/]+/providers/Microsoft\.Compute/"
                       r"(images/[^/]+|galleries/[^/]+/images/[^/]+/versions/[^/]+)$", re.IGNORECASE)
_GCP_IMAGE = re.compile(r"^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/global/images/[a-z][a-z0-9-]{0,61}[a-z0-9]$")


class AwsSandbox(BaseModel):
    model_config = ConfigDict(extra="forbid")
    region: str
    subnet_id: str = Field(pattern=r"^subnet-[0-9a-f]{8,17}$")
    security_group_id: str = Field(pattern=r"^sg-[0-9a-f]{8,17}$")
    instance_type: str = "t3.small"


class AzureSandbox(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subscription_id: str
    resource_group: str
    location: str
    subnet_id: str
    vm_size: str = "Standard_B2s"
    admin_username: str = "opliadrill"
    ssh_public_key: str = Field(min_length=20)   # public key only; the VM gets no password


class GcpSandbox(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project: str
    zone: str
    subnetwork: str                              # projects/<p>/regions/<r>/subnetworks/<name>
    machine_type: str = "e2-small"


class DrillSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    aws: AwsSandbox | None = None
    azure: AzureSandbox | None = None
    gcp: GcpSandbox | None = None
    boot_timeout_seconds: int = Field(default=900, ge=60, le=7200)
    check_window_seconds: int = Field(default=600, ge=30, le=7200)
    teardown_timeout_seconds: int = Field(default=900, ge=60, le=7200)


class Check(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["tcp", "http"]
    port: int = Field(ge=1, le=65535)
    path: str = Field(default="/", pattern=r"^/[A-Za-z0-9._~/?=&%-]*$", max_length=256)
    expect_status: int = Field(default=200, ge=100, le=599)


def validate_drill(cloud: str, image: str, checks: list[dict[str, Any]], cfg: DrillSettings) -> list[Check]:
    if cloud not in ("aws", "azure", "gcp"):
        raise ValueError("cloud must be aws, azure or gcp")
    if getattr(cfg, cloud) is None:
        raise ValueError(f"no {cloud} drill sandbox configured")
    pattern = {"aws": _AMI, "azure": _AZ_IMAGE, "gcp": _GCP_IMAGE}[cloud]
    if not pattern.match(image):
        raise ValueError({"aws": "AWS image must be an AMI id", "azure": "Azure image must be a managed image or "
                          "gallery image version resource id", "gcp": "GCP image must be "
                          "projects/<project>/global/images/<name>"}[cloud])
    parsed = [Check.model_validate(c) for c in checks]
    if not parsed or len(parsed) > 10:
        raise ValueError("1 to 10 health checks")
    return parsed


def probe(ip: str, check: Check, timeout: float = 5.0) -> tuple[bool, str]:
    """One health check against a private IP. Returns (passed, detail)."""
    if check.type == "tcp":
        try:
            with socket.create_connection((ip, check.port), timeout=timeout):
                return True, f"tcp {check.port} open"
        except OSError as exc:
            return False, f"tcp {check.port}: {type(exc).__name__}"
    import httpx
    try:
        r = httpx.get(f"http://{ip}:{check.port}{check.path}", timeout=timeout, follow_redirects=False)
    except httpx.HTTPError as exc:
        return False, f"http {check.port}{check.path}: {type(exc).__name__}"
    return r.status_code == check.expect_status, f"http {check.port}{check.path}: {r.status_code}"


class DrillClients:
    """Real SDK clients (default credential chains). Tests pass a fake with the same methods."""

    def ec2(self, region: str) -> Any:
        import boto3
        return boto3.client("ec2", region_name=region)

    def azure_compute(self, subscription: str) -> Any:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.compute import ComputeManagementClient
        return ComputeManagementClient(DefaultAzureCredential(), subscription)

    def azure_network(self, subscription: str) -> Any:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.network import NetworkManagementClient
        return NetworkManagementClient(DefaultAzureCredential(), subscription)

    def gcp_instances(self) -> Any:
        from google.cloud import compute_v1
        return compute_v1.InstancesClient()


def parse_checks(v: Any) -> list[dict[str, Any]]:
    """``"tcp:22, http:80/healthz=200"`` or a list of check objects."""
    if isinstance(v, list):
        return [Check.model_validate(c).model_dump() for c in v]
    out = []
    for part in str(v or "").replace("\n", ",").split(","):
        part = part.strip()
        if not part:
            continue
        kind, _, rest = part.partition(":")
        if kind == "tcp":
            out.append(Check(type="tcp", port=int(rest)).model_dump())
        elif kind == "http":
            m = re.fullmatch(r"(\d+)(/[^=\s]*)?(?:=(\d{3}))?", rest)
            if m is None:
                raise ValueError(f"bad http check {part!r} (http:PORT/PATH=STATUS)")
            out.append(Check(type="http", port=int(m.group(1)), path=m.group(2) or "/",
                             expect_status=int(m.group(3) or 200)).model_dump())
        else:
            raise ValueError(f"bad check {part!r}: use tcp:PORT or http:PORT/PATH=STATUS")
    return out


class RestoreDrills(JobMachine):
    kind = "restore_drill"
    action = ACTION_RESTORE_DRILL
    title = "Restore drill"
    first_step = "LAUNCH"

    def __init__(self, cfg: DrillSettings, session_factory: Any, clients: DrillClients | None = None,
                 audit: Callable[[str, dict[str, Any]], None] | None = None,
                 prober: Callable[[str, Check], tuple[bool, str]] = probe,
                 now: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        super().__init__(session_factory, now)
        self.cfg = cfg
        self._c = clients or DrillClients()
        self._audit = audit
        self._probe = prober

    # ------------------------------------------------------------------ module / gate executor
    def fields(self) -> list[dict[str, Any]]:
        clouds = [c for c in ("aws", "azure", "gcp") if getattr(self.cfg, c) is not None]
        return [
            {"name": "cloud", "label": "Sandbox cloud", "kind": "select", "required": True,
             "options": [{"value": c, "label": c.upper()} for c in clouds]},
            {"name": "image", "label": "Replicated image", "kind": "text", "required": True, "maxLength": 512,
             "help": "AMI id, Azure image / gallery image version id, or projects/<p>/global/images/<name>"},
            {"name": "checks", "label": "Health checks", "kind": "text", "required": True, "maxLength": 500,
             "initial": "tcp:22", "help": "Comma separated: tcp:PORT or http:PORT/PATH=STATUS"},
        ]

    def parse(self, params: dict[str, Any]) -> dict[str, Any]:
        cloud, image = str(params.get("cloud", "")), str(params.get("image", "")).strip()
        checks = parse_checks(params.get("checks"))
        validate_drill(cloud, image, checks, self.cfg)
        return {"cloud": cloud, "image": image, "checks": checks}

    def target_of(self, payload: dict[str, Any]) -> str:
        return str(payload["image"])

    def summary(self) -> dict[str, Any]:
        return {"sandboxes": [c for c in ("aws", "azure", "gcp") if getattr(self.cfg, c) is not None],
                "boot_timeout_seconds": self.cfg.boot_timeout_seconds,
                "check_window_seconds": self.cfg.check_window_seconds}

    def describe(self, payload: dict[str, Any]) -> str:
        checks = validate_drill(payload["cloud"], payload["image"], payload.get("checks") or [], self.cfg)
        return (f"Boot {payload['image']} in the {payload['cloud']} drill sandbox (no public IP), run "
                f"{len(checks)} health check(s) ({', '.join(f'{c.type}:{c.port}' for c in checks)}), "
                f"then delete the instance")

    # ------------------------------------------------------------------ helpers
    def _elapsed(self, st: dict[str, Any], key: str) -> float:
        return (self._now() - datetime.fromisoformat(st[key])).total_seconds()

    def _name(self, job: DrJobRow) -> str:
        return f"oplia-drill-{job.id[:8]}"

    def _tags(self, job: DrJobRow) -> dict[str, str]:
        return {"oplia-drill": job.id, "oplia-purpose": "dr-restore-drill"}

    # ------------------------------------------------------------------ steps
    def _step_launch(self, job: DrJobRow, p: dict[str, Any], st: dict[str, Any]) -> str:
        st["launched_at"] = self._now().isoformat()
        name = self._name(job)
        cloud = p["cloud"]
        if cloud == "aws":
            a = self.cfg.aws
            if a is None:
                raise RuntimeError("AWS sandbox no longer configured")
            r = self._c.ec2(a.region).run_instances(
                ImageId=p["image"], InstanceType=a.instance_type, MinCount=1, MaxCount=1,
                NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": a.subnet_id, "Groups": [a.security_group_id],
                                    "AssociatePublicIpAddress": False, "DeleteOnTermination": True}],
                MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
                ClientToken=job.id,
                TagSpecifications=[{"ResourceType": rt, "Tags": [{"Key": k, "Value": v} for k, v in
                                                                 {**self._tags(job), "Name": name}.items()]}
                                   for rt in ("instance", "volume")])
            st["instance_id"] = r["Instances"][0]["InstanceId"]
        elif cloud == "azure":
            from azure.mgmt.compute.models import (
                HardwareProfile,
                ImageReference,
                LinuxConfiguration,
                ManagedDiskParameters,
                NetworkInterfaceReference,
                NetworkInterfaceReferenceProperties,
                NetworkProfile,
                OSDisk,
                OSProfile,
                SshConfiguration,
                SshPublicKey,
                StorageProfile,
                VirtualMachine,
                VirtualMachineProperties,
            )
            from azure.mgmt.network.models import (
                NetworkInterface,
                NetworkInterfaceIPConfiguration,
                NetworkInterfaceIPConfigurationPropertiesFormat,
                NetworkInterfacePropertiesFormat,
                Subnet,
            )
            z = self.cfg.azure
            if z is None:
                raise RuntimeError("Azure sandbox no longer configured")
            nic = self._c.azure_network(z.subscription_id).network_interfaces.begin_create_or_update(
                z.resource_group, f"{name}-nic",
                NetworkInterface(location=z.location, tags=self._tags(job),
                                 properties=NetworkInterfacePropertiesFormat(ip_configurations=[
                                     NetworkInterfaceIPConfiguration(
                                         name="ipconfig1", properties=NetworkInterfaceIPConfigurationPropertiesFormat(
                                             subnet=Subnet(id=z.subnet_id), private_ip_allocation_method="Dynamic"))
                                 ]))).result()
            st["nic_id"] = nic.id
            vm = VirtualMachine(location=z.location, tags=self._tags(job), properties=VirtualMachineProperties(
                hardware_profile=HardwareProfile(vm_size=z.vm_size),
                storage_profile=StorageProfile(
                    image_reference=ImageReference(id=p["image"]),
                    os_disk=OSDisk(create_option="FromImage", delete_option="Delete",
                                   managed_disk=ManagedDiskParameters(storage_account_type="StandardSSD_LRS"))),
                os_profile=OSProfile(computer_name=name, admin_username=z.admin_username,
                                     linux_configuration=LinuxConfiguration(
                                         disable_password_authentication=True,
                                         ssh=SshConfiguration(public_keys=[SshPublicKey(
                                             path=f"/home/{z.admin_username}/.ssh/authorized_keys",
                                             key_data=z.ssh_public_key)]))),
                network_profile=NetworkProfile(network_interfaces=[
                    NetworkInterfaceReference(id=nic.id, properties=NetworkInterfaceReferenceProperties(
                        primary=True, delete_option="Delete"))])))
            self._c.azure_compute(z.subscription_id).virtual_machines.begin_create_or_update(
                z.resource_group, name, vm)
            st["vm_name"] = name
        else:
            from google.cloud import compute_v1
            g = self.cfg.gcp
            if g is None:
                raise RuntimeError("GCP sandbox no longer configured")
            inst = compute_v1.Instance(
                name=name, machine_type=f"zones/{g.zone}/machineTypes/{g.machine_type}",
                labels=self._tags(job),
                disks=[compute_v1.AttachedDisk(boot=True, auto_delete=True, initialize_params=
                                               compute_v1.AttachedDiskInitializeParams(source_image=p["image"]))],
                network_interfaces=[compute_v1.NetworkInterface(subnetwork=g.subnetwork)],   # no access_configs
                shielded_instance_config=compute_v1.ShieldedInstanceConfig(enable_secure_boot=False))
            self._c.gcp_instances().insert(project=g.project, zone=g.zone, instance_resource=inst,
                                           request_id=str(uuid.UUID(job.id)))
            st["instance_name"] = name
        return "WAIT_RUNNING"

    def _step_wait_running(self, job: DrJobRow, p: dict[str, Any], st: dict[str, Any]) -> str:
        ip = self._running_ip(p["cloud"], st)
        if ip is None:
            if self._elapsed(st, "launched_at") > self.cfg.boot_timeout_seconds:
                raise TimeoutError(f"instance not running within {self.cfg.boot_timeout_seconds}s")
            return "WAIT_RUNNING"
        st["private_ip"] = ip
        st["running_at"] = self._now().isoformat()
        st["boot_seconds"] = round(self._elapsed(st, "launched_at"), 1)
        return "CHECK"

    def _running_ip(self, cloud: str, st: dict[str, Any]) -> str | None:
        if cloud == "aws":
            a = self.cfg.aws
            if a is None:
                raise RuntimeError("AWS sandbox no longer configured")
            ec2 = self._c.ec2(a.region)
            inst = ec2.describe_instances(InstanceIds=[st["instance_id"]])["Reservations"][0]["Instances"][0]
            if inst["State"]["Name"] in ("shutting-down", "terminated", "stopped", "stopping"):
                raise RuntimeError(f"instance is {inst['State']['Name']}")
            if inst["State"]["Name"] != "running":
                return None
            statuses = ec2.describe_instance_status(InstanceIds=[st["instance_id"]])["InstanceStatuses"]
            if not statuses:
                return None
            s0 = statuses[0]
            st["status_checks"] = {"system": s0["SystemStatus"]["Status"], "instance": s0["InstanceStatus"]["Status"]}
            if "impaired" in st["status_checks"].values():
                raise RuntimeError(f"status checks impaired: {st['status_checks']}")
            return str(inst["PrivateIpAddress"]) if set(st["status_checks"].values()) == {"ok"} else None
        if cloud == "azure":
            z = self.cfg.azure
            if z is None:
                raise RuntimeError("Azure sandbox no longer configured")
            vm = self._c.azure_compute(z.subscription_id).virtual_machines.get(
                z.resource_group, st["vm_name"], expand="instanceView")
            props = vm.properties
            if props.provisioning_state == "Failed":
                raise RuntimeError("VM provisioning failed")
            codes = [s.code for s in (props.instance_view.statuses if props.instance_view else []) or []]
            st["power"] = next((c for c in codes if c and c.startswith("PowerState/")), None)
            if props.provisioning_state != "Succeeded" or st["power"] != "PowerState/running":
                return None
            nic = self._c.azure_network(z.subscription_id).network_interfaces.get(
                z.resource_group, st["nic_id"].rsplit("/", 1)[-1])
            return str(nic.properties.ip_configurations[0].properties.private_ip_address)
        g = self.cfg.gcp
        if g is None:
            raise RuntimeError("GCP sandbox no longer configured")
        inst = self._c.gcp_instances().get(project=g.project, zone=g.zone, instance=st["instance_name"])
        st["gcp_status"] = inst.status
        if inst.status in ("STOPPING", "TERMINATED", "SUSPENDED"):
            raise RuntimeError(f"instance is {inst.status}")
        return str(inst.network_interfaces[0].network_i_p) if inst.status == "RUNNING" else None

    def _step_check(self, job: DrJobRow, p: dict[str, Any], st: dict[str, Any]) -> str:
        checks = [Check.model_validate(c) for c in p["checks"]]
        results = []
        for c in checks:
            ok, detail = self._probe(st["private_ip"], c)
            results.append({"check": c.model_dump(), "passed": ok, "detail": detail})
        st["checks"] = results
        st["check_attempts"] = int(st.get("check_attempts", 0)) + 1
        if all(r["passed"] for r in results):
            st["verdict"] = "PASSED"
            return "TEARDOWN"
        if self._elapsed(st, "running_at") > self.cfg.check_window_seconds:
            st["verdict"] = "FAILED"
            return "TEARDOWN"          # tear down first; the job is marked FAILED after teardown
        return "CHECK"

    def _step_teardown(self, job: DrJobRow, p: dict[str, Any], st: dict[str, Any]) -> str:
        self._delete(p["cloud"], st)
        st["teardown_started_at"] = self._now().isoformat()
        return "WAIT_GONE"

    def _step_wait_gone(self, job: DrJobRow, p: dict[str, Any], st: dict[str, Any]) -> str:
        if not self._gone(p["cloud"], st):
            if self._elapsed(st, "teardown_started_at") > self.cfg.teardown_timeout_seconds:
                raise TimeoutError("drill instance still exists after teardown timeout: delete it by hand")
            return "WAIT_GONE"
        st["torn_down"] = True
        if st.get("verdict") != "PASSED":
            raise RuntimeError("health checks did not pass: " + "; ".join(
                r["detail"] for r in st.get("checks", []) if not r["passed"]))
        return "DONE"

    # ------------------------------------------------------------------ teardown
    def _delete(self, cloud: str, st: dict[str, Any]) -> None:
        if cloud == "aws" and st.get("instance_id") and self.cfg.aws:
            self._c.ec2(self.cfg.aws.region).terminate_instances(InstanceIds=[st["instance_id"]])
        elif cloud == "azure" and self.cfg.azure:
            z = self.cfg.azure
            if st.get("vm_name"):
                self._c.azure_compute(z.subscription_id).virtual_machines.begin_delete(
                    z.resource_group, st["vm_name"]).result()
            if st.get("nic_id"):
                self._delete_nic(z, st)
        elif cloud == "gcp" and st.get("instance_name") and self.cfg.gcp:
            g = self.cfg.gcp
            self._c.gcp_instances().delete(project=g.project, zone=g.zone, instance=st["instance_name"])

    def _delete_nic(self, z: AzureSandbox, st: dict[str, Any]) -> None:
        from azure.core.exceptions import ResourceNotFoundError
        try:
            self._c.azure_network(z.subscription_id).network_interfaces.begin_delete(
                z.resource_group, st["nic_id"].rsplit("/", 1)[-1]).result()
        except ResourceNotFoundError:
            pass                        # removed with the VM (delete_option=Delete)

    def _gone(self, cloud: str, st: dict[str, Any]) -> bool:
        if cloud == "aws":
            if not st.get("instance_id") or self.cfg.aws is None:
                return True
            r = self._c.ec2(self.cfg.aws.region).describe_instances(InstanceIds=[st["instance_id"]])
            return bool(r["Reservations"][0]["Instances"][0]["State"]["Name"] == "terminated")
        if cloud == "azure":
            from azure.core.exceptions import ResourceNotFoundError
            z = self.cfg.azure
            if not st.get("vm_name") or z is None:
                return True
            try:
                self._c.azure_compute(z.subscription_id).virtual_machines.get(z.resource_group, st["vm_name"])
            except ResourceNotFoundError:
                return True
            return False
        g = self.cfg.gcp
        if not st.get("instance_name") or g is None:
            return True
        from google.api_core.exceptions import NotFound
        try:
            self._c.gcp_instances().get(project=g.project, zone=g.zone, instance=st["instance_name"])
        except NotFound:
            return True
        return False

    def on_failure(self, job: DrJobRow, payload: dict[str, Any], state: dict[str, Any], error: str) -> None:
        if state.get("torn_down"):
            return
        self._delete(payload["cloud"], state)
        state["teardown_requested_after_failure"] = True
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:          # quick look only; WAIT_GONE is not re-entered
            if self._gone(payload["cloud"], state):
                state["torn_down"] = True
                break
            time.sleep(1)

    def finish(self, job: DrJobRow) -> None:
        if self._audit is None:
            return
        pub = self._public(job)
        st = pub["state"]
        self._audit("dr_restore_drill", {
            "job_id": job.id, "cloud": pub["payload"]["cloud"], "image": pub["payload"]["image"],
            "status": job.status, "verdict": st.get("verdict"), "boot_seconds": st.get("boot_seconds"),
            "checks": st.get("checks", []), "torn_down": bool(st.get("torn_down")), "error": job.error})
