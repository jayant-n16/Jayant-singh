"""Forced DNS failover / failback outside Global Accelerator (Route 53 and Azure Traffic Manager).

The records themselves are created by the Terraform modules ``aws-route53-failover``,
``azure-traffic-manager-failover`` and ``gcp-cloud-dns-failover``; their health checks fail over
automatically. This ``dr.dns_failover`` job forces the switch when an operator decides to (a planned
DR test, or a degraded-but-passing primary), and switches back:

* Route 53: ``UpdateHealthCheck(Inverted=true)`` on the PRIMARY record's health check makes Route 53
  treat it as unhealthy, so the SECONDARY answers; failback sets ``Inverted=false``.
* Traffic Manager: the primary endpoint's ``endpointStatus`` is set to ``Disabled`` (``Enabled`` to
  fail back), so the priority-2 endpoint answers.

Steps: ``APPLY`` -> ``WAIT`` (until the provider reports the expected state: Route 53 checker
reports from ``GetHealthCheckStatus``; Traffic Manager endpoint status) -> ``DONE``. Cloud DNS
failover is automatic only (its routing policy has no switch to force); the module refuses it.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from oplia_ctl.replication.jobs import JobMachine
from oplia_ctl.replication.models import DrJobRow

ACTION_DNS_FAILOVER = "dr.dns_failover"


class DnsRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    provider: Literal["route53", "traffic_manager"]
    fqdn: str
    # route53
    primary_health_check_id: str = ""
    # traffic_manager
    subscription_id: str = ""
    resource_group: str = ""
    profile: str = ""
    primary_endpoint: str = "primary"
    wait_timeout_seconds: int = Field(default=600, ge=30, le=7200)

    def model_post_init(self, _ctx: Any) -> None:
        if self.provider == "route53" and not self.primary_health_check_id:
            raise ValueError(f"{self.name}: primary_health_check_id is required for route53")
        if self.provider == "traffic_manager" and not (self.subscription_id and self.resource_group and self.profile):
            raise ValueError(f"{self.name}: subscription_id, resource_group and profile are required")


class DnsSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    records: list[DnsRecord] = Field(min_length=1)


class DnsClients:  # pragma: no cover - real SDK wiring
    def route53(self) -> Any:
        import boto3
        return boto3.client("route53")

    def traffic_manager(self, subscription: str) -> Any:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.trafficmanager import TrafficManagerManagementClient
        return TrafficManagerManagementClient(DefaultAzureCredential(), subscription)


class DnsFailover(JobMachine):
    kind = "dns_failover"
    action = ACTION_DNS_FAILOVER
    title = "DNS failover"
    first_step = "APPLY"

    def __init__(self, cfg: DnsSettings, session_factory: Any, clients: Any = None,
                 audit: Callable[[str, dict[str, Any]], None] | None = None, **kw: Any) -> None:
        super().__init__(session_factory, **kw)
        self.cfg = cfg
        self.records = {r.name: r for r in cfg.records}
        self._c = clients or DnsClients()
        self._audit = audit

    def fields(self) -> list[dict[str, Any]]:
        return [
            {"name": "record", "label": "Record", "kind": "select", "required": True,
             "options": [{"value": r.name, "label": f"{r.fqdn} ({r.provider})"} for r in self.cfg.records]},
            {"name": "direction", "label": "Direction", "kind": "radio", "required": True,
             "options": [{"value": "failover", "label": "Fail over to the DR endpoint"},
                         {"value": "failback", "label": "Fail back to the primary endpoint"}]},
        ]

    def summary(self) -> dict[str, Any]:
        return {"records": [f"{r.fqdn} ({r.provider})" for r in self.cfg.records]}

    def parse(self, params: dict[str, Any]) -> dict[str, Any]:
        rec = self.records.get(str(params.get("record", "")))
        if rec is None:
            raise ValueError(f"unknown DNS failover record {params.get('record')!r}")
        direction = str(params.get("direction", ""))
        if direction not in ("failover", "failback"):
            raise ValueError("direction must be failover or failback")
        return {"record": rec.name, "direction": direction}

    def target_of(self, payload: dict[str, Any]) -> str:
        return self.records[payload["record"]].fqdn

    def describe(self, payload: dict[str, Any]) -> str:
        c = self.parse(payload)
        r = self.records[c["record"]]
        if r.provider == "route53":
            how = (f"set Inverted={'true' if c['direction'] == 'failover' else 'false'} on Route 53 health check "
                   f"{r.primary_health_check_id}")
        else:
            how = (f"set Traffic Manager endpoint {r.profile}/{r.primary_endpoint} to "
                   f"{'Disabled' if c['direction'] == 'failover' else 'Enabled'}")
        return f"{c['direction']} {r.fqdn}: {how}, then wait until the provider reports it"

    # --------------------------------------------------------------- steps
    def _step_apply(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        r = self.records[payload["record"]]
        fail = payload["direction"] == "failover"
        if r.provider == "route53":
            hc = self._c.route53().update_health_check(HealthCheckId=r.primary_health_check_id, Inverted=fail)
            st["inverted"] = bool(hc["HealthCheck"]["HealthCheckConfig"].get("Inverted"))
        else:
            tm = self._c.traffic_manager(r.subscription_id)
            ep = tm.endpoints.get(r.resource_group, r.profile, "ExternalEndpoints", r.primary_endpoint)
            st["before"] = ep.endpoint_status
            ep.endpoint_status = "Disabled" if fail else "Enabled"
            tm.endpoints.update(r.resource_group, r.profile, "ExternalEndpoints", r.primary_endpoint, ep)
        st["applied_at"] = self._now().isoformat()
        return "WAIT"

    def _step_wait(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        r = self.records[payload["record"]]
        fail = payload["direction"] == "failover"
        if r.provider == "route53":
            reports = self._c.route53().get_health_check_status(
                HealthCheckId=r.primary_health_check_id)["HealthCheckObservations"]
            # with Inverted=true a passing endpoint is reported as failing ("Failure: ...")
            ok = [o for o in reports if str(o["StatusReport"]["Status"]).startswith("Success")]
            st["checkers"] = {"total": len(reports), "reporting_healthy": len(ok)}
            done = bool(reports) and (len(ok) < len(reports) / 2 if fail else len(ok) >= len(reports) / 2)
        else:
            tm = self._c.traffic_manager(r.subscription_id)
            ep = tm.endpoints.get(r.resource_group, r.profile, "ExternalEndpoints", r.primary_endpoint)
            st["endpoint"] = {"status": ep.endpoint_status, "monitor": ep.endpoint_monitor_status}
            done = (ep.endpoint_status == "Disabled") if fail else (
                ep.endpoint_status == "Enabled" and ep.endpoint_monitor_status == "Online")
        if done:
            return "DONE"
        if (self._now() - datetime.fromisoformat(st["applied_at"])).total_seconds() > r.wait_timeout_seconds:
            raise TimeoutError(f"{payload['direction']} of {r.fqdn} not confirmed within {r.wait_timeout_seconds}s: "
                               f"{st.get('checkers') or st.get('endpoint')}")
        return "WAIT"

    def finish(self, job: DrJobRow) -> None:
        if self._audit is not None:
            pub = self._public(job)
            self._audit("dr_dns_failover", {"job_id": job.id, **pub["payload"], "status": job.status,
                                            "state": pub["state"], "error": job.error})
