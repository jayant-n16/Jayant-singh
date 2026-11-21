"""Translate firewall rules and IAM role bindings between AWS, Azure and GCP.

Firewall: AWS security groups <-> Azure network security groups <-> GCP VPC firewall rules, through
a neutral rule (direction, action, protocol, port ranges, CIDRs, priority). Anything the target
cannot express is never silently changed: it is listed in ``lossy`` with the reason, and the rule
is left out. Examples:

* AWS security groups only allow; a ``deny`` rule is dropped for an AWS target.
* References that are not CIDRs (AWS security-group and prefix-list references, Azure service tags
  and application security groups, GCP source/target tags and service accounts) have no
  equivalent in another cloud and are dropped.
* ICMP type/code (AWS) cannot be expressed in Azure NSG rules; GCP takes the protocol only.
* AWS has no priority; Azure/GCP priorities are assigned in source order from ``priority_base``.

The ``dr.firewall_translate`` job (gated: proposal -> approval -> execute) runs
``READ`` (live source) -> ``TRANSLATE`` (stores the plan and the lossy report) -> ``APPLY`` (creates
the translated rules in the existing target SG / NSG / VPC; never deletes anything) -> ``VERIFY``
(reads the target back and checks every translated rule is present) -> ``DONE``.

IAM: there is no built-in equivalence between AWS policies, Azure roles and GCP roles, so the
translation uses only the operator's explicit ``role_map`` and ``principal_map``; a binding without
a mapping is reported, never guessed. IAM translation is a report (``translate_iam``); applying IAM
changes is not done by this module.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from oplia_ctl.replication.jobs import JobMachine
from oplia_ctl.replication.models import DrJobRow

ACTION_FIREWALL = "dr.firewall_translate"
Cloud = Literal["aws", "azure", "gcp"]
_PROTOS = ("tcp", "udp", "icmp", "all")
RulesOut = tuple[list[dict[str, Any]], list[dict[str, str]]]


class Rule(BaseModel):
    """Neutral rule. ``ports`` are inclusive ranges; empty means all ports."""
    model_config = ConfigDict(extra="forbid")
    name: str
    direction: Literal["ingress", "egress"]
    action: Literal["allow", "deny"] = "allow"
    protocol: Literal["tcp", "udp", "icmp", "all"]
    ports: list[tuple[int, int]] = Field(default_factory=list)
    cidrs: list[str]
    priority: int | None = None
    description: str = ""

    def key(self) -> tuple[Any, ...]:
        return (self.direction, self.action, self.protocol, tuple(sorted(self.ports)), tuple(sorted(self.cidrs)))


def _cidr(v: str) -> str | None:
    if v in ("*", "Internet", "Any"):  # Azure '*' / 'Internet' mean any address on the public side
        return "0.0.0.0/0" if v == "*" else None
    try:
        return str(ipaddress.ip_network(v, strict=False))
    except ValueError:
        return None


# ------------------------------------------------------------------------------------- readers
def from_aws(sg: dict[str, Any]) -> tuple[list[Rule], list[dict[str, str]]]:
    rules, lossy = [], []
    for direction, key in (("ingress", "IpPermissions"), ("egress", "IpPermissionsEgress")):
        for i, p in enumerate(sg.get(key, [])):
            name = f"{sg.get('GroupId', 'sg')}-{direction}-{i}"
            proto = {"-1": "all", "6": "tcp", "17": "udp", "1": "icmp"}.get(str(p["IpProtocol"]), str(p["IpProtocol"]))
            if proto not in _PROTOS:
                lossy.append({"rule": name, "reason": f"protocol {p['IpProtocol']} is not supported"})
                continue
            ports: list[tuple[int, int]] = []
            if proto in ("tcp", "udp") and "FromPort" in p:
                ports = [(int(p["FromPort"]), int(p["ToPort"]))]
            if proto == "icmp" and p.get("FromPort", -1) != -1:
                lossy.append({"rule": name, "reason": "ICMP type/code is kept only on an AWS target"})
            cidrs = [r["CidrIp"] for r in p.get("IpRanges", [])] + [r["CidrIpv6"] for r in p.get("Ipv6Ranges", [])]
            for ref, what in (("UserIdGroupPairs", "security-group reference"), ("PrefixListIds", "prefix list")):
                if p.get(ref):
                    lossy.append({"rule": name, "reason": f"{what} has no equivalent in another cloud; dropped"})
            if cidrs:
                rules.append(Rule.model_validate({
                    "name": name, "direction": direction, "protocol": proto, "ports": ports, "cidrs": cidrs,
                    "description": (p.get("IpRanges") or [{}])[0].get("Description", "")}))
    return rules, lossy


def _snake(k: str) -> str:
    import re
    return re.sub(r"(?<!^)([A-Z])", r"_\1", k).lower()


def _azure_rules(nsg: dict[str, Any]) -> list[dict[str, Any]]:
    """Accept the REST shape (azure-mgmt-network >= 30: ``properties.securityRules[].properties``,
    camelCase) and the flat snake_case shape used in plans."""
    if "security_rules" in nsg:
        return list(nsg["security_rules"])
    out = []
    for r in (nsg.get("properties") or {}).get("securityRules") or []:
        flat = {_snake(k): v for k, v in (r.get("properties") or {}).items()}
        flat["name"] = r["name"]
        out.append(flat)
    return out


def from_azure(nsg: dict[str, Any]) -> tuple[list[Rule], list[dict[str, str]]]:
    rules, lossy = [], []
    for r in _azure_rules(nsg):
        name = r["name"]
        proto = {"*": "all", "Tcp": "tcp", "Udp": "udp", "Icmp": "icmp"}.get(r["protocol"])
        if proto is None:
            lossy.append({"rule": name, "reason": f"protocol {r['protocol']} is not supported"})
            continue
        inbound = r["direction"] == "Inbound"
        addrs = [r[k] for k in (("source_address_prefix",) if inbound else ("destination_address_prefix",)) if r.get(k)]
        addrs += r.get("source_address_prefixes" if inbound else "destination_address_prefixes") or []
        cidrs = []
        for a in addrs:
            c = _cidr(a)
            if c is None:
                lossy.append({"rule": name, "reason": f"address {a!r} (service tag) has no equivalent; dropped"})
            else:
                cidrs.append(c)
        if r.get("source_application_security_groups") or r.get("destination_application_security_groups"):
            lossy.append({"rule": name, "reason": "application security group has no equivalent; dropped"})
        prange = [r["destination_port_range"]] if r.get("destination_port_range") else []
        prange += r.get("destination_port_ranges") or []
        ports = []
        for pr in prange:
            if pr == "*":
                continue
            lo, _, hi = pr.partition("-")
            ports.append((int(lo), int(hi or lo)))
        if cidrs:
            rules.append(Rule.model_validate({
                "name": name, "direction": "ingress" if inbound else "egress",
                "action": "allow" if r["access"] == "Allow" else "deny", "protocol": proto,
                "ports": ports if proto in ("tcp", "udp") else [], "cidrs": cidrs,
                "priority": r.get("priority"), "description": r.get("description") or ""}))
    return rules, lossy


def from_gcp(firewalls: list[dict[str, Any]]) -> tuple[list[Rule], list[dict[str, str]]]:
    rules, lossy = [], []
    for fw in firewalls:
        name = fw["name"]
        if fw.get("disabled"):
            lossy.append({"rule": name, "reason": "disabled in GCP; not translated"})
            continue
        if fw.get("target_tags") or fw.get("target_service_accounts") or fw.get("source_tags") \
                or fw.get("source_service_accounts"):
            lossy.append({"rule": name, "reason": "network tags / service accounts have no equivalent; scope "
                                                  "widened is refused, rule dropped"})
            continue
        egress = fw.get("direction") == "EGRESS"
        cidrs = fw.get("destination_ranges" if egress else "source_ranges") or []
        action = "allow" if fw.get("allowed") else "deny"
        entries: list[dict[str, Any]] = list(fw.get("allowed") or fw.get("denied") or [])
        for j, e in enumerate(entries):
            proto = e.get("I_p_protocol") or e.get("ip_protocol") or e.get("IPProtocol")
            if proto not in _PROTOS:
                lossy.append({"rule": f"{name}-{j}", "reason": f"protocol {proto} is not supported"})
                continue
            ports = []
            for p in e.get("ports") or []:
                lo, _, hi = str(p).partition("-")
                ports.append((int(lo), int(hi or lo)))
            rules.append(Rule.model_validate({
                "name": f"{name}-{j}" if len(entries) > 1 else name, "direction": "egress" if egress else "ingress",
                "action": action, "protocol": proto, "ports": ports, "cidrs": list(cidrs),
                "priority": fw.get("priority"), "description": fw.get("description") or ""}))
    return rules, lossy


# ------------------------------------------------------------------------------------- writers
def _prio(rules: list[Rule], base: int, step: int, lo: int, hi: int) -> list[int]:
    out = [base + i * step for i in range(len(rules))]
    if (out and out[-1] > hi) or base < lo:
        raise ValueError(f"{len(rules)} rules do not fit the priority range {lo}..{hi} from {base} step {step}")
    return out


def to_aws(rules: list[Rule]) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, str]]]:
    out: dict[str, list[dict[str, Any]]] = {"ingress": [], "egress": []}
    lossy = []
    for r in rules:
        if r.action == "deny":
            lossy.append({"rule": r.name, "reason": "AWS security groups cannot deny; use a network ACL"})
            continue
        v4 = [c for c in r.cidrs if ipaddress.ip_network(c).version == 4]
        v6 = [c for c in r.cidrs if ipaddress.ip_network(c).version == 6]
        base: dict[str, Any] = {"IpProtocol": "-1" if r.protocol == "all" else r.protocol}
        ranges = (r.ports or [(0, 65535)]) if r.protocol in ("tcp", "udp") else [(-1, -1)]
        for lo, hi in ranges:
            perm = dict(base)
            if r.protocol != "all":
                perm["FromPort"], perm["ToPort"] = lo, hi
            if v4:
                perm["IpRanges"] = [{"CidrIp": c, "Description": r.description[:255]} if r.description
                                    else {"CidrIp": c} for c in v4]
            if v6:
                perm["Ipv6Ranges"] = [{"CidrIpv6": c} for c in v6]
            out[r.direction].append(perm)
    return out, lossy


def to_azure(rules: list[Rule], priority_base: int = 1000, step: int = 10) -> RulesOut:
    lossy: list[dict[str, str]] = []
    pr = _prio(rules, priority_base, step, 100, 4096)
    out = []
    for r, p in zip(rules, pr, strict=True):
        ports = [f"{lo}-{hi}" if lo != hi else str(lo) for lo, hi in r.ports] if r.protocol in ("tcp", "udp") else []
        inbound = r.direction == "ingress"
        out.append({
            "name": _azname(r.name), "priority": p, "direction": "Inbound" if inbound else "Outbound",
            "access": "Allow" if r.action == "allow" else "Deny",
            "protocol": {"all": "*", "tcp": "Tcp", "udp": "Udp", "icmp": "Icmp"}[r.protocol],
            "source_address_prefixes" if inbound else "destination_address_prefixes": sorted(r.cidrs),
            "destination_address_prefix" if inbound else "source_address_prefix": "*",
            "source_port_range": "*",
            **({"destination_port_ranges": ports} if ports else {"destination_port_range": "*"}),
            "description": r.description[:140],
        })
    return out, lossy


def to_gcp(rules: list[Rule], network: str, priority_base: int = 1000, step: int = 10) -> RulesOut:
    pr = _prio(rules, priority_base, step, 0, 65535)
    out = []
    for r, p in zip(rules, pr, strict=True):
        entry: dict[str, Any] = {"I_p_protocol": r.protocol}
        if r.protocol in ("tcp", "udp") and r.ports:
            entry["ports"] = [f"{lo}-{hi}" if lo != hi else str(lo) for lo, hi in r.ports]
        fw: dict[str, Any] = {"name": _gcpname(r.name), "network": network, "priority": p,
                              "direction": "INGRESS" if r.direction == "ingress" else "EGRESS",
                              "allowed" if r.action == "allow" else "denied": [entry],
                              "description": r.description[:2048]}
        fw["source_ranges" if r.direction == "ingress" else "destination_ranges"] = sorted(r.cidrs)
        out.append(fw)
    return out, []


def _azname(n: str) -> str:
    import re
    s = re.sub(r"[^A-Za-z0-9_.-]", "-", n)[:80].rstrip(".-")
    return s if s[:1].isalnum() else f"r{s}"[:80]


def _gcpname(n: str) -> str:
    import re
    s = re.sub(r"[^a-z0-9-]", "-", n.lower())[:63].strip("-")
    return s if s[:1].isalpha() else f"r-{s}"[:63]


Reader = Callable[[Any], tuple[list[Rule], list[dict[str, str]]]]
READERS: dict[str, Reader] = {"aws": from_aws, "azure": from_azure, "gcp": from_gcp}


def translate(source: Cloud, data: Any, target: Cloud, *, network: str = "",
              priority_base: int = 1000) -> dict[str, Any]:
    rules, lossy = READERS[source](data)
    out: Any
    if target == "aws":
        out, more = to_aws(rules)
    elif target == "azure":
        out, more = to_azure(rules, priority_base)
    else:
        out, more = to_gcp(rules, network, priority_base)
    return {"rules": [r.model_dump() for r in rules], "target_rules": out, "lossy": lossy + more}


# ------------------------------------------------------------------------------------- IAM
class IamBinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    principal: str
    role: str
    scope: str = ""


def translate_iam(bindings: list[IamBinding], target: Cloud, role_map: dict[str, dict[str, str]],
                  principal_map: dict[str, dict[str, str]]) -> dict[str, Any]:
    """Only explicit mappings: ``role_map[source_role][target]`` and ``principal_map[source_principal][target]``."""
    out, unmapped = [], []
    for b in bindings:
        role = role_map.get(b.role, {}).get(target)
        who = principal_map.get(b.principal, {}).get(target)
        if role and who:
            out.append({"principal": who, "role": role, "from": b.model_dump()})
        else:
            why = [x for x, ok in (("no role mapping", role), ("no principal mapping", who)) if not ok]
            unmapped.append({"binding": b.model_dump(), "reason": " and ".join(why)})
    return {"bindings": out, "unmapped": unmapped}


# ------------------------------------------------------------------------------------- gated job
class FwEndpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cloud: Cloud
    # aws
    region: str = ""
    security_group_id: str = ""
    # azure
    subscription_id: str = ""
    resource_group: str = ""
    nsg: str = ""
    # gcp
    project: str = ""
    network: str = ""
    name_prefix: str = ""   # gcp: only firewall rules whose name starts with this are read

    def model_post_init(self, _ctx: Any) -> None:
        need = {"aws": ("region", "security_group_id"), "azure": ("subscription_id", "resource_group", "nsg"),
                "gcp": ("project", "network")}[self.cloud]
        missing = [k for k in need if not getattr(self, k)]
        if missing:
            raise ValueError(f"{self.cloud} endpoint needs {', '.join(missing)}")


class FwPair(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    source: FwEndpoint
    target: FwEndpoint
    priority_base: int = Field(default=1000, ge=0, le=65000)


class FirewallSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pairs: list[FwPair] = Field(min_length=1)


class FwClients:  # pragma: no cover - real SDK wiring
    def ec2(self, region: str) -> Any:
        import boto3
        return boto3.client("ec2", region_name=region)

    def network(self, subscription: str) -> Any:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.network import NetworkManagementClient
        return NetworkManagementClient(DefaultAzureCredential(), subscription)

    def gcp_firewalls(self) -> Any:
        from google.cloud import compute_v1
        return compute_v1.FirewallsClient()


class FirewallTranslator(JobMachine):
    kind = "firewall_translate"
    action = ACTION_FIREWALL
    title = "Firewall translation"
    first_step = "READ"

    def __init__(self, cfg: FirewallSettings, session_factory: Any, clients: Any = None,
                 audit: Callable[[str, dict[str, Any]], None] | None = None, **kw: Any) -> None:
        super().__init__(session_factory, **kw)
        self.cfg = cfg
        self.pairs = {p.name: p for p in cfg.pairs}
        self._c = clients or FwClients()
        self._audit = audit

    def fields(self) -> list[dict[str, Any]]:
        return [{"name": "pair", "label": "Rule set", "kind": "select", "required": True,
                 "options": [{"value": p.name, "label": f"{p.name}: {p.source.cloud} -> {p.target.cloud}"}
                             for p in self.cfg.pairs]}]

    def summary(self) -> dict[str, Any]:
        return {"pairs": [f"{p.name}: {p.source.cloud} -> {p.target.cloud}" for p in self.cfg.pairs]}

    def parse(self, params: dict[str, Any]) -> dict[str, Any]:
        if str(params.get("pair", "")) not in self.pairs:
            raise ValueError(f"unknown firewall pair {params.get('pair')!r}")
        return {"pair": str(params["pair"])}

    def target_of(self, payload: dict[str, Any]) -> str:
        return str(payload["pair"])

    def describe(self, payload: dict[str, Any]) -> str:
        p = self.pairs[self.parse(payload)["pair"]]
        return (f"translate {p.source.cloud} rules into {p.target.cloud} ({p.name}); add the translated rules "
                f"(nothing is deleted) and verify them; untranslatable rules are reported, not applied")

    # --------------------------------------------------------------- cloud I/O
    def _read(self, ep: FwEndpoint) -> Any:
        if ep.cloud == "aws":
            return self._c.ec2(ep.region).describe_security_groups(GroupIds=[ep.security_group_id])["SecurityGroups"][0]
        if ep.cloud == "azure":
            return self._c.network(ep.subscription_id).network_security_groups.get(ep.resource_group, ep.nsg).as_dict()
        from google.cloud import compute_v1
        out = []
        for fw in self._c.gcp_firewalls().list(project=ep.project):
            d = compute_v1.Firewall.to_dict(fw, preserving_proto_field_name=True)
            on_net = d.get("network", "").rstrip("/").endswith(f"/networks/{ep.network}")
            if on_net and d["name"].startswith(ep.name_prefix):
                out.append(d)
        return out

    def _step_read(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        st["source"] = self._read(self.pairs[payload["pair"]].source)
        return "TRANSLATE"

    def _step_translate(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        p = self.pairs[payload["pair"]]
        net = (f"projects/{p.target.project}/global/networks/{p.target.network}" if p.target.cloud == "gcp" else "")
        res = translate(p.source.cloud, st.pop("source"), p.target.cloud, network=net, priority_base=p.priority_base)
        st["plan"], st["lossy"] = res["target_rules"], res["lossy"]
        return "APPLY"

    def _step_apply(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        t = self.pairs[payload["pair"]].target
        plan = st["plan"]
        applied = st.setdefault("applied", [])
        if t.cloud == "aws":
            ec2 = self._c.ec2(t.region)
            calls = (("ingress", ec2.authorize_security_group_ingress), ("egress", ec2.authorize_security_group_egress))
            for d, call in calls:
                for i, perm in enumerate(plan[d]):
                    key = f"{d}-{i}"
                    if key in applied:
                        continue
                    try:
                        call(GroupId=t.security_group_id, IpPermissions=[perm])
                    except Exception as exc:  # an identical rule already present is fine
                        if "InvalidPermission.Duplicate" not in str(exc):
                            raise
                    applied.append(key)
        elif t.cloud == "azure":
            from azure.mgmt.network.models import SecurityRule
            net = self._c.network(t.subscription_id)
            for r in plan:
                if r["name"] in applied:
                    continue
                net.security_rules.begin_create_or_update(t.resource_group, t.nsg, r["name"],
                                                          SecurityRule(**r)).result()
                applied.append(r["name"])
        else:
            from google.cloud import compute_v1
            fws = self._c.gcp_firewalls()
            for r in plan:
                if r["name"] in applied:
                    continue
                fws.insert(project=t.project, firewall_resource=compute_v1.Firewall(r)).result()
                applied.append(r["name"])
        return "VERIFY"

    def _step_verify(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        t = self.pairs[payload["pair"]].target
        live = self._read(t)
        got = {r.key() for r in READERS[t.cloud](live)[0]}
        want_rules = READERS[t.cloud](
            {"IpPermissions": st["plan"]["ingress"], "IpPermissionsEgress": st["plan"]["egress"]} if t.cloud == "aws"
            else {"security_rules": st["plan"]} if t.cloud == "azure" else st["plan"])[0]
        missing = [r.name for r in want_rules if r.key() not in got]
        st["verified"] = {"expected": len(want_rules), "missing": missing}
        if missing:
            raise RuntimeError(f"translated rules not found on the target after apply: {missing}")
        return "DONE"

    def finish(self, job: DrJobRow) -> None:
        if self._audit is not None:
            pub = self._public(job)
            self._audit("dr_firewall_translate", {"job_id": job.id, "pair": pub["payload"]["pair"],
                                                  "status": job.status, "lossy": pub["state"].get("lossy"),
                                                  "verified": pub["state"].get("verified"), "error": job.error})
