"""FR-06 cutover and reverse-CDC rollback through an Envoy TCP proxy.

Applications connect to Envoy listeners instead of the database. Envoy reads its listeners and clusters from
files (``path_config_source`` with ``watched_directory``); the engine rewrites the listener file atomically
(write + rename) to change where connections go, then polls Envoy's admin ``/config_dump`` until the new
version is active - that elapsed time is reported.

What Envoy does and does not do (evidence: Envoy listener drain behaviour): a listener update sends **new**
connections to the new cluster at once; existing connections stay on the old listener until they close or
the drain time ends. So:

* read-only listeners can be shifted progressively (``stages``, e.g. 10 -> 50 -> 100 per cent), with a soak
  and an error-budget check (``upstream_cx_connect_fail``) between stages;
* a write listener is switched in one step (two primaries taking writes at once would diverge). Forward CDC
  keeps running through the drain window so writes that still reach the old primary are carried over; then
  the forward connector is paused and the reverse connector (new -> old) is created, so the old database
  stays current for failback for ``retain_days`` (PRD: 7).

Failback is the same switch in the other direction; its measured time is in the result. The PRD's "< 5 s
failback" is checked against that measurement, not assumed.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from oplia_ctl.replication.jobs import JobMachine

ACTION_CUTOVER = "migration.cutover"
ACTION_FAILBACK = "migration.failback"
_N = r"^[a-z0-9][a-z0-9_-]{0,62}$"
TCP_PROXY = "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy"
LISTENER = "type.googleapis.com/envoy.config.listener.v3.Listener"
CLUSTER = "type.googleapis.com/envoy.config.cluster.v3.Cluster"


class Endpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: str = Field(pattern=r"^[A-Za-z0-9.-]{1,253}$")
    port: int = Field(ge=1, le=65535)


class ListenerSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=_N)
    port: int = Field(ge=1, le=65535)
    legacy: str = Field(pattern=_N)          # cluster names
    new: str = Field(pattern=_N)
    writes: bool = True


class ProxySettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    config_dir: str                          # shared with the Envoy pod (e.g. a ConfigMap-free emptyDir/volume)
    admin_url: str = Field(default="http://127.0.0.1:9901", pattern=r"^http://(127\.0\.0\.1|localhost|\[::1\]):\d+$")
    bind_address: str = "0.0.0.0"           # noqa: S104 # nosec B104 - Envoy listens for the applications
    clusters: dict[str, Endpoint]
    listeners: list[ListenerSpec] = Field(min_length=1)
    drain_seconds: int = Field(default=30, ge=0, le=3600)


def bootstrap(cfg: ProxySettings) -> dict[str, Any]:
    port = int(cfg.admin_url.rsplit(":", 1)[1])
    d = cfg.config_dir.rstrip("/")

    # One directory per resource type: Envoy 1.34 fired only one of two subscriptions watching the same
    # directory (observed: a move refreshed CDS but not LDS), so LDS and CDS each get their own.
    def src(kind: str) -> dict[str, Any]:
        return {"path_config_source": {"path": f"{d}/{kind}/{kind}.json", "watched_directory": {"path": f"{d}/{kind}"}}}
    return {"node": {"id": "oplia-migration-proxy", "cluster": "oplia"},
            "admin": {"address": {"socket_address": {"address": "127.0.0.1", "port_value": port}}},
            "dynamic_resources": {"lds_config": src("lds"), "cds_config": src("cds")}}


def cds(cfg: ProxySettings, version: str) -> dict[str, Any]:
    return {"version_info": version, "resources": [
        {"@type": CLUSTER, "name": n, "connect_timeout": "2s", "type": "STRICT_DNS",
         "load_assignment": {"cluster_name": n, "endpoints": [{"lb_endpoints": [{"endpoint": {"address": {
             "socket_address": {"address": e.host, "port_value": e.port}}}}]}]}}
        for n, e in sorted(cfg.clusters.items())]}


def lds(cfg: ProxySettings, weights: dict[str, dict[str, int]], version: str) -> dict[str, Any]:
    res = []
    for li in cfg.listeners:
        w = weights.get(li.name, {li.legacy: 100})
        clusters = [{"name": c, "weight": v} for c, v in sorted(w.items()) if v > 0]
        tcp: dict[str, Any] = {"@type": TCP_PROXY, "stat_prefix": li.name}
        if len(clusters) == 1:
            tcp["cluster"] = clusters[0]["name"]
        else:
            tcp["weighted_clusters"] = {"clusters": clusters}
        res.append({"@type": LISTENER, "name": li.name, "drain_type": "DEFAULT",
                    "address": {"socket_address": {"address": cfg.bind_address, "port_value": li.port}},
                    "filter_chains": [{"filters": [{"name": "envoy.filters.network.tcp_proxy", "typed_config": tcp}]}]})
    return {"version_info": version, "resources": res}


def _atomic_write(path: Path, data: dict[str, Any]) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".oplia-", suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)            # rename within the watched directory: Envoy sees one complete file


class EnvoyRouter:
    def __init__(self, cfg: ProxySettings, http: Any, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.cfg, self.h, self._clock, self._sleep = cfg, http, clock, sleep
        self.dir = Path(cfg.config_dir)

    def weights_file(self) -> Path:
        return self.dir / "state" / "weights.json"

    def current(self) -> dict[str, dict[str, int]]:
        f = self.weights_file()
        return json.loads(f.read_text()) if f.exists() else {li.name: {li.legacy: 100} for li in self.cfg.listeners}

    def write_initial(self) -> None:
        for sub in ("lds", "cds", "state"):
            (self.dir / sub).mkdir(parents=True, exist_ok=True)
        _atomic_write(self.dir / "cds" / "cds.json", cds(self.cfg, "1"))
        _atomic_write(self.dir / "lds" / "lds.json", lds(self.cfg, self.current(), "1"))
        (self.dir / "bootstrap.json").write_text(json.dumps(bootstrap(self.cfg), indent=1))

    def set(self, listener: str, weights: dict[str, int], timeout_s: float = 30) -> dict[str, Any]:
        li = next((x for x in self.cfg.listeners if x.name == listener), None)
        if li is None or set(weights) - {li.legacy, li.new} or sum(weights.values()) != 100 \
                or any(v < 0 for v in weights.values()):
            raise ValueError(f"weights for {listener} must split 100 between {li.legacy if li else '?'} and "
                             f"{li.new if li else '?'}")
        allw = self.current()
        allw[listener] = weights
        version = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        t0 = self._clock()
        _atomic_write(self.dir / "lds" / "lds.json", lds(self.cfg, allw, version))
        _atomic_write(self.weights_file(), allw)
        want = {c: v for c, v in weights.items() if v > 0}
        while True:
            if self.active_version(listener) == version and self.routes(listener) == want:
                return {"listener": listener, "weights": weights, "version": version,
                        "applied_ms": round((self._clock() - t0) * 1000, 1)}
            if self._clock() - t0 > timeout_s:
                raise TimeoutError(f"Envoy did not apply listener version {version} within {timeout_s}s")
            self._sleep(0.05)

    def active_version(self, listener: str) -> str | None:
        """The LDS version Envoy has applied, if ``listener`` is active.

        Observed on Envoy 1.34: after a filesystem LDS update the per-listener ``active_state.version_info`` keeps
        its first value, while the ListenersConfigDump ``version_info`` follows the file; so that is read, and
        ``routes`` confirms the active listener really sends traffic where the weights say."""
        r = self.h.request("GET", f"{self.cfg.admin_url}/config_dump", expected={200})
        for c in r.json().get("configs", []):
            if str(c.get("@type", "")).endswith("ListenersConfigDump"):
                active = [d for d in c.get("dynamic_listeners", []) if d.get("name") == listener
                          and d.get("active_state")]
                return str(c.get("version_info")) if active else None
        return None

    def routes(self, listener: str) -> dict[str, int]:
        r = self.h.request("GET", f"{self.cfg.admin_url}/config_dump", params={"resource": "dynamic_listeners"},
                           expected={200})
        for c in r.json().get("configs", []):
            if c.get("name") == listener:
                tcp = c["active_state"]["listener"]["filter_chains"][0]["filters"][0]["typed_config"]
                if "cluster" in tcp:
                    return {tcp["cluster"]: 100}
                return {x["name"]: int(x["weight"]) for x in tcp["weighted_clusters"]["clusters"]}
        return {}

    def connect_failures(self, cluster: str) -> int:
        flt = f"^cluster\\.{re.escape(cluster)}\\.upstream_cx_connect_fail$"
        r = self.h.request("GET", f"{self.cfg.admin_url}/stats", params={"format": "json", "filter": flt},
                           expected={200})
        return int(sum(s.get("value", 0) for s in r.json().get("stats", []) if "value" in s))


class CutoverSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proxy: ProxySettings
    retain_days: int = Field(default=7, ge=1, le=90)


class Cutover(JobMachine):
    """PRECHECK -> SHIFT (per stage, soak + error budget) -> DRAIN -> REVERSE -> DONE."""

    kind = "cutover"
    action = ACTION_CUTOVER
    title = "Cutover (FR-06)"
    first_step = "PRECHECK"

    def __init__(self, cfg: CutoverSettings, session_factory: Any, router: EnvoyRouter,
                 jobs: Callable[[str, str], dict[str, Any]], kafka_connect: Any = None,
                 audit: Callable[[str, dict[str, Any]], None] | None = None,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC), **kw: Any) -> None:
        super().__init__(session_factory, **kw)
        self.cfg, self.router, self._jobs, self.kc, self._audit, self._wall = cfg, router, jobs, kafka_connect, \
            audit, clock

    def fields(self) -> list[dict[str, Any]]:
        return [{"name": "listener", "label": "Listener", "kind": "select", "required": True,
                 "options": [{"value": li.name, "label": f"{li.name}: {li.legacy} -> {li.new}"
                              + (" (writes)" if li.writes else " (read-only)")} for li in self.cfg.proxy.listeners]},
                {"name": "spec", "label": "Cutover (JSON)", "kind": "textarea", "required": True,
                 "help": '{"lag_job": "<cdc_lag_probe job id>", "parity_job": "<parity_check job id>", '
                         '"stages": [10, 50, 100], "soak_seconds": 300, "max_connect_failures": 0, '
                         '"forward_connector": "...", "reverse_connector": {"name": "...", "config": {...}}}'}]

    def parse(self, params: dict[str, Any]) -> dict[str, Any]:
        li = next((x for x in self.cfg.proxy.listeners if x.name == params.get("listener")), None)
        if li is None:
            raise ValueError("unknown listener")
        spec = params.get("spec", {})
        if isinstance(spec, str):
            spec = json.loads(spec)
        stages = [int(x) for x in spec.get("stages", [100])]
        if not stages or stages[-1] != 100 or any(not 0 < s <= 100 for s in stages) or stages != sorted(stages):
            raise ValueError("stages must increase and end at 100")
        if li.writes and stages != [100]:
            raise ValueError("a write listener is switched in one step (stages [100]); progressive shifts are for "
                             "read-only listeners")
        for k in ("lag_job", "parity_job"):
            if not re.fullmatch(r"[0-9a-f-]{36}", str(spec.get(k, ""))):
                raise ValueError(f"{k} must be the id of a finished job (cutover is refused without evidence)")
        rc = spec.get("reverse_connector")
        if li.writes and not (isinstance(rc, dict) and re.fullmatch(_N, str(rc.get("name", ""))) and
                              isinstance(rc.get("config"), dict) and spec.get("forward_connector")):
            raise ValueError("a write cutover needs forward_connector and reverse_connector {name, config}")
        return {"listener": li.name, "spec": {**spec, "stages": stages,
                                              "soak_seconds": int(spec.get("soak_seconds", 300)),
                                              "max_connect_failures": int(spec.get("max_connect_failures", 0)),
                                              "max_lag_ms": float(spec.get("max_lag_ms", 500))}}

    def target_of(self, payload: dict[str, Any]) -> str:
        return str(payload["listener"])

    def describe(self, payload: dict[str, Any]) -> str:
        p = self.parse(payload)
        li = next(x for x in self.cfg.proxy.listeners if x.name == p["listener"])
        return (f"shift listener {li.name} from {li.legacy} to {li.new} in stages {p['spec']['stages']}"
                + (" and start reverse CDC for failback" if li.writes else ""))

    def _li(self, name: str) -> ListenerSpec:
        return next(x for x in self.cfg.proxy.listeners if x.name == name)

    def _step_precheck(self, job: Any, payload: dict[str, Any], st: dict[str, Any]) -> str:
        sp = payload["spec"]
        lag = self._jobs("cdc_lag_probe", sp["lag_job"])
        par = self._jobs("parity_check", sp["parity_job"])
        r = lag.get("state", {}).get("result", {})
        problems = []
        if lag.get("status") != "SUCCEEDED" or r.get("p99_ms") is None or r["p99_ms"] > sp["max_lag_ms"] \
                or r.get("not_arrived_within_timeout"):
            problems.append(f"lag evidence not good enough: {lag.get('status')} {r}")
        if par.get("status") != "SUCCEEDED" or par.get("state", {}).get("result", {}).get("status") != "MATCH":
            problems.append(f"parity evidence not MATCH: {par.get('status')}")
        st["precheck"] = {"lag": r, "parity_job": sp["parity_job"], "problems": problems}
        if problems:
            raise ValueError("; ".join(problems))
        st.update(stage=0, shifts=[])
        return "SHIFT"

    def _step_shift(self, job: Any, payload: dict[str, Any], st: dict[str, Any]) -> str:
        sp, li = payload["spec"], self._li(payload["listener"])
        i = int(st["stage"])
        pct = sp["stages"][i]
        if st.get("soak_until"):
            if self._wall() < datetime.fromisoformat(st["soak_until"]):
                return "SHIFT"                         # still soaking; next worker run continues
            fails = self.router.connect_failures(li.new) - int(st["fail_base"])
            if fails > sp["max_connect_failures"]:
                back = self.router.set(li.name, {li.legacy: 100, li.new: 0})
                st["auto_rollback"] = {"connect_failures": fails, **back}
                raise RuntimeError(f"{fails} connect failures on {li.new} during soak; traffic moved back")
            st["soak_until"] = None
            st["stage"] = i = i + 1
            if i >= len(sp["stages"]):
                return "DRAIN" if li.writes else "DONE"
            pct = sp["stages"][i]
        st["fail_base"] = self.router.connect_failures(li.new)
        st["shifts"].append(self.router.set(li.name, {li.legacy: 100 - pct, li.new: pct}))
        soak = sp["soak_seconds"] if pct < 100 or not li.writes else 0
        st["soak_until"] = (self._wall() + timedelta(seconds=soak)).isoformat()
        return "SHIFT"

    def _step_drain(self, job: Any, payload: dict[str, Any], st: dict[str, Any]) -> str:
        if not st.get("drain_until"):
            st["drain_until"] = (self._wall() + timedelta(seconds=self.cfg.proxy.drain_seconds)).isoformat()
        if self._wall() < datetime.fromisoformat(st["drain_until"]):
            return "DRAIN"
        return "REVERSE"

    def _step_reverse(self, job: Any, payload: dict[str, Any], st: dict[str, Any]) -> str:
        sp = payload["spec"]
        if self.kc is None:
            raise RuntimeError("reverse CDC needs Kafka Connect (OPLIA_REPLICATION_KAFKA_CONNECT_URL)")
        self.kc.act(sp["forward_connector"], "pause")
        rc = sp["reverse_connector"]
        self.kc.put_config(rc["name"], rc["config"])
        st["reverse"] = {"connector": rc["name"], "retain_until":
                         (self._wall() + timedelta(days=self.cfg.retain_days)).isoformat()}
        return "DONE"

    def finish(self, job: Any) -> None:
        if self._audit is not None:
            self._audit(f"{self.action}.{job.status.lower()}", {"job_id": job.id, "target": job.target,
                                                               "error": job.error})


class Failback(JobMachine):
    """Move a listener back to the legacy cluster (reverse CDC kept it current) and report the switch time."""

    kind = "failback"
    action = ACTION_FAILBACK
    title = "Failback (FR-06)"
    first_step = "SWITCH"

    def __init__(self, cfg: CutoverSettings, session_factory: Any, router: EnvoyRouter, kafka_connect: Any = None,
                 audit: Callable[[str, dict[str, Any]], None] | None = None, **kw: Any) -> None:
        super().__init__(session_factory, **kw)
        self.cfg, self.router, self.kc, self._audit = cfg, router, kafka_connect, audit

    def fields(self) -> list[dict[str, Any]]:
        return [{"name": "listener", "label": "Listener", "kind": "select", "required": True,
                 "options": [{"value": li.name, "label": li.name} for li in self.cfg.proxy.listeners]},
                {"name": "slo_ms", "label": "Failback SLO (ms)", "kind": "number", "initial": "5000"}]

    def parse(self, params: dict[str, Any]) -> dict[str, Any]:
        if not any(li.name == params.get("listener") for li in self.cfg.proxy.listeners):
            raise ValueError("unknown listener")
        slo = float(params.get("slo_ms") or 5000)
        rev = params.get("reverse_connector")
        if rev is not None and not re.fullmatch(_N, str(rev)):
            raise ValueError("reverse_connector must be a connector name")
        return {"listener": params["listener"], "slo_ms": slo, "reverse_connector": rev}

    def target_of(self, payload: dict[str, Any]) -> str:
        return str(payload["listener"])

    def describe(self, payload: dict[str, Any]) -> str:
        return f"move all new connections on {payload['listener']} back to the legacy database"

    def _step_switch(self, job: Any, payload: dict[str, Any], st: dict[str, Any]) -> str:
        li = next(x for x in self.cfg.proxy.listeners if x.name == payload["listener"])
        r = self.router.set(li.name, {li.legacy: 100, li.new: 0})
        if payload.get("reverse_connector") and self.kc is not None:
            self.kc.act(payload["reverse_connector"], "pause")
        st["result"] = {**r, "slo_ms": payload["slo_ms"],
                        "verdict": "MEETS SLO" if r["applied_ms"] < payload["slo_ms"] else "MISSES SLO",
                        "note": "time from writing the listener file to Envoy reporting the new version active; "
                                "existing connections drain separately"}
        return "DONE"

    def finish(self, job: Any) -> None:
        if self._audit is not None:
            r = json.loads(job.state_json).get("result", {})
            self._audit(f"{self.action}.{job.status.lower()}", {"job_id": job.id, "target": job.target,
                                                               "applied_ms": r.get("applied_ms")})
