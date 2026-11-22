"""Self-healing executors. They run only through the safety gate.

* ``aiops.k8s.rolling_restart`` - the same change as ``kubectl rollout restart``
  (a new ``kubectl.kubernetes.io/restartedAt`` pod-template annotation).
* ``aiops.k8s.hpa_scale`` - when the HPA is already at ``maxReplicas`` it raises the maximum by
  a bounded step (never above the configured ceiling); otherwise it lowers the CPU
  utilisation target by a bounded step (never below the floor) so the HPA scales out earlier.
  The patch carries ``resourceVersion``, so a concurrent edit makes it fail instead of being
  overwritten, and the result is re-read and verified.
* ``aiops.runbook`` - launches a registered runbook as a hardened Kubernetes Job.

``NotifyBeforeActExecutor`` wraps each of them so PagerDuty and Slack are told *before* the
action runs; if no channel accepts the message the action is not taken.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from oplia_ctl.aiops.notify import Incident, IncidentNotifier
from oplia_ctl.aiops.runbooks import RunbookSpec
from oplia_ctl.cloud.k8s_isolation import PROTECTED_NAMESPACES

ACTION_ROLLING_RESTART = "aiops.k8s.rolling_restart"
ACTION_HPA_SCALE = "aiops.k8s.hpa_scale"
ACTION_RUNBOOK = "aiops.runbook"
RESTART_ANNOTATION = "kubectl.kubernetes.io/restartedAt"

_NS_RE = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
_NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")
_DB_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}$")
_ALERT_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SUFFIX_RE = re.compile(r"^[a-f0-9]{12}$")
_KINDS = ("Deployment", "StatefulSet", "DaemonSet")

ApiFactory = Callable[[], Any]


class AIOpsActionError(RuntimeError):
    """The action cannot (or must not) be performed in the current cluster state."""


class NotificationRequiredError(AIOpsActionError):
    """No channel accepted the pre-action notification, so the action was not taken."""


def _load_k8s_config() -> None:
    from kubernetes import config

    try:
        config.load_incluster_config()  # type: ignore[no-untyped-call]
    except config.ConfigException:
        config.load_kube_config()  # type: ignore[no-untyped-call]


def _apps_api() -> Any:
    from kubernetes import client

    _load_k8s_config()
    return client.AppsV1Api()


def _autoscaling_api() -> Any:
    from kubernetes import client

    _load_k8s_config()
    return client.AutoscalingV2Api()


def _batch_api() -> Any:
    from kubernetes import client

    _load_k8s_config()
    return client.BatchV1Api()


def validate_namespace(ns: str) -> str:
    if not _NS_RE.fullmatch(ns):
        raise ValueError(f"invalid namespace {ns!r}")
    if ns in PROTECTED_NAMESPACES or ns.startswith(("openshift-", "kube-")):
        raise ValueError(f"refusing to act in protected namespace {ns!r}")
    return ns


def _target(payload: dict[str, Any]) -> tuple[str, str, str]:
    ns = validate_namespace(str(payload.get("namespace", "")))
    kind = str(payload.get("kind", ""))
    if kind not in _KINDS:
        raise ValueError(f"unsupported workload kind {kind!r}")
    name = str(payload.get("name", ""))
    if not _NAME_RE.fullmatch(name):
        raise ValueError(f"invalid workload name {name!r}")
    return ns, kind, name


class K8sRollingRestartExecutor:
    def __init__(self, api_factory: ApiFactory = _apps_api,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self._factory = api_factory
        self._clock = clock

    def describe(self, payload: dict[str, Any]) -> str:
        ns, kind, name = _target(payload)
        return f"Rolling restart of {kind} {ns}/{name} (sets pod-template annotation {RESTART_ANNOTATION})"

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        ns, kind, name = _target(payload)
        stamp = self._clock().astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        body = {"spec": {"template": {"metadata": {"annotations": {RESTART_ANNOTATION: stamp}}}}}
        api = self._factory()
        method = {
            "Deployment": api.patch_namespaced_deployment,
            "StatefulSet": api.patch_namespaced_stateful_set,
            "DaemonSet": api.patch_namespaced_daemon_set,
        }[kind]
        resp = method(name=name, namespace=ns, body=body)
        generation = getattr(getattr(resp, "metadata", None), "generation", None)
        return {"workload": f"{kind}/{ns}/{name}", "restarted_at": stamp, "generation": generation,
                "note": "Rollout progress: kubectl rollout status " f"{kind.lower()}/{name} -n {ns}"}


def _serialize(obj: Any) -> Any:
    from kubernetes.client import ApiClient

    with ApiClient() as c:
        return c.sanitize_for_serialization(obj)


class K8sHpaScaleExecutor:
    def __init__(self, *, max_step: int, max_ceiling: int, cpu_target_step: int, cpu_target_floor: int,
                 api_factory: ApiFactory = _autoscaling_api) -> None:
        if not (1 <= max_step <= 20 and 1 <= max_ceiling <= 1000):
            raise ValueError("max_step must be 1..20 and max_ceiling 1..1000")
        if not (1 <= cpu_target_step <= 50 and 10 <= cpu_target_floor <= 95):
            raise ValueError("cpu_target_step must be 1..50 and cpu_target_floor 10..95")
        self._step = max_step
        self._ceiling = max_ceiling
        self._cpu_step = cpu_target_step
        self._cpu_floor = cpu_target_floor
        self._factory = api_factory

    @staticmethod
    def _hpa_name(payload: dict[str, Any]) -> str:
        hpa = str(payload.get("hpa", ""))
        if not _NAME_RE.fullmatch(hpa):
            raise ValueError(f"invalid HPA name {hpa!r}")
        return hpa

    def describe(self, payload: dict[str, Any]) -> str:
        ns, kind, name = _target(payload)
        hpa = self._hpa_name(payload)
        return (f"HPA {ns}/{hpa} (target {kind}/{name}): if at maxReplicas raise it by up to "
                f"{self._step} (ceiling {self._ceiling}); otherwise lower the CPU utilisation target "
                f"by up to {self._cpu_step} points (floor {self._cpu_floor}%)")

    @staticmethod
    def _cpu_index(metrics: list[dict[str, Any]]) -> int | None:
        for i, m in enumerate(metrics):
            res = m.get("resource") or {}
            target = res.get("target") or {}
            if (m.get("type") == "Resource" and res.get("name") == "cpu"
                    and target.get("type") == "Utilization" and target.get("averageUtilization") is not None):
                return i
        return None

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        ns, kind, name = _target(payload)
        hpa = self._hpa_name(payload)
        api = self._factory()
        obj = api.read_namespaced_horizontal_pod_autoscaler(name=hpa, namespace=ns)
        ref = obj.spec.scale_target_ref
        if ref.kind != kind or ref.name != name:
            raise AIOpsActionError(f"HPA {ns}/{hpa} targets {ref.kind}/{ref.name}, not {kind}/{name}")
        rv = obj.metadata.resource_version
        cur_max = int(obj.spec.max_replicas)
        cur_replicas = int((obj.status.current_replicas if obj.status else None) or 0)

        if cur_replicas >= cur_max:
            if cur_max >= self._ceiling:
                raise AIOpsActionError(f"HPA {ns}/{hpa} is at maxReplicas {cur_max}, which is the configured "
                                       f"ceiling {self._ceiling}; capacity must be reviewed by a person")
            new_max = min(cur_max + self._step, self._ceiling)
            body: dict[str, Any] = {"metadata": {"resourceVersion": rv}, "spec": {"maxReplicas": new_max}}
            change: dict[str, Any] = {"field": "maxReplicas", "from": cur_max, "to": new_max}
        else:
            metrics: list[dict[str, Any]] = _serialize(obj.spec.metrics or [])
            idx = self._cpu_index(metrics)
            if idx is None:
                raise AIOpsActionError(f"HPA {ns}/{hpa} is below maxReplicas ({cur_replicas}/{cur_max}) and "
                                       "has no CPU utilisation target to adjust")
            cur_t = int(metrics[idx]["resource"]["target"]["averageUtilization"])
            if cur_t <= self._cpu_floor:
                raise AIOpsActionError(f"HPA {ns}/{hpa} CPU target {cur_t}% is already at or below the floor "
                                       f"{self._cpu_floor}%")
            new_t = max(cur_t - self._cpu_step, self._cpu_floor)
            metrics[idx]["resource"]["target"]["averageUtilization"] = new_t
            body = {"metadata": {"resourceVersion": rv}, "spec": {"metrics": metrics}}
            change = {"field": "cpu averageUtilization", "from": cur_t, "to": new_t}

        api.patch_namespaced_horizontal_pod_autoscaler(name=hpa, namespace=ns, body=body)
        after = api.read_namespaced_horizontal_pod_autoscaler(name=hpa, namespace=ns)
        if change["field"] == "maxReplicas":
            ok = int(after.spec.max_replicas) == change["to"]
        else:
            idx_after = self._cpu_index(_serialize(after.spec.metrics or []))
            ok = idx_after is not None and int(
                _serialize(after.spec.metrics)[idx_after]["resource"]["target"]["averageUtilization"]) == change["to"]
        if not ok:
            raise AIOpsActionError(f"HPA {ns}/{hpa} did not reflect the change after patching: {change}")
        return {"hpa": f"{ns}/{hpa}", "change": change, "verified": True}


def job_name(runbook_id: str, suffix: str) -> str:
    return f"oplia-rb-{runbook_id}"[:50].rstrip("-") + "-" + suffix


def job_suffix(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]


class K8sRunbookJobExecutor:
    def __init__(self, runbooks: dict[str, RunbookSpec], api_factory: ApiFactory = _batch_api,
                 ttl_after_finished_seconds: int = 86400) -> None:
        self._runbooks = runbooks
        self._factory = api_factory
        self._ttl = ttl_after_finished_seconds

    def _resolve(self, payload: dict[str, Any]) -> tuple[RunbookSpec, str, str, str, dict[str, str]]:
        ns, kind, name = _target(payload)
        rb_id = str(payload.get("runbook", ""))
        spec = self._runbooks.get(rb_id)
        if spec is None:
            raise ValueError(f"runbook {rb_id!r} is not registered")
        if ns not in spec.allowed_namespaces:
            raise ValueError(f"runbook {rb_id!r} is not allowed in namespace {ns!r}")
        alert_id = str(payload.get("alert_id", ""))
        if not _ALERT_RE.fullmatch(alert_id):
            raise ValueError("invalid alert_id")
        suffix = str(payload.get("job_suffix", ""))
        if not _SUFFIX_RE.fullmatch(suffix):
            raise ValueError("invalid job_suffix")
        database = payload.get("database")
        if database is not None and not _DB_RE.fullmatch(str(database)):
            raise ValueError("invalid database name")
        params = {"OPLIA_NAMESPACE": ns, "OPLIA_WORKLOAD_KIND": kind, "OPLIA_WORKLOAD_NAME": name,
                  "OPLIA_DATABASE": str(database or ""), "OPLIA_ALERT_ID": alert_id}
        return spec, ns, kind, job_name(spec.id, suffix), params

    def describe(self, payload: dict[str, Any]) -> str:
        spec, ns, _, jname, _ = self._resolve(payload)
        return (f"Create Job {ns}/{jname} running runbook '{spec.id}' ({spec.description}) "
                f"image {spec.image}, timeout {spec.timeout_seconds}s")

    def build_job(self, payload: dict[str, Any]) -> dict[str, Any]:
        spec, ns, _, jname, params = self._resolve(payload)
        env: list[dict[str, Any]] = [{"name": k, "value": v} for k, v in params.items()]
        env += [{"name": k, "value": v} for k, v in sorted(spec.env.items())]
        env += [{"name": k, "valueFrom": {"secretKeyRef": {"name": ref.secret, "key": ref.key}}}
                for k, ref in sorted(spec.secret_env.items())]
        labels = {"app.kubernetes.io/managed-by": "oplia", "oplia.io/runbook": spec.id}
        pod_spec: dict[str, Any] = {
            "restartPolicy": "Never",
            "automountServiceAccountToken": spec.service_account is not None,
            "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "runbook",
                "image": spec.image,
                "imagePullPolicy": "IfNotPresent",
                "command": list(spec.command),
                "env": env,
                "resources": {"limits": {"cpu": spec.cpu_limit, "memory": spec.memory_limit},
                              "requests": {"cpu": spec.cpu_limit, "memory": spec.memory_limit}},
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],  # noqa: S108  # nosec B108 - pod emptyDir, not host /tmp
            }],
            "volumes": [{"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}}],
        }
        if spec.service_account is not None:
            pod_spec["serviceAccountName"] = spec.service_account
        return {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {"name": jname, "namespace": ns, "labels": labels,
                         "annotations": {"oplia.io/alert-id": params["OPLIA_ALERT_ID"]}},
            "spec": {"backoffLimit": 0, "activeDeadlineSeconds": spec.timeout_seconds,
                     "ttlSecondsAfterFinished": self._ttl,
                     "template": {"metadata": {"labels": labels}, "spec": pod_spec}},
        }

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        from kubernetes.client.exceptions import ApiException

        body = self.build_job(payload)
        ns, jname = body["metadata"]["namespace"], body["metadata"]["name"]
        api = self._factory()
        try:
            api.create_namespaced_job(namespace=ns, body=body)
            created = True
        except ApiException as exc:
            if exc.status != 409:
                raise
            created = False  # same proposal executed before; the Job already exists, do not start another
        return {"job": f"{ns}/{jname}", "created": created, "runbook": body["metadata"]["labels"]["oplia.io/runbook"],
                "note": f"Job started, not awaited. Check: kubectl get job {jname} -n {ns}; "
                        f"logs: kubectl logs job/{jname} -n {ns}"}


def incident_from_payload(payload: dict[str, Any]) -> Incident:
    inc = payload.get("incident")
    if not isinstance(inc, dict):
        raise ValueError("payload has no incident context")
    return Incident(
        dedup_key=str(inc["dedup_key"]), summary=str(inc["summary"]), severity=inc["severity"],
        source=str(inc["source"]), klass=str(inc["klass"]), component=inc.get("component"),
        group=inc.get("group"), details=dict(inc.get("details") or {}),
        links=tuple((str(h), str(t)) for h, t in inc.get("links") or ()),
    )


class NotifyBeforeActExecutor:
    """Sends the incident to PagerDuty/Slack, then runs the inner executor, then reports the result."""

    def __init__(self, inner: Any, notifier: IncidentNotifier, *, require_delivery: bool = True) -> None:
        self._inner = inner
        self._notifier = notifier
        self._require = require_delivery

    def describe(self, payload: dict[str, Any]) -> str:
        channels = ", ".join(self._notifier.channel_names) or "no channels"
        return f"{self._inner.describe(payload)}; notify {channels} before acting"

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        incident = incident_from_payload(payload)
        self._inner.describe(payload)  # validate before telling anyone an action is starting
        pre = self._notifier.notify(incident, "pre_action")
        if self._require and not IncidentNotifier.any_delivered(pre):
            raise NotificationRequiredError(f"pre-action notification not delivered ({pre}); action not taken")
        try:
            result = self._inner(payload)
        except Exception as exc:
            failed = replace(incident, details={
                **incident.details, "outcome": "FAILED", "error": f"{type(exc).__name__}: {str(exc)[:300]}"})
            self._notifier.notify(failed, "result")
            raise
        done = replace(incident, details={**incident.details, "outcome": "EXECUTED",
                                          "result": str(result)[:500]})
        post = self._notifier.notify(done, "result")
        return {**result, "notifications": {"pre_action": pre, "result": post}}
