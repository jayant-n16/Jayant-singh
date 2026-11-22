"""Kubernetes containment: a deny-all NetworkPolicy for a namespace.

Effective only on clusters whose CNI enforces NetworkPolicy (OpenShift SDN/OVN,
Calico, Cilium, ...). The result states this so nobody assumes otherwise.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

POLICY_NAME = "oplia-quarantine-deny-all"
_NS_RE = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
PROTECTED_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease", "default"})

NetworkingApiFactory = Callable[[], Any]


def _default_factory() -> Any:
    from kubernetes import client, config

    try:
        config.load_incluster_config()  # type: ignore[no-untyped-call]
    except config.ConfigException:
        config.load_kube_config()  # type: ignore[no-untyped-call]
    return client.NetworkingV1Api()


class K8sNamespaceIsolationExecutor:
    def __init__(self, api_factory: NetworkingApiFactory = _default_factory) -> None:
        self._factory = api_factory

    @staticmethod
    def _namespace(payload: dict[str, Any]) -> str:
        ns = str(payload.get("namespace", ""))
        if not _NS_RE.fullmatch(ns):
            raise ValueError(f"invalid namespace {ns!r}")
        if ns in PROTECTED_NAMESPACES or ns.startswith("openshift-"):
            raise ValueError(f"refusing to isolate protected namespace {ns!r}")
        return ns

    def describe(self, payload: dict[str, Any]) -> str:
        ns = self._namespace(payload)
        return f"Create NetworkPolicy '{POLICY_NAME}' denying all ingress and egress in namespace {ns}"

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        from kubernetes.client.exceptions import ApiException

        ns = self._namespace(payload)
        body = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": POLICY_NAME, "namespace": ns, "labels": {"app.kubernetes.io/managed-by": "oplia"}},
            "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
        }
        api = self._factory()
        try:
            api.create_namespaced_network_policy(namespace=ns, body=body)
            created = True
        except ApiException as exc:
            if exc.status != 409:
                raise
            # A policy with this name exists; re-assert the deny-all spec in case it was edited.
            api.replace_namespaced_network_policy(name=POLICY_NAME, namespace=ns, body=body)
            created = False
        return {
            "cloud": "k8s",
            "namespace": ns,
            "policy": POLICY_NAME,
            "created": created,
            "note": "Requires a CNI that enforces NetworkPolicy.",
        }
