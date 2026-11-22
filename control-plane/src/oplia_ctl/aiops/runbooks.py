"""Registry of runbooks that the self-healing engine may launch as Kubernetes Jobs.

A runbook is **operator-defined**: a container image pinned by digest and a fixed command.
Alerts can never supply commands; they only provide validated values that are exposed to
the Job as environment variables (``OPLIA_NAMESPACE``, ``OPLIA_WORKLOAD_KIND``,
``OPLIA_WORKLOAD_NAME``, ``OPLIA_DATABASE``, ``OPLIA_ALERT_ID``). Kubernetes expands
``$(VAR)`` references in ``command`` from these variables, so the command stays fixed text.

Credentials (database password, admin token ...) come from Kubernetes Secrets referenced in
``secret_env``; they are never stored in the control plane.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator

from oplia_ctl.aiops.matrix import K8sName, Namespace

EnvName = Annotated[str, Field(pattern=r"^[A-Z_][A-Z0-9_]{0,63}$")]
RESERVED_ENV_PREFIX = "OPLIA_"


class SecretKeyRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    secret: K8sName
    key: Annotated[str, Field(pattern=r"^[-._a-zA-Z0-9]{1,253}$")]


class RunbookSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,40}$")]
    description: Annotated[str, Field(min_length=1, max_length=500)]
    image: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._/:-]*@sha256:[a-f0-9]{64}$", max_length=512)]
    command: list[Annotated[str, Field(min_length=1, max_length=8192)]] = Field(min_length=1, max_length=32)
    allowed_namespaces: list[Namespace] = Field(min_length=1, max_length=200)
    service_account: K8sName | None = None
    env: dict[EnvName, Annotated[str, Field(max_length=4096)]] = Field(default_factory=dict)
    secret_env: dict[EnvName, SecretKeyRef] = Field(default_factory=dict)
    timeout_seconds: Annotated[int, Field(ge=30, le=3600)] = 600
    cpu_limit: Annotated[str, Field(pattern=r"^[0-9]+m?$")] = "500m"
    memory_limit: Annotated[str, Field(pattern=r"^[0-9]+(Mi|Gi)$")] = "256Mi"

    @field_validator("image")
    @classmethod
    def _real_digest(cls, v: str) -> str:
        if v.rsplit("@sha256:", 1)[1] == "0" * 64:
            raise ValueError("image digest is a placeholder; pin the real sha256 digest")
        return v

    @field_validator("env", "secret_env")
    @classmethod
    def _no_reserved(cls, v: dict[str, object]) -> dict[str, object]:
        bad = [k for k in v if k.startswith(RESERVED_ENV_PREFIX)]
        if bad:
            raise ValueError(f"environment names starting with {RESERVED_ENV_PREFIX} are reserved: {bad}")
        return v


_SPECS = TypeAdapter(list[RunbookSpec])


def load_runbooks(path: str) -> dict[str, RunbookSpec]:
    """Load the registry; an empty path means no runbooks (runbook rules are then refused)."""
    if not path:
        return {}
    specs = _SPECS.validate_python(json.loads(Path(path).read_text(encoding="utf-8")))
    registry: dict[str, RunbookSpec] = {}
    for spec in specs:
        if spec.id in registry:
            raise ValueError(f"duplicate runbook id {spec.id!r}")
        overlap = set(spec.env) & set(spec.secret_env)
        if overlap:
            raise ValueError(f"runbook {spec.id!r}: {sorted(overlap)} set in both env and secret_env")
        registry[spec.id] = spec
    return registry
