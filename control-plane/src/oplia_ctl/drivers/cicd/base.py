"""Common types for CI/CD drivers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

Cloud = Literal["aws", "azure", "gcp", "ibm"]

# Conservative character sets: these values end up as pipeline variables, so they
# must never be able to carry shell metacharacters.
_ZONE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_BLUEPRINT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


Operation = Literal["remediate", "destroy"]


class RemediationRequest(BaseModel):
    """A validated pipeline request: drift remediation (default) or TTL teardown.

    ``operation`` defaults to ``remediate`` so proposals stored before Phase 2
    (which have no operation field) keep their original meaning.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    zone_name: str
    cloud: Cloud
    account_id: str
    blueprint: str
    correlation_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")
    operation: Operation = "remediate"

    @field_validator("zone_name")
    @classmethod
    def _zone(cls, v: str) -> str:
        if not _ZONE_RE.fullmatch(v):
            raise ValueError("zone_name may contain letters, digits, '.', '_' and '-' only")
        return v

    @field_validator("account_id")
    @classmethod
    def _account(cls, v: str) -> str:
        if not _ACCOUNT_RE.fullmatch(v):
            raise ValueError("account_id may contain letters, digits, '_' and '-' only")
        return v

    @field_validator("blueprint")
    @classmethod
    def _blueprint(cls, v: str) -> str:
        if not _BLUEPRINT_RE.fullmatch(v):
            raise ValueError("blueprint must be lowercase letters, digits and '-'")
        return v

    def as_variables(self) -> dict[str, str]:
        return {
            "ZONE_NAME": self.zone_name,
            "CLOUD": self.cloud,
            "ACCOUNT_ID": self.account_id,
            "BLUEPRINT": self.blueprint,
            "CORRELATION_ID": self.correlation_id,
            "OPERATION": self.operation,
        }


@dataclass(frozen=True)
class TriggerResult:
    system: str
    accepted: bool
    reference: str  # run/pipeline/queue reference when the system returns one
    detail: dict[str, Any]


class CICDDriver(Protocol):
    name: str

    def describe(self, req: RemediationRequest) -> str: ...

    def trigger(self, req: RemediationRequest) -> TriggerResult: ...
