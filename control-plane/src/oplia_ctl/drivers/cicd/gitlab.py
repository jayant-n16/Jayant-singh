"""GitLab CI driver: pipeline trigger token.

API: ``POST /api/v4/projects/:id/trigger/pipeline`` (form: token, ref,
``variables[KEY]``) -> 201 with the created pipeline JSON.
"""

from __future__ import annotations

import re
from urllib.parse import quote

from oplia_ctl.drivers.cicd.base import RemediationRequest, TriggerResult
from oplia_ctl.http import ResilientClient
from oplia_ctl.secrets import SecretProvider

_PROJECT_RE = re.compile(r"^(\d+|[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)+)$")
_REF_RE = re.compile(r"^[A-Za-z0-9_./-]{1,200}$")


class GitLabDriver:
    name = "gitlab"

    def __init__(
        self,
        *,
        base_url: str,
        project_id: str,
        ref: str,
        trigger_token_secret: str,
        secrets: SecretProvider,
        client: ResilientClient,
    ) -> None:
        if not _PROJECT_RE.fullmatch(project_id):
            raise ValueError("gitlab project_id must be numeric or 'group/project'")
        if not _REF_RE.fullmatch(ref) or ".." in ref:
            raise ValueError("invalid gitlab ref")
        if not base_url.startswith("https://"):
            raise ValueError("gitlab url must use https")
        self._url = f"{base_url.rstrip('/')}/api/v4/projects/{quote(project_id, safe='')}/trigger/pipeline"
        self._project = project_id
        self._ref = ref
        self._token_secret = trigger_token_secret
        self._secrets = secrets
        self._client = client

    def describe(self, req: RemediationRequest) -> str:
        return (
            f"Trigger GitLab pipeline on {self._project}@{self._ref} ({req.operation.upper()}) "
            f"for zone={req.zone_name} cloud={req.cloud} account={req.account_id} blueprint={req.blueprint}"
        )

    def trigger(self, req: RemediationRequest) -> TriggerResult:
        data = {"token": self._secrets.get(self._token_secret), "ref": self._ref}
        for key, value in req.as_variables().items():
            data[f"variables[{key}]"] = value
        resp = self._client.request("POST", self._url, expected={201}, data=data)
        body = resp.json()
        return TriggerResult(
            system=self.name,
            accepted=True,
            reference=str(body.get("id", "")),
            detail={"project": self._project, "ref": self._ref, "web_url": body.get("web_url", "")},
        )
