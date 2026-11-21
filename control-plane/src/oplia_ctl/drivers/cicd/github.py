"""GitHub Actions driver: ``repository_dispatch``.

API: ``POST /repos/{owner}/{repo}/dispatches`` -> 204 No Content.
The token needs ``contents: write`` (fine-grained) on the infrastructure repo.

Each operation uses its own event type (``oplia-drift-remediation`` /
``oplia-ttl-destroy`` by default), so the workflow can gate destroy behind a
separate protected environment.
"""

from __future__ import annotations

import re

from oplia_ctl.drivers.cicd.base import Operation, RemediationRequest, TriggerResult
from oplia_ctl.http import ResilientClient
from oplia_ctl.secrets import SecretProvider

_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_EVENT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


class GitHubDriver:
    name = "github"

    def __init__(
        self,
        *,
        api_url: str,
        repository: str,
        event_types: dict[Operation, str],
        token_secret: str,
        secrets: SecretProvider,
        client: ResilientClient,
    ) -> None:
        if not _REPO_RE.fullmatch(repository):
            raise ValueError("github repository must be 'owner/repo'")
        if set(event_types) != {"remediate", "destroy"}:
            raise ValueError("github event_types must define 'remediate' and 'destroy'")
        for ev in event_types.values():
            if not _EVENT_RE.fullmatch(ev):
                raise ValueError(f"invalid github event_type {ev!r}")
        if event_types["remediate"] == event_types["destroy"]:
            raise ValueError("remediate and destroy must use different github event types")
        if not api_url.startswith("https://"):
            raise ValueError("github api_url must use https")
        self._url = f"{api_url.rstrip('/')}/repos/{repository}/dispatches"
        self._repository = repository
        self._event_types = dict(event_types)
        self._token_secret = token_secret
        self._secrets = secrets
        self._client = client

    def describe(self, req: RemediationRequest) -> str:
        return (
            f"POST repository_dispatch '{self._event_types[req.operation]}' to {self._repository} "
            f"({req.operation.upper()}) for zone={req.zone_name} cloud={req.cloud} account={req.account_id} "
            f"blueprint={req.blueprint}"
        )

    def trigger(self, req: RemediationRequest) -> TriggerResult:
        token = self._secrets.get(self._token_secret)
        event_type = self._event_types[req.operation]
        self._client.request(
            "POST",
            self._url,
            expected={204},
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json={
                "event_type": event_type,
                "client_payload": {
                    "zone_name": req.zone_name,
                    "cloud": req.cloud,
                    "account_id": req.account_id,
                    "blueprint": req.blueprint,
                    "correlation_id": req.correlation_id,
                    "operation": req.operation,
                },
            },
        )
        # GitHub does not return a run id for dispatches; the workflow is correlated
        # by correlation_id, which it echoes into its run name.
        return TriggerResult(system=self.name, accepted=True, reference=req.correlation_id,
                             detail={"repository": self._repository, "event_type": event_type,
                                     "operation": req.operation})
