"""Jenkins driver: remote ``buildWithParameters`` with basic auth (user + API token).

Flow: ``GET /crumbIssuer/api/json`` (404 means CSRF protection is disabled, which
is accepted), then ``POST /job/<path>/buildWithParameters`` with the crumb
header. The same HTTP client keeps the session cookie the crumb is bound to.
Jenkins answers 201 with a ``Location`` header pointing at the queue item.
"""

from __future__ import annotations

import re
from urllib.parse import quote

from oplia_ctl.drivers.cicd.base import RemediationRequest, TriggerResult
from oplia_ctl.http import HttpError, ResilientClient
from oplia_ctl.secrets import SecretProvider

_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_. -]{1,128}$")


def job_path(job: str) -> str:
    segments = [s for s in job.split("/") if s]
    if not segments:
        raise ValueError("jenkins job must not be empty")
    for seg in segments:
        if not _SEGMENT_RE.fullmatch(seg) or seg in {".", ".."}:
            raise ValueError(f"invalid jenkins job segment {seg!r}")
    return "".join(f"/job/{quote(seg, safe='')}" for seg in segments)


class JenkinsDriver:
    name = "jenkins"

    def __init__(
        self,
        *,
        base_url: str,
        job: str,
        user_secret: str,
        api_token_secret: str,
        secrets: SecretProvider,
        client: ResilientClient,
    ) -> None:
        if not base_url.startswith("https://"):
            raise ValueError("jenkins url must use https")
        self._base = base_url.rstrip("/")
        self._job = job
        self._job_path = job_path(job)
        self._user_secret = user_secret
        self._token_secret = api_token_secret
        self._secrets = secrets
        self._client = client

    def describe(self, req: RemediationRequest) -> str:
        return (
            f"Jenkins buildWithParameters on job '{self._job}' "
            f"for zone={req.zone_name} cloud={req.cloud} account={req.account_id} blueprint={req.blueprint}"
        )

    def trigger(self, req: RemediationRequest) -> TriggerResult:
        auth = (self._secrets.get(self._user_secret), self._secrets.get(self._token_secret))
        headers: dict[str, str] = {}
        try:
            crumb = self._client.request(
                "GET", f"{self._base}/crumbIssuer/api/json", expected={200}, auth=auth
            ).json()
            headers[str(crumb["crumbRequestField"])] = str(crumb["crumb"])
        except HttpError as exc:
            if exc.status != 404:  # 404 = CSRF protection disabled on this controller
                raise
        resp = self._client.request(
            "POST",
            f"{self._base}{self._job_path}/buildWithParameters",
            expected={201},
            auth=auth,
            headers=headers,
            data=req.as_variables(),
        )
        return TriggerResult(
            system=self.name,
            accepted=True,
            reference=resp.headers.get("Location", ""),
            detail={"job": self._job},
        )
