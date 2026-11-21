from __future__ import annotations

import json
from urllib.parse import parse_qs

import httpx
import pytest
import respx
from pydantic import ValidationError

from oplia_ctl.config import CICDTarget
from oplia_ctl.drivers.cicd import RemediationRequest, build_cicd_driver
from oplia_ctl.drivers.cicd.factory import CICDNotConfiguredError
from oplia_ctl.drivers.cicd.jenkins import job_path
from oplia_ctl.http import HttpError, ResilientClient
from oplia_ctl.secrets import StaticSecretProvider

SECRETS = StaticSecretProvider({
    "github_dispatch_token": "ghp_x",
    "gitlab_trigger_token": "glptt_x",
    "jenkins_user": "svc",
    "jenkins_api_token": "tok",
})
REQ = RemediationRequest(zone_name="prod-zone-1", cloud="aws", account_id="123456789012",
                         blueprint="control-tower-standard", correlation_id="dlv-1")


@pytest.fixture
def client():
    with ResilientClient(sleep=lambda _s: None) as c:
        yield c


@respx.mock
def test_github_dispatch(client):
    cfg = CICDTarget(github_repository="acme/infra")
    route = respx.post("https://api.github.com/repos/acme/infra/dispatches").mock(return_value=httpx.Response(204))
    res = build_cicd_driver("github", cfg, SECRETS, client).trigger(REQ)
    assert res.accepted and res.reference == "dlv-1"
    sent = route.calls.last.request
    assert sent.headers["Authorization"] == "Bearer ghp_x"
    body = json.loads(sent.content)
    assert body["event_type"] == "oplia-drift-remediation"
    assert body["client_payload"]["zone_name"] == "prod-zone-1"


@respx.mock
def test_gitlab_trigger(client):
    cfg = CICDTarget(gitlab_project_id="platform/infra", gitlab_ref="main")
    route = respx.post("https://gitlab.com/api/v4/projects/platform%2Finfra/trigger/pipeline").mock(
        return_value=httpx.Response(201, json={"id": 991, "web_url": "https://gitlab.com/p/991"}))
    res = build_cicd_driver("gitlab", cfg, SECRETS, client).trigger(REQ)
    assert res.reference == "991"
    form = parse_qs(route.calls.last.request.content.decode())
    assert form["token"] == ["glptt_x"] and form["ref"] == ["main"]
    assert form["variables[BLUEPRINT]"] == ["control-tower-standard"]


@respx.mock
def test_jenkins_with_crumb(client):
    cfg = CICDTarget(jenkins_url="https://ci.example.com", jenkins_job="infra/force-remediate")
    respx.get("https://ci.example.com/crumbIssuer/api/json").mock(
        return_value=httpx.Response(200, json={"crumbRequestField": "Jenkins-Crumb", "crumb": "abc"}))
    build = respx.post("https://ci.example.com/job/infra/job/force-remediate/buildWithParameters").mock(
        return_value=httpx.Response(201, headers={"Location": "https://ci.example.com/queue/item/7/"}))
    res = build_cicd_driver("jenkins", cfg, SECRETS, client).trigger(REQ)
    assert res.reference.endswith("/queue/item/7/")
    req = build.calls.last.request
    assert req.headers["Jenkins-Crumb"] == "abc"
    assert req.headers["Authorization"].startswith("Basic ")


@respx.mock
def test_jenkins_without_csrf(client):
    cfg = CICDTarget(jenkins_url="https://ci.example.com", jenkins_job="force-remediate")
    respx.get("https://ci.example.com/crumbIssuer/api/json").mock(return_value=httpx.Response(404))
    respx.post("https://ci.example.com/job/force-remediate/buildWithParameters").mock(
        return_value=httpx.Response(201))
    assert build_cicd_driver("jenkins", cfg, SECRETS, client).trigger(REQ).accepted


@respx.mock
def test_jenkins_crumb_auth_failure_propagates(client):
    cfg = CICDTarget(jenkins_url="https://ci.example.com", jenkins_job="j")
    respx.get("https://ci.example.com/crumbIssuer/api/json").mock(return_value=httpx.Response(401))
    with pytest.raises(HttpError):
        build_cicd_driver("jenkins", cfg, SECRETS, client).trigger(REQ)


def test_factory_rejects_unknown_and_unconfigured(client):
    with pytest.raises(ValueError, match="unsupported"):
        build_cicd_driver("circleci", CICDTarget(), SECRETS, client)
    with pytest.raises(CICDNotConfiguredError):
        build_cicd_driver("github", CICDTarget(), SECRETS, client)


@pytest.mark.parametrize("job", ["../x", "a/../b", "", "a/b;rm"])
def test_jenkins_job_path_rejects_traversal(job):
    with pytest.raises(ValueError):
        job_path(job)


def test_driver_rejects_http_urls(client):
    with pytest.raises(ValueError, match="https"):
        build_cicd_driver("jenkins", CICDTarget(jenkins_url="http://ci", jenkins_job="j"), SECRETS, client)


@pytest.mark.parametrize("field,value", [
    ("zone_name", "zone; rm -rf /"), ("zone_name", "$(id)"), ("account_id", "12`whoami`"),
    ("blueprint", "Control_Tower"), ("correlation_id", "a b"),
])
def test_request_rejects_shell_metacharacters(field, value):
    data = REQ.model_dump() | {field: value}
    with pytest.raises(ValidationError):
        RemediationRequest(**data)
