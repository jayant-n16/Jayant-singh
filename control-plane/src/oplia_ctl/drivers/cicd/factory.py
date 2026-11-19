"""Driver factory keyed by ``target_cicd``."""

from __future__ import annotations

from oplia_ctl.config import CICDTarget
from oplia_ctl.drivers.cicd.base import CICDDriver
from oplia_ctl.drivers.cicd.github import GitHubDriver
from oplia_ctl.drivers.cicd.gitlab import GitLabDriver
from oplia_ctl.drivers.cicd.jenkins import JenkinsDriver
from oplia_ctl.http import ResilientClient
from oplia_ctl.secrets import SecretProvider

SUPPORTED_CICD = ("github", "gitlab", "jenkins")


class CICDNotConfiguredError(ValueError):
    pass


def build_cicd_driver(
    target_cicd: str, cfg: CICDTarget, secrets: SecretProvider, client: ResilientClient
) -> CICDDriver:
    if target_cicd == "github":
        if not cfg.github_repository:
            raise CICDNotConfiguredError("OPLIA_CICD__GITHUB_REPOSITORY is not set")
        return GitHubDriver(api_url=cfg.github_api_url, repository=cfg.github_repository,
                            event_type=cfg.github_event_type, token_secret=cfg.github_token_secret,
                            secrets=secrets, client=client)
    if target_cicd == "gitlab":
        if not cfg.gitlab_project_id:
            raise CICDNotConfiguredError("OPLIA_CICD__GITLAB_PROJECT_ID is not set")
        return GitLabDriver(base_url=cfg.gitlab_url, project_id=cfg.gitlab_project_id, ref=cfg.gitlab_ref,
                            trigger_token_secret=cfg.gitlab_trigger_token_secret, secrets=secrets,
                            client=client)
    if target_cicd == "jenkins":
        if not (cfg.jenkins_url and cfg.jenkins_job):
            raise CICDNotConfiguredError("OPLIA_CICD__JENKINS_URL and OPLIA_CICD__JENKINS_JOB must be set")
        return JenkinsDriver(base_url=cfg.jenkins_url, job=cfg.jenkins_job,
                             user_secret=cfg.jenkins_user_secret,
                             api_token_secret=cfg.jenkins_api_token_secret, secrets=secrets, client=client)
    raise ValueError(f"unsupported target_cicd {target_cicd!r}; expected one of {SUPPORTED_CICD}")
