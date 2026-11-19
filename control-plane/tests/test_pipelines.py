"""Static safety checks on the pipeline templates.

These cannot replace running the pipelines on GitHub/GitLab/Jenkins; they guard the
properties that matter most: valid YAML, pinned actions, no untrusted input
interpolated into shell, and apply gated behind a human approval.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1] / "pipelines"


def _load(path: Path) -> dict:
    # GitHub's `on:` key parses as boolean True in YAML 1.1; normalise it.
    data = yaml.safe_load(path.read_text())
    if True in data:
        data["on"] = data.pop(True)
    return data


def test_github_workflow_structure_and_gates():
    wf = _load(ROOT / "github" / "force-remediate.yml")
    assert wf["on"] == {"repository_dispatch": {"types": ["oplia-drift-remediation"]}}
    assert wf["permissions"] == {"contents": "read", "id-token": "write"}
    assert wf["concurrency"]["cancel-in-progress"] is False
    apply = wf["jobs"]["apply"]
    assert apply["environment"] == "oplia-production-remediation"
    assert apply["needs"] == "plan"
    apply_cmds = " ".join(s.get("run", "") for s in apply["steps"])
    assert "apply -input=false -lock-timeout=5m tfplan" in apply_cmds
    code = [ln for ln in (ROOT / "github" / "force-remediate.yml").read_text().splitlines()
            if not ln.lstrip().startswith("#")]
    assert not any("-auto-approve" in ln for ln in code)


def test_github_actions_pinned_to_full_sha():
    wf = _load(ROOT / "github" / "force-remediate.yml")
    uses = [s["uses"] for job in wf["jobs"].values() for s in job["steps"] if "uses" in s]
    assert uses, "expected action references"
    for ref in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), ref


def test_github_no_event_payload_interpolated_into_run_scripts():
    wf = _load(ROOT / "github" / "force-remediate.yml")
    for job in wf["jobs"].values():
        for step in job["steps"]:
            assert "github.event" not in step.get("run", ""), step.get("name")


def test_gitlab_pipeline_structure_and_gates():
    ci = _load(ROOT / "gitlab" / ".gitlab-ci.yml")
    assert ci["workflow"]["rules"][0]["if"] == '$CI_PIPELINE_SOURCE == "trigger"'
    assert ci["stages"] == ["validate", "plan", "apply"]
    apply = ci["apply"]
    assert apply["rules"] == [{"when": "manual", "allow_failure": False}]
    assert apply["environment"]["name"] == "oplia-production-remediation"
    assert apply["resource_group"] == ci["plan"]["resource_group"]
    assert any("apply -input=false -lock-timeout=5m" in line for line in apply["script"])
    assert "AWS_OIDC_TOKEN" in apply["id_tokens"]


def test_jenkinsfile_gates_and_no_groovy_interpolation_in_sh():
    text = (ROOT / "jenkins" / "Jenkinsfile").read_text()
    assert "disableConcurrentBuilds()" in text
    assert "input(" in text and "submitter: env.OPLIA_APPROVERS" in text
    assert "apply -input=false -lock-timeout=5m tfplan" in text
    # sh steps must use single quotes so Groovy never interpolates parameters into shell code
    for m in re.finditer(r"\bsh\s*\(?\s*(['\"]{1,3})", text):
        assert m.group(1).startswith("'"), text[m.start(): m.start() + 80]
