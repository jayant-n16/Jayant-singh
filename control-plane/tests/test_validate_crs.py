"""scripts/validate-crs.py and split-crs.py: CR validation against CRD schemas used by the mesh CI."""

from __future__ import annotations

import subprocess  # nosec B404 - runs our own scripts with fixed arguments
import sys
from pathlib import Path

import yaml

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"

CRD = """apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata: {name: servers.policy.linkerd.io}
spec:
  group: policy.linkerd.io
  names: {kind: Server, plural: servers}
  scope: Namespaced
  versions:
    - name: v1beta3
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          required: [spec]
          properties:
            spec:
              type: object
              required: [port]
              properties:
                port: {x-kubernetes-int-or-string: true}
                labels: {type: object, x-kubernetes-preserve-unknown-fields: true, properties: {a: {type: string}}}
"""


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, check=False)  # noqa: S603  # nosec B603


def _write(tmp: Path, name: str, text: str) -> str:
    p = tmp / name
    p.write_text(text)
    return str(p)


def test_valid_resource_with_undeclared_root_fields_passes(tmp_path):
    crd = _write(tmp_path, "crd.yaml", CRD)
    cr = _write(tmp_path, "cr.yaml", "apiVersion: policy.linkerd.io/v1beta3\nkind: Server\nmetadata: {name: a}\n"
                                     "spec: {port: admin, labels: {anything: goes}}\n")
    r = _run(str(SCRIPTS / "validate-crs.py"), crd, cr)
    assert r.returncode == 0, r.stdout
    assert "1 resource(s) checked, 0 invalid" in r.stdout


def test_unknown_field_missing_required_and_unknown_kind_fail(tmp_path):
    crd = _write(tmp_path, "crd.yaml", CRD)
    cr = _write(tmp_path, "cr.yaml",
                "apiVersion: policy.linkerd.io/v1beta3\nkind: Server\nmetadata: {name: typo}\n"
                "spec: {port: 1, prot: 2}\n"
                "---\napiVersion: policy.linkerd.io/v1beta3\nkind: Server\nmetadata: {name: noport}\nspec: {}\n"
                "---\napiVersion: policy.linkerd.io/v1beta1\nkind: Server\nmetadata: {name: oldver}\nspec: {port: 1}\n")
    r = _run(str(SCRIPTS / "validate-crs.py"), crd, cr)
    assert r.returncode == 1
    assert "'prot' was unexpected" in r.stdout and "'port' is a required property" in r.stdout
    assert "no served CRD version" in r.stdout and "3 resource(s) checked, 3 invalid" in r.stdout


def test_no_crds_is_an_error(tmp_path):
    empty = _write(tmp_path, "none.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n")
    assert _run(str(SCRIPTS / "validate-crs.py"), empty, empty).returncode == 1


def test_split_by_group_suffix(tmp_path):
    src = _write(tmp_path, "in.yaml", CRD + "---\napiVersion: v1\nkind: Service\nmetadata: {name: s}\n"
                 "---\napiVersion: policy.linkerd.io/v1beta3\nkind: Server\nmetadata: {name: a}\nspec: {port: 1}\n")
    core, crs = str(tmp_path / "core.yaml"), str(tmp_path / "crs.yaml")
    r = _run(str(SCRIPTS / "split-crs.py"), src, core, crs, "linkerd.io")
    assert r.returncode == 0 and "2 core resource(s), 1 custom resource(s)" in r.stdout
    kinds = lambda p: [d["kind"] for d in yaml.safe_load_all(Path(p).read_text()) if d]  # noqa: E731
    assert kinds(crs) == ["Server"] and kinds(core) == ["CustomResourceDefinition", "Service"]
