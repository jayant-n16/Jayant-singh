#!/usr/bin/env python3
"""Validate custom resources against the openAPIV3Schema of the CRDs that define them.

Usage: validate-crs.py CRDS.yaml CR.yaml [CR.yaml ...]

CRDS.yaml is a multi-document stream (for example `helm template` output); only
CustomResourceDefinition documents are used from it. Every document in the CR files must match a
served version of a CRD in that stream (group, kind and version), must satisfy that version's
schema, and must not carry spec fields the schema does not declare (unless the schema allows
them with x-kubernetes-preserve-unknown-fields or additionalProperties). Exit code 1 on any problem.
"""

from __future__ import annotations

import sys
from typing import Any

import yaml
from jsonschema import Draft7Validator


def _strict(schema: Any) -> Any:
    """Copy of an openAPIV3 schema where objects with declared properties reject unknown keys,
    mirroring how the API server prunes/rejects unknown fields for structural schemas."""
    if isinstance(schema, list):
        return [_strict(s) for s in schema]
    if not isinstance(schema, dict):
        return schema
    out = {k: _strict(v) for k, v in schema.items() if not k.startswith("x-kubernetes-")}
    if (schema.get("type") == "object" and "properties" in schema and "additionalProperties" not in schema
            and not schema.get("x-kubernetes-preserve-unknown-fields")):
        out["additionalProperties"] = False
    return out


def load_crds(path: str) -> dict[tuple[str, str, str], dict[str, Any]]:
    schemas: dict[tuple[str, str, str], dict[str, Any]] = {}
    with open(path, encoding="utf-8") as fh:
        for doc in yaml.safe_load_all(fh):
            if not doc or doc.get("kind") != "CustomResourceDefinition":
                continue
            spec = doc["spec"]
            for ver in spec.get("versions", []):
                if ver.get("served") and "schema" in ver:
                    schemas[(spec["group"], spec["names"]["kind"], ver["name"])] = ver["schema"]["openAPIV3Schema"]
    return schemas


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    schemas = load_crds(argv[1])
    if not schemas:
        print(f"no CustomResourceDefinitions in {argv[1]}", file=sys.stderr)
        return 1
    failed = checked = 0
    for path in argv[2:]:
        with open(path, encoding="utf-8") as fh:
            for doc in yaml.safe_load_all(fh):
                if not doc:
                    continue
                group, _, version = str(doc.get("apiVersion", "")).rpartition("/")
                key = (group, str(doc.get("kind")), version)
                name = f"{path}: {doc.get('kind')}/{doc.get('metadata', {}).get('name')}"
                checked += 1
                if key not in schemas:
                    print(f"FAIL {name}: no served CRD version for {key}")
                    failed += 1
                    continue
                schema = dict(schemas[key])
                # apiVersion, kind and metadata are always accepted at the root by the API server
                # (metadata is validated by it, not by the CRD schema), declared or not
                props = dict(schema.get("properties", {}))
                props.update(apiVersion={"type": "string"}, kind={"type": "string"}, metadata={"type": "object"})
                schema["properties"] = props
                errors = sorted(Draft7Validator(_strict(schema)).iter_errors(doc), key=lambda e: list(e.path))
                for err in errors:
                    print(f"FAIL {name}: {'/'.join(map(str, err.path)) or '<root>'}: {err.message}")
                failed += bool(errors)
                if not errors:
                    print(f"ok   {name}")
    print(f"{checked} resource(s) checked, {failed} invalid")
    return 1 if failed or not checked else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
