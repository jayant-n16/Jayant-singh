#!/usr/bin/env python3
"""Split a manifest stream into core resources and custom resources of the given API groups.

Usage: split-crs.py IN.yaml CORE_OUT.yaml CR_OUT.yaml GROUP_SUFFIX [GROUP_SUFFIX ...]

Documents whose apiVersion group ends with one of the suffixes (e.g. ``linkerd.io``) go to
CR_OUT (validate them with validate-crs.py against the CRDs that define them); everything else
goes to CORE_OUT (validate with kubeconform). Prints the counts.
"""

from __future__ import annotations

import sys

import yaml


def main(argv: list[str]) -> int:
    if len(argv) < 5:
        print(__doc__, file=sys.stderr)
        return 2
    src, core_out, cr_out, suffixes = argv[1], argv[2], argv[3], tuple(argv[4:])
    core, crs = [], []
    with open(src, encoding="utf-8") as fh:
        for doc in yaml.safe_load_all(fh):
            if not doc:
                continue
            group = str(doc.get("apiVersion", "")).rpartition("/")[0]
            (crs if group and group.endswith(suffixes) else core).append(doc)
    for path, docs in ((core_out, core), (cr_out, crs)):
        with open(path, "w", encoding="utf-8") as fh:
            yaml.safe_dump_all(docs, fh, sort_keys=False)
    print(f"{len(core)} core resource(s), {len(crs)} custom resource(s) of {', '.join(suffixes)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
