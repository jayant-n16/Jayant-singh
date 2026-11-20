"""Map resource tags/labels between AWS, Azure and GCP under each cloud's rules.

Rules applied (from each provider's documented limits):

* AWS tags: at most 50; key 1-128 characters, value 0-256; keys starting with ``aws:`` are
  reserved; allowed characters are letters, digits, spaces and ``+ - = . _ : / @``.
* Azure tags: at most 50; key 1-512 characters, value 0-256; keys may not contain
  ``< > % & \\ ? /``; prefixes ``microsoft``, ``azure`` and ``windows`` are reserved.
* GCP labels: at most 64; keys 1-63 characters, start with a lowercase letter, contain only
  lowercase letters, digits, ``_`` and ``-``; values 0-63 characters of the same set. (GCP also
  accepts international lowercase letters; this mapping keeps to ASCII on purpose.)

Nothing is dropped silently: every rename, truncation, collision and drop is reported.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

Cloud = Literal["aws", "azure", "gcp"]

_AWS_BAD = re.compile(r"[^\w\s+\-=.:/@]", re.ASCII)
_AZURE_BAD = re.compile(r"[<>%&\\?/]")
_GCP_BAD = re.compile(r"[^a-z0-9_-]")
LIMITS = {"aws": (50, 128, 256), "azure": (50, 512, 256), "gcp": (64, 63, 63)}


@dataclass
class TagMapResult:
    tags: dict[str, str] = field(default_factory=dict)
    changes: list[str] = field(default_factory=list)   # renamed / truncated
    dropped: list[str] = field(default_factory=list)   # not representable or over the limit


def _key(target: Cloud, k: str) -> str | None:
    if target == "aws":
        k = _AWS_BAD.sub("_", k).strip()[:128]
        return None if not k or k.lower().startswith("aws:") else k
    if target == "azure":
        k = _AZURE_BAD.sub("_", k).strip()[:512]
        return None if not k or k.lower().startswith(("microsoft", "azure", "windows")) else k
    k = _GCP_BAD.sub("_", k.lower())[:63]
    if not k:
        return None
    if not k[0].isalpha():
        k = ("k" + k)[:63]
    return k


def _value(target: Cloud, v: str) -> str:
    if target == "aws":
        return _AWS_BAD.sub("_", v)[:256]
    if target == "azure":
        return v[:256]
    return _GCP_BAD.sub("_", v.lower())[:63]


def map_tags(tags: dict[str, str], target: Cloud) -> TagMapResult:
    res = TagMapResult()
    max_n = LIMITS[target][0]
    for src_k in sorted(tags):                      # sorted: collisions resolve deterministically
        src_v = str(tags[src_k])
        k = _key(target, src_k)
        if k is None:
            res.dropped.append(f"{src_k}: key not allowed on {target}")
            continue
        v = _value(target, src_v)
        if k in res.tags:
            res.dropped.append(f"{src_k}: maps to '{k}', already used by another tag")
            continue
        if len(res.tags) >= max_n:
            res.dropped.append(f"{src_k}: {target} allows at most {max_n} tags")
            continue
        if k != src_k:
            res.changes.append(f"key '{src_k}' -> '{k}'")
        if v != src_v:
            res.changes.append(f"value of '{k}' changed ('{src_v[:40]}' -> '{v[:40]}')")
        res.tags[k] = v
    return res
