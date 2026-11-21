"""Target-side encryption key references. Only *names* of keys are handled here, never key material.

Per target cloud the reference means:

* aws   - KMS key ARN or ``alias/<name>``: S3 SSE-KMS for objects, ``KmsKeyId`` for imported AMIs;
* azure - for objects: the name of a blob *encryption scope* backed by a Key Vault key; for images:
          the resource id of a *disk encryption set*;
* gcp   - Cloud KMS key resource name ``projects/P/locations/L/keyRings/R/cryptoKeys/K``.
"""

from __future__ import annotations

import re

_AWS = re.compile(r"^(arn:aws[a-z-]*:kms:[a-z0-9-]+:\d{12}:(key/[0-9a-f-]{36}|alias/[A-Za-z0-9/_-]+)"
                  r"|alias/[A-Za-z0-9/_-]+)$")
_AZ_SCOPE = re.compile(r"^[A-Za-z0-9]{3,63}$")
_AZ_DES = re.compile(r"^/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/]+/providers/Microsoft\.Compute/"
                     r"diskEncryptionSets/[^/]+$", re.IGNORECASE)
_GCP = re.compile(r"^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]+/"
                  r"cryptoKeys/[A-Za-z0-9_-]+$")


def validate_key_ref(cloud: str, ref: str, purpose: str = "objects") -> str:
    """Return ref if it is a well-formed key reference for (cloud, purpose); raise ValueError otherwise."""
    ok = {
        "aws": bool(_AWS.match(ref)),
        "azure": bool(_AZ_DES.match(ref)) if purpose == "images" else bool(_AZ_SCOPE.match(ref)),
        "gcp": bool(_GCP.match(ref)),
    }.get(cloud)
    if ok is None:
        raise ValueError(f"unknown cloud {cloud!r}")
    if not ok:
        what = {"aws": "a KMS key ARN or alias/<name>",
                "azure": "a disk encryption set resource id" if purpose == "images" else "an encryption scope name",
                "gcp": "projects/P/locations/L/keyRings/R/cryptoKeys/K"}[cloud]
        raise ValueError(f"{cloud} key reference for {purpose} must be {what}")
    return ref
