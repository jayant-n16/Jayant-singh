"""Stack model, TTL parsing and grouping of tagged cloud resources into stacks.

A *stack* is everything one Terraform root deployed. Every resource of a stack
must carry these tags (set by the deploying pipeline):

* ``OpliaBlueprint``  blueprint name (same as the Terraform root layout)
* ``OpliaZone``       zone / workspace name
* ``LifecycleTTL``    lifetime, e.g. ``8h``, ``3d``, ``2w`` (15 minutes to 90 days)
* ``CreatedAt``       ISO-8601 timestamp with timezone, set at creation

Creation time is a tag because cloud APIs do not expose a uniform creation
timestamp for every resource type.

Grouping is deliberately conservative: anything ambiguous is *skipped with a
reason*, never treated as expired.

* missing or invalid tags                     -> skipped
* resources of one stack disagree on TTL or
  CreatedAt                                   -> whole stack skipped
* any resource tagged Environment=prod/production/prd -> whole stack protected
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

TAG_TTL = "LifecycleTTL"
TAG_CREATED = "CreatedAt"
TAG_BLUEPRINT = "OpliaBlueprint"
TAG_ZONE = "OpliaZone"
TAG_ENVIRONMENT = "Environment"

PROTECTED_ENVIRONMENTS = frozenset({"prod", "production", "prd"})
MIN_TTL = timedelta(minutes=15)
MAX_TTL = timedelta(days=90)

_TTL_RE = re.compile(r"^(\d{1,4})([mhdw])$")
_UNITS = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


class TTLError(ValueError):
    pass


def parse_ttl(value: str) -> timedelta:
    m = _TTL_RE.fullmatch(value.strip().lower())
    if not m:
        raise TTLError(f"invalid TTL {value!r}; use e.g. 30m, 8h, 3d, 2w")
    ttl = timedelta(**{_UNITS[m[2]]: int(m[1])})
    if not MIN_TTL <= ttl <= MAX_TTL:
        raise TTLError(f"TTL {value!r} outside allowed range 15m..90d")
    return ttl


def parse_created_at(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"invalid CreatedAt {value!r}; use ISO-8601 with timezone") from None
    if dt.tzinfo is None:
        raise ValueError(f"CreatedAt {value!r} has no timezone")
    return dt.astimezone(UTC)


@dataclass(frozen=True)
class TaggedResource:
    cloud: str  # "aws" | "azure"
    account_id: str  # AWS account id / Azure subscription id
    resource_id: str  # ARN / Azure resource id
    tags: dict[str, str]


@dataclass(frozen=True)
class Stack:
    cloud: str
    account_id: str
    blueprint: str
    zone: str
    created_at: datetime
    ttl: timedelta
    resource_ids: tuple[str, ...]

    @property
    def expires_at(self) -> datetime:
        return self.created_at + self.ttl

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    @property
    def key(self) -> str:
        return f"{self.cloud}:{self.account_id}:{self.blueprint}:{self.zone}"


@dataclass
class GroupingResult:
    stacks: list[Stack] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (key or resource id, reason)


def _get(tags: dict[str, str], name: str) -> str:
    # Tag keys are matched case-insensitively (Azure tag names are case-insensitive).
    for k, v in tags.items():
        if k.lower() == name.lower():
            return str(v).strip()
    return ""


def group_stacks(resources: list[TaggedResource]) -> GroupingResult:
    result = GroupingResult()
    buckets: dict[tuple[str, str, str, str], list[TaggedResource]] = {}
    for r in resources:
        blueprint, zone = _get(r.tags, TAG_BLUEPRINT), _get(r.tags, TAG_ZONE)
        if not blueprint or not zone:
            result.skipped.append((r.resource_id, f"missing {TAG_BLUEPRINT} or {TAG_ZONE} tag"))
            continue
        buckets.setdefault((r.cloud, r.account_id, blueprint, zone), []).append(r)

    for (cloud, account, blueprint, zone), members in sorted(buckets.items()):
        key = f"{cloud}:{account}:{blueprint}:{zone}"
        envs = {_get(m.tags, TAG_ENVIRONMENT).lower() for m in members}
        if envs & PROTECTED_ENVIRONMENTS:
            result.skipped.append((key, "protected: Environment tag is production"))
            continue
        ttls = {_get(m.tags, TAG_TTL) for m in members}
        createds = {_get(m.tags, TAG_CREATED) for m in members}
        if len(ttls) != 1 or len(createds) != 1:
            result.skipped.append((key, "inconsistent LifecycleTTL/CreatedAt across resources"))
            continue
        try:
            ttl = parse_ttl(ttls.pop())
            created = parse_created_at(createds.pop())
        except ValueError as exc:
            result.skipped.append((key, str(exc)))
            continue
        result.stacks.append(Stack(cloud=cloud, account_id=account, blueprint=blueprint, zone=zone,
                                   created_at=created, ttl=ttl,
                                   resource_ids=tuple(sorted(m.resource_id for m in members))))
    return result


def utcnow() -> datetime:
    return datetime.now(UTC)
