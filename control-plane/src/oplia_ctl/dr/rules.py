"""Corruption signatures and the rolling mutation-rate detector.

Static rules (per bundle):

* ``DROP TABLE`` / ``DROP DATABASE`` / ``DROP SCHEMA`` (SQL, Mongo ``drop`` / ``dropDatabase``)
* ``TRUNCATE`` (SQL statement or Debezium ``op: t``)
* ``UPDATE`` / ``DELETE`` without ``WHERE``; Mongo ``deleteMany`` / ``updateMany`` with an empty filter
* undecodable records (unknown traffic is not let through silently)

Rate rule (``RateMonitor``): the document's "more than 500 % over the rolling 5-minute
baseline". *current* = row/document mutations in the last ``window`` (60 s); *baseline* = average
per-window count over the preceding 5 minutes. It trips when
``current > baseline * (1 + spike_percent / 100)`` - i.e. more than 6x for 500 % - and
``current >= min_mutations`` (so 1 row becoming 7 rows does not stop replication), and only after
5 minutes of history have been observed.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from oplia_ctl.dr.decode import Mutation

RuleName = Literal["drop", "truncate", "unconstrained_write", "undecodable", "rate_spike", "manual"]
_ROW_KINDS = frozenset({"insert", "update", "delete"})


@dataclass(frozen=True)
class Finding:
    rule: RuleName
    message: str
    mutation: Mutation | None = None
    numbers: dict[str, float] = field(default_factory=dict)


def static_findings(mutations: list[Mutation], *, block_undecodable: bool = True) -> list[Finding]:
    out: list[Finding] = []
    for m in mutations:
        if m.kind in ("drop_table", "drop_database", "drop_schema"):
            out.append(Finding("drop", f"{m.engine}: {m.kind.replace('_', ' ')} {m.target}".strip(), m))
        elif m.kind == "truncate":
            out.append(Finding("truncate", f"{m.engine}: truncate {m.target}".strip(), m))
        elif m.kind in ("update", "delete") and m.unconstrained:
            what = m.statement or m.kind
            out.append(Finding("unconstrained_write", f"{m.engine}: {what} on {m.target} without a filter", m))
        elif m.kind == "undecodable" and block_undecodable:
            out.append(Finding("undecodable", f"{m.engine}: record could not be decoded {m.detail}", m))
    return out


class RateMonitor:
    def __init__(self, *, spike_percent: float = 500.0, window_seconds: int = 60, baseline_windows: int = 5,
                 min_mutations: int = 1000, clock: Callable[[], float] = time.monotonic) -> None:
        if spike_percent <= 0 or window_seconds < 1 or baseline_windows < 1 or min_mutations < 1:
            raise ValueError("invalid rate monitor parameters")
        self._factor = 1.0 + spike_percent / 100.0
        self._spike_percent = spike_percent
        self._window = window_seconds
        self._baseline_windows = baseline_windows
        self._min = min_mutations
        self._clock = clock
        self._events: deque[tuple[float, int]] = deque()
        self._started = clock()

    @staticmethod
    def count_rows(mutations: list[Mutation]) -> int:
        return sum(max(0, m.rows) for m in mutations if m.kind in _ROW_KINDS)

    def _sum(self, after: float, upto: float) -> int:
        """Rows in the half-open interval (after, upto] - windows never overlap."""
        return sum(n for t, n in self._events if after < t <= upto)

    def observe(self, mutations: list[Mutation]) -> Finding | None:
        """Record a bundle and return a finding if the rate now spikes (the bundle counts toward it)."""
        now = self._clock()
        horizon = self._window * (self._baseline_windows + 1)
        while self._events and self._events[0][0] <= now - horizon:
            self._events.popleft()
        rows = self.count_rows(mutations)
        if rows:
            self._events.append((now, rows))
        if now - self._started < self._window * self._baseline_windows:
            return None  # warming up: no baseline yet
        current = self._sum(now - self._window, now)
        baseline = self._sum(now - horizon, now - self._window) / self._baseline_windows
        limit = baseline * self._factor
        if current >= self._min and current > limit:
            return Finding("rate_spike",
                           f"{current} row mutations in the last {self._window}s vs baseline {baseline:.1f} per "
                           f"{self._window}s (limit {limit:.1f}, +{self._spike_percent:g}%)",
                           numbers={"current": current, "baseline": baseline, "limit": limit})
        return None
