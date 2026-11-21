"""Timestamps leave the API as timezone-aware UTC ISO 8601 strings.

SQLite returns ``DateTime(timezone=True)`` columns as *naive* datetimes (the offset is not stored), so a
plain ``.isoformat()`` produced ``2026-11-21T12:31:00`` and browsers read that as local time (a job that
ran at 18:01 IST was shown as 12:31). Every stored timestamp in this code base is written in UTC, so a
naive value read back is UTC.
"""

from __future__ import annotations

from datetime import UTC, datetime


def as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def iso_utc(dt: datetime | None) -> str | None:
    """``2026-11-21T12:31:00+00:00`` for any datetime (naive = UTC); None stays None."""
    return None if dt is None else as_utc(dt).isoformat()
