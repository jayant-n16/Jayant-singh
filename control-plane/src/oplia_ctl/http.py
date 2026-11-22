"""Outbound HTTP with timeouts and safe retries.

Retry rules (deliberately conservative so a trigger is never fired twice):

* Connection failures where the request never left (``httpx.ConnectError``,
  ``httpx.ConnectTimeout``) are retried for every method.
* Status 429 is retried for every method (the server explicitly did not
  process the request), honouring ``Retry-After``.
* 502/503/504 and read timeouts are retried only for idempotent methods
  (GET, HEAD, PUT, DELETE, OPTIONS).
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from typing import Any

import httpx

IDEMPOTENT = {"GET", "HEAD", "PUT", "DELETE", "OPTIONS"}
_RETRY_STATUS_IDEMPOTENT = {502, 503, 504}
_MAX_BACKOFF = 30.0


class HttpError(Exception):
    """Non-success response. Carries status and a truncated body, never headers."""

    def __init__(self, method: str, url: str, status: int, body: str) -> None:
        self.status = status
        super().__init__(f"{method} {url} -> HTTP {status}: {body[:300]}")


def _retry_after(resp: httpx.Response) -> float | None:
    value = resp.headers.get("Retry-After")
    if value is None:
        return None
    try:
        return min(float(value), _MAX_BACKOFF)
    except ValueError:
        return None


class ResilientClient:
    def __init__(
        self,
        *,
        timeout: float = 10.0,
        max_retries: int = 3,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._client = httpx.Client(timeout=timeout, transport=transport, follow_redirects=False)
        self._max_retries = max_retries
        self._sleep = sleep

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> ResilientClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _backoff(self, attempt: int) -> float:
        # random is used for jitter only, not for anything security-relevant
        return float(min(_MAX_BACKOFF, (2**attempt) * 0.5 + random.uniform(0, 0.5)))  # noqa: S311  # nosec B311 - jitter only

    def request(
        self,
        method: str,
        url: str,
        *,
        expected: set[int] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        method = method.upper()
        expected = expected or {200, 201, 202, 204}
        attempt = 0
        while True:
            try:
                resp = self._client.request(method, url, **kwargs)
            except (httpx.ConnectError, httpx.ConnectTimeout):
                if attempt >= self._max_retries:
                    raise
                self._sleep(self._backoff(attempt))
                attempt += 1
                continue
            except httpx.ReadTimeout:
                if method not in IDEMPOTENT or attempt >= self._max_retries:
                    raise
                self._sleep(self._backoff(attempt))
                attempt += 1
                continue

            if resp.status_code in expected:
                return resp
            retryable = resp.status_code == 429 or (
                method in IDEMPOTENT and resp.status_code in _RETRY_STATUS_IDEMPOTENT
            )
            if retryable and attempt < self._max_retries:
                self._sleep(_retry_after(resp) or self._backoff(attempt))
                attempt += 1
                continue
            raise HttpError(method, url, resp.status_code, resp.text)
