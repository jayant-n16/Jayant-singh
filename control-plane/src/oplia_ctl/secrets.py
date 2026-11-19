"""Secret resolution.

Code asks for secrets by *name*; the provider decides where they live. The
``env`` provider reads ``OPLIA_SECRET_<NAME>`` and exists for local development
and CI. Production uses the Vault provider (added in Phase 7). Secret values are
never logged, never placed in exceptions, and never written to the database.
"""

from __future__ import annotations

import os
import re
from typing import Protocol

_NAME_RE = re.compile(r"^[a-z0-9_]{1,64}$")


class SecretNotFoundError(LookupError):
    """Raised when a named secret is not available. Carries the name only."""


class SecretProvider(Protocol):
    def get(self, name: str) -> str: ...


def _check_name(name: str) -> None:
    if not _NAME_RE.fullmatch(name):
        raise ValueError(f"invalid secret name {name!r}: use lowercase letters, digits, underscore")


class EnvSecretProvider:
    """Reads ``OPLIA_SECRET_<NAME>`` from the process environment."""

    def __init__(self, environ: dict[str, str] | None = None) -> None:
        self._environ = environ if environ is not None else os.environ

    def get(self, name: str) -> str:
        _check_name(name)
        value = self._environ.get(f"OPLIA_SECRET_{name.upper()}")
        if not value:
            raise SecretNotFoundError(name)
        return value


class StaticSecretProvider:
    """In-memory provider for tests."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = dict(values)

    def get(self, name: str) -> str:
        _check_name(name)
        try:
            return self._values[name]
        except KeyError:
            raise SecretNotFoundError(name) from None


def build_secret_provider(kind: str) -> SecretProvider:
    if kind == "env":
        return EnvSecretProvider()
    if kind == "vault":
        # Implemented in Phase 7 (oplia_ctl.vault). Fail loudly rather than silently
        # falling back to environment variables in an environment expecting Vault.
        from oplia_ctl.vault import VaultSecretProvider

        provider: SecretProvider = VaultSecretProvider.from_settings()
        return provider
    raise ValueError(f"unknown secret provider {kind!r}")
