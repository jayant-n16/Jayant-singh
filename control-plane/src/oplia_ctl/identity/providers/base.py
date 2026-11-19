"""Unified identity-provider interface.

``group_ref`` is provider specific and validated by each driver:

* Entra ID - a group object id, or ``role:<roleDefinitionId>`` for a directory role
* Okta     - a group id (``00g...``), or ``role:<ROLE_TYPE>`` for an admin role (e.g. ``role:SUPER_ADMIN``)
* AD       - the distinguished name of a security group

``user_id`` is the provider's id: Entra object id, Okta user id (``00u...``), AD ``sAMAccountName``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

IdpName = Literal["entra", "okta", "ad"]


class IdentityProviderError(RuntimeError):
    """The provider rejected or failed the operation."""


@dataclass(frozen=True)
class IdpUser:
    idp: IdpName
    user_id: str
    display: str
    last_login: datetime | None     # None = never signed in (or not recorded)
    created: datetime | None
    exclude_reason: str = ""        # non-empty: report only, never disable


class IdentityProvider(Protocol):
    name: IdpName

    def validate_user_id(self, user_id: str) -> str: ...

    def validate_group_ref(self, group_ref: str) -> str: ...

    def add_member(self, group_ref: str, user_id: str) -> None:
        """Grant. Idempotent: already a member is success."""
        ...

    def remove_member(self, group_ref: str, user_id: str) -> None:
        """Revoke. Idempotent: not a member is success."""
        ...

    def has_access(self, group_ref: str, user_id: str) -> bool:
        """True if the user currently holds the group/role (used to verify a revocation)."""
        ...

    def list_members(self, group_ref: str) -> list[str]: ...

    def list_inactive_users(self, cutoff: datetime) -> list[IdpUser]:
        """Enabled users whose last login (or creation, if they never logged in) is <= cutoff."""
        ...

    def last_login(self, user_id: str) -> datetime | None: ...

    def disable_user(self, user_id: str) -> None: ...
