"""Okta driver - Okta Management API (Users, Groups, Roles) with an API token (``SSWS``).

* group membership: ``PUT`` / ``DELETE /api/v1/groups/{groupId}/users/{userId}`` (204, idempotent)
* admin roles (``role:<TYPE>``, e.g. ``role:SUPER_ADMIN``): ``/api/v1/users/{userId}/roles``
* inactivity: ``ACTIVE`` users whose ``lastLogin`` (or ``created`` if never logged in) is past the
  cutoff; disabling uses ``lifecycle/suspend`` - reversible with ``unsuspend``, unlike deactivate.

Pagination follows the ``Link: rel="next"`` header, and only to the configured Okta host so the
token never leaves it.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from oplia_ctl.http import HttpError, ResilientClient
from oplia_ctl.identity.providers.base import IdentityProviderError, IdpName, IdpUser
from oplia_ctl.secrets import SecretProvider

_USER = re.compile(r"^00u[0-9A-Za-z]{17}$")
_GROUP = re.compile(r"^00g[0-9A-Za-z]{17}$")
OKTA_ADMIN_ROLES = frozenset({
    "SUPER_ADMIN", "ORG_ADMIN", "APP_ADMIN", "USER_ADMIN", "HELP_DESK_ADMIN", "READ_ONLY_ADMIN",
    "MOBILE_ADMIN", "API_ACCESS_MANAGEMENT_ADMIN", "REPORT_ADMIN", "GROUP_MEMBERSHIP_ADMIN",
})


def _ts(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


class OktaProvider:
    name: IdpName = "okta"

    def __init__(self, *, org_url: str, secrets: SecretProvider, client: ResilientClient,
                 token_secret_name: str = "okta_api_token") -> None:
        parts = urlsplit(org_url)
        if parts.scheme != "https" or not parts.hostname or parts.path not in ("", "/"):
            raise ValueError("Okta org_url must be https://<your-org>.okta.com (no path)")
        self._base = f"https://{parts.netloc}"
        self._host = parts.netloc.lower()
        self._secrets = secrets
        self._http = client
        self._secret_name = token_secret_name

    def _call(self, method: str, path_or_url: str, *, expected: set[int], **kw: Any) -> Any:
        url = path_or_url if path_or_url.startswith("https://") else self._base + path_or_url
        if urlsplit(url).netloc.lower() != self._host:
            raise IdentityProviderError("refusing to send the Okta token to another host")
        headers = {"Authorization": f"SSWS {self._secrets.get(self._secret_name)}",
                   "Accept": "application/json", **kw.pop("headers", {})}
        return self._http.request(method, url, expected=expected, headers=headers, **kw)

    def _pages(self, path: str, params: dict[str, str] | None = None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        url: str | None = path
        first = True
        while url:
            resp = self._call("GET", url, expected={200}, params=params if first else None)
            out.extend(resp.json())
            url = resp.links.get("next", {}).get("url")
            first = False
        return out

    def validate_user_id(self, user_id: str) -> str:
        if not _USER.fullmatch(user_id):
            raise ValueError("Okta user_id must be an Okta user id (00u...)")
        return user_id

    def validate_group_ref(self, group_ref: str) -> str:
        if group_ref.startswith("role:"):
            if group_ref[5:] not in OKTA_ADMIN_ROLES:
                raise ValueError(f"unknown Okta admin role {group_ref[5:]!r}")
        elif not _GROUP.fullmatch(group_ref):
            raise ValueError("Okta group_ref must be a group id (00g...) or role:<ROLE_TYPE>")
        return group_ref

    def _role_ids(self, role_type: str, user_id: str) -> list[str]:
        return [r["id"] for r in self._call("GET", f"/api/v1/users/{user_id}/roles", expected={200}).json()
                if r.get("type") == role_type]

    def has_access(self, group_ref: str, user_id: str) -> bool:
        self.validate_group_ref(group_ref)
        self.validate_user_id(user_id)
        if group_ref.startswith("role:"):
            return bool(self._role_ids(group_ref[5:], user_id))
        return any(g.get("id") == group_ref for g in self._pages(f"/api/v1/users/{user_id}/groups"))

    def add_member(self, group_ref: str, user_id: str) -> None:
        self.validate_group_ref(group_ref)
        self.validate_user_id(user_id)
        if group_ref.startswith("role:"):
            if not self._role_ids(group_ref[5:], user_id):
                self._call("POST", f"/api/v1/users/{user_id}/roles", expected={200, 201},
                           json={"type": group_ref[5:]})
            return
        self._call("PUT", f"/api/v1/groups/{group_ref}/users/{user_id}", expected={204})

    def remove_member(self, group_ref: str, user_id: str) -> None:
        self.validate_group_ref(group_ref)
        self.validate_user_id(user_id)
        if group_ref.startswith("role:"):
            for rid in self._role_ids(group_ref[5:], user_id):
                try:
                    self._call("DELETE", f"/api/v1/users/{user_id}/roles/{rid}", expected={204})
                except HttpError as exc:
                    if exc.status != 404:
                        raise
            return
        try:
            self._call("DELETE", f"/api/v1/groups/{group_ref}/users/{user_id}", expected={204})
        except HttpError as exc:
            if exc.status != 404:
                raise

    def list_members(self, group_ref: str) -> list[str]:
        self.validate_group_ref(group_ref)
        if group_ref.startswith("role:"):
            raise IdentityProviderError("listing all holders of an Okta admin role is not supported here; "
                                        "use a group-based role for standing-access reconciliation")
        return [u["id"] for u in self._pages(f"/api/v1/groups/{group_ref}/users", {"limit": "200"})]

    def list_inactive_users(self, cutoff: datetime) -> list[IdpUser]:
        out: list[IdpUser] = []
        for u in self._pages("/api/v1/users", {"filter": 'status eq "ACTIVE"', "limit": "200"}):
            if u.get("status") != "ACTIVE":
                continue
            last, created = _ts(u.get("lastLogin")), _ts(u.get("created"))
            reference = last or created
            if reference is None or reference > cutoff:
                continue
            login = (u.get("profile") or {}).get("login") or u["id"]
            out.append(IdpUser("okta", u["id"], login, last, created))
        return out

    def last_login(self, user_id: str) -> datetime | None:
        self.validate_user_id(user_id)
        return _ts(self._call("GET", f"/api/v1/users/{user_id}", expected={200}).json().get("lastLogin"))

    def disable_user(self, user_id: str) -> None:
        self.validate_user_id(user_id)
        self._call("POST", f"/api/v1/users/{user_id}/lifecycle/suspend", expected={200})
