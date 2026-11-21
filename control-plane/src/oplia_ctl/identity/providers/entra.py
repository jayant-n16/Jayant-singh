"""Microsoft Entra ID driver - Microsoft Graph v1.0 over HTTPS (app-only, client credentials).

Application permissions needed (admin consent):

* ``GroupMember.ReadWrite.All``                 - add/remove group members
* ``RoleManagement.ReadWrite.Directory``        - directory role assignments; also required when the
                                                  group is role-assignable
* ``User.ReadWrite.All`` (or ``User.EnableDisableAccount.All`` + ``User.Read.All``) - disable users
* ``AuditLog.Read.All``                         - ``signInActivity`` (needs Entra ID P1/P2)

Notes taken from the Graph documentation:

* adding an existing member returns 400 (also used for other errors), so a 400 is accepted only
  when a follow-up check shows the user already has the access;
* when ``signInActivity`` is selected the page size is capped (120); 100 is used;
* inactivity uses the latest of ``lastSuccessfulSignInDateTime`` / ``lastSignInDateTime`` /
  ``lastNonInteractiveSignInDateTime`` - the conservative choice (any recent attempt counts);
* users synchronised from on-premises AD are reported but not disabled here (Entra Connect would
  re-enable them); they are disabled through the AD driver instead.
"""

from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Any
from urllib.parse import quote

from oplia_ctl.http import HttpError, ResilientClient
from oplia_ctl.identity.providers.base import IdentityProviderError, IdpName, IdpUser
from oplia_ctl.secrets import SecretProvider

GRAPH = "https://graph.microsoft.com/v1.0"
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_SIGNIN_FIELDS = ("lastSuccessfulSignInDateTime", "lastSignInDateTime", "lastNonInteractiveSignInDateTime")


def _ts(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def entra_last_activity(user: dict[str, Any]) -> datetime | None:
    act = user.get("signInActivity") or {}
    stamps = [t for t in (_ts(act.get(f)) for f in _SIGNIN_FIELDS) if t is not None]
    return max(stamps) if stamps else None


class EntraProvider:
    name: IdpName = "entra"

    def __init__(self, *, tenant_id: str, client_id: str, secrets: SecretProvider, client: ResilientClient,
                 client_secret_name: str = "entra_client_secret", members_only: bool = True,
                 clock: Any = time.monotonic) -> None:
        if not _GUID.fullmatch(tenant_id) or not _GUID.fullmatch(client_id):
            raise ValueError("Entra tenant_id and client_id must be GUIDs")
        self._tenant = tenant_id
        self._client_id = client_id
        self._secrets = secrets
        self._http = client
        self._secret_name = client_secret_name
        self._members_only = members_only
        self._clock = clock
        self._token: tuple[str, float] | None = None

    # ------------------------------------------------------------------ plumbing
    def _bearer(self) -> str:
        if self._token and self._token[1] - 60 > self._clock():
            return self._token[0]
        resp = self._http.request(
            "POST", f"https://login.microsoftonline.com/{self._tenant}/oauth2/v2.0/token", expected={200},
            data={"client_id": self._client_id, "client_secret": self._secrets.get(self._secret_name),
                  "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials"})
        body = resp.json()
        self._token = (str(body["access_token"]), self._clock() + float(body.get("expires_in", 3599)))
        return self._token[0]

    def _call(self, method: str, path_or_url: str, *, expected: set[int], **kw: Any) -> Any:
        url = path_or_url if path_or_url.startswith("https://") else GRAPH + path_or_url
        if not url.startswith(GRAPH + "/"):
            raise IdentityProviderError("refusing to send the Graph token to a non-Graph URL")
        headers = {"Authorization": f"Bearer {self._bearer()}", **kw.pop("headers", {})}
        return self._http.request(method, url, expected=expected, headers=headers, **kw)

    def _pages(self, path: str, params: dict[str, str] | None = None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        url: str | None = path
        first = True
        while url:
            resp = self._call("GET", url, expected={200}, params=params if first else None)
            data = resp.json()
            out.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
            first = False
        return out

    # --------------------------------------------------------------- validation
    def validate_user_id(self, user_id: str) -> str:
        if not _GUID.fullmatch(user_id):
            raise ValueError("Entra user_id must be the user's object id (GUID)")
        return user_id

    def validate_group_ref(self, group_ref: str) -> str:
        ref = group_ref.removeprefix("role:")
        if not _GUID.fullmatch(ref):
            raise ValueError("Entra group_ref must be a group object id or role:<roleDefinitionId>")
        return group_ref

    # ------------------------------------------------------------------- access
    def _role_assignment_ids(self, role_def: str, user_id: str) -> list[str]:
        flt = f"principalId eq '{user_id}' and roleDefinitionId eq '{role_def}'"
        return [a["id"] for a in self._pages("/roleManagement/directory/roleAssignments", {"$filter": flt})]

    def has_access(self, group_ref: str, user_id: str) -> bool:
        self.validate_group_ref(group_ref)
        self.validate_user_id(user_id)
        if group_ref.startswith("role:"):
            return bool(self._role_assignment_ids(group_ref[5:], user_id))
        resp = self._call("POST", f"/users/{user_id}/checkMemberGroups", expected={200},
                          json={"groupIds": [group_ref]})
        return group_ref.lower() in {g.lower() for g in resp.json().get("value", [])}

    def add_member(self, group_ref: str, user_id: str) -> None:
        self.validate_group_ref(group_ref)
        self.validate_user_id(user_id)
        if group_ref.startswith("role:"):
            if self._role_assignment_ids(group_ref[5:], user_id):
                return
            self._call("POST", "/roleManagement/directory/roleAssignments", expected={201},
                       json={"principalId": user_id, "roleDefinitionId": group_ref[5:], "directoryScopeId": "/"})
            return
        try:
            self._call("POST", f"/groups/{group_ref}/members/$ref", expected={204},
                       json={"@odata.id": f"{GRAPH}/directoryObjects/{user_id}"})
        except HttpError as exc:
            if exc.status == 400 and self.has_access(group_ref, user_id):
                return  # already a member
            raise

    def remove_member(self, group_ref: str, user_id: str) -> None:
        self.validate_group_ref(group_ref)
        self.validate_user_id(user_id)
        if group_ref.startswith("role:"):
            for aid in self._role_assignment_ids(group_ref[5:], user_id):
                try:
                    self._call("DELETE", f"/roleManagement/directory/roleAssignments/{quote(aid, safe='')}",
                               expected={204})
                except HttpError as exc:
                    if exc.status != 404:
                        raise
            return
        try:
            self._call("DELETE", f"/groups/{group_ref}/members/{user_id}/$ref", expected={204})
        except HttpError as exc:
            if exc.status != 404:  # 404: not a (direct) member any more
                raise

    def list_members(self, group_ref: str) -> list[str]:
        self.validate_group_ref(group_ref)
        if group_ref.startswith("role:"):
            flt = f"roleDefinitionId eq '{group_ref[5:]}'"
            assignments = self._pages("/roleManagement/directory/roleAssignments", {"$filter": flt})
            return [a["principalId"] for a in assignments]
        return [m["id"] for m in self._pages(f"/groups/{group_ref}/members", {"$select": "id"})]

    # ----------------------------------------------------------------- lifecycle
    def list_inactive_users(self, cutoff: datetime) -> list[IdpUser]:
        params = {"$select": "id,userPrincipalName,accountEnabled,userType,createdDateTime,"
                             "onPremisesSyncEnabled,signInActivity",
                  "$top": "100"}
        out: list[IdpUser] = []
        for u in self._pages("/users", params):
            if not u.get("accountEnabled"):
                continue
            if self._members_only and u.get("userType") == "Guest":
                continue
            last = entra_last_activity(u)
            created = _ts(u.get("createdDateTime"))
            reference = last or created
            if reference is None or reference > cutoff:
                continue
            why = "synchronised from on-premises AD: disable it in AD" if u.get("onPremisesSyncEnabled") else ""
            out.append(IdpUser("entra", u["id"], u.get("userPrincipalName") or u["id"], last, created, why))
        return out

    def last_login(self, user_id: str) -> datetime | None:
        self.validate_user_id(user_id)
        u = self._call("GET", f"/users/{user_id}", expected={200},
                       params={"$select": "id,signInActivity"}).json()
        return entra_last_activity(u)

    def disable_user(self, user_id: str) -> None:
        self.validate_user_id(user_id)
        self._call("PATCH", f"/users/{user_id}", expected={204}, json={"accountEnabled": False})
