"""Active Directory driver - LDAP via ``python-ldap`` (as specified), LDAPS or StartTLS only.

* grant / revoke: ``modify_s`` with ``MOD_ADD`` / ``MOD_DELETE`` of the user's DN on the group's
  ``member`` attribute (idempotent: "already exists" / "no such value" are success)
* access check: transitive (``LDAP_MATCHING_RULE_IN_CHAIN``) so nested-group access is seen;
  ``active_directory=False`` switches to plain LDAP (direct membership, no range retrieval,
  configurable user filter / login attribute) - used to test against OpenLDAP
* inactivity: enabled user accounts whose ``lastLogonTimestamp`` (replicated; AD updates it only
  every 9-14 days, irrelevant for a 90-day threshold) is older than the cutoff, or that never
  logged on and were created before it. Critical system objects and built-in accounts are skipped.
* disable: sets ``ACCOUNTDISABLE`` (0x2) in ``userAccountControl`` - reversible.

The bind password is a secret (``ad_bind_password``); a plaintext ``ldap://`` bind without
StartTLS is refused.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any

from oplia_ctl.identity.providers.base import IdentityProviderError, IdpName, IdpUser
from oplia_ctl.secrets import SecretProvider

UF_ACCOUNTDISABLE = 0x2
_SAM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._$-]{0,19}$")
_DN = re.compile(r"^(?:[A-Za-z][\w-]*=[^,=]+)(?:,[A-Za-z][\w-]*=[^,=]+)+$")
_EPOCH_DIFF = 11644473600  # seconds between 1601-01-01 and 1970-01-01
DEFAULT_EXEMPT = frozenset({"krbtgt", "administrator", "guest", "defaultaccount", "wdagutilityaccount"})


def filetime_to_dt(value: int) -> datetime | None:
    if value <= 0 or value >= 0x7FFFFFFFFFFFFFFF:
        return None
    return datetime.fromtimestamp(value / 10_000_000 - _EPOCH_DIFF, tz=UTC)


def dt_to_filetime(dt: datetime) -> int:
    return int((dt.timestamp() + _EPOCH_DIFF) * 10_000_000)


def generalized_to_dt(value: str) -> datetime:
    return datetime.strptime(value.split(".")[0].rstrip("Z"), "%Y%m%d%H%M%S").replace(tzinfo=UTC)


def _first(entry: dict[str, list[bytes]], attr: str) -> str | None:
    for k, v in entry.items():
        if k.lower() == attr.lower() and v:
            return v[0].decode()
    return None


class AdProvider:
    name: IdpName = "ad"

    def __init__(self, *, url: str, bind_dn: str, base_dn: str, secrets: SecretProvider,
                 password_secret_name: str = "ad_bind_password", ca_cert_file: str | None = None,
                 start_tls: bool = False, page_size: int = 500, timeout_seconds: int = 15,
                 active_directory: bool = True, exempt_accounts: frozenset[str] = DEFAULT_EXEMPT,
                 user_filter: str = "(&(objectCategory=person)(objectClass=user))",
                 login_attr: str = "sAMAccountName",
                 conn_factory: Callable[[], Any] | None = None) -> None:
        if url.startswith("ldap://") and not start_tls:
            raise ValueError("plaintext LDAP bind refused: use ldaps:// or start_tls=True")
        if not url.startswith(("ldaps://", "ldap://")):
            raise ValueError("AD url must be ldaps://host[:port] or ldap://host with start_tls")
        if not _DN.fullmatch(base_dn) or not _DN.fullmatch(bind_dn):
            raise ValueError("base_dn and bind_dn must be distinguished names")
        self._url, self._bind_dn, self._base = url, bind_dn, base_dn
        self._secrets, self._pw = secrets, password_secret_name
        self._ca, self._start_tls = ca_cert_file, start_tls
        self._page, self._timeout = page_size, timeout_seconds
        # active_directory=False: plain LDAP (e.g. OpenLDAP) - direct membership, no range retrieval
        self._ad = active_directory
        self._user_filter = user_filter
        self._login = login_attr
        self._exempt = frozenset(a.lower() for a in exempt_accounts)
        self._factory = conn_factory or self._connect

    # ------------------------------------------------------------------ plumbing
    def _connect(self) -> Any:
        import ldap

        conn = ldap.initialize(self._url)
        conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        conn.set_option(ldap.OPT_REFERRALS, 0)
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, self._timeout)
        conn.set_option(ldap.OPT_TIMEOUT, self._timeout)
        conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
        if self._ca:
            conn.set_option(ldap.OPT_X_TLS_CACERTFILE, self._ca)
        conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
        if self._start_tls:
            conn.start_tls_s()
        conn.simple_bind_s(self._bind_dn, self._secrets.get(self._pw))
        return conn

    def _with(self, fn: Callable[[Any], Any]) -> Any:
        conn = self._factory()
        try:
            return fn(conn)
        finally:
            try:
                conn.unbind_s()
            except Exception:  # noqa: S110  # nosec B110 - best-effort close
                pass

    def _paged(self, conn: Any, base: str, flt: str, attrs: list[str]) -> Iterator[tuple[str, dict[str, list[bytes]]]]:
        import ldap
        from ldap.controls import SimplePagedResultsControl

        ctrl = SimplePagedResultsControl(True, size=self._page, cookie=b"")
        while True:
            msgid = conn.search_ext(base, ldap.SCOPE_SUBTREE, flt, attrs, serverctrls=[ctrl])
            _rtype, data, _mid, sctrls = conn.result3(msgid)
            for dn, entry in data:
                if dn:  # skip search continuation references
                    yield dn, entry
            pctrls = [c for c in sctrls if c.controlType == SimplePagedResultsControl.controlType]
            if not pctrls or not pctrls[0].cookie:
                return
            ctrl.cookie = pctrls[0].cookie

    def _user_dn(self, conn: Any, sam: str) -> str:
        import ldap
        from ldap.filter import escape_filter_chars

        flt = f"(&{self._user_filter}({self._login}={escape_filter_chars(sam)}))"
        res = [(dn, e) for dn, e in conn.search_s(self._base, ldap.SCOPE_SUBTREE, flt, ["1.1"]) if dn]
        if len(res) != 1:
            raise IdentityProviderError(f"expected exactly one AD user {sam!r}, found {len(res)}")
        return str(res[0][0])

    # --------------------------------------------------------------- validation
    def validate_user_id(self, user_id: str) -> str:
        if not _SAM.fullmatch(user_id):
            raise ValueError("AD user_id must be a sAMAccountName")
        return user_id

    def validate_group_ref(self, group_ref: str) -> str:
        if not _DN.fullmatch(group_ref):
            raise ValueError("AD group_ref must be the group's distinguished name")
        return group_ref

    # ------------------------------------------------------------------- access
    def has_access(self, group_ref: str, user_id: str) -> bool:
        import ldap
        from ldap.filter import escape_filter_chars

        self.validate_group_ref(group_ref)
        self.validate_user_id(user_id)

        def run(conn: Any) -> bool:
            dn = self._user_dn(conn, user_id)
            if self._ad:
                flt = f"(memberOf:1.2.840.113556.1.4.1941:={escape_filter_chars(group_ref)})"
                return bool([d for d, _ in conn.search_s(dn, ldap.SCOPE_BASE, flt, ["1.1"]) if d])
            flt = f"(member={escape_filter_chars(dn)})"
            return bool([d for d, _ in conn.search_s(group_ref, ldap.SCOPE_BASE, flt, ["1.1"]) if d])

        return bool(self._with(run))

    def add_member(self, group_ref: str, user_id: str) -> None:
        import ldap

        self.validate_group_ref(group_ref)
        self.validate_user_id(user_id)

        def run(conn: Any) -> None:
            dn = self._user_dn(conn, user_id)
            try:
                conn.modify_s(group_ref, [(ldap.MOD_ADD, "member", [dn.encode()])])
            except (ldap.ALREADY_EXISTS, ldap.TYPE_OR_VALUE_EXISTS):
                return

        self._with(run)

    def remove_member(self, group_ref: str, user_id: str) -> None:
        import ldap

        self.validate_group_ref(group_ref)
        self.validate_user_id(user_id)

        def run(conn: Any) -> None:
            dn = self._user_dn(conn, user_id)
            try:
                conn.modify_s(group_ref, [(ldap.MOD_DELETE, "member", [dn.encode()])])
            except ldap.NO_SUCH_ATTRIBUTE:
                return  # not a member
            except ldap.UNWILLING_TO_PERFORM:
                # AD may answer this for a value that is not present; only accept it if verifiably absent
                from ldap.filter import escape_filter_chars

                flt = f"(member={escape_filter_chars(dn)})"
                if [d for d, _ in conn.search_s(group_ref, ldap.SCOPE_BASE, flt, ["1.1"]) if d]:
                    raise

        self._with(run)

    def list_members(self, group_ref: str) -> list[str]:
        import ldap

        self.validate_group_ref(group_ref)

        def run(conn: Any) -> list[str]:
            dns: list[str] = []
            start = 0
            while True:  # AD range retrieval for groups with more than ~1500 members
                attr = f"member;range={start}-*" if self._ad else "member"
                [(_dn, entry)] = conn.search_s(group_ref, ldap.SCOPE_BASE, "(objectClass=*)", [attr])
                key = next((k for k in entry if k.lower().startswith("member")), None)
                if key is None:
                    break
                dns += [v.decode() for v in entry[key]]
                if ";range=" not in key or key.endswith("-*"):
                    break
                start = int(key.rsplit("-", 1)[1]) + 1
            sams: list[str] = []
            for dn in dns:
                res = conn.search_s(dn, ldap.SCOPE_BASE, "(objectClass=*)", [self._login])
                sam = _first(res[0][1], self._login) if res else None
                sams.append(sam or dn)
            return sams

        return list(self._with(run))

    # ----------------------------------------------------------------- lifecycle
    def list_inactive_users(self, cutoff: datetime) -> list[IdpUser]:
        ft = dt_to_filetime(cutoff)
        gt = cutoff.astimezone(UTC).strftime("%Y%m%d%H%M%S.0Z")
        flt = ("(&(objectCategory=person)(objectClass=user)"
               "(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(isCriticalSystemObject=TRUE))"
               f"(|(lastLogonTimestamp<={ft})(&(!(lastLogonTimestamp=*))(whenCreated<={gt}))))")
        attrs = ["sAMAccountName", "userPrincipalName", "lastLogonTimestamp", "whenCreated"]

        def run(conn: Any) -> list[IdpUser]:
            out: list[IdpUser] = []
            for _dn, e in self._paged(conn, self._base, flt, attrs):
                sam = _first(e, "sAMAccountName")
                if not sam or sam.lower() in self._exempt:
                    continue
                llt = _first(e, "lastLogonTimestamp")
                wc = _first(e, "whenCreated")
                out.append(IdpUser("ad", sam, _first(e, "userPrincipalName") or sam,
                                   filetime_to_dt(int(llt)) if llt else None,
                                   generalized_to_dt(wc) if wc else None))
            return out

        return list(self._with(run))

    def last_login(self, user_id: str) -> datetime | None:
        import ldap

        self.validate_user_id(user_id)

        def run(conn: Any) -> datetime | None:
            dn = self._user_dn(conn, user_id)
            [(_d, e)] = conn.search_s(dn, ldap.SCOPE_BASE, "(objectClass=*)", ["lastLogonTimestamp"])
            llt = _first(e, "lastLogonTimestamp")
            return filetime_to_dt(int(llt)) if llt else None

        result: datetime | None = self._with(run)
        return result

    def disable_user(self, user_id: str) -> None:
        import ldap

        self.validate_user_id(user_id)

        def run(conn: Any) -> None:
            dn = self._user_dn(conn, user_id)
            [(_d, e)] = conn.search_s(dn, ldap.SCOPE_BASE, "(objectClass=*)", ["userAccountControl"])
            uac = int(_first(e, "userAccountControl") or "0")
            if uac & UF_ACCOUNTDISABLE:
                return
            conn.modify_s(dn, [(ldap.MOD_REPLACE, "userAccountControl", [str(uac | UF_ACCOUNTDISABLE).encode()])])

        self._with(run)
