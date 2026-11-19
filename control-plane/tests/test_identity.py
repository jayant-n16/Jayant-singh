from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from oplia_ctl.api import create_app
from oplia_ctl.auth import OIDCVerifier
from oplia_ctl.http import HttpError, ResilientClient
from oplia_ctl.identity.jit import (
    ACTION_JIT_GRANT,
    JitConflictError,
    JitRequestError,
    JitService,
    RoleSpec,
    load_catalog,
)
from oplia_ctl.identity.providers.ad import (
    UF_ACCOUNTDISABLE,
    AdProvider,
    dt_to_filetime,
    filetime_to_dt,
    generalized_to_dt,
)
from oplia_ctl.identity.providers.base import IdentityProviderError, IdpUser
from oplia_ctl.identity.providers.entra import GRAPH, EntraProvider
from oplia_ctl.identity.providers.okta import OktaProvider
from oplia_ctl.identity.sweep import ACTION_DISABLE_INACTIVE, DisableInactiveExecutor, InactivitySweeper
from oplia_ctl.safety import FourEyesViolationError, KillSwitchEngagedError, ProposalStatus, SafetyGate
from oplia_ctl.secrets import StaticSecretProvider
from tests.test_aiops import FakeNotifier
from tests.test_api import AUD, ISS, KEY, bearer

TENANT = "11111111-1111-1111-1111-111111111111"
CLIENT = "22222222-2222-2222-2222-222222222222"
GROUP = "33333333-3333-3333-3333-333333333333"
USER = "44444444-4444-4444-4444-444444444444"
ROLE_DEF = "62e90394-69f5-4237-9190-012177145e10"
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
OKTA = "https://acme.okta.com"
OKTA_USER = "00u1abcdEFGHijklMNOP"
OKTA_GROUP = "00g1abcdEFGHijklMNOP"
SECRETS = StaticSecretProvider({"entra_client_secret": "s3cr3t", "okta_api_token": "tok",
                                "ad_bind_password": "pw"})


def http() -> ResilientClient:
    return ResilientClient(sleep=lambda _s: None, max_retries=1)


# ============================================================== Entra (Graph)
def entra() -> EntraProvider:
    return EntraProvider(tenant_id=TENANT, client_id=CLIENT, secrets=SECRETS, client=http(), clock=lambda: 1000.0)


@respx.mock
def test_entra_group_add_remove_and_token_cache():
    tok = respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "AT", "expires_in": 3599}))
    add = respx.post(f"{GRAPH}/groups/{GROUP}/members/$ref").mock(return_value=httpx.Response(204))
    rm = respx.delete(f"{GRAPH}/groups/{GROUP}/members/{USER}/$ref").mock(return_value=httpx.Response(204))
    p = entra()
    p.add_member(GROUP, USER)
    p.remove_member(GROUP, USER)
    assert json.loads(add.calls.last.request.content) == {"@odata.id": f"{GRAPH}/directoryObjects/{USER}"}
    assert add.calls.last.request.headers["Authorization"] == "Bearer AT"
    assert rm.called and tok.call_count == 1  # token reused
    form = dict(httpx.QueryParams(tok.calls.last.request.content.decode()))
    assert form == {"client_id": CLIENT, "client_secret": "s3cr3t", "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials"}


@respx.mock
def test_entra_400_on_add_is_accepted_only_if_already_member():
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "AT"}))
    respx.post(f"{GRAPH}/groups/{GROUP}/members/$ref").mock(return_value=httpx.Response(400, json={"error": {}}))
    check = respx.post(f"{GRAPH}/users/{USER}/checkMemberGroups").mock(
        return_value=httpx.Response(200, json={"value": [GROUP.upper()]}))
    entra().add_member(GROUP, USER)  # already a member -> success
    assert json.loads(check.calls.last.request.content) == {"groupIds": [GROUP]}
    check.mock(return_value=httpx.Response(200, json={"value": []}))
    with pytest.raises(HttpError):
        entra().add_member(GROUP, USER)  # a real 400


@respx.mock
def test_entra_remove_404_is_success_and_roles():
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "AT"}))
    respx.delete(f"{GRAPH}/groups/{GROUP}/members/{USER}/$ref").mock(return_value=httpx.Response(404))
    entra().remove_member(GROUP, USER)
    lst = respx.get(f"{GRAPH}/roleManagement/directory/roleAssignments").mock(
        side_effect=[httpx.Response(200, json={"value": []}),
                     httpx.Response(200, json={"value": [{"id": "ra-1", "principalId": USER}]})])
    post = respx.post(f"{GRAPH}/roleManagement/directory/roleAssignments").mock(return_value=httpx.Response(201))
    dele = respx.delete(f"{GRAPH}/roleManagement/directory/roleAssignments/ra-1").mock(return_value=httpx.Response(204))
    entra().add_member(f"role:{ROLE_DEF}", USER)
    assert json.loads(post.calls.last.request.content) == {"principalId": USER, "roleDefinitionId": ROLE_DEF,
                                                           "directoryScopeId": "/"}
    assert lst.calls[0].request.url.params["$filter"] == (
        f"principalId eq '{USER}' and roleDefinitionId eq '{ROLE_DEF}'")
    entra().remove_member(f"role:{ROLE_DEF}", USER)
    assert dele.called


@respx.mock
def test_entra_inactive_users_paging_and_rules():
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "AT"}))
    cutoff = datetime(2026, 8, 21, tzinfo=UTC)
    page1 = {"value": [
        {"id": "u-old", "userPrincipalName": "old@acme", "accountEnabled": True, "userType": "Member",
         "createdDateTime": "2024-01-01T00:00:00Z",
         "signInActivity": {"lastSignInDateTime": "2026-05-01T00:00:00Z",
                            "lastNonInteractiveSignInDateTime": "2026-06-01T00:00:00Z"}},
        {"id": "u-recent-noninteractive", "accountEnabled": True, "userType": "Member",
         "createdDateTime": "2024-01-01T00:00:00Z",
         "signInActivity": {"lastSignInDateTime": "2026-01-01T00:00:00Z",
                            "lastNonInteractiveSignInDateTime": "2026-11-01T00:00:00Z"}},
        {"id": "u-guest", "accountEnabled": True, "userType": "Guest", "createdDateTime": "2024-01-01T00:00:00Z"},
    ], "@odata.nextLink": f"{GRAPH}/users?$skiptoken=abc"}
    page2 = {"value": [
        {"id": "u-never", "userPrincipalName": "never@acme", "accountEnabled": True, "userType": "Member",
         "createdDateTime": "2025-01-01T00:00:00Z", "signInActivity": None},
        {"id": "u-new", "accountEnabled": True, "userType": "Member", "createdDateTime": "2026-11-01T00:00:00Z"},
        {"id": "u-synced", "userPrincipalName": "synced@acme", "accountEnabled": True, "userType": "Member",
         "onPremisesSyncEnabled": True, "createdDateTime": "2020-01-01T00:00:00Z"},
        {"id": "u-disabled", "accountEnabled": False, "createdDateTime": "2020-01-01T00:00:00Z"},
    ]}
    route = respx.get(f"{GRAPH}/users").mock(side_effect=[httpx.Response(200, json=page1),
                                                         httpx.Response(200, json=page2)])
    users = {u.user_id: u for u in entra().list_inactive_users(cutoff)}
    assert set(users) == {"u-old", "u-never", "u-synced"}
    assert users["u-old"].last_login == datetime(2026, 6, 1, tzinfo=UTC)  # latest of the timestamps
    assert users["u-never"].last_login is None and users["u-synced"].exclude_reason
    first = route.calls[0].request.url.params
    assert first["$top"] == "100" and "signInActivity" in first["$select"]
    assert "skiptoken=abc" in str(route.calls[1].request.url)


@respx.mock
def test_entra_refuses_foreign_next_link_and_disables():
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "AT"}))
    respx.get(f"{GRAPH}/users").mock(return_value=httpx.Response(200, json={
        "value": [], "@odata.nextLink": "https://evil.example.com/steal"}))
    with pytest.raises(IdentityProviderError, match="non-Graph"):
        entra().list_inactive_users(datetime(2026, 8, 21, tzinfo=UTC))
    patch = respx.patch(f"{GRAPH}/users/{USER}").mock(return_value=httpx.Response(204))
    entra().disable_user(USER)
    assert json.loads(patch.calls.last.request.content) == {"accountEnabled": False}
    with pytest.raises(ValueError, match="GUID"):
        entra().disable_user("alice@acme.com")


# ======================================================================= Okta
def okta() -> OktaProvider:
    return OktaProvider(org_url=OKTA, secrets=SECRETS, client=http())


@respx.mock
def test_okta_group_membership():
    put = respx.put(f"{OKTA}/api/v1/groups/{OKTA_GROUP}/users/{OKTA_USER}").mock(return_value=httpx.Response(204))
    dele = respx.delete(f"{OKTA}/api/v1/groups/{OKTA_GROUP}/users/{OKTA_USER}").mock(
        side_effect=[httpx.Response(204), httpx.Response(404)])
    respx.get(f"{OKTA}/api/v1/users/{OKTA_USER}/groups").mock(
        return_value=httpx.Response(200, json=[{"id": OKTA_GROUP}]))
    p = okta()
    p.add_member(OKTA_GROUP, OKTA_USER)
    assert put.calls.last.request.headers["Authorization"] == "SSWS tok"
    assert p.has_access(OKTA_GROUP, OKTA_USER) is True
    p.remove_member(OKTA_GROUP, OKTA_USER)
    p.remove_member(OKTA_GROUP, OKTA_USER)  # 404: already removed
    assert dele.call_count == 2
    with pytest.raises(ValueError):
        p.add_member("Admins", OKTA_USER)
    with pytest.raises(ValueError, match="https"):
        OktaProvider(org_url="http://acme.okta.com", secrets=SECRETS, client=http())


@respx.mock
def test_okta_admin_roles():
    roles = respx.get(f"{OKTA}/api/v1/users/{OKTA_USER}/roles").mock(side_effect=[
        httpx.Response(200, json=[]),
        httpx.Response(200, json=[{"id": "ra1", "type": "SUPER_ADMIN"}, {"id": "ra2", "type": "REPORT_ADMIN"}])])
    post = respx.post(f"{OKTA}/api/v1/users/{OKTA_USER}/roles").mock(return_value=httpx.Response(201))
    dele = respx.delete(f"{OKTA}/api/v1/users/{OKTA_USER}/roles/ra1").mock(return_value=httpx.Response(204))
    okta().add_member("role:SUPER_ADMIN", OKTA_USER)
    assert json.loads(post.calls.last.request.content) == {"type": "SUPER_ADMIN"}
    okta().remove_member("role:SUPER_ADMIN", OKTA_USER)
    assert dele.called and roles.call_count == 2
    with pytest.raises(ValueError, match="unknown Okta admin role"):
        okta().add_member("role:GOD_MODE", OKTA_USER)


@respx.mock
def test_okta_inactive_users_link_paging_and_suspend():
    cutoff = datetime(2026, 8, 21, tzinfo=UTC)
    nxt = f"{OKTA}/api/v1/users?after=00u2&limit=200"
    p1 = httpx.Response(200, json=[
        {"id": "00uOLD000000000000001", "status": "ACTIVE", "lastLogin": "2026-01-01T00:00:00.000Z",
         "created": "2024-01-01T00:00:00.000Z", "profile": {"login": "old@acme"}},
        {"id": "00uNEW000000000000002", "status": "ACTIVE", "lastLogin": "2026-11-10T00:00:00.000Z",
         "created": "2024-01-01T00:00:00.000Z", "profile": {"login": "new@acme"}}],
        headers=[("Link", f'<{OKTA}/api/v1/users?limit=200>; rel="self"'), ("Link", f'<{nxt}>; rel="next"')])
    p2 = httpx.Response(200, json=[
        {"id": "00uNVR000000000000003", "status": "ACTIVE", "lastLogin": None,
         "created": "2025-02-01T00:00:00.000Z", "profile": {"login": "never@acme"}}])
    route = respx.get(f"{OKTA}/api/v1/users").mock(side_effect=[p1, p2])
    users = okta().list_inactive_users(cutoff)
    assert [u.display for u in users] == ["old@acme", "never@acme"]
    assert route.calls[0].request.url.params["filter"] == 'status eq "ACTIVE"'
    assert str(route.calls[1].request.url) == nxt
    sus = respx.post(f"{OKTA}/api/v1/users/{OKTA_USER}/lifecycle/suspend").mock(return_value=httpx.Response(200))
    okta().disable_user(OKTA_USER)
    assert sus.called


@respx.mock
def test_okta_never_follows_link_to_other_host():
    respx.get(f"{OKTA}/api/v1/users").mock(return_value=httpx.Response(
        200, json=[], headers={"Link": '<https://evil.example.com/x>; rel="next"'}))
    with pytest.raises(IdentityProviderError, match="another host"):
        okta().list_inactive_users(datetime(2026, 8, 21, tzinfo=UTC))


# ================================================================= AD (fake)
def test_filetime_and_generalized_time():
    dt = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
    assert filetime_to_dt(dt_to_filetime(dt)) == dt
    assert filetime_to_dt(0) is None and filetime_to_dt(0x7FFFFFFFFFFFFFFF) is None
    assert generalized_to_dt("20250101093000.0Z") == datetime(2025, 1, 1, 9, 30, tzinfo=UTC)


class FakeLdap:
    """Records calls; answers like Active Directory for the queries the driver makes."""

    def __init__(self):
        import ldap

        self.ldap = ldap
        self.mods = []
        self.searches = []
        self.uac = 512
        self.group_member_present = True
        self.range_chunks = None
        self.raise_on_delete = None

    def search_s(self, base, scope, flt, attrs):
        self.searches.append((base, flt, attrs))
        if "sAMAccountName=" in flt:
            return [(f"CN={flt.split('sAMAccountName=')[1].rstrip(')')},OU=Users,DC=acme,DC=com", {}), (None, [])]
        if attrs == ["userAccountControl"]:
            return [(base, {"userAccountControl": [str(self.uac).encode()]})]
        if attrs == ["lastLogonTimestamp"]:
            return [(base, {"lastLogonTimestamp": [str(dt_to_filetime(datetime(2026, 1, 1, tzinfo=UTC))).encode()]})]
        if attrs and attrs[0].startswith("member;range="):
            return [(base, self.range_chunks.pop(0))]
        if attrs == ["sAMAccountName"]:
            return [(base, {"sAMAccountName": [base.split(",")[0][3:].encode()]})]
        if "(member=" in flt or "memberOf:" in flt:
            return [(base, {})] if self.group_member_present else []
        raise AssertionError(f"unexpected search {base} {flt} {attrs}")

    def modify_s(self, dn, mods):
        if self.raise_on_delete and mods[0][0] == self.ldap.MOD_DELETE:
            raise self.raise_on_delete
        self.mods.append((dn, mods))

    def search_ext(self, base, scope, flt, attrs, serverctrls):
        self.searches.append((base, flt, attrs))
        return 1

    def result3(self, msgid):
        old = str(dt_to_filetime(datetime(2026, 1, 1, tzinfo=UTC))).encode()
        data = [("CN=old,OU=Users,DC=acme,DC=com", {"sAMAccountName": [b"old"], "lastLogonTimestamp": [old]}),
                ("CN=never,OU=Users,DC=acme,DC=com",
                 {"sAMAccountName": [b"never"], "whenCreated": [b"20240101000000.0Z"]}),
                ("CN=krbtgt,CN=Users,DC=acme,DC=com", {"sAMAccountName": [b"krbtgt"]}),
                (None, ["ldap://other/ref"])]
        return 101, data, msgid, []

    def unbind_s(self):
        pass


def ad(fake: FakeLdap) -> AdProvider:
    return AdProvider(url="ldaps://dc1.acme.com", bind_dn="CN=svc-oplia,OU=Svc,DC=acme,DC=com",
                      base_dn="DC=acme,DC=com", secrets=SECRETS, conn_factory=lambda: fake)


GROUP_DN = "CN=Platform Admins,OU=Groups,DC=acme,DC=com"


def test_ad_add_remove_uses_member_attribute():
    import ldap

    f = FakeLdap()
    ad(f).add_member(GROUP_DN, "alice")
    ad(f).remove_member(GROUP_DN, "alice")
    assert f.mods == [(GROUP_DN, [(ldap.MOD_ADD, "member", [b"CN=alice,OU=Users,DC=acme,DC=com"])]),
                      (GROUP_DN, [(ldap.MOD_DELETE, "member", [b"CN=alice,OU=Users,DC=acme,DC=com"])])]
    f.raise_on_delete = ldap.NO_SUCH_ATTRIBUTE({"desc": "No such attribute"})
    ad(f).remove_member(GROUP_DN, "alice")  # not a member: success
    f.raise_on_delete = ldap.UNWILLING_TO_PERFORM({"desc": "Server is unwilling to perform"})
    with pytest.raises(ldap.UNWILLING_TO_PERFORM):
        ad(f).remove_member(GROUP_DN, "alice")  # still present -> real error
    f.group_member_present = False
    ad(f).remove_member(GROUP_DN, "alice")  # verifiably absent -> success


def test_ad_transitive_access_check_and_filter_escaping():
    f = FakeLdap()
    assert ad(f).has_access(GROUP_DN, "alice") is True
    base, flt, _ = f.searches[-1]
    assert base == "CN=alice,OU=Users,DC=acme,DC=com"
    assert flt == f"(memberOf:1.2.840.113556.1.4.1941:={GROUP_DN})"
    with pytest.raises(ValueError):
        ad(f).has_access(GROUP_DN, "alice)(objectClass=*")


def test_ad_inactive_sweep_query_and_parsing():
    f = FakeLdap()
    cutoff = datetime(2026, 8, 21, tzinfo=UTC)
    users = ad(f).list_inactive_users(cutoff)
    assert [u.user_id for u in users] == ["old", "never"]  # krbtgt skipped, referral skipped
    assert users[0].last_login == datetime(2026, 1, 1, tzinfo=UTC) and users[1].created.year == 2024
    _, flt, _ = f.searches[-1]
    assert "(!(userAccountControl:1.2.840.113556.1.4.803:=2))" in flt
    assert f"(lastLogonTimestamp<={dt_to_filetime(cutoff)})" in flt
    assert "(whenCreated<=20260821000000.0Z)" in flt and "(!(isCriticalSystemObject=TRUE))" in flt


def test_ad_disable_sets_accountdisable_bit():
    import ldap

    f = FakeLdap()
    ad(f).disable_user("old")
    assert f.mods == [("CN=old,OU=Users,DC=acme,DC=com",
                       [(ldap.MOD_REPLACE, "userAccountControl", [str(512 | UF_ACCOUNTDISABLE).encode()])])]
    f.mods.clear()
    f.uac = 514
    ad(f).disable_user("old")
    assert f.mods == []  # already disabled
    assert ad(f).last_login("old") == datetime(2026, 1, 1, tzinfo=UTC)


def test_ad_range_retrieval_for_large_groups():
    f = FakeLdap()
    f.range_chunks = [{"member;range=0-1": [b"CN=u1,OU=Users,DC=acme,DC=com", b"CN=u2,OU=Users,DC=acme,DC=com"]},
                      {"member;range=2-*": [b"CN=u3,OU=Users,DC=acme,DC=com"]}]
    assert ad(f).list_members(GROUP_DN) == ["u1", "u2", "u3"]
    requested = [a[0] for _, _, a in f.searches if a and a[0].startswith("member;")]
    assert requested == ["member;range=0-*", "member;range=2-*"]


def test_ad_refuses_plaintext_bind():
    with pytest.raises(ValueError, match="plaintext"):
        AdProvider(url="ldap://dc1.acme.com", bind_dn="CN=a,DC=acme,DC=com", base_dn="DC=acme,DC=com",
                   secrets=SECRETS)


# =============================================== AD driver vs a real OpenLDAP
LDAP_URL = os.environ.get("OPLIA_TEST_LDAP_URL", "")
needs_slapd = pytest.mark.skipif(not LDAP_URL, reason="set OPLIA_TEST_LDAP_URL (scripts/test-slapd.sh)")
SLAPD_GROUP = "cn=platform-admins,ou=groups,dc=oplia,dc=test"


def slapd(ca: str | None = None, pw: str | None = None, page_size: int = 500) -> AdProvider:
    return AdProvider(url=LDAP_URL, bind_dn="cn=admin,dc=oplia,dc=test", base_dn="dc=oplia,dc=test",
                      secrets=StaticSecretProvider({"ad_bind_password": pw or os.environ["OPLIA_TEST_LDAP_PW"]}),
                      ca_cert_file=ca or os.environ["OPLIA_TEST_LDAP_CA"], active_directory=False,
                      user_filter="(objectClass=inetOrgPerson)", login_attr="uid", page_size=page_size)


@needs_slapd
def test_real_ldap_grant_verify_revoke():
    p = slapd()
    assert p.has_access(SLAPD_GROUP, "alice") is False
    p.add_member(SLAPD_GROUP, "alice")
    p.add_member(SLAPD_GROUP, "alice")  # idempotent against a real server
    assert p.has_access(SLAPD_GROUP, "alice") is True
    assert sorted(p.list_members(SLAPD_GROUP)) == ["alice", "bob"]
    p.remove_member(SLAPD_GROUP, "alice")
    p.remove_member(SLAPD_GROUP, "alice")  # idempotent
    assert p.has_access(SLAPD_GROUP, "alice") is False
    assert p.list_members(SLAPD_GROUP) == ["bob"]
    with pytest.raises(IdentityProviderError, match="exactly one"):
        p.add_member(SLAPD_GROUP, "mallory")


@needs_slapd
def test_real_ldap_paged_search():
    p = slapd(page_size=1)
    got = p._with(lambda c: [dn for dn, _ in p._paged(c, "dc=oplia,dc=test", "(objectClass=inetOrgPerson)",
                                                      ["uid"])])
    assert sorted(got) == ["uid=alice,ou=people,dc=oplia,dc=test", "uid=bob,ou=people,dc=oplia,dc=test"]


@needs_slapd
def test_real_ldap_rejects_bad_password_and_untrusted_certificate(tmp_path):
    import subprocess

    import ldap

    with pytest.raises(ldap.INVALID_CREDENTIALS):
        slapd(pw="wrong-password").has_access(SLAPD_GROUP, "bob")
    other_ca = tmp_path / "other.crt"
    argv = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=x",
            "-keyout", str(tmp_path / "k"), "-out", str(other_ca)]
    subprocess.run(argv, check=True, capture_output=True)  # noqa: S603 - fixed argv, test-only certificate
    with pytest.raises(ldap.SERVER_DOWN):
        slapd(ca=str(other_ca)).has_access(SLAPD_GROUP, "bob")


# ================================================================ JIT service
class FakeIdp:
    name = "entra"

    def __init__(self):
        self.members: dict[str, set[str]] = {GROUP: set()}
        self.fail_remove = 0
        self.lie_on_check = False
        self.inactive: list[IdpUser] = []
        self.last: dict[str, datetime | None] = {}
        self.disabled: list[str] = []

    def validate_user_id(self, u):
        if not u.startswith("u-"):
            raise ValueError("bad user id")
        return u

    def validate_group_ref(self, g):
        return g

    def add_member(self, g, u):
        self.members.setdefault(g, set()).add(u)

    def remove_member(self, g, u):
        if self.fail_remove:
            self.fail_remove -= 1
            raise RuntimeError("graph 503")
        self.members.get(g, set()).discard(u)

    def has_access(self, g, u):
        return False if self.lie_on_check else u in self.members.get(g, set())

    def list_members(self, g):
        return sorted(self.members.get(g, set()))

    def list_inactive_users(self, cutoff):
        return list(self.inactive)

    def last_login(self, u):
        return self.last.get(u)

    def disable_user(self, u):
        if u == "u-broken":
            raise RuntimeError("403")
        self.disabled.append(u)


ROLE = RoleSpec(role="platform-admin", description="Platform administrators", idp="entra", group_ref=GROUP,
                max_minutes=240, target_cloud_accounts=["aws-prod-123", "azure-prod"])


@pytest.fixture
def idp():
    return FakeIdp()


@pytest.fixture
def jit(gate, session_factory, idp, clock):
    return JitService(gate=gate, session_factory=session_factory, providers={"entra": idp},
                      catalog={"platform-admin": ROLE}, notifier=FakeNotifier(), clock=clock)


def req(jit, **kw):
    base = {"requester": "carol", "user_id": "u-carol", "requested_role": "platform-admin",
            "target_cloud_account": "aws-prod-123", "expiration_minutes": 60,
            "justification": "INC-4711 production hotfix"}
    return jit.request(**{**base, **kw})


@pytest.mark.parametrize(("kw", "msg"), [
    ({"requested_role": "root"}, "unknown role"),
    ({"target_cloud_account": "gcp-x"}, "not available"),
    ({"expiration_minutes": 241}, "1..240"),
    ({"justification": "because"}, "10..1000"),
    ({"user_id": "carol@acme"}, "bad user id"),
])
def test_jit_request_validation(jit, kw, msg):
    with pytest.raises((JitRequestError, ValueError), match=msg):
        req(jit, **kw)


def test_jit_full_lifecycle(jit, gate, idp, clock):
    r = req(jit)
    assert r["approval_status"] == "PENDING" and r["access_status"] == "NONE"
    assert gate.get(r["proposal_id"]).action_type == ACTION_JIT_GRANT
    with pytest.raises(JitConflictError):
        req(jit)  # one open request per user and access
    with pytest.raises(FourEyesViolationError):
        jit.approve(r["id"], "carol")  # requester cannot approve own request
    done = jit.approve(r["id"], "dave")
    assert done["approval_status"] == "APPROVED" and done["access_status"] == "ACTIVE"
    assert done["expires_at"] == (clock.now + timedelta(minutes=60)).isoformat()
    assert "u-carol" in idp.members[GROUP]

    clock.advance(minutes=59)
    assert jit.tick()["revoked"] == 0 and "u-carol" in idp.members[GROUP]
    clock.advance(minutes=1)
    assert jit.tick()["revoked"] == 1
    assert "u-carol" not in idp.members[GROUP]
    final = jit.get(r["id"])
    assert final["access_status"] == "REVOKED" and final["revoked_by"] == "jit-worker"
    assert gate.verify_audit_chain()
    assert jit.tick()["revoked"] == 0  # nothing left


def test_jit_revocation_retries_and_alerts(jit, idp, clock):
    r = req(jit)
    jit.approve(r["id"], "dave")
    clock.advance(minutes=61)
    idp.fail_remove = 4
    for _ in range(3):
        assert jit.tick()["failed"] == 1
    row = jit.get(r["id"])
    assert row["access_status"] == "ACTIVE" and row["revoke_attempts"] == 3 and "503" in row["last_error"]
    alerts = jit._notifier.sent
    assert len(alerts) == 1 and alerts[0][0].severity == "critical"
    assert jit.tick()["failed"] == 1 and len(jit._notifier.sent) == 1  # alerted once, still retrying
    assert jit.tick()["revoked"] == 1


def test_jit_unverifiable_grant_is_undone(jit, idp):
    r = req(jit)
    idp.lie_on_check = True
    done = jit.approve(r["id"], "dave")
    assert done["access_status"] == "GRANT_FAILED" and "did not report" in done["last_error"]
    assert idp.members[GROUP] == set()  # rolled back, no standing access left behind


def test_jit_dry_run_grants_nothing(session_factory, idp, clock):
    g = SafetyGate(session_factory, dry_run=True, require_approval=True, four_eyes=True, clock=clock)
    svc = JitService(gate=g, session_factory=session_factory, providers={"entra": idp},
                     catalog={"platform-admin": ROLE}, clock=clock)
    r = req(svc)
    assert svc.approve(r["id"], "dave")["access_status"] == "DRY_RUN"
    assert idp.members[GROUP] == set()


def test_jit_kill_switch_then_retry(jit, gate, idp):
    r = req(jit)
    gate.set_kill_switch(engaged=True, actor="sec", reason="incident")
    with pytest.raises(KillSwitchEngagedError):
        jit.approve(r["id"], "dave")
    assert jit.get(r["id"])["approval_status"] == "APPROVED" and idp.members[GROUP] == set()
    gate.set_kill_switch(engaged=False, actor="sec", reason="over")
    assert jit.execute_approved(r["id"], "dave")["access_status"] == "ACTIVE"


def test_jit_reject_expire_and_generic_approval(jit, gate, clock):
    r1 = req(jit)
    assert jit.reject(r1["id"], "dave", "no")["approval_status"] == "REJECTED"
    r2 = req(jit)
    clock.advance(minutes=61)
    assert jit.tick()["pending_expired"] == 1 and jit.get(r2["id"])["approval_status"] == "EXPIRED"
    r3 = req(jit)
    gate.approve(r3["proposal_id"], "dave")  # through /proposals, not /jit
    assert jit.get(r3["id"])["approval_status"] == "APPROVED"
    assert jit.execute_approved(r3["id"], "dave")["access_status"] == "ACTIVE"


def test_jit_early_revoke_and_superseded(jit, idp, clock, session_factory):
    r = req(jit)
    jit.approve(r["id"], "dave")
    assert jit.revoke_now(r["id"], "carol")["access_status"] == "REVOKED"
    assert "u-carol" not in idp.members[GROUP]
    with pytest.raises(JitConflictError):
        jit.revoke_now(r["id"], "carol")
    # two active grants for the same membership (e.g. created before the duplicate check) -> keep it
    from oplia_ctl.db import session_scope
    from oplia_ctl.identity.models import JitRequestRow

    a = req(jit)
    jit.approve(a["id"], "dave")
    with session_scope(session_factory) as s:
        s.add(JitRequestRow(id="other", user_id="u-carol", requested_role="platform-admin",
                            target_cloud_account="azure-prod", expiration_minutes=120, approval_status="APPROVED",
                            idp="entra", group_ref=GROUP, justification="parallel grant", requested_by="x",
                            access_status="ACTIVE", created_at=clock.now, granted_at=clock.now,
                            expires_at=clock.now + timedelta(minutes=120), revoke_attempts=0, alerted=0))
    clock.advance(minutes=61)
    assert jit.tick()["superseded"] == 1 and "u-carol" in idp.members[GROUP]
    clock.advance(minutes=60)
    assert jit.tick()["revoked"] == 1 and "u-carol" not in idp.members[GROUP]


def test_jit_reconcile_standing_access(jit, idp):
    idp.members[GROUP] = {"u-standing", "u-breakglass"}
    r = req(jit)
    jit.approve(r["id"], "dave")
    out = jit.reconcile({f"entra:{GROUP}": ["u-breakglass"]})
    assert [f["user_id"] for f in out["standing"]] == ["u-standing"]
    assert "u-standing" in idp.members[GROUP]  # report only by default
    out = jit.reconcile({f"entra:{GROUP}": ["u-breakglass"]}, remove=True)
    assert out["standing"][0]["removed"] is True and "u-standing" not in idp.members[GROUP]
    assert idp.members[GROUP] == {"u-breakglass", "u-carol"}


def test_load_catalog_validates(tmp_path, idp):
    p = tmp_path / "roles.json"
    p.write_text(json.dumps([ROLE.model_dump(), ROLE.model_dump()]))
    with pytest.raises(ValueError, match="duplicate"):
        load_catalog(str(p), {"entra": idp})
    p.write_text(json.dumps([{**ROLE.model_dump(), "idp": "okta"}]))
    with pytest.raises(ValueError, match="not configured"):
        load_catalog(str(p), {"entra": idp})
    p.write_text(json.dumps([ROLE.model_dump()]))
    assert list(load_catalog(str(p), {"entra": idp})) == ["platform-admin"]


# ====================================================================== sweep
def iu(uid, days_ago, now, **kw):
    return IdpUser("entra", uid, uid + "@acme", now - timedelta(days=days_ago), None, **kw)


def test_sweep_proposes_and_executor_rechecks(gate, idp, clock):
    now = clock.now
    idp.inactive = [iu("u-old", 120, now), iu("u-breakglass", 400, now), iu("u-synced", 200, now,
                                                                             exclude_reason="synced from AD")]
    sw = InactivitySweeper(gate=gate, providers={"entra": idp}, exempt={"entra": ["U-BREAKGLASS"]}, clock=clock)
    rep = sw.run()
    e = rep.per_idp["entra"]
    assert (e["inactive"], e["exempt"], e["targets"], e["outcome"]) == (3, 1, 1, "proposed")
    p = gate.get(e["proposal_id"])
    assert p.action_type == ACTION_DISABLE_INACTIVE and [u["user_id"] for u in p.payload["users"]] == ["u-old"]
    assert p.expires_at - p.created_at == timedelta(hours=24)
    assert sw.run().per_idp["entra"]["proposal_id"] == p.id  # same day, same set: idempotent

    gate.approve(p.id, "dave")
    idp.last["u-old"] = None
    done = gate.execute(p.id, DisableInactiveExecutor({"entra": idp}, inactive_days=90, clock=clock), "dave")
    assert done.status is ProposalStatus.EXECUTED and idp.disabled == ["u-old"]


def test_sweep_skips_users_who_signed_in_since(idp, clock):
    idp.last = {"u-a": clock.now - timedelta(days=1), "u-b": None}
    out = DisableInactiveExecutor({"entra": idp}, inactive_days=90, clock=clock)(
        {"idp": "entra", "users": [{"user_id": "u-a"}, {"user_id": "u-b"}, {"user_id": "u-broken"}]})
    assert out["results"]["u-a"].startswith("skipped") and out["results"]["u-b"] == "disabled"
    assert out["results"]["u-broken"].startswith("error") and out["disabled"] == 1
    with pytest.raises(RuntimeError, match="all 1 disable calls failed"):
        DisableInactiveExecutor({"entra": idp}, inactive_days=90, clock=clock)(
            {"idp": "entra", "users": [{"user_id": "u-broken"}]})


def test_sweep_circuit_breaker(gate, idp, clock):
    idp.inactive = [iu(f"u-{i}", 100, clock.now) for i in range(30)]
    n = FakeNotifier()
    rep = InactivitySweeper(gate=gate, providers={"entra": idp}, max_per_run=25, notifier=n, clock=clock).run()
    assert "circuit breaker" in rep.per_idp["entra"]["outcome"] and gate.list() == []
    assert n.sent[0][0].severity == "error"


def test_sweep_auto_execute_without_approval(session_factory, idp, clock):
    g = SafetyGate(session_factory, dry_run=False, require_approval=False, four_eyes=True, clock=clock)
    idp.inactive = [iu("u-old", 120, clock.now)]
    rep = InactivitySweeper(gate=g, providers={"entra": idp}, clock=clock).run()
    assert rep.per_idp["entra"]["outcome"] == "EXECUTED" and idp.disabled == ["u-old"]


def test_sweep_provider_error_is_reported(gate, clock):
    class Down(FakeIdp):
        def list_inactive_users(self, cutoff):
            raise RuntimeError("403 AuditLog.Read.All missing")

    rep = InactivitySweeper(gate=gate, providers={"entra": Down()}, clock=clock).run()
    assert rep.errors == ["entra: RuntimeError: 403 AuditLog.Read.All missing"]


# ======================================================================== API
@pytest.fixture
def api(gate, jit):
    app = create_app(
        gate=gate, secrets=StaticSecretProvider({}),
        verifier=OIDCVerifier(issuer=ISS, audience=AUD, jwks_url="", key_resolver=lambda _t: KEY.public_key()),
        executors={}, webhook_secret_name="w", webhook_max_skew_seconds=300, allowed_blueprints=[],
        approver_role="oplia-approver", operator_role="oplia-operator", jit=jit)
    return TestClient(app)


BODY = {"user_id": "u-carol", "requested_role": "platform-admin", "target_cloud_account": "aws-prod-123",
        "expiration_minutes": 30, "justification": "INC-4711 production hotfix"}


def test_api_jit_flow(api, idp):
    op, ap = bearer("carol", "oplia-operator"), bearer("dave", "oplia-approver")
    other = bearer("erin", "oplia-operator")
    assert api.post("/jit/requests", json=BODY).status_code == 401
    assert api.get("/jit/roles", headers=op).json()[0]["role"] == "platform-admin"
    r = api.post("/jit/requests", json=BODY, headers=op)
    assert r.status_code == 201, r.text
    rid = r.json()["id"]
    assert api.post("/jit/requests", json=BODY, headers=op).status_code == 409
    assert api.post("/jit/requests", json={**BODY, "user_id": "u-x", "requested_role": "root"},
                    headers=op).status_code == 422
    assert api.post(f"/jit/requests/{rid}/approve", json={}, headers=op).status_code == 403  # not an approver
    got = api.post(f"/jit/requests/{rid}/approve", json={"note": "ok"}, headers=ap)
    assert got.status_code == 200 and got.json()["access_status"] == "ACTIVE"
    assert api.get("/jit/requests?access_status=ACTIVE", headers=op).json()[0]["id"] == rid
    assert api.post(f"/jit/requests/{rid}/revoke", headers=other).status_code == 403  # neither approver nor requester
    rv = api.post(f"/jit/requests/{rid}/revoke", headers=op)
    assert rv.status_code == 200 and rv.json()["access_status"] == "REVOKED"
    assert "u-carol" not in idp.members[GROUP]
    assert api.get("/jit/requests/nope", headers=op).status_code == 404
    assert api.get("/jit/requests?approval_status=MAYBE", headers=op).status_code == 400


def test_api_jit_self_approval_forbidden(api):
    ap = bearer("dave", "oplia-approver")
    rid = api.post("/jit/requests", json=BODY, headers=ap).json()["id"]
    assert api.post(f"/jit/requests/{rid}/approve", json={}, headers=ap).status_code == 403


def test_api_jit_not_configured(gate):
    app = create_app(
        gate=gate, secrets=StaticSecretProvider({}),
        verifier=OIDCVerifier(issuer=ISS, audience=AUD, jwks_url="", key_resolver=lambda _t: KEY.public_key()),
        executors={}, webhook_secret_name="w", webhook_max_skew_seconds=300, allowed_blueprints=[],
        approver_role="oplia-approver", operator_role="oplia-operator")
    assert TestClient(app).get("/jit/roles", headers=bearer("x", "oplia-operator")).status_code == 503
