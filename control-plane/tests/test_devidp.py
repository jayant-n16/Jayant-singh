from __future__ import annotations

import base64
import hashlib
import re
import secrets
import time
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from fastapi.testclient import TestClient

from oplia_ctl.auth import AuthError, OIDCVerifier
from oplia_ctl.config import Settings
from oplia_ctl.devidp import DevIdpSettings, create_idp

REDIRECT = "http://localhost:8080/"


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


@pytest.fixture
def idp():
    now = [time.time()]  # real time: PyJWT checks iat/exp against the wall clock
    app = create_idp(DevIdpSettings(port=8090), clock=lambda: now[0])
    return TestClient(app), now


def verifier_for(client: TestClient) -> OIDCVerifier:
    keys = {k["kid"]: jwt.PyJWK(k).key for k in client.get("/jwks").json()["keys"]}
    return OIDCVerifier(issuer="http://127.0.0.1:8090/", audience="oplia-api", jwks_url="",
                        key_resolver=lambda t: keys[jwt.get_unverified_header(t)["kid"]])


def login(client, user, challenge, *, state="st-1", nonce="n-1", redirect=REDIRECT):
    page = client.get("/authorize", params={"response_type": "code", "client_id": "oplia-console",
                                            "redirect_uri": redirect, "code_challenge": challenge,
                                            "code_challenge_method": "S256", "state": state, "nonce": nonce})
    assert page.status_code == 200, page.text
    assert "Development only" in page.text and f'value="{user}"' in page.text
    r = client.post("/authorize", data={"user": user, "client_id": "oplia-console", "redirect_uri": redirect,
                                        "code_challenge": challenge, "state": state, "nonce": nonce},
                    follow_redirects=False)
    assert r.status_code == 303
    loc = urlsplit(r.headers["location"])
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == redirect
    q = parse_qs(loc.query)
    assert q["state"] == [state]
    return q["code"][0]


def exchange(client, code, verifier, redirect=REDIRECT):
    return client.post("/token", data={"grant_type": "authorization_code", "code": code, "code_verifier": verifier,
                                       "client_id": "oplia-console", "redirect_uri": redirect})


def test_pkce_flow_issues_tokens_the_api_accepts(idp):
    client, _ = idp
    disc = client.get("/.well-known/openid-configuration").json()
    assert disc["issuer"] == "http://127.0.0.1:8090/" and disc["code_challenge_methods_supported"] == ["S256"]
    v, c = pkce()
    r = exchange(client, login(client, "carol", c), v)
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    body = r.json()
    p = verifier_for(client).verify(body["access_token"])
    assert p.subject == "carol" and p.roles == {"oplia-approver", "oplia-operator"}
    idt = jwt.decode(body["id_token"], options={"verify_signature": False})
    assert idt["aud"] == "oplia-console" and idt["nonce"] == "n-1"


def test_code_is_single_use_and_bound_to_verifier_client_and_redirect(idp):
    client, _ = idp
    v, c = pkce()
    code = login(client, "alice", c)
    assert exchange(client, code, "x" * 43).json() == {"error": "invalid_grant"}  # wrong verifier
    assert exchange(client, code, v).status_code == 400                            # the failed try consumed it
    code = login(client, "alice", c)
    assert exchange(client, code, v, redirect="http://localhost:5173/").status_code == 400
    code = login(client, "alice", c)
    assert exchange(client, code, v).status_code == 200
    assert exchange(client, code, v).status_code == 400                            # replay


def test_code_expires(idp):
    client, now = idp
    v, c = pkce()
    code = login(client, "bob", c)
    now[0] += 61
    assert exchange(client, code, v).json() == {"error": "invalid_grant"}


@pytest.mark.parametrize("params,detail", [
    ({"client_id": "other"}, "unknown client_id"),
    ({"redirect_uri": "https://evil.example.com/"}, "not registered"),
    ({"code_challenge_method": "plain"}, "S256"),
])
def test_authorize_rejects_bad_requests(idp, params, detail):
    client, _ = idp
    _, c = pkce()
    base = {"response_type": "code", "client_id": "oplia-console", "redirect_uri": REDIRECT,
            "code_challenge": c, "code_challenge_method": "S256", "state": "s"}
    r = client.get("/authorize", params=base | params)
    assert r.status_code == 400 and detail in r.text


def test_unknown_user_and_html_escaping(idp):
    client, _ = idp
    _, c = pkce()
    r = client.post("/authorize", data={"user": "mallory", "client_id": "oplia-console", "redirect_uri": REDIRECT,
                                        "code_challenge": c, "state": "s"}, follow_redirects=False)
    assert r.status_code == 400
    page = client.get("/authorize", params={"response_type": "code", "client_id": "oplia-console",
                                            "redirect_uri": REDIRECT, "code_challenge": c,
                                            "code_challenge_method": "S256", "state": '"><script>x</script>'})
    assert "<script>x" not in page.text and "&quot;&gt;&lt;script&gt;" in page.text


def test_cors_only_for_registered_origins(idp):
    client, _ = idp
    ok = client.options("/token", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    bad = client.options("/token", headers={"Origin": "https://evil.example.com",
                                            "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in bad.headers


def test_tokens_from_another_key_are_refused(idp):
    client, now = idp
    other = TestClient(create_idp(DevIdpSettings(port=8090), clock=lambda: now[0]))
    v, c = pkce()
    token = exchange(other, login(other, "alice", c), v).json()["access_token"]
    with pytest.raises((AuthError, KeyError)):
        verifier_for(client).verify(token)


def test_production_refuses_http_issuer(monkeypatch):
    monkeypatch.setenv("OPLIA_VAULT_ADDR", "https://vault.example.com:8200")
    s = Settings(environment="prod", database_url="postgresql+psycopg://u@h/db", secret_provider="vault",
                 oidc_issuer="http://127.0.0.1:8090/", oidc_audience="oplia-api",
                 oidc_jwks_url="http://127.0.0.1:8090/jwks")
    with pytest.raises(RuntimeError, match=re.escape("must be https://")):
        s.assert_production_safe()
