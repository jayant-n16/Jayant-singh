from __future__ import annotations

import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from oplia_ctl.auth import AuthError, OIDCVerifier, sign_webhook, verify_webhook
from oplia_ctl.http import HttpError, ResilientClient

ISS, AUD = "https://idp.example.com/", "oplia-api"


@pytest.fixture(scope="module")
def keys():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, other


def _token(priv, **over):
    now = int(time.time())
    claims = {"iss": ISS, "aud": AUD, "sub": "bob", "iat": now, "exp": now + 300, "roles": ["oplia-approver"]}
    claims.update(over)
    return jwt.encode(claims, priv, algorithm="RS256")


def _verifier(priv):
    return OIDCVerifier(issuer=ISS, audience=AUD, jwks_url="", key_resolver=lambda _t: priv.public_key())


def test_valid_token(keys):
    p = _verifier(keys[0]).verify(_token(keys[0]))
    assert p.subject == "bob" and p.has_role("oplia-approver")


@pytest.mark.parametrize("over", [{"aud": "other"}, {"iss": "https://evil/"}, {"exp": int(time.time()) - 120}])
def test_rejects_bad_claims(keys, over):
    with pytest.raises(AuthError):
        _verifier(keys[0]).verify(_token(keys[0], **over))


def test_rejects_wrong_signing_key(keys):
    with pytest.raises(AuthError):
        _verifier(keys[0]).verify(_token(keys[1]))


def test_rejects_alg_none(keys):
    unsigned = jwt.encode({"iss": ISS, "aud": AUD, "sub": "x", "iat": 1, "exp": 2**31}, None, algorithm="none")
    with pytest.raises(AuthError):
        _verifier(keys[0]).verify(unsigned)


def test_string_role_claim(keys):
    p = _verifier(keys[0]).verify(_token(keys[0], roles="oplia-operator"))
    assert p.roles == frozenset({"oplia-operator"})


def test_webhook_signature_roundtrip_and_failures():
    body, ts = b'{"a":1}', str(int(time.time()))
    sig = sign_webhook("s3cret", ts, body)
    verify_webhook(secret="s3cret", timestamp=ts, signature=sig, body=body, max_skew_seconds=300)
    with pytest.raises(AuthError, match="mismatch"):
        verify_webhook(secret="s3cret", timestamp=ts, signature=sig, body=b'{"a":2}', max_skew_seconds=300)
    with pytest.raises(AuthError, match="window"):
        old = str(int(time.time()) - 1000)
        verify_webhook(secret="s3cret", timestamp=old, signature=sign_webhook("s3cret", old, body),
                       body=body, max_skew_seconds=300)
    with pytest.raises(AuthError, match="missing"):
        verify_webhook(secret="s3cret", timestamp=None, signature=sig, body=body, max_skew_seconds=300)


def _client(handler, retries=3):
    return ResilientClient(transport=httpx.MockTransport(handler), max_retries=retries, sleep=lambda _s: None)


def test_post_not_retried_on_503():
    calls = []

    def h(req):
        calls.append(1)
        return httpx.Response(503)

    with pytest.raises(HttpError):
        _client(h).request("POST", "https://x/y")
    assert len(calls) == 1  # a POST that may have been processed must not be replayed


def test_post_retried_on_429_then_succeeds():
    seq = iter([httpx.Response(429, headers={"Retry-After": "1"}), httpx.Response(204)])
    assert _client(lambda r: next(seq)).request("POST", "https://x/y", expected={204}).status_code == 204


def test_get_retried_on_503():
    seq = iter([httpx.Response(503), httpx.Response(502), httpx.Response(200)])
    assert _client(lambda r: next(seq)).request("GET", "https://x/y").status_code == 200


def test_connect_error_retried_for_post_then_raises():
    calls = []

    def h(req):
        calls.append(1)
        raise httpx.ConnectError("refused", request=req)

    with pytest.raises(httpx.ConnectError):
        _client(h, retries=2).request("POST", "https://x/y")
    assert len(calls) == 3
