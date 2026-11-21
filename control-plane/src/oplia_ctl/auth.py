"""Authentication.

* Humans (approvers/operators) call the API with an OIDC JWT bearer token issued
  by your identity provider (Entra ID, Okta, IBM w3id, ...). Signature, issuer,
  audience and expiry are all verified; roles come from a configurable claim.
* Machines (drift detectors, Falco/falcosidekick) call webhooks signed with
  HMAC-SHA256 over ``"<unix-timestamp>." + body``; stale timestamps are refused
  to stop replays.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import jwt


class AuthError(Exception):
    """Authentication or authorisation failure. Message is safe to return."""


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: frozenset[str] = field(default_factory=frozenset)

    def has_role(self, role: str) -> bool:
        return role in self.roles


class OIDCVerifier:
    ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384", "PS256")

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_url: str,
        roles_claim: str = "roles",
        key_resolver: Callable[[str], Any] | None = None,
    ) -> None:
        if not (issuer and audience and (jwks_url or key_resolver)):
            raise ValueError("issuer, audience and jwks_url are required")
        self._issuer = issuer
        self._audience = audience
        self._roles_claim = roles_claim
        if key_resolver is not None:
            self._resolve = key_resolver
        else:
            client = jwt.PyJWKClient(jwks_url, cache_keys=True, lifespan=300)
            self._resolve = lambda token: client.get_signing_key_from_jwt(token).key

    def verify(self, token: str) -> Principal:
        try:
            key = self._resolve(token)
            claims = jwt.decode(
                token,
                key=key,
                algorithms=list(self.ALGORITHMS),
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
                leeway=30,
            )
        except jwt.PyJWTError as exc:
            raise AuthError(f"invalid token: {type(exc).__name__}") from None
        raw_roles = claims.get(self._roles_claim, [])
        if isinstance(raw_roles, str):
            raw_roles = [raw_roles]
        if not isinstance(raw_roles, list):
            raw_roles = []
        return Principal(subject=str(claims["sub"]), roles=frozenset(str(r) for r in raw_roles))


SIGNATURE_PREFIX = "sha256="


def sign_webhook(secret: str, timestamp: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return SIGNATURE_PREFIX + mac.hexdigest()


def verify_webhook(
    *,
    secret: str,
    timestamp: str | None,
    signature: str | None,
    body: bytes,
    max_skew_seconds: int,
    now: Callable[[], float] = time.time,
) -> None:
    if not timestamp or not signature:
        raise AuthError("missing signature headers")
    try:
        ts = int(timestamp)
    except ValueError:
        raise AuthError("invalid timestamp") from None
    if abs(now() - ts) > max_skew_seconds:
        raise AuthError("timestamp outside allowed window")
    expected = sign_webhook(secret, timestamp, body)
    if not hmac.compare_digest(expected, signature):
        raise AuthError("signature mismatch")
