"""Local development login (OIDC authorization code + PKCE) for the admin console.

**Development only.** It exists so the console and the API can be tried on a laptop without an
Entra ID / Okta tenant. It refuses to start unless ``OPLIA_ENVIRONMENT=dev``, listens on
127.0.0.1 only, signs with an RSA key generated in memory at start-up (tokens die with the
process), and production API start-up refuses any ``http://`` issuer, so it cannot be used there.

* ``/.well-known/openid-configuration``, ``/jwks``
* ``GET /authorize`` shows the configured test users; ``POST /authorize`` issues a one-time code
  (60 s, bound to client, redirect URI and S256 code challenge) and redirects back.
* ``POST /token`` exchanges the code + ``code_verifier`` for an access token (audience = the API)
  and an ID token (with the ``nonce``).

Users come from ``OPLIA_DEV_IDP_USERS`` (JSON ``{"alice": ["oplia-approver"], ...}``); the defaults
cover approver-only, operator-only, both, and no role.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import secrets
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Any
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_USERS = {
    "alice": ["oplia-approver"],
    "bob": ["oplia-operator"],
    "carol": ["oplia-approver", "oplia-operator"],
    "dave": [],
}
CODE_TTL = 60.0
TOKEN_TTL = 3600


class DevIdpSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPLIA_DEV_IDP_", extra="ignore")

    port: int = Field(default=8090, ge=1024, le=65535)
    issuer: str = ""                              # default http://127.0.0.1:<port>
    audience: str = "oplia-api"                   # must equal the API's OPLIA_OIDC_AUDIENCE
    client_id: str = "oplia-console"
    redirect_uris: list[str] = ["http://localhost:8080/", "http://localhost:5173/",
                                "http://127.0.0.1:8080/", "http://127.0.0.1:5173/"]
    users: dict[str, list[str]] = Field(default_factory=lambda: dict(DEFAULT_USERS))
    roles_claim: str = "roles"


@dataclass
class _Code:
    user: str
    client_id: str
    redirect_uri: str
    challenge: str
    nonce: str | None
    expires: float


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _origin(url: str) -> str:
    u = urlsplit(url)
    return f"{u.scheme}://{u.netloc}"


def create_idp(cfg: DevIdpSettings, *, clock: Callable[[], float] = time.time) -> FastAPI:
    issuer = (cfg.issuer or f"http://127.0.0.1:{cfg.port}").rstrip("/")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = uuid.uuid4().hex[:16]
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    codes: dict[str, _Code] = {}
    lock = threading.Lock()

    app = FastAPI(title="OPLIA dev login (development only)", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(CORSMiddleware, allow_origins=sorted({_origin(u) for u in cfg.redirect_uris}),
                       allow_methods=["GET", "POST"], allow_headers=["Content-Type"])

    def _check_client(client_id: str, redirect_uri: str) -> None:
        if client_id != cfg.client_id:
            raise HTTPException(400, "unknown client_id")
        if redirect_uri not in cfg.redirect_uris:
            raise HTTPException(400, "redirect_uri is not registered")

    @app.get("/.well-known/openid-configuration")
    def discovery() -> dict[str, Any]:
        return {"issuer": issuer + "/", "authorization_endpoint": f"{issuer}/authorize",
                "token_endpoint": f"{issuer}/token", "jwks_uri": f"{issuer}/jwks",
                "response_types_supported": ["code"], "grant_types_supported": ["authorization_code"],
                "code_challenge_methods_supported": ["S256"], "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "token_endpoint_auth_methods_supported": ["none"], "scopes_supported": ["openid", "profile"]}

    @app.get("/jwks")
    def jwks() -> dict[str, Any]:
        return {"keys": [jwk]}

    @app.get("/authorize", response_class=HTMLResponse)
    def authorize_page(
        response_type: Annotated[str, Query()], client_id: Annotated[str, Query()],
        redirect_uri: Annotated[str, Query()], code_challenge: Annotated[str, Query()],
        code_challenge_method: Annotated[str, Query()], state: Annotated[str, Query(max_length=512)],
        nonce: Annotated[str | None, Query(max_length=512)] = None,
        scope: Annotated[str, Query()] = "openid",
    ) -> str:
        _check_client(client_id, redirect_uri)
        if response_type != "code" or code_challenge_method != "S256" or not 43 <= len(code_challenge) <= 128:
            raise HTTPException(400, "only response_type=code with an S256 code_challenge is supported")
        hidden = {"client_id": client_id, "redirect_uri": redirect_uri, "code_challenge": code_challenge,
                  "state": state, "nonce": nonce or ""}
        fields = "".join(f'<input type="hidden" name="{k}" value="{html.escape(v, quote=True)}">'
                         for k, v in hidden.items())
        buttons = "".join(
            f'<button name="user" value="{html.escape(u, quote=True)}">{html.escape(u)}'
            f'<small>{html.escape(", ".join(r) or "no role")}</small></button>' for u, r in cfg.users.items())
        return ("<!doctype html><html lang=en><meta charset=utf-8><title>OPLIA dev login</title>"
                "<style>body{font:15px system-ui;max-width:28rem;margin:4rem auto;padding:0 1rem}"
                "button{display:flex;justify-content:space-between;width:100%;padding:.7rem 1rem;"
                "margin:.4rem 0;font:inherit;cursor:pointer}small{opacity:.7}"
                "p{background:#fff4ce;padding:.6rem;border-radius:4px}</style>"
                "<h1>OPLIA dev login</h1><p>Development only - not a real identity provider.</p>"
                f'<form method="post" action="{issuer}/authorize">{fields}{buttons}</form></html>')

    @app.post("/authorize")
    async def authorize_submit(request: Request) -> Response:
        # forms are parsed here (FastAPI's Form would need python-multipart)
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode(), keep_blank_values=True).items()}
        client_id, redirect_uri = form.get("client_id", ""), form.get("redirect_uri", "")
        _check_client(client_id, redirect_uri)
        user = form.get("user", "")
        if user not in cfg.users:
            raise HTTPException(400, "unknown user")
        challenge = form.get("code_challenge", "")
        if not 43 <= len(challenge) <= 128:
            raise HTTPException(400, "invalid code_challenge")
        code = secrets.token_urlsafe(32)
        with lock:
            now = clock()
            for c in [c for c, v in codes.items() if v.expires < now]:
                del codes[c]
            codes[code] = _Code(user, client_id, redirect_uri, challenge, form.get("nonce") or None,
                                now + CODE_TTL)
        sep = "&" if "?" in redirect_uri else "?"
        return RedirectResponse(f"{redirect_uri}{sep}{urlencode({'code': code, 'state': form.get('state', '')})}",
                                status_code=303)

    @app.post("/token")
    async def token(request: Request) -> JSONResponse:
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}

        def err(error: str) -> JSONResponse:
            return JSONResponse({"error": error}, status_code=400, headers={"Cache-Control": "no-store"})

        if form.get("grant_type") != "authorization_code":
            return err("unsupported_grant_type")
        with lock:
            entry = codes.pop(form.get("code", ""), None)  # one-time: removed even if the checks below fail
        if entry is None or entry.expires < clock():
            return err("invalid_grant")
        if form.get("client_id") != entry.client_id or form.get("redirect_uri") != entry.redirect_uri:
            return err("invalid_grant")
        verifier = form.get("code_verifier", "")
        if not 43 <= len(verifier) <= 128 or _b64url(hashlib.sha256(verifier.encode()).digest()) != entry.challenge:
            return err("invalid_grant")
        now = int(clock())
        common = {"iss": issuer + "/", "sub": entry.user, "iat": now, "exp": now + TOKEN_TTL,
                  "name": entry.user, cfg.roles_claim: cfg.users[entry.user]}
        access = jwt.encode({**common, "aud": cfg.audience, "scope": "openid profile"}, key,
                            algorithm="RS256", headers={"kid": kid})
        id_claims = {**common, "aud": entry.client_id}
        if entry.nonce:
            id_claims["nonce"] = entry.nonce
        id_token = jwt.encode(id_claims, key, algorithm="RS256", headers={"kid": kid})
        return JSONResponse({"access_token": access, "id_token": id_token, "token_type": "Bearer",  # nosec B105 - OAuth token type, not a password
                             "expires_in": TOKEN_TTL, "scope": "openid profile"},
                            headers={"Cache-Control": "no-store", "Pragma": "no-cache"})

    return app


def main() -> None:  # pragma: no cover - process wiring
    import os

    import uvicorn

    if os.environ.get("OPLIA_ENVIRONMENT", "") != "dev":
        raise SystemExit("oplia-dev-idp runs only with OPLIA_ENVIRONMENT=dev (it is a local test login)")
    cfg = DevIdpSettings()
    print(f"OPLIA dev login on http://127.0.0.1:{cfg.port} - users: "
          + ", ".join(f"{u} ({'/'.join(r) or 'no role'})" for u, r in cfg.users.items()))
    uvicorn.run(create_idp(cfg), host="127.0.0.1", port=cfg.port, log_level="info")
