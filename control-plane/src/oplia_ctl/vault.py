"""HashiCorp Vault driver (the document's ``vault_secrets_driver``) and the Vault secret provider.

* **Auth**: AppRole (``role_id`` + ``secret_id`` read from files, for CI runners and daemons) or
  Kubernetes (the pod's service-account token, for workloads). The token is renewed before it
  expires (``renew-self``) and the driver logs in again when renewal is not possible or the token
  was revoked (a 403 triggers exactly one re-login and retry).
* **KV v2**: ``read_kv`` / ``write_kv`` on ``<mount>/data/<path>``. ``VaultSecretProvider`` maps a
  secret *name* to ``secret/data/coc/<name>`` (field ``value``) - the existing OPLIA paths - and
  caches values for a short time.
* **Transit**: encrypt / decrypt, HMAC and HMAC verification (batch), used by the DR circuit
  breaker for incident dumps and forwarded bundles.
* **Database**: dynamic credentials (``database/creds/<role>``) and lease revocation.

Tokens, secret IDs and secret values are never logged and never placed in exception messages.
Only ``https://`` is accepted unless ``allow_insecure_http`` is set (local development only;
refused in production by ``Settings.assert_production_safe``).
"""

from __future__ import annotations

import base64
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote

import httpx
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from oplia_ctl.secrets import SecretNotFoundError, _check_name

_RENEW_MARGIN = 60.0  # seconds before expiry to renew


class VaultError(RuntimeError):
    """Vault rejected a request. Carries the status and Vault's error list, never the token."""

    def __init__(self, method: str, path: str, status: int, errors: list[str]) -> None:
        self.status = status
        self.errors = errors
        super().__init__(f"Vault {method} {path} -> HTTP {status}: {'; '.join(errors)[:300]}")


class VaultSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPLIA_VAULT_", extra="ignore")

    addr: str = ""
    namespace: str = ""                       # Vault Enterprise / HCP namespace (optional)
    ca_cert: str = ""                         # PEM bundle for a private CA
    allow_insecure_http: bool = False
    auth_method: Literal["kubernetes", "approle"] = "kubernetes"
    kubernetes_mount: str = "kubernetes"      # e.g. kubernetes-aws
    kubernetes_role: str = "oplia-control-plane"
    kubernetes_jwt_file: str = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    approle_mount: str = "approle"
    approle_role_id_file: str = ""
    approle_secret_id_file: str = ""
    kv_mount: str = "secret"
    kv_prefix: str = "coc"                    # names resolve to secret/data/coc/<name>
    kv_field: str = "value"
    cache_seconds: float = Field(default=300.0, ge=0, le=3600)
    timeout_seconds: float = Field(default=10.0, gt=0, le=120)


@dataclass
class _Token:
    value: str
    expires_at: float          # monotonic; inf for non-expiring tokens
    renewable: bool


class VaultClient:
    def __init__(self, settings: VaultSettings, *, transport: httpx.BaseTransport | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if not settings.addr:
            raise ValueError("OPLIA_VAULT_ADDR is required")
        if not settings.addr.startswith("https://") and not (
                settings.allow_insecure_http and settings.addr.startswith("http://")):
            raise ValueError("Vault address must use https:// (allow_insecure_http is for local development only)")
        self._s = settings
        verify: Any = settings.ca_cert or True
        self._http = httpx.Client(base_url=settings.addr.rstrip("/"), timeout=settings.timeout_seconds,
                                  verify=verify, transport=transport, follow_redirects=False)
        self._clock = clock
        self._token: _Token | None = None
        self._lock = threading.Lock()

    def close(self) -> None:
        self._http.close()

    # ------------------------------------------------------------------- auth
    def _login_body(self) -> tuple[str, dict[str, str]]:
        s = self._s
        if s.auth_method == "approle":
            if not (s.approle_role_id_file and s.approle_secret_id_file):
                raise ValueError("AppRole needs approle_role_id_file and approle_secret_id_file")
            return (f"/v1/auth/{s.approle_mount}/login",
                    {"role_id": Path(s.approle_role_id_file).read_text(encoding="utf-8").strip(),
                     "secret_id": Path(s.approle_secret_id_file).read_text(encoding="utf-8").strip()})
        return (f"/v1/auth/{s.kubernetes_mount}/login",
                {"role": s.kubernetes_role,
                 "jwt": Path(s.kubernetes_jwt_file).read_text(encoding="utf-8").strip()})

    def _store(self, auth: dict[str, Any]) -> None:
        ttl = float(auth.get("lease_duration") or 0)
        self._token = _Token(str(auth["client_token"]), self._clock() + ttl if ttl > 0 else float("inf"),
                             bool(auth.get("renewable")))

    def login(self) -> None:
        path, body = self._login_body()
        data = self._raw("POST", path, json=body, token=None)
        self._store(data["auth"])

    def _current_token(self) -> str:
        with self._lock:
            tok = self._token
            if tok is None:
                self.login()
            elif tok.expires_at - self._clock() < _RENEW_MARGIN:
                renewed = False
                if tok.renewable:
                    try:
                        data = self._raw("POST", "/v1/auth/token/renew-self", json={}, token=tok.value)
                        auth = data["auth"]
                        # a renewal that cannot extend beyond the margin (max TTL reached) is not enough
                        if float(auth.get("lease_duration") or 0) > _RENEW_MARGIN:
                            self._store(auth)
                            renewed = True
                    except VaultError:
                        renewed = False
                if not renewed:
                    self.login()
            assert self._token is not None  # nosec B101 - set by login()/_store()
            return self._token.value

    # --------------------------------------------------------------- plumbing
    def _raw(self, method: str, path: str, *, json: Any = None, token: str | None,
             params: dict[str, str] | None = None) -> dict[str, Any]:
        headers = {"X-Vault-Request": "true"}
        if token is not None:
            headers["X-Vault-Token"] = token
        if self._s.namespace:
            headers["X-Vault-Namespace"] = self._s.namespace
        resp = self._http.request(method, path, json=json, headers=headers, params=params)
        if resp.status_code == 204:
            return {}
        try:
            body = resp.json()
        except ValueError:
            body = {}
        if resp.status_code >= 400:
            errors = [str(e) for e in body.get("errors", [])] if isinstance(body, dict) else []
            raise VaultError(method, path, resp.status_code, errors)
        return body if isinstance(body, dict) else {}

    def request(self, method: str, path: str, *, json: Any = None,
                params: dict[str, str] | None = None) -> dict[str, Any]:
        try:
            return self._raw(method, path, json=json, token=self._current_token(), params=params)
        except VaultError as exc:
            if exc.status != 403:
                raise
            with self._lock:  # token revoked or expired early: log in once and retry
                self.login()
            return self._raw(method, path, json=json, token=self._current_token(), params=params)

    # ------------------------------------------------------------------- KV v2
    def read_kv(self, path: str, mount: str | None = None) -> dict[str, Any]:
        m = mount or self._s.kv_mount
        data = self.request("GET", f"/v1/{quote(m)}/data/{quote(path.strip('/'))}")
        return dict((data.get("data") or {}).get("data") or {})

    def write_kv(self, path: str, values: dict[str, str], mount: str | None = None,
                 cas: int | None = None) -> int:
        m = mount or self._s.kv_mount
        body: dict[str, Any] = {"data": values}
        if cas is not None:
            body["options"] = {"cas": cas}
        data = self.request("POST", f"/v1/{quote(m)}/data/{quote(path.strip('/'))}", json=body)
        return int((data.get("data") or {}).get("version", 0))

    # ----------------------------------------------------------------- transit
    @staticmethod
    def _b64(data: bytes) -> str:
        return base64.b64encode(data).decode()

    def encrypt(self, mount: str, key: str, plaintext: bytes) -> str:
        data = self.request("POST", f"/v1/{quote(mount)}/encrypt/{quote(key)}",
                            json={"plaintext": self._b64(plaintext)})
        return str(data["data"]["ciphertext"])

    def decrypt(self, mount: str, key: str, ciphertext: str) -> bytes:
        data = self.request("POST", f"/v1/{quote(mount)}/decrypt/{quote(key)}", json={"ciphertext": ciphertext})
        return base64.b64decode(data["data"]["plaintext"])

    def hmac(self, mount: str, key: str, inputs: list[bytes], algorithm: str = "sha2-256") -> list[str]:
        if not inputs:
            return []
        data = self.request("POST", f"/v1/{quote(mount)}/hmac/{quote(key)}/{quote(algorithm)}",
                            json={"batch_input": [{"input": self._b64(i)} for i in inputs]})
        results = data["data"]["batch_results"]
        errors = [r["error"] for r in results if r.get("error")]
        if errors or len(results) != len(inputs):
            raise VaultError("POST", "transit/hmac", 200, errors or ["batch size mismatch"])
        return [str(r["hmac"]) for r in results]

    def verify_hmac(self, mount: str, key: str, data_in: bytes, hmac_value: str,
                    algorithm: str = "sha2-256") -> bool:
        data = self.request("POST", f"/v1/{quote(mount)}/verify/{quote(key)}/{quote(algorithm)}",
                            json={"input": self._b64(data_in), "hmac": hmac_value})
        return bool(data["data"]["valid"])

    # ---------------------------------------------------------------- database
    def database_credentials(self, role: str, mount: str = "database") -> dict[str, Any]:
        data = self.request("GET", f"/v1/{quote(mount)}/creds/{quote(role)}")
        return {"username": data["data"]["username"], "password": data["data"]["password"],
                "lease_id": data.get("lease_id"), "lease_duration": data.get("lease_duration")}

    def revoke_lease(self, lease_id: str) -> None:
        self.request("PUT", "/v1/sys/leases/revoke", json={"lease_id": lease_id})


class VaultSecretProvider:
    """``SecretProvider`` backed by KV v2: ``name`` -> ``<kv_mount>/data/<kv_prefix>/<name>`` field ``value``."""

    def __init__(self, client: VaultClient, settings: VaultSettings,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._c = client
        self._s = settings
        self._clock = clock
        self._cache: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    @property
    def client(self) -> VaultClient:
        return self._c

    @classmethod
    def from_settings(cls) -> VaultSecretProvider:
        s = VaultSettings()
        return cls(VaultClient(s), s)

    def get(self, name: str) -> str:
        _check_name(name)
        now = self._clock()
        with self._lock:
            hit = self._cache.get(name)
            if hit is not None and hit[1] > now:
                return hit[0]
        try:
            values = self._c.read_kv(f"{self._s.kv_prefix}/{name}")
        except VaultError as exc:
            if exc.status == 404:
                raise SecretNotFoundError(name) from None
            raise
        value = values.get(self._s.kv_field)
        if not isinstance(value, str) or not value:
            raise SecretNotFoundError(name)
        with self._lock:
            self._cache[name] = (value, now + self._s.cache_seconds)
        return value

    def invalidate(self, name: str | None = None) -> None:
        with self._lock:
            if name is None:
                self._cache.clear()
            else:
                self._cache.pop(name, None)
