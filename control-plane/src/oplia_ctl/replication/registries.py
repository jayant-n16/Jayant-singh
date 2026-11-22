"""Container registry replication: ECR <-> ACR <-> Artifact Registry, copied by digest and verified.

Uses the OCI Distribution API directly (no Docker daemon, no image unpacking):

1. ``RESOLVE``   - GET the manifest for the tag (or digest) at the source. Its digest is computed from
   the exact bytes; when the registry sends ``Docker-Content-Digest`` it must agree. An image index
   (multi-platform) is followed to every child manifest.
2. ``BLOBS``     - for every config and layer blob: HEAD at the target; if missing, stream it from the
   source and upload it (monolithic PUT with ``?digest=``), computing SHA-256 while streaming. A
   mismatch aborts. Done blobs are saved, so a worker restart resumes; each run copies at most
   ``max_blobs_per_run`` blobs.
3. ``MANIFESTS`` - PUT child manifests by digest, then the top manifest by tag, byte-for-byte (so the
   digest is identical at the target).
4. ``VERIFY``    - GET the manifest at the target by tag and by digest and compare the digest.

Authentication per registry kind:

* ``ecr``  - ``ecr:GetAuthorizationToken`` (default AWS credential chain) -> HTTP Basic.
* ``acr``  - Microsoft Entra token (``DefaultAzureCredential``) exchanged at ``/oauth2/exchange``
  for an ACR refresh token, used as the password of the documented all-zero user.
* ``gar``  - Google access token (Application Default Credentials) as the password of user
  ``oauth2accesstoken``.
* ``basic`` - ``user:password`` read from the secret provider (any other OCI registry).

With those credentials a ``401`` carrying a ``Bearer`` challenge is answered at the challenge's
realm (service + scope) for a registry token; a ``Basic`` challenge uses the credentials directly.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Callable, Iterator
from typing import Any, Literal
from urllib.parse import urlencode, urljoin

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

from oplia_ctl.replication.jobs import JobMachine
from oplia_ctl.replication.models import DrJobRow

ACTION_REGISTRY_COPY = "dr.registry_copy"
ACR_USER = "00000000-0000-0000-0000-000000000000"
MANIFEST_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)
INDEX_TYPES = MANIFEST_TYPES[0], MANIFEST_TYPES[2]
_REPO = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$")
_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_LOCAL = ("127.0.0.1", "localhost", "[::1]")


class Registry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["ecr", "acr", "gar", "basic"]
    host: str                                   # e.g. 123456789012.dkr.ecr.eu-west-1.amazonaws.com
    region: str = ""                            # ecr only
    secret: str = ""                            # basic only: secret NAME holding "user:password"
    plain_http: bool = False                    # only allowed for a registry on this host (tests, dev)

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9.-]+(:\d{1,5})?|\[::1\](:\d{1,5})?", v):
            raise ValueError("host must be a registry host name, optionally with :port")
        return v.lower()

    def base(self) -> str:
        if self.plain_http:
            if self.host.rsplit(":", 1)[0] not in _LOCAL:
                raise ValueError("plain_http is only allowed for a registry on localhost")
            return f"http://{self.host}"
        return f"https://{self.host}"


class RegistryPair(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    source: Registry
    source_repo: str
    target: Registry
    target_repo: str
    tag_pattern: str = r"^[A-Za-z0-9_][A-Za-z0-9._-]*$"   # which tags may be copied

    @field_validator("source_repo", "target_repo")
    @classmethod
    def _repo(cls, v: str) -> str:
        if not _REPO.match(v) or len(v) > 255:
            raise ValueError(f"invalid repository name {v!r}")
        return v

    @field_validator("tag_pattern")
    @classmethod
    def _pattern(cls, v: str) -> str:
        re.compile(v)
        return v


class RegistrySettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pairs: list[RegistryPair] = Field(min_length=1)
    max_blobs_per_run: int = Field(default=50, ge=1, le=10000)
    timeout_seconds: float = Field(default=300, ge=5, le=3600)


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class Credentials:
    """Base credentials for a registry (HTTP Basic user/password or ``None`` for anonymous)."""

    def __init__(self, reg: Registry, secrets: Any = None, client: httpx.Client | None = None) -> None:
        self.reg = reg
        self._secrets = secrets
        self._client = client

    def basic(self) -> tuple[str, str] | None:
        r = self.reg
        if r.kind == "ecr":
            import boto3
            tok = boto3.client("ecr", region_name=r.region).get_authorization_token()["authorizationData"][0]
            user, _, pw = base64.b64decode(tok["authorizationToken"]).decode().partition(":")
            return user, pw
        if r.kind == "acr":
            from azure.identity import DefaultAzureCredential
            aad = DefaultAzureCredential().get_token("https://management.azure.com/.default").token
            if self._client is None:
                raise RuntimeError("ACR credentials need an HTTP client")
            resp = self._client.post(f"{r.base()}/oauth2/exchange", data={
                "grant_type": "access_token", "service": r.host, "access_token": aad})
            resp.raise_for_status()
            return ACR_USER, str(resp.json()["refresh_token"])
        if r.kind == "gar":
            import google.auth
            import google.auth.transport.requests
            creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            creds.refresh(google.auth.transport.requests.Request())  # type: ignore[no-untyped-call]
            return "oauth2accesstoken", str(creds.token)
        if not r.secret:
            return None
        user, sep, pw = str(self._secrets.get(r.secret)).partition(":")
        if not sep:
            raise ValueError(f"secret {r.secret!r} must hold user:password")
        return user, pw


class RegistryClient:
    """Minimal OCI Distribution client with challenge-based auth, per repository scope."""

    def __init__(self, reg: Registry, creds: Credentials | Callable[[], tuple[str, str] | None],
                 timeout: float = 300, transport: httpx.BaseTransport | None = None) -> None:
        self.reg = reg
        self.base = reg.base()
        self.http = httpx.Client(timeout=timeout, transport=transport, follow_redirects=False)
        if isinstance(creds, Credentials):
            creds._client = self.http
            self._creds: Callable[[], tuple[str, str] | None] = creds.basic
        else:
            self._creds = creds
        self._basic: tuple[str, str] | None = None
        self._loaded = False
        self._tokens: dict[str, str] = {}
        self._mode: str | None = None          # "bearer" | "basic" once a challenge was seen

    def close(self) -> None:
        self.http.close()

    def _credentials(self) -> tuple[str, str] | None:
        if not self._loaded:
            self._basic, self._loaded = self._creds(), True
        return self._basic

    def _auth_headers(self, scope: str) -> dict[str, str]:
        if self._mode == "basic" and self._credentials():
            u, p = self._credentials()  # type: ignore[misc]
            return {"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()}
        if self._mode == "bearer" and scope in self._tokens:
            return {"Authorization": f"Bearer {self._tokens[scope]}"}
        return {}

    def _challenge(self, header: str, scope: str) -> None:
        scheme, _, params = header.partition(" ")
        if scheme.lower() == "basic":
            if not self._credentials():
                raise PermissionError(f"{self.reg.host}: registry requires credentials")
            self._mode = "basic"
            return
        if scheme.lower() != "bearer":
            raise PermissionError(f"{self.reg.host}: unsupported auth challenge {scheme!r}")
        kv = dict(re.findall(r'(\w+)="([^"]*)"', params))
        realm = kv.get("realm", "")
        if not realm.startswith("https://") and not (self.reg.plain_http and realm.startswith("http://")):
            raise PermissionError(f"{self.reg.host}: refusing token realm {realm!r} (https required)")
        q = {"service": kv.get("service", self.reg.host), "scope": scope}
        creds = self._credentials()
        auth = httpx.BasicAuth(*creds) if creds else None
        r = self.http.get(f"{realm}?{urlencode(q)}", auth=auth)
        if r.status_code != 200:
            raise PermissionError(f"{self.reg.host}: token request failed with HTTP {r.status_code}")
        body = r.json()
        tok = body.get("token") or body.get("access_token")
        if not tok:
            raise PermissionError(f"{self.reg.host}: token response without a token")
        self._mode = "bearer"
        self._tokens[scope] = str(tok)

    def request(self, method: str, url: str, scope: str, **kw: Any) -> httpx.Response:
        full = url if url.startswith("http") else self.base + url
        for _ in range(2):
            headers = {**kw.pop("headers", {}), **self._auth_headers(scope)}
            r = self.http.request(method, full, headers=headers, **kw)
            if r.status_code != 401 or "www-authenticate" not in r.headers:
                return r
            kw["headers"] = {k: v for k, v in headers.items() if k != "Authorization"}
            self._challenge(r.headers["www-authenticate"], scope)
        return r

    def stream(self, url: str, scope: str) -> Any:
        """GET a blob as a stream, answering an auth challenge first if needed."""
        r = self.request("HEAD", url, scope)          # establishes auth; registries answer HEAD on blobs
        if r.status_code == 404:
            raise LookupError(f"{self.reg.host}{url}: not found")
        return self.http.stream("GET", self.base + url, headers=self._auth_headers(scope), follow_redirects=True)

    # ------------------------------------------------------------- operations
    def get_manifest(self, repo: str, ref: str) -> tuple[bytes, str, str]:
        r = self.request("GET", f"/v2/{repo}/manifests/{ref}", f"repository:{repo}:pull",
                         headers={"Accept": ", ".join(MANIFEST_TYPES)})
        if r.status_code == 404:
            raise LookupError(f"{self.reg.host}/{repo}:{ref} not found")
        r.raise_for_status()
        body = r.content
        digest = _sha(body)
        sent = r.headers.get("docker-content-digest")
        if sent and sent != digest:
            raise RuntimeError(f"{self.reg.host}/{repo}@{ref}: manifest digest {digest} != header {sent}")
        if _DIGEST.match(ref) and ref != digest:
            raise RuntimeError(f"{self.reg.host}/{repo}@{ref}: content has digest {digest}")
        ctype = r.headers.get("content-type", "").split(";")[0].strip() or json.loads(body).get("mediaType", "")
        return body, digest, ctype

    def has_blob(self, repo: str, digest: str) -> bool:
        r = self.request("HEAD", f"/v2/{repo}/blobs/{digest}", f"repository:{repo}:pull,push")
        if r.status_code == 404:
            return False
        r.raise_for_status()
        return True

    def put_blob(self, repo: str, digest: str, chunks: Iterator[bytes], size: int) -> None:
        scope = f"repository:{repo}:pull,push"
        r = self.request("POST", f"/v2/{repo}/blobs/uploads/", scope)
        if r.status_code != 202:
            raise RuntimeError(f"{self.reg.host}/{repo}: upload start failed with HTTP {r.status_code}")
        loc = urljoin(self.base + "/", r.headers["location"])
        sep = "&" if "?" in loc else "?"
        r = self.http.put(f"{loc}{sep}digest={digest}", content=chunks,
                          headers={**self._auth_headers(scope), "Content-Type": "application/octet-stream",
                                   "Content-Length": str(size)})
        if r.status_code != 201:
            raise RuntimeError(f"{self.reg.host}/{repo}: upload of {digest} failed with HTTP {r.status_code}: "
                               f"{r.text[:300]}")

    def put_manifest(self, repo: str, ref: str, body: bytes, ctype: str) -> str:
        r = self.request("PUT", f"/v2/{repo}/manifests/{ref}", f"repository:{repo}:pull,push",
                         content=body, headers={"Content-Type": ctype})
        if r.status_code != 201:
            raise RuntimeError(f"{self.reg.host}/{repo}:{ref}: manifest PUT failed with HTTP {r.status_code}: "
                               f"{r.text[:300]}")
        return str(r.headers.get("docker-content-digest", _sha(body)))


def blobs_of(manifest: bytes) -> list[dict[str, Any]]:
    m = json.loads(manifest)
    out = [m["config"]] if "config" in m else []
    out += list(m.get("layers", []))
    for d in out:
        if not _DIGEST.match(str(d.get("digest", ""))):
            raise RuntimeError(f"unsupported blob digest {d.get('digest')!r} (sha256 only)")
    return out


def children_of(manifest: bytes) -> list[str]:
    ds = [str(m["digest"]) for m in json.loads(manifest).get("manifests", [])]
    for d in ds:
        if not _DIGEST.match(d):
            raise RuntimeError(f"unsupported manifest digest {d!r} (sha256 only)")
    return ds


class RegistryReplicator(JobMachine):
    kind = "registry_copy"
    action = ACTION_REGISTRY_COPY
    title = "Container image copy"
    first_step = "RESOLVE"

    def __init__(self, cfg: RegistrySettings, session_factory: Any, secrets: Any = None,
                 client_factory: Callable[[Registry], RegistryClient] | None = None,
                 audit: Callable[[str, dict[str, Any]], None] | None = None, **kw: Any) -> None:
        super().__init__(session_factory, **kw)
        self._audit = audit
        self.cfg = cfg
        self.pairs = {p.name: p for p in cfg.pairs}
        self._secrets = secrets
        self._factory = client_factory or (lambda reg: RegistryClient(reg, Credentials(reg, secrets),
                                                                      timeout=cfg.timeout_seconds))
        self._clients: dict[str, RegistryClient] = {}

    def _client(self, reg: Registry) -> RegistryClient:
        key = reg.model_dump_json()
        if key not in self._clients:
            self._clients[key] = self._factory(reg)
        return self._clients[key]

    # ------------------------------------------------------------- module interface
    def fields(self) -> list[dict[str, Any]]:
        return [
            {"name": "pair", "label": "Registry pair", "kind": "select", "required": True,
             "options": [{"value": p.name, "label": f"{p.name}: {p.source.kind}:{p.source_repo} → "
                                                    f"{p.target.kind}:{p.target_repo}"} for p in self.cfg.pairs]},
            {"name": "ref", "label": "Tag or digest", "kind": "text", "required": True, "maxLength": 128,
             "help": "e.g. v1.4.2 or sha256:…"},
        ]

    def summary(self) -> dict[str, Any]:
        return {"pairs": [f"{p.name}: {p.source.host}/{p.source_repo} → {p.target.host}/{p.target_repo}"
                          for p in self.cfg.pairs]}

    def parse(self, params: dict[str, Any]) -> dict[str, Any]:
        pair, ref = str(params.get("pair", "")), str(params.get("ref", "")).strip()
        p = self.pairs.get(pair)
        if p is None:
            raise ValueError(f"unknown registry pair {pair!r}")
        if _DIGEST.match(ref):
            pass
        elif not _TAG.match(ref) or not re.match(p.tag_pattern, ref):
            raise ValueError(f"tag {ref!r} is not allowed for pair {pair} (pattern {p.tag_pattern})")
        return {"pair": pair, "ref": ref}

    def target_of(self, payload: dict[str, Any]) -> str:
        p = self.pairs[payload["pair"]]
        return f"{p.target.host}/{p.target_repo}:{payload['ref']}"

    def describe(self, payload: dict[str, Any]) -> str:
        clean = self.parse(payload)
        p = self.pairs[clean["pair"]]
        return (f"copy {p.source.host}/{p.source_repo}@{clean['ref']} to {p.target.host}/{p.target_repo} by "
                f"digest (every blob SHA-256 verified, manifests byte-identical)")

    # ------------------------------------------------------------- steps
    def _step_resolve(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        p = self.pairs[payload["pair"]]
        src = self._client(p.source)
        body, digest, ctype = src.get_manifest(p.source_repo, payload["ref"])
        manifests = [{"digest": digest, "type": ctype, "top": True}]
        blobs: dict[str, int] = {}
        if ctype in INDEX_TYPES or json.loads(body).get("manifests"):
            for child in children_of(body):
                cb, cd, ct = src.get_manifest(p.source_repo, child)
                manifests.append({"digest": cd, "type": ct, "top": False})
                blobs.update({b["digest"]: int(b["size"]) for b in blobs_of(cb)})
        else:
            blobs.update({b["digest"]: int(b["size"]) for b in blobs_of(body)})
        st.update(digest=digest, media_type=ctype, manifests=manifests,
                  blobs=sorted(blobs.items()), blobs_done=[], bytes_copied=0, blobs_present=0)
        return "BLOBS"

    def _step_blobs(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        p = self.pairs[payload["pair"]]
        src, dst = self._client(p.source), self._client(p.target)
        done: list[str] = st["blobs_done"]
        todo = [(d, s) for d, s in st["blobs"] if d not in done]
        for digest, size in todo[: self.cfg.max_blobs_per_run]:
            if dst.has_blob(p.target_repo, digest):
                st["blobs_present"] += 1
            else:
                self._copy_blob(src, dst, p, digest, size)
                st["bytes_copied"] += size
            done.append(digest)
        return "MANIFESTS" if len(done) == len(st["blobs"]) else "BLOBS"

    def _copy_blob(self, src: RegistryClient, dst: RegistryClient, p: RegistryPair, digest: str, size: int) -> None:
        h = hashlib.sha256()
        seen = 0

        def chunks() -> Iterator[bytes]:
            nonlocal seen
            with src.stream(f"/v2/{p.source_repo}/blobs/{digest}", f"repository:{p.source_repo}:pull") as r:
                r.raise_for_status()
                for c in r.iter_bytes(1 << 20):
                    h.update(c)
                    seen += len(c)
                    yield c
            if seen != size or "sha256:" + h.hexdigest() != digest:
                raise RuntimeError(f"blob {digest}: source sent {seen} bytes with sha256:{h.hexdigest()}")

        dst.put_blob(p.target_repo, digest, chunks(), size)
        if "sha256:" + h.hexdigest() != digest:      # the generator may not be fully consumed on some errors
            raise RuntimeError(f"blob {digest}: streamed content does not match its digest")

    def _step_manifests(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        p = self.pairs[payload["pair"]]
        src, dst = self._client(p.source), self._client(p.target)
        for m in [m for m in st["manifests"] if not m["top"]] + [m for m in st["manifests"] if m["top"]]:
            body, digest, ctype = src.get_manifest(p.source_repo, m["digest"])
            ref = payload["ref"] if m["top"] and not _DIGEST.match(payload["ref"]) else digest
            got = dst.put_manifest(p.target_repo, ref, body, ctype)
            if got != digest:
                raise RuntimeError(f"target stored manifest {ref} as {got}, expected {digest}")
        return "VERIFY"

    def _step_verify(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        p = self.pairs[payload["pair"]]
        dst = self._client(p.target)
        _, by_ref, _ = dst.get_manifest(p.target_repo, payload["ref"])
        _, by_digest, _ = dst.get_manifest(p.target_repo, st["digest"])
        if by_ref != st["digest"] or by_digest != st["digest"]:
            raise RuntimeError(f"target digest {by_ref} differs from source {st['digest']}")
        st["verified_digest"] = by_ref
        return "DONE"

    def finish(self, job: DrJobRow) -> None:
        if self._audit is not None:
            pub = self._public(job)
            st = pub["state"]
            self._audit("dr_registry_copy", {
                "job_id": job.id, "pair": pub["payload"]["pair"], "ref": pub["payload"]["ref"],
                "status": job.status, "digest": st.get("digest"), "verified_digest": st.get("verified_digest"),
                "blobs": len(st.get("blobs", [])), "bytes_copied": st.get("bytes_copied"), "error": job.error})

