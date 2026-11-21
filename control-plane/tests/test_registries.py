"""Container registry replication against REAL OCI registries (CNCF Distribution 3.0.0 binary).

Two registries are started on 127.0.0.1 for each test: the source with htpasswd (HTTP Basic) auth
and the target with token (Bearer) auth served by a small local token server that signs RS256 JWTs
with an x5c chain the registry trusts - the same challenge flow ACR and Artifact Registry use.
Images are pushed with plain httpx (independent of the code under test) and the copies are checked
by downloading every blob and re-hashing it. ECR / ACR / GAR credential exchanges are tested with
botocore's Stubber and httpx mock transports. No cloud account is used.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import shutil
import socket
import subprocess  # nosec B404 - fixed local test binary
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import boto3
import httpx
import jwt
import pytest
from botocore.stub import Stubber
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from oplia_ctl.replication.registries import (
    ACR_USER,
    Credentials,
    Registry,
    RegistryClient,
    RegistryReplicator,
    RegistrySettings,
)
from oplia_ctl.secrets import StaticSecretProvider

REGISTRY_BIN = os.environ.get("OPLIA_TEST_REGISTRY_BIN") or shutil.which("registry")
if os.environ.get("CI") and not REGISTRY_BIN:
    raise RuntimeError("the Distribution registry binary is required in CI (OPLIA_TEST_REGISTRY_BIN)")
needs_registry = pytest.mark.skipif(not REGISTRY_BIN, reason="registry binary not installed")

SRC_USER, SRC_PW = "src-user", "src-pass-123"
DST_USER, DST_PW = "dst-user", "dst-pass-456"
SECRETS = StaticSecretProvider({"src_registry": f"{SRC_USER}:{SRC_PW}", "dst_registry": f"{DST_USER}:{DST_PW}"})


def _port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return int(p)


class TokenServer:
    """Docker token auth server: Basic credentials in, RS256 JWT with an x5c chain out."""

    def __init__(self, tmp: Path) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "oplia-token")])
        now = dt.datetime.now(dt.UTC)
        self.cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                     .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                     .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
                     .sign(self.key, hashes.SHA256()))
        self.bundle = tmp / "token-ca.pem"
        self.bundle.write_bytes(self.cert.public_bytes(serialization.Encoding.PEM))
        self.requests: list[dict[str, str]] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                q = {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}
                auth = self.headers.get("Authorization", "")
                outer.requests.append({**q, "auth": auth.split(" ")[0]})
                if auth != "Basic " + base64.b64encode(f"{DST_USER}:{DST_PW}".encode()).decode():
                    self.send_response(401)
                    self.end_headers()
                    return
                access = []
                if q.get("scope"):
                    _, name, actions = q["scope"].split(":")
                    access = [{"type": "repository", "name": name, "actions": actions.split(",")}]
                t = int(time.time())
                tok = jwt.encode({"iss": "oplia-token", "sub": DST_USER, "aud": q.get("service"), "exp": t + 300,
                                  "nbf": t - 10, "iat": t, "jti": str(uuid.uuid4()), "access": access},
                                 outer.key, algorithm="RS256",
                                 headers={"x5c": [base64.b64encode(outer.cert.public_bytes(
                                     serialization.Encoding.DER)).decode()]})
                body = json.dumps({"token": tok}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/token"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()


def _start(tmp: Path, auth: str, token: TokenServer | None = None) -> tuple[subprocess.Popen, str]:
    port = _port()
    root = tmp / f"reg-{port}"
    root.mkdir()
    lines = ["version: 0.1", "log: {level: error}", "storage:",
             f"  filesystem: {{rootdirectory: {root / 'data'}}}", "  delete: {enabled: false}",
             f"http: {{addr: 127.0.0.1:{port}}}"]
    if auth == "htpasswd":
        import bcrypt
        (root / "htpasswd").write_text(f"{SRC_USER}:{bcrypt.hashpw(SRC_PW.encode(), bcrypt.gensalt(5)).decode()}\n")
        lines += ["auth:", f"  htpasswd: {{realm: oplia-src, path: {root / 'htpasswd'}}}"]
    elif auth == "token":
        assert token is not None
        lines += ["auth:", f"  token: {{realm: '{token.url}', service: oplia-dst, issuer: oplia-token, "
                           f"rootcertbundle: {token.bundle}}}"]
    (root / "config.yml").write_text("\n".join(lines) + "\n")
    proc = subprocess.Popen([str(REGISTRY_BIN), "serve", str(root / "config.yml")],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    host = f"127.0.0.1:{port}"
    for _ in range(100):
        try:
            if httpx.get(f"http://{host}/v2/", timeout=1).status_code in (200, 401):
                return proc, host
        except httpx.HTTPError:
            pass
        if proc.poll() is not None:
            raise RuntimeError(f"registry exited: {proc.stderr.read().decode() if proc.stderr else ''}")
        time.sleep(0.1)
    proc.kill()
    raise RuntimeError("registry did not start")


@pytest.fixture
def registries(tmp_path):
    token = TokenServer(tmp_path)
    src, src_host = _start(tmp_path, "htpasswd")
    dst, dst_host = _start(tmp_path, "token", token)
    yield src_host, dst_host, token
    for p in (src, dst):
        p.terminate()
        p.wait(10)
    token.srv.shutdown()


# ----------------------------------------------------------------------------- seeding (plain httpx)
def _sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def _push_blob(host: str, repo: str, data: bytes) -> dict:
    auth = (SRC_USER, SRC_PW)
    r = httpx.post(f"http://{host}/v2/{repo}/blobs/uploads/", auth=auth)
    assert r.status_code == 202, r.text
    loc = r.headers["location"]
    loc = loc if loc.startswith("http") else f"http://{host}{loc}"
    r = httpx.put(f"{loc}{'&' if '?' in loc else '?'}digest={_sha(data)}", content=data, auth=auth,
                  headers={"Content-Type": "application/octet-stream"})
    assert r.status_code == 201, r.text
    return {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": _sha(data), "size": len(data)}


def _push_manifest(host: str, repo: str, ref: str, doc: dict, mtype: str) -> bytes:
    body = json.dumps(doc, separators=(",", ":")).encode()
    r = httpx.put(f"http://{host}/v2/{repo}/manifests/{ref}", content=body, auth=(SRC_USER, SRC_PW),
                  headers={"Content-Type": mtype})
    assert r.status_code == 201, r.text
    return body


def _image(host: str, repo: str, arch: str, shared: dict) -> tuple[bytes, dict]:
    cfg_bytes = json.dumps({"architecture": arch, "os": "linux", "rootfs": {"type": "layers",
                                                                             "diff_ids": []}}).encode()
    cfg = {**_push_blob(host, repo, cfg_bytes), "mediaType": "application/vnd.oci.image.config.v1+json"}
    own = _push_blob(host, repo, os.urandom(3 * 1024 * 1024 + 17))       # > 1 MiB: several stream chunks
    doc = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
           "config": cfg, "layers": [shared, own]}
    body = _push_manifest(host, repo, _sha(json.dumps(doc, separators=(",", ":")).encode()), doc,
                          "application/vnd.oci.image.manifest.v1+json")
    return body, {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": _sha(body),
                  "size": len(body), "platform": {"architecture": arch, "os": "linux"}}


def _seed(host: str, repo: str = "team/web") -> tuple[bytes, list[str]]:
    shared = _push_blob(host, repo, b"shared base layer " * 1000)
    _, m1 = _image(host, repo, "amd64", shared)
    _, m2 = _image(host, repo, "arm64", shared)
    idx = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [m1, m2]}
    body = _push_manifest(host, repo, "v1.4.2", idx, "application/vnd.oci.image.index.v1+json")
    return body, [m1["digest"], m2["digest"]]


def _settings(src_host, dst_host, **kw):
    return RegistrySettings.model_validate({"pairs": [{
        "name": "web", "source": {"kind": "basic", "host": src_host, "secret": "src_registry", "plain_http": True},
        "source_repo": "team/web",
        "target": {"kind": "basic", "host": dst_host, "secret": "dst_registry", "plain_http": True},
        "target_repo": "dr/team/web", "tag_pattern": r"^v\d+\.\d+\.\d+$"}], **kw})


def _dst_get(dst_host, token: TokenServer, path: str, accept: str = "") -> httpx.Response:
    """Independent reader for the target: fetch a pull token, then GET."""
    repo = path.split("/v2/")[1].rsplit("/", 2)[0]
    tok = httpx.get(token.url, params={"service": "oplia-dst", "scope": f"repository:{repo}:pull"},
                    auth=(DST_USER, DST_PW)).json()["token"]
    return httpx.get(f"http://{dst_host}{path}", headers={"Authorization": f"Bearer {tok}",
                                                          **({"Accept": accept} if accept else {})})


# ----------------------------------------------------------------------------- tests
@needs_registry
def test_copy_multi_platform_index_basic_to_bearer(registries, session_factory, gate):
    src_host, dst_host, token = registries
    index_body, children = _seed(src_host)
    rep = RegistryReplicator(_settings(src_host, dst_host), session_factory, secrets=SECRETS,
                             audit=lambda e, d: gate.record_event(actor="t", event=e, detail=d))
    payload = rep.parse({"pair": "web", "ref": "v1.4.2"})
    assert "by digest" in rep.describe(payload)
    jid = rep.queue(rep.target_of(payload), payload, "ann")["job_id"]
    rep.run_pending()
    job = rep.get(jid)
    assert job["status"] == "SUCCEEDED", job["error"]
    st = job["state"]
    assert st["digest"] == _sha(index_body) == st["verified_digest"]
    assert len(st["manifests"]) == 3 and len(st["blobs"]) == 5        # 2 configs, 2 own layers, 1 shared
    assert st["blobs_present"] == 0 and st["bytes_copied"] == sum(s for _, s in st["blobs"])

    # independent check: same index bytes under the tag, every blob re-hashed at the target
    r = _dst_get(dst_host, token, "/v2/dr/team/web/manifests/v1.4.2", "application/vnd.oci.image.index.v1+json")
    assert r.status_code == 200 and r.content == index_body
    for d, _size in st["blobs"]:
        b = _dst_get(dst_host, token, f"/v2/dr/team/web/blobs/{d}")
        assert b.status_code == 200 and _sha(b.content) == d
    for c in children:
        assert _dst_get(dst_host, token, f"/v2/dr/team/web/manifests/{c}",
                        "application/vnd.oci.image.manifest.v1+json").status_code == 200
    # the target really used the Bearer flow with push scope
    assert any(q.get("scope") == "repository:dr/team/web:pull,push" and q["auth"] == "Basic"
               for q in token.requests)
    ev = [e for e in gate.list_audit(limit=20) if e["event"] == "dr_registry_copy"]
    assert ev[0]["detail"]["verified_digest"] == _sha(index_body)

    # a second copy finds every blob already there and uploads nothing
    jid2 = rep.queue(rep.target_of(payload), payload, "ann")["job_id"]
    rep.run_pending()
    st2 = rep.get(jid2)["state"]
    assert rep.get(jid2)["status"] == "SUCCEEDED" and st2["blobs_present"] == 5 and st2["bytes_copied"] == 0


@needs_registry
def test_resumes_across_worker_restarts_one_blob_per_run(registries, session_factory):
    src_host, dst_host, _ = registries
    _seed(src_host)
    cfg = _settings(src_host, dst_host, max_blobs_per_run=1)
    r1 = RegistryReplicator(cfg, session_factory, secrets=SECRETS)
    jid = r1.queue("t", {"pair": "web", "ref": "v1.4.2"}, "ann")["job_id"]
    r1.run_pending()
    assert r1.get(jid)["step"] == "BLOBS" and len(r1.get(jid)["state"]["blobs_done"]) == 1
    runs = 1
    while RegistryReplicator(cfg, session_factory, secrets=SECRETS).get(jid)["status"] != "SUCCEEDED":
        RegistryReplicator(cfg, session_factory, secrets=SECRETS).run_pending()   # a fresh process each time
        runs += 1
        assert runs < 10
    assert runs == 5


@needs_registry
def test_corrupt_source_blob_is_refused_and_not_stored(registries, session_factory):
    src_host, dst_host, token = registries
    cfg = _settings(src_host, dst_host)
    layer = b"good layer bytes" * 100
    cfg_blob = b'{"architecture":"amd64","os":"linux"}'
    manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                           "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                                      "digest": _sha(cfg_blob), "size": len(cfg_blob)},
                           "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                                       "digest": _sha(layer), "size": len(layer)}]}).encode()

    def handler(req: httpx.Request) -> httpx.Response:     # a source that serves tampered layer bytes
        if "/manifests/" in req.url.path:
            return httpx.Response(200, content=manifest,
                                  headers={"Content-Type": "application/vnd.oci.image.manifest.v1+json"})
        if req.url.path.endswith(_sha(cfg_blob)):
            return httpx.Response(200, content=cfg_blob)
        return httpx.Response(200, content=b"evil layer bytes" * 100)

    def factory(reg: Registry) -> RegistryClient:
        if reg.host == src_host:
            return RegistryClient(reg, lambda: None, transport=httpx.MockTransport(handler))
        return RegistryClient(reg, Credentials(reg, SECRETS))

    rep = RegistryReplicator(cfg, session_factory, secrets=SECRETS, client_factory=factory)
    jid = rep.queue("t", {"pair": "web", "ref": "v1.0.0"}, "ann")["job_id"]
    rep.run_pending()
    job = rep.get(jid)
    assert job["status"] == "FAILED" and job["state"]["failed_step"] == "BLOBS", job
    assert "source sent 1600 bytes with sha256:" in job["error"]
    r = _dst_get(dst_host, token, f"/v2/dr/team/web/blobs/{_sha(layer)}")
    assert r.status_code == 404                              # the registry rejected the mismatching upload


def test_parse_and_settings_validation():
    cfg = _settings("127.0.0.1:5001", "127.0.0.1:5002")
    rep = RegistryReplicator(cfg, session_factory=None, secrets=SECRETS)
    assert rep.parse({"pair": "web", "ref": "v2.0.1"}) == {"pair": "web", "ref": "v2.0.1"}
    assert rep.parse({"pair": "web", "ref": "sha256:" + "a" * 64})["ref"].startswith("sha256:")
    with pytest.raises(ValueError, match="not allowed"):
        rep.parse({"pair": "web", "ref": "latest"})
    with pytest.raises(ValueError, match="unknown registry pair"):
        rep.parse({"pair": "nope", "ref": "v1.0.0"})
    assert [f["name"] for f in rep.fields()] == ["pair", "ref"]
    with pytest.raises(ValueError, match="only allowed for a registry on localhost"):
        Registry(kind="basic", host="registry.example.com", plain_http=True).base()
    with pytest.raises(ValueError):
        RegistrySettings.model_validate({"pairs": [{**cfg.pairs[0].model_dump(), "target_repo": "Bad Repo"}]})


def test_bearer_realm_must_be_https_for_remote_registries():
    reg = Registry(kind="basic", host="registry.example.com")

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(401, headers={"www-authenticate": 'Bearer realm="http://evil.example/token",'
                                                                  'service="x"'})

    c = RegistryClient(reg, lambda: ("u", "p"), transport=httpx.MockTransport(handler))
    with pytest.raises(PermissionError, match="https required"):
        c.get_manifest("team/web", "v1")


def test_ecr_credentials_from_get_authorization_token(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    ecr = boto3.client("ecr", region_name="eu-west-1")
    stub = Stubber(ecr)
    stub.add_response("get_authorization_token", {"authorizationData": [{
        "authorizationToken": base64.b64encode(b"AWS:ecr-password").decode(),
        "proxyEndpoint": "https://123456789012.dkr.ecr.eu-west-1.amazonaws.com"}]}, {})
    stub.activate()
    monkeypatch.setattr(boto3, "client", lambda *a, **k: ecr)
    reg = Registry(kind="ecr", host="123456789012.dkr.ecr.eu-west-1.amazonaws.com", region="eu-west-1")
    assert Credentials(reg).basic() == ("AWS", "ecr-password")
    stub.assert_no_pending_responses()


def test_acr_refresh_token_exchange(monkeypatch):
    import azure.identity

    class Cred:
        def get_token(self, scope):
            assert scope == "https://management.azure.com/.default"
            return type("T", (), {"token": "aad-access-token"})()

    monkeypatch.setattr(azure.identity, "DefaultAzureCredential", Cred)
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["url"], seen["form"] = str(req.url), parse_qs(req.content.decode())
        return httpx.Response(200, json={"refresh_token": "acr-refresh"})

    reg = Registry(kind="acr", host="oplia.azurecr.io")
    creds = Credentials(reg)
    RegistryClient(reg, creds, transport=httpx.MockTransport(handler))
    assert creds.basic() == (ACR_USER, "acr-refresh")
    assert seen["url"] == "https://oplia.azurecr.io/oauth2/exchange"
    assert seen["form"] == {"grant_type": ["access_token"], "service": ["oplia.azurecr.io"],
                            "access_token": ["aad-access-token"]}


def test_gar_uses_oauth2accesstoken(monkeypatch):
    import google.auth

    class C:
        token = "ya29.token"

        def refresh(self, req):
            pass

    monkeypatch.setattr(google.auth, "default", lambda scopes: (C(), "proj"))
    assert Credentials(Registry(kind="gar", host="europe-docker.pkg.dev")).basic() == (
        "oauth2accesstoken", "ya29.token")
