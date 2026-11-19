from __future__ import annotations

import json
import os
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import httpx
import pytest
import respx

from oplia_ctl.secrets import SecretNotFoundError
from oplia_ctl.vault import VaultClient, VaultError, VaultSecretProvider, VaultSettings

ADDR = "https://vault.test:8200"


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def approle_files(tmp_path, role="role-123", secret="secret-456"):  # noqa: S107 - test fixture values
    (tmp_path / "rid").write_text(role)
    (tmp_path / "sid").write_text(secret + "\n")
    return {"auth_method": "approle", "approle_role_id_file": str(tmp_path / "rid"),
            "approle_secret_id_file": str(tmp_path / "sid")}


def login_ok(token="s.tok1", ttl=3600, renewable=True):  # noqa: S107 - test fixture value
    return httpx.Response(200, json={"auth": {"client_token": token, "lease_duration": ttl, "renewable": renewable}})


# ===================================================================== unit
def test_requires_https(tmp_path):
    with pytest.raises(ValueError, match="https"):
        VaultClient(VaultSettings(addr="http://vault:8200"))
    VaultClient(VaultSettings(addr="http://127.0.0.1:8200", allow_insecure_http=True)).close()
    with pytest.raises(ValueError, match="OPLIA_VAULT_ADDR"):
        VaultClient(VaultSettings(addr=""))


@respx.mock
def test_approle_login_and_kv_read(tmp_path):
    login = respx.post(f"{ADDR}/v1/auth/approle/login").mock(return_value=login_ok())
    kv = respx.get(f"{ADDR}/v1/secret/data/coc/okta_api_token").mock(return_value=httpx.Response(
        200, json={"data": {"data": {"value": "00abc"}, "metadata": {"version": 3}}}))
    s = VaultSettings(addr=ADDR, namespace="admin/oplia", **approle_files(tmp_path))
    p = VaultSecretProvider(VaultClient(s), s)
    assert p.get("okta_api_token") == "00abc"
    assert p.get("okta_api_token") == "00abc"  # cached
    assert json.loads(login.calls.last.request.content) == {"role_id": "role-123", "secret_id": "secret-456"}
    req = kv.calls.last.request
    assert req.headers["X-Vault-Token"] == "s.tok1" and req.headers["X-Vault-Namespace"] == "admin/oplia"
    assert kv.call_count == 1 and login.call_count == 1


@respx.mock
def test_kubernetes_login_body(tmp_path):
    (tmp_path / "jwt").write_text("eyJ.sa.token\n")
    route = respx.post(f"{ADDR}/v1/auth/kubernetes-aws/login").mock(return_value=login_ok())
    respx.get(f"{ADDR}/v1/secret/data/coc/x").mock(
        return_value=httpx.Response(200, json={"data": {"data": {"value": "v"}}}))
    s = VaultSettings(addr=ADDR, kubernetes_mount="kubernetes-aws", kubernetes_role="oplia-control-plane",
                      kubernetes_jwt_file=str(tmp_path / "jwt"))
    assert VaultSecretProvider(VaultClient(s), s).get("x") == "v"
    assert json.loads(route.calls.last.request.content) == {"role": "oplia-control-plane", "jwt": "eyJ.sa.token"}


@respx.mock
def test_renews_before_expiry_and_relogs_at_max_ttl(tmp_path):
    clock = Clock()
    login = respx.post(f"{ADDR}/v1/auth/approle/login").mock(side_effect=[login_ok("t1", 120), login_ok("t2", 3600)])
    renew = respx.post(f"{ADDR}/v1/auth/token/renew-self").mock(side_effect=[
        httpx.Response(200, json={"auth": {"client_token": "t1", "lease_duration": 3600, "renewable": True}}),
        httpx.Response(200, json={"auth": {"client_token": "t1", "lease_duration": 30, "renewable": True}})])
    kv = respx.get(f"{ADDR}/v1/secret/data/coc/a").mock(return_value=httpx.Response(200, json={"data": {"data": {}}}))
    c = VaultClient(VaultSettings(addr=ADDR, **approle_files(tmp_path)), clock=clock)
    c.read_kv("coc/a")                       # login t1 (120 s)
    clock.t += 70                            # 50 s left < 60 s margin -> renew
    c.read_kv("coc/a")
    assert renew.call_count == 1 and kv.calls.last.request.headers["X-Vault-Token"] == "t1"
    clock.t += 3560                          # near expiry again; renewal only gives 30 s (max TTL) -> re-login
    c.read_kv("coc/a")
    assert renew.call_count == 2 and login.call_count == 2
    assert kv.calls.last.request.headers["X-Vault-Token"] == "t2"


@respx.mock
def test_403_relogs_once_and_errors_never_contain_tokens(tmp_path):
    respx.post(f"{ADDR}/v1/auth/approle/login").mock(side_effect=[login_ok("s.SECRET1"), login_ok("s.SECRET2")])
    respx.get(f"{ADDR}/v1/secret/data/coc/a").mock(return_value=httpx.Response(
        403, json={"errors": ["permission denied"]}))
    c = VaultClient(VaultSettings(addr=ADDR, **approle_files(tmp_path, secret="SID-SECRET")))
    with pytest.raises(VaultError) as ei:
        c.read_kv("coc/a")
    msg = str(ei.value)
    assert ei.value.status == 403 and "permission denied" in msg
    assert "s.SECRET" not in msg and "SID-SECRET" not in msg


@respx.mock
def test_provider_not_found(tmp_path):
    respx.post(f"{ADDR}/v1/auth/approle/login").mock(return_value=login_ok())
    respx.get(f"{ADDR}/v1/secret/data/coc/missing").mock(return_value=httpx.Response(404, json={"errors": []}))
    respx.get(f"{ADDR}/v1/secret/data/coc/nofield").mock(return_value=httpx.Response(
        200, json={"data": {"data": {"other": "x"}}}))
    s = VaultSettings(addr=ADDR, **approle_files(tmp_path))
    p = VaultSecretProvider(VaultClient(s), s)
    for name in ("missing", "nofield"):
        with pytest.raises(SecretNotFoundError):
            p.get(name)
    with pytest.raises(ValueError):
        p.get("../etc/passwd")


def test_build_secret_provider_vault(monkeypatch):
    from oplia_ctl.secrets import build_secret_provider

    monkeypatch.setenv("OPLIA_VAULT_ADDR", ADDR)
    assert isinstance(build_secret_provider("vault"), VaultSecretProvider)


# =========================================================== real OpenBao
VAULT = os.environ.get("OPLIA_TEST_VAULT_ADDR", "")
ROOT = os.environ.get("OPLIA_TEST_VAULT_ROOT_TOKEN", "")
needs_vault = pytest.mark.skipif(not VAULT, reason="needs a Vault/OpenBao server (scripts/test-openbao.sh)")
POLICY_DIR = Path(__file__).resolve().parents[1] / "deploy" / "vault" / "policies"


def root(method, path, **kw):
    r = httpx.request(method, f"{VAULT}/v1/{path}", headers={"X-Vault-Token": ROOT}, timeout=10, **kw)
    if r.status_code >= 400:
        raise AssertionError(f"{method} {path}: {r.status_code} {r.text}")
    return r.json() if r.content else {}


@pytest.fixture(scope="module")
def bao():
    """Mounts and policies exactly as deploy/vault (idempotent), via the HTTP API with the root token."""
    mounts = root("GET", "sys/mounts")
    if "transit-dr-broker/" not in mounts:
        root("POST", "sys/mounts/transit-dr-broker", json={"type": "transit"})
    if "database/" not in mounts:
        root("POST", "sys/mounts/database", json={"type": "database"})
    if "secret/" not in mounts:
        root("POST", "sys/mounts/secret", json={"type": "kv", "options": {"version": "2"}})
    for key in ("circuit-breaker-key", "app-prod-data"):
        root("POST", f"transit-dr-broker/keys/{key}", json={"type": "aes256-gcm96"})
    if "approle/" not in root("GET", "sys/auth"):
        root("POST", "sys/auth/approle", json={"type": "approle"})
    for pol in ("app-database-access", "oplia-control-plane", "ci-runner"):
        root("PUT", f"sys/policies/acl/{pol}", json={"policy": (POLICY_DIR / f"{pol}.hcl").read_text()})
    return VAULT


def approle(tmp_path, role, policies):
    root("POST", f"auth/approle/role/{role}", json={"token_policies": policies, "token_ttl": "60m",
                                                     "token_max_ttl": "24h"})
    rid = root("GET", f"auth/approle/role/{role}/role-id")["data"]["role_id"]
    sid = root("POST", f"auth/approle/role/{role}/secret-id")["data"]["secret_id"]
    (tmp_path / f"{role}.rid").write_text(rid)
    (tmp_path / f"{role}.sid").write_text(sid)
    return VaultSettings(addr=VAULT, allow_insecure_http=True, auth_method="approle",
                         approle_role_id_file=str(tmp_path / f"{role}.rid"),
                         approle_secret_id_file=str(tmp_path / f"{role}.sid"))


@needs_vault
def test_real_approle_kv_and_policy_boundaries(bao, tmp_path):
    root("POST", "secret/data/coc/okta_api_token", json={"data": {"value": "00real-token"}})
    root("POST", "secret/data/coc/root_token", json={"data": {"value": "nope"}})
    s = approle(tmp_path, "oplia-daemons-test", ["oplia-control-plane"])
    client = VaultClient(s)
    p = VaultSecretProvider(client, s)
    assert p.get("okta_api_token") == "00real-token"
    with pytest.raises(VaultError) as ei:
        client.read_kv("coc/root_token")  # explicit deny in the policy
    assert ei.value.status == 403
    with pytest.raises(VaultError) as ei:
        client.request("POST", "/v1/auth/token/create", json={})
    assert ei.value.status == 403
    with pytest.raises(SecretNotFoundError):
        p.get("does_not_exist")
    assert client.write_kv is not None


@needs_vault
def test_real_transit_encrypt_hmac_and_tamper_detection(bao, tmp_path):
    from oplia_ctl.dr.crypto import TransitProtector

    client = VaultClient(approle(tmp_path, "oplia-transit-test", ["oplia-control-plane"]))
    data = b'{"records": [{"payload": "UPDATE accounts SET balance = 0"}]}'
    prot = TransitProtector(client)
    env = prot.protect(data)
    parsed = json.loads(env)
    assert parsed["ciphertext"].startswith("vault:v1:") and parsed["hmac"].startswith("vault:v1:")
    assert b"UPDATE accounts" not in env
    assert prot.open(env) == data
    tampered = json.loads(env)
    other = client.encrypt("transit-dr-broker", "circuit-breaker-key", b'{"records": []}')
    tampered["ciphertext"] = other
    with pytest.raises(ValueError, match="HMAC"):
        prot.open(json.dumps(tampered).encode())
    macs = prot.sign([b"a", b"b"])
    assert len(macs) == 2 and macs[0] != macs[1]
    with pytest.raises(VaultError):  # the app key is not allowed for the control plane
        client.encrypt("transit-dr-broker", "app-prod-data", b"x")


@needs_vault
def test_real_kafka_records_carry_verifiable_transit_hmac(bao, tmp_path):
    from oplia_ctl.dr.crypto import TransitProtector
    from oplia_ctl.dr.decode import Record
    from oplia_ctl.dr.relay import KafkaSink

    client = VaultClient(approle(tmp_path, "oplia-sign-test", ["oplia-control-plane"]))
    sent = []

    class Producer:
        def produce(self, topic, value, on_delivery, headers=None):
            sent.append((value, dict(headers or [])))
            on_delivery(None, None)

        def flush(self, timeout):
            return 0

    sink = KafkaSink(config={}, topic="dr.orders", signer=TransitProtector(client).sign,
                     producer_factory=lambda cfg: Producer())
    sink.send([Record("debezium", {"op": "u", "after": {"id": 1}}, "postgres"), Record("sql", "SELECT 1", "postgres")])
    assert len(sent) == 2
    for value, headers in sent:
        mac = headers["oplia-hmac"].decode()
        assert client.verify_hmac("transit-dr-broker", "circuit-breaker-key", value, mac) is True
        assert client.verify_hmac("transit-dr-broker", "circuit-breaker-key", value + b"x", mac) is False


PG_URL = os.environ.get("OPLIA_TEST_DATABASE_URL", "")


@needs_vault
@pytest.mark.skipif(not PG_URL, reason="needs PostgreSQL")
def test_real_dynamic_postgres_credentials(bao, tmp_path):
    import psycopg

    admin = PG_URL.replace("postgresql+psycopg://", "postgresql://")
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute("DROP DATABASE IF EXISTS oplia_vault_app WITH (FORCE)")
        c.execute("CREATE DATABASE oplia_vault_app ENCODING 'UTF8' TEMPLATE template0")
        for role in ("app_rw", "app_owner"):
            if not c.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
                c.execute(f"CREATE ROLE {role} NOLOGIN")
        if not c.execute("SELECT 1 FROM pg_roles WHERE rolname = 'vault_admin'").fetchone():
            c.execute("CREATE ROLE vault_admin LOGIN CREATEROLE PASSWORD 'vault-admin-pw'")
        c.execute("GRANT app_rw, app_owner TO vault_admin WITH ADMIN OPTION")
        # PostgreSQL 16: without this, users created by vault_admin cannot be REASSIGNed/dropped on revoke
        c.execute("ALTER ROLE vault_admin SET createrole_self_grant = 'set, inherit'")
    host = admin.split("@", 1)[1].split("/", 1)[0]
    root("POST", "database/config/app-prod-postgres", json={
        "plugin_name": "postgresql-database-plugin", "allowed_roles": "app-prod-postgres",
        "connection_url": f"postgresql://{{{{username}}}}:{{{{password}}}}@{host}/oplia_vault_app?sslmode=disable",
        "username": "vault_admin", "password": "vault-admin-pw"})
    root("POST", "database/roles/app-prod-postgres", json={
        "db_name": "app-prod-postgres", "default_ttl": "1h", "max_ttl": "24h",
        "creation_statements": ["CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' "
                                "VALID UNTIL '{{expiration}}' INHERIT; GRANT app_rw TO \"{{name}}\";"],
        "revocation_statements": ["REASSIGN OWNED BY \"{{name}}\" TO app_owner; DROP OWNED BY \"{{name}}\"; "
                                  "DROP ROLE IF EXISTS \"{{name}}\";"]})
    app = VaultClient(approle(tmp_path, "app-prod-test", ["app-database-access"]))
    creds = app.database_credentials("app-prod-postgres")
    assert creds["lease_duration"] == 3600 and creds["username"].startswith("v-")
    base = admin.split("://", 1)[1].split("@", 1)[1].split("/", 1)[0]
    with psycopg.connect(f"postgresql://{creds['username']}:{creds['password']}@{base}/oplia_vault_app") as c:
        assert c.execute("SELECT current_user").fetchone()[0] == creds["username"]
        assert c.execute("SELECT pg_has_role(current_user, 'app_rw', 'MEMBER')").fetchone()[0] is True
    with pytest.raises(psycopg.OperationalError, match="password authentication failed"):
        psycopg.connect(f"postgresql://{creds['username']}:wrong-password@{base}/oplia_vault_app")
    with pytest.raises(VaultError):  # the application cannot read the admin connection
        app.request("GET", "/v1/database/config/app-prod-postgres")
    root("PUT", "sys/leases/revoke", json={"lease_id": creds["lease_id"]})
    with psycopg.connect(admin, autocommit=True) as c:
        for _ in range(50):
            if not c.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (creds["username"],)).fetchone():
                break
            time.sleep(0.1)
        assert not c.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (creds["username"],)).fetchone()


# --------------------------------------------- Kubernetes auth with a TokenReview API
def _jwt(claims: dict) -> str:
    import jwt as pyjwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return pyjwt.encode(claims, key, algorithm="RS256")


@needs_vault
def test_real_kubernetes_auth_login(bao, tmp_path):
    """Vault calls our TLS TokenReview endpoint; the role's SA/namespace binding is enforced."""
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",  # noqa: S603, S607
                    "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
                    "-keyout", str(tmp_path / "k.pem"), "-out", str(tmp_path / "c.pem")], check=True,
                   capture_output=True)
    reviews: list[dict] = []
    accounts = {}

    class Api(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            reviews.append({"auth": self.headers.get("Authorization"), "body": body})
            sa = accounts.get(body["spec"]["token"])
            status = ({"authenticated": True, "user": {"username": f"system:serviceaccount:{sa[0]}:{sa[1]}",
                                                        "uid": "uid-1"}} if sa else {"authenticated": False})
            out = json.dumps({"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
                              "status": status}).encode()
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Api)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(tmp_path / "c.pem"), str(tmp_path / "k.pem"))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        if "kubernetes-test/" not in root("GET", "sys/auth"):
            root("POST", "sys/auth/kubernetes-test", json={"type": "kubernetes"})
        root("POST", "auth/kubernetes-test/config", json={
            "kubernetes_host": f"https://127.0.0.1:{srv.server_address[1]}",
            "kubernetes_ca_cert": (tmp_path / "c.pem").read_text(), "token_reviewer_jwt": "reviewer-jwt",
            "disable_local_ca_jwt": True})
        root("POST", "auth/kubernetes-test/role/oplia-control-plane", json={
            "bound_service_account_names": ["oplia-control-plane"],
            "bound_service_account_namespaces": ["oplia-system"],
            "token_policies": ["oplia-control-plane"], "token_ttl": "60m", "token_max_ttl": "24h"})
        now = int(time.time())
        claims = {"iss": "kubernetes/serviceaccount", "iat": now, "exp": now + 600,
                  "kubernetes.io/serviceaccount/namespace": "oplia-system",
                  "kubernetes.io/serviceaccount/service-account.name": "oplia-control-plane",
                  "kubernetes.io/serviceaccount/service-account.uid": "uid-1",
                  "sub": "system:serviceaccount:oplia-system:oplia-control-plane"}
        good = _jwt(claims)
        accounts[good] = ("oplia-system", "oplia-control-plane")
        (tmp_path / "sa").write_text(good)
        root("POST", "secret/data/coc/k8s_probe", json={"data": {"value": "from-k8s-auth"}})
        s = VaultSettings(addr=VAULT, allow_insecure_http=True, kubernetes_mount="kubernetes-test",
                          kubernetes_role="oplia-control-plane", kubernetes_jwt_file=str(tmp_path / "sa"))
        assert VaultSecretProvider(VaultClient(s), s).get("k8s_probe") == "from-k8s-auth"
        assert reviews and reviews[-1]["auth"] == "Bearer reviewer-jwt"
        assert reviews[-1]["body"]["spec"]["token"] == good

        wrong = _jwt({**claims, "kubernetes.io/serviceaccount/namespace": "default",
                      "sub": "system:serviceaccount:default:oplia-control-plane"})
        accounts[wrong] = ("default", "oplia-control-plane")  # right name, wrong namespace
        (tmp_path / "sa").write_text(wrong)
        with pytest.raises(VaultError) as ei:
            VaultClient(s).login()
        assert ei.value.status in (400, 403)
    finally:
        srv.shutdown()


@needs_vault
def test_breaker_dump_is_encrypted_with_transit(bao, tmp_path, gate, session_factory):
    from oplia_ctl.dr.breaker import CircuitBreaker, list_incidents
    from oplia_ctl.dr.crypto import TransitProtector
    from oplia_ctl.dr.decode import Record
    from oplia_ctl.http import ResilientClient
    from oplia_ctl.secrets import StaticSecretProvider

    client = VaultClient(approle(tmp_path, "oplia-dr-test", ["oplia-control-plane"]))
    b = CircuitBreaker(stream="s1", gate=gate, session_factory=session_factory, secrets=StaticSecretProvider({}),
                       client=ResilientClient(), lockers=[], webhooks=[], notifier=None,
                       quarantine_dir=str(tmp_path / "q"), protector=TransitProtector(client))
    bundle = [Record("sql", "DROP TABLE customers", "postgres", position="p:0:1")]
    b.trip(bundle, b.inspect(bundle).findings, None)
    inc = list_incidents(session_factory)[0]
    raw = Path(inc["dump_path"]).read_bytes()
    assert b"DROP TABLE customers" not in raw and json.loads(raw)["ciphertext"].startswith("vault:v1:")
    assert json.loads(TransitProtector(client).open(raw))["records"][0]["payload"] == "DROP TABLE customers"
    assert inc["actions"]["dump_protection"] == "vault transit transit-dr-broker/circuit-breaker-key"
