#!/usr/bin/env bash
# Runs the deploy/vault scripts end to end against a dev Vault/OpenBao server (scripts/test-openbao.sh)
# and a PostgreSQL server, then checks the effective policy capabilities and a dynamic credential.
# Needs: VAULT_CLI (vault or bao), its ADDR/TOKEN env (VAULT_* or BAO_*), OPLIA_TEST_DATABASE_URL
# (postgresql+psycopg://user:pass@host:port/db, a superuser), python with psycopg.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
S="$here/deploy/vault/scripts"
V=${VAULT_CLI:-vault}
export VAULT_CLI="$V"
: "${OPLIA_TEST_DATABASE_URL:?}"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

echo "== bootstrap (twice: must be idempotent)"
"$S/vault-bootstrap.sh"
"$S/vault-bootstrap.sh"

echo "== kubernetes auth for four clusters (configuration only; Vault does not contact the API here)"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=k8s-test -keyout "$W/ca.key" -out "$W/ca.pem" 2>/dev/null
printf 'reviewer-token-placeholder' > "$W/jwt"
for c in AWS AZURE GCP IBM; do
  export "K8S_${c}_HOST=https://k8s-$c.example.internal:6443" "K8S_${c}_CA_FILE=$W/ca.pem" "K8S_${c}_REVIEWER_JWT_FILE=$W/jwt"
done
"$S/vault-k8s-auth.sh" | tee "$W/k8s.out"
grep -q "configured 4 Kubernetes auth path" "$W/k8s.out" || fail "expected 4 kubernetes auth paths"
K8S_AWS_HOST=http://insecure.example "$S/vault-k8s-auth.sh" >/dev/null 2>&1 && fail "http:// API host accepted"

echo "== roles"
"$S/vault-roles.sh"
"$V" read -format=json auth/kubernetes-gcp/role/app-prod | python3 -c '
import json, sys
d = json.load(sys.stdin)["data"]
assert d["bound_service_account_names"] == ["app-service-account"], d
assert d["bound_service_account_namespaces"] == ["production"], d
assert d["token_policies"] == ["app-database-access"], d
assert d["token_ttl"] == 3600 and d["token_max_ttl"] == 86400, d'

echo "== dynamic PostgreSQL credentials (dedicated admin role, rotate-root runs for real)"
python3 - "$OPLIA_TEST_DATABASE_URL" <<'PY'
import sys, psycopg
url = sys.argv[1].replace("postgresql+psycopg://", "postgresql://")
with psycopg.connect(url, autocommit=True) as c:
    c.execute("DROP DATABASE IF EXISTS oplia_vault_deploy WITH (FORCE)")
    c.execute("CREATE DATABASE oplia_vault_deploy ENCODING 'UTF8' TEMPLATE template0")
    for role in ("app_rw", "app_owner"):
        if not c.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
            c.execute(f"CREATE ROLE {role} NOLOGIN")
    if not c.execute("SELECT 1 FROM pg_roles WHERE rolname = 'vault_deploy_admin'").fetchone():
        c.execute("CREATE ROLE vault_deploy_admin LOGIN CREATEROLE")
    c.execute("ALTER ROLE vault_deploy_admin PASSWORD 'deploy-admin-initial'")
    c.execute("GRANT app_rw, app_owner TO vault_deploy_admin WITH ADMIN OPTION")
    c.execute("ALTER ROLE vault_deploy_admin SET createrole_self_grant = 'set, inherit'")
PY
printf 'deploy-admin-initial' > "$W/pgpw"
hostport=$(python3 -c 'import sys,urllib.parse as u; p=u.urlsplit(sys.argv[1].replace("+psycopg","")); print(p.hostname, p.port or 5432)' "$OPLIA_TEST_DATABASE_URL")
PG_HOST=${hostport% *} PG_PORT=${hostport#* } PG_DB=oplia_vault_deploy PG_SSLMODE=disable \
  PG_ADMIN_USER=vault_deploy_admin PG_ADMIN_PASSWORD_FILE="$W/pgpw" "$S/vault-database.sh"

echo "== effective policy capabilities"
tok() { "$V" token create -policy="$1" -ttl=10m -field=token; }
cap() { "$V" token capabilities "$1" "$2"; }
expect() { got=$(cap "$1" "$2"); [ "$got" = "$3" ] || fail "$4: $2 -> '$got' (expected '$3')"; }
APP=$(tok app-database-access); OPS=$(tok oplia-control-plane); CI=$(tok ci-runner)
expect "$APP" database/creds/app-prod-postgres read app
expect "$APP" transit-dr-broker/encrypt/app-prod-data update app
expect "$APP" database/config/app-prod-postgres deny app
expect "$APP" secret/data/coc/okta-api-token deny app
expect "$APP" sys/leases/renew update app
expect "$OPS" secret/data/coc/okta-api-token read control-plane
expect "$OPS" transit-dr-broker/hmac/circuit-breaker-key/sha2-256 update control-plane
expect "$OPS" transit-dr-broker/keys/circuit-breaker-key deny control-plane
expect "$OPS" sys/policies/acl/x deny control-plane
expect "$OPS" auth/token/create deny control-plane
expect "$CI" secret/data/coc/cicd/github read ci
expect "$CI" secret/data/coc/okta-api-token deny ci

echo "== a credential from the app policy logs in"
creds=$(VAULT_TOKEN=$APP BAO_TOKEN=$APP "$V" read -format=json database/creds/app-prod-postgres)
python3 - "$OPLIA_TEST_DATABASE_URL" "$creds" <<'PY'
import json, sys, urllib.parse as u, psycopg
p = u.urlsplit(sys.argv[1].replace("+psycopg", ""))
d = json.loads(sys.argv[2])
with psycopg.connect(host=p.hostname, port=p.port or 5432, dbname="oplia_vault_deploy",
                     user=d["data"]["username"], password=d["data"]["password"]) as c:
    assert c.execute("SELECT pg_has_role(current_user, 'app_rw', 'MEMBER')").fetchone()[0] is True
print("dynamic credential login ok, lease", d["lease_duration"], "s")
PY
"$V" lease revoke -prefix database/creds/app-prod-postgres >/dev/null
echo "OK: deploy/vault scripts verified"
