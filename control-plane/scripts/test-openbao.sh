#!/usr/bin/env bash
# Start a throwaway OpenBao (Vault-API compatible) dev server for the Vault driver tests.
# Usage: scripts/test-openbao.sh <workdir> [port]  -> prints export lines (BAO_* and OPLIA_TEST_VAULT_*).
set -euo pipefail
D=${1:?workdir}; PORT=${2:-58200}; BAO=${BAO_BIN:-bao}
rm -rf "$D"; mkdir -p "$D/audit"
TOKEN=$(openssl rand -hex 24)
"$BAO" server -dev -dev-root-token-id="$TOKEN" -dev-listen-address="127.0.0.1:$PORT" -dev-no-store-token \
  >"$D/server.log" 2>&1 &
echo $! > "$D/pid"
for _ in $(seq 1 100); do curl -sf "http://127.0.0.1:$PORT/v1/sys/health" >/dev/null 2>&1 && break; sleep 0.1; done
curl -sf "http://127.0.0.1:$PORT/v1/sys/health" >/dev/null
echo "export BAO_ADDR=http://127.0.0.1:$PORT"
echo "export BAO_TOKEN=$TOKEN"
echo "export OPLIA_TEST_VAULT_ADDR=http://127.0.0.1:$PORT"
echo "export OPLIA_TEST_VAULT_ROOT_TOKEN=$TOKEN"
echo "export VAULT_AUDIT_FILE=$D/audit/audit.log"
