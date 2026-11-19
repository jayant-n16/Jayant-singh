#!/usr/bin/env bash
# Bootstrap Vault for OPLIA. Idempotent: safe to run again. Needs a token with admin rights
# (VAULT_ADDR / VAULT_TOKEN, or BAO_* for OpenBao). Run from deploy/vault/scripts.
set -euo pipefail
V=${VAULT_CLI:-vault}
HERE=$(cd "$(dirname "$0")" && pwd)
POLICIES="$HERE/../policies"

mounted() { $V secrets list -format=json | python3 -c "import json,sys; sys.exit(0 if '$1/' in json.load(sys.stdin) else 1)"; }
auth_on() { $V auth list -format=json | python3 -c "import json,sys; sys.exit(0 if '$1/' in json.load(sys.stdin) else 1)"; }

# 1. audit device first, so everything after this is recorded
AUDIT_WARNING=""
if ! $V audit list -format=json 2>/dev/null | python3 -c "import json,sys; sys.exit(0 if json.load(sys.stdin) else 1)"; then
  err=$(mktemp)
  if ! $V audit enable file file_path="${VAULT_AUDIT_FILE:-/vault/audit/audit.log}" 2>"$err"; then
    if grep -qi "declarative" "$err"; then
      # OpenBao 2.x only accepts audit devices from the server configuration file
      AUDIT_WARNING="AUDIT DEVICE NOT ENABLED: add an audit \"file\" stanza to the server config (see ../server/README.md)"
    else
      cat "$err" >&2; rm -f "$err"; exit 1
    fi
  fi
  rm -f "$err"
fi

# 2. engines
mounted secret || $V secrets enable -path=secret -version=2 kv          # existing paths secret/data/coc/*
mounted transit-dr-broker || $V secrets enable -path=transit-dr-broker -description="DR breaker and app data encryption" transit
mounted database || $V secrets enable -path=database database
auth_on approle || $V auth enable approle

# 3. transit keys (non-exportable, no plaintext backup)
for key in circuit-breaker-key app-prod-data; do
  $V read "transit-dr-broker/keys/$key" >/dev/null 2>&1 || $V write -f "transit-dr-broker/keys/$key" type=aes256-gcm96
  $V write "transit-dr-broker/keys/$key/config" deletion_allowed=false exportable=false allow_plaintext_backup=false >/dev/null
done

# 4. policies
for p in app-database-access oplia-control-plane ci-runner; do
  $V policy write "$p" "$POLICIES/$p.hcl"
done
if [ -n "$AUDIT_WARNING" ]; then echo "WARNING: $AUDIT_WARNING" >&2; fi
echo "bootstrap complete"
