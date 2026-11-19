#!/usr/bin/env bash
# Import existing static credentials into secret/data/coc/<name> without putting them on the command
# line, in shell history or in logs: each value is typed (not echoed) and piped to the CLI on stdin.
# Usage: import-static-secrets.sh entra_client_secret okta_api_token ad_bind_password ...
set -euo pipefail
V=${VAULT_CLI:-vault}
[ "$#" -gt 0 ] || { echo "usage: $0 <secret-name> [...]" >&2; exit 2; }
for name in "$@"; do
  [[ "$name" =~ ^[a-z0-9_]{1,64}$ ]] || { echo "invalid name $name" >&2; exit 2; }
  read -r -s -p "value for $name: " value; echo
  [ -n "$value" ] || { echo "empty value for $name, skipped" >&2; continue; }
  printf '%s' "$value" | $V kv put "secret/coc/$name" value=- >/dev/null
  unset value
  echo "stored secret/coc/$name (version $($V kv metadata get -format=json "secret/coc/$name" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["current_version"])'))"
done
