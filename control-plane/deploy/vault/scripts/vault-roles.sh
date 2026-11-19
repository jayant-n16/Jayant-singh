#!/usr/bin/env bash
# Roles: workloads (Kubernetes auth, every cloud) and CI runners / daemons (AppRole).
# Tokens: 60 minutes, renewable up to 24 hours.
set -euo pipefail
V=${VAULT_CLI:-vault}
enabled() { $V auth list -format=json | python3 -c "import json,sys; sys.exit(0 if '$1/' in json.load(sys.stdin) else 1)"; }
for c in aws azure gcp ibm; do
  enabled "kubernetes-$c" || { echo "skip kubernetes-$c (not enabled)"; continue; }
  $V write "auth/kubernetes-$c/role/app-prod" \
    bound_service_account_names=app-service-account \
    bound_service_account_namespaces=production \
    token_policies=app-database-access \
    token_no_default_policy=false \
    token_ttl=60m token_max_ttl=24h
  $V write "auth/kubernetes-$c/role/oplia-control-plane" \
    bound_service_account_names=oplia-control-plane,oplia-dr-breaker \
    bound_service_account_namespaces=oplia-system \
    token_policies=oplia-control-plane \
    token_ttl=60m token_max_ttl=24h
done
for r in github-actions gitlab-ci jenkins; do
  $V write "auth/approle/role/$r" token_policies=ci-runner token_ttl=60m token_max_ttl=24h \
    secret_id_ttl=24h secret_id_num_uses=0 token_num_uses=0 ${CI_BOUND_CIDRS:+token_bound_cidrs=$CI_BOUND_CIDRS}
done
$V write auth/approle/role/oplia-daemons token_policies=oplia-control-plane token_ttl=60m token_max_ttl=24h \
  secret_id_ttl=720h ${DAEMON_BOUND_CIDRS:+token_bound_cidrs=$DAEMON_BOUND_CIDRS}
echo "roles written"
