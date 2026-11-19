#!/usr/bin/env bash
# Kubernetes auth for every cluster: auth/kubernetes-aws, -azure, -gcp, -ibm.
# For each cloud C (aws azure gcp ibm) provide, from that cluster:
#   K8S_<C>_HOST       API server URL reachable from Vault, e.g. https://ABC.gr7.us-east-1.eks.amazonaws.com
#   K8S_<C>_CA_FILE    the cluster CA (PEM)
#   K8S_<C>_REVIEWER_JWT_FILE  token of a service account bound to system:auth-delegator
#                              (vault-auth, see deploy/vault/k8s/token-reviewer.yaml)
# A cloud whose variables are not set is skipped and reported.
set -euo pipefail
V=${VAULT_CLI:-vault}
auth_on() { $V auth list -format=json | python3 -c "import json,sys; sys.exit(0 if '$1/' in json.load(sys.stdin) else 1)"; }
configured=0
for c in aws azure gcp ibm; do
  C=${c^^}
  host_var="K8S_${C}_HOST"; ca_var="K8S_${C}_CA_FILE"; jwt_var="K8S_${C}_REVIEWER_JWT_FILE"
  if [ -z "${!host_var:-}" ] || [ -z "${!ca_var:-}" ] || [ -z "${!jwt_var:-}" ]; then
    echo "skip kubernetes-$c: set $host_var, $ca_var and $jwt_var"; continue
  fi
  case "${!host_var}" in https://*) ;; *) echo "kubernetes-$c: $host_var must be https://"; exit 1;; esac
  auth_on "kubernetes-$c" || $V auth enable -path="kubernetes-$c" -description="Kubernetes ($c)" kubernetes
  $V write "auth/kubernetes-$c/config" \
    kubernetes_host="${!host_var}" \
    kubernetes_ca_cert=@"${!ca_var}" \
    token_reviewer_jwt=@"${!jwt_var}" \
    disable_local_ca_jwt=true
  configured=$((configured + 1))
done
echo "configured $configured Kubernetes auth path(s)"
