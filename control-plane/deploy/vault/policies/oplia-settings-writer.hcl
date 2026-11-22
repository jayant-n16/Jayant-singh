# OPLIA API only (Kubernetes auth role "oplia-api"): write secrets entered in the console's integration
# settings. Granted together with oplia-control-plane. Workers and CronJobs do NOT get this policy.
# Values are staged under coc/_pending/<change-id>/<name> when a change is proposed and copied to
# coc/<name> only when the approved proposal executes; the staged copy is then destroyed.

path "secret/data/coc/*" {
  capabilities = ["create", "update", "read"]
}
path "secret/metadata/coc/_pending/*" {
  capabilities = ["list", "read", "delete"]
}

# --- explicit denials (same as oplia-control-plane)
path "secret/data/coc/root*" {
  capabilities = ["deny"]
}
path "secret/metadata/coc/root*" {
  capabilities = ["deny"]
}
