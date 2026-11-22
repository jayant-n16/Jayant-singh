# OPLIA control plane (API, workers, CronJobs). Secrets are read by name from secret/data/coc/<name>.

path "secret/data/coc/*" {
  capabilities = ["read"]
}
path "secret/metadata/coc/*" {
  capabilities = ["list"]
}

# DR circuit breaker: protect incident dumps and sign forwarded bundles
path "transit-dr-broker/encrypt/circuit-breaker-key" {
  capabilities = ["update"]
}
path "transit-dr-broker/decrypt/circuit-breaker-key" {
  capabilities = ["update"]
}
path "transit-dr-broker/hmac/circuit-breaker-key/*" {
  capabilities = ["update"]
}
path "transit-dr-broker/verify/circuit-breaker-key/*" {
  capabilities = ["update"]
}

path "sys/leases/renew" {
  capabilities = ["update"]
}

# --- explicit denials
path "secret/data/coc/root*" {
  capabilities = ["deny"]
}
path "sys/policies/*" {
  capabilities = ["deny"]
}
path "sys/mounts*" {
  capabilities = ["deny"]
}
path "sys/auth*" {
  capabilities = ["deny"]
}
path "sys/raw*" {
  capabilities = ["deny"]
}
path "sys/generate-root*" {
  capabilities = ["deny"]
}
path "auth/token/create*" {
  capabilities = ["deny"]
}
path "identity/*" {
  capabilities = ["deny"]
}
path "transit-dr-broker/keys/*" {
  capabilities = ["deny"]
}
