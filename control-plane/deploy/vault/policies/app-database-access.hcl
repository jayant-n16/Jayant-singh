# Application workloads (Kubernetes service account "app-service-account" in "production").
# Least privilege: dynamic database credentials and the application's own Transit key - nothing else.

path "database/creds/app-prod-postgres" {
  capabilities = ["read"]
}
path "database/creds/app-prod-mysql" {
  capabilities = ["read"]
}
path "database/creds/app-prod-mongodb" {
  capabilities = ["read"]
}

# encrypt / decrypt application data with the app key (the key itself never leaves Vault)
path "transit-dr-broker/encrypt/app-prod-data" {
  capabilities = ["update"]
}
path "transit-dr-broker/decrypt/app-prod-data" {
  capabilities = ["update"]
}

# keep its own credential leases alive (renewal only; leases expire on their own)
path "sys/leases/renew" {
  capabilities = ["update"]
}

# --- explicit denials: these win over any grant from another policy attached to the same token
path "sys/*" {
  capabilities = ["deny"]
}
path "auth/*" {
  capabilities = ["deny"]
}
path "identity/*" {
  capabilities = ["deny"]
}
path "database/config/*" {
  capabilities = ["deny"]
}
path "database/roles/*" {
  capabilities = ["deny"]
}
path "transit-dr-broker/keys/*" {
  capabilities = ["deny"]
}
path "secret/*" {
  capabilities = ["deny"]
}
