# Vault server - one file per node (3 or 5 nodes, ideally one per cloud/zone). HA through the
# integrated Raft storage; every node lists the others in retry_join. TLS everywhere.
ui            = true
cluster_name  = "oplia-vault"
api_addr      = "https://vault-0.vault.example.internal:8200"   # this node
cluster_addr  = "https://vault-0.vault.example.internal:8201"
disable_mlock = true                                             # with integrated storage, per Vault docs

listener "tcp" {
  address                  = "0.0.0.0:8200"
  cluster_address          = "0.0.0.0:8201"
  tls_cert_file            = "/vault/tls/tls.crt"
  tls_key_file             = "/vault/tls/tls.key"
  tls_min_version          = "tls12"
  tls_disable_client_certs = true
}

storage "raft" {
  path    = "/vault/data"
  node_id = "vault-0"
  retry_join {
    leader_api_addr     = "https://vault-1.vault.example.internal:8200"
    leader_ca_cert_file = "/vault/tls/ca.crt"
  }
  retry_join {
    leader_api_addr     = "https://vault-2.vault.example.internal:8200"
    leader_ca_cert_file = "/vault/tls/ca.crt"
  }
}

# Auto-unseal with a cloud KMS key (choose one). Replace the identifiers with yours.
seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "alias/oplia-vault-unseal"
}

telemetry {
  prometheus_retention_time = "30s"
  disable_hostname          = true
}
