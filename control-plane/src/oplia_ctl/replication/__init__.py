"""Cross-cloud DR replication: object storage, VM images, CDC pipelines, key and tag mapping.

Key material never moves between clouds: data is decrypted by the source service on read and
re-encrypted on arrival with the *target* cloud's key (KMS key, Key Vault-backed encryption scope
or disk encryption set, Cloud KMS key) named in configuration.
"""
