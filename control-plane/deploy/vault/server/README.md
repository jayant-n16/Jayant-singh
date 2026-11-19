# Vault server and bootstrap

1. **Servers** - `vault-server.hcl` per node (integrated Raft, TLS, cloud-KMS auto-unseal, Prometheus
   telemetry at `/v1/sys/metrics?format=prometheus`). Initialise once:
   `vault operator init -recovery-shares=5 -recovery-threshold=3` - store recovery keys offline,
   revoke the initial root token after bootstrap (`vault token revoke <root>`).
2. **Audit** - HashiCorp Vault: `vault-bootstrap.sh` enables a file audit device through the API.
   OpenBao 2.x refuses that ("declarative" audit only) - add this to every node's config instead:

   ```hcl
   audit "file" "oplia" {
     options {
       file_path = "/vault/audit/audit.log"
     }
   }
   ```
3. **Bootstrap** (`../scripts`, admin token): `vault-bootstrap.sh` (engines, transit keys, policies),
   `vault-database.sh` (dynamic DB credentials), `vault-k8s-auth.sh` (one auth path per cluster, after
   applying `../k8s/token-reviewer.yaml` in each cluster), `vault-roles.sh` (workload and CI roles),
   `import-static-secrets.sh <name...>` (existing IdP keys into `secret/coc/<name>`, values typed, never echoed).
4. **PostgreSQL prerequisite for dynamic credentials (PostgreSQL 16+)** - the admin role Vault uses must
   be able to clean up the users it creates, otherwise lease revocation fails and expired users remain:

   ```sql
   CREATE ROLE vault_admin LOGIN CREATEROLE PASSWORD '...';
   GRANT app_rw, app_owner TO vault_admin WITH ADMIN OPTION;
   ALTER ROLE vault_admin SET createrole_self_grant = 'set, inherit';
   ```

## Validation status

Scripts, policies and the agent template were run against **OpenBao 2.5.3** (the open-source fork
with the Vault HTTP API), not HashiCorp Vault itself: bootstrap (re-run idempotent), Kubernetes auth
for four clusters, roles, effective policy capabilities, AppRole and Kubernetes-auth logins (with a
TokenReview endpoint), KV v2, Transit, dynamic PostgreSQL credentials (login, wrong password refused,
revocation) and a Vault Agent rendering the injector template. `vault-server.hcl` was not run (needs
KMS and TLS material); `vault-database.sh` MySQL/MongoDB sections were not run.
