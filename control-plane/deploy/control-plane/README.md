# Control-plane deployment (namespace `oplia-system`)

`kustomize build deploy/control-plane | kubectl apply -f -` after replacing the image
(`kustomize edit set image oplia-control-plane=<registry>/oplia-control-plane@sha256:...`).

| Object | Kind | Purpose |
|---|---|---|
| `oplia-migrate` | Job | `alembic upgrade head` - run (and wait for) it before rolling the API |
| `oplia-console` | Deployment (2) + Service + PDB + Ingress | web console; the only external entry point, forwards `/api/` to the API |
| `oplia-api-ingress` | NetworkPolicy | API reachable only from the console and namespaces labelled `oplia.io/api-client=true` |
| `oplia-api` | Deployment (2) + Service + PDB | REST API, `/healthz` and `/readyz` probes |
| `oplia-jit-worker`, `oplia-aiops-escalator` | Deployment (1, Recreate) | long-running workers |
| `oplia-finops-audit` | CronJob, **suspended** | read-only audit, run on demand: `kubectl -n oplia-system create job finops-audit-1 --from=cronjob/oplia-finops-audit` |
| `oplia-finops-scan`, `-observe`, `-window` | CronJob | tag compliance, idle detection, approved clean-ups inside maintenance windows |
| `oplia-identity-sweep`, `oplia-iac-lifecycle` | CronJob | 90-day sweep, TTL lifecycle proposals |

Every pod runs as UID 1001 with a read-only root filesystem, no API-server token
(`automountServiceAccountToken: false`) and a **projected, 1-hour service-account token** at
`/var/run/secrets/vault/token` used only to log in to Vault (Kubernetes auth role
`oplia-control-plane`). Secrets are read from `secret/data/coc/<name>`; only `OPLIA_DATABASE_URL`
comes from the Kubernetes Secret `oplia-control-plane-env`.

Required before applying: ConfigMap `oplia-console-config` (`examples/console/console.env.example`,
see `docs/console-login.md`), ConfigMap `oplia-config` (non-secret `OPLIA_*` settings, see
`examples/`), ConfigMap `oplia-vault` (`examples/vault/vault.env.example`, with
`OPLIA_VAULT_KUBERNETES_MOUNT` set to this cluster's auth path), Secret `oplia-control-plane-env`.
Cloud API credentials for FinOps/lifecycle use the cluster's workload identity (IRSA, Azure
Workload Identity, GKE Workload Identity) bound to the `oplia-control-plane` service account.

The SOAR exporter (`oplia-soar-exporter`) follows a local event file and is deployed beside its
event source (falcosidekick), not here. The DR breaker is in `deploy/dr/breaker` (one per stream).

Validation: `kustomize build` + `kubeconform -strict` (Kubernetes 1.30) in CI. Not applied to a cluster.
