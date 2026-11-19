# OPLIA control plane – multi-cloud rollout runbook

Rollout of the control plane (Phases 1–7 of this repository) across AWS, Azure, GCP and IBM Cloud
without interrupting running applications. Each phase has **steps**, **verification commands** and a
**gate**: do not start the next phase until every gate item is green, and use the phase's
**rollback** if a stop condition fires.

Conventions used below:

```bash
export OPLIA=https://oplia.example.internal          # control-plane API
export TOKEN=$(...)                                   # OIDC access token of an operator/approver
export VAULT_ADDR=https://vault.example.internal:8200
auth() { curl -sSf -H "Authorization: Bearer $TOKEN" "$@"; }
```

Global stop conditions (apply in every phase; any one of them = **freeze**, then roll back the
current phase):

| Signal | Threshold | Source |
|---|---|---|
| HTTP 5xx ratio of production services | > 0.01 % over 5 min (or 2x the pre-change baseline if that is higher) | Prometheus / Datadog APM |
| p99 latency | > 1.2x the pre-change baseline over 10 min | Prometheus / Datadog / Dynatrace |
| Container crash loops | any pod of a changed workload in `CrashLoopBackOff`, or restarts > 0 in 10 min | kube-state-metrics |
| DR replication lag | > 2 s for 5 min | CockroachDB changefeed / Debezium / DB exporters |
| Vault request latency p99 | > 50 ms for 10 min | Vault telemetry |
| Audit chain | `GET /audit/verify` returns `intact: false` | OPLIA |

Freeze = engage the kill switch (stops every executor in the control plane; proposals stay queued):

```bash
auth -X POST "$OPLIA/kill-switch" -H 'Content-Type: application/json' \
     -d '{"engaged": true, "reason": "rollout freeze: <signal>"}'
```

Example PromQL for the stop conditions. Metric names depend on your exporters and instrumentation –
confirm each one returns data **before** the rollout starts, otherwise the gate is blind:

```promql
# 5xx ratio (replace http_requests_total with your server metric)
sum(rate(http_requests_total{namespace="production",code=~"5.."}[5m]))
  / sum(rate(http_requests_total{namespace="production"}[5m])) > 0.0001
# crash loops (kube-state-metrics)
max by (namespace, pod) (kube_pod_container_status_waiting_reason{namespace="production",reason="CrashLoopBackOff"}) > 0
sum by (namespace, pod) (increase(kube_pod_container_status_restarts_total{namespace="production"}[10m])) > 0
# Vault: request handling p99 in milliseconds (summary from /v1/sys/metrics?format=prometheus)
max(vault_core_handle_request{quantile="0.99"}) > 50
# CockroachDB changefeed lag (seconds)
max(changefeed_max_behind_nanos) / 1e9 > 2
```

---

## Phase 1 – Vault baseline, IdP keys and passive FinOps audit

### 1.1 Vault cluster

1. Deploy 3 or 5 nodes with `deploy/vault/server/vault-server.hcl` (integrated Raft, TLS, KMS auto-unseal).
   On OpenBao add the `audit "file"` stanza from `deploy/vault/server/README.md`.
2. Initialise once, store the recovery keys offline:
   ```bash
   vault operator init -recovery-shares=5 -recovery-threshold=3
   ```
3. Bootstrap with the initial root token, then revoke it:
   ```bash
   deploy/vault/scripts/vault-bootstrap.sh       # audit, kv-v2 at secret/, transit-dr-broker, database, approle, policies
   vault token revoke "$VAULT_TOKEN"              # after an admin auth method (OIDC) is configured
   ```

**Verify**

```bash
vault status -format=json | jq '{sealed, ha_enabled, raft_committed_index}'   # sealed=false, ha_enabled=true
vault operator raft list-peers                                                # all nodes, one leader
vault audit list                                                              # file/ enabled (Vault) or configured in HCL (OpenBao)
vault secrets list -format=json | jq 'keys'                                   # secret/, transit-dr-broker/, database/
vault read -format=json transit-dr-broker/keys/circuit-breaker-key | jq '.data | {exportable, deletion_allowed, type}'
#   -> exportable=false, deletion_allowed=false, type=aes256-gcm96
curl -sS "$VAULT_ADDR/v1/sys/health" -o /dev/null -w '%{http_code}\n'          # 200 on the leader, 429 on standbys
```

Fail-over test: stop the leader process; `vault operator raft list-peers` must show a new leader
within 10 s and `sys/health` must answer on the remaining nodes.

### 1.2 Import the existing IdP / CI keys (no session impact)

The keys are copied, not rotated: the IdPs see no change and no active user session is affected.

```bash
deploy/vault/scripts/import-static-secrets.sh entra-client-secret okta-api-token ad-bind-password \
    github-dispatch-token gitlab-trigger-token jenkins-api-token webhook-hmac-secret
```

Values are typed at a hidden prompt and written to `secret/coc/<name>` (field `value`).

**Verify** (metadata only – never print values):

```bash
vault kv metadata get -format=json secret/coc/okta-api-token | jq '.data.current_version'
OPS=$(vault token create -policy=oplia-control-plane -ttl=5m -field=token)
vault token capabilities "$OPS" secret/data/coc/okta-api-token       # read
vault token capabilities "$OPS" sys/policies/acl/x                    # deny
```

Deploy or switch the control plane to Vault (`deploy/control-plane`, ConfigMap `oplia-vault` from
`examples/vault/vault.env.example`), migrate the schema first:

```bash
kubectl -n oplia-system wait --for=condition=complete job/oplia-migrate --timeout=5m
kubectl -n oplia-system rollout restart deploy/oplia-api && kubectl -n oplia-system rollout status deploy/oplia-api
curl -sSf "$OPLIA/readyz"                                             # {"status":"ready"}
auth "$OPLIA/jit/roles" | jq length                                   # IdP-backed endpoints answer
```

Production start-up refuses to run unless `OPLIA_SECRET_PROVIDER=vault` and an `https://` Vault address are set.

### 1.3 FinOps scanner – passive audit first

```bash
kubectl -n oplia-system create job finops-audit-1 --from=cronjob/oplia-finops-audit   # suspended CronJob, runs --audit
kubectl -n oplia-system logs -f job/finops-audit-1
```

`--audit` reads inventories of all four clouds, prints findings and writes nothing (no tags, no DB
rows, no alerts). Check that every configured cloud and account appears in the output and that the
non-compliant resources match a sample checked by hand. Only then let the scheduled `oplia-finops-scan` CronJob run
(it records findings and alerts, it never changes cloud resources); keep `OPLIA_DRY_RUN=true` for the
optimizer CronJobs.

**Gate 1**: Vault HA healthy and fail-over tested; control plane ready on Vault; audit run lists all
clouds; no stop condition fired.

**Rollback 1**: set `OPLIA_SECRET_PROVIDER` back to the previous provider and restart (the KV copies are
harmless). The audit run changed nothing, so there is nothing to undo.

---

## Phase 2 – Workload identity, one cloud at a time

Order: **one cluster per cloud, one namespace, one canary Deployment**, then the rest of that cloud,
then the next cloud (AWS → Azure → GCP → IBM). A problem stays inside one cloud's network path.

### 2.1 Per cluster

```bash
kubectl apply -f deploy/vault/k8s/token-reviewer.yaml                  # vault-auth SA + system:auth-delegator
kubectl -n vault-auth get secret vault-auth-reviewer -o jsonpath='{.data.token}' | base64 -d > /secure/aws-reviewer.jwt
kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > /secure/aws-ca.pem
export K8S_AWS_HOST=https://<api-server> K8S_AWS_CA_FILE=/secure/aws-ca.pem K8S_AWS_REVIEWER_JWT_FILE=/secure/aws-reviewer.jwt
deploy/vault/scripts/vault-k8s-auth.sh       # clouds without variables are skipped and reported
deploy/vault/scripts/vault-roles.sh          # app-prod (app-service-account/production), oplia-control-plane
```

Database engine (once, before the first workload): run the prerequisite SQL in
`deploy/vault/server/README.md` (PostgreSQL 16 needs `createrole_self_grant`), then
`deploy/vault/scripts/vault-database.sh`.

**Verify the auth path from inside the cluster** (a throwaway pod with the app's service account):

```bash
kubectl -n production run vault-login-test --rm -i --restart=Never --image=hashicorp/vault:2.2.1 \
  --overrides='{"spec":{"serviceAccountName":"app-service-account"}}' --env VAULT_ADDR=$VAULT_ADDR -- \
  sh -c 'vault write -field=token_policies auth/kubernetes-aws/login role=app-prod jwt=@/var/run/secrets/kubernetes.io/serviceaccount/token'
# -> [app-database-access default]
```

### 2.2 Canary: env vars → Vault agent file

1. Deploy the overlay for the cloud with **one** replica of each base image (Alpine, Ubuntu, Distroless):
   ```bash
   kustomize build deploy/apps/overlays/aws | kubectl apply -f - --dry-run=server
   kustomize build deploy/apps/overlays/aws | kubectl apply -f -
   ```
2. The application must read `/vault/secrets/db.env` and fall back to nothing (no static env var):
   remove the old `PG*` environment variables in the same change so a broken injection fails loudly.

**Validation matrix** (run for each of `checkout-alpine`, `checkout-ubuntu`, `checkout-distroless`):

```bash
D=checkout-alpine
kubectl -n production rollout status deploy/$D --timeout=5m
POD=$(kubectl -n production get pod -l app.kubernetes.io/name=$D -o jsonpath='{.items[0].metadata.name}')
kubectl -n production get pod $POD -o jsonpath='{.spec.initContainers[*].name} {.spec.containers[*].name}{"\n"}'
#   -> vault-agent-init ... app otel-collector vault-agent
kubectl -n production logs $POD -c vault-agent-init | grep -i 'rendered'             # template rendered
kubectl -n production logs $POD -c vault-agent --tail=20                              # no auth errors / renew failures
kubectl -n production exec $POD -c vault-agent -- ls -ln /vault/secrets/db.env        # mode -r--------, owner = app UID
```

Distroless has no shell in the app container – check the file through the `vault-agent` container (same
volume) and confirm the app's own readiness probe and DB connection metrics instead.

```bash
vault list sys/leases/lookup/database/creds/app-prod-postgres     # one lease per running pod
kubectl -n production delete pod $POD                             # lease must disappear (revoke-on-shutdown)
```

**Telemetry checks**

- Prometheus: `max(vault_core_handle_request{quantile="0.99"}) < 50` and
  `sum(rate(vault_core_handle_request_count[5m]))` rising with the canary.
- Datadog: the pods appear with `env:production service:<name> version:<v>`; the OpenMetrics check
  reports metrics under the configured namespace.
- Dynatrace: process groups of the canary pods show OneAgent code modules injected; no new problems
  (`GET $DT_URL/api/v2/problems?problemSelector=status("OPEN")` with an `Api-Token` header).
- OTel: `kubectl -n production logs $POD -c otel-collector` shows no exporter errors.

Then scale the cloud's workloads in steps (25 % → 50 % → 100 % of replicas migrated), checking the
stop conditions for 30 min at each step, then move to the next cloud.

**Gate 2**: all three base images pass the matrix in every cloud; one lease per pod; leases revoked
on pod deletion; Vault p99 < 50 ms; no stop condition fired for 24 h.

**Rollback 2**: `kubectl rollout undo deploy/<name>` restores the env-var version (keep the old static
secret until Gate 2 is passed). Vault roles can stay; they grant nothing until a pod logs in.

---

## Phase 3 – DR channel and replication circuit breaker

Order per engine: PostgreSQL → MySQL → MongoDB → CockroachDB. Start in **active-passive**: the DR
copy receives changes but serves no traffic.

1. Create the CDC sources (`deploy/dr/cdc/*.json` for Debezium, `deploy/dr/sql/02-dr-changefeed.sql`
   for CockroachDB). They write to the CDC topic; DR consumers read only the DR topic.
2. Deploy one breaker per stream (`deploy/dr/breaker`, ConfigMaps `oplia-dr-<stream>` and
   `oplia-vault`), with `OPLIA_DRY_RUN=true` first: trips are recorded and alerted, the lock step (C)
   only reports what it would do.
3. Leave it for **at least one business week** to learn the rate baseline (rows in the last minute
   vs the average of the previous 5 minutes; trip above +500 %, with the volume floor).

**Verify**

```bash
auth "$OPLIA/dr/breakers" | jq '.[] | {stream, state, incident_id}'   # CLOSED, no incident
auth "$OPLIA/dr/incidents" | jq length                                 # 0 in normal operation
kubectl -n oplia-system logs deploy/oplia-dr-breaker-orders --tail=50   # decoded records, no undecodable warnings
```

End-to-end drill on a **staging** stream:

```bash
psql "$STAGING_SOURCE" -c "CREATE TABLE oplia_drill(id int); DROP TABLE oplia_drill;"
auth "$OPLIA/dr/breakers" | jq '.[] | select(.stream=="staging-pg") | .state'    # "OPEN"
auth "$OPLIA/dr/incidents" | jq '.[0] | {trigger, summary, dump_sha256, protection: .actions.dump_protection}'
auth -X POST "$OPLIA/dr/breakers/staging-pg/reset" -H 'Content-Type: application/json' \
     -d '{"decision": "discard", "unlock_targets": true, "note": "rollout drill"}'
```

False positives: if a legitimate batch job trips the rate rule, raise the volume floor or the
multiplier for that stream (`examples/dr/dr.env.example`) – do not disable the signature rules.
Lag: Debezium `MilliSecondsBehindSource`, CockroachDB `changefeed_max_behind_nanos`, plus the
breaker consumer group's lag on the CDC topic must stay below 2 s.

Then disable dry-run per stream (`OPLIA_DRY_RUN=false`), one engine at a time.

**Gate 3**: every stream CLOSED and advancing; the staging drill tripped, quarantined an encrypted
dump, locked the DR target read-only and reset cleanly; lag < 2 s; no false positive for a week.

**Rollback 3**: point DR consumers back at the CDC topic (bypass) and scale the breaker to 0. The source
offsets are only committed after the DR topic acknowledged, so no change is lost.

---

## Phase 4 – Anycast / global load balancer cutover

OPLIA does not configure the global load balancer; this phase is executed with the provider's own
tools. Keep the existing cloud-native DNS records unchanged as the fallback path.

1. Put the global load balancer (Cloudflare Load Balancing / Magic Transit or AWS Global Accelerator)
   in front of the existing public endpoints with health checks on each cloud's `/healthz`.
2. Shift traffic in steps: **10 % → 25 % → 50 % → 100 %** through the global entry point; within it,
   cloud weights move from the current primary (e.g. 90/10) towards 25/25/25/25. Example for AWS
   Global Accelerator:
   ```bash
   aws globalaccelerator update-endpoint-group --endpoint-group-arn "$EG_ARN" --traffic-dial-percentage 10
   ```
3. Hold each step at least 30 min (the 100 % step 24 h). Before every increment:
   ```bash
   for c in aws azure gcp ibm; do curl -sS -o /dev/null -w "$c %{http_code} %{time_total}\n" "https://$c.app.example.com/healthz"; done
   ```
   and all of these green: the PromQL stop conditions above, the Datadog monitors on
   `trace.*.errors` / `trace.*.hits` for `env:production` and p99 per service, and no open Dynatrace
   problem for the affected services.

**Gate 4**: 100 % through the global entry point for 24 h with all monitors green.

**Rollback 4**: set the dial/weights back to the previous step (seconds); in an emergency send clients
back to the unchanged DNS records.

---

## Phase 5 – Enable automated remediation and destruction tests

1. Drift remediation (Phase 1 pipelines): keep `OPLIA_REQUIRE_APPROVAL=true` and four-eyes. Fire a
   test drift event in a **non-production** stack and follow the proposal:
   ```bash
   auth "$OPLIA/proposals?status_filter=PENDING" | jq '.[0] | {id, action_type, target, expires_at}'
   auth -X POST "$OPLIA/proposals/$ID/approve" -d '{"note":"drill"}' -H 'Content-Type: application/json'   # second person
   auth -X POST "$OPLIA/proposals/$ID/execute"
   ```
   Confirm that the GitHub Actions / GitLab CI / Jenkins run started, used credentials from Vault
   (AppRole roles `github-actions`, `gitlab-ci`, `jenkins`) and converged the stack.
2. AIOps, FinOps optimizer, JIT sweep: switch each from dry-run to execution separately, one per week.
3. Autonomous mode (no approval) in production is refused unless `OPLIA_ALLOW_AUTONOMOUS_IN_PROD=true`
   is set explicitly; it is not part of this rollout.

**Chaos / validation list** (run in staging, then in one production cloud in a maintenance window):

| Test | Expected result |
|---|---|
| Kill the Vault leader | new leader < 10 s; pods keep their rendered credentials; agents re-authenticate |
| Revoke a pod's DB lease (`vault lease revoke <id>`) | the agent fetches new credentials; app reconnects |
| Delete a breaker pod while OPEN | restarts OPEN, re-reads the held records, nothing forwarded until reset |
| Kill switch on | every executor stops; proposals stay pending; `GET /audit/verify` intact |
| Black-hole one cloud at the load balancer | traffic moves to the others; stop conditions stay green |

**Emergency rollback protocol**

1. Engage the kill switch (command above).
2. Revert the current phase with its rollback step.
3. If a DR breaker is OPEN: inspect `GET /dr/incidents`, decide `release` or `discard` with a second
   approver; unlock targets only after the decision.
4. Record the incident; `GET /audit/verify` must be intact before the kill switch is released:
   ```bash
   auth -X POST "$OPLIA/kill-switch" -H 'Content-Type: application/json' -d '{"engaged": false, "reason": "incident <id> closed"}'
   ```
