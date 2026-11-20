# OPLIA Control Plane

Production backend for the OPLIA multi-cloud platform. It turns detections (infrastructure
drift, runtime threats, and in later phases AIOps alerts, FinOps findings, access expiry and
replication anomalies) into **guarded actions**: every change to real infrastructure,
identities or data passes through one safety gate.

> Status: **Foundation + Phase 1 of 7** (drift remediation, SOAR export, containment).
> Phases 2–7 are tracked in the PR description and are not implemented yet.

## Safety model (applies to every phase)

| Control | Default | What it does |
|---|---|---|
| `OPLIA_DRY_RUN` | `true` | Approved actions record what they *would* do; nothing is changed |
| `OPLIA_REQUIRE_APPROVAL` | `true` | Nothing executes without an explicit approval |
| `OPLIA_FOUR_EYES` | `true` | The approver must differ from the requester |
| Kill switch | off | `POST /kill-switch` blocks all execution immediately |
| Proposal TTL | 60 min | Stale proposals/approvals expire and cannot run |
| At-most-once | always | Execution is claimed with a compare-and-set; concurrent workers cannot double-run |
| Audit log | always | Append-only, SHA-256 hash-chained; `GET /audit/verify` detects tampering |

`OPLIA_ENVIRONMENT=prod` refuses to start with SQLite, without OIDC, or in autonomous mode
(no approval + no dry-run) unless `OPLIA_ALLOW_AUTONOMOUS_IN_PROD=true` is set explicitly.

## Admin console

`console/` is the web console (React + TypeScript): proposals, kill switch, audit log, DR breakers,
FinOps, JIT access, AIOps. Sign-in with Entra ID / Okta (OIDC + PKCE); the API enforces every
permission. See `console/README.md` to run it locally with the dev login.

## Compute inventory and power actions

`oplia-inventory-scan` (CronJob every 30 min) reads compute resources from the FinOps inventory
sources (EC2, Azure VMs/scale sets/AKS, GCE/GKE via Cloud Asset, IBM VPC instances/clusters) into
`inventory_instances`; size and state are stored only where the listing API returns them (EC2 type
and state, GCP asset state) - otherwise empty, never guessed. A machine is marked gone only if its
source answered completely. `GET /inventory/instances` (filters `cloud`, `region`, `state`) serves the
console **Infrastructure** screen. Start/stop is a gated proposal (`compute.power`): AWS
Start/StopInstances, Azure start/deallocate, GCP instances.start/stop, IBM VPC instance actions.
Tested with moto (AWS) and fakes/respx (Azure, GCP, IBM); not run against real accounts.

## Database registry and health

Databases are declared in `OPLIA_DATABASES` (JSON list, example `examples/databases/databases.example.json`):
name, engine (`postgres`, `mysql`, `mongodb`, `cockroachdb`), cloud, role (`primary`/`dr`/`replica`),
`dr_of` (the source of a DR copy) and `dsn_secret` - the *name* of the secret holding the connection
string (Vault `secret/data/coc/<name>`); it never appears in API responses, and connection errors are
scrubbed of the DSN and password. `oplia-db-health` (CronJob, every 5 min) and `POST /databases/{name}/check`
(operator/approver, audited) run read-only checks: version, role (primary/standby/replica/secondary),
read-only flag and replication state/lag per engine. Console: **Databases**. Tested against real
PostgreSQL 16 and MySQL 8 servers in CI; MongoDB and CockroachDB with fakes of their status commands.

## DR consistency checks

For every DR copy (`dr_of`), `oplia-db-consistency` (CronJob, hourly) and `POST /databases/{name}/consistency`
compare source and copy read-only: schema (tables, columns, types, nullability; MongoDB collections and
indexes), row/document counts, **chunked checksums** (keyset pagination by primary key; same-engine pairs;
tables without a primary key or above `OPLIA_CONSISTENCY_CHECKSUM_MAX_ROWS` are compared by count only, and
the report says so) and replication lag. A table that differs is re-checked once after
`OPLIA_CONSISTENCY_RECHECK_DELAY_SECONDS` (the source keeps changing). If the DR breaker is OPEN the report
says differences are expected and no proposal is raised. Otherwise data/schema drift raises a `dr.resync`
proposal for same-engine pairs (PostgreSQL, MySQL, CockroachDB, MongoDB; PostgreSQL<->CockroachDB is
refused): it refuses a read-only (locked) target and any schema difference, pauses replication into the
copy (PostgreSQL subscriptions, MySQL SQL thread, CockroachDB `LOGICAL REPLICATION` jobs, and any Kafka Connect
sink connectors listed in the target's `pause_connectors`), replaces each drifted table in one transaction
(CockroachDB: refused above `OPLIA_CONSISTENCY_CHECKSUM_MAX_ROWS`) and verifies the checksum before reporting
success. MongoDB collections are copied into a temporary collection with the source's indexes, verified, and
swapped in with `renameCollection` (`dropTarget`); the target must be a writable primary. Results: `GET /databases/consistency`, audit event
`dr_consistency_check`, console **Databases -> DR consistency**. Tested against real PostgreSQL 16 and MySQL 8
(drift, recheck, resync, locked target, schema drift); resync also against real MongoDB 7.0 and
CockroachDB 24.3 containers in CI (drift, resync, indexes, read-only target, size limit); pausing CockroachDB
logical replication jobs is not exercised (no LDR job runs in the single-node test cluster).

## Try it locally with a login (development only)

`oplia-dev-idp` is a local OIDC login (authorization code + PKCE) so the API - and the admin
console - can be used on a laptop without an Entra ID / Okta tenant. It starts only with
`OPLIA_ENVIRONMENT=dev`, listens on 127.0.0.1, signs with a key generated in memory, and a
production API refuses any `http://` issuer. Test users: `alice` (approver), `bob` (operator),
`carol` (both), `dave` (no role).

```bash
export OPLIA_ENVIRONMENT=dev
oplia-dev-idp                                   # terminal 1, http://127.0.0.1:8090
export OPLIA_DATABASE_URL=sqlite:///./oplia-dev.db
export OPLIA_OIDC_ISSUER=http://127.0.0.1:8090/ OPLIA_OIDC_AUDIENCE=oplia-api
export OPLIA_OIDC_JWKS_URL=http://127.0.0.1:8090/jwks OPLIA_SECRET_WEBHOOK_HMAC_SECRET=local-test-secret
uvicorn oplia_ctl.main:app --port 8080         # terminal 2
```

## Phase 1 components

* **Drift auto-remediation** – `POST /webhooks/drift` (HMAC-signed, replay-protected,
  deduplicated by `X-OPLIA-Delivery`) creates a `drift.remediate` proposal. Once approved and
  executed, the CI/CD driver factory dispatches the configured pipeline:
  * GitHub Actions – `repository_dispatch`
  * GitLab CI – pipeline trigger token
  * Jenkins – `buildWithParameters` with CSRF crumb
  
  Targets (repo / project / job) are fixed in configuration; a webhook can never redirect the
  control plane to another URL. All values are validated against strict patterns so they cannot
  carry shell metacharacters into pipelines.
* **Pipeline templates** (`pipelines/`) for the *infrastructure* repository: Terraform with
  locked remote state (S3 + DynamoDB or Azure Blob lease), `plan` unattended, `apply` of the
  reviewed plan file only, behind a protected environment / manual job / `input` step. Cloud
  credentials use OIDC federation on GitHub and GitLab (no static keys). Actions are pinned to
  verified commit SHAs.
* **SOAR exporter** – follows Falco JSON output (or `POST /webhooks/runtime-threat` for
  falcosidekick), exports every event to a SIEM (Splunk HEC or generic HTTPS JSON) with a
  dead-letter file, and for confidence **> 0.85** with a resolvable resource records an
  isolation proposal. Falco has no native confidence: an upstream `confidence` field is used
  when present, otherwise a documented priority mapping (`soar/events.py`).
* **Containment executors** (run only through the gate):
  * AWS – move all ENIs of an instance into a no-ingress/no-egress quarantine SG, then
    re-read the ENIs and fail loudly if the change did not take effect
  * Azure – attach a deny-all NSG (priority 100) to the NIC
  * Kubernetes – deny-all NetworkPolicy; refuses `kube-*`, `default`, `openshift-*`

## Phase 2 components

* **Remote state backends** (`terraform/modules/`, bootstrap root in `terraform/examples/state-backends`):
  * AWS – S3 bucket (versioned, SSE-KMS with a rotating key, public access blocked, TLS-only
    policy, noncurrent-version expiry) and a DynamoDB lock table (PITR, KMS, deletion protection)
  * Azure – StorageV2 account (TLS 1.2, shared keys disabled / Entra ID only, infrastructure
    encryption, blob versioning and soft delete, network rules default Deny, `CanNotDelete`
    lock, optional blob audit logs to Log Analytics) and a private container. Locking is the
    azurerm backend's native blob lease – there is no separate switch to enable.
  * Eight checkov findings are skipped in code with a written reason each (e.g. cross-region
    replication and private endpoints are caller decisions).
* **TTL lifecycle manager** – `oplia-iac-lifecycle`, intended to run as a CronJob. It reads
  resources tagged `LifecycleTTL` (`15m`…`90d`) plus `CreatedAt` (ISO-8601 with timezone),
  `OpliaBlueprint` and `OpliaZone` from the AWS Resource Groups Tagging API and Azure Resource
  Manager, groups them into stacks, and for every expired stack records an `iac.destroy`
  proposal. It never deletes anything itself: after approval the same CI/CD drivers dispatch the
  pipeline with `OPERATION=destroy`, which runs `plan -destroy` and applies only that reviewed plan.
  * stacks containing a resource tagged `Environment=prod|production|prd` are never proposed
  * stacks with inconsistent tags, unknown blueprints or unsupported clouds are skipped and reported
  * one open proposal per stack; a new attempt is proposed only after the previous one EXPIRED or
    FAILED; a REJECTED stack is not proposed again
  * the pipelines refuse `destroy` unless the repository/project/job variable
    `OPLIA_ALLOW_DESTROY=true` is set – leave it unset for production infrastructure
  * configuration: `OPLIA_LIFECYCLE_AWS_REGIONS`, `OPLIA_LIFECYCLE_AZURE_SUBSCRIPTIONS`
    (JSON lists), `OPLIA_LIFECYCLE_TARGET_CICD`; exit code 2 when any source failed

## Phase 3 components – AIOps self-healing

* **Alert intake** – `POST /webhooks/aiops/alert` (HMAC-signed, normalised JSON) and
  `POST /webhooks/aiops/alertmanager` (native Prometheus Alertmanager webhook, bearer token from the
  secret `alertmanager_webhook_token`). Alerts carry one root-cause metric plus correlated metrics.
  Alerts for another cluster (`OPLIA_AIOPS_CLUSTER_NAME`) or a protected namespace are refused.
* **Mapping matrix** (`aiops/matrix.py`, replaceable via `OPLIA_AIOPS_MATRIX_PATH`; first match wins):

  | Root cause | Action |
  |---|---|
  | p99 latency > 800 ms **and** DB connections ≥ 90 % | runbook `db-connection-pool-flush` |
  | p99 latency > 800 ms **and** CPU throttling > 25 % (HPA present) | HPA adjustment |
  | CPU throttling > 25 % (HPA present) | HPA adjustment |
  | CPU throttling > 25 % (no HPA) | notify only – limits must change in the manifest |
  | p99 latency > 800 ms, no correlated cause | rolling restart |
  | memory working set ≥ 90 % of limit, or OOM kills | runbook `memory-cache-clear` |
  | disk I/O wait > 30 % | runbook `iops-optimize` |

* **Executors** (run only through the safety gate):
  * rolling restart – the same patch as `kubectl rollout restart` (Deployment/StatefulSet/DaemonSet)
  * HPA – at `maxReplicas`: raise it by a step, never above the ceiling (default +2, ceiling 50);
    below max: lower the CPU utilisation target by a step, never below the floor (default −10, floor 40 %).
    The patch carries `resourceVersion` (concurrent edits fail instead of being overwritten) and the
    result is re-read and verified.
  * runbooks – Kubernetes Jobs from an operator-defined registry (`OPLIA_AIOPS_RUNBOOKS_PATH`): image
    pinned by digest, fixed command, allowed namespaces, credentials only via Kubernetes Secret
    references; non-root, read-only root FS, no capabilities, deadline, no retries. Alerts never
    supply commands. Examples: `examples/aiops/runbooks.example.json` (digests must be filled in –
    placeholders are rejected on load). The control plane refuses to start AIOps if the matrix names
    a runbook that is not registered.
* **PagerDuty and Slack before acting** – the incident is sent when the proposal is created
  (`opened`) and again immediately **before** the executor acts (`pre_action`); the result follows
  on Slack. If no channel accepts the pre-action message the action is not taken and the proposal
  is FAILED (`OPLIA_AIOPS_REQUIRE_PRE_ACTION_NOTIFICATION`, default true). PagerDuty Events API v2
  de-duplicates per workload and rule. Secrets: `pagerduty_routing_key`, `slack_webhook_url`.
* **De-duplication** – one open proposal per workload and rule; repeats do not page again; after a
  final state a new proposal is allowed only after the cool-down (default 30 min).
* **Predictive escalation** – `POST /webhooks/aiops/prediction` accepts risks predicted within the
  next 4 hours. The escalation matrix routes them ahead of time:

  | Severity | Sent before predicted time | Channels | Min. probability |
  |---|---|---|---|
  | critical | 240 min | PagerDuty + Slack | 0.50 |
  | high | 120 min | PagerDuty + Slack | 0.60 |
  | medium | 60 min | Slack | 0.60 |
  | low | 30 min | Slack | 0.75 |

  `oplia-aiops-escalator` (daemon, or `--once` as a CronJob) sends due predictions. Claims are
  compare-and-set (safe with several replicas); failed channels are retried with back-off, delivered
  ones are not repeated; after 5 attempts the row is FAILED; a prediction whose time passed while the
  scheduler was down is marked EXPIRED, not sent late. Delivery is at-least-once.
* **Monitoring examples** – `examples/aiops/prometheus-rules.example.yaml` (with a `promtool` unit
  test) and `alertmanager-receiver.yaml`; both are checked in CI with `promtool` / `amtool`.

## Phase 4 components – FinOps tag compliance and cost optimisation

* **Tag compliance scanner** – `oplia-finops-scan` (CronJob). Inventories compute, storage and
  database resources and checks the exact, case-sensitive tags `Owner`, `CostCenter`, `Environment`:
  * AWS – EC2 instances, EBS volumes, S3 buckets, RDS instances/clusters, DynamoDB tables (service
    APIs, so never-tagged resources are found too)
  * Azure – VMs, scale sets, AKS, managed disks, storage accounts, SQL databases/managed instances,
    PostgreSQL/MySQL flexible servers, Cosmos DB, Redis
  * GCP – Cloud Asset Inventory (instances, GKE, disks, buckets, Cloud SQL, AlloyDB, Spanner,
    Bigtable, Memorystore). **GCP label keys can only be lowercase**, so `owner` / `costcenter` /
    `environment` labels satisfy the policy on GCP (configurable); Resource Manager tags with the
    exact short names also count
  * IBM Cloud – Global Search and Tagging API v3 (`key:value` user tags), queries configurable
  * Each problem is classified as *missing*, *wrong case* (e.g. `owner` on AWS – reported, not
    accepted) or *invalid* (empty value, or Environment outside `allowed_environments`)
* **Compliance log database** – `finops_compliance_findings` (one row per non-compliant resource,
  OPEN → RESOLVED as *tagged* or *resource not found*, never deleted) and `finops_compliance_scans`.
  Findings of a cloud whose scan failed are left untouched. API: `GET /finops/findings`,
  `GET /finops/scans`.
* **Operations-desk alert** – one digest per scan with the new findings (Slack by default,
  PagerDuty optional); known findings do not alert again, regressions do.
* **Audit (dry-run) mode** – `oplia-finops-scan --audit` prints the non-compliant resources and
  writes and sends nothing. The scanner never changes cloud resources in either mode.
* **Cost-optimisation policy engine** – `oplia-finops-optimize observe` records idle resources
  (unattached EBS volumes, unassociated Elastic IPs, unattached Azure disks, GCP disks without
  users) with the time first seen idle; after the grace period (default 7 days) it proposes a
  clean-up in the safety gate (proposal lifetime 8 days so it survives until a weekly window).
  `oplia-finops-optimize window` executes **approved** clean-ups inside the configured maintenance
  windows only; outside a window the API answers 409 and the proposal stays approved.
  Executors re-check the live state, **snapshot disks first and delete only after the snapshot
  completed**, and never touch resources tagged `OpliaRetain` or with a protected `Environment`.
  API: `GET /finops/candidates`. Example settings: `examples/finops/finops.env.example`.

## Phase 5 components – just-in-time privileged access (Entra ID, Okta, Active Directory)

* **Schema** – `jit_access_requests` with the document's fields (`user_id`, `requested_role`,
  `target_cloud_account`, `expiration_minutes`, `approval_status`) plus grant/revoke state.
* **Role catalog** (`OPLIA_IDENTITY_CATALOG_PATH`, example `examples/identity/jit-roles.example.json`):
  each role maps to one Entra group or directory role (`role:<roleDefinitionId>`), one Okta group or
  admin role (`role:SUPER_ADMIN`…), or one AD group DN, with allowed accounts and a maximum duration.
  Requesters can only ask for catalog roles; one open request or active grant per user and group.
* **Flow** – `POST /jit/requests` → safety-gate proposal → `POST /jit/requests/{id}/approve` by an
  approver who is **not the requester** → membership added and verified → `expires_at` set.
  Dry-run and the kill switch apply to grants. A grant whose membership cannot be verified is undone.
* **Worker** – `oplia-jit-worker` runs every 60 s: removes expired memberships, verifies they are
  gone, writes `jit_revoked` to the hash-chained audit log. Revocation bypasses approval and the kill
  switch (it only reduces privilege); failures are retried every tick and alert PagerDuty/Slack after
  3 attempts. Every 15 min it reports members of catalog groups **without** an active grant
  (standing access); `OPLIA_IDENTITY_REMOVE_STANDING_MEMBERS=true` removes them (break-glass accounts
  go in `OPLIA_IDENTITY_STANDING_ALLOWLIST`).
* **Drivers**
  * Entra ID – Microsoft Graph v1.0 over HTTPS (client credentials): `members/$ref`, role
    assignments, `checkMemberGroups` for verification (transitive), `accountEnabled=false`.
  * Okta – Users/Groups/Roles API (`SSWS` token), `lifecycle/suspend` (reversible).
  * Active Directory – **python-ldap**, LDAPS or StartTLS only with certificate verification,
    `MOD_ADD`/`MOD_DELETE` on `member`, transitive check (`LDAP_MATCHING_RULE_IN_CHAIN`), range
    retrieval for large groups, paged searches, `ACCOUNTDISABLE` bit.
  Tokens are only ever sent to the provider's own host (pagination links to other hosts are refused).
* **90-day sweep** – `oplia-identity-sweep` (daily): enabled accounts whose latest sign-in (or
  creation, if never) is older than 90 days → one `identity.disable_inactive` proposal per directory.
  Exempt accounts are skipped; Entra users synchronised from AD are reported but not disabled in
  Entra (disable them in AD); more than `OPLIA_IDENTITY_SWEEP_MAX_PER_RUN` (25) in one directory trips
  a circuit breaker (nothing proposed, alert sent). Each account is re-checked when executed (anyone
  who signed in meanwhile is skipped). With approval switched off the sweep disables immediately.
* Settings: `examples/identity/identity.env.example`. Secrets: `entra_client_secret`,
  `okta_api_token`, `ad_bind_password`.

## Phase 6 components – cross-cloud DR and replication circuit breaker

* **DR plane** (`deploy/dr/`, design in `deploy/dr/README.md`): CockroachDB spanning AWS, Azure,
  GCP and IBM Cloud (3 nodes per cloud, `SURVIVE REGION FAILURE`), plus an **asynchronous DR
  channel** (CockroachDB changefeed and Debezium for PostgreSQL/MySQL/MongoDB -> Kafka).
  Within one CockroachDB cluster a committed `DROP TABLE` is on every cloud at once - nothing can be
  intercepted there; the breaker protects the asynchronous DR copies.
* **`oplia-dr-breaker`** (one process per stream): CDC topic -> inspect -> DR topic. DR consumers read
  only the DR topic. Decoders for SQL text (sqlglot: keywords inside string literals are not
  commands), Debezium envelopes, MongoDB change events and BSON commands, CockroachDB changefeed
  messages; undecodable records are treated as suspicious.
* **Signatures**: DROP TABLE/DATABASE/SCHEMA, TRUNCATE, UPDATE/DELETE without WHERE, Mongo
  `deleteMany`/`updateMany` with an empty filter, `drop`, `dropDatabase`; **rate**: row mutations in
  the last minute > 6x the average of the previous 5 minutes (+500 %), with a volume floor
  (default 1000) and 5-minute warm-up.
* **On a trip**: **A** the bundle is withheld, the destination connection closed and consumption
  stopped - the source position is not committed, so nothing is lost; **B** the complete bundle is
  written to a 0600 quarantine file and POSTed to incident webhooks (HMAC-signed), PagerDuty/Slack get
  a critical summary with the dump's SHA-256; **C** every DR target is switched to read-only and
  verified - PostgreSQL (`ALTER SUBSCRIPTION ... DISABLE`, database `default_transaction_read_only`,
  other sessions terminated), MySQL (`STOP REPLICA`, `SET PERSIST super_read_only`), MongoDB
  (`fsync` lock), CockroachDB (`ALTER ROLE ALL IN DATABASE ... SET default_transaction_read_only`).
  C honours dry-run. Every step is in the audit chain.
* **Reset** (`POST /dr/breakers/{stream}/reset`, approver): `release` forwards the held bundle,
  `discard` skips it; optional unlock of exactly what was locked. A relay restarted while OPEN
  re-reads the held records and applies the decision by source position.
* Kafka: consumer without auto-commit and `read_committed`; producer idempotent with `acks=all`;
  the source is committed only after the destination acknowledged.
* Settings: `examples/dr/dr.env.example`. MySQL lock account needs `SYSTEM_VARIABLES_ADMIN`,
  `REPLICATION_SLAVE_ADMIN`, `REPLICATION CLIENT`.

## Phase 7 components – Vault security engine, workload identity and rollout

* **Vault driver** (`src/oplia_ctl/vault.py`, the document's `vault_secrets_driver`): AppRole
  (`role_id`/`secret_id` read from files) or Kubernetes auth (projected service-account token);
  token renewal before expiry and one re-login on 403; KV v2; Transit encrypt/decrypt/HMAC/verify;
  dynamic database credentials and lease revocation. Only `https://` (plain HTTP is a local-dev
  switch that production start-up refuses). Tokens and values never appear in logs or errors.
* **`VaultSecretProvider`** (`OPLIA_SECRET_PROVIDER=vault`): every secret name used by Phases 1–6
  resolves to `secret/data/coc/<name>` field `value` (the existing OPLIA paths), cached briefly.
  **Production requires it**: `prod` refuses to start with environment secrets or a non-https Vault.
* **DR circuit breaker + Transit**: with `OPLIA_DR_TRANSIT_KEY=circuit-breaker-key` incident dumps
  are encrypted (`transit-dr-broker`) with an HMAC and SHA-256 integrity envelope; webhooks receive
  the envelope, never plaintext (if encryption fails the plaintext stays only in the 0600 local file
  and webhooks get a summary). `OPLIA_DR_SIGN_BUNDLES=true` adds an `oplia-hmac` header (Transit HMAC)
  to every record forwarded to the DR topic.
* **Vault deployment** (`deploy/vault/`): server config (Raft HA, TLS, KMS auto-unseal), policies
  `app-database-access`, `oplia-control-plane`, `ci-runner` (least privilege, explicit denials of
  administrative paths), scripts `vault-bootstrap.sh` (idempotent), `vault-database.sh` (PostgreSQL,
  MySQL, MongoDB dynamic credentials), `vault-k8s-auth.sh` (`auth/kubernetes-aws|azure|gcp|ibm`,
  token reviewer, host, CA), `vault-roles.sh` (`app-service-account`/`production` -> 60 min tokens,
  24 h max; AppRoles for GitHub Actions, GitLab CI, Jenkins and the daemons),
  `import-static-secrets.sh` (Entra/Okta/AD/CI keys, typed at a hidden prompt).
  **PostgreSQL 16+ prerequisite**: `ALTER ROLE vault_admin SET createrole_self_grant = 'set, inherit'`,
  otherwise lease revocation cannot drop the users Vault created (`deploy/vault/server/README.md`).
* **Workloads** (`deploy/apps/`): Alpine, Ubuntu and Distroless Deployments with the Vault Agent
  injector (credentials file `/vault/secrets/db.env`, 0400, owned by the app UID, lease revoked on
  shutdown), Prometheus annotations, Datadog unified tags + OpenMetrics check, Dynatrace OneAgent
  injection and an OpenTelemetry collector sidecar; one overlay per cloud.
* **Control plane on Kubernetes** (`deploy/control-plane/`): API (2 replicas, PDB, probes), migration
  Job, workers, CronJobs (including a suspended read-only FinOps audit), all logging in to Vault with a
  projected 1-hour token; the DR breaker manifest uses the same pattern.
* **Rollout runbook** (`docs/rollout-runbook.md`): five phases with verification commands, gates,
  stop thresholds (5xx > 0.01 %, crash loops, replication lag > 2 s, Vault p99 > 50 ms) and rollback.
* Settings: `examples/vault/vault.env.example`.

## Integrations status

`GET /integrations` (operator or approver) contacts each configured connection once and reports
`ok`, `configured` (secret present but no safe read-only probe), `error` (with the scrubbed error) or
`not_configured`. Secret *names* are listed; secret values are never returned or logged.
Covered: AWS (STS), Azure, GCP, IBM Cloud, GitHub, GitLab, Jenkins, console OIDC sign-in (JWKS),
Entra ID, Okta, Active Directory, Slack, PagerDuty, SIEM and Vault.

`POST /integrations/{name}/test` (approver only) sends one labelled test notification to Slack,
PagerDuty (an info-severity event that is resolved immediately with the same dedup key) or the SIEM
sink, and is recorded in the audit log as `integration_test_notification`. The console screen is
"Integrations". Validated with respx/fakes only; not run against real Slack, PagerDuty or cloud accounts.

## Network layer

* **Global entry** – `terraform/modules/aws-global-accelerator` (flow logs on, health checks on
  `/healthz`, one endpoint group per cloud). Terraform sets the initial traffic dial only.
* **Traffic dial** – `POST /network/endpoint-groups/{key}/traffic-dial` creates a
  `network.traffic_dial` proposal; after approval an operator executes it (UpdateEndpointGroup in
  us-west-2, then read back). Step limit, hold time and health are checked at proposal and again at
  execution; decreases are always allowed. History in `network_dial_changes` (migration 0008).
* **Interconnects** – `equinix-fabric-cloud-connections` and `megaport-cloud-vxcs` (redundant legs)
  to AWS Direct Connect, Azure ExpressRoute, GCP Partner Interconnect and IBM Direct Link, with the
  accepting sides `aws-dx-hosted-accept`, `azure-expressroute-circuit`, `gcp-partner-interconnect`,
  `ibm-direct-link-approve`; wiring in `terraform/examples/network`. Providers pinned: aws 6.72.0,
  azurerm 5.13.0, google 8.10.0, ibm 2.9.0, equinix 5.3.0, megaport 1.26.3.
* **Meshes** – Consul 2.1.0 and Linkerd edge 2026.10.2 (`deploy/mesh/`).
* **Status** – `GET /network/status` and the console "Network" screen: endpoint groups and health,
  Direct Connect connections/VIFs/BGP (`OPLIA_NETWORK_DX_REGIONS`), Consul peerings
  (`OPLIA_NETWORK_CONSUL_ADDR`, token by secret name), Linkerd `Link` resources
  (`OPLIA_NETWORK_LINKERD_LINKS=true`, needs list on `links.multicluster.linkerd.io`).

Validated: `terraform validate` of every module and the example root, checkov, Helm rendering +
kubeconform (CI); the API and executor with botocore Stubber (requests checked against the AWS API
model), respx and fakes. **Not validated: anything against a real AWS, Azure, GCP, IBM, Equinix or
Megaport account, or a real cluster.**

## DR replication (AWS, Azure, GCP)

Console screen **DR replication**; API under `/dr/replication`; settings `OPLIA_REPLICATION_*`;
tables from migration 0009. Every change is a proposal (approve by a second person, execute by an
operator). Key material never moves: data is re-encrypted on arrival with the *target* cloud's key.

| Sub-item | What it does | How it is verified here |
|---|---|---|
| Database CDC pipelines | Kafka Connect status (connector + task state, failure trace); `dr.pipeline` proposals to pause / resume / restart failed tasks; state re-read afterwards. Works with the existing Debezium configs and DR circuit breaker. | respx against the Kafka Connect REST API |
| VM images | AWS AMI → Azure (ExportImage RAW → fixed VHD page blob, footer built per the VHD spec, padded to whole MiB → managed image with disk encryption set); AWS AMI → GCP (RAW → `disk.raw` GNU tar.gz → images.insert with Cloud KMS key); Azure snapshot/disk → AWS (read-only SAS, footer validated, ImportImage with KMS key, access revoked also on failure); Azure → GCP (footer stripped); Azure *blob* VHD (unmanaged page blob in an allow-listed storage account, `azure_source_accounts`) → AWS / GCP for **fixed, dynamic and differencing** VHDs (range reads; dynamic and differencing disks expanded to the raw disk; a differencing disk's parent is looked up in the same folder and must carry the UUID the child records). Managed snapshots/disks are always fixed VHDs and still go through the SAS path. SHA-256 of the raw disk computed while streaming and re-checked on the staged copy before the image is created. `dr.image_replicate` proposal queues a job; CronJob `oplia-dr-image-worker` advances it one persisted step at a time. | botocore Stubber (EC2 requests checked against the API model), moto S3, fakes for Azure/GCP SDKs; **qemu-img** reads our VHDs and converts them back to identical bytes, our reader expands qemu-written dynamic VHDs to the same bytes as `qemu-img convert -O raw`; differencing chains are compared with libyal's **libvhdi** (one difference observed: libvhdi returns zeros for sectors 1-3 when only sector 0 of the first block is written in the child; that case is checked against the specification); the **tar** CLI extracts our archives byte-identically |
| Object storage | S3 ↔ Blob ↔ GCS, incremental via a manifest (etag + size), source re-checked at copy time, SHA-256 while streaming plus read-back of the target, target-side key (SSE-KMS / Key Vault-backed encryption scope / Cloud KMS), mapped tags. Deletions are reported and never copied automatically; a pair can opt in with `replicate_deletions: true` (default false), then `POST /dr/replication/objects/{pair}/deletions` proposes a `dr.object_delete` (four-eyes, kill switch) that re-checks each key is still gone at the source, refuses batches above `max_delete_fraction` (default 10%) of the replicated objects, and removes the manifest rows. CronJob `oplia-dr-object-plan` creates proposals. | moto S3 (SSE-KMS and tags checked on the written object), fakes for Blob/GCS plus checks of the exact SDK arguments |
| Keys and tags | Key references validated per cloud and purpose (`keys.py`); tags mapped with AWS / Azure limits and GCP label rules (lowercase, `[a-z0-9_-]`, ≤ 63, start with a letter, ≤ 64 labels); every rename, truncation, collision and drop reported; preview endpoint in the console. | unit tests |

### DR jobs and restore drills

Console screen **DR jobs & drills**; API `GET /dr/jobs`, `GET /dr/jobs/{kind}/{id}`,
`POST /dr/jobs/{kind}` (body `{"params": {...}, "reason": "..."}`); table `dr_jobs` (migration 0010);
CronJob `oplia-dr-job-worker` advances every queued job one persisted step at a time (a restart
resumes at the saved step). Each module describes its own form fields, so new DR job types appear in
the console without console changes.

| Module | What it does | How it is verified here |
|---|---|---|
| Restore drill (`dr.restore_drill`, `OPLIA_REPLICATION_DRILLS`) | Boots a replicated image in a configured sandbox subnet with **no public IP** (AWS `RunInstances` with IMDSv2 required and an idempotency token; Azure NIC + VM from a managed image or gallery version, SSH key only, OS disk and NIC `delete_option=Delete`; GCP `instances.insert` without an access config, boot disk auto-deleted). Waits for running (AWS: both status checks `ok`), then runs `tcp:PORT` / `http:PORT/PATH=STATUS` checks from the control plane against the private IP, retried until `check_window_seconds`. **Always tears the instance down**, also after a boot timeout or failed checks, and waits until it is gone. Ends with a `dr_restore_drill` audit event: verdict, boot time, per-check result, teardown. The control plane needs network reach to the sandbox subnet. | botocore Stubber (EC2 requests checked against the API model), fakes receiving the real Azure / GCP SDK model objects, the probe tested against real local TCP/HTTP servers; worker restart and timeout paths tested |
| Container image copy (`dr.registry_copy`, `OPLIA_REPLICATION_REGISTRIES`) | Copies a tag or digest between configured registry pairs (ECR, ACR, Artifact Registry or any OCI registry) over the OCI Distribution API, no Docker daemon. Multi-platform indexes are followed to every child manifest; each blob is HEAD-checked at the target and otherwise streamed and uploaded with its digest, SHA-256 computed while streaming; manifests are written byte-for-byte (same digest) and read back by tag and digest. Saved progress per blob, at most `max_blobs_per_run` per run. Auth: ECR `GetAuthorizationToken`, ACR Entra token → `/oauth2/exchange` refresh token, Artifact Registry `oauth2accesstoken`, or `user:password` from the secret store; Bearer challenges answered at the realm (https only for remote registries). Only tags matching the pair's `tag_pattern` can be proposed. `dr_registry_copy` audit event. | Against **real CNCF Distribution 3.0.0 registries** started by the tests: the source with htpasswd (Basic) and the target with token auth (a local token server signing RS256 JWTs with an x5c chain), images pushed and copies re-read with plain httpx and every blob re-hashed; a tampered source blob is refused and not stored; resume across fresh worker processes; ECR/ACR/GAR credential exchanges with botocore Stubber and httpx mock transports |

**Not supported, by design or not built:** GCP as an image *source* (Compute Engine has no API that
returns image bytes; `gcloud compute images export` uses a Cloud Build workflow).

**Other DR gaps, not built in this PR:** Kubernetes workload/volume backup and restore (e.g. Velero); Vault replication (Vault
Enterprise performance/DR replication or OpenBao equivalents); DNS failover records outside Global
Accelerator; translation of firewall rules / security groups / IAM between clouds; file-share
replication (EFS / Azure Files / Filestore); message queue replication other than Kafka.

**Not validated:** nothing in this section was run against a real AWS, Azure or GCP account or a
real Kafka Connect cluster.

## API

| Method | Path | Auth |
|---|---|---|
| GET | `/healthz`, `/readyz` | none |
| POST | `/webhooks/drift`, `/webhooks/runtime-threat` | HMAC (`X-OPLIA-Timestamp`, `X-OPLIA-Signature`) |
| GET | `/proposals`, `/proposals/{id}` | OIDC: operator or approver |
| POST | `/proposals/{id}/approve`, `/reject` | OIDC: approver |
| POST | `/proposals/{id}/execute` | OIDC: operator |
| GET | `/me` | OIDC: any signed-in user (subject, roles, what the console may offer) |
| GET | `/kill-switch` | OIDC: operator or approver |
| POST | `/kill-switch` | OIDC: approver |
| GET | `/audit/events` | OIDC: approver (newest first; `before_seq`, `limit`, `proposal_id`) |
| GET | `/audit/verify` | OIDC: approver |
| POST | `/webhooks/aiops/alert`, `/webhooks/aiops/prediction` | HMAC |
| POST | `/webhooks/aiops/alertmanager` | bearer token (`alertmanager_webhook_token`) |
| GET | `/aiops/predictions` | OIDC: operator or approver |
| GET | `/finops/findings`, `/finops/scans`, `/finops/candidates` | OIDC: operator or approver |
| GET/POST | `/jit/roles`, `/jit/requests` | OIDC: operator or approver |
| POST | `/jit/requests/{id}/approve`, `/reject`, `/grant` | OIDC: approver (not the requester) |
| POST | `/jit/requests/{id}/revoke` | OIDC: approver or the requester |
| GET | `/dr/breakers`, `/dr/incidents` | OIDC: operator or approver |
| POST | `/dr/breakers/{stream}/trip`, `/reset` | OIDC: approver |
| POST | `/aiops/predictions/{id}/cancel` | OIDC: operator or approver |

## Configuration

Settings are `OPLIA_*` environment variables (`src/oplia_ctl/config.py`). Secrets are referenced
by **name** and resolved at runtime (`OPLIA_SECRET_<NAME>` in dev; Vault `secret/data/coc/<name>` in
stg/prod, `OPLIA_SECRET_PROVIDER=vault`, see `examples/vault/vault.env.example`). Key ones:

```
OPLIA_ENVIRONMENT=prod
OPLIA_DATABASE_URL=postgresql+psycopg://...
OPLIA_OIDC_ISSUER / OPLIA_OIDC_AUDIENCE / OPLIA_OIDC_JWKS_URL / OPLIA_OIDC_ROLES_CLAIM
OPLIA_CICD__GITHUB_REPOSITORY=owner/infra-repo      # or GITLAB_PROJECT_ID / JENKINS_URL + JENKINS_JOB
OPLIA_SOAR_SIEM_ENDPOINT=https://...  OPLIA_SOAR_SIEM_FORMAT=splunk_hec|generic
secrets: webhook_hmac_secret, github_dispatch_token, gitlab_trigger_token,
         jenkins_user, jenkins_api_token, siem_token
```

## Run and test

```bash
pip install -e ".[dev,postgres,gcp,ad,dr]"   # ad needs libldap/libsasl2 headers
ruff check src tests migrations && mypy && bandit -r src -q
pytest                                                     # SQLite
OPLIA_TEST_DATABASE_URL=postgresql+psycopg://... pytest    # PostgreSQL, schema built by migrations
OPLIA_DATABASE_URL=postgresql+psycopg://... alembic upgrade head && alembic check
uvicorn oplia_ctl.main:app --port 8080                     # API
oplia-soar-exporter                                        # SOAR daemon
oplia-iac-lifecycle                                        # TTL scan (CronJob)
oplia-aiops-escalator [--once]                             # predictive escalation
oplia-finops-scan [--audit]                                # tag compliance (CronJob)
oplia-finops-optimize observe|window                       # idle clean-up (CronJobs)
oplia-jit-worker [--once]                                  # JIT revocation every 60 s
oplia-identity-sweep                                       # 90-day inactive accounts (CronJob)
oplia-dr-breaker                                           # DR circuit breaker (one per stream)
scripts/test-openbao.sh DIR                                # throwaway OpenBao for the Vault tests
VAULT_CLI=bao scripts/test-vault-deploy.sh                 # deploy/vault scripts end to end
shellcheck scripts/*.sh deploy/vault/scripts/*.sh
```

## What is and is not verified

Verified in this repository (and re-run by `.github/workflows/control-plane-ci.yml`):
lint (ruff), strict type checking (mypy, Python 3.12 and 3.13), security scan (bandit), shellcheck, 330 tests on PostgreSQL 16 with the schema built by Alembic (326 on SQLite; 4 need PostgreSQL), with real OpenLDAP, MySQL 8.0 and OpenBao 2.5.3 test servers, migration up/down and model-drift check, `kustomize` + `kubeconform -strict` for every manifest.
External APIs are exercised with mocks: GitHub/GitLab/Jenkins/SIEM via HTTP mocks, AWS via
moto, Azure and Kubernetes via fakes; the Azure request bodies were checked against the real
SDK serializer.

**Phase 3 not yet verified live**: no real Kubernetes API server (fakes with the official
`kubernetes` client models), no real PagerDuty/Slack (HTTP mocks of the documented APIs), the example
runbook images/digests are placeholders, and the Prometheus rules use common exporter metric names
that must be matched to yours. Runbook Jobs are started, not awaited – their outcome is in the Job
status/logs, not in the proposal result.

**Phase 4 not yet verified live**: AWS calls run against moto (the real boto3 SDK and request
shapes); Azure and GCP against fakes (the Azure snapshot body was checked with the real SDK
serializer); IBM against HTTP mocks of the documented Global Search API. The default IBM queries
(e.g. `service_name:databases-for-*`) must be checked against your account (`"fields": ["*"]`).
Cost figures are not calculated: candidates show size only.

**Phase 5 not yet verified live**: the AD driver ran against a **real OpenLDAP server** over LDAPS
(grant, verify, revoke, idempotency, paged search, bad password, untrusted certificate) but not
against Active Directory itself - the AD-only parts (transitive membership rule, range retrieval,
`userAccountControl`, `lastLogonTimestamp`) are tested with a fake connection. Entra ID and Okta
were tested with HTTP mocks of the documented endpoints. Entra `signInActivity` needs an Entra ID
P1/P2 licence and `AuditLog.Read.All`.

**Phase 6 not yet verified live**: the read-only locks ran against **real PostgreSQL 16 and
MySQL 8.0** (lock, verify, writes refused, unlock); MongoDB and CockroachDB lockers are tested with
fakes. Kafka was not run - the Kafka adapter is tested with fakes of the confluent-kafka API. The
CockroachDB manifests pass `kustomize` + `kubeconform -strict` but were not applied to a cluster,
and the SQL was not executed against CockroachDB.

**Phase 7 not yet verified live**: the Vault driver, policies, scripts and the agent template ran
against **OpenBao 2.5.3** (the open-source fork that implements the Vault HTTP API), not HashiCorp
Vault: AppRole and Kubernetes-auth logins (Kubernetes via a TLS TokenReview endpoint in the test),
KV v2, Transit (encryption, HMAC, tamper detection), effective policy capabilities, dynamic
PostgreSQL credentials (login, wrong password refused, revocation leaves no user behind), every
`deploy/vault` script run twice (idempotent), and a real `bao agent` rendering the injector template
into working credentials. Not run: `vault-server.hcl` (needs TLS and KMS), the MySQL/MongoDB parts of
`vault-database.sh`, the injector in a real cluster, Datadog/Dynatrace agents, and the global load
balancer steps of the runbook (provider tools, not OPLIA code). OpenBao refuses enabling audit
devices through the API; `vault-bootstrap.sh` then prints a warning and the audit device must be in
the server configuration.

**Not yet verified against live systems**: real GitHub/GitLab/Jenkins instances, a real SIEM,
real AWS/Azure accounts, a real Kubernetes/OpenShift cluster, and the pipeline templates
running on their CI platforms. The Docker image is built in CI, not in the authoring
environment. These need your DEV environment and credentials.

Operational notes: AWS security groups are stateful (established connections can persist);
the Kubernetes policy needs a CNI that enforces NetworkPolicy; a proposal left in `EXECUTING`
after a crash is not auto-retried and must be reviewed manually.
