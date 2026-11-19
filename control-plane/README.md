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

## API

| Method | Path | Auth |
|---|---|---|
| GET | `/healthz`, `/readyz` | none |
| POST | `/webhooks/drift`, `/webhooks/runtime-threat` | HMAC (`X-OPLIA-Timestamp`, `X-OPLIA-Signature`) |
| GET | `/proposals`, `/proposals/{id}` | OIDC: operator or approver |
| POST | `/proposals/{id}/approve`, `/reject` | OIDC: approver |
| POST | `/proposals/{id}/execute` | OIDC: operator |
| POST | `/kill-switch` | OIDC: approver |
| GET | `/audit/verify` | OIDC: approver |
| POST | `/webhooks/aiops/alert`, `/webhooks/aiops/prediction` | HMAC |
| POST | `/webhooks/aiops/alertmanager` | bearer token (`alertmanager_webhook_token`) |
| GET | `/aiops/predictions` | OIDC: operator or approver |
| GET | `/finops/findings`, `/finops/scans`, `/finops/candidates` | OIDC: operator or approver |
| GET/POST | `/jit/roles`, `/jit/requests` | OIDC: operator or approver |
| POST | `/jit/requests/{id}/approve`, `/reject`, `/grant` | OIDC: approver (not the requester) |
| POST | `/jit/requests/{id}/revoke` | OIDC: approver or the requester |
| POST | `/aiops/predictions/{id}/cancel` | OIDC: operator or approver |

## Configuration

Settings are `OPLIA_*` environment variables (`src/oplia_ctl/config.py`). Secrets are referenced
by **name** and resolved at runtime (`OPLIA_SECRET_<NAME>` in dev; Vault in Phase 7). Key ones:

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
pip install -e ".[dev,postgres,gcp,ad]"   # ad needs libldap/libsasl2 headers
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
```

## What is and is not verified

Verified in this repository (and re-run by `.github/workflows/control-plane-ci.yml`):
lint (ruff), strict type checking (mypy), security scan (bandit), 236 tests on SQLite and 237 on PostgreSQL 16 (one concurrency test runs only on PostgreSQL) with the schema built by Alembic, migration up/down and model-drift check.
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

**Not yet verified against live systems**: real GitHub/GitLab/Jenkins instances, a real SIEM,
real AWS/Azure accounts, a real Kubernetes/OpenShift cluster, and the pipeline templates
running on their CI platforms. The Docker image is built in CI, not in the authoring
environment. These need your DEV environment and credentials.

Operational notes: AWS security groups are stateful (established connections can persist);
the Kubernetes policy needs a CNI that enforces NetworkPolicy; a proposal left in `EXECUTING`
after a crash is not auto-retried and must be reviewed manually.
