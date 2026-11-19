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
pip install -e ".[dev,postgres]"
ruff check src tests migrations && mypy && bandit -r src -q
pytest                                                     # SQLite
OPLIA_TEST_DATABASE_URL=postgresql+psycopg://... pytest    # PostgreSQL, schema built by migrations
OPLIA_DATABASE_URL=postgresql+psycopg://... alembic upgrade head && alembic check
uvicorn oplia_ctl.main:app --port 8080                     # API
oplia-soar-exporter                                        # SOAR daemon
oplia-iac-lifecycle                                        # TTL scan (CronJob)
```

## What is and is not verified

Verified in this repository (and re-run by `.github/workflows/control-plane-ci.yml`):
lint (ruff), strict type checking (mypy), security scan (bandit), 85 tests on SQLite **and**
PostgreSQL 16 with the schema built by Alembic, migration up/down and model-drift check.
External APIs are exercised with mocks: GitHub/GitLab/Jenkins/SIEM via HTTP mocks, AWS via
moto, Azure and Kubernetes via fakes; the Azure request bodies were checked against the real
SDK serializer.

**Not yet verified against live systems**: real GitHub/GitLab/Jenkins instances, a real SIEM,
real AWS/Azure accounts, a real Kubernetes/OpenShift cluster, and the pipeline templates
running on their CI platforms. The Docker image is built in CI, not in the authoring
environment. These need your DEV environment and credentials.

Operational notes: AWS security groups are stateful (established connections can persist);
the Kubernetes policy needs a CNI that enforces NetworkPolicy; a proposal left in `EXECUTING`
after a crash is not auto-retried and must be reviewed manually.
