# CloudOps Console (COC) – dummy prototype

A clickable, **mock-data-only** prototype of every module in the CloudOps Console feature map.
No build step, no backend, no cloud credentials – just open `index.html` in a browser.

```bash
open prototype/index.html          # or: cd prototype && python3 -m http.server 8080
```

## What's in it (19 modules + feature map)

| Phase | Modules |
|---|---|
| 1 | Multi-Cloud Dashboard · CMDB · Cloud Connectors · OpenShift Module |
| 2 | Alerting Engine · Security & Vulnerability · FinOps & Cost Intelligence · Certificate & Secret Mgmt |
| 3 | IaC Generator · Cloud Configurator · Compliance & Governance · IAM Governance · Observability · Image & SBOM Governance · Pipeline & Deployment Tracking |
| 4 | AIOps · Incident & Change Mgmt · Capacity Planning · Backup & DR |

Every module has working interactions against in-memory data, e.g. run CMDB discovery, build an alert rule,
generate Terraform/Ansible (blocked by an OPA-style policy gate if you un-tick *Encrypt*), run scans, apply
rightsizing, execute a runbook, approve a change, promote/roll back a deployment.

* **Tenant switcher** (header) filters data per client – multi-tenancy preview.
* **Role switcher** (header) – Platform Admin, Cloud Engineer, Ops/SRE, Client Viewer, Auditor. Write buttons lock for
  read-only roles and modules the role cannot open are denied.
* **Audit trail** (Compliance → Audit trail) records every action you take in the session; exportable to CSV.
* Light/dark theme toggle.

## Files

```
prototype/
  index.html        shell
  css/styles.css    theme tokens + components
  js/core.js        router, RBAC, modal/toast, escaped html`` templating, SVG charts
  js/data.js        all mock data (seeded RNG → stable between reloads)
  js/m-*.js         the modules, grouped by area
```

All interpolated values go through an escaping `h` template tag, so user-entered text (rule names, asset names…) is rendered safely.

## Not real (yet)

Everything is mocked – no FastAPI, PostgreSQL/TimescaleDB, Redis, MinIO, OIDC, Helm or cloud SDK calls. After approval the final
version replaces `data.js` with the real API and builds on the Phase-1 scaffold (FastAPI + React/TS + Helm + Tekton).
