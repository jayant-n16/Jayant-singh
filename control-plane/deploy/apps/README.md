# Application workloads with Vault workload identity and telemetry

`kustomize build deploy/apps/overlays/<aws|azure|gcp|ibm> | kubectl apply -f -`

Three Deployments, one per base image, in namespace `production` with service account
`app-service-account` (bound by the Vault Kubernetes role `app-prod`):

| Deployment | Base | App UID | Notes |
|---|---|---|---|
| `checkout-alpine` | Alpine | 10001 | |
| `checkout-ubuntu` | Ubuntu | 10001 | |
| `checkout-distroless` | Distroless (`nonroot`) | 65532 | no shell in the app container; nothing in the pod needs one |

The **Vault agent never runs inside the application image**: the injector adds `vault-agent-init`
(pre-populates the file before the app starts) and `vault-agent` (renews/re-renders) from the
`hashicorp/vault` image - a static binary - so the same annotations work on every base. The rendered
file `/vault/secrets/db.env` (`PGUSER`, `PGPASSWORD`) has mode `0400` and is owned by the app UID
(`agent-run-as-same-user`); the lease is revoked when the pod stops. The overlay only changes the
auth path (`auth/kubernetes-<cloud>`).

Telemetry per pod:

* **Prometheus/Grafana** - `prometheus.io/*` annotations on the app's `/metrics` (port 9102).
* **Datadog** - unified service tags (`tags.datadoghq.com/*`) and an Autodiscovery OpenMetrics check
  on the same endpoint. This assumes the **node Agent DaemonSet** (Datadog's recommended setup on
  EKS/AKS/GKE/IKS). A per-pod Datadog Agent sidecar is only needed on serverless nodes (EKS Fargate);
  there, add the Agent container from Datadog's Fargate instructions instead of relying on these
  annotations.
* **Dynatrace** - `oneagent.dynatrace.com/inject: "true"` (Dynatrace Operator, cloud-native full-stack
  or application-only mode must be installed in the cluster).
* **OpenTelemetry** - an `otel-collector` sidecar (`otel/opentelemetry-collector:0.163.2`, config in
  `base/otel-collector-config.yaml`) receives OTLP from the app on localhost and exports to the
  central gateway over TLS.

## Validation status

* `kustomize build` + `kubeconform -strict` (Kubernetes 1.30) for all four overlays - in CI.
* All Vault annotations were checked against the `hashicorp/vault-k8s` source; the Dynatrace
  annotation against the Dynatrace Operator source; the Datadog and OTel image tags exist.
* The `db.env` template was rendered by a real agent (OpenBao 2.5.3 `bao agent`, AppRole login) and
  the rendered credentials logged in to PostgreSQL 16.
* **Not validated**: the OTel collector configuration was not loaded by a collector binary (the
  release checksum could not be verified in the authoring environment, so the binary was not run);
  run `otelcol validate --config=...` with the pinned version before rollout. The manifests were not
  applied to a cluster, and the image names `registry.example.com/shop/...` are placeholders.
