# Service mesh across clouds: Consul and Linkerd

Both meshes are provided; run **one per cluster** (they both inject sidecars and would conflict).
Cross-cloud traffic between meshes rides the private interconnects (Equinix Fabric / Megaport,
`terraform/modules/*`), not the internet.

| | Consul (`consul/`) | Linkerd (`linkerd/`) |
|---|---|---|
| Chart (pinned) | `hashicorp/consul` **2.1.0** from `https://helm.releases.hashicorp.com` | `linkerd-edge/linkerd-crds`, `linkerd-control-plane`, `linkerd-multicluster` **2026.10.2** (edge-26.10.2) from `https://helm.linkerd.io/edge` |
| Kubernetes | 1.30+ (validated at 1.30) | **1.31+** — the chart declares `kubeVersion: >=1.31.0-0` and refuses older clusters (found by CI) |
| Cross-cluster model | cluster peering through mesh gateways | multicluster `Link` with gateways (or flat network / federated) |
| mTLS | built-in CA, `ProxyDefaults` + default-deny `ServiceIntentions` | identity issuer from your trust anchor (generate in Vault PKI, never commit keys) |
| OPLIA status | `GET /network/status` reads `/v1/peerings` from `OPLIA_CONSUL_ADDR` | `GET /network/status` reads `Link` resources (multicluster.linkerd.io) |

## Consul

```bash
helm repo add hashicorp https://helm.releases.hashicorp.com
helm upgrade --install consul hashicorp/consul --version 2.1.0 -n consul --create-namespace \
  -f deploy/mesh/consul/values.yaml --set global.datacenter=<cloud-region>
kubectl apply -f deploy/mesh/consul/config-entries.yaml
# peering: on the accepting cluster
kubectl apply -f deploy/mesh/consul/peering-acceptor.yaml      # then copy the generated secret
```

## Linkerd

```bash
# Trust anchor + issuer from Vault PKI (pki_int) - do not create long-lived keys on a laptop.
helm repo add linkerd-edge https://helm.linkerd.io/edge
helm upgrade --install linkerd-crds linkerd-edge/linkerd-crds --version 2026.10.2 -n linkerd --create-namespace
helm upgrade --install linkerd-control-plane linkerd-edge/linkerd-control-plane --version 2026.10.2 -n linkerd \
  -f deploy/mesh/linkerd/values.yaml --set-file identityTrustAnchorsPEM=ca.crt \
  --set-file identity.issuer.tls.crtPEM=issuer.crt --set-file identity.issuer.tls.keyPEM=issuer.key
helm upgrade --install linkerd-multicluster linkerd-edge/linkerd-multicluster --version 2026.10.2 -n linkerd-multicluster \
  --create-namespace -f deploy/mesh/linkerd/multicluster-values.yaml
linkerd multicluster link-gen --cluster-name <peer> | kubectl apply -f -   # on the source cluster
```

**Validated:** CI renders every chart with these values at the pinned versions (`helm template`) and
checks the output with kubeconform. **Not validated:** installation on a real cluster, peering
between real clusters, failover over a real interconnect.
