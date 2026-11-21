# Cross-cloud DR plane

```
                 synchronous (Raft quorum)                       asynchronous DR channel
  ┌────────── CockroachDB cluster spanning 4 clouds ──────────┐
  │ AWS us-east-1 ─ Azure eastus2 ─ GCP us-central1 ─ IBM us-south │──changefeed──▶ Kafka cdc.* ──▶ oplia-dr-breaker ──▶ Kafka dr.* ──▶ standby / DR copies
  └───────────────────────────────────────────────────────────┘                     ▲                    │ trip
  PostgreSQL / MySQL / MongoDB primaries ──Debezium─────────────────────────────────┘                    ▼
                                                                         A sever  B alert+dump  C lock DR targets read-only
```

## What each layer protects against

| Failure | Protected by | RPO |
|---|---|---|
| node, zone, region or an entire cloud lost | CockroachDB `SURVIVE REGION FAILURE` across 4 clouds (`sql/01-multi-region.sql`) | 0 (quorum commit) |
| logical corruption (DROP, TRUNCATE, mass UPDATE/DELETE, write-rate spike, ransomware) | asynchronous DR copies behind `oplia-dr-breaker` | DR copy stays at the last good bundle |

**Important:** inside one CockroachDB cluster every committed write - including a `DROP TABLE` - is
already on all clouds when it commits; nothing can be intercepted between clouds there. The
breaker protects the **separate, asynchronous** copies (changefeeds / Debezium to standby systems).
Keep at least one such copy plus regular backups (`BACKUP ... INTO` to object storage in another
cloud) - quorum replication is not a backup.

## Contents

* `cockroachdb/base` + `overlays/{aws,azure,gcp,ibm}` - StatefulSet (3 nodes per cloud, TLS, non-root,
  zone spread, PDB, NetworkPolicy), per-cloud SSD StorageClass (`Retain`) and locality, and a
  `ServiceExport` so nodes are reachable across clouds as
  `<pod>.<cloud>.cockroachdb.oplia-data.svc.clusterset.local`.
  **Prerequisites not included here:** private connectivity between the four clouds (VPN or
  interconnect) and a Multi-Cluster Services implementation (e.g. Submariner Lighthouse);
  node certificates (`cockroach cert create-node` with the clusterset DNS names as SANs) in the
  secret `cockroachdb-node-certs`; after the first start run `cockroach init` once.
* `sql/` - multi-region placement and the DR changefeed.
* `cdc/` - Debezium connector configs for PostgreSQL, MySQL and MongoDB (`skipped.operations: none`
  so TRUNCATE events reach the breaker; MySQL schema changes carry the DDL text).
* `breaker/` - the `oplia-dr-breaker` Deployment (one per stream, quarantine volume).

## Validation status

`kustomize build` + `kubeconform -strict` (Kubernetes 1.30 schemas) pass for all four overlays and
the breaker (the `ServiceExport` CRD is skipped: no schema in the core set). Nothing here has been
applied to a real cluster. The CockroachDB tag `v25.4.21` was verified to exist in the source
repository; the container registry was not reachable from the build environment - pin the image
by digest when you deploy. The SQL was not executed against CockroachDB.

## Engine notes for the breaker

* PostgreSQL logical replication (`pgoutput`) does not carry DDL - a `DROP TABLE` on the source is
  not replicated by it at all; statement-level detection needs statement text (format `sql`, e.g.
  from pgaudit) - row events and TRUNCATE are seen through Debezium.
* MongoDB change streams show `drop` / `dropDatabase` and one `delete` per document (caught by the
  rate rule); an unconstrained `deleteMany({})` as a *command* is only visible in a command feed
  (format `mongo_command`, e.g. from the profiler or audit log).
* A CockroachDB changefeed with `schema_change_policy = 'stop'` stops on schema changes such as
  `DROP TABLE`, so they never reach the DR side through the feed.
