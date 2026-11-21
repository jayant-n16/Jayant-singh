# Zero-downtime migration engine

What the engine in `src/oplia_ctl/migration/` does for each requirement of the PRD ("Universal Zero-Downtime
Migration Engine"), what it does not do, and the vendor documentation each design decision rests on.

## Departures from the PRD (decided with the requester)

* **Orchestration:** the existing control-plane job runner and safety gate are used instead of Temporal
  (PRD section 4). Every step that changes something is a proposal (propose -> approve by someone else ->
  execute), and the `oplia-dr-job-worker` CronJob advances each job one persisted step at a time. The kill
  switch stops the worker from advancing any job.
* **PRD section 3 (the pipeline diagram) arrived empty.** The stages were built from sections 1, 2 and 4:
  discover/synthesize (FR-01), online DDL (FR-02), backfill + CDC (FR-03), hydration (FR-04), parity
  (FR-05), cutover and reverse-CDC failback (FR-06).
* **AI:** Anthropic Claude API, Azure OpenAI, Amazon Bedrock and Vertex AI are all supported and optional.
  AI output is only ever a proposal for a person to review. Sending stored-routine code to an AI vendor is
  off unless `OPLIA_MIGRATION_AI_ALLOW_SOURCE_CODE=true`.
* **UUIDv5 instead of UUIDv4** for Spanner / DSQL key replacement: name-based UUIDs are as evenly spread as
  random ones but let CDC map every source row and every foreign key to the same UUID without a lookup table.

## Requirements: status and evidence

| Req | Built | Tested against | Not met / limits |
|---|---|---|---|
| FR-01 schema synthesis | Source from a live PostgreSQL/MySQL catalog or DDL in any SQLGlot dialect; designs for all 41 engines of the matrix; access patterns from a query log | Generated PostgreSQL and MySQL DDL executed on real servers; DynamoDB design created in moto and validated against the botocore model; DDL dry-run job on PostgreSQL (rolled back) | Non-SQL designs are documents/JSON, not applied by the engine. Stored routines: AI proposal or manual. SQLGlot's own transpiler output was not used (it produced invalid DDL for several targets - see `synthesis.py`). |
| FR-02 non-blocking online DDL | Expand / backfill / validate, separately approved contract; PostgreSQL and MySQL | Declared lock of every statement compared with `pg_locks` on PostgreSQL 16; writers kept < 1 s latency while a long transaction held the table (lock_timeout + retries); MySQL statements carry `ALGORITHM=INSTANT` or `INPLACE, LOCK=NONE` | **"Zero ACCESS EXCLUSIVE locks" is not achievable on PostgreSQL** for ADD COLUMN, CHECK NOT VALID, SET NOT NULL, RENAME, DROP COLUMN: they take ACCESS EXCLUSIVE for a catalog-only change (milliseconds). The engine bounds the wait with `lock_timeout`; `forbid_access_exclusive` refuses such operations. Ghost-table tools (gh-ost, pg-osc) are not used; type changes and renames use a trigger-synced column. |
| FR-03 CDC, p99 < 500 ms | Debezium (PG, MySQL, SQL Server, Oracle, MongoDB) + JDBC sink on Kafka Connect, AWS DMS, Datastream, Azure DMS (SQL MI); prerequisite checks; heartbeat lag probe | Lag probe over real PostgreSQL logical replication (local run: p99 7.3 ms, same server - **not** a cross-cloud figure); DMS calls against the botocore DMS model; Datastream/Azure DMS with their SDK model classes | The SLO is **measured, not guaranteed**. Datastream documents eventual consistency "within a 1-hour window" and no ordering guarantee. Datastream writes only to BigQuery/Cloud Storage. Azure DMS online for SQL Server is SQL MI / SQL VM only (SQL Database is offline only). Debezium/Kafka Connect was not run end to end in CI or locally. |
| FR-04 hydration | Sidecar: flat, document (stateful 1:N join), graph, vector (embeddings) modes; at-least-once with idempotent upserts | Real Redis and MongoDB; DynamoDB in moto; Timestream / Redshift Data API against botocore models; other SDK calls bound to the real SDK method signatures | Apache Flink (PRD section 4) is not used; the join state lives in the control-plane database. Synapse / Fabric MERGE (needs ODBC), Cosmos Table API and Vertex AI Search row writes are not shipped. |
| FR-05 parity | Exact (order-independent bucketed hashes, any SQL engines), documents, shape, vector cosine | PostgreSQL vs PostgreSQL and **PostgreSQL vs MySQL** on real servers, including located missing/extra/changed keys | "Continuous" = schedule the job; no streaming verifier. |
| FR-06 cutover, < 5 s failback, 7-day reverse CDC | Envoy TCP proxy with file-based LDS/CDS; staged shifts for read-only listeners, one-step switch for writers; reverse connector after drain; failback job | Real Envoy 1.34.4: traffic moved and moved back; local run: switch 8.6 ms, failback 7.8 ms (one host) | A listener change moves **new** connections; existing ones drain. Writes during the drain window still reach the old primary and are carried by forward CDC; conflicting writes to the same row in that window are not resolved. Failback time is measured per run, not guaranteed. Custom Envoy protocol filters for shadow reads were not built. |

## Vendor documentation used

Checked during this build (each link was opened):

* PostgreSQL table-level lock modes: https://www.postgresql.org/docs/current/interactive/explicit-locking.html
* MySQL 8.0 InnoDB online DDL: https://dev.mysql.com/doc/refman/8.0/en/innodb-online-ddl-operations.html
* Aurora DSQL unsupported features: https://docs.aws.amazon.com/aurora-dsql/latest/userguide/working-with-postgresql-compatibility-unsupported-features.html
  (no PL/pgSQL, temp tables or TRUNCATE; one DDL per transaction; 3,000 rows per transaction)
* Aurora DSQL data types: https://docs.aws.amazon.com/aurora-dsql/latest/userguide/working-with-postgresql-compatibility-supported-data-types.html
  (arrays runtime-only; JSON/JSONB columns without indexes; numeric default (18,6))
* Spanner primary keys: https://docs.cloud.google.com/spanner/docs/primary-keys-overview
* Spanner Graph schema: https://docs.cloud.google.com/spanner/docs/graph/schema-overview
* Fabric Warehouse data types: https://learn.microsoft.com/en-us/fabric/data-warehouse/data-types
* Azure AI Search vector index: https://learn.microsoft.com/azure/search/vector-search-how-to-create-index
* OpenSearch k-NN index: https://docs.opensearch.org/2.18/search-plugins/knn/knn-index
* Kusto `.create table`: https://learn.microsoft.com/en-us/kusto/management/create-table-command ;
  JSON ingestion mapping: https://learn.microsoft.com/en-us/azure/data-explorer/ingest-json-formats ;
  streaming ingestion REST: https://github.com/MicrosoftDocs/dataexplorer-docs/blob/main/data-explorer/kusto/api/rest/streaming-ingest.md
* Debezium PostgreSQL connector properties: https://docs.confluent.io/kafka-connectors/debezium-postgres-source/current/postgres_source_connector_config.html
* Debezium JDBC sink: https://debezium.io/documentation/reference/2.2/connectors/jdbc.html
* Datastream FAQ (sources, destinations, latency): https://docs.cloud.google.com/datastream/docs/faq
* Azure DMS supported scenarios: https://learn.microsoft.com/azure/dms/resource-scenario-status
* Anthropic Messages API: https://platform.claude.com/docs/en/api/messages/create?version=2023-06-01
* Azure OpenAI REST reference: https://learn.microsoft.com/azure/foundry/openai/reference and v1 API:
  https://learn.microsoft.com/azure/foundry/openai/api-version-lifecycle
* Bedrock Converse: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html ;
  Titan Text Embeddings V2: https://docs.aws.amazon.com/en_us/bedrock/latest/userguide/model-parameters-titan-embed-text.html
* Vertex AI generateContent: https://docs.cloud.google.com/vertex-ai/generative-ai/docs/reference/rest/v1/projects.locations.endpoints/generateContent ;
  text embeddings: https://docs.cloud.google.com/vertex-ai/docs/generative-ai/model-reference/text

**Not individually checked in this build** (the engine relies on their official SDKs/APIs, whose request
shapes the tests bind to, but no product page was read for limits): Aurora/RDS PostgreSQL and MySQL, Azure
SQL, Azure Database for PostgreSQL/MySQL, Cloud SQL, AlloyDB, Cosmos DB for PostgreSQL, DocumentDB, Cosmos DB
NoSQL/MongoDB/Table/Cassandra/Gremlin/vector, Firestore, DynamoDB, Bigtable, Keyspaces, ElastiCache, MemoryDB,
Azure Cache for Redis, Memorystore, Neptune, Timestream, Redshift, Synapse, BigQuery, Vertex AI Search. Their
quotas and limits must be checked before a production migration.

## Issues found in the vendors' behaviour while testing

* SQLGlot 30.x transpiles `JSONB` into MySQL/T-SQL/BigQuery DDL and `UINT`/`ENUM` into PostgreSQL DDL; the
  engine renders types from its own tables instead.
* MySQL refuses `CREATE TRIGGER` with binary logging on unless the user has SUPER or
  `log_bin_trust_function_creators=1` (error 1419); the engine checks this before EXPAND.
* `azure-kusto-ingest` 6.0.4 pins `azure-storage-blob==12.26.0`, which conflicts with the 12.31.1 used for
  object replication; ADX ingestion therefore uses the documented REST call.
* Envoy 1.34.4 did not refresh LDS when LDS and CDS watched the same directory, and the per-listener
  `version_info` in `config_dump` does not follow filesystem updates; separate directories and the
  ListenersConfigDump version plus the active routes are used.
