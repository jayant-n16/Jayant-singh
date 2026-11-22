# Database disaster recovery with OPLIA: production setup

This guide sets up DR monitoring and control for PostgreSQL, MySQL, SQL Server, Oracle, MongoDB and
CockroachDB, step by step. Every statement about OPLIA below was checked against the code in this
repository; vendor statements link to the official page that was opened for this guide.

## What OPLIA does and does not do

**OPLIA does not replicate databases.** The copy from the source to the DR database is made by the
database's own replication or by a managed service (section 1). OPLIA then:

| OPLIA function | Where | Engines |
|---|---|---|
| Registers each source and its DR copy (`dr_of`) | `OPLIA_DATABASES`, or the console's **Integrations → Database list…** | all six |
| Health: connection, version, role, read-only, replication lag | CronJob `oplia-db-health` (every 5 min); **Databases → Health** | all six |
| Consistency: schema, row counts, chunked checksums, lag | CronJob `oplia-db-consistency` (hourly, minute 37); **Databases → DR consistency** | all six |
| Gated repair of drifted tables (`dr.resync` proposal: approve, then execute) | consistency check raises it; **Proposals** | PostgreSQL, MySQL, CockroachDB, MongoDB only |
| DR circuit breaker: locks the DR copy read-only when a change stream looks destructive | `oplia-dr-breaker`, `OPLIA_DR_*` (Kafka/Debezium stream) | PostgreSQL, MySQL, MongoDB, CockroachDB |
| Moving traffic to the DR site, through the gate | `dr.dns_failover` (Route 53, Traffic Manager), `network.traffic_dial` (Global Accelerator), `migration.cutover` / `migration.failback` (Envoy) | any |

**Not done by OPLIA:** promoting a standby to primary. Promotion is a database operation (section 6)
done with the vendor's tool; OPLIA records it, moves traffic through an approved proposal, and keeps
checking the new pair.

**SQL Server and Oracle: check only.** Their consistency checks run and report drift, but no
`dr.resync` proposal is raised and the console shows "no automatic resync": repair them through their
own replication (reseed the availability-group database; re-instantiate the Data Guard standby).

## 1. Choose and build the replication (outside OPLIA)

| Engine | Same-cloud / self-managed | Managed DR | Cross-cloud |
|---|---|---|---|
| PostgreSQL | Streaming replication, hot standby, promote with `pg_promote()` ([PostgreSQL 18: log-shipping standby servers](https://www.postgresql.org/docs/18/warm-standby.html)) | Aurora Global Database ([secondary clusters](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-global-database-secondary-availability.html)); Cloud SQL cross-region replica ([Cloud SQL DR](https://docs.cloud.google.com/sql/docs/mysql/intro-to-cloud-sql-disaster-recovery)) | Logical replication or Debezium → Kafka → JDBC sink (OPLIA's `dr.pipeline` / CDC module manages Kafka Connect pipelines) |
| MySQL | GTID replication, `SOURCE_AUTO_POSITION = 1` ([MySQL 8.4: GTID replication](https://dev.mysql.com/doc/refman/8.4/en/replication-gtids-howto.html)) | Aurora MySQL Global Database; Cloud SQL cross-region replica | Debezium → Kafka → JDBC sink, or AWS DMS |
| SQL Server | Always On availability group (Enterprise; Standard has Basic AG, one database) ([availability groups](https://learn.microsoft.com/sql/database-engine/availability-groups/windows/always-on-availability-groups-sql-server)); log shipping, manual failover, secondary readable only in STANDBY mode ([log shipping](https://learn.microsoft.com/en-us/sql/database-engine/log-shipping/about-log-shipping-sql-server)) | Azure SQL Database active geo-replication, up to four readable geo-secondaries, planned or forced failover ([active geo-replication](https://learn.microsoft.com/azure/azure-sql/database/active-geo-replication-overview)) | Debezium SQL Server connector (needs CDC on the source) |
| Oracle | Data Guard physical standby; switchover (planned) or failover ([Data Guard concepts](https://docs.oracle.com/en/database/oracle/oracle-database/23/sbydb/oracle-data-guard-concepts.html)) | — | Debezium Oracle connector or GoldenGate |
| MongoDB | Replica set across regions; a hidden member (priority 0) never becomes primary ([hidden members](https://www.mongodb.com/docs/manual/core/replica-set-hidden-member/)) | — | Debezium MongoDB connector |
| CockroachDB | Physical cluster replication to a standby cluster; failover is called cutover and redirecting traffic is a manual step ([PCR overview](https://docs.cockroachlabs.com/docs/v24.2/physical-cluster-replication-overview)) | — | Changefeeds |

What OPLIA can read on the DR copy depends on this choice:

* The DR copy must accept read connections for consistency checks. A PostgreSQL hot standby, a
  readable AG secondary, an Azure geo-secondary, a MongoDB secondary and a CockroachDB standby are
  readable. **An Oracle physical standby must be open read-only, which needs the separately licensed
  Active Data Guard option** (stated in the Data Guard concepts page above); a mounted standby cannot
  be checked. A log-shipping secondary is readable only in STANDBY mode, between restores.
* `dr.resync` writes to the DR copy, so it only applies to targets that accept writes (logical
  replication, Debezium/DMS sinks, or a CockroachDB/MongoDB target). On a physical standby it is
  refused because the target is read-only.

## 2. Create the OPLIA database user (least privilege)

Create the user **on the source/primary**; physical replication copies it to the standby. Each
grant below matches a query in `src/oplia_ctl/databases/registry.py` (health) and
`consistency.py` (checks). Replace the passwords with generated ones and never paste them anywhere
but Vault.

**PostgreSQL** (health reads `pg_stat_replication`, whose details need `pg_read_all_stats`, part of
`pg_monitor`; information_schema shows only tables the user can access):
```sql
CREATE ROLE oplia_dr LOGIN PASSWORD '<generated>';
GRANT pg_monitor TO oplia_dr;
GRANT CONNECT ON DATABASE app TO oplia_dr;
GRANT USAGE ON SCHEMA public TO oplia_dr;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO oplia_dr;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO oplia_dr;
```
Repeat the schema grants for every schema to check. Resync additionally needs, on a writable DR
copy only: `INSERT, DELETE` on the tables and ownership of (or superuser on) its subscriptions,
which it disables and re-enables.

**MySQL** (`SHOW REPLICA STATUS` requires `REPLICATION CLIENT`, per the
[MySQL 8.4 manual](https://dev.mysql.com/doc/refman/8.4/en/show-replica-status.html)):
```sql
CREATE USER 'oplia_dr'@'<oplia egress range>' IDENTIFIED BY '<generated>';
GRANT SELECT ON app.* TO 'oplia_dr'@'<oplia egress range>';
GRANT REPLICATION CLIENT ON *.* TO 'oplia_dr'@'<oplia egress range>';
```
Resync on a writable DR copy additionally needs `INSERT, DELETE` on the schema and
`REPLICATION_SLAVE_ADMIN` (it runs `STOP/START REPLICA SQL_THREAD`), as the CI test user has.

**SQL Server** (lag from `sys.dm_hadr_database_replica_states` needs `VIEW SERVER PERFORMANCE STATE`
on SQL Server 2022 and later, `VIEW SERVER STATE` before, per the
[DMV page](https://learn.microsoft.com/sql/relational-databases/system-dynamic-management-views/sys-dm-hadr-database-replica-states-transact-sql)):
```sql
USE master;
CREATE LOGIN oplia_dr WITH PASSWORD = '<generated>';
GRANT VIEW SERVER PERFORMANCE STATE TO oplia_dr;   -- SQL Server 2019 and earlier: VIEW SERVER STATE
USE app;
CREATE USER oplia_dr FOR LOGIN oplia_dr;
ALTER ROLE db_datareader ADD MEMBER oplia_dr;
```
Logins are server objects and are not part of the replicated database: create the login on every
replica as well (with the same SID so the database user maps; not exercised in this build's tests).

**Oracle** (the health check reads `V$DATABASE` and, on a standby, `V$DATAGUARD_STATS`, which has
rows only on the standby per the
[reference](https://docs.oracle.com/en/database/oracle/oracle-database/21/refrn/V-DATAGUARD_STATS.html);
the catalog comes from `ALL_TAB_COLUMNS`, which lists only tables the user can read):
```sql
CREATE USER oplia_dr IDENTIFIED BY "<generated>";
GRANT CREATE SESSION TO oplia_dr;
GRANT SELECT ON sys.v_$database TO oplia_dr;          -- as SYS
GRANT SELECT ON sys.v_$dataguard_stats TO oplia_dr;   -- as SYS
GRANT SELECT ON app.orders TO oplia_dr;               -- every table to check (or READ ANY TABLE, broader)
```
In `OPLIA_DATABASES`, `database` is the **owner** (schema) to compare, e.g. `APP`.

**MongoDB** (`replSetGetStatus` is used for lag; MongoDB's built-in `clusterMonitor` role is the
documented holder of that action — the access-control part of the command page did not load for
this guide, so confirm it on your version):
```javascript
db.getSiblingDB("admin").createUser({user: "oplia_dr", pwd: "<generated>",
  roles: [{role: "read", db: "app"}, {role: "clusterMonitor", db: "admin"}]})
```
Resync replaces collections (`renameCollection` with `dropTarget`) on a writable primary target only;
that needs `readWrite` on the DR database.

**CockroachDB** (`SHOW CHANGEFEED JOBS` needs `VIEWJOB`, `admin`, `CONTROLJOB`, or `CHANGEFEED` on the
tables, per [SHOW JOBS](https://docs.cockroachlabs.com/docs/v26.3/show-jobs)):
```sql
CREATE USER oplia_dr WITH PASSWORD '<generated>';
USE app;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO oplia_dr;   -- syntax from the CockroachDB GRANT page
GRANT SYSTEM VIEWJOB TO oplia_dr;
```

## 3. Store each DSN in Vault

One secret per database at `secret/data/coc/<dsn_secret>`, field `value` (KV v2 mount `secret`,
prefix `coc`, set in `src/oplia_ctl/vault.py`). DSN formats accepted by the registry:

| Engine | DSN |
|---|---|
| PostgreSQL, CockroachDB | `postgresql://oplia_dr:<pw>@host:5432/app?sslmode=verify-full` |
| MySQL | `mysql://oplia_dr:<pw>@host:3306/app` |
| SQL Server | `sqlserver://oplia_dr:<pw>@host:1433/app` |
| Oracle | `oracle://oplia_dr:<pw>@host:1521/<service_name>` |
| MongoDB | `mongodb://oplia_dr:<pw>@host1,host2/?replicaSet=rs0&tls=true` |

```bash
vault kv put secret/coc/orders_dr_dsn value='sqlserver://oplia_dr:...@dr-sql.example.internal:1433/app'
```
Or enter the values in the console (step 4): they are written only to Vault, never to the OPLIA
database. Without Vault (`OPLIA_SECRET_PROVIDER=env`) the console cannot save secrets; set
`OPLIA_SECRET_<NAME>` environment variables instead.

## 4. Register the pair

Each DR copy names its source in `dr_of`. Allowed values: `engine` = postgres, mysql, mongodb,
cockroachdb, sqlserver, oracle; `cloud` = aws, azure, gcp, ibm, onprem; `role` = primary, dr, replica.

```json
[
  {"name": "orders-sql", "engine": "sqlserver", "cloud": "azure", "role": "primary",
   "dsn_secret": "orders_sql_dsn", "database": "app"},
  {"name": "orders-sql-dr", "engine": "sqlserver", "cloud": "azure", "role": "dr", "dr_of": "orders-sql",
   "dsn_secret": "orders_sql_dr_dsn", "database": "app"},
  {"name": "billing-ora", "engine": "oracle", "cloud": "onprem", "role": "primary",
   "dsn_secret": "billing_ora_dsn", "database": "APP"},
  {"name": "billing-ora-dr", "engine": "oracle", "cloud": "aws", "role": "dr", "dr_of": "billing-ora",
   "dsn_secret": "billing_ora_dr_dsn", "database": "APP"}
]
```

Two ways to apply it:

* **Console:** sign in as an approver, open **Integrations**, click **Database list…** (top right),
  paste the list and enter each DSN secret. This creates a proposal; another approver approves it and
  an operator executes it. It applies at once in the API that executed it; **the CronJobs and other
  API replicas read settings at start-up, so restart them** (the console says so).
* **Config:** set `OPLIA_DATABASES` in the `oplia-config` ConfigMap, which the API and every CronJob
  load, and roll them out.

Optional, for pairs repaired through Kafka Connect: `pause_connectors` lists the sink connectors to
pause during a resync.

## 5. Network and the schedules

* Allow the OPLIA API and CronJob pods to reach each database port (5432, 3306, 1433, 1521, 27017,
  26257) on both sites, and nothing else; use TLS in the DSN. Kubernetes egress is controlled by your
  NetworkPolicy (the shipped `deploy/control-plane/console.yaml` NetworkPolicy covers API ingress only).
* CronJobs in `deploy/control-plane/cronjobs.yaml`, enabled (`suspend: false`) as shipped:
  * `oplia-db-health`: every 5 minutes.
  * `oplia-db-consistency`: hourly at minute 37. Tuning: `OPLIA_CONSISTENCY_RECHECK_DELAY_SECONDS`
    (30), `_CHECKSUM_CHUNK_ROWS` (5000), `_CHECKSUM_MAX_ROWS` (5,000,000; larger tables are compared by
    count only), `_MAX_TABLES` (500), `_MAX_LAG_SECONDS` (60).
* For the DR breaker (PostgreSQL, MySQL, MongoDB, CockroachDB fed by Debezium/Kafka), configure
  `OPLIA_DR_*` as in the README.

## 6. Verify

1. **Databases → Health → Check now** on both rows: both CONNECTED; the DR row shows its role
   (standby / secondary / replica) and lag. Lag sources: PostgreSQL `pg_last_xact_replay_timestamp()`,
   MySQL `Seconds_Behind_Source`, MongoDB optime difference, CockroachDB changefeed high-water mark,
   SQL Server `secondary_lag_seconds` read **on the primary** (Microsoft documents it from the
   primary's side), Oracle `apply lag` from `V$DATAGUARD_STATS` on the standby.
2. **Databases → DR consistency → Run check** on the DR row: CONSISTENT. **Report** lists each table
   with rows, checksum, and "Compared on". A table whose columns differ is still compared on the
   columns both sides share, so changed data is never hidden behind a schema difference.
3. Drift on PostgreSQL, MySQL, CockroachDB or MongoDB raises one `dr.resync` proposal; repeated checks
   of the same drift reuse it while it is pending or approved.
4. **Audit log** shows `dr_consistency_check` events.

## 7. Fail over and fail back

1. **Freeze writes**: put the application in maintenance, or let the DR breaker lock the target.
2. **Check lag** on **Databases → Health** for the DR row, and run a consistency check if the source is
   still up.
3. **Promote with the vendor's tool** (OPLIA has no promote action): `pg_promote()`; MySQL stop
   replication and set `read_only = OFF`; AG failover; Azure geo-replication planned or forced
   failover; Data Guard switchover (planned) or failover; MongoDB `rs.stepDown()` or reconfiguration;
   CockroachDB PCR cutover.
4. **Move traffic through the gate**: propose `dr.dns_failover` (Route 53 / Traffic Manager; Cloud DNS
   fails over only automatically), or `network.traffic_dial` (Global Accelerator), or
   `migration.cutover` (Envoy). Another approver approves; an operator executes; the audit log records
   it.
5. **Swap the roles in OPLIA** with **Database list…**: the promoted database becomes `primary`, the
   old one (once rebuilt as a standby) becomes `dr` with `dr_of` pointing at the new primary. Restart
   the CronJobs.
6. **Fail back** the same way once the original site is rebuilt as a standby and its consistency
   check is CONSISTENT: planned switchover, then the gated traffic change back.

## Known limits

* SQL Server and Oracle: no automatic resync (check only).
* Checksums compare same-engine pairs ordered by primary key; tables without one, or above
  `checksum_max_rows`, are compared by row count only, and the report says so.
* Cross-engine pairs (e.g. PostgreSQL → MySQL) are compared by counts only.
* Oracle `V$DATAGUARD_STATS.VALUE` has no documented format; OPLIA parses `+DD HH:MM:SS` and otherwise
  shows the raw value with no number.
* SQL Server lag is read on the primary; if OPLIA's login lacks the permission there, lag shows "—".
* Not exercised in tests: a real availability group, a real Data Guard standby, real managed services.
  SQL Server 2022 and Oracle Database Free 23 single instances are tested in CI.
