"""Target writers for the 10 database paradigms (used by the CDC hydration sidecar, FR-04).

Every writer takes an already-built SDK client (so credentials stay with the SDK's own credential
chain: IAM roles, managed identity, workload identity) and exposes ``upsert`` / ``delete`` /
``flush``. Writes are idempotent upserts keyed by the source primary key, so redelivered CDC events
(at-least-once) do not duplicate data.

| Paradigm      | Engines (PRD matrix)                                   | Writer                        |
|---------------|--------------------------------------------------------|-------------------------------|
| relational    | RDS/Aurora, Azure SQL/DB for PG/MySQL, Cloud SQL, AlloyDB | Debezium JDBC sink (FR-03)  |
| distributed   | Spanner (+ Aurora DSQL, Cosmos PG via JDBC sink)       | ``SpannerWriter``             |
| document      | DocumentDB, Cosmos DB (Mongo API), Cosmos NoSQL,       | ``MongoWriter``, ``CosmosWriter``, |
|               | Firestore                                              | ``FirestoreWriter``           |
| key-value     | DynamoDB, Cosmos Table / Table Storage, Bigtable       | ``DynamoWriter``, ``TableWriter``, |
|               |                                                        | ``BigtableWriter``            |
| wide-column   | Keyspaces, Cosmos Cassandra, Bigtable                  | ``CqlWriter``, ``BigtableWriter`` |
| cache         | ElastiCache, MemoryDB, Azure Redis, Memorystore        | ``RedisWriter``               |
| graph         | Neptune, Cosmos Gremlin (+ Spanner Graph via Spanner)  | ``GremlinWriter``             |
| time-series   | Timestream, Azure Data Explorer, Bigtable              | ``TimestreamWriter``, ``KustoWriter`` |
| warehouse     | Redshift, BigQuery, Synapse dedicated, Fabric Warehouse | ``RedshiftMergeWriter``,     |
|               |                                                        | ``BigQueryMergeWriter``,      |
|               |                                                        | ``TsqlWarehouseMergeWriter``  |
| vector        | OpenSearch, Azure AI Search, pgvector, Cosmos vector,  | ``OpenSearchWriter``,         |
|               | Vertex AI Search                                       | ``AzureSearchWriter``,        |
|               |                                                        | ``PgVectorWriter``, ``CosmosWriter``, |
|               |                                                        | ``VertexSearchWriter``        |

Synapse dedicated SQL pool and Fabric Warehouse are reached through ODBC (pyodbc + Microsoft ODBC Driver 18),
which the sidecar image must provide; the writer itself only needs a DB-API connection.
"""

from __future__ import annotations

import json
import math
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Protocol

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def _id(v: str) -> str:
    if not _IDENT.fullmatch(v):
        raise ValueError(f"invalid identifier {v!r}")
    return v


def _plain(v: Any) -> Any:
    """JSON-safe value (Decimal -> str to keep precision, datetimes -> ISO-8601)."""
    if isinstance(v, Decimal):
        return str(v)
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_plain(x) for x in v]
    return v


def normalise(vec: list[float]) -> list[float]:
    n = math.sqrt(sum(x * x for x in vec))
    if n == 0:
        raise ValueError("zero-length embedding")
    return [x / n for x in vec]


class TargetWriter(Protocol):
    def upsert(self, collection: str, key: str, doc: dict[str, Any]) -> None: ...

    def delete(self, collection: str, key: str, doc: dict[str, Any] | None = None) -> None: ...

    def flush(self) -> None: ...


class _NoFlush:
    def flush(self) -> None:
        return None


# --------------------------------------------------------------------------- document
class MongoWriter(_NoFlush):
    """Amazon DocumentDB and Azure Cosmos DB for MongoDB (both speak the MongoDB wire protocol)."""

    def __init__(self, client: Any, database: str) -> None:
        self.db = client[_id(database)]

    def upsert(self, collection: str, key: str, doc: dict[str, Any]) -> None:
        self.db[_id(collection)].replace_one({"_id": key}, {**_plain(doc), "_id": key}, upsert=True)

    def delete(self, collection: str, key: str, doc: dict[str, Any] | None = None) -> None:
        self.db[_id(collection)].delete_one({"_id": key})


class CosmosWriter(_NoFlush):
    """Azure Cosmos DB for NoSQL (also vector containers): ``containers`` maps collection -> ContainerProxy."""

    def __init__(self, containers: dict[str, Any], partition_key: dict[str, str]) -> None:
        self.containers, self.pk = containers, partition_key

    def upsert(self, collection: str, key: str, doc: dict[str, Any]) -> None:
        self.containers[collection].upsert_item(body={**_plain(doc), "id": key})

    def delete(self, collection: str, key: str, doc: dict[str, Any] | None = None) -> None:
        field = self.pk.get(collection, "id")
        pkv = key if field == "id" else (doc or {}).get(field)
        if pkv is None:
            raise ValueError(f"{collection}: delete needs the partition key value ({field})")
        self.containers[collection].delete_item(item=key, partition_key=pkv)


class FirestoreWriter(_NoFlush):
    def __init__(self, client: Any) -> None:
        self.client = client

    def upsert(self, collection: str, key: str, doc: dict[str, Any]) -> None:
        self.client.collection(collection).document(key).set(_plain(doc))

    def delete(self, collection: str, key: str, doc: dict[str, Any] | None = None) -> None:
        self.client.collection(collection).document(key).delete()


# --------------------------------------------------------------------------- key-value / wide-column
class DynamoWriter(_NoFlush):
    """Single-table design: ``keys`` maps an entity (collection) to PK/SK templates (from FR-01)."""

    def __init__(self, client: Any, table: str, keys: dict[str, dict[str, str]]) -> None:
        from boto3.dynamodb.types import TypeSerializer

        self.c, self.table, self.keys, self._ser = client, table, keys, TypeSerializer()

    def _key(self, entity: str, doc: dict[str, Any]) -> dict[str, str]:
        k = self.keys[entity]
        return {name: tpl.format(**doc) for name, tpl in k.items()}

    def upsert(self, collection: str, key: str, doc: dict[str, Any]) -> None:
        item = {**{k: v for k, v in doc.items() if v is not None}, **self._key(collection, doc), "entity": collection}
        item = {k: (Decimal(str(v)) if isinstance(v, float) else v) for k, v in _plain(item).items()}
        self.c.put_item(TableName=self.table, Item={k: self._ser.serialize(v) for k, v in item.items()})

    def delete(self, collection: str, key: str, doc: dict[str, Any] | None = None) -> None:
        k = self._key(collection, doc or {})
        self.c.delete_item(TableName=self.table, Key={n: {"S": v} for n, v in k.items() if n in ("PK", "SK")})


class BigtableWriter(_NoFlush):
    def __init__(self, tables: dict[str, Any], family: str = "d") -> None:
        self.tables, self.family = tables, family

    def upsert(self, collection: str, key: str, doc: dict[str, Any]) -> None:
        row = self.tables[collection].direct_row(key.encode())
        for col, v in doc.items():
            if v is not None:
                row.set_cell(self.family, col.encode(), json.dumps(_plain(v)).encode())
        row.commit()

    def delete(self, collection: str, key: str, doc: dict[str, Any] | None = None) -> None:
        row = self.tables[collection].direct_row(key.encode())
        row.delete()
        row.commit()


class CqlWriter(_NoFlush):
    """Amazon Keyspaces and Azure Cosmos DB for Apache Cassandra (CQL INSERT is an upsert)."""

    def __init__(self, session: Any, keyspace: str, primary_keys: dict[str, list[str]]) -> None:
        self.s, self.ks, self.pks = session, _id(keyspace), primary_keys

    def upsert(self, collection: str, key: str, doc: dict[str, Any]) -> None:
        cols = [_id(c) for c in doc]
        q = (f'INSERT INTO "{self.ks}"."{_id(collection)}" (' + ", ".join(f'"{c}"' for c in cols)
             + ") VALUES (" + ", ".join(["%s"] * len(cols)) + ")")
        self.s.execute(q, [doc[c] for c in cols])

    def delete(self, collection: str, key: str, doc: dict[str, Any] | None = None) -> None:
        pk = self.pks[collection]
        q = (f'DELETE FROM "{self.ks}"."{_id(collection)}" WHERE '  # nosec B608 - validated identifiers
             + " AND ".join(f'"{_id(c)}" = %s' for c in pk))
        self.s.execute(q, [(doc or {})[c] for c in pk])


class SpannerWriter(_NoFlush):
    def __init__(self, database: Any) -> None:
        self.db = database

    def upsert(self, collection: str, key: str, doc: dict[str, Any]) -> None:
        cols = list(doc)
        with self.db.batch() as b:
            b.insert_or_update(table=_id(collection), columns=cols, values=[[doc[c] for c in cols]])

    def delete(self, collection: str, key: str, doc: dict[str, Any] | None = None) -> None:
        from google.cloud.spanner_v1 import KeySet

        with self.db.batch() as b:
            b.delete(table=_id(collection), keyset=KeySet(keys=[[key]]))  # type: ignore[no-untyped-call]


# --------------------------------------------------------------------------- cache
class RedisWriter(_NoFlush):
    """ElastiCache / MemoryDB / Azure Cache for Redis / Memorystore: hash per row + secondary lookup sets."""

    def __init__(self, client: Any, ttl_seconds: int | None = None,
                 lookups: dict[str, list[str]] | None = None) -> None:
        self.r, self.ttl, self.lookups = client, ttl_seconds, lookups or {}

    def upsert(self, collection: str, key: str, doc: dict[str, Any]) -> None:
        k = f"{collection}:{key}"
        old = self.r.hgetall(k)
        p = self.r.pipeline(transaction=True)
        p.delete(k)
        p.hset(k, mapping={f: json.dumps(_plain(v)) for f, v in doc.items()})
        if self.ttl:
            p.expire(k, self.ttl)
        for col in self.lookups.get(collection, []):
            prev = old.get(col.encode()) if old else None
            if prev is not None:
                p.srem(f"{collection}:by:{col}:{json.loads(prev)}", key)
            if doc.get(col) is not None:
                p.sadd(f"{collection}:by:{col}:{doc[col]}", key)
        p.execute()

    def delete(self, collection: str, key: str, doc: dict[str, Any] | None = None) -> None:
        k = f"{collection}:{key}"
        old = self.r.hgetall(k)
        p = self.r.pipeline(transaction=True)
        p.delete(k)
        for col in self.lookups.get(collection, []):
            prev = old.get(col.encode()) if old else None
            if prev is not None:
                p.srem(f"{collection}:by:{col}:{json.loads(prev)}", key)
        p.execute()


# --------------------------------------------------------------------------- graph
class GremlinWriter(_NoFlush):
    """Neptune and Cosmos DB for Gremlin. Uses fold()/coalesce() upserts (both services support them; Cosmos
    does not support mergeV). Vertex id property: 'oplia_id' = '<label>:<key>'; Cosmos also needs the
    container's partition key property (``partition_property``)."""

    def __init__(self, client: Any, partition_property: str | None = None) -> None:
        self.c, self.pp = client, partition_property

    def upsert(self, collection: str, key: str, doc: dict[str, Any]) -> None:
        vid = f"{collection}:{key}"
        props = {k: v for k, v in _plain(doc).items() if v is not None and not isinstance(v, (dict, list))}
        q = ("g.V().has('oplia_id', vid).fold().coalesce(unfold(), addV(label).property('oplia_id', vid)"
             + (f".property('{_id(self.pp)}', vid)" if self.pp else "") + ")")
        for i, k in enumerate(props):
            q += f".property(single, '{_id(k)}', p{i})"
        self.c.submit(q, bindings={"vid": vid, "label": collection, **{f"p{i}": v for i, v in
                                                                       enumerate(props.values())}}).all().result()

    def edge(self, label: str, from_vid: str, to_vid: str) -> None:
        q = ("g.V().has('oplia_id', a).as('a').V().has('oplia_id', b).coalesce(inE(lbl).where(outV().as('a')), "
             "addE(lbl).from('a'))")
        self.c.submit(q, bindings={"a": from_vid, "b": to_vid, "lbl": label}).all().result()

    def delete(self, collection: str, key: str, doc: dict[str, Any] | None = None) -> None:
        self.c.submit("g.V().has('oplia_id', vid).drop()", bindings={"vid": f"{collection}:{key}"}).all().result()


# --------------------------------------------------------------------------- time-series
class TimestreamWriter:
    """Multi-measure records; ``spec`` per table: {time, dimensions, measures, version?} (from FR-01).

    Timestream rejects a second write of the same record (time + dimensions + measure name) unless it carries a
    higher ``Version`` (Record.Version in the API: "Write requests for duplicate data with a higher version number
    will update the existing measure value"; default 1). Without it every CDC *update* of a row that was already
    written would be rejected. ``version`` names a monotonically increasing source column (e.g. an update
    counter or commit timestamp in ms); without it the writer uses the wall clock in ms, which is correct for
    in-order delivery but lets a redelivered older event overwrite a newer value."""

    def __init__(self, client: Any, database: str, spec: dict[str, dict[str, Any]], batch: int = 100) -> None:
        self.c, self.db, self.spec, self.batch = client, database, spec, batch
        self._buf: dict[str, list[dict[str, Any]]] = {}

    def upsert(self, collection: str, key: str, doc: dict[str, Any]) -> None:
        sp = self.spec[collection]
        t = doc[sp["time"]]
        ts = t if isinstance(t, datetime) else datetime.fromisoformat(str(t))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        rec = {"Dimensions": [{"Name": d, "Value": str(doc[d])} for d in sp["dimensions"] if doc.get(d) is not None],
               "MeasureName": collection, "MeasureValueType": "MULTI",
               "MeasureValues": [{"Name": m, "Value": str(doc[m]), "Type": "DOUBLE"} for m in sp["measures"]
                                 if doc.get(m) is not None],
               "Time": str(int(ts.timestamp() * 1000)), "TimeUnit": "MILLISECONDS",
               "Version": max(1, int(doc[sp["version"]]) if sp.get("version") else int(time.time() * 1000))}
        self._buf.setdefault(collection, []).append(rec)
        if len(self._buf[collection]) >= self.batch:
            self.flush()

    def delete(self, collection: str, key: str, doc: dict[str, Any] | None = None) -> None:
        raise NotImplementedError("Timestream records cannot be deleted; deletes are reported, not applied")

    def flush(self) -> None:
        for table, recs in self._buf.items():
            for i in range(0, len(recs), 100):          # WriteRecords accepts at most 100 records per call
                self.c.write_records(DatabaseName=self.db, TableName=table, Records=recs[i:i + 100])
        self._buf = {}


class KustoWriter:
    """Azure Data Explorer streaming ingestion over REST (``POST /v1/rest/ingest/{db}/{table}?streamFormat=
    MultiJSON&mappingName=...``). Streaming ingestion must be enabled on the cluster and table, and the JSON
    ingestion mapping must exist (FR-01 emits it as ``oplia_json``). The azure-kusto-ingest SDK is not used:
    it pins azure-storage-blob to a version that conflicts with the object-replication pin."""

    def __init__(self, http: Any, cluster_url: str, database: str, token: Callable[[], str],
                 mapping: str = "oplia_json") -> None:
        if not re.fullmatch(r"https://[a-z0-9.-]+\.kusto\.(windows\.net|azure\.com|fabric\.microsoft\.com)",
                            cluster_url.rstrip("/")):
            raise ValueError("cluster_url must be https://<cluster>.<region>.kusto.windows.net")
        self.h, self.url, self.db, self.token, self.mapping = http, cluster_url.rstrip("/"), _id(database), token, \
            _id(mapping)
        self._buf: dict[str, list[str]] = {}

    def upsert(self, collection: str, key: str, doc: dict[str, Any]) -> None:
        self._buf.setdefault(collection, []).append(json.dumps(_plain(doc)))

    def delete(self, collection: str, key: str, doc: dict[str, Any] | None = None) -> None:
        raise NotImplementedError("ADX ingestion is append-only; deletes need a purge/soft-delete policy")

    def flush(self) -> None:
        import gzip

        for table, lines in self._buf.items():
            self.h.request("POST", f"{self.url}/v1/rest/ingest/{self.db}/{_id(table)}", expected={200},
                           params={"streamFormat": "MultiJSON", "mappingName": self.mapping},
                           content=gzip.compress("\n".join(lines).encode()),
                           headers={"Authorization": f"Bearer {self.token()}", "Content-Encoding": "gzip"})
        self._buf = {}


# --------------------------------------------------------------------------- warehouse (micro-batched MERGE)
class _MergeBuffer:
    def __init__(self, keys: dict[str, list[str]], batch: int) -> None:
        self.keys, self.batch = keys, batch
        self._rows: dict[str, dict[str, tuple[str, dict[str, Any]]]] = {}

    def add(self, table: str, key: str, op: str, doc: dict[str, Any]) -> bool:
        self._rows.setdefault(table, {})[key] = (op, doc)     # last change per key wins within a batch
        return sum(len(v) for v in self._rows.values()) >= self.batch

    def drain(self) -> dict[str, dict[str, tuple[str, dict[str, Any]]]]:
        out, self._rows = self._rows, {}
        return out


class BigQueryMergeWriter:
    """Row mutations -> staging load job -> one MERGE per table per batch (no long locks on analytical tables)."""

    def __init__(self, client: Any, dataset: str, keys: dict[str, list[str]], batch: int = 5000) -> None:
        self.c, self.ds, self.buf = client, dataset, _MergeBuffer(keys, batch)

    def upsert(self, collection: str, key: str, doc: dict[str, Any]) -> None:
        if self.buf.add(collection, key, "u", doc):
            self.flush()

    def delete(self, collection: str, key: str, doc: dict[str, Any] | None = None) -> None:
        if self.buf.add(collection, key, "d", doc or {}):
            self.flush()

    def flush(self) -> None:
        from google.cloud import bigquery

        for table, rows in self.buf.drain().items():
            pk = self.buf.keys[table]
            stage = f"{self.ds}.{_id(table)}__oplia_stage"
            cols = sorted({c for _, d in rows.values() for c in d} | set(pk))
            data = [{**{c: _plain(d.get(c)) for c in cols}, "_oplia_op": op} for op, d in rows.values()]
            cfg = bigquery.LoadJobConfig(write_disposition="WRITE_TRUNCATE", autodetect=True)
            self.c.load_table_from_json(data, stage, job_config=cfg).result()
            on = " AND ".join(f"T.`{_id(k)}` = S.`{_id(k)}`" for k in pk)
            upd = ", ".join(f"`{_id(c)}` = S.`{_id(c)}`" for c in cols if c not in pk)
            ins = ", ".join(f"`{_id(c)}`" for c in cols)
            self.c.query(f"MERGE `{self.ds}.{_id(table)}` T USING `{stage}` S ON {on} "  # nosec B608
                         "WHEN MATCHED AND S._oplia_op = 'd' THEN DELETE "
                         f"WHEN MATCHED THEN UPDATE SET {upd} "
                         f"WHEN NOT MATCHED AND S._oplia_op != 'd' THEN INSERT ({ins}) VALUES "
                         f"({', '.join('S.`' + c + '`' for c in cols)})").result()


class RedshiftMergeWriter:
    """Redshift Data API. Per batch, in one Data API session: a temp staging table, parameterised INSERTs, then
    DELETE + MERGE in one batch transaction. Every statement is polled until FINISHED (the API is async)."""

    def __init__(self, client: Any, target: dict[str, str], database: str, schema: str,
                 keys: dict[str, list[str]], batch: int = 1000, sleep: Callable[[float], None] | None = None,
                 timeout_s: float = 300) -> None:
        import time

        if set(target) - {"WorkgroupName", "ClusterIdentifier", "SecretArn", "DbUser"}:
            raise ValueError("target: WorkgroupName or ClusterIdentifier (+ SecretArn / DbUser)")
        self.c, self.target, self.db, self.schema = client, target, database, _id(schema)
        self.buf = _MergeBuffer(keys, batch)
        self._sleep, self._timeout = sleep or time.sleep, timeout_s

    def upsert(self, collection: str, key: str, doc: dict[str, Any]) -> None:
        if self.buf.add(collection, key, "u", doc):
            self.flush()

    def delete(self, collection: str, key: str, doc: dict[str, Any] | None = None) -> None:
        if self.buf.add(collection, key, "d", doc or {}):
            self.flush()

    def _wait(self, sid: str) -> None:
        waited = 0.0
        while True:
            d = self.c.describe_statement(Id=sid)
            if d["Status"] == "FINISHED":
                return
            if d["Status"] in ("FAILED", "ABORTED"):
                raise RuntimeError(f"Redshift statement {d['Status']}: {str(d.get('Error', ''))[:500]}")
            if waited > self._timeout:
                raise TimeoutError(f"Redshift statement {sid} still {d['Status']}")
            self._sleep(0.5)
            waited += 0.5

    def _exec(self, sql: str, session: str | None, params: list[dict[str, str]] | None = None) -> str:
        kw: dict[str, Any] = {"Sql": sql}
        kw.update({"SessionId": session} if session else {"SessionKeepAliveSeconds": 300, "Database": self.db,
                                                          **self.target})
        if params:
            kw["Parameters"] = params
        r = self.c.execute_statement(**kw)
        self._wait(r["Id"])
        return str(r.get("SessionId") or session)

    def flush(self) -> None:
        for table, rows in self.buf.drain().items():
            pk = self.buf.keys[table]
            cols = sorted({c for _, d in rows.values() for c in d} | set(pk))
            t, st = f'"{self.schema}"."{_id(table)}"', f'"{_id(table)}__oplia_stage"'
            qc = ", ".join(f'"{_id(c)}"' for c in cols)
            session = self._exec(f"CREATE TEMP TABLE {st} (LIKE {t})", None)
            self._exec(f"ALTER TABLE {st} ADD COLUMN _oplia_op CHAR(1)", session)
            for op, d in rows.values():
                # Data API: a parameter cannot be NULL (it becomes the string 'NULL') or zero-length (the statement
                # fails), so both are written as SQL literals instead of parameters
                params = [{"name": f"c{j}", "value": str(_plain(d[c]))} for j, c in enumerate(cols)
                          if d.get(c) is not None and str(_plain(d[c])) != ""]
                names = {p["name"] for p in params}
                empty = {f"c{j}" for j, c in enumerate(cols) if d.get(c) is not None and str(_plain(d[c])) == ""}
                vals = ", ".join(f":c{j}" if f"c{j}" in names else ("''" if f"c{j}" in empty else "NULL")
                                 for j in range(len(cols)))
                self._exec(f"INSERT INTO {st} ({qc}, _oplia_op) VALUES ({vals}, '{op}')",  # nosec B608
                           session, params)
            on = " AND ".join(f'{t}."{_id(k)}" = s."{_id(k)}"' for k in pk)
            r = self.c.batch_execute_statement(SessionId=session, Sqls=[
                f"DELETE FROM {t} USING {st} s WHERE {on} AND s._oplia_op = 'd'",  # nosec B608
                f"MERGE INTO {t} USING (SELECT {qc} FROM {st} WHERE _oplia_op = 'u') s ON {on} "  # nosec B608
                "WHEN MATCHED THEN UPDATE SET " + ", ".join(f'"{_id(c)}" = s."{_id(c)}"' for c in cols if c not in pk)
                + f" WHEN NOT MATCHED THEN INSERT ({qc}) VALUES (" + ", ".join(f's."{_id(c)}"' for c in cols) + ")"])
            self._wait(r["Id"])


# --------------------------------------------------------------------------- vector
class OpenSearchWriter(_NoFlush):
    """OpenSearch Service: _bulk index/delete through an HTTP client that signs requests (SigV4)."""

    def __init__(self, http: Any, endpoint: str, auth: Callable[[], dict[str, str]] | None = None) -> None:
        if not endpoint.startswith("https://"):
            raise ValueError("OpenSearch endpoint must be https://")
        self.h, self.url, self.auth = http, endpoint.rstrip("/"), auth or (lambda: {})

    def _bulk(self, lines: list[dict[str, Any]]) -> None:
        body = "".join(json.dumps(x) + "\n" for x in lines)
        r = self.h.request("POST", f"{self.url}/_bulk", expected={200}, content=body.encode(),
                           headers={"Content-Type": "application/x-ndjson", **self.auth()})
        res = r.json()
        if res.get("errors"):
            bad = [i for i in res.get("items", []) if next(iter(i.values())).get("error")]
            raise RuntimeError(f"OpenSearch bulk errors: {json.dumps(bad)[:500]}")

    def upsert(self, collection: str, key: str, doc: dict[str, Any]) -> None:
        d = dict(_plain(doc))
        if "embedding" in d:
            d["embedding"] = normalise(d["embedding"])     # inner product on unit vectors = cosine
        self._bulk([{"index": {"_index": collection, "_id": key}}, d])

    def delete(self, collection: str, key: str, doc: dict[str, Any] | None = None) -> None:
        self._bulk([{"delete": {"_index": collection, "_id": key}}])


class AzureSearchWriter(_NoFlush):
    API_VERSION = "2024-07-01"

    def __init__(self, http: Any, service_url: str, key_header: Callable[[], dict[str, str]]) -> None:
        if not re.fullmatch(r"https://[a-z0-9-]+\.search\.windows\.net", service_url.rstrip("/")):
            raise ValueError("service_url must be https://<service>.search.windows.net")
        self.h, self.url, self.key = http, service_url.rstrip("/"), key_header

    def _index(self, collection: str, docs: list[dict[str, Any]]) -> None:
        r = self.h.request("POST", f"{self.url}/indexes/{_id_dash(collection)}/docs/index?api-version="
                                   f"{self.API_VERSION}", expected={200, 207}, json={"value": docs},
                           headers=self.key())
        failed = [x for x in r.json().get("value", []) if not x.get("status")]
        if failed:
            raise RuntimeError(f"Azure AI Search rejected {len(failed)} document(s): {failed[:3]}")

    def upsert(self, collection: str, key: str, doc: dict[str, Any]) -> None:
        self._index(collection, [{"@search.action": "mergeOrUpload", "id": key, **_plain(doc)}])

    def delete(self, collection: str, key: str, doc: dict[str, Any] | None = None) -> None:
        self._index(collection, [{"@search.action": "delete", "id": key}])


def _id_dash(v: str) -> str:
    v = v.lower().replace("_", "-")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,127}", v):
        raise ValueError(f"invalid index name {v!r}")
    return v


class PgVectorWriter(_NoFlush):
    """Aurora PostgreSQL / AlloyDB with pgvector: UPDATE the embedding column of the replicated row."""

    def __init__(self, conn: Any, keys: dict[str, list[str]]) -> None:
        self.c, self.keys = conn, keys

    def upsert(self, collection: str, key: str, doc: dict[str, Any]) -> None:
        if "embedding" not in doc:
            return
        pk = self.keys[collection]
        vec = "[" + ",".join(repr(float(x)) for x in doc["embedding"]) + "]"
        where = " AND ".join(f'"{_id(k)}" = %s' for k in pk)
        self.c.execute(f'UPDATE "{_id(collection)}" SET "embedding" = %s::vector WHERE {where}',  # nosec B608
                       (vec, *[doc[k] for k in pk]))

    def delete(self, collection: str, key: str, doc: dict[str, Any] | None = None) -> None:
        return None          # the row itself is deleted by the JDBC sink


# --------------------------------------------------------------------------- key-value: Table API
_TABLE_KEY_BAD = re.compile(r"[/\\#?\x00-\x1f\x7f-\x9f]")
_TABLE_PROP = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,254}$")


class TableWriter(_NoFlush):
    """Azure Cosmos DB for Table / Azure Table Storage through ``azure-data-tables`` (one TableClient per table).

    Entity rules from "Understanding the Table service data model": PartitionKey and RowKey are strings up to
    1024 characters without ``/ \\ # ?`` or control characters; at most 252 custom properties; property names
    are C#-identifier-like (no dash); an entity is at most 1 MiB. Azure Cosmos DB for Table is stricter (its
    FAQ): RowKey at most 255 bytes, and the property names ID, rid, etag and ResourceId are reserved;
    ``cosmos=True`` enforces those too. Keys that break the rules are refused (not rewritten) so two source keys
    can never collapse into one entity."""

    MAX_PROPS = 252
    COSMOS_RESERVED = ("ID", "rid", "etag", "ResourceId")

    def __init__(self, tables: dict[str, Any], partition_key: dict[str, str], cosmos: bool = False) -> None:
        self.t, self.pk, self.cosmos = tables, partition_key, cosmos

    def _key(self, v: Any, what: str) -> str:
        s = str(v)
        if not s or len(s) > 1024 or _TABLE_KEY_BAD.search(s):
            raise ValueError(f"{what} {s[:80]!r} is not a valid Table key (1-1024 chars, no / \\ # ? or control)")
        if self.cosmos and what == "RowKey" and len(s.encode()) > 255:
            raise ValueError(f"RowKey {s[:80]!r} is longer than the 255 bytes Azure Cosmos DB for Table allows")
        return s

    def _keys(self, collection: str, key: str, doc: dict[str, Any] | None) -> tuple[str, str]:
        field = self.pk.get(collection)
        part = (doc or {}).get(field) if field else collection
        if part is None:
            raise ValueError(f"{collection}: partition key field {field!r} missing from the change")
        return self._key(part, "PartitionKey"), self._key(key, "RowKey")

    def upsert(self, collection: str, key: str, doc: dict[str, Any]) -> None:
        from azure.data.tables import UpdateMode

        pk, rk = self._keys(collection, key, doc)
        props = {k: v for k, v in _plain(doc).items() if k not in ("PartitionKey", "RowKey")}
        bad = [k for k in props if not _TABLE_PROP.fullmatch(k) or (self.cosmos and k in self.COSMOS_RESERVED)]
        if bad:
            raise ValueError(f"{collection}: property names not allowed by the Table API: {bad[:5]}")
        if len(props) > self.MAX_PROPS:
            raise ValueError(f"{collection}: {len(props)} properties, the Table API allows {self.MAX_PROPS}")
        ent = {"PartitionKey": pk, "RowKey": rk,
               **{k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in props.items()}}
        self.t[collection].upsert_entity(ent, mode=UpdateMode.REPLACE)

    def delete(self, collection: str, key: str, doc: dict[str, Any] | None = None) -> None:
        pk, rk = self._keys(collection, key, doc)
        self.t[collection].delete_entity(partition_key=pk, row_key=rk)     # no error if it is already gone


# --------------------------------------------------------------------------- warehouse: Synapse / Fabric
class TsqlWarehouseMergeWriter:
    """Azure Synapse dedicated SQL pool and Fabric Warehouse: per batch a session #temp staging table (columns
    typed from the target's INFORMATION_SCHEMA), single-row parameterised INSERTs (a table value constructor
    is not allowed as a MERGE source there) and one MERGE per table. The connection must be in autocommit
    mode: Synapse does not allow DDL such as CREATE TABLE inside a user-defined transaction ("Use transactions
    in a SQL pool"); each MERGE is atomic on its own.

    Documented limits (MERGE Transact-SQL reference, Synapse / Fabric section): ``WHEN NOT MATCHED BY TARGET``
    needs a HASH-distributed target on Synapse; MERGE ... INSERT is not supported on tables with IDENTITY
    columns; on Synapse builds older than 10.0.17829.0 MERGE must not update a distribution key column."""

    def __init__(self, connect: Callable[[], Any], schema: str, keys: dict[str, list[str]], batch: int = 1000,
                 paramstyle: str = "qmark") -> None:
        if paramstyle not in ("qmark", "format"):
            raise ValueError("paramstyle: qmark (pyodbc) or format (pymssql)")
        self._connect, self.schema, self.buf = connect, _id(schema), _MergeBuffer(keys, batch)
        self._ph = "?" if paramstyle == "qmark" else "%s"

    def upsert(self, collection: str, key: str, doc: dict[str, Any]) -> None:
        if self.buf.add(collection, key, "u", doc):
            self.flush()

    def delete(self, collection: str, key: str, doc: dict[str, Any] | None = None) -> None:
        if self.buf.add(collection, key, "d", doc or {}):
            self.flush()

    def _types(self, cur: Any, table: str) -> dict[str, str]:
        from oplia_ctl.migration.online_ddl_engines import mssql_type

        cur.execute("SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, NUMERIC_PRECISION, NUMERIC_SCALE, "  # nosec B608 - placeholders only
                    f"DATETIME_PRECISION FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = {self._ph} "
                    f"AND TABLE_NAME = {self._ph}", (self.schema, table))
        out = {}
        for name, typ, clen, prec, scale, dprec in cur.fetchall():
            t = str(typ).lower()
            ml = -1 if clen == -1 else (int(clen) * (2 if t in ("nvarchar", "nchar") else 1) if clen else 0)
            sc = int(dprec) if t in ("datetime2", "time", "datetimeoffset") and dprec is not None else int(scale or 0)
            out[str(name)] = mssql_type(t, ml, int(prec or 0), sc, None)
        if not out:
            raise ValueError(f"table {self.schema}.{table} not found")
        return out

    def flush(self) -> None:
        batches = self.buf.drain()
        if not batches:
            return
        conn = self._connect()
        try:
            cur = conn.cursor()
            for table, rows in batches.items():
                pk = self.buf.keys[table]
                types = self._types(cur, _id(table))
                cols = sorted({c for _, d in rows.values() for c in d} | set(pk))
                missing = [c for c in cols if c not in types]
                if missing:
                    raise ValueError(f"{table}: columns not in the target: {missing[:5]}")
                t, st = f"[{self.schema}].[{_id(table)}]", f"[#{_id(table)}__oplia_stage]"
                qc = ", ".join(f"[{_id(c)}]" for c in cols)
                cur.execute(f"IF OBJECT_ID('tempdb..#{_id(table)}__oplia_stage') IS NOT NULL DROP TABLE {st}")
                cur.execute(f"CREATE TABLE {st} (" + ", ".join(f"[{_id(c)}] {types[c]}" for c in cols)
                            + ", [_oplia_op] char(1))")
                ins = f"INSERT INTO {st} ({qc}, [_oplia_op]) VALUES ({', '.join([self._ph] * (len(cols) + 1))})"  # nosec B608
                for op, d in rows.values():
                    cur.execute(ins, (*[_plain(d.get(c)) if not isinstance(d.get(c), (dict, list))
                                        else json.dumps(d.get(c)) for c in cols], op))
                on = " AND ".join(f"T.[{_id(k)}] = S.[{_id(k)}]" for k in pk)
                upd = ", ".join(f"T.[{_id(c)}] = S.[{_id(c)}]" for c in cols if c not in pk)
                matched = f"WHEN MATCHED AND S.[_oplia_op] <> 'd' THEN UPDATE SET {upd} " if upd else ""  # nosec B608 - identifiers checked by _id()
                cur.execute(f"MERGE INTO {t} AS T USING {st} AS S ON {on} "  # nosec B608
                            "WHEN MATCHED AND S.[_oplia_op] = 'd' THEN DELETE " + matched
                            + f"WHEN NOT MATCHED BY TARGET AND S.[_oplia_op] <> 'd' THEN INSERT ({qc}) VALUES ("
                            + ", ".join(f"S.[{_id(c)}]" for c in cols) + ");")
                cur.execute(f"DROP TABLE {st}")
        finally:
            conn.close()


# --------------------------------------------------------------------------- vector: Vertex AI Search
_RFC1034 = re.compile(r"^[A-Za-z]([A-Za-z0-9-]{0,126}[A-Za-z0-9])?$")


class VertexSearchWriter(_NoFlush):
    """Vertex AI Search (Discovery Engine) data store: ``UpdateDocument(allow_missing=True)`` upserts a
    structured document, ``DeleteDocument`` removes it. Document ids must follow RFC-1034 with at most 128
    characters (Document.id in the API); a source key that does not fit is mapped to ``k-<sha256>`` and the
    original key is kept in ``struct_data._oplia_key``, so the mapping is deterministic and collision-free."""

    def __init__(self, client: Any, data_stores: dict[str, str]) -> None:
        for c, ds in data_stores.items():
            if not re.fullmatch(r"projects/[^/]+/locations/[^/]+/collections/[^/]+/dataStores/[^/]+", ds):
                raise ValueError(f"{c}: data store must be projects/*/locations/*/collections/*/dataStores/*")
        self.c, self.ds = client, data_stores

    @staticmethod
    def doc_id(key: str) -> str:
        import hashlib

        return key if _RFC1034.fullmatch(key) else "k-" + hashlib.sha256(key.encode()).hexdigest()

    def _name(self, collection: str, key: str) -> str:
        return f"{self.ds[collection]}/branches/default_branch/documents/{self.doc_id(key)}"

    def upsert(self, collection: str, key: str, doc: dict[str, Any]) -> None:
        from google.cloud import discoveryengine_v1 as de
        from google.protobuf import struct_pb2

        data = struct_pb2.Struct()
        data.update({**_plain(doc), "_oplia_key": key})
        d = de.Document(name=self._name(collection, key), id=self.doc_id(key), struct_data=data)
        self.c.update_document(request=de.UpdateDocumentRequest(document=d, allow_missing=True))

    def delete(self, collection: str, key: str, doc: dict[str, Any] | None = None) -> None:
        from google.api_core.exceptions import NotFound
        from google.cloud import discoveryengine_v1 as de

        try:
            self.c.delete_document(request=de.DeleteDocumentRequest(name=self._name(collection, key)))
        except NotFound:
            return            # already gone: deletes are idempotent like every other writer
