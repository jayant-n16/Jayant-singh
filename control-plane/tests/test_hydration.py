"""FR-04 hydration sidecar and the target writers.

Real engines: Redis (a local redis-server is started), MongoDB (OPLIA_TEST_MONGO_URL, in CI), DynamoDB in
moto. AWS Timestream and the Redshift Data API go through botocore's Stubber (parameters checked against the
real service models). OpenSearch and Azure AI Search are HTTP mocks of the documented bulk/index calls. For
Spanner, Bigtable, Firestore, Cosmos DB, Gremlin, CQL, ADX and BigQuery, each call the writer makes is bound
against the signature of the real SDK method (``SdkFake``), so a wrong method or argument name fails the test;
the services themselves are not called."""

from __future__ import annotations

import inspect
import json
import math
import os
import shutil
import socket
import subprocess
import time

import boto3
import httpx
import pytest
import respx
from botocore.stub import ANY, Stubber

from oplia_ctl.http import ResilientClient
from oplia_ctl.migration.hydrate import HydrationSpec, Hydrator, parse_event, run_kafka
from oplia_ctl.migration.targets import (
    AzureSearchWriter,
    BigQueryMergeWriter,
    BigtableWriter,
    CosmosWriter,
    CqlWriter,
    DynamoWriter,
    FirestoreWriter,
    GremlinWriter,
    KustoWriter,
    MongoWriter,
    OpenSearchWriter,
    PgVectorWriter,
    RedisWriter,
    RedshiftMergeWriter,
    SpannerWriter,
    TimestreamWriter,
)

MONGO_URL = os.environ.get("OPLIA_TEST_MONGO_URL", "")


@pytest.fixture(autouse=True)
def _aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")


def ev(table, op, before=None, after=None, wrap=False):
    e = {"before": before, "after": after, "op": op, "ts_ms": 1, "source": {"table": table, "db": "shop"}}
    return json.dumps({"schema": {}, "payload": e} if wrap else e).encode()


class Rec:
    def __init__(self):
        self.ups, self.dels, self.edges, self.flushed = [], [], [], 0

    def upsert(self, c, k, d):
        self.ups.append((c, k, d))

    def delete(self, c, k, d=None):
        self.dels.append((c, k))

    def edge(self, label, a, b):
        self.edges.append((label, a, b))

    def flush(self):
        self.flushed += 1


# ----------------------------------------------------------------------------- hydrator
def test_parse_event_envelopes():
    assert parse_event(ev("orders", "c", after={"id": 1}, wrap=True)).after == {"id": 1}
    assert parse_event(ev("orders", "d", before={"id": 1})).row == {"id": 1}
    assert parse_event(None) is None
    with pytest.raises(ValueError, match="not a Debezium"):
        parse_event(b'{"hello": 1}')


DOC = HydrationSpec(pipeline="shop", mode="document", root="orders", keys={"orders": ["id"], "lines": ["order_id",
                                                                                                    "line"]},
                    children=[{"table": "lines", "fk": "order_id", "field": "lines", "key": ["order_id", "line"]}])


def test_document_mode_joins_children_and_holds_orphans(session_factory):
    w = Rec()
    h = Hydrator(DOC, w, session_factory)
    h.process(parse_event(ev("lines", "c", after={"order_id": 7, "line": 2, "sku": "b"})))      # child first
    assert w.ups == [] and h.stats["held"] == 1
    h.process(parse_event(ev("orders", "c", after={"id": 7, "total": "9.50"})))
    assert w.ups[-1] == ("orders", "7", {"id": 7, "total": "9.50", "lines": [{"line": 2, "sku": "b"}]})
    h.process(parse_event(ev("lines", "c", after={"order_id": 7, "line": 1, "sku": "a"})))
    h.process(parse_event(ev("lines", "u", before={"order_id": 7, "line": 2, "sku": "b"},
                             after={"order_id": 7, "line": 2, "sku": "B"})))
    assert w.ups[-1][2]["lines"] == [{"line": 1, "sku": "a"}, {"line": 2, "sku": "B"}]
    h.process(parse_event(ev("lines", "d", before={"order_id": 7, "line": 1, "sku": "a"})))
    assert w.ups[-1][2]["lines"] == [{"line": 2, "sku": "B"}]
    h.process(parse_event(ev("orders", "u", before={"id": 7}, after={"id": 7, "total": "10.00"})))
    assert w.ups[-1][2] == {"id": 7, "total": "10.00", "lines": [{"line": 2, "sku": "B"}]}
    h.process(parse_event(ev("orders", "d", before={"id": 7})))
    assert w.dels == [("orders", "7")]


def test_writer_failure_rolls_back_document_state(session_factory):
    class Boom(Rec):
        def upsert(self, c, k, d):
            raise RuntimeError("target down")

    h = Hydrator(DOC, Boom(), session_factory)
    with pytest.raises(RuntimeError):
        h.process(parse_event(ev("orders", "c", after={"id": 1})))
    w = Rec()
    Hydrator(DOC, w, session_factory).process(parse_event(ev("lines", "c", after={"order_id": 1, "line": 1})))
    assert w.ups == []           # the failed root write was not kept: the child is still held


def test_graph_and_vector_modes():
    w = Rec()
    g = Hydrator(HydrationSpec(pipeline="g", mode="graph", keys={"orders": ["id"], "customers": ["id"]},
                               edges=[{"table": "orders", "column": "customer_id", "to": "customers",
                                       "label": "PLACED_BY"}]), w)
    g.process(parse_event(ev("orders", "c", after={"id": 1, "customer_id": 9})))
    assert w.edges == [("PLACED_BY", "orders:1", "customers:9")]
    v = Rec()
    hv = Hydrator(HydrationSpec(pipeline="v", mode="vector", keys={"docs": ["id"]}, embed={"docs": ["title", "body"]}),
                  v, embed=lambda texts: [[3.0, 4.0] for _ in texts])
    hv.process(parse_event(ev("docs", "c", after={"id": 5, "title": "t", "body": "b"})))
    assert v.ups[0][2]["embedding"] == [0.6, 0.8]
    with pytest.raises(ValueError, match="embedding provider"):
        Hydrator(HydrationSpec(pipeline="v", mode="vector", keys={}), v)


def test_kafka_loop_commits_after_flush():
    class Msg:
        def __init__(self, v):
            self.v = v

        def error(self):
            return None

        def value(self):
            return self.v

    class Cons:
        def __init__(self):
            self.batches = [[Msg(ev("t", "c", after={"id": 1})), Msg(None)], []]
            self.commits, self.order = 0, []

        def subscribe(self, topics):
            self.topics = topics

        def consume(self, num_messages, timeout):
            return self.batches.pop(0) if self.batches else []

        def commit(self, asynchronous):
            assert asynchronous is False
            self.order.append("commit")

    class W(Rec):
        def flush(self):
            cons.order.append("flush")

    cons = Cons()
    h = Hydrator(HydrationSpec(pipeline="k", mode="flat", keys={"t": ["id"]}), W())
    calls = iter([False, False, True])
    stats = run_kafka(h, cons, ["shop.public.t"], stop=lambda: next(calls))
    assert cons.order == ["flush", "commit"] and stats["writes"] == 1


# ----------------------------------------------------------------------------- real engines
@pytest.fixture(scope="module")
def redis_url(tmp_path_factory):
    if shutil.which("redis-server") is None:
        pytest.skip("redis-server not installed")
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    d = tmp_path_factory.mktemp("redis")
    p = subprocess.Popen([shutil.which("redis-server") or "redis-server", "--port", str(port), "--bind",
                          "127.0.0.1", "--save", "", "--appendonly", "no", "--dir", str(d)], stdout=subprocess.DEVNULL)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    yield f"redis://127.0.0.1:{port}/0"
    p.terminate()
    p.wait(5)


def test_redis_writer_on_a_real_server(redis_url):
    import redis

    r = redis.Redis.from_url(redis_url)
    w = RedisWriter(r, ttl_seconds=600, lookups={"orders": ["customer_id"]})
    w.upsert("orders", "1", {"id": 1, "customer_id": 9, "total": "5.00"})
    assert json.loads(r.hget("orders:1", "total")) == "5.00" and 0 < r.ttl("orders:1") <= 600
    assert r.smembers("orders:by:customer_id:9") == {b"1"}
    w.upsert("orders", "1", {"id": 1, "customer_id": 4, "total": "5.00"})       # lookup moves with the value
    assert r.smembers("orders:by:customer_id:9") == set() and r.smembers("orders:by:customer_id:4") == {b"1"}
    w.delete("orders", "1")
    assert not r.exists("orders:1") and r.smembers("orders:by:customer_id:4") == set()


@pytest.mark.skipif(not MONGO_URL, reason="needs MongoDB (OPLIA_TEST_MONGO_URL)")
def test_mongo_writer_on_a_real_server(session_factory):
    from pymongo import MongoClient

    c = MongoClient(MONGO_URL, directConnection=True)
    c.drop_database("hyd_test")
    w = MongoWriter(c, "hyd_test")
    h = Hydrator(DOC, w, session_factory)
    h.process(parse_event(ev("orders", "c", after={"id": 3, "total": "1.00"})))
    h.process(parse_event(ev("lines", "c", after={"order_id": 3, "line": 1, "sku": "x"})))
    h.process(parse_event(ev("lines", "c", after={"order_id": 3, "line": 1, "sku": "x"})))     # redelivered
    got = c["hyd_test"]["orders"].find_one({"_id": "3"})
    assert got == {"_id": "3", "id": 3, "total": "1.00", "lines": [{"line": 1, "sku": "x"}]}
    h.process(parse_event(ev("orders", "d", before={"id": 3})))
    assert c["hyd_test"]["orders"].count_documents({}) == 0


def test_dynamodb_writer_in_moto():
    from moto import mock_aws

    with mock_aws():
        c = boto3.client("dynamodb", region_name="eu-west-1")
        c.create_table(TableName="oplia_app", BillingMode="PAY_PER_REQUEST",
                       AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"},
                                             {"AttributeName": "SK", "AttributeType": "S"}],
                       KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"},
                                  {"AttributeName": "SK", "KeyType": "RANGE"}])
        w = DynamoWriter(c, "oplia_app", {"orders": {"PK": "CUSTOMERS#{customer_id}", "SK": "ORDERS#{id}"}})
        w.upsert("orders", "1", {"id": 1, "customer_id": 9, "total": 2.5, "note": None})
        item = c.get_item(TableName="oplia_app", Key={"PK": {"S": "CUSTOMERS#9"}, "SK": {"S": "ORDERS#1"}})["Item"]
        assert item["total"] == {"N": "2.5"} and item["entity"] == {"S": "orders"} and "note" not in item
        w.delete("orders", "1", {"id": 1, "customer_id": 9})
        assert "Item" not in c.get_item(TableName="oplia_app", Key={"PK": {"S": "CUSTOMERS#9"},
                                                                   "SK": {"S": "ORDERS#1"}})


def test_timestream_and_redshift_against_the_real_service_models():
    ts = boto3.client("timestream-write", region_name="eu-west-1")
    stub = Stubber(ts)
    stub.add_response("write_records", {"RecordsIngested": {"Total": 1}},
                      {"DatabaseName": "metrics", "TableName": "readings", "Records": [{
                          "Dimensions": [{"Name": "device", "Value": "d1"}], "MeasureName": "readings",
                          "MeasureValueType": "MULTI", "MeasureValues": [{"Name": "temp", "Value": "21.5",
                                                                          "Type": "DOUBLE"}],
                          "Time": "1767225600000", "TimeUnit": "MILLISECONDS", "Version": 7}]})
    stub.activate()
    w = TimestreamWriter(ts, "metrics", {"readings": {"time": "at", "dimensions": ["device"], "measures": ["temp"],
                                                      "version": "rev"}})
    w.upsert("readings", "1", {"id": 1, "device": "d1", "temp": 21.5, "at": "2026-01-01T00:00:00+00:00", "rev": 7})
    w.flush()
    stub.assert_no_pending_responses()

    rs = boto3.client("redshift-data", region_name="eu-west-1")
    st = Stubber(rs)
    tgt = {"WorkgroupName": "oplia-wh"}
    st.add_response("execute_statement", {"Id": "s1", "SessionId": "sess"},
                    {"Sql": 'CREATE TEMP TABLE "orders__oplia_stage" (LIKE "public"."orders")',
                     "SessionKeepAliveSeconds": 300, "Database": "dev", **tgt})
    st.add_response("describe_statement", {"Id": "s1", "Status": "FINISHED"}, {"Id": "s1"})
    st.add_response("execute_statement", {"Id": "s2"}, {"Sql": ANY, "SessionId": "sess"})
    st.add_response("describe_statement", {"Id": "s2", "Status": "FINISHED"}, {"Id": "s2"})
    st.add_response("execute_statement", {"Id": "s3"}, {"Sql": ANY, "SessionId": "sess", "Parameters": [
        {"name": "c0", "value": "1"}, {"name": "c1", "value": "9.5"}]})
    st.add_response("describe_statement", {"Id": "s3", "Status": "FINISHED"}, {"Id": "s3"})
    st.add_response("batch_execute_statement", {"Id": "b1"}, {"SessionId": "sess", "Sqls": ANY})
    st.add_response("describe_statement", {"Id": "b1", "Status": "FINISHED"}, {"Id": "b1"})
    st.activate()
    rw = RedshiftMergeWriter(rs, tgt, "dev", "public", {"orders": ["id"]}, sleep=lambda s: None)
    rw.upsert("orders", "1", {"id": 1, "total": "9.5"})
    rw.flush()
    st.assert_no_pending_responses()


def test_redshift_data_api_null_and_empty_values_are_literals():
    """Data API: a NULL parameter becomes the string 'NULL' and a zero-length one fails the statement."""
    rs = boto3.client("redshift-data", region_name="eu-west-1")
    st = Stubber(rs)
    tgt = {"WorkgroupName": "oplia-wh"}
    st.add_response("execute_statement", {"Id": "s1", "SessionId": "sess"}, {"Sql": ANY, "SessionKeepAliveSeconds": 300,
                                                                            "Database": "dev", **tgt})
    st.add_response("describe_statement", {"Id": "s1", "Status": "FINISHED"}, {"Id": "s1"})
    st.add_response("execute_statement", {"Id": "s2"}, {"Sql": ANY, "SessionId": "sess"})
    st.add_response("describe_statement", {"Id": "s2", "Status": "FINISHED"}, {"Id": "s2"})
    st.add_response("execute_statement", {"Id": "s3"}, {
        "Sql": 'INSERT INTO "orders__oplia_stage" ("id", "note", "total", _oplia_op) VALUES (:c0, \'\', NULL, \'u\')',
        "SessionId": "sess", "Parameters": [{"name": "c0", "value": "1"}]})
    st.add_response("describe_statement", {"Id": "s3", "Status": "FINISHED"}, {"Id": "s3"})
    st.add_response("batch_execute_statement", {"Id": "b1"}, {"SessionId": "sess", "Sqls": ANY})
    st.add_response("describe_statement", {"Id": "b1", "Status": "FINISHED"}, {"Id": "b1"})
    st.activate()
    rw = RedshiftMergeWriter(rs, tgt, "dev", "public", {"orders": ["id"]}, sleep=lambda s: None)
    rw.upsert("orders", "1", {"id": 1, "note": "", "total": None})
    rw.flush()
    st.assert_no_pending_responses()


@respx.mock
def test_opensearch_and_azure_search_documented_calls():
    bulk = respx.post("https://search-x.eu-west-1.es.amazonaws.com/_bulk").mock(
        return_value=httpx.Response(200, json={"errors": False, "items": []}))
    w = OpenSearchWriter(ResilientClient(timeout=5, max_retries=0), "https://search-x.eu-west-1.es.amazonaws.com")
    w.upsert("docs", "5", {"title": "t", "embedding": [3.0, 4.0]})
    lines = bulk.calls[0].request.content.decode().splitlines()
    assert json.loads(lines[0]) == {"index": {"_index": "docs", "_id": "5"}}
    assert json.loads(lines[1])["embedding"] == [0.6, 0.8]
    assert bulk.calls[0].request.headers["content-type"] == "application/x-ndjson"
    idx = respx.post("https://oplia.search.windows.net/indexes/order-docs/docs/index?api-version=2024-07-01").mock(
        return_value=httpx.Response(200, json={"value": [{"key": "5", "status": True}]}))
    a = AzureSearchWriter(ResilientClient(timeout=5, max_retries=0), "https://oplia.search.windows.net",
                          lambda: {"api-key": "k"})
    a.upsert("order_docs", "5", {"title": "t"})
    a.delete("order_docs", "5")
    assert json.loads(idx.calls[0].request.content)["value"][0]["@search.action"] == "mergeOrUpload"
    assert json.loads(idx.calls[1].request.content)["value"][0] == {"@search.action": "delete", "id": "5"}
    with pytest.raises(ValueError):
        OpenSearchWriter(None, "http://plain")
    kq = respx.post("https://adx1.westeurope.kusto.windows.net/v1/rest/ingest/telemetry/readings").mock(
        return_value=httpx.Response(200, json={}))
    k = KustoWriter(ResilientClient(timeout=5, max_retries=0), "https://adx1.westeurope.kusto.windows.net",
                    "telemetry", lambda: "tok")
    k.upsert("readings", "1", {"a": 1})
    k.upsert("readings", "2", {"a": 2})
    k.flush()
    import gzip

    req = kq.calls[0].request
    assert req.url.params["streamFormat"] == "MultiJSON" and req.url.params["mappingName"] == "oplia_json"
    assert gzip.decompress(req.content).decode().splitlines() == ['{"a": 1}', '{"a": 2}']
    assert req.headers["authorization"] == "Bearer tok" and req.headers["content-encoding"] == "gzip"


# ----------------------------------------------------------------------------- SDK-signature-checked fakes
class SdkFake:
    """Records calls and binds each one to the real SDK method signature."""

    def __init__(self, cls, log, returns=None):
        self._cls, self._log, self._returns = cls, log, returns or {}

    def __getattr__(self, name):
        real = getattr(self._cls, name)

        def call(*a, **kw):
            inspect.signature(real).bind(None, *a, **kw)
            self._log.append((self._cls.__name__, name, a, kw))
            r = self._returns.get(name)
            return r() if callable(r) else r
        return call


def test_cloud_writers_call_real_sdk_signatures():
    from azure.cosmos import ContainerProxy
    from cassandra.cluster import Session as CqlSession
    from google.cloud.bigquery import Client as BqClient
    from google.cloud.bigtable.row import DirectRow
    from google.cloud.bigtable.table import Table as BtTable
    from google.cloud.firestore_v1.client import Client as FsClient
    from google.cloud.firestore_v1.collection import CollectionReference
    from google.cloud.firestore_v1.document import DocumentReference
    from google.cloud.spanner_v1.batch import Batch
    from google.cloud.spanner_v1.database import Database
    from gremlin_python.driver.client import Client as GremlinClient

    log: list = []

    class Done:
        def result(self):
            return None

        def all(self):
            return self

    batch = SdkFake(Batch, log)

    class Ctx:
        def __enter__(self):
            return batch

        def __exit__(self, *a):
            return False

    SpannerWriter(SdkFake(Database, log, {"batch": Ctx})).upsert("orders", "1", {"id": "1", "total": 2})
    row = SdkFake(DirectRow, log)
    BigtableWriter({"orders": SdkFake(BtTable, log, {"direct_row": row})}).upsert("orders", "1", {"total": 2})
    doc = SdkFake(DocumentReference, log)
    coll = SdkFake(CollectionReference, log, {"document": doc})
    FirestoreWriter(SdkFake(FsClient, log, {"collection": coll})).upsert("orders", "1", {"total": 2})
    cw = CosmosWriter({"orders": SdkFake(ContainerProxy, log)}, {"orders": "customer_id"})
    cw.upsert("orders", "1", {"customer_id": 9})
    cw.delete("orders", "1", {"customer_id": 9})
    GremlinWriter(SdkFake(GremlinClient, log, {"submit": Done}), partition_property="pk").upsert(
        "orders", "1", {"total": 2})
    CqlWriter(SdkFake(CqlSession, log), "shop", {"orders": ["id"]}).upsert("orders", "1", {"id": 1, "total": 2})
    bq = BigQueryMergeWriter(SdkFake(BqClient, log, {"load_table_from_json": Done, "query": Done}), "proj.ds",
                             {"orders": ["id"]})
    bq.upsert("orders", "1", {"id": 1, "total": 2})
    bq.delete("orders", "2", {"id": 2})
    bq.flush()
    names = [(c, n) for c, n, _, _ in log]
    for want in [("Batch", "insert_or_update"), ("DirectRow", "set_cell"), ("DirectRow", "commit"),
                 ("DocumentReference", "set"), ("ContainerProxy", "upsert_item"), ("ContainerProxy", "delete_item"),
                 ("Client", "submit"), ("Session", "execute"),
                 ("Client", "load_table_from_json"), ("Client", "query")]:
        assert want in names, want
    merge = next(a[0] for c, n, a, _ in log if n == "query")
    assert "WHEN MATCHED AND S._oplia_op = 'd' THEN DELETE" in merge and "`proj.ds.orders__oplia_stage`" in merge


def test_pgvector_writer_sql():
    calls = []

    class Conn:
        def execute(self, sql, params):
            calls.append((sql, params))

    PgVectorWriter(Conn(), {"docs": ["id"]}).upsert("docs", "1", {"id": 1, "embedding": [0.5, 0.25]})
    assert calls == [('UPDATE "docs" SET "embedding" = %s::vector WHERE "id" = %s', ("[0.5,0.25]", 1))]
    assert math.isclose(sum(x * x for x in [0.6, 0.8]), 1.0)
