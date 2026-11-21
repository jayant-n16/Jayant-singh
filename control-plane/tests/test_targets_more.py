"""FR-04 writers added for Cosmos DB for Table / Table Storage, Synapse / Fabric Warehouse MERGE and Vertex AI
Search. Real-service runs: Azurite (Table API emulator) and SQL Server 2022 (same MERGE syntax as Synapse /
Fabric) when CI provides them; Vertex AI Search is checked against the SDK's own request types."""

from __future__ import annotations

import os
import uuid

import pytest

from oplia_ctl.migration.targets import TableWriter, TsqlWarehouseMergeWriter, VertexSearchWriter

AZURITE = os.environ.get("OPLIA_TEST_AZURITE_TABLES", "")   # Azurite connection string (well-known dev account)
MSSQL_URL = os.environ.get("OPLIA_TEST_MSSQL_URL", "")


# ----------------------------------------------------------------------------- Table API
class _FakeTable:
    def __init__(self):
        self.calls = []

    def upsert_entity(self, entity, mode):
        self.calls.append(("upsert", entity, str(mode)))

    def delete_entity(self, partition_key, row_key):
        self.calls.append(("delete", partition_key, row_key))


def test_table_writer_keys_and_properties_follow_the_table_rules():
    t = _FakeTable()
    w = TableWriter({"orders": t}, {"orders": "region"})
    w.upsert("orders", "42", {"id": 42, "region": "eu", "items": [1, 2], "total": 1.5})
    _op, ent, mode = t.calls[0]
    assert (ent["PartitionKey"], ent["RowKey"], ent["items"]) == ("eu", "42", "[1, 2]") and "REPLACE" in mode
    w.delete("orders", "42", {"region": "eu"})
    assert t.calls[1] == ("delete", "eu", "42")
    for bad in ("a/b", "a#b", "a?b", "a\\b", "a\tb", "x" * 1025, ""):
        with pytest.raises(ValueError, match="not a valid Table key"):
            w.upsert("orders", bad, {"region": "eu"})
    with pytest.raises(ValueError, match="property names"):
        w.upsert("orders", "1", {"region": "eu", "bad-name": 1})
    with pytest.raises(ValueError, match="allows 252"):
        w.upsert("orders", "1", {"region": "eu", **{f"p{i}": i for i in range(260)}})
    with pytest.raises(ValueError, match="partition key field"):
        w.upsert("orders", "1", {"id": 1})
    TableWriter({"t": t}, {}).upsert("t", "7", {"a": 1})          # no partition field: the table name
    assert t.calls[-1][1]["PartitionKey"] == "t"
    # Azure Cosmos DB for Table: RowKey at most 255 bytes, reserved property names
    cw = TableWriter({"t": t}, {}, cosmos=True)
    with pytest.raises(ValueError, match="255 bytes"):
        cw.upsert("t", "é" * 128, {"a": 1})
    with pytest.raises(ValueError, match="property names"):
        cw.upsert("t", "1", {"etag": "x"})
    TableWriter({"t": t}, {}).upsert("t", "x" * 300, {"etag": "x"})     # fine on Table Storage


@pytest.mark.skipif(not AZURITE, reason="needs Azurite (OPLIA_TEST_AZURITE_TABLES)")
def test_table_writer_against_azurite():
    from azure.data.tables import TableServiceClient

    svc = TableServiceClient.from_connection_string(AZURITE)
    name = "oplia" + uuid.uuid4().hex[:10]
    table = svc.create_table(name)
    try:
        w = TableWriter({"orders": table}, {"orders": "region"})
        w.upsert("orders", "1", {"region": "eu", "total": 10, "note": "a"})
        w.upsert("orders", "1", {"region": "eu", "total": 11})          # REPLACE: "note" is gone
        w.upsert("orders", "2", {"region": "us", "total": 5})
        e = table.get_entity("eu", "1")
        assert e["total"] == 11 and "note" not in e
        w.delete("orders", "2", {"region": "us"})
        w.delete("orders", "2", {"region": "us"})                        # idempotent
        assert sorted(x["RowKey"] for x in table.list_entities()) == ["1"]
    finally:
        svc.delete_table(name)


# ----------------------------------------------------------------------------- Synapse / Fabric MERGE
class _Cur:
    def __init__(self, log):
        self.log, self._rows = log, []

    def execute(self, sql, params=None):
        self.log.append((sql, params))
        if "INFORMATION_SCHEMA" in sql:
            self._rows = [("id", "int", None, 10, 0, None), ("total", "decimal", None, 12, 2, None),
                          ("note", "nvarchar", 50, None, None, None)]

    def fetchall(self):
        return self._rows


class _Conn:
    def __init__(self, log):
        self.log, self.closed = log, False

    def cursor(self):
        return _Cur(self.log)

    def close(self):
        self.closed = True


def test_tsql_warehouse_merge_statements():
    log, conns = [], []

    def connect():
        conns.append(_Conn(log))
        return conns[-1]

    w = TsqlWarehouseMergeWriter(connect, "dbo", {"orders": ["id"]}, batch=3)
    w.upsert("orders", "1", {"id": 1, "total": "9.50", "note": "a"})
    w.delete("orders", "2", {"id": 2})
    w.upsert("orders", "1", {"id": 1, "total": "9.75", "note": "b"})   # last change per key wins
    assert not log
    w.flush()
    sql = [s for s, _ in log]
    assert "CREATE TABLE [#orders__oplia_stage] ([id] int, [note] nvarchar(50), [total] decimal(12,2), " \
           "[_oplia_op] char(1))" in sql
    inserts = [p for s, p in log if s.startswith("INSERT")]
    assert inserts == [(1, "b", "9.75", "u"), (2, None, None, "d")]
    merge = next(s for s in sql if s.startswith("MERGE"))
    assert "WHEN MATCHED AND S.[_oplia_op] = 'd' THEN DELETE" in merge and merge.endswith(");")
    assert conns[0].closed
    with pytest.raises(ValueError, match="paramstyle"):
        TsqlWarehouseMergeWriter(connect, "dbo", {}, paramstyle="named")


@pytest.mark.skipif(not MSSQL_URL, reason="needs SQL Server (OPLIA_TEST_MSSQL_URL)")
def test_tsql_warehouse_merge_on_sql_server():
    from oplia_ctl.databases.registry import connect_sqlserver

    c = connect_sqlserver(MSSQL_URL)
    cur = c.cursor()
    cur.execute("IF OBJECT_ID('dbo.wh_orders') IS NOT NULL DROP TABLE dbo.wh_orders")
    cur.execute("CREATE TABLE dbo.wh_orders (id int PRIMARY KEY, total decimal(12,2), note nvarchar(50))")
    cur.execute("INSERT INTO dbo.wh_orders VALUES (1, 1.00, N'old'), (2, 2.00, N'gone')")
    c.close()
    w = TsqlWarehouseMergeWriter(lambda: connect_sqlserver(MSSQL_URL), "dbo", {"wh_orders": ["id"]},
                                 paramstyle="format")
    w.upsert("wh_orders", "1", {"id": 1, "total": "9.75", "note": "new"})
    w.delete("wh_orders", "2", {"id": 2})
    w.upsert("wh_orders", "3", {"id": 3, "total": "3.10", "note": "ins"})
    w.flush()
    w.flush()                                                           # empty batch: nothing to do
    c = connect_sqlserver(MSSQL_URL)
    cur = c.cursor()
    cur.execute("SELECT id, CAST(total AS varchar(20)), note FROM dbo.wh_orders ORDER BY id")
    assert [tuple(r) for r in cur.fetchall()] == [(1, "9.75", "new"), (3, "3.10", "ins")]
    c.close()


# ----------------------------------------------------------------------------- Vertex AI Search
class _FakeDocs:
    def __init__(self):
        self.reqs = []

    def update_document(self, request):
        self.reqs.append(request)

    def delete_document(self, request):
        from google.api_core.exceptions import NotFound

        self.reqs.append(request)
        if "missing" in request.name:
            raise NotFound("no such document")


def test_vertex_search_writer_builds_sdk_requests():
    from google.cloud import discoveryengine_v1 as de

    ds = "projects/p/locations/global/collections/default_collection/dataStores/orders-ds"
    f = _FakeDocs()
    w = VertexSearchWriter(f, {"orders": ds})
    w.upsert("orders", "order-1", {"id": 1, "title": "Blue mug", "price": "9.50"})
    r = f.reqs[0]
    assert isinstance(r, de.UpdateDocumentRequest) and r.allow_missing
    assert r.document.name == f"{ds}/branches/default_branch/documents/order-1" and r.document.id == "order-1"
    assert dict(r.document.struct_data)["title"] == "Blue mug"
    assert dict(r.document.struct_data)["_oplia_key"] == "order-1"
    # keys that are not RFC-1034 labels get a deterministic, collision-free id
    assert VertexSearchWriter.doc_id("42") == VertexSearchWriter.doc_id("42") != VertexSearchWriter.doc_id("43")
    assert VertexSearchWriter.doc_id("42").startswith("k-") and len(VertexSearchWriter.doc_id("42")) <= 128
    w.delete("orders", "missing")                                       # NotFound: already gone
    assert isinstance(f.reqs[-1], de.DeleteDocumentRequest)
    with pytest.raises(ValueError, match="dataStores"):
        VertexSearchWriter(f, {"x": "projects/p/dataStores/y"})
