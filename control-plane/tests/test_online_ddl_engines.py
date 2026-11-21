"""FR-02 online DDL for SQL Server and Oracle: planner (no database) and, when the servers are available
(CI starts SQL Server 2022 Developer and Oracle Database Free 23), a full expand / backfill / validate /
contract run with a concurrent writer."""

from __future__ import annotations

import json
import os
import threading
import time

import pytest

from oplia_ctl.databases.registry import DatabaseRegistry, DatabaseSpec, connect_oracle, connect_sqlserver
from oplia_ctl.migration.online_ddl import (
    ColumnInfo,
    OnlineSchemaChange,
    SchemaChange,
    SchemaContract,
    TableInfo,
    build_plan,
)
from oplia_ctl.migration.online_ddl_engines import Caps, keyset_after, keyset_params, retryable_code
from oplia_ctl.secrets import StaticSecretProvider

MSSQL_URL = os.environ.get("OPLIA_TEST_MSSQL_URL", "")      # sqlserver://sa:...@localhost:1433/master
ORACLE_URL = os.environ.get("OPLIA_TEST_ORACLE_URL", "")    # oracle://oplia:...@localhost:1521/FREEPDB1

ONLINE, OFFLINE = Caps(True, "Developer"), Caps(False, "Standard Edition")


def _ms_info() -> TableInfo:
    return TableInfo(columns={"id": ColumnInfo("id", "bigint", False, None, []),
                              "amount": ColumnInfo("amount", "int", True, None, []),
                              "note": ColumnInfo("note", "nvarchar(50) COLLATE Latin1_General_CI_AS", True, None, []),
                              "status": ColumnInfo("status", "varchar(10)", True, "('ok')", [])},
                     pk=["id"], indexes=["PK_orders"])


def _ora_info() -> TableInfo:
    return TableInfo(columns={"ID": ColumnInfo("ID", "NUMBER(19,0)", False, None, []),
                              "AMOUNT": ColumnInfo("AMOUNT", "NUMBER(10,0)", True, None, []),
                              "NOTE": ColumnInfo("NOTE", "VARCHAR2(50)", True, None, [])},
                     pk=["ID"], indexes=["SYS_C001"])


def _change(*ops, **kw):
    return SchemaChange.model_validate({"database": "app", "table": "orders", "operations": list(ops), **kw})


# ----------------------------------------------------------------------------- planner
def test_mssql_plan_is_online_or_refused():
    p = build_plan(_change(
        {"op": "add_column", "column": "flag", "type": "bit", "default": 0, "nullable": False},
        {"op": "add_column", "column": "memo", "type": "nvarchar(20)"},
        {"op": "add_index", "name": "ix_memo", "columns": ["memo"]},
        {"op": "set_not_null", "column": "amount"},
        {"op": "change_type", "column": "amount", "type": "bigint"},
        {"op": "rename_column", "column": "note", "new_name": "remark"}), "sqlserver", _ms_info(), {}, ONLINE)
    sql = [s.sql for s in p.expand]
    assert sql[0].startswith("ALTER TABLE [dbo].[orders] ADD [flag] BIT NOT NULL CONSTRAINT [df_oplia_")
    assert sql[1] == "ALTER TABLE [dbo].[orders] ADD [memo] NVARCHAR(20) NULL"
    assert sql[2] == "CREATE INDEX [ix_memo] ON [dbo].[orders] ([memo]) WITH (ONLINE = ON)"
    assert any("CREATE OR ALTER TRIGGER" in s and "TRIGGER_NESTLEVEL(@@PROCID) > 1" in s for s in sql)
    assert p.validate[0].sql == ("ALTER TABLE [dbo].[orders] ALTER COLUMN [amount] int NOT NULL "
                                 "WITH (ONLINE = ON)")
    assert any("sp_rename N'dbo.orders.amount', N'amount__oplia_old', N'COLUMN'" in s.sql for s in p.contract)
    assert p.contract[-1].sql == "ALTER TABLE [dbo].[orders] DROP COLUMN [note]"
    # a collation is kept when a char column's nullability changes (ALTER COLUMN would reset it otherwise)
    p2 = build_plan(_change({"op": "set_not_null", "column": "note"}), "sqlserver", _ms_info(), {}, ONLINE)
    assert "COLLATE Latin1_General_CI_AS NOT NULL WITH (ONLINE = ON)" in p2.validate[0].sql
    # editions without online operations: refused, never an offline fallback
    for op in ({"op": "add_index", "name": "ix", "columns": ["amount"]},
               {"op": "add_column", "column": "f", "type": "int", "default": 1, "nullable": False},
               {"op": "set_not_null", "column": "amount"}):
        with pytest.raises(ValueError, match="cannot run online"):
            build_plan(_change(op), "sqlserver", _ms_info(), {}, OFFLINE)
    # a NULL column without default needs no edition
    assert build_plan(_change({"op": "add_column", "column": "m", "type": "int"}), "sqlserver", _ms_info(), {},
                      OFFLINE).expand
    with pytest.raises(ValueError, match="cannot add a"):
        build_plan(_change({"op": "add_column", "column": "x", "type": "nvarchar(max)", "default": "a",
                            "nullable": False}), "sqlserver", _ms_info(), {}, ONLINE)
    with pytest.raises(ValueError, match="refuses ALTER COLUMN"):
        build_plan(_change({"op": "add_index", "name": "ix_a", "columns": ["amount"]},
                           {"op": "set_not_null", "column": "amount"}), "sqlserver", _ms_info(), {}, ONLINE)
    with pytest.raises(ValueError, match="DEFAULT constraint"):
        build_plan(_change({"op": "change_type", "column": "status", "type": "varchar(20)"}), "sqlserver",
                   _ms_info(), {}, ONLINE)


def test_mssql_constraints_are_added_without_a_scan_and_checked_by_query():
    ref = TableInfo(columns={"id": ColumnInfo("id", "int", False, None, [])}, pk=["id"], indexes=[])
    p = build_plan(_change({"op": "add_foreign_key", "name": "fk_c", "columns": ["amount"], "ref_table": "customers",
                            "ref_columns": ["id"], "on_delete": "RESTRICT"},
                           {"op": "add_check", "name": "ck_amt", "expression": "amount >= 0"}),
                   "sqlserver", _ms_info(), {"customers": ref}, OFFLINE)
    assert p.expand[0].sql.startswith("ALTER TABLE [dbo].[orders] WITH NOCHECK ADD CONSTRAINT [fk_c]")
    assert p.expand[0].sql.endswith("ON DELETE NO ACTION")
    assert [c.what for c in p.checks] == ["no orphan rows for fk_c", "rows satisfy ck_amt"]
    assert "WITH NOCHECK ADD CONSTRAINT [ck_amt] CHECK ([amount] >= 0)" in p.validate[0].sql
    assert any("not trusted" in w for w in p.warnings)


def test_oracle_plan_uses_nonblocking_ddl_and_upper_case_names():
    ref = TableInfo(columns={"ID": ColumnInfo("ID", "NUMBER", False, None, [])}, pk=["ID"], indexes=[])
    p = build_plan(_change(
        {"op": "add_column", "column": "flag", "type": "number(1)", "default": 0, "nullable": False},
        {"op": "add_index", "name": "ix_flag", "columns": ["flag"]},
        {"op": "add_foreign_key", "name": "fk_c", "columns": ["flag"], "ref_table": "customers",
         "ref_columns": ["id"], "on_delete": "NO ACTION"},
        {"op": "add_check", "name": "ck_flag", "expression": "flag >= 0"},
        {"op": "set_not_null", "column": "note"},
        {"op": "change_type", "column": "amount", "type": "number(19)"},
        {"op": "rename_column", "column": "note", "new_name": "remark"},
        {"op": "drop_index", "name": "SYS_C001"}), "oracle", _ora_info(), {"CUSTOMERS": ref}, ONLINE)
    sql = [s.sql for s in p.expand]
    assert sql[0] == 'ALTER TABLE "ORDERS" ADD ("FLAG" NUMBER(1) DEFAULT 0 NOT NULL)'
    assert sql[1] == 'CREATE INDEX "IX_FLAG" ON "ORDERS" ("FLAG") ONLINE'
    assert sql[2].endswith('REFERENCES "CUSTOMERS" ("ID") ENABLE NOVALIDATE')
    assert 'CHECK ("FLAG" >= 0) ENABLE NOVALIDATE' in sql[3]
    with pytest.raises(ValueError, match="used by check CK"):
        build_plan(_change({"op": "add_check", "name": "ck", "expression": "amount > 0"},
                           {"op": "change_type", "column": "amount", "type": "number(19)"}), "oracle", _ora_info(),
                   {}, ONLINE)
    assert "NOT NULL ENABLE NOVALIDATE)" in sql[4]
    assert any(':NEW."AMOUNT__OPLIA_NEW" := CAST(:NEW."AMOUNT" AS NUMBER(19))' in s for s in sql)
    assert all(s.sql.endswith("VALIDATE") for s in p.validate)
    assert 'DROP INDEX "SYS_C001" ONLINE' in [s.sql for s in p.contract]
    assert 'ALTER TABLE "ORDERS" SET UNUSED ("NOTE") ONLINE' in [s.sql for s in p.contract]
    assert any("supplemental logging" in w for w in p.warnings)
    with pytest.raises(ValueError, match="Standard Edition 2"):
        build_plan(_change({"op": "add_index", "name": "ix", "columns": ["amount"]}), "oracle", _ora_info(), {},
                   OFFLINE)


def test_keyset_without_row_constructors():
    def q(n):
        return f"[{n}]"

    sql, n = keyset_after("sqlserver", ["a", "b"], q)
    assert sql == "(([a] > %s) OR ([a] = %s AND [b] > %s))" and n == 3
    assert keyset_params([1, 2]) == [1, 1, 2]
    sql, n = keyset_after("oracle", ["a", "b"], q, start=4)
    assert sql == "(([a] > :4) OR ([a] = :5 AND [b] > :6))" and n == 3


def test_null_safe_equality_never_unknown():
    """Found by the SQL Server run: NOT (a = b OR (a IS NULL AND b IS NULL)) is UNKNOWN when only one side is
    NULL, so the backfill skipped every not-yet-filled row and the zero-mismatch check counted none of them."""
    from oplia_ctl.migration.online_ddl_engines import null_eq

    assert null_eq("a", "b") == "(CASE WHEN a = b OR (a IS NULL AND b IS NULL) THEN 1 ELSE 0 END = 1)"
    p = build_plan(_change({"op": "change_type", "column": "amount", "type": "bigint"}), "sqlserver", _ms_info(),
                   {}, ONLINE)
    assert "WHERE NOT ((CASE WHEN [amount__oplia_new] = (CAST([amount] AS BIGINT))" in p.checks[0].sql


def test_retryable_errors_and_dsns():
    assert retryable_code("sqlserver", Exception(1222, b"Lock request time out period exceeded."))
    assert not retryable_code("sqlserver", Exception(2627, b"duplicate"))

    class OraErr:
        code = 54

    assert retryable_code("oracle", Exception(OraErr()))
    with pytest.raises(ValueError, match="sqlserver://"):
        connect_sqlserver("mssql://h/db")
    with pytest.raises(ValueError, match="oracle://"):
        connect_oracle("oracle://u:p@h:1521")
    with pytest.raises(ValueError, match="DR consistency checks support"):
        DatabaseSpec(name="x", engine="oracle", cloud="aws", role="dr", dsn_secret="d", dr_of="y")


# ----------------------------------------------------------------------------- real servers
def _run(session_factory, engine, dsn, setup, change, writer_sql, check):
    reg = DatabaseRegistry([DatabaseSpec(name="app", engine=engine, cloud="azure", role="primary",
                                         dsn_secret="d")], StaticSecretProvider({"d": dsn}), session_factory)
    conn = reg.connect(reg.get("app"))[0]
    cur = conn.cursor()
    for s in setup:
        cur.execute(s)
    cur.close()
    conn.close()
    health = reg.check("app", triggered_by="test")
    assert health["ok"], health
    events: list = []
    ex = OnlineSchemaChange(reg, session_factory, audit=lambda e, d: events.append(e), max_batches_per_step=2)
    contract = SchemaContract(ex, reg, session_factory)
    jid = ex(ex.parse({"database": "app", "change": json.dumps(change)}))["job_id"]
    stop, errors, lat = threading.Event(), [], []

    def writer():
        w = reg.connect(reg.get("app"))[0]
        c = w.cursor()
        i = 0
        while not stop.is_set():
            t0 = time.monotonic()
            try:
                c.execute(writer_sql(i))
            except Exception as e:
                errors.append(repr(e))
            lat.append(time.monotonic() - t0)
            i += 1
            time.sleep(0.005)
        c.close()
        w.close()

    t = threading.Thread(target=writer)
    t.start()
    try:
        for _ in range(300):
            ex.run_pending()
            job = ex.get(jid)
            if job["status"] in ("SUCCEEDED", "FAILED"):
                break
    finally:
        stop.set()
        t.join()
    assert job["status"] == "SUCCEEDED", (job["error"], job["state"].get("failed_step"))
    assert errors == [] and max(lat) < 2.0, (errors[:3], max(lat))
    assert all(c["passed"] for c in job["state"]["checks"])
    cj = contract(contract.parse({"expand_job_id": jid}))["job_id"]
    for _ in range(50):
        contract.run_pending()
        if contract.get(cj)["status"] in ("SUCCEEDED", "FAILED"):
            break
    assert contract.get(cj)["status"] == "SUCCEEDED", contract.get(cj)
    conn = reg.connect(reg.get("app"))[0]
    try:
        check(conn)
    finally:
        conn.close()
    assert events == ["migration.schema_change.succeeded"]
    return job


@pytest.mark.skipif(not MSSQL_URL, reason="needs SQL Server (OPLIA_TEST_MSSQL_URL)")
def test_mssql_online_change_with_concurrent_writes(session_factory):
    setup = ["IF OBJECT_ID('dbo.s_orders') IS NOT NULL DROP TABLE dbo.s_orders",
             "IF OBJECT_ID('dbo.s_customers') IS NOT NULL DROP TABLE dbo.s_customers",
             "CREATE TABLE dbo.s_customers (id int PRIMARY KEY)",
             "INSERT INTO dbo.s_customers SELECT TOP (50) ROW_NUMBER() OVER (ORDER BY object_id) FROM sys.all_objects",
             "CREATE TABLE dbo.s_orders (id int PRIMARY KEY, customer_id int, amount int, note nvarchar(50), "
             "region int)",
             "INSERT INTO dbo.s_orders SELECT n, n % 50 + 1, n, CONCAT('n', n), n % 5 FROM (SELECT TOP (3000) "
             "ROW_NUMBER() OVER (ORDER BY a.object_id) n FROM sys.all_objects a CROSS JOIN sys.all_objects b) x"]
    change = {"table": "s_orders", "batch_size": 500, "batch_pause_ms": 0, "operations": [
        {"op": "add_column", "column": "discount", "type": "int", "default": 0, "nullable": False},
        {"op": "add_index", "name": "ix_s_cust", "columns": ["customer_id"]},
        {"op": "add_foreign_key", "name": "fk_s_cust", "columns": ["customer_id"], "ref_table": "s_customers",
         "ref_columns": ["id"]},
        {"op": "set_not_null", "column": "region"},
        {"op": "change_type", "column": "amount", "type": "bigint"},
        {"op": "rename_column", "column": "note", "new_name": "remark"}]}

    def check(conn):
        c = conn.cursor()
        c.execute("UPDATE dbo.s_orders SET remark = N'via-new' WHERE id = 9")
        c.execute("SELECT name, TYPE_NAME(user_type_id), is_nullable FROM sys.columns "
                  "WHERE object_id = OBJECT_ID('dbo.s_orders')")
        cols = {r[0]: (r[1], r[2]) for r in c.fetchall()}
        assert cols["amount"][0] == "bigint" and "remark" in cols and "note" not in cols
        assert not cols["region"][1]
        c.execute("SELECT amount, remark FROM dbo.s_orders WHERE id = 9")
        assert tuple(c.fetchone()) == (9, "via-new")
        c.execute("INSERT INTO dbo.s_orders (id, customer_id, amount, remark, region) VALUES (9999, 1, 5, N'x', 1)")
        c.execute("SELECT discount FROM dbo.s_orders WHERE id = 9999")
        assert c.fetchone()[0] == 0
        c.close()

    job = _run(session_factory, "sqlserver", MSSQL_URL, setup, change,
               lambda i: f"UPDATE dbo.s_orders SET note = N'w{i}' WHERE id = {1 + i % 3000}", check)  # noqa: S608
    assert "EngineEdition 3" in job["state"]["server"]


@pytest.mark.skipif(not ORACLE_URL, reason="needs Oracle (OPLIA_TEST_ORACLE_URL)")
def test_oracle_online_change_with_concurrent_writes(session_factory):
    setup = ["BEGIN EXECUTE IMMEDIATE 'DROP TABLE o_orders PURGE'; EXCEPTION WHEN OTHERS THEN NULL; END;",
             "BEGIN EXECUTE IMMEDIATE 'DROP TABLE o_customers PURGE'; EXCEPTION WHEN OTHERS THEN NULL; END;",
             "CREATE TABLE o_customers (id NUMBER(10) PRIMARY KEY)",
             "INSERT INTO o_customers SELECT level FROM dual CONNECT BY level <= 50",
             "CREATE TABLE o_orders (id NUMBER(10) PRIMARY KEY, customer_id NUMBER(10), amount NUMBER(10), "
             "note VARCHAR2(50))",
             "INSERT INTO o_orders SELECT level, MOD(level, 50) + 1, level, 'n' || level FROM dual "
             "CONNECT BY level <= 3000"]
    change = {"table": "o_orders", "batch_size": 500, "batch_pause_ms": 0, "operations": [
        {"op": "add_column", "column": "discount", "type": "number(10)", "default": 0, "nullable": False},
        {"op": "add_index", "name": "ix_o_cust", "columns": ["customer_id"]},
        {"op": "add_foreign_key", "name": "fk_o_cust", "columns": ["customer_id"], "ref_table": "o_customers",
         "ref_columns": ["id"]},
        {"op": "add_check", "name": "ck_o_discount", "expression": "discount >= 0"},
        {"op": "set_not_null", "column": "customer_id"},
        {"op": "change_type", "column": "amount", "type": "number(19)"},
        {"op": "rename_column", "column": "note", "new_name": "remark"}]}

    def check(conn):
        c = conn.cursor()
        c.execute("UPDATE o_orders SET remark = 'via-new' WHERE id = 9")
        c.execute("SELECT column_name, data_precision FROM user_tab_columns WHERE table_name = 'O_ORDERS'")
        cols = dict(c.fetchall())
        assert cols["AMOUNT"] == 19 and "REMARK" in cols and "NOTE" not in cols
        c.execute("SELECT amount, remark FROM o_orders WHERE id = 9")
        assert tuple(c.fetchone()) == (9, "via-new")
        c.execute("SELECT constraint_name, validated FROM user_constraints WHERE table_name = 'O_ORDERS' "
                  "AND constraint_name IN ('FK_O_CUST', 'CK_O_DISCOUNT')")
        assert dict(c.fetchall()) == {"FK_O_CUST": "VALIDATED", "CK_O_DISCOUNT": "VALIDATED"}
        c.close()

    _run(session_factory, "oracle", ORACLE_URL, setup, change,
         lambda i: f"UPDATE o_orders SET note = 'w{i}' WHERE id = {1 + i % 3000}", check)  # noqa: S608
