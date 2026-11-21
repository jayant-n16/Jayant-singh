"""Run the Synapse / Fabric Warehouse MERGE writer through pyodbc + Microsoft ODBC Driver 18 (from inside the
control-plane image in CI) against a SQL Server: MERGE syntax and #temp staging are the same.

Usage: OPLIA_ODBC_CONN='DRIVER={ODBC Driver 18 for SQL Server};SERVER=...;...' python odbc-merge-smoke.py
Exit code 0 and one JSON line on success."""

from __future__ import annotations

import json
import os
import sys

import pyodbc

from oplia_ctl.migration.targets import TsqlWarehouseMergeWriter


def main() -> int:
    conn_str = os.environ["OPLIA_ODBC_CONN"]

    def connect() -> pyodbc.Connection:
        return pyodbc.connect(conn_str, autocommit=True)   # Synapse: no CREATE TABLE inside a user transaction

    c = connect()
    drv = c.getinfo(pyodbc.SQL_DRIVER_NAME), c.getinfo(pyodbc.SQL_DRIVER_VER)
    cur = c.cursor()
    cur.execute("IF OBJECT_ID('dbo.odbc_orders') IS NOT NULL DROP TABLE dbo.odbc_orders")
    cur.execute("CREATE TABLE dbo.odbc_orders (id int PRIMARY KEY, total decimal(12,2), note nvarchar(50))")
    cur.execute("INSERT INTO dbo.odbc_orders VALUES (1, 1.00, N'old'), (2, 2.00, N'gone')")
    c.close()
    w = TsqlWarehouseMergeWriter(connect, "dbo", {"odbc_orders": ["id"]}, paramstyle="qmark")
    w.upsert("odbc_orders", "1", {"id": 1, "total": "9.75", "note": "new"})
    w.delete("odbc_orders", "2", {"id": 2})
    w.upsert("odbc_orders", "3", {"id": 3, "total": "3.10", "note": "ins"})
    w.flush()
    c = connect()
    cur = c.cursor()
    cur.execute("SELECT id, CAST(total AS varchar(20)), note FROM dbo.odbc_orders ORDER BY id")
    rows = [tuple(r) for r in cur.fetchall()]
    c.close()
    ok = rows == [(1, "9.75", "new"), (3, "3.10", "ins")]
    print(json.dumps({"ok": ok, "driver": drv[0], "driver_version": drv[1], "pyodbc": pyodbc.version, "rows": rows}))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
