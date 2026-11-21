"""FR-02 online DDL plans for SQL Server and Oracle (expand / backfill / validate / contract).

Each statement is generated from validated identifiers, SQLGlot-normalised types and parsed expressions,
and tagged with the lock it takes. What each engine documents, and therefore what the planner does:

SQL Server (Transact-SQL ``ALTER TABLE`` reference; "Guidelines for online index operations";
"Editions and supported features of SQL Server 2022"):

* Every ``ALTER TABLE`` takes a schema-modification (Sch-M) lock for the statement ("except online index
  operations that require a short Sch-M lock at the end"). The engine runs each statement with
  ``SET LOCK_TIMEOUT`` so it never waits in the lock queue behind a long transaction (where it would
  block every later reader and writer); on timeout (error 1222) or deadlock (1205) it retries with back-off.
* ``ADD`` a NULL column without a default: no existing row is updated (the column "contains a null value
  for each row"). ``ADD`` a NOT NULL column with a *runtime-constant* default is online only "in SQL Server
  2012 (11.x) Enterprise edition and later" - on other editions it rewrites every row under Sch-M, so the
  planner refuses it there. LOB / ``max`` types are never added online, so they are refused with a default.
* ``CREATE INDEX ... WITH (ONLINE = ON)`` - reads and writes continue; Enterprise (and Developer),
  Azure SQL Database and Azure SQL Managed Instance only. Refused on other editions instead of falling back
  to an offline build.
* Foreign keys and CHECK constraints are added ``WITH NOCHECK`` (no scan while Sch-M is held; new writes are
  checked at once). The existing rows are checked by a separate read-only query (orphan / violation count).
  The constraint then stays *not trusted* (``is_not_trusted = 1``): it is enforced for every write but the
  optimizer does not use it. ``WITH CHECK CHECK CONSTRAINT`` (which would make it trusted) scans the table
  inside the ALTER TABLE statement and is therefore not run.
* ``ALTER COLUMN ... NOT NULL WITH (ONLINE = ON)`` (SQL Server 2016+, Azure SQL) for set_not_null, after a
  zero-NULL check. "Online schema change" is listed for Enterprise only, so it is refused on other editions.
* Type changes and renames use a second column kept in sync by an AFTER trigger (expand / contract), like
  PostgreSQL and MySQL. Columns with a DEFAULT constraint are refused for change_type, rename_column and
  drop_column (SQL Server refuses to drop such a column until its default constraint is dropped).
* ``DROP COLUMN`` does not reclaim space (documented); ``DROP INDEX`` of a nonclustered index is a
  catalog change under Sch-M.

Oracle (SQL Language Reference, "Automatic and Manual Locking Mechanisms During SQL Operations" lists the
*nonblocking* DDL by release; Database Licensing Information lists the edition of each online feature):

* Nonblocking: ``ALTER TABLE ... ADD`` column (with or without default), ``CREATE INDEX ... ONLINE``,
  ``DROP INDEX ... ONLINE`` (12.1), ``ADD CONSTRAINT ... ENABLE NOVALIDATE``, ``MODIFY CONSTRAINT ...
  VALIDATE``, ``SET UNUSED ... ONLINE`` (12.1). Several of them are documented to *downgrade to blocking
  while supplemental logging is on* (which CDC tools such as GoldenGate, Debezium/LogMiner and DMS enable):
  the plan records that as a warning.
* "Online index rebuild" and "online table redefinition" are Enterprise Edition (and Oracle Database Free)
  features, not Standard Edition 2: on SE2 the planner refuses the online index build.
* Every DDL statement runs with ``DDL_LOCK_TIMEOUT`` so it waits a bounded time for its DML lock instead of
  failing at once (ORA-00054 when it expires, retried with back-off).
* NOT NULL: ``MODIFY (col CONSTRAINT nn NOT NULL ENABLE NOVALIDATE)`` (no scan) then ``MODIFY CONSTRAINT nn
  VALIDATE`` (nonblocking). Type changes and renames use a synced column and a BEFORE ROW trigger;
  ``SET UNUSED ... ONLINE`` replaces ``DROP COLUMN`` (space is reclaimed later by ``DROP UNUSED COLUMNS``,
  which is blocking and not run by the engine).
* Identifiers: Oracle folds unquoted names to upper case. The engine upper-cases every identifier of a
  change on Oracle and always quotes it, so ``orders`` addresses the table created as ``ORDERS``.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sqlglot import exp

if TYPE_CHECKING:  # pragma: no cover
    from oplia_ctl.migration.online_ddl import ColumnInfo, Plan, SchemaChange, Stmt, TableInfo

SCH_M = "Sch-M (statement, LOCK_TIMEOUT bounded)"
SCH_M_ONLINE = "online (short Sch-M at the end)"
ORA_NONBLOCKING = "nonblocking DDL"
ORA_DDL = "exclusive DDL lock (brief, no scan; DDL_LOCK_TIMEOUT bounded)"
# SERVERPROPERTY('EngineEdition'): 3 = Enterprise/Developer/Evaluation, 5 = Azure SQL Database,
# 8 = Azure SQL Managed Instance - the ones with online index operations and online schema change.
MSSQL_ONLINE_EDITIONS = {3, 5, 8}
MSSQL_NO_ONLINE_ADD = ("varchar(max)", "nvarchar(max)", "varbinary(max)", "xml", "text", "ntext", "image",
                       "hierarchyid", "geometry", "geography")
MSSQL_RETRYABLE = {1222, 1205}                     # lock request time out, deadlock victim
ORA_RETRYABLE = {54, 60, 4021}                      # resource busy / DDL_LOCK_TIMEOUT, deadlock, lock wait timeout


@dataclass
class Caps:
    """What the connected server can do online (read at PLAN time)."""
    online: bool                 # online index build / online schema change available
    detail: str


def mssql_caps(conn: Any) -> Caps:
    with conn.cursor() as cur:
        cur.execute("SELECT CAST(SERVERPROPERTY('EngineEdition') AS int), CAST(SERVERPROPERTY('Edition') AS "
                    "nvarchar(128)), CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128))")
        ee, edition, version = cur.fetchone()
    return Caps(online=int(ee) in MSSQL_ONLINE_EDITIONS, detail=f"{edition} {version} (EngineEdition {ee})")


def oracle_caps(conn: Any) -> Caps:
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT banner FROM v$version")
            banner = " ".join(str(r[0]) for r in cur.fetchall())
    except Exception as e:  # v$version is normally readable by every user; report, do not guess
        return Caps(online=True, detail=f"edition not readable ({type(e).__name__}); an edition without online "
                                        "operations will refuse the statement with ORA-00439")
    se2 = "Standard Edition" in banner
    return Caps(online=not se2, detail=banner[:200])


def retryable_code(engine: str, e: Exception) -> bool:
    if engine == "sqlserver":
        args: tuple[Any, ...] = tuple(getattr(e, "args", ()))
        return bool(args) and isinstance(args[0], int) and args[0] in MSSQL_RETRYABLE
    err = e.args[0] if getattr(e, "args", None) else None
    code = getattr(err, "code", None)
    return isinstance(code, int) and code in ORA_RETRYABLE


def placeholders(engine: str, n: int, start: int = 1) -> list[str]:
    return [f":{i}" for i in range(start, start + n)] if engine == "oracle" else ["%s"] * n


def keyset_after(engine: str, pk: list[str], q: Callable[[str], str], start: int = 1) -> tuple[str, int]:
    """``(a, b) > (?, ?)`` without row constructors (neither engine supports them): returns (sql, #params).

    Parameters are positional and appear in order: for pk [a, b] -> a > ? OR (a = ? AND b > ?)."""
    parts, n = [], 0
    for i in range(len(pk)):
        conds = []
        for j in range(i):
            conds.append(f"{q(pk[j])} = {placeholders(engine, 1, start + n)[0]}")
            n += 1
        conds.append(f"{q(pk[i])} > {placeholders(engine, 1, start + n)[0]}")
        n += 1
        parts.append("(" + " AND ".join(conds) + ")")
    return "(" + " OR ".join(parts) + ")", n


def keyset_params(last: Sequence[Any]) -> list[Any]:
    out: list[Any] = []
    for i in range(len(last)):
        out.extend(last[:i])
        out.append(last[i])
    return out


def keyset_upto(engine: str, pk: list[str], q: Callable[[str], str], start: int) -> tuple[str, int]:
    """``(a, b) <= (?, ?)``: NOT ((a, b) > (?, ?))."""
    sql, n = keyset_after(engine, pk, q, start)
    return f"NOT {sql}", n


# --------------------------------------------------------------------------- catalog
def mssql_table_info(conn: Any, table: str, schema: str | None) -> TableInfo | None:
    from oplia_ctl.migration.online_ddl import ColumnInfo, TableInfo

    sch = schema or "dbo"
    with conn.cursor() as cur:
        cur.execute("SELECT OBJECT_ID(QUOTENAME(%s) + '.' + QUOTENAME(%s), 'U')", (sch, table))
        oid = cur.fetchone()[0]
        if oid is None:
            return None
        cur.execute(
            "SELECT c.name, t.name, c.max_length, c.precision, c.scale, c.is_nullable, c.collation_name, "
            "dc.definition, c.column_id FROM sys.columns c JOIN sys.types t ON t.user_type_id = c.user_type_id "
            "LEFT JOIN sys.default_constraints dc ON dc.object_id = c.default_object_id "
            "WHERE c.object_id = %s ORDER BY c.column_id", (oid,))
        rows = cur.fetchall()
        cur.execute(
            "SELECT c.name, i.name FROM sys.index_columns ic JOIN sys.indexes i ON i.object_id = ic.object_id "
            "AND i.index_id = ic.index_id JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = "
            "ic.column_id WHERE ic.object_id = %s AND i.is_primary_key = 0", (oid,))
        idx_cols = cur.fetchall()
        cur.execute(
            "SELECT c.name FROM sys.foreign_key_columns f JOIN sys.columns c ON c.object_id = f.parent_object_id "
            "AND c.column_id = f.parent_column_id WHERE f.parent_object_id = %s UNION SELECT c.name FROM "
            "sys.foreign_key_columns f JOIN sys.columns c ON c.object_id = f.referenced_object_id AND "
            "c.column_id = f.referenced_column_id WHERE f.referenced_object_id = %s", (oid, oid))
        fk_cols = {str(r[0]) for r in cur.fetchall()}
        cur.execute(
            "SELECT c.name FROM sys.indexes i JOIN sys.index_columns ic ON ic.object_id = i.object_id AND "
            "ic.index_id = i.index_id JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = "
            "ic.column_id WHERE i.object_id = %s AND i.is_primary_key = 1 ORDER BY ic.key_ordinal", (oid,))
        pk = [str(r[0]) for r in cur.fetchall()]
        cur.execute("SELECT name FROM sys.indexes WHERE object_id = %s AND name IS NOT NULL", (oid,))
        indexes = sorted(str(r[0]) for r in cur.fetchall())
    deps: dict[str, list[str]] = {}
    for col, ix in idx_cols:
        deps.setdefault(str(col), []).append(f"index {ix}")
    for col in fk_cols:
        deps.setdefault(col, []).append("a foreign key")
    cols = {}
    for name, typ, max_len, prec, scale, nullable, coll, default, _ in rows:
        cols[str(name)] = ColumnInfo(str(name), mssql_type(str(typ), int(max_len), int(prec), int(scale), coll),
                                     bool(nullable), None if default is None else str(default),
                                     deps.get(str(name), []))
    return TableInfo(cols, pk, indexes)


def mssql_type(typ: str, max_len: int, prec: int, scale: int, collation: str | None) -> str:
    t = typ.lower()
    if t in ("varchar", "char", "varbinary", "binary"):
        s = f"{t}({'max' if max_len == -1 else max_len})"
    elif t in ("nvarchar", "nchar"):
        s = f"{t}({'max' if max_len == -1 else max_len // 2})"
    elif t in ("decimal", "numeric"):
        s = f"{t}({prec},{scale})"
    elif t in ("datetime2", "time", "datetimeoffset"):
        s = f"{t}({scale})"
    else:
        s = t
    if collation and t in ("varchar", "char", "nvarchar", "nchar", "text", "ntext"):
        s += f" COLLATE {collation}"
    return s


def oracle_table_info(conn: Any, table: str, schema: str | None) -> TableInfo | None:
    from oplia_ctl.migration.online_ddl import ColumnInfo, TableInfo

    with conn.cursor() as cur:
        cur.execute("SELECT NVL(:1, SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA')) FROM dual", [schema])
        owner = str(cur.fetchone()[0])
        cur.execute(
            "SELECT column_name, data_type, data_length, data_precision, data_scale, char_length, char_used, "
            "nullable, data_default FROM all_tab_columns WHERE owner = :1 AND table_name = :2 ORDER BY column_id",
            [owner, table])
        rows = cur.fetchall()
        if not rows:
            return None
        cur.execute(
            "SELECT ic.column_name, ic.index_name FROM all_ind_columns ic JOIN all_indexes i ON i.owner = "
            "ic.index_owner AND i.index_name = ic.index_name WHERE ic.table_owner = :1 AND ic.table_name = :2 "
            "AND NOT EXISTS (SELECT 1 FROM all_constraints c WHERE c.owner = i.table_owner AND c.table_name = "
            "i.table_name AND c.constraint_type = 'P' AND c.index_name = i.index_name)", [owner, table])
        idx_cols = cur.fetchall()
        cur.execute(
            "SELECT cc.column_name FROM all_cons_columns cc JOIN all_constraints c ON c.owner = cc.owner AND "
            "c.constraint_name = cc.constraint_name WHERE c.owner = :1 AND c.table_name = :2 AND "
            "c.constraint_type = 'R' UNION SELECT cc.column_name FROM all_constraints r JOIN all_constraints c "
            "ON c.owner = r.r_owner AND c.constraint_name = r.r_constraint_name JOIN all_cons_columns cc ON "
            "cc.owner = c.owner AND cc.constraint_name = c.constraint_name WHERE c.owner = :3 AND "
            "c.table_name = :4 AND r.constraint_type = 'R'", [owner, table, owner, table])
        fk_cols = {str(r[0]) for r in cur.fetchall()}
        cur.execute(
            "SELECT cc.column_name FROM all_constraints c JOIN all_cons_columns cc ON cc.owner = c.owner AND "
            "cc.constraint_name = c.constraint_name WHERE c.owner = :1 AND c.table_name = :2 AND "
            "c.constraint_type = 'P' ORDER BY cc.position", [owner, table])
        pk = [str(r[0]) for r in cur.fetchall()]
        cur.execute("SELECT index_name FROM all_indexes WHERE table_owner = :1 AND table_name = :2", [owner, table])
        indexes = sorted(str(r[0]) for r in cur.fetchall())
    deps: dict[str, list[str]] = {}
    for col, ix in idx_cols:
        deps.setdefault(str(col), []).append(f"index {ix}")
    for col in fk_cols:
        deps.setdefault(col, []).append("a foreign key")
    cols = {}
    for name, typ, dlen, prec, scale, clen, cused, nullable, default in rows:
        d = None if default is None else str(default).strip() or None
        cols[str(name)] = ColumnInfo(str(name), oracle_type(str(typ), dlen, prec, scale, clen, cused),
                                     nullable == "Y", d, deps.get(str(name), []))
    return TableInfo(cols, pk, indexes)


def oracle_type(typ: str, dlen: Any, prec: Any, scale: Any, clen: Any, cused: Any) -> str:
    t = typ.upper()
    if t == "NUMBER":
        if prec is None:
            return "NUMBER" if scale is None else f"NUMBER(*,{int(scale)})"
        return f"NUMBER({int(prec)},{int(scale or 0)})"
    if t in ("VARCHAR2", "CHAR", "NVARCHAR2", "NCHAR"):
        unit = " CHAR" if cused == "C" and t in ("VARCHAR2", "CHAR") else ""
        return f"{t}({int(clen)}{unit})"
    if t == "RAW":
        return f"RAW({int(dlen)})"
    return t


# --------------------------------------------------------------------------- planner
def build_plan_x(change: SchemaChange, engine: str, info: TableInfo, ref_tables: dict[str, TableInfo],
                 caps: Caps | None) -> Plan:
    from oplia_ctl.migration import online_ddl as o

    ms = engine == "sqlserver"
    online = caps.online if caps is not None else False
    cap_detail = caps.detail if caps is not None else "unknown edition"

    def q(n: str) -> str:
        return o._q(engine, n)

    schema = change.schema_name or ("dbo" if ms else None)
    table = (q(schema) + "." + q(change.table)) if schema else q(change.table)
    p = o.Plan(engine=engine, qualified=table)
    cols = dict(info.columns)
    if not ms:
        p.warnings.append("Oracle documents ADD COLUMN, ENABLE NOVALIDATE, MODIFY CONSTRAINT VALIDATE and SET UNUSED "
                          "ONLINE as downgrading to blocking DDL while supplemental logging is enabled (CDC)")

    def need_online(what: str) -> None:
        if not online:
            raise ValueError(f"{what} cannot run online on this server ({cap_detail}): "
                             + ("SQL Server online index and schema operations need Enterprise/Developer edition, "
                                "Azure SQL Database or Azure SQL Managed Instance" if ms else
                                "Oracle online operations need Enterprise Edition (or Oracle Database Free), not "
                                "Standard Edition 2"))

    def need_col(c: str) -> ColumnInfo:
        if c not in cols:
            raise ValueError(f"column {c!r} does not exist on {change.table}")
        return cols[c]

    def need_pk(what: str) -> list[str]:
        if not info.pk:
            raise ValueError(f"{what} needs a primary key on {change.table} for batched backfill")
        return list(info.pk)

    def depend(columns: list[str], what: str) -> None:
        for c in columns:
            if c in cols:
                ci = cols[c]
                cols[c] = o.ColumnInfo(ci.name, ci.type, ci.nullable, ci.default, [*ci.dependents, what])

    def obj(name: str) -> str:
        return (q(schema) + "." + q(name)) if schema else q(name)

    def drop_col(col: str) -> Stmt:
        if ms:
            return o.Stmt(f"ALTER TABLE {table} DROP COLUMN {q(col)}", SCH_M,
                          "catalog change; SQL Server does not reclaim the space until the clustered index is rebuilt")
        return o.Stmt(f"ALTER TABLE {table} SET UNUSED ({q(col)}) ONLINE", ORA_NONBLOCKING,
                      "space is reclaimed later by ALTER TABLE ... DROP UNUSED COLUMNS (blocking, not run here)")

    for op in change.operations:
        if isinstance(op, o.AddColumn):
            if op.column in cols:
                raise ValueError(f"column {op.column!r} already exists")
            t = o.normalise_type(op.type, engine)
            if not op.nullable and op.default is None:
                raise ValueError(f"{op.column}: a NOT NULL column needs a constant default to be added online")
            lit = o._literal(op.default, engine) if op.default is not None else None
            if ms:
                if lit is not None:
                    need_online(f"add_column {op.column} with a default")
                    if any(t.lower().startswith(x) for x in MSSQL_NO_ONLINE_ADD):
                        raise ValueError(f"{op.column}: SQL Server cannot add a {t} column with a default online")
                    dfn = o.ident(f"df_oplia_{o._short(change.table, op.column)}")
                    nn = " NOT NULL" if not op.nullable else " NULL"
                    p.expand.append(o.Stmt(f"ALTER TABLE {table} ADD {q(op.column)} {t}{nn} CONSTRAINT {q(dfn)} "
                                           f"DEFAULT {lit}", SCH_M,
                                           "runtime-constant default: online, existing rows are not updated "
                                           "(Enterprise / Azure SQL)"))
                else:
                    p.expand.append(o.Stmt(f"ALTER TABLE {table} ADD {q(op.column)} {t} NULL", SCH_M,
                                           "NULL column without default: existing rows are not updated"))
            else:
                d = f" DEFAULT {lit}" if lit is not None else ""
                nn = " NOT NULL" if not op.nullable else ""
                p.expand.append(o.Stmt(f"ALTER TABLE {table} ADD ({q(op.column)} {t}{d}{nn})", ORA_NONBLOCKING,
                                       "nonblocking ADD COLUMN (11.2 / 12.1 / 23.3 lists)"))
            cols[op.column] = o.ColumnInfo(op.column, t, op.nullable, lit, [])
        elif isinstance(op, o.AddIndex):
            for col in op.columns:
                need_col(col)
            if op.name in info.indexes:
                raise ValueError(f"index {op.name!r} already exists")
            need_online(f"add_index {op.name}")
            depend(op.columns, f"index {op.name}")
            u = "UNIQUE " if op.unique else ""
            cl = ", ".join(q(col) for col in op.columns)
            if ms:
                p.expand.append(o.Stmt(f"CREATE {u}INDEX {q(op.name)} ON {table} ({cl}) WITH (ONLINE = ON)",
                                       SCH_M_ONLINE, "online index build: reads and writes continue"))
                p.checks.append(o.Check(
                    f"SELECT 1 - count(*) FROM sys.indexes WHERE object_id = OBJECT_ID('{table}') "  # nosec B608
                    f"AND name = '{o.ident(op.name)}' AND is_disabled = 0", f"index {op.name} exists and is enabled"))
            else:
                p.expand.append(o.Stmt(f"CREATE {u}INDEX {obj(op.name)} ON {table} ({cl}) ONLINE", ORA_NONBLOCKING,
                                       "CREATE INDEX ONLINE (nonblocking since 11.2)"))
                p.checks.append(o.Check(
                    "SELECT CASE WHEN count(*) = 1 THEN 0 ELSE 1 END FROM all_indexes WHERE index_name = "  # nosec B608
                    f"'{o.ident(op.name)}' AND table_name = '{o.ident(change.table)}' AND status = 'VALID'"
                    + (f" AND owner = '{o.ident(schema)}'" if schema else " AND owner = SYS_CONTEXT('USERENV', "
                                                                         "'CURRENT_SCHEMA')"),
                    f"index {op.name} is VALID"))
        elif isinstance(op, o.DropIndex):
            if op.name not in info.indexes:
                raise ValueError(f"index {op.name!r} does not exist")
            if ms:
                p.contract.append(o.Stmt(f"DROP INDEX {q(op.name)} ON {table}", SCH_M,
                                         "nonclustered index: catalog change"))
            else:
                p.contract.append(o.Stmt(f"DROP INDEX {obj(op.name)} ONLINE", ORA_NONBLOCKING,
                                         "DROP INDEX ONLINE (nonblocking since 12.1)"))
        elif isinstance(op, o.AddForeignKey):
            for col in op.columns:
                need_col(col)
            ref = ref_tables.get(op.ref_table)
            if ref is None:
                raise ValueError(f"referenced table {op.ref_table!r} does not exist")
            for col in op.ref_columns:
                if col not in ref.columns:
                    raise ValueError(f"referenced column {op.ref_table}.{col} does not exist")
            depend(op.columns, f"foreign key {op.name}")
            rt = obj(op.ref_table)
            cl, rl = ", ".join(q(x) for x in op.columns), ", ".join(q(x) for x in op.ref_columns)
            orphans = (f"SELECT count(*) FROM {table} c LEFT JOIN {rt} r ON "  # nosec B608
                       + " AND ".join(f"c.{q(a)} = r.{q(b)}" for a, b in zip(op.columns, op.ref_columns, strict=True))
                       + " WHERE " + " AND ".join(f"c.{q(a)} IS NOT NULL" for a in op.columns)
                       + f" AND r.{q(op.ref_columns[0])} IS NULL")
            if ms:
                od = {"RESTRICT": "NO ACTION"}.get(op.on_delete, op.on_delete)
                p.expand.append(o.Stmt(f"ALTER TABLE {table} WITH NOCHECK ADD CONSTRAINT {q(op.name)} FOREIGN KEY "
                                       f"({cl}) REFERENCES {rt} ({rl}) ON DELETE {od}", SCH_M,
                                       "WITH NOCHECK: no scan; new writes are checked at once"))
                p.checks.append(o.Check(orphans, f"no orphan rows for {op.name}"))
                p.warnings.append(f"{op.name} stays not trusted (enforced for writes, not used by the optimizer): "
                                  "WITH CHECK CHECK CONSTRAINT scans under Sch-M and is not run")
            else:
                od = f" ON DELETE {op.on_delete}" if op.on_delete in ("CASCADE", "SET NULL") else ""
                p.expand.append(o.Stmt(f"ALTER TABLE {table} ADD CONSTRAINT {q(op.name)} FOREIGN KEY ({cl}) "
                                       f"REFERENCES {rt} ({rl}){od} ENABLE NOVALIDATE", ORA_NONBLOCKING,
                                       "ENABLE NOVALIDATE: new rows are checked at once; existing rows later"))
                p.checks.append(o.Check(orphans, f"no orphan rows for {op.name}"))
                p.validate.append(o.Stmt(f"ALTER TABLE {table} MODIFY CONSTRAINT {q(op.name)} VALIDATE",
                                         ORA_NONBLOCKING, "MODIFY CONSTRAINT VALIDATE (nonblocking since 11.2)"))
        elif isinstance(op, o.AddCheck):
            node = o.parse_expression(op.expression, engine, set(cols))
            e = o._expr_sql(node, engine)
            depend(sorted({(c.name.upper() if not ms else c.name) for c in node.find_all(exp.Column)}),
                   f"check {op.name}")
            p.checks.append(o.Check(f"SELECT count(*) FROM {table} WHERE NOT ({e})", f"rows satisfy {op.name}"))  # nosec B608
            if ms:
                p.validate.append(o.Stmt(f"ALTER TABLE {table} WITH NOCHECK ADD CONSTRAINT {q(op.name)} CHECK ({e})",
                                         SCH_M, "added after the violation check passed; WITH NOCHECK: no scan"))
                p.warnings.append(f"{op.name} stays not trusted (enforced for writes, not used by the optimizer)")
            else:
                p.expand.append(o.Stmt(f"ALTER TABLE {table} ADD CONSTRAINT {q(op.name)} CHECK ({e}) ENABLE NOVALIDATE",
                                       ORA_NONBLOCKING))
                p.validate.append(o.Stmt(f"ALTER TABLE {table} MODIFY CONSTRAINT {q(op.name)} VALIDATE",
                                         ORA_NONBLOCKING))
        elif isinstance(op, o.SetNotNull):
            c = need_col(op.column)
            if not c.nullable:
                raise ValueError(f"{op.column} is already NOT NULL")
            p.checks.append(o.Check(f"SELECT count(*) FROM {table} WHERE {q(op.column)} IS NULL",  # nosec B608
                                    f"no NULLs in {op.column}"))
            if ms:
                need_online(f"set_not_null {op.column}")
                if c.dependents:
                    raise ValueError(f"{op.column} is used by {', '.join(c.dependents)}: SQL Server refuses ALTER "
                                     "COLUMN on a column an index or constraint depends on; set it NOT NULL first")
                p.validate.append(o.Stmt(f"ALTER TABLE {table} ALTER COLUMN {q(op.column)} {c.type} NOT NULL "
                                         "WITH (ONLINE = ON)", SCH_M_ONLINE,
                                         "online ALTER COLUMN (SQL Server 2016+, Azure SQL)"))
            else:
                cn = o.ident(f"OPLIA_NN_{o._short(change.table, op.column)}".upper())
                p.expand.append(o.Stmt(f"ALTER TABLE {table} MODIFY ({q(op.column)} CONSTRAINT {q(cn)} NOT NULL "
                                       "ENABLE NOVALIDATE)", ORA_DDL))
                p.validate.append(o.Stmt(f"ALTER TABLE {table} MODIFY CONSTRAINT {q(cn)} VALIDATE", ORA_NONBLOCKING))
        elif isinstance(op, o.ChangeType | o.RenameColumn):
            c = need_col(op.column)
            pk = need_pk(op.op)
            if op.column in pk:
                raise ValueError(f"{op.column} is part of the primary key; changing it online is not supported")
            if c.dependents:
                raise ValueError(f"{op.column} is used by {', '.join(c.dependents)}; drop or recreate them first "
                                 "(they would not follow the new column)")
            if ms and c.default is not None:
                raise ValueError(f"{op.column} has a DEFAULT constraint; drop it first (SQL Server will not drop "
                                 "the old column at contract while it exists)")
            if isinstance(op, o.ChangeType):
                new = op.column + (o.NEW_SUFFIX if ms else o.NEW_SUFFIX.upper())
                t = o.normalise_type(op.type, engine)
                node = o.parse_expression(op.using or f"CAST({op.column} AS {t})", engine, {op.column})
            else:
                new, t = op.new_name, c.type
                if new in cols:
                    raise ValueError(f"column {new!r} already exists")
                node = o.parse_expression(op.column, engine, {op.column})
            o.ident(new)
            if ms:
                p.expand.append(o.Stmt(f"ALTER TABLE {table} ADD {q(new)} {t} NULL", SCH_M,
                                       "new column, filled by trigger and backfill"))
            else:
                p.expand.append(o.Stmt(f"ALTER TABLE {table} ADD ({q(new)} {t})", ORA_NONBLOCKING,
                                       "new column, filled by trigger and backfill"))
            trig = o.ident(f"oplia_sync_{o._short(change.table, op.column, new)}" if ms
                           else f"OPLIA_SYNC_{o._short(change.table, op.column, new)}".upper())
            two_way = isinstance(op, o.RenameColumn)
            p.expand.extend(sync_trigger(engine, table, obj(trig), q, op.column, new, node, two_way, pk))
            p.backfill.append(o.Backfill(column=new, expression=o._expr_sql(node, engine), pk=pk))
            p.checks.append(o.Check(
                f"SELECT count(*) FROM {table} WHERE NOT ({null_eq(q(new), '(' + o._expr_sql(node, engine) + ')')})",  # nosec B608
                f"{new} matches {op.column} on every row"))
            p.contract_checks.append(p.checks[-1])
            p.contract.append(o.Stmt(f"DROP TRIGGER {obj(trig)}", SCH_M if ms else ORA_DDL))
            if isinstance(op, o.ChangeType):
                p.contract.extend(rename(engine, table, schema, change.table, q, op.column,
                                         op.column + (o.OLD_SUFFIX if ms else o.OLD_SUFFIX.upper())))
                p.contract.extend(rename(engine, table, schema, change.table, q, new, op.column))
                p.contract.append(drop_col(op.column + (o.OLD_SUFFIX if ms else o.OLD_SUFFIX.upper())))
            else:
                p.contract.append(drop_col(op.column))
            if c.default is not None:
                p.warnings.append(f"{op.column} has a default ({c.default}); it is not copied to {new}")
            cols[new] = o.ColumnInfo(new, t, True, None, [])
        elif isinstance(op, o.DropColumn):
            c = need_col(op.column)
            if op.column in info.pk:
                raise ValueError(f"{op.column} is part of the primary key")
            if ms and c.default is not None:
                raise ValueError(f"{op.column} has a DEFAULT constraint; drop it first")
            p.contract.append(drop_col(op.column))
    return p


def null_eq(a: str, b: str) -> str:
    """NULL-safe equality without IS NOT DISTINCT FROM (not in SQL Server before 2022 or in Oracle before 23ai)."""
    return f"({a} = {b} OR ({a} IS NULL AND {b} IS NULL))"


def rename(engine: str, table: str, schema: str | None, tname: str, q: Callable[[str], str], old: str,
           new: str) -> list[Stmt]:
    from oplia_ctl.migration import online_ddl as o

    if engine == "sqlserver":
        path = f"{o.ident(schema or 'dbo')}.{o.ident(tname)}.{o.ident(old)}"
        return [o.Stmt(f"EXEC sp_rename N'{path}', N'{o.ident(new)}', N'COLUMN'", SCH_M)]
    return [o.Stmt(f"ALTER TABLE {table} RENAME COLUMN {q(old)} TO {q(new)}", ORA_DDL)]


def sync_trigger(engine: str, table: str, trig: str, q: Callable[[str], str], old: str, new: str, node: Any,
                 two_way: bool, pk: list[str]) -> list[Stmt]:
    from oplia_ctl.migration import online_ddl as o

    if engine == "sqlserver":
        on = " AND ".join(f"x.{q(k)} = i.{q(k)}" for k in pk)
        ond = " AND ".join(f"d.{q(k)} = i.{q(k)}" for k in pk)
        if two_way:
            changed = f"NOT {null_eq(f'i.{q(new)}', f'd.{q(new)}')}"
            body = (f"UPDATE x SET x.{q(old)} = CASE WHEN d.{q(pk[0])} IS NULL THEN COALESCE(i.{q(old)}, i.{q(new)}) "
                    f"WHEN {changed} THEN i.{q(new)} ELSE i.{q(old)} END, "
                    f"x.{q(new)} = CASE WHEN d.{q(pk[0])} IS NULL THEN COALESCE(i.{q(new)}, i.{q(old)}) "
                    f"WHEN {changed} THEN i.{q(new)} ELSE i.{q(old)} END "
                    f"FROM {table} x JOIN inserted i ON {on} LEFT JOIN deleted d ON {ond}")  # nosec B608
        else:
            fill = o._expr_sql(node, engine, "x")
            body = f"UPDATE x SET x.{q(new)} = {fill} FROM {table} x JOIN inserted i ON {on}"  # nosec B608
        return [o.Stmt(f"CREATE OR ALTER TRIGGER {trig} ON {table} AFTER INSERT, UPDATE AS BEGIN SET NOCOUNT ON; "  # nosec B608 - identifiers validated by ident()
                       f"IF TRIGGER_NESTLEVEL(@@PROCID) > 1 RETURN; {body}; END", SCH_M,
                       "AFTER trigger keeps the new column in sync for every write from now on")]
    if two_way:
        body = (f"IF INSERTING THEN IF :NEW.{q(new)} IS NULL THEN :NEW.{q(new)} := :NEW.{q(old)}; "
                f"ELSIF :NEW.{q(old)} IS NULL THEN :NEW.{q(old)} := :NEW.{q(new)}; END IF; "
                f"ELSIF NOT {null_eq(f':NEW.{q(new)}', f':OLD.{q(new)}')} THEN :NEW.{q(old)} := :NEW.{q(new)}; "
                f"ELSE :NEW.{q(new)} := :NEW.{q(old)}; END IF;")
    else:
        fill = o._expr_sql(node, engine, "OPLIA_NEW_ROW").replace('"OPLIA_NEW_ROW".', ":NEW.").replace(
            "OPLIA_NEW_ROW.", ":NEW.")
        body = f":NEW.{q(new)} := {fill};"
    return [o.Stmt(f"CREATE OR REPLACE TRIGGER {trig} BEFORE INSERT OR UPDATE ON {table} FOR EACH ROW BEGIN "
                   f"{body} END;", ORA_DDL, "BEFORE ROW trigger keeps the new column in sync")]
