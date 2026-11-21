"""FR-02 non-blocking online DDL for PostgreSQL and MySQL (expand / backfill / validate / contract).

A schema change is a declarative list of operations, never raw SQL. Every statement the engine runs
is generated here from validated identifiers and SQLGlot-normalised types and expressions, and is
tagged with the table lock it takes:

PostgreSQL (lock modes from the PostgreSQL "Explicit Locking" and ALTER TABLE documentation; the
tests check each declared mode against ``pg_locks``):

* ``CREATE/DROP INDEX CONCURRENTLY``, ``VALIDATE CONSTRAINT`` - SHARE UPDATE EXCLUSIVE (reads and
  writes continue).
* ``ADD FOREIGN KEY ... NOT VALID``, ``CREATE TRIGGER`` - SHARE ROW EXCLUSIVE (reads continue,
  writes wait only for the catalog change).
* ``ADD COLUMN`` (constant default), ``ADD CHECK ... NOT VALID``, ``SET NOT NULL`` after a validated
  ``IS NOT NULL`` check, ``RENAME``, ``DROP COLUMN`` - **ACCESS EXCLUSIVE, catalog only**: no table
  rewrite and no scan, held for milliseconds. PostgreSQL has no way to make these changes without
  that lock, so the PRD's "zero ACCESS EXCLUSIVE locks" cannot be met for them. What the engine
  guarantees instead: each such statement runs with ``lock_timeout`` (default 2 s) so it never queues
  behind a long transaction and blocks other sessions; on timeout it is retried with back-off. With
  ``forbid_access_exclusive`` the planner refuses every operation that needs it.
* Statements that rewrite or scan a table under ACCESS EXCLUSIVE (``ALTER COLUMN TYPE``, ``ADD
  COLUMN`` with a volatile default, ``SET NOT NULL`` without a validated check) are never generated:
  type changes and renames use a second column kept in sync by a trigger (expand / contract).

MySQL 8 (InnoDB online DDL documentation): every ``ALTER TABLE`` carries ``ALGORITHM=INSTANT`` or
``ALGORITHM=INPLACE, LOCK=NONE``. MySQL then refuses the statement with an error instead of
falling back to a blocking table copy. Online DDL still takes an exclusive metadata lock briefly
at the start and end; ``lock_wait_timeout`` bounds the wait for it. A foreign key is added INPLACE
with ``foreign_key_checks=0`` (the only online way) and then validated by an orphan-row query.

Phases: ``EXPAND`` (additive, safe for the running application) -> ``BACKFILL`` (keyset batches,
throttled, resumable) -> ``VALIDATE`` (constraint validation and zero-mismatch checks) -> done.
``CONTRACT`` (drop old columns, swap names, drop indexes) is a separate gated proposal that refers to
a finished expand job, because it is the step the application must be ready for.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from typing import Annotated, Any, Literal

import sqlglot
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlglot import exp

from oplia_ctl.databases.registry import DatabaseRegistry, DatabaseSpec
from oplia_ctl.replication.jobs import JobMachine
from oplia_ctl.replication.models import DrJobRow

ACTION_SCHEMA_CHANGE = "migration.schema_change"
ACTION_SCHEMA_CONTRACT = "migration.schema_contract"
SUPPORTED_ENGINES = ("postgres", "mysql")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
NEW_SUFFIX = "__oplia_new"
OLD_SUFFIX = "__oplia_old"
PG_RETRYABLE = {"55P03", "57014", "40P01"}          # lock_not_available, query_canceled, deadlock
MYSQL_RETRYABLE = {1205, 1213}                       # lock wait timeout, deadlock

Lock = Literal["SHARE UPDATE EXCLUSIVE", "SHARE ROW EXCLUSIVE", "ACCESS EXCLUSIVE (catalog only)",
               "ROW EXCLUSIVE", "MDL (brief, INSTANT)", "MDL (brief, INPLACE LOCK=NONE)", "none"]


def ident(v: str) -> str:
    if not _IDENT.fullmatch(v):
        raise ValueError(f"invalid identifier {v!r} (letters, digits and _, max 63, not starting with a digit)")
    return v


Ident = Annotated[str, Field(pattern=_IDENT.pattern)]


# --------------------------------------------------------------------------- operations
class _Op(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AddColumn(_Op):
    op: Literal["add_column"]
    column: Ident
    type: str = Field(min_length=1, max_length=100)
    nullable: bool = True
    default: str | int | float | bool | None = None


class AddIndex(_Op):
    op: Literal["add_index"]
    name: Ident
    columns: list[Ident] = Field(min_length=1, max_length=16)
    unique: bool = False


class DropIndex(_Op):
    op: Literal["drop_index"]
    name: Ident


class AddForeignKey(_Op):
    op: Literal["add_foreign_key"]
    name: Ident
    columns: list[Ident] = Field(min_length=1, max_length=16)
    ref_table: Ident
    ref_columns: list[Ident] = Field(min_length=1, max_length=16)
    on_delete: Literal["NO ACTION", "RESTRICT", "CASCADE", "SET NULL"] = "NO ACTION"

    @model_validator(mode="after")
    def _same_len(self) -> AddForeignKey:
        if len(self.columns) != len(self.ref_columns):
            raise ValueError("columns and ref_columns must have the same length")
        return self


class AddCheck(_Op):
    op: Literal["add_check"]
    name: Ident
    expression: str = Field(min_length=1, max_length=1000)


class SetNotNull(_Op):
    op: Literal["set_not_null"]
    column: Ident


class ChangeType(_Op):
    op: Literal["change_type"]
    column: Ident
    type: str = Field(min_length=1, max_length=100)
    using: str | None = Field(default=None, max_length=1000)   # expression of the column; default CAST


class RenameColumn(_Op):
    op: Literal["rename_column"]
    column: Ident
    new_name: Ident


class DropColumn(_Op):
    op: Literal["drop_column"]
    column: Ident


Operation = Annotated[AddColumn | AddIndex | DropIndex | AddForeignKey | AddCheck | SetNotNull | ChangeType
                      | RenameColumn | DropColumn, Field(discriminator="op")]


class SchemaChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    database: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    schema_name: Ident | None = None          # PostgreSQL schema (default public); MySQL uses the DSN database
    table: Ident
    operations: list[Operation] = Field(min_length=1, max_length=20)
    lock_timeout_ms: int = Field(default=2000, ge=50, le=10000)
    max_retries: int = Field(default=30, ge=0, le=500)
    batch_size: int = Field(default=1000, ge=10, le=50000)
    batch_pause_ms: int = Field(default=50, ge=0, le=60000)
    forbid_access_exclusive: bool = False


# --------------------------------------------------------------------------- plan
@dataclass
class Stmt:
    sql: str
    lock: str
    note: str = ""
    autocommit: bool = False        # CREATE/DROP INDEX CONCURRENTLY cannot run inside a transaction
    session: list[str] = field(default_factory=list)   # extra session settings (MySQL foreign_key_checks)


@dataclass
class Backfill:
    column: str              # column being filled
    expression: str          # SQL expression over the row (plain column references)
    pk: list[str]


@dataclass
class Check:
    sql: str                 # returns one integer: offending rows; 0 = valid
    what: str


@dataclass
class Plan:
    engine: str
    qualified: str
    expand: list[Stmt] = field(default_factory=list)
    backfill: list[Backfill] = field(default_factory=list)
    validate: list[Stmt] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    contract: list[Stmt] = field(default_factory=list)
    contract_checks: list[Check] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_json(d: dict[str, Any]) -> Plan:
        return Plan(engine=d["engine"], qualified=d["qualified"],
                    expand=[Stmt(**s) for s in d["expand"]], backfill=[Backfill(**b) for b in d["backfill"]],
                    validate=[Stmt(**s) for s in d["validate"]], checks=[Check(**c) for c in d["checks"]],
                    contract=[Stmt(**s) for s in d["contract"]],
                    contract_checks=[Check(**c) for c in d["contract_checks"]], warnings=list(d["warnings"]))


@dataclass
class ColumnInfo:
    name: str
    type: str
    nullable: bool
    default: str | None
    dependents: list[str]       # indexes / constraints / views using the column (PostgreSQL pg_depend)


@dataclass
class TableInfo:
    columns: dict[str, ColumnInfo]
    pk: list[str]
    indexes: list[str]


def _dialect(engine: str) -> str:
    return "postgres" if engine == "postgres" else "mysql"


def normalise_type(type_sql: str, engine: str) -> str:
    """Parse a column type with SQLGlot and return it re-rendered (rejects anything that is not a type)."""
    if ";" in type_sql or "--" in type_sql or "/*" in type_sql:
        raise ValueError(f"invalid type {type_sql!r}")
    try:
        dt = exp.DataType.build(type_sql, dialect=_dialect(engine))
    except Exception as e:
        raise ValueError(f"invalid type {type_sql!r}: {e}") from None
    if dt.this is None or dt.this == exp.DataType.Type.USERDEFINED:
        raise ValueError(f"unknown type {type_sql!r}")
    return str(dt.sql(dialect=_dialect(engine)))


def parse_expression(expr_sql: str, engine: str, allowed_columns: set[str]) -> exp.Condition:
    """A scalar SQL expression over this table's columns only: no subqueries, no statements."""
    if ";" in expr_sql:
        raise ValueError("expression must not contain ';'")
    try:
        node = sqlglot.parse_one(expr_sql, read=_dialect(engine))
    except Exception as e:
        raise ValueError(f"cannot parse expression {expr_sql!r}: {e}") from None
    if not isinstance(node, exp.Condition):          # whitelist: DROP/DELETE/INSERT/SELECT ... are not conditions
        raise ValueError("expression must be a scalar expression, not a statement")
    for bad in (exp.Subquery, exp.Select, exp.Query, exp.DDL, exp.DML, exp.Command):
        if node.find(bad):
            raise ValueError("subqueries are not allowed in expressions")
    for col in node.find_all(exp.Column):
        if col.table or col.name not in allowed_columns:
            raise ValueError(f"expression may only use these columns: {sorted(allowed_columns)}; got {col.sql()!r}")
    return node


def _q(engine: str, name: str) -> str:
    ident(name)
    return f'"{name}"' if engine == "postgres" else f"`{name}`"


def _expr_sql(node: Any, engine: str, row_prefix: str | None = None) -> str:
    """Render with every column identifier quoted (case preserved); ``row_prefix`` gives NEW."col" in triggers."""
    def fix(x: exp.Expression) -> exp.Expression:
        if isinstance(x, exp.Column):
            return exp.Column(this=exp.to_identifier(x.name, quoted=True),
                              table=exp.to_identifier(row_prefix) if row_prefix else None)
        return x
    return str(node.copy().transform(fix).sql(dialect=_dialect(engine)))


def _pct(sql: str) -> str:
    """Escape literal % for statements sent together with DB-API parameters."""
    return sql.replace("%", "%%")


def _literal(v: str | int | float | bool | None, engine: str) -> str:
    return str(exp.convert(v).sql(dialect=_dialect(engine)))


def _short(*parts: str) -> str:
    return hashlib.sha256("/".join(parts).encode()).hexdigest()[:10]


def build_plan(change: SchemaChange, engine: str, info: TableInfo, ref_tables: dict[str, TableInfo]) -> Plan:
    if engine not in SUPPORTED_ENGINES:
        raise ValueError(f"online DDL supports {SUPPORTED_ENGINES}, not {engine}")
    def q(n: str) -> str:
        return _q(engine, n)

    pg = engine == "postgres"
    schema = change.schema_name or "public"
    table = q(schema) + "." + q(change.table) if pg else q(change.table)
    p = Plan(engine=engine, qualified=table)
    cols = dict(info.columns)
    ae: Lock = "ACCESS EXCLUSIVE (catalog only)"

    def need_ae(what: str) -> None:
        if pg and change.forbid_access_exclusive:
            raise ValueError(f"{what} needs a brief ACCESS EXCLUSIVE lock on PostgreSQL and "
                             "forbid_access_exclusive is set")

    def need_col(c: str) -> ColumnInfo:
        if c not in cols:
            raise ValueError(f"column {c!r} does not exist on {change.table}")
        return cols[c]

    def need_pk(what: str) -> list[str]:
        if not info.pk:
            raise ValueError(f"{what} needs a primary key on {change.table} for batched backfill")
        return list(info.pk)

    for op in change.operations:
        if isinstance(op, AddColumn):
            if op.column in cols:
                raise ValueError(f"column {op.column!r} already exists")
            t = normalise_type(op.type, engine)
            if not op.nullable and op.default is None:
                raise ValueError(f"{op.column}: a NOT NULL column needs a constant default to be added online")
            d = f" DEFAULT {_literal(op.default, engine)}" if op.default is not None else ""
            nn = " NOT NULL" if not op.nullable else ""
            if pg:
                need_ae(f"add_column {op.column}")
                p.expand.append(Stmt(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {q(op.column)} {t}{d}{nn}", ae,
                                     "constant default: catalog-only change, no table rewrite (PostgreSQL 11+)"))
            else:
                p.expand.append(Stmt(f"ALTER TABLE {table} ADD COLUMN {q(op.column)} {t}{nn}{d}, ALGORITHM=INSTANT",
                                     "MDL (brief, INSTANT)"))
            cols[op.column] = ColumnInfo(op.column, t, op.nullable, None, [])
            p.contract.append(Stmt("", "none", f"nothing to contract for add_column {op.column}"))
        elif isinstance(op, AddIndex):
            for col in op.columns:
                need_col(col)
            if op.name in info.indexes:
                raise ValueError(f"index {op.name!r} already exists")
            u = "UNIQUE " if op.unique else ""
            cl = ", ".join(q(col) for col in op.columns)
            if pg:
                p.expand.append(Stmt(f"CREATE {u}INDEX CONCURRENTLY IF NOT EXISTS {q(op.name)} ON {table} ({cl})",
                                     "SHARE UPDATE EXCLUSIVE", "builds without blocking reads or writes",
                                     autocommit=True))
                p.checks.append(Check(
                    f"SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "  # nosec B608
                    f"JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = '{ident(schema)}' "
                    f"AND c.relname = '{ident(op.name)}' AND NOT (i.indisvalid AND i.indisready)",
                    f"index {op.name} is valid"))
            else:
                p.expand.append(Stmt(f"ALTER TABLE {table} ADD {u}INDEX {q(op.name)} ({cl}), "
                                     "ALGORITHM=INPLACE, LOCK=NONE", "MDL (brief, INPLACE LOCK=NONE)"))
        elif isinstance(op, DropIndex):
            if op.name not in info.indexes:
                raise ValueError(f"index {op.name!r} does not exist")
            if pg:
                p.contract.append(Stmt(f"DROP INDEX CONCURRENTLY IF EXISTS {q(schema)}.{q(op.name)}",
                                       "SHARE UPDATE EXCLUSIVE", autocommit=True))
            else:
                p.contract.append(Stmt(f"ALTER TABLE {table} DROP INDEX {q(op.name)}, ALGORITHM=INPLACE, LOCK=NONE",
                                       "MDL (brief, INPLACE LOCK=NONE)"))
        elif isinstance(op, AddForeignKey):
            for col in op.columns:
                need_col(col)
            ref = ref_tables.get(op.ref_table)
            if ref is None:
                raise ValueError(f"referenced table {op.ref_table!r} does not exist")
            for col in op.ref_columns:
                if col not in ref.columns:
                    raise ValueError(f"referenced column {op.ref_table}.{col} does not exist")
            rt = (q(schema) + "." + q(op.ref_table)) if pg else q(op.ref_table)
            cl, rl = ", ".join(q(x) for x in op.columns), ", ".join(q(x) for x in op.ref_columns)
            fk = f"CONSTRAINT {q(op.name)} FOREIGN KEY ({cl}) REFERENCES {rt} ({rl}) ON DELETE {op.on_delete}"
            orphans = (f"SELECT count(*) FROM {table} c LEFT JOIN {rt} r ON "  # nosec B608
                       + " AND ".join(f"c.{q(a)} = r.{q(b)}" for a, b in zip(op.columns, op.ref_columns, strict=True))
                       + " WHERE " + " AND ".join(f"c.{q(a)} IS NOT NULL" for a in op.columns)
                       + f" AND r.{q(op.ref_columns[0])} IS NULL")
            if pg:
                p.expand.append(Stmt(f"ALTER TABLE {table} ADD {fk} NOT VALID", "SHARE ROW EXCLUSIVE",
                                     "new rows are checked at once; existing rows are validated later"))
                p.validate.append(Stmt(f"ALTER TABLE {table} VALIDATE CONSTRAINT {q(op.name)}",
                                       "SHARE UPDATE EXCLUSIVE", "scans without blocking writes"))
            else:
                p.expand.append(Stmt(f"ALTER TABLE {table} ADD {fk}, ALGORITHM=INPLACE, LOCK=NONE",
                                     "MDL (brief, INPLACE LOCK=NONE)",
                                     "INPLACE needs foreign_key_checks=0; existing rows are checked by VALIDATE",
                                     session=["SET SESSION foreign_key_checks = 0"]))
                p.checks.append(Check(orphans, f"no orphan rows for {op.name}"))
        elif isinstance(op, AddCheck):
            node = parse_expression(op.expression, engine, set(cols))
            e = _expr_sql(node, engine)
            if pg:
                need_ae(f"add_check {op.name}")
                p.expand.append(Stmt(f"ALTER TABLE {table} ADD CONSTRAINT {q(op.name)} CHECK ({e}) NOT VALID", ae,
                                     "NOT VALID: no scan while the lock is held"))
                p.validate.append(Stmt(f"ALTER TABLE {table} VALIDATE CONSTRAINT {q(op.name)}",
                                       "SHARE UPDATE EXCLUSIVE"))
            else:
                p.checks.append(Check(f"SELECT count(*) FROM {table} WHERE NOT ({e})", f"rows satisfy {op.name}"))  # nosec B608
                p.validate.append(Stmt(f"ALTER TABLE {table} ADD CONSTRAINT {q(op.name)} CHECK ({e}), "
                                       "ALGORITHM=INPLACE, LOCK=NONE", "MDL (brief, INPLACE LOCK=NONE)",
                                       "MySQL refuses this with an error if it cannot be done online"))
        elif isinstance(op, SetNotNull):
            c = need_col(op.column)
            if not c.nullable:
                raise ValueError(f"{op.column} is already NOT NULL")
            if pg:
                need_ae(f"set_not_null {op.column}")
                cn = ident(f"oplia_nn_{_short(change.table, op.column)}")
                p.expand.append(Stmt(f"ALTER TABLE {table} ADD CONSTRAINT {q(cn)} CHECK ({q(op.column)} IS NOT NULL) "
                                     "NOT VALID", ae))
                p.validate.append(Stmt(f"ALTER TABLE {table} VALIDATE CONSTRAINT {q(cn)}", "SHARE UPDATE EXCLUSIVE"))
                p.validate.append(Stmt(f"ALTER TABLE {table} ALTER COLUMN {q(op.column)} SET NOT NULL", ae,
                                       "the validated CHECK lets PostgreSQL 12+ skip the full-table scan"))
                p.validate.append(Stmt(f"ALTER TABLE {table} DROP CONSTRAINT {q(cn)}", ae))
            else:
                if c.default is not None:
                    raise ValueError(f"{op.column} has a default; MySQL MODIFY COLUMN would need the full column "
                                     "definition and could drop it, so set_not_null is refused for this column")
                p.checks.append(Check(f"SELECT count(*) FROM {table} WHERE {q(op.column)} IS NULL",  # nosec B608
                                      f"no NULLs in {op.column}"))
                p.validate.append(Stmt(f"ALTER TABLE {table} MODIFY COLUMN {q(op.column)} {c.type} NOT NULL, "
                                       "ALGORITHM=INPLACE, LOCK=NONE", "MDL (brief, INPLACE LOCK=NONE)"))
        elif isinstance(op, ChangeType | RenameColumn):
            c = need_col(op.column)
            pk = need_pk(op.op)
            if op.column in pk:
                raise ValueError(f"{op.column} is part of the primary key; changing it online is not supported")
            if c.dependents:
                raise ValueError(f"{op.column} is used by {', '.join(c.dependents)}; drop or recreate them first "
                                 "(they would not follow the new column)")
            if isinstance(op, ChangeType):
                new, t = op.column + NEW_SUFFIX, normalise_type(op.type, engine)
                node = parse_expression(op.using or f"CAST({op.column} AS {t})", engine, {op.column})
            else:
                new, t = op.new_name, c.type
                if new in cols:
                    raise ValueError(f"column {new!r} already exists")
                node = parse_expression(op.column, engine, {op.column})
            ident(new)
            need_ae(f"{op.op} {op.column}")
            p.expand.append(Stmt(
                f"ALTER TABLE {table} ADD COLUMN {'IF NOT EXISTS ' if pg else ''}{q(new)} {t}"
                + ("" if pg else ", ALGORITHM=INSTANT"),
                ae if pg else "MDL (brief, INSTANT)", "new column, filled by trigger and backfill"))
            trig = ident(f"oplia_sync_{_short(change.table, op.column, new)}")
            fill = _expr_sql(node, engine, "NEW")
            two_way = isinstance(op, RenameColumn)
            p.expand.extend(_sync_trigger(engine, table, trig, op.column, new, fill, two_way, schema))
            p.backfill.append(Backfill(column=new, expression=_expr_sql(node, engine), pk=pk))
            p.checks.append(Check(
                f"SELECT count(*) FROM {table} WHERE NOT ({_eq(engine, q(new), '(' + _expr_sql(node, engine) + ')')})",  # nosec B608
                f"{new} matches {op.column} on every row"))
            p.contract_checks.append(p.checks[-1])
            p.contract.extend(_drop_trigger(engine, table, trig, schema))
            if isinstance(op, ChangeType):
                if pg:
                    p.contract.append(Stmt(
                        f"ALTER TABLE {table} RENAME COLUMN {q(op.column)} TO {q(op.column + OLD_SUFFIX)}", ae))
                    p.contract.append(Stmt(f"ALTER TABLE {table} RENAME COLUMN {q(new)} TO {q(op.column)}", ae))
                else:
                    p.contract.append(Stmt(
                        f"ALTER TABLE {table} RENAME COLUMN {q(op.column)} TO {q(op.column + OLD_SUFFIX)}, "
                        f"RENAME COLUMN {q(new)} TO {q(op.column)}, ALGORITHM=INSTANT", "MDL (brief, INSTANT)"))
                p.contract.append(_drop_col(engine, table, op.column + OLD_SUFFIX))
            else:
                p.contract.append(_drop_col(engine, table, op.column))
            if c.default is not None:
                p.warnings.append(f"{op.column} has a default ({c.default}); it is not copied to {new}")
            cols[new] = ColumnInfo(new, t, True, None, [])
        elif isinstance(op, DropColumn):
            need_col(op.column)
            if op.column in info.pk:
                raise ValueError(f"{op.column} is part of the primary key")
            need_ae(f"drop_column {op.column}")
            p.contract.append(_drop_col(engine, table, op.column))
    p.contract = [s for s in p.contract if s.sql]
    return p


def _eq(engine: str, a: str, b: str) -> str:
    return f"{a} IS NOT DISTINCT FROM {b}" if engine == "postgres" else f"{a} <=> {b}"


def _drop_col(engine: str, table: str, col: str) -> Stmt:
    if engine == "postgres":
        return Stmt(f'ALTER TABLE {table} DROP COLUMN IF EXISTS "{ident(col)}"', "ACCESS EXCLUSIVE (catalog only)",
                    "catalog-only: space is reclaimed by later updates/VACUUM")
    return Stmt(f"ALTER TABLE {table} DROP COLUMN `{ident(col)}`, ALGORITHM=INSTANT", "MDL (brief, INSTANT)")


def _sync_trigger(engine: str, table: str, trig: str, old: str, new: str, fill: str, two_way: bool,
                  schema: str) -> list[Stmt]:
    if engine == "postgres":
        fn = f'"{schema}"."{trig}"'
        if two_way:
            body = (f'IF TG_OP = \'INSERT\' THEN IF NEW."{new}" IS NULL THEN NEW."{new}" := NEW."{old}"; '
                    f'ELSIF NEW."{old}" IS NULL THEN NEW."{old}" := NEW."{new}"; END IF; '
                    f'ELSIF NEW."{new}" IS DISTINCT FROM OLD."{new}" THEN NEW."{old}" := NEW."{new}"; '
                    f'ELSE NEW."{new}" := NEW."{old}"; END IF;')
        else:
            body = f'NEW."{new}" := {fill};'
        return [
            Stmt(f"CREATE OR REPLACE FUNCTION {fn}() RETURNS trigger LANGUAGE plpgsql AS $oplia$ BEGIN {body} "
                 "RETURN NEW; END $oplia$", "none", "trigger function (no table lock)"),
            Stmt(f'DROP TRIGGER IF EXISTS "{trig}" ON {table}', "ACCESS EXCLUSIVE (catalog only)",
                 "makes re-running EXPAND idempotent"),
            Stmt(f'CREATE TRIGGER "{trig}" BEFORE INSERT OR UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION {fn}()',
                 "SHARE ROW EXCLUSIVE", "keeps the new column in sync for every write from now on"),
        ]
    if two_way:
        ins = (f"IF NEW.`{new}` IS NULL THEN SET NEW.`{new}` = NEW.`{old}`; "
               f"ELSEIF NEW.`{old}` IS NULL THEN SET NEW.`{old}` = NEW.`{new}`; END IF;")
        upd = (f"IF NOT (NEW.`{new}` <=> OLD.`{new}`) THEN SET NEW.`{old}` = NEW.`{new}`; "
               f"ELSE SET NEW.`{new}` = NEW.`{old}`; END IF;")
    else:
        ins = upd = f"SET NEW.`{new}` = {fill};"
    return [
        Stmt(f"DROP TRIGGER IF EXISTS `{trig}_i`", "none"),
        Stmt(f"CREATE TRIGGER `{trig}_i` BEFORE INSERT ON {table} FOR EACH ROW BEGIN {ins} END",
             "MDL (brief, INSTANT)",
             "needs TRIGGER privilege; with binary logging also log_bin_trust_function_creators or SUPER"),
        Stmt(f"DROP TRIGGER IF EXISTS `{trig}_u`", "none"),
        Stmt(f"CREATE TRIGGER `{trig}_u` BEFORE UPDATE ON {table} FOR EACH ROW BEGIN {upd} END",
             "MDL (brief, INSTANT)"),
    ]


def _drop_trigger(engine: str, table: str, trig: str, schema: str) -> list[Stmt]:
    if engine == "postgres":
        return [Stmt(f'DROP TRIGGER IF EXISTS "{trig}" ON {table}', "ACCESS EXCLUSIVE (catalog only)"),
                Stmt(f'DROP FUNCTION IF EXISTS "{schema}"."{trig}"()', "none")]
    return [Stmt(f"DROP TRIGGER IF EXISTS `{trig}_i`", "MDL (brief, INSTANT)"),
            Stmt(f"DROP TRIGGER IF EXISTS `{trig}_u`", "MDL (brief, INSTANT)")]


# --------------------------------------------------------------------------- catalog
def _rows(conn: Any, engine: str, sql: str, params: Sequence[Any] = ()) -> list[tuple[Any, ...]]:
    args = tuple(params) if params else None       # no parameters: the SQL is sent as is (no % processing)
    if engine == "postgres":
        return list(conn.execute(sql, args).fetchall())
    with conn.cursor() as cur:
        cur.execute(sql, args)
        return list(cur.fetchall())


def table_info(conn: Any, engine: str, table: str, schema: str | None = None) -> TableInfo | None:
    if engine == "postgres":
        rel = _rows(conn, engine, "SELECT to_regclass(format('%%I.%%I', %s::text, %s::text))::oid",
                    (schema or "public", table))[0][0]
        if rel is None:
            return None
        cols = {}
        for name, typ, notnull, default, num in _rows(conn, engine, (
                "SELECT a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull, "
                "pg_get_expr(d.adbin, d.adrelid), a.attnum FROM pg_attribute a "
                "LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum "
                "WHERE a.attrelid = %s AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum"), (rel,)):
            deps = [str(r[0]) for r in _rows(conn, engine, (
                "SELECT DISTINCT pg_describe_object(classid, objid, objsubid) FROM pg_depend "
                "WHERE refclassid = 'pg_class'::regclass AND refobjid = %s AND refobjsubid = %s "
                "AND deptype IN ('n', 'a') AND classid <> 'pg_attrdef'::regclass "
                "AND NOT (classid = 'pg_constraint'::regclass AND objid IN "
                "(SELECT oid FROM pg_constraint WHERE conrelid = %s AND contype = 'p'))"), (rel, num, rel))]
            cols[name] = ColumnInfo(name, typ, not notnull, default, deps)
        pk = [r[0] for r in _rows(conn, engine, (
            "SELECT a.attname FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid "
            "AND a.attnum = ANY(i.indkey) WHERE i.indrelid = %s AND i.indisprimary "
            "ORDER BY array_position(i.indkey::int2[], a.attnum)"), (rel,))]
        idx = [r[0] for r in _rows(conn, engine, (
            "SELECT c.relname FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE i.indrelid = %s"), (rel,))]
        return TableInfo(cols, pk, idx)
    rows = _rows(conn, engine, (
        "SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_DEFAULT, COLUMN_KEY FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s ORDER BY ORDINAL_POSITION"), (table,))
    if not rows:
        return None
    used = {r[0] for r in _rows(conn, engine, (
        "SELECT COLUMN_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s "
        "AND INDEX_NAME <> 'PRIMARY' UNION SELECT COLUMN_NAME FROM information_schema.KEY_COLUMN_USAGE "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND REFERENCED_TABLE_NAME IS NOT NULL "
        "UNION SELECT REFERENCED_COLUMN_NAME FROM information_schema.KEY_COLUMN_USAGE "
        "WHERE REFERENCED_TABLE_SCHEMA = DATABASE() AND REFERENCED_TABLE_NAME = %s"), (table, table, table))}
    cols = {str(r[0]): ColumnInfo(str(r[0]), _txt(r[1]), r[2] == "YES", None if r[3] is None else _txt(r[3]),
                                  ["an index or foreign key"] if r[0] in used else []) for r in rows}
    pk = [str(r[0]) for r in _rows(conn, engine, (
        "SELECT COLUMN_NAME FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = DATABASE() "
        "AND TABLE_NAME = %s AND CONSTRAINT_NAME = 'PRIMARY' ORDER BY ORDINAL_POSITION"), (table,))]
    idx = sorted({str(r[0]) for r in _rows(conn, engine, (
        "SELECT INDEX_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() "
        "AND TABLE_NAME = %s"), (table,))})
    return TableInfo(cols, pk, idx)


def _txt(v: Any) -> str:
    return v.decode() if isinstance(v, (bytes, bytearray)) else str(v)


# --------------------------------------------------------------------------- execution
class LockRetryExhaustedError(RuntimeError):
    pass


def _retryable(engine: str, e: Exception) -> bool:
    if engine == "postgres":
        return getattr(e, "sqlstate", None) in PG_RETRYABLE
    args: tuple[Any, ...] = tuple(getattr(e, "args", ()))
    return bool(args) and args[0] in MYSQL_RETRYABLE


class Runner:
    """Runs plan statements with bounded lock waits and back-off retries."""

    def __init__(self, conn: Any, engine: str, change: SchemaChange,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.conn, self.engine, self.change, self._sleep = conn, engine, change, sleep
        self.attempts: list[dict[str, Any]] = []
        if engine == "mysql":
            secs = max(1, -(-change.lock_timeout_ms // 1000))
            self._mysql(f"SET SESSION lock_wait_timeout = {int(secs)}")
            self._mysql(f"SET SESSION innodb_lock_wait_timeout = {int(secs)}")

    def _mysql(self, sql: str, params: Sequence[Any] = ()) -> list[tuple[Any, ...]]:
        with self.conn.cursor() as cur:
            cur.execute(sql, tuple(params) if params else None)
            return list(cur.fetchall()) if cur.description else []

    def run(self, s: Stmt) -> None:
        for attempt in range(self.change.max_retries + 1):
            t0 = time.monotonic()
            try:
                self._once(s)
                self.attempts.append({"sql": s.sql[:200], "attempt": attempt + 1, "ok": True,
                                      "ms": round((time.monotonic() - t0) * 1000, 1)})
                return
            except Exception as e:
                if not _retryable(self.engine, e) or attempt == self.change.max_retries:
                    if _retryable(self.engine, e):
                        raise LockRetryExhaustedError(
                            f"lock not acquired within {self.change.lock_timeout_ms} ms after "
                            f"{attempt + 1} attempts: {s.sql[:200]}") from e
                    raise
                self.attempts.append({"sql": s.sql[:200], "attempt": attempt + 1, "ok": False,
                                      "error": type(e).__name__})
                base = min(5.0, self.change.lock_timeout_ms / 1000 * (2 ** min(attempt, 6)))
                self._sleep(base * (0.5 + random.random() / 2))  # noqa: S311 # nosec B311 - jitter, not crypto

    def _once(self, s: Stmt) -> None:
        if self.engine == "postgres":
            lt = f"SET {{}}lock_timeout = '{int(self.change.lock_timeout_ms)}ms'"
            if s.autocommit:
                self.conn.execute(lt.format(""))
                try:
                    self.conn.execute(s.sql)
                except Exception:
                    self._drop_invalid_index(s)
                    raise
                finally:
                    self.conn.execute("RESET lock_timeout")
            else:
                with self.conn.transaction():
                    self.conn.execute(lt.format("LOCAL "))
                    self.conn.execute(s.sql)
            return
        for pre in s.session:
            self._mysql(pre)
        try:
            self._mysql(s.sql)
        finally:
            if s.session:
                self._mysql("SET SESSION foreign_key_checks = 1")

    def _drop_invalid_index(self, s: Stmt) -> None:
        """A failed CREATE INDEX CONCURRENTLY leaves an INVALID index behind; remove it before a retry."""
        m = re.match(r'CREATE (?:UNIQUE )?INDEX CONCURRENTLY IF NOT EXISTS "(\w+)"', s.sql)
        if not m:
            return
        schema = self.change.schema_name or "public"
        bad = self.conn.execute(
            "SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_namespace n "
            "ON n.oid = c.relnamespace WHERE n.nspname = %s AND c.relname = %s AND NOT i.indisvalid",
            (schema, m.group(1))).fetchone()
        if bad:
            self.conn.execute(f'DROP INDEX CONCURRENTLY IF EXISTS "{ident(schema)}"."{ident(m.group(1))}"')

    def scalar(self, sql: str, params: Sequence[Any] = ()) -> Any:
        rows = _rows(self.conn, self.engine, sql, params)
        return rows[0][0] if rows else None

    def backfill_batch(self, plan: Plan, b: Backfill, last: list[Any] | None) -> tuple[list[Any] | None, int]:
        """One keyset batch: rows after ``last`` (by primary key), up to batch_size. Returns (new last, updated)."""
        def q(n: str) -> str:
            return _q(self.engine, n)

        pk = ", ".join(q(c) for c in b.pk)
        ph = ", ".join(["%s"] * len(b.pk))
        after = f" WHERE ({pk}) > ({ph})" if last is not None else ""
        rows = _rows(self.conn, self.engine,
                     f"SELECT {pk} FROM {plan.qualified}{after} ORDER BY {pk} LIMIT {int(self.change.batch_size)}",  # nosec B608
                     tuple(last or ()))
        if not rows:
            return None, 0
        hi = list(rows[-1])
        lo_cond = f"({pk}) > ({ph}) AND " if last is not None else ""
        e = _pct(b.expression)
        sql = (f"UPDATE {plan.qualified} SET {q(b.column)} = {e} WHERE {lo_cond}({pk}) <= ({ph}) "  # nosec B608
               f"AND NOT ({_eq(self.engine, q(b.column), '(' + e + ')')})")
        params = tuple(last or []) + tuple(hi)
        for attempt in range(self.change.max_retries + 1):
            try:
                if self.engine == "postgres":
                    with self.conn.transaction():
                        self.conn.execute(f"SET LOCAL lock_timeout = '{int(self.change.lock_timeout_ms)}ms'")
                        n = self.conn.execute(sql, params).rowcount
                else:
                    with self.conn.cursor() as cur:
                        n = cur.execute(sql, params)
                return hi, int(n or 0)
            except Exception as e:
                if not _retryable(self.engine, e) or attempt == self.change.max_retries:
                    raise
                self._sleep(min(5.0, self.change.lock_timeout_ms / 1000 * (2 ** min(attempt, 6))))
        raise AssertionError("unreachable")  # pragma: no cover


def mysql_trigger_precheck(conn: Any) -> None:
    """With binary logging on, MySQL refuses CREATE TRIGGER (error 1419) unless the user has SUPER or
    log_bin_trust_function_creators=1. Check before EXPAND so nothing is half-applied."""
    log_bin, trust = _rows(conn, "mysql", "SELECT @@log_bin, @@log_bin_trust_function_creators")[0]
    if not int(log_bin) or int(trust):
        return
    who = _rows(conn, "mysql", "SELECT CURRENT_USER()")[0][0]
    user, _, host = _txt(who).rpartition("@")
    sup = _rows(conn, "mysql", "SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE = %s "
                "AND PRIVILEGE_TYPE = 'SUPER'", (f"'{user}'@'{host}'",))[0][0]
    if not int(sup):
        raise ValueError("binary logging is on and log_bin_trust_function_creators=0: MySQL will refuse the sync "
                         "triggers (error 1419). Set log_bin_trust_function_creators=1 (RDS/Aurora parameter group, "
                         "Azure server parameter, Cloud SQL flag) before this change")


def _jsonable(v: Any) -> Any:
    return v if isinstance(v, (int, str, float, bool)) or v is None else str(v)


# --------------------------------------------------------------------------- job machines
class _Base(JobMachine):
    def __init__(self, registry: DatabaseRegistry, session_factory: Any,
                 audit: Callable[[str, dict[str, Any]], None] | None = None,
                 sleep: Callable[[float], None] = time.sleep, max_batches_per_step: int = 200, **kw: Any) -> None:
        super().__init__(session_factory, **kw)
        self.registry = registry
        self._audit = audit
        self._sleep = sleep
        self.max_batches_per_step = max_batches_per_step

    def _dbs(self) -> list[DatabaseSpec]:
        return [s for s in self.registry.specs.values() if s.engine in SUPPORTED_ENGINES]

    def _connect(self, name: str) -> tuple[Any, DatabaseSpec]:
        spec = self.registry.get(name)
        if spec.engine not in SUPPORTED_ENGINES:
            raise ValueError(f"{name}: online DDL supports {SUPPORTED_ENGINES}, not {spec.engine}")
        conn, _ = self.registry.connect(spec)
        return conn, spec

    def finish(self, job: DrJobRow) -> None:
        if self._audit is not None:
            st = json.loads(job.state_json)
            self._audit(f"{self.action}.{job.status.lower()}",
                        {"job_id": job.id, "target": job.target, "error": job.error,
                         "rows_backfilled": st.get("rows_backfilled"), "attempts": len(st.get("attempts", []))})


class OnlineSchemaChange(_Base):
    """Gated job: PLAN -> EXPAND -> BACKFILL -> VALIDATE. Contract is a separate job (``schema_contract``)."""

    kind = "schema_change"
    action = ACTION_SCHEMA_CHANGE
    title = "Online schema change (expand)"
    first_step = "PLAN"

    def fields(self) -> list[dict[str, Any]]:
        return [{"name": "database", "label": "Database", "kind": "select", "required": True,
                 "options": [{"value": s.name, "label": f"{s.name} ({s.engine}, {s.cloud})"} for s in self._dbs()]},
                {"name": "change", "label": "Change (JSON: table, operations, ...)", "kind": "textarea",
                 "required": True,
                 "help": 'e.g. {"table": "orders", "operations": [{"op": "add_index", "name": "ix_orders_c", '
                         '"columns": ["customer_id"]}]}'}]

    def summary(self) -> dict[str, Any]:
        return {"databases": [f"{s.name} ({s.engine})" for s in self._dbs()],
                "operations": ["add_column", "add_index", "drop_index", "add_foreign_key", "add_check",
                               "set_not_null", "change_type", "rename_column", "drop_column"]}

    def parse(self, params: dict[str, Any]) -> dict[str, Any]:
        raw = params.get("change", params)
        if isinstance(raw, str):
            raw = json.loads(raw)
        if not isinstance(raw, dict):
            raise ValueError("change must be a JSON object")
        raw = {k: v for k, v in raw.items() if k != "requested_by"}
        if "database" not in raw and params.get("database"):
            raw["database"] = params["database"]
        change = SchemaChange.model_validate(raw)
        spec = self.registry.get(change.database)
        if spec.engine not in SUPPORTED_ENGINES:
            raise ValueError(f"{spec.name}: online DDL supports {SUPPORTED_ENGINES}, not {spec.engine}")
        return change.model_dump(mode="json")

    def target_of(self, payload: dict[str, Any]) -> str:
        return f"{payload['database']}:{payload['table']}"

    def describe(self, payload: dict[str, Any]) -> str:
        c = SchemaChange.model_validate(payload)
        ops = ", ".join(o.op for o in c.operations)
        return (f"online schema change on {c.database} table {c.table}: {ops} (expand, backfill, validate; "
                f"lock_timeout {c.lock_timeout_ms} ms; contract is a separate approval)")

    # steps
    def _step_plan(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        change = SchemaChange.model_validate(payload)
        conn, spec = self._connect(change.database)
        try:
            info = table_info(conn, spec.engine, change.table, change.schema_name)
            if info is None:
                raise ValueError(f"table {change.table} not found in {change.database}")
            refs: dict[str, TableInfo] = {}
            for op in change.operations:
                if isinstance(op, AddForeignKey):
                    r = table_info(conn, spec.engine, op.ref_table, change.schema_name)
                    if r is not None:
                        refs[op.ref_table] = r
            plan = build_plan(change, spec.engine, info, refs)
            if spec.engine == "mysql" and any("CREATE TRIGGER" in x.sql for x in plan.expand):
                mysql_trigger_precheck(conn)
        finally:
            conn.close()
        st.update(plan=plan.to_json(), expand_done=0, validate_done=0, backfill_index=0, backfill_last=None,
                  rows_backfilled=0, attempts=[])
        return "EXPAND"

    def _run_list(self, change: SchemaChange, st: dict[str, Any], key: str, stmts: list[Stmt]) -> None:
        conn, spec = self._connect(change.database)
        try:
            r = Runner(conn, spec.engine, change, self._sleep)
            for i in range(int(st[key]), len(stmts)):
                r.run(stmts[i])
                st[key] = i + 1
                st["attempts"] = (st.get("attempts", []) + r.attempts)[-200:]
                r.attempts = []
        finally:
            conn.close()

    def _step_expand(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        change = SchemaChange.model_validate(payload)
        self._run_list(change, st, "expand_done", Plan.from_json(st["plan"]).expand)
        return "BACKFILL"

    def _step_backfill(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        change = SchemaChange.model_validate(payload)
        plan = Plan.from_json(st["plan"])
        conn, spec = self._connect(change.database)
        try:
            r = Runner(conn, spec.engine, change, self._sleep)
            for _ in range(self.max_batches_per_step):
                i = int(st["backfill_index"])
                if i >= len(plan.backfill):
                    return "VALIDATE"
                last, n = r.backfill_batch(plan, plan.backfill[i], st["backfill_last"])
                if last is None:
                    st["backfill_index"], st["backfill_last"] = i + 1, None
                    continue
                st["backfill_last"] = [_jsonable(v) for v in last]
                st["rows_backfilled"] = int(st["rows_backfilled"]) + n
                if change.batch_pause_ms:
                    self._sleep(change.batch_pause_ms / 1000)
        finally:
            conn.close()
        return "BACKFILL"     # more batches: the next worker run continues from backfill_last

    def _step_validate(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        change = SchemaChange.model_validate(payload)
        plan = Plan.from_json(st["plan"])
        conn, spec = self._connect(change.database)
        try:
            r = Runner(conn, spec.engine, change, self._sleep)
            results = []
            for c in plan.checks:
                bad = int(r.scalar(c.sql) or 0)
                results.append({"check": c.what, "offending_rows": bad, "passed": bad == 0})
                if bad:
                    st["checks"] = results
                    raise ValueError(f"validation failed: {c.what}: {bad} offending rows")
            st["checks"] = results
        finally:
            conn.close()
        self._run_list(change, st, "validate_done", plan.validate)
        st["awaiting_contract"] = bool(plan.contract)
        return "DONE"


class SchemaContract(_Base):
    """Gated job: re-check a finished expand job, then run its CONTRACT statements."""

    kind = "schema_contract"
    action = ACTION_SCHEMA_CONTRACT
    title = "Online schema change (contract)"
    first_step = "CHECK"

    def __init__(self, expand: OnlineSchemaChange, *a: Any, **kw: Any) -> None:
        super().__init__(*a, **kw)
        self.expand = expand

    def fields(self) -> list[dict[str, Any]]:
        return [{"name": "expand_job_id", "label": "Finished expand job ID", "kind": "text", "required": True,
                 "help": "Run this only after the application no longer uses the old column or index."}]

    def parse(self, params: dict[str, Any]) -> dict[str, Any]:
        jid = str(params.get("expand_job_id", ""))
        if not re.fullmatch(r"[0-9a-f-]{36}", jid):
            raise ValueError("expand_job_id must be a job id")
        try:
            job = self.expand.get(jid)
        except KeyError:
            raise ValueError("expand job not found") from None
        if job["kind"] != self.expand.kind or job["status"] != "SUCCEEDED":
            raise ValueError(f"expand job must be a SUCCEEDED schema_change, it is {job['kind']} {job['status']}")
        if not job["state"].get("plan", {}).get("contract"):
            raise ValueError("that expand job has nothing to contract")
        return {"expand_job_id": jid}

    def target_of(self, payload: dict[str, Any]) -> str:
        return str(self.expand.get(payload["expand_job_id"])["target"])

    def describe(self, payload: dict[str, Any]) -> str:
        job = self.expand.get(self.parse(payload)["expand_job_id"])
        stmts = [s["sql"][:120] for s in job["state"]["plan"]["contract"]]
        return f"contract {job['target']}: " + "; ".join(stmts)

    def _step_check(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        ex = self.expand.get(self.parse(payload)["expand_job_id"])
        change = SchemaChange.model_validate(ex["payload"])
        plan = Plan.from_json(ex["state"]["plan"])
        conn, spec = self._connect(change.database)
        try:
            r = Runner(conn, spec.engine, change, self._sleep)
            res = []
            for c in plan.contract_checks:
                bad = int(r.scalar(c.sql) or 0)
                res.append({"check": c.what, "offending_rows": bad, "passed": bad == 0})
                if bad:
                    raise ValueError(f"re-check failed before contract: {c.what}: {bad} rows")
            st["checks"] = res
        finally:
            conn.close()
        st.update(contract_done=0, attempts=[])
        return "CONTRACT"

    def _step_contract(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        ex = self.expand.get(payload["expand_job_id"])
        change = SchemaChange.model_validate(ex["payload"])
        conn, spec = self._connect(change.database)
        try:
            r = Runner(conn, spec.engine, change, self._sleep)
            stmts = Plan.from_json(ex["state"]["plan"]).contract
            for i in range(int(st["contract_done"]), len(stmts)):
                r.run(stmts[i])
                st["contract_done"] = i + 1
            st["attempts"] = r.attempts[-200:]
        finally:
            conn.close()
        return "DONE"
