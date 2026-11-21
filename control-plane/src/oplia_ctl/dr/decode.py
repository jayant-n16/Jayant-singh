"""Decode replication records of different engines into one normalised :class:`Mutation` model.

Supported formats (``Record.format``):

* ``sql``             - statement text (PostgreSQL / MySQL / CockroachDB dialects), parsed with
                        sqlglot so keywords inside string literals are not mistaken for commands
* ``debezium``        - Debezium change-event envelope (PostgreSQL, MySQL, MongoDB connectors):
                        ``op`` c/u/d/r/t and MySQL schema-change events carrying ``ddl``
* ``mongo_change``    - MongoDB change-stream event (``operationType``)
* ``mongo_command``   - MongoDB command document, BSON bytes or JSON (``delete``/``update``/
                        ``drop``/``dropDatabase``) - this is where a ``deleteMany({})`` is visible
* ``crdb_changefeed`` - CockroachDB changefeed message (``wrapped`` envelope: ``after``/``before``,
                        or ``enriched`` envelope with ``op``); a deleted row has ``after: null``

Anything that cannot be decoded is returned as a ``undecodable`` mutation - the rules treat
unreadable traffic as suspicious instead of silently passing it.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any, Literal

Engine = Literal["postgres", "mysql", "mongodb", "cockroachdb", "unknown"]
Kind = Literal["insert", "update", "delete", "truncate", "drop_table", "drop_database", "drop_schema",
               "ddl", "read", "other", "undecodable"]
Format = Literal["sql", "debezium", "mongo_change", "mongo_command", "crdb_changefeed"]


@dataclass(frozen=True)
class Record:
    """One record from the replication stream, as received."""

    format: Format
    payload: bytes | str | dict[str, Any]
    engine: Engine = "unknown"
    position: str = ""          # source position (topic/partition/offset, LSN, resume token ...)
    sql_dialect: str = "postgres"


@dataclass(frozen=True)
class Mutation:
    engine: Engine
    kind: Kind
    target: str                 # database.table / database.collection, best effort
    rows: int = 1               # rows/documents affected (best effort, >= 0)
    unconstrained: bool = False  # UPDATE/DELETE/deleteMany/updateMany without any filter
    statement: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


def _as_obj(payload: bytes | str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(payload, dict):
        return payload
    text = payload.decode("utf-8") if isinstance(payload, bytes) else payload
    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError("record is not a JSON object")
    return obj


# ---------------------------------------------------------------------------- SQL
def decode_sql(text: str, engine: Engine = "postgres", dialect: str = "postgres") -> list[Mutation]:
    import sqlglot
    from sqlglot import exp
    from sqlglot.errors import ParseError

    try:
        statements = [s for s in sqlglot.parse(text, read=dialect) if s is not None]
    except ParseError as exc:
        return [Mutation(engine, "undecodable", "", 0, statement=text, detail={"error": str(exc)[:300]})]
    out: list[Mutation] = []
    for st in statements:
        sql = st.sql(dialect=dialect)
        table = st.find(exp.Table)
        target = table.sql(dialect=dialect) if table is not None else ""
        if isinstance(st, exp.Drop):
            kind_word = str(st.args.get("kind") or "").upper()
            kind: Kind = {"TABLE": "drop_table", "DATABASE": "drop_database",
                          "SCHEMA": "drop_schema"}.get(kind_word, "ddl")  # type: ignore[assignment]
            out.append(Mutation(engine, kind, target, 0, statement=sql, detail={"object": kind_word}))
        elif isinstance(st, exp.TruncateTable):
            names = [t.sql(dialect=dialect) for t in st.find_all(exp.Table)]
            out.append(Mutation(engine, "truncate", ", ".join(names), 0, statement=sql))
        elif isinstance(st, exp.Delete):
            out.append(Mutation(engine, "delete", target, 0, unconstrained=st.args.get("where") is None,
                                statement=sql))
        elif isinstance(st, exp.Update):
            out.append(Mutation(engine, "update", target, 0, unconstrained=st.args.get("where") is None,
                                statement=sql))
        elif isinstance(st, exp.Insert):
            out.append(Mutation(engine, "insert", target, 0, statement=sql))
        elif isinstance(st, (exp.Create, exp.Alter)):
            out.append(Mutation(engine, "ddl", target, 0, statement=sql))
        elif isinstance(st, exp.Select):
            out.append(Mutation(engine, "read", target, 0, statement=sql))
        else:
            out.append(Mutation(engine, "other", target, 0, statement=sql))
    return out


# ----------------------------------------------------------------------- Debezium
_DBZ_OPS: dict[str, Kind] = {"c": "insert", "u": "update", "d": "delete", "r": "read", "t": "truncate"}


def decode_debezium(obj: dict[str, Any], engine: Engine) -> list[Mutation]:
    payload = obj.get("payload", obj) if "schema" in obj else obj
    if payload is None:  # tombstone that follows a delete
        return []
    if "ddl" in payload and "op" not in payload:  # MySQL schema-change event
        ddl = str(payload.get("ddl") or "")
        return decode_sql(ddl, engine="mysql", dialect="mysql") if ddl else []
    op = str(payload.get("op", ""))
    src = payload.get("source") or {}
    db = src.get("db") or src.get("database") or ""
    tbl = src.get("table") or src.get("collection") or ""
    kind = _DBZ_OPS.get(op)
    if kind is None:
        return [Mutation(engine, "undecodable", f"{db}.{tbl}", 0, detail={"op": op})]
    return [Mutation(engine, kind, f"{db}.{tbl}", 1, detail={"op": op})]


# ------------------------------------------------------------------------ MongoDB
_CHANGE_KINDS: dict[str, Kind] = {
    "insert": "insert", "update": "update", "replace": "update", "delete": "delete",
    "drop": "drop_table", "dropDatabase": "drop_database", "rename": "ddl", "invalidate": "other",
    "create": "ddl", "createIndexes": "ddl", "dropIndexes": "ddl", "modify": "ddl",
}


def decode_mongo_change(obj: dict[str, Any]) -> list[Mutation]:
    op = str(obj.get("operationType", ""))
    ns = obj.get("ns") or {}
    target = ".".join(x for x in (ns.get("db"), ns.get("coll")) if x)
    kind = _CHANGE_KINDS.get(op, "undecodable")
    return [Mutation("mongodb", kind, target, 1 if kind in ("insert", "update", "delete") else 0,
                     detail={"operationType": op})]


def _empty_filter(q: Any) -> bool:
    return q is None or (isinstance(q, dict) and len(q) == 0)


def decode_mongo_command(payload: bytes | str | dict[str, Any]) -> list[Mutation]:
    if isinstance(payload, bytes) and not payload.lstrip().startswith(b"{"):
        import bson

        cmd: dict[str, Any] = bson.decode(payload)
    else:
        cmd = _as_obj(payload)
    db = str(cmd.get("$db", ""))
    if "dropDatabase" in cmd:
        return [Mutation("mongodb", "drop_database", db, 0, statement="dropDatabase")]
    if "drop" in cmd:
        return [Mutation("mongodb", "drop_table", f"{db}.{cmd['drop']}", 0, statement="drop")]
    if "delete" in cmd:
        coll = f"{db}.{cmd['delete']}"
        out = []
        for d in cmd.get("deletes") or []:
            many = int(d.get("limit", 0)) == 0  # limit 0 = deleteMany
            out.append(Mutation("mongodb", "delete", coll, 0, unconstrained=many and _empty_filter(d.get("q")),
                                statement="deleteMany" if many else "deleteOne",
                                detail={"filter": d.get("q")}))
        return out
    if "update" in cmd:
        coll = f"{db}.{cmd['update']}"
        return [Mutation("mongodb", "update", coll, 0,
                         unconstrained=bool(u.get("multi")) and _empty_filter(u.get("q")),
                         statement="updateMany" if u.get("multi") else "updateOne",
                         detail={"filter": u.get("q")}) for u in cmd.get("updates") or []]
    if "insert" in cmd:
        return [Mutation("mongodb", "insert", f"{db}.{cmd['insert']}", len(cmd.get("documents") or []),
                         statement="insert")]
    return [Mutation("mongodb", "other", db, 0, statement=next(iter(cmd), ""))]


# -------------------------------------------------------------------- CockroachDB
def decode_crdb_changefeed(obj: dict[str, Any]) -> list[Mutation]:
    if "payload" in obj and isinstance(obj["payload"], list):  # webhook sink batches messages
        out: list[Mutation] = []
        for m in obj["payload"]:
            out += decode_crdb_changefeed(m)
        return out
    if "resolved" in obj and "after" not in obj and "op" not in obj:
        return []  # resolved timestamp: no data
    topic = str(obj.get("topic") or obj.get("table") or "")
    op = obj.get("op")
    if op is not None:  # enriched envelope
        kind = _DBZ_OPS.get(str(op), "undecodable")
        return [Mutation("cockroachdb", kind, topic, 1, detail={"op": op})]
    if "after" in obj:
        if obj["after"] is None:
            return [Mutation("cockroachdb", "delete", topic, 1)]
        return [Mutation("cockroachdb", "update" if obj.get("before") else "insert", topic, 1)]
    return [Mutation("cockroachdb", "undecodable", topic, 0)]


def decode(record: Record) -> list[Mutation]:
    try:
        if record.format == "sql":
            text = record.payload if isinstance(record.payload, str) else (
                record.payload.decode("utf-8") if isinstance(record.payload, bytes) else json.dumps(record.payload))
            return decode_sql(text, record.engine, record.sql_dialect)
        if record.format == "debezium":
            return decode_debezium(_as_obj(record.payload), record.engine)
        if record.format == "mongo_change":
            return decode_mongo_change(_as_obj(record.payload))
        if record.format == "mongo_command":
            return decode_mongo_command(record.payload)
        if record.format == "crdb_changefeed":
            return decode_crdb_changefeed(_as_obj(record.payload))
    except Exception as exc:  # unreadable traffic is reported, never passed silently
        return [Mutation(record.engine, "undecodable", "", 0, detail={"error": f"{type(exc).__name__}: {exc}"[:300]})]
    raise ValueError(f"unknown record format {record.format!r}")


def payload_for_dump(record: Record) -> Any:
    """JSON-safe, complete representation of a record for incident dumps (never truncated)."""
    p = record.payload
    if isinstance(p, dict):
        return p
    if isinstance(p, bytes):
        if record.format == "mongo_command" and not p.lstrip().startswith(b"{"):
            import bson
            from bson import json_util

            return json.loads(json_util.dumps(bson.decode(p)))
        try:
            return json.loads(p.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return {"base64": base64.b64encode(p).decode()}
    try:
        return json.loads(p)
    except ValueError:
        return p
