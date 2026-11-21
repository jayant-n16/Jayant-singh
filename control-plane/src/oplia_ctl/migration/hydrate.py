"""FR-04 inline hydration sidecar: Debezium change events -> joined documents / graph / embeddings -> target.

Modes (``HydrationSpec.mode``):

* ``flat``     - each source table goes to a collection of the same name (key-value, cache, time-series,
                 warehouse, wide-column targets).
* ``document`` - a root table plus 1:N children embedded as arrays (Cosmos DB, DocumentDB, Firestore). The
                 joined document is kept in the control-plane database (``migration_hydration_docs``) so a
                 child change rewrites the whole parent document; a child that arrives before its parent
                 is held until the parent arrives (CDC gives no cross-table ordering).
* ``graph``    - tables become vertices, foreign keys become edges (Neptune, Cosmos Gremlin).
* ``vector``   - configured text columns are embedded by an AI provider (``embed``) and written with the
                 row; embeddings are normalised to unit length.

Delivery is at-least-once: Kafka offsets are committed only after the target accepted the batch, and every
write is an idempotent upsert keyed by the source primary key. Debezium events must use the JSON converter
(``value.converter.schemas.enable`` true or false - both envelopes are handled).
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session, sessionmaker

from oplia_ctl.migration.models import HydrationDocRow
from oplia_ctl.migration.targets import TargetWriter, normalise

log = logging.getLogger("oplia.migration.hydrate")


@dataclass
class Change:
    table: str
    op: str                      # c (insert), u (update), d (delete), r (snapshot read)
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    ts_ms: int | None

    @property
    def row(self) -> dict[str, Any]:
        return (self.after if self.op != "d" else self.before) or {}


def parse_event(value: bytes | str | dict[str, Any] | None) -> Change | None:
    """A Debezium change event (JSON converter, with or without the schema wrapper). None for tombstones."""
    if value is None:
        return None
    ev = json.loads(value) if isinstance(value, (bytes, str)) else value
    if isinstance(ev, dict) and "payload" in ev and "schema" in ev:
        ev = ev["payload"]
    if not ev:
        return None
    src = ev.get("source") or {}
    table = src.get("table") or src.get("collection")
    op = ev.get("op")
    if not table or op not in ("c", "u", "d", "r"):
        raise ValueError(f"not a Debezium change event: {str(ev)[:200]}")
    return Change(str(table), str(op), ev.get("before"), ev.get("after"), ev.get("ts_ms") or src.get("ts_ms"))


class Child(BaseModel):
    model_config = ConfigDict(extra="forbid")
    table: str
    fk: str                       # child column referencing the root key
    field: str                    # array field in the root document
    key: list[str]                # child primary key


class HydrationSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pipeline: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    mode: Literal["flat", "document", "graph", "vector"]
    keys: dict[str, list[str]]                                  # table -> primary key columns
    root: str | None = None                                     # document mode
    children: list[Child] = Field(default_factory=list)         # document mode
    edges: list[dict[str, str]] = Field(default_factory=list)   # graph: {table, column, to, label}
    embed: dict[str, list[str]] = Field(default_factory=dict)   # vector: table -> text columns
    collection_names: dict[str, str] = Field(default_factory=dict)


def _key(row: dict[str, Any], cols: list[str]) -> str:
    missing = [c for c in cols if row.get(c) is None]
    if missing:
        raise ValueError(f"event has no value for key column(s) {missing}")
    return "#".join(str(row[c]) for c in cols)


class Hydrator:
    def __init__(self, spec: HydrationSpec, writer: TargetWriter, sf: sessionmaker[Session] | None = None,
                 embed: Callable[[list[str]], list[list[float]]] | None = None) -> None:
        if spec.mode == "document" and (sf is None or not spec.root):
            raise ValueError("document mode needs a root table and the state database")
        if spec.mode == "vector" and embed is None:
            raise ValueError("vector mode needs an embedding provider")
        self.spec, self.w, self._sf, self._embed = spec, writer, sf, embed
        self.stats = {"events": 0, "writes": 0, "deletes": 0, "held": 0, "skipped": 0}

    def _coll(self, table: str) -> str:
        return self.spec.collection_names.get(table, table)

    def process(self, ch: Change) -> None:
        self.stats["events"] += 1
        sp = self.spec
        if ch.table not in sp.keys and not any(c.table == ch.table for c in sp.children):
            self.stats["skipped"] += 1
            return
        if sp.mode == "document":
            self._document(ch)
            return
        key = _key(ch.row, sp.keys[ch.table])
        if ch.op == "d":
            self.w.delete(self._coll(ch.table), key, ch.before)
            self.stats["deletes"] += 1
            return
        doc = dict(ch.after or {})
        if sp.mode == "vector" and sp.embed.get(ch.table):
            text = "\n".join(str(doc[c]) for c in sp.embed[ch.table] if doc.get(c))
            if text and self._embed is not None:
                doc["embedding"] = normalise(self._embed([text])[0])
        self.w.upsert(self._coll(ch.table), key, doc)
        self.stats["writes"] += 1
        if sp.mode == "graph":
            edge = getattr(self.w, "edge", None)
            for e in sp.edges:
                if e["table"] == ch.table and doc.get(e["column"]) is not None and edge is not None:
                    edge(e["label"], f"{self._coll(ch.table)}:{key}", f"{self._coll(e['to'])}:{doc[e['column']]}")

    # -- document mode -------------------------------------------------------------------------------
    def _state_id(self, key: str) -> str:
        return hashlib.sha256(f"{self.spec.pipeline}/{self.spec.root}/{key}".encode()).hexdigest()

    def _load(self, s: Session, key: str) -> HydrationDocRow:
        row = s.get(HydrationDocRow, self._state_id(key))
        if row is None:
            row = HydrationDocRow(id=self._state_id(key), pipeline=self.spec.pipeline, collection=self.spec.root or "",
                                  doc_key=key[:512], doc_json="{}", has_root=False, updated_at=datetime.now(UTC))
            s.add(row)
        return row

    def _document(self, ch: Change) -> None:
        sp = self.spec
        if self._sf is None or sp.root is None:
            raise RuntimeError("document mode needs a root table and the state database")
        child = next((c for c in sp.children if c.table == ch.table), None)
        with self._sf() as s, s.begin():
            if child is None:                     # root row
                key = _key(ch.row, sp.keys[sp.root])
                row = self._load(s, key)
                doc = json.loads(row.doc_json)
                if ch.op == "d":
                    s.delete(row)
                    self.w.delete(self._coll(sp.root), key, ch.before)
                    self.stats["deletes"] += 1
                    return
                kids = {c.field: doc.get(c.field, []) for c in sp.children}
                doc = {**(ch.after or {}), **kids}
                row.has_root = True
            else:
                parent_val = ch.row.get(child.fk)
                if parent_val is None:
                    self.stats["skipped"] += 1
                    return
                key = str(parent_val)
                row = self._load(s, key)
                doc = json.loads(row.doc_json)
                # inside one parent the foreign key is constant, so a child is identified by the rest of its key
                ck = [k for k in child.key if k != child.fk] or child.key
                arr = [x for x in doc.get(child.field, []) if _key(x, ck) != _key(ch.row, ck)]
                if ch.op != "d":
                    arr.append({k: v for k, v in (ch.after or {}).items() if k != child.fk})
                    arr.sort(key=lambda x: _key(x, ck))
                doc[child.field] = arr
            row.doc_json = json.dumps(doc, default=str)
            row.updated_at = datetime.now(UTC)
            if not row.has_root:
                self.stats["held"] += 1          # written when the root row arrives
                return
            self.w.upsert(self._coll(sp.root), key, doc)
            self.stats["writes"] += 1


def run_kafka(hydrator: Hydrator, consumer: Any, topics: list[str], max_batch: int = 500,
              poll_timeout: float = 1.0, stop: Callable[[], bool] = lambda: False) -> dict[str, int]:
    """Consume, process and commit only after the writer flushed (at-least-once)."""
    consumer.subscribe(topics)
    while not stop():
        msgs = consumer.consume(num_messages=max_batch, timeout=poll_timeout)
        if not msgs:
            continue
        for m in msgs:
            if m.error():
                raise RuntimeError(f"Kafka error: {m.error()}")
            ch = parse_event(m.value())
            if ch is not None:
                hydrator.process(ch)
        hydrator.w.flush()
        consumer.commit(asynchronous=False)
    return hydrator.stats
