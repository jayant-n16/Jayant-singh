"""Relay: source change stream -> circuit breaker -> DR destination.

Delivery guarantees:

* a bundle is committed at the source only **after** the destination acknowledged it, so a
  crash never loses data (at-least-once; consumers on the DR side must be idempotent, which
  Debezium/changefeed sinks are by key);
* a bundle that trips the breaker is neither forwarded nor committed. If the relay restarts
  while the breaker is OPEN, the same bundle is read again after the reset and the reset
  decision (``release`` / ``discard``) is applied to it by matching its source positions.

Kafka (confluent-kafka): the consumer uses ``enable.auto.commit=false`` and
``isolation.level=read_committed``; the producer uses ``enable.idempotence=true`` and
``acks=all``.
"""

from __future__ import annotations

import json
import logging
import signal
import threading
from collections.abc import Callable
from typing import Any, Protocol

from sqlalchemy.orm import Session, sessionmaker

from oplia_ctl.db import session_scope
from oplia_ctl.dr.breaker import CircuitBreaker, Sink
from oplia_ctl.dr.decode import Engine, Format, Record
from oplia_ctl.dr.models import DrIncidentRow
from oplia_ctl.dr.rules import RateMonitor

log = logging.getLogger("oplia.dr.relay")


class Source(Protocol):
    def poll_bundle(self, timeout: float) -> list[Record]: ...

    def commit(self, bundle: list[Record]) -> None: ...

    def close(self) -> None: ...


class KafkaSource:
    def __init__(self, *, config: dict[str, Any], topics: list[str], fmt: Format, engine: Engine,
                 sql_dialect: str = "postgres", max_records: int = 500, consumer: Any = None) -> None:
        if consumer is None:
            from confluent_kafka import Consumer

            consumer = Consumer({**config, "enable.auto.commit": False, "isolation.level": "read_committed",
                                 "enable.partition.eof": False})
        self._c = consumer
        self._c.subscribe(topics)
        self._fmt, self._engine, self._dialect, self._max = fmt, engine, sql_dialect, max_records
        self._last: dict[tuple[str, int], int] = {}

    def poll_bundle(self, timeout: float) -> list[Record]:
        from confluent_kafka import KafkaException

        msgs = self._c.consume(num_messages=self._max, timeout=timeout)
        out: list[Record] = []
        for m in msgs:
            if m.error() is not None:
                raise KafkaException(m.error())
            if m.value() is None:
                continue  # tombstone
            out.append(Record(self._fmt, m.value(), self._engine, f"{m.topic()}:{m.partition()}:{m.offset()}",
                              self._dialect))
        return out

    def commit(self, bundle: list[Record]) -> None:
        from confluent_kafka import TopicPartition

        high: dict[tuple[str, int], int] = {}
        for r in bundle:
            topic, part, off = r.position.rsplit(":", 2)
            key = (topic, int(part))
            high[key] = max(high.get(key, -1), int(off))
        if high:
            self._c.commit(offsets=[TopicPartition(t, p, o + 1) for (t, p), o in high.items()], asynchronous=False)

    def close(self) -> None:
        self._c.close()


class KafkaSink:
    def __init__(self, *, config: dict[str, Any], topic: str, flush_timeout: float = 30.0,
                 producer_factory: Callable[[dict[str, Any]], Any] | None = None) -> None:
        cfg = {**config, "enable.idempotence": True, "acks": "all"}
        if producer_factory is None:
            from confluent_kafka import Producer

            producer_factory = Producer
        self._p: Any = producer_factory(cfg)
        self._topic = topic
        self._timeout = flush_timeout

    def send(self, records: list[Record]) -> None:
        if self._p is None:
            raise RuntimeError("destination is severed")
        errors: list[str] = []

        def on_delivery(err: Any, _msg: Any) -> None:
            if err is not None:
                errors.append(str(err))

        for r in records:
            value = r.payload if isinstance(r.payload, bytes) else (
                r.payload.encode() if isinstance(r.payload, str) else json.dumps(r.payload).encode())
            self._p.produce(self._topic, value=value, on_delivery=on_delivery)
        remaining = self._p.flush(self._timeout)
        if remaining or errors:
            raise RuntimeError(f"destination did not acknowledge: {remaining} pending, errors {errors[:3]}")

    def close(self) -> None:
        if self._p is not None:
            self._p.purge(in_queue=True, in_flight=True)
            self._p.flush(0)
            self._p = None


class Relay:
    def __init__(self, *, breaker: CircuitBreaker, source: Source, sink_factory: Callable[[], Sink],
                 session_factory: sessionmaker[Session], rate_factory: Callable[[], RateMonitor] = RateMonitor,
                 poll_timeout: float = 1.0) -> None:
        self._b = breaker
        self._src = source
        self._sink_factory = sink_factory
        self._sink: Sink | None = sink_factory()
        self._sf = session_factory
        self._rate_factory = rate_factory
        self._poll = poll_timeout
        self._held: list[Record] | None = None
        self._pending: tuple[str, set[str]] | None = None  # (decision, positions) after a restart

    def _incident_positions(self, incident_id: str | None) -> list[str]:
        if incident_id is None:
            return []
        with session_scope(self._sf) as s:
            row = s.get(DrIncidentRow, incident_id)
            return list(json.loads(row.positions_json)) if row else []

    def step(self) -> str:
        """One iteration. Returns what happened (for logs and tests)."""
        state, incident_id, _ = self._b.store.state(self._b.stream)
        if state == "OPEN":
            if self._sink is not None:  # opened elsewhere (manual trip): sever here too
                self._sink.close()
                self._sink = None
            return "open"
        decision = self._b.store.consume_decision(self._b.stream)
        if decision is not None:
            # back from an incident: fresh destination connection and a fresh baseline
            self._sink = self._sink_factory()
            self._b.new_rate_monitor(self._rate_factory())
            held, self._held = self._held, None
            if held is not None:
                return self._apply(decision, held)
            # relay restarted while OPEN: the held records will be re-read; match them by position
            self._pending = (decision, set(self._incident_positions(incident_id)))
        if self._sink is None:
            self._sink = self._sink_factory()
        return self._process(self._src.poll_bundle(self._poll))

    def _apply(self, decision: str, records: list[Record]) -> str:
        if decision == "release":
            assert self._sink is not None  # nosec B101 - created by step()
            self._sink.send(records)
        self._src.commit(records)
        return {"release": "released", "discard": "discarded"}[decision]

    def _process(self, bundle: list[Record]) -> str:
        if not bundle:
            return "idle"
        if self._pending is not None:
            decision, positions = self._pending
            reviewed = [r for r in bundle if r.position in positions]
            bundle = [r for r in bundle if r.position not in positions]
            if reviewed:
                self._apply(decision, reviewed)
                positions.difference_update(r.position for r in reviewed)
            if not positions:
                self._pending = None
            if not bundle:
                return {"release": "released", "discard": "discarded"}[decision] if reviewed else "idle"
        result = self._b.inspect(bundle)
        if result.findings:
            self._held = bundle
            self._b.trip(bundle, result.findings, self._sink)
            self._sink = None
            return "tripped"
        assert self._sink is not None  # nosec B101 - ensured by step()
        self._sink.send(bundle)
        self._src.commit(bundle)
        return "forwarded"

    def run_forever(self, open_poll_seconds: float = 5.0, stop: threading.Event | None = None) -> None:
        stop = stop or threading.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, lambda *_: stop.set())
            except ValueError:
                pass
        try:
            while not stop.is_set():
                outcome = self.step()
                if outcome == "open":
                    stop.wait(open_poll_seconds)
        finally:
            self._src.close()
            if self._sink is not None:
                self._sink.close()
