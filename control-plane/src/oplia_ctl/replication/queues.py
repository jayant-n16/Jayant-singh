"""Message-queue replication beyond Kafka: SQS / SNS <-> Azure Service Bus <-> Google Pub/Sub.

A relay moves messages from a source to a target **at least once**: a message is removed from the
source (SQS ``DeleteMessage``, Service Bus ``complete``, Pub/Sub ``acknowledge``) only after the
target has accepted it (SQS/SNS returned a ``MessageId``, Service Bus ``send_messages`` returned,
Pub/Sub publish future resolved with an id). A failure leaves the message at the source, where it
becomes visible again after its lock / visibility timeout. Consumers at the target must therefore
de-duplicate; every relayed message carries:

* ``oplia-source-id``  - the message id at the source (use it as the de-duplication key),
* ``oplia-sha256``     - SHA-256 of the body, checked again before the body is sent,
* ``oplia-source``     - ``<kind>:<name>`` of the source.

Message attributes / application properties / Pub/Sub attributes that are strings are copied;
other attribute types are reported and dropped. Ordering is not preserved across clouds (SQS FIFO
groups, Service Bus sessions and Pub/Sub ordering keys have no common equivalent); FIFO targets get
the source id as their ``MessageDeduplicationId`` and the pair's ``fifo_group``.

SNS is a push service and cannot be read: to replicate an SNS topic, subscribe an SQS queue to it
(raw message delivery) and use that queue as the source. SNS can be a target (``Publish``).

Each ``dr.queue_relay`` job (gated) relays at most ``max_messages`` messages, in batches, then ends;
a scheduler can propose it periodically. ``dr_queue_relay`` audit event with counts.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from oplia_ctl.replication.jobs import JobMachine
from oplia_ctl.replication.models import DrJobRow

ACTION_QUEUE = "dr.queue_relay"
log = logging.getLogger(__name__)
Kind = Literal["sqs", "sns", "servicebus", "pubsub"]


class QueueEnd(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Kind
    # sqs: queue URL; sns: topic ARN; servicebus: queue or topic name, or "topic/subscriptions/sub" as a source;
    # pubsub: projects/P/subscriptions/S as a source, projects/P/topics/T as a target
    name: str
    region: str = ""                 # sqs / sns
    namespace: str = ""              # servicebus fully qualified namespace (x.servicebus.windows.net)
    fifo_group: str = "oplia-dr"     # sqs FIFO / sns FIFO targets
    entity: Literal["queue", "topic"] = "queue"   # servicebus target: send to a queue or a topic

    def model_post_init(self, _ctx: Any) -> None:
        if self.kind in ("sqs", "sns") and not self.region:
            raise ValueError(f"{self.kind} needs region")
        if self.kind == "servicebus" and not self.namespace.endswith(".servicebus.windows.net"):
            raise ValueError("servicebus needs namespace <name>.servicebus.windows.net")

    @property
    def fifo(self) -> bool:
        return self.kind in ("sqs", "sns") and self.name.endswith(".fifo")


class QueuePair(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    source: QueueEnd
    target: QueueEnd
    max_messages: int = Field(default=1000, ge=1, le=100000)
    batch: int = Field(default=10, ge=1, le=10)

    def model_post_init(self, _ctx: Any) -> None:
        if self.source.kind == "sns":
            raise ValueError(f"{self.name}: SNS cannot be read; subscribe an SQS queue to the topic and use "
                             "it as source")
        if self.source.kind == "pubsub" and "/subscriptions/" not in self.source.name:
            raise ValueError(f"{self.name}: a Pub/Sub source must be projects/P/subscriptions/S")
        if self.target.kind == "pubsub" and "/topics/" not in self.target.name:
            raise ValueError(f"{self.name}: a Pub/Sub target must be projects/P/topics/T")


class QueueSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pairs: list[QueuePair] = Field(min_length=1)


class Msg(BaseModel):
    id: str
    body: bytes
    attributes: dict[str, str] = Field(default_factory=dict)
    receipt: Any = None
    dropped_attributes: list[str] = Field(default_factory=list)


class QueueClients:  # pragma: no cover - real SDK wiring
    def sqs(self, region: str) -> Any:
        import boto3
        return boto3.client("sqs", region_name=region)

    def sns(self, region: str) -> Any:
        import boto3
        return boto3.client("sns", region_name=region)

    def servicebus(self, namespace: str) -> Any:
        from azure.identity import DefaultAzureCredential
        from azure.servicebus import ServiceBusClient
        return ServiceBusClient(namespace, DefaultAzureCredential())

    def pubsub_subscriber(self) -> Any:
        from google.cloud import pubsub_v1  # type: ignore[attr-defined]
        return pubsub_v1.SubscriberClient()

    def pubsub_publisher(self) -> Any:
        from google.cloud import pubsub_v1  # type: ignore[attr-defined]
        return pubsub_v1.PublisherClient()


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class QueueRelay(JobMachine):
    kind = "queue_relay"
    action = ACTION_QUEUE
    title = "Message queue relay"
    first_step = "RELAY"

    def __init__(self, cfg: QueueSettings, session_factory: Any, clients: Any = None,
                 audit: Callable[[str, dict[str, Any]], None] | None = None, **kw: Any) -> None:
        super().__init__(session_factory, **kw)
        self.cfg = cfg
        self.pairs = {p.name: p for p in cfg.pairs}
        self._c = clients or QueueClients()
        self._audit = audit
        self._sb: dict[str, Any] = {}

    def fields(self) -> list[dict[str, Any]]:
        return [{"name": "pair", "label": "Queue pair", "kind": "select", "required": True,
                 "options": [{"value": p.name, "label": f"{p.name}: {p.source.kind} -> {p.target.kind}"}
                             for p in self.cfg.pairs]}]

    def summary(self) -> dict[str, Any]:
        return {"pairs": [f"{p.name}: {p.source.kind} {p.source.name} -> {p.target.kind} {p.target.name}"
                          for p in self.cfg.pairs]}

    def parse(self, params: dict[str, Any]) -> dict[str, Any]:
        if str(params.get("pair", "")) not in self.pairs:
            raise ValueError(f"unknown queue pair {params.get('pair')!r}")
        return {"pair": str(params["pair"])}

    def target_of(self, payload: dict[str, Any]) -> str:
        return str(payload["pair"])

    def describe(self, payload: dict[str, Any]) -> str:
        p = self.pairs[self.parse(payload)["pair"]]
        return (f"relay up to {p.max_messages} message(s) from {p.source.kind} {p.source.name} to {p.target.kind} "
                f"{p.target.name}; each is removed from the source only after the target accepted it "
                f"(at-least-once, de-duplicate on oplia-source-id)")

    # ------------------------------------------------------------------ receive
    def _receive(self, e: QueueEnd, n: int) -> list[Msg]:
        if e.kind == "sqs":
            r = self._c.sqs(e.region).receive_message(QueueUrl=e.name, MaxNumberOfMessages=n, WaitTimeSeconds=1,
                                                      MessageAttributeNames=["All"])
            out = []
            for m in r.get("Messages", []):
                attrs, dropped = {}, []
                for k, v in (m.get("MessageAttributes") or {}).items():
                    if v.get("DataType", "").startswith("String"):
                        attrs[k] = v["StringValue"]
                    else:
                        dropped.append(k)
                out.append(Msg(id=m["MessageId"], body=m["Body"].encode(), attributes=attrs,
                               receipt=m["ReceiptHandle"], dropped_attributes=dropped))
            return out
        if e.kind == "servicebus":
            rc = self._sb_receiver(e)
            out = []
            for m in rc.receive_messages(max_message_count=n, max_wait_time=1):
                attrs, dropped = {}, []
                for k, v in (m.application_properties or {}).items():
                    key = k.decode() if isinstance(k, bytes) else str(k)
                    if isinstance(v, (str, bytes)):
                        attrs[key] = v.decode() if isinstance(v, bytes) else v
                    else:
                        dropped.append(key)
                out.append(Msg(id=str(m.message_id), body=b"".join(m.body), attributes=attrs, receipt=m,
                               dropped_attributes=dropped))
            return out
        resp = self._c.pubsub_subscriber().pull(request={"subscription": e.name, "max_messages": n})
        return [Msg(id=r.message.message_id, body=bytes(r.message.data), attributes=dict(r.message.attributes),
                    receipt=r.ack_id) for r in resp.received_messages]

    def _sb_receiver(self, e: QueueEnd) -> Any:
        key = f"r:{e.namespace}/{e.name}"
        if key not in self._sb:
            client = self._c.servicebus(e.namespace)
            if "/subscriptions/" in e.name:
                topic, _, sub = e.name.partition("/subscriptions/")
                self._sb[key] = client.get_subscription_receiver(topic_name=topic, subscription_name=sub)
            else:
                self._sb[key] = client.get_queue_receiver(queue_name=e.name)
        return self._sb[key]

    def _remove(self, e: QueueEnd, m: Msg) -> None:
        if e.kind == "sqs":
            self._c.sqs(e.region).delete_message(QueueUrl=e.name, ReceiptHandle=m.receipt)
        elif e.kind == "servicebus":
            self._sb_receiver(e).complete_message(m.receipt)
        else:
            self._c.pubsub_subscriber().acknowledge(request={"subscription": e.name, "ack_ids": [m.receipt]})

    # ------------------------------------------------------------------ send
    def _send(self, src: QueueEnd, e: QueueEnd, m: Msg) -> str:
        attrs = {**m.attributes, "oplia-source-id": m.id, "oplia-sha256": _sha(m.body),
                 "oplia-source": f"{src.kind}:{src.name}"}
        if e.kind in ("sqs", "sns"):
            body = m.body.decode("utf-8")  # SQS/SNS bodies are text; raises for binary bodies
            mattrs = {k: {"DataType": "String", "StringValue": v} for k, v in attrs.items()}
            extra = {"MessageGroupId": e.fifo_group, "MessageDeduplicationId": _sha(m.id.encode())[:128]} \
                if e.fifo else {}
            if e.kind == "sqs":
                r = self._c.sqs(e.region).send_message(QueueUrl=e.name, MessageBody=body,
                                                       MessageAttributes=mattrs, **extra)
            else:
                r = self._c.sns(e.region).publish(TopicArn=e.name, Message=body, MessageAttributes=mattrs, **extra)
            if not r.get("MessageId"):
                raise RuntimeError("target did not return a MessageId")
            return str(r["MessageId"])
        if e.kind == "servicebus":
            from azure.servicebus import ServiceBusMessage
            key = f"s:{e.namespace}/{e.name}"
            if key not in self._sb:
                sb = self._c.servicebus(e.namespace)
                self._sb[key] = sb.get_topic_sender(topic_name=e.name) if e.entity == "topic" \
                    else sb.get_queue_sender(queue_name=e.name)
            props: dict[str | bytes, Any] = {k: v for k, v in attrs.items()}
            self._sb[key].send_messages(ServiceBusMessage(m.body, message_id=m.id, application_properties=props))
            return m.id
        fut = self._c.pubsub_publisher().publish(e.name, m.body, **attrs)
        return str(fut.result(timeout=60))

    # ------------------------------------------------------------------ step
    def _step_relay(self, job: DrJobRow, payload: dict[str, Any], st: dict[str, Any]) -> str:
        p = self.pairs[payload["pair"]]
        st.setdefault("relayed", 0)
        st.setdefault("failed", [])
        st.setdefault("dropped_attributes", {})
        while st["relayed"] + len(st["failed"]) < p.max_messages:
            n = min(p.batch, p.max_messages - st["relayed"] - len(st["failed"]))
            msgs = self._receive(p.source, n)
            if not msgs:
                break
            for m in msgs:
                try:
                    self._send(p.source, p.target, m)
                except Exception as exc:  # stays at the source; redelivered after its visibility timeout
                    st["failed"].append({"id": m.id, "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
                    continue
                self._remove(p.source, m)
                st["relayed"] += 1
                for a in m.dropped_attributes:
                    st["dropped_attributes"][a] = st["dropped_attributes"].get(a, 0) + 1
            if len(st["failed"]) > 50:
                break
        if st["failed"] and not st["relayed"]:
            raise RuntimeError(f"no message could be sent to the target: {st['failed'][0]['error']}")
        return "DONE"

    def finish(self, job: DrJobRow) -> None:
        for r in list(self._sb.values()):
            try:
                r.close()
            except Exception as exc:  # closing a handle must not hide the job result
                log.warning("closing a Service Bus handle failed: %s", type(exc).__name__)
        self._sb.clear()
        if self._audit is not None:
            pub = self._public(job)
            st = pub["state"]
            self._audit("dr_queue_relay", {"job_id": job.id, "pair": pub["payload"]["pair"], "status": job.status,
                                           "relayed": st.get("relayed"), "failed": len(st.get("failed") or []),
                                           "dropped_attributes": st.get("dropped_attributes"), "error": job.error})
