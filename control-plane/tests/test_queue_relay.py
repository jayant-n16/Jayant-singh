"""Message-queue relay. SQS/SNS use moto (real request/response shapes); Service Bus and Pub/Sub use
fakes that receive the real SDK objects (azure-servicebus 7.15.0 ``ServiceBusMessage``,
google-cloud-pubsub 2.43.0 ``PullResponse``). No cloud account is used."""

from __future__ import annotations

import hashlib
import json
from concurrent.futures import Future
from types import SimpleNamespace

import boto3
import pytest
from azure.servicebus import ServiceBusMessage
from google.pubsub_v1 import types as ps
from moto import mock_aws

from oplia_ctl.replication.queues import QueueRelay, QueueSettings


@pytest.fixture(autouse=True)
def _aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")


class SB:
    """Fake Service Bus namespace: senders keep the real ServiceBusMessage objects."""

    def __init__(self, fail=False):
        self.sent: list[ServiceBusMessage] = []
        self.fail = fail
        self.closed = 0
        outer = self

        class Sender:
            def send_messages(self, m):
                assert isinstance(m, ServiceBusMessage)
                if outer.fail:
                    raise ConnectionError("namespace unreachable")
                outer.sent.append(m)

            def close(self):
                outer.closed += 1

        self.sender = Sender()

    def get_queue_sender(self, queue_name):
        assert queue_name == "orders-dr"
        return self.sender


class PubSub:
    def __init__(self, messages):
        self.pending = [ps.ReceivedMessage(ack_id=f"ack-{i}", message=ps.PubsubMessage(
            data=d, attributes=a, message_id=f"ps-{i}")) for i, (d, a) in enumerate(messages)]
        self.acked: list[str] = []

    def pull(self, request):
        assert request["subscription"] == "projects/p/subscriptions/orders"
        batch, self.pending = self.pending[:request["max_messages"]], self.pending[request["max_messages"]:]
        return ps.PullResponse(received_messages=batch)

    def acknowledge(self, request):
        self.acked += request["ack_ids"]


def _relay(cfg, session_factory, clock, clients, events=None):
    r = QueueRelay(QueueSettings.model_validate({"pairs": [cfg]}), session_factory, clients=clients, now=clock,
                   audit=(lambda e, d: events.append((e, d))) if events is not None else None)
    jid = r.queue("t", r.parse({"pair": cfg["name"]}), "ann")["job_id"]
    r.run_pending()
    return r.get(jid)


def test_sqs_to_sns_fifo_and_sqs_with_attributes_and_dedup_ids(session_factory, clock):
    with mock_aws():
        sqs, sns = boto3.client("sqs", region_name="eu-west-1"), boto3.client("sns", region_name="eu-west-1")
        src = sqs.create_queue(QueueName="orders")["QueueUrl"]
        dst = sqs.create_queue(QueueName="orders-dr.fifo", Attributes={"FifoQueue": "true"})["QueueUrl"]
        for i in range(13):
            sqs.send_message(QueueUrl=src, MessageBody=json.dumps({"n": i}), MessageAttributes={
                "tenant": {"DataType": "String", "StringValue": "acme"},
                "blob": {"DataType": "Binary", "BinaryValue": b"\x00"}})
        clients = SimpleNamespace(sqs=lambda region: sqs, sns=lambda region: sns)
        events: list = []
        job = _relay({"name": "orders", "source": {"kind": "sqs", "name": src, "region": "eu-west-1"},
                      "target": {"kind": "sqs", "name": dst, "region": "eu-west-1"}, "max_messages": 100},
                     session_factory, clock, clients, events)
        assert job["status"] == "SUCCEEDED", job["error"]
        assert job["state"]["relayed"] == 13 and job["state"]["dropped_attributes"] == {"blob": 13}
        left = sqs.get_queue_attributes(QueueUrl=src, AttributeNames=["ApproximateNumberOfMessages",
                                                                      "ApproximateNumberOfMessagesNotVisible"])
        assert left["Attributes"] == {"ApproximateNumberOfMessages": "0", "ApproximateNumberOfMessagesNotVisible": "0"}
        got = []
        while True:
            r = sqs.receive_message(QueueUrl=dst, MaxNumberOfMessages=10, MessageAttributeNames=["All"],
                                    AttributeNames=["All"])
            if not r.get("Messages"):
                break
            for m in r["Messages"]:
                got.append(m)
                sqs.delete_message(QueueUrl=dst, ReceiptHandle=m["ReceiptHandle"])
        assert sorted(json.loads(m["Body"])["n"] for m in got) == list(range(13))
        m = got[0]
        a = {k: v["StringValue"] for k, v in m["MessageAttributes"].items()}
        assert a["tenant"] == "acme" and a["oplia-sha256"] == hashlib.sha256(m["Body"].encode()).hexdigest()
        assert a["oplia-source"] == f"sqs:{src}" and m["Attributes"]["MessageGroupId"] == "oplia-dr"
        assert events[-1][1]["relayed"] == 13

        topic = sns.create_topic(Name="orders-dr")["TopicArn"]
        sqs.send_message(QueueUrl=src, MessageBody="to sns")
        job = _relay({"name": "to-sns", "source": {"kind": "sqs", "name": src, "region": "eu-west-1"},
                      "target": {"kind": "sns", "name": topic, "region": "eu-west-1"}}, session_factory, clock, clients)
        assert job["status"] == "SUCCEEDED" and job["state"]["relayed"] == 1


def test_target_failure_leaves_messages_at_the_source(session_factory, clock):
    with mock_aws():
        sqs = boto3.client("sqs", region_name="eu-west-1")
        src = sqs.create_queue(QueueName="orders", Attributes={"VisibilityTimeout": "0"})["QueueUrl"]
        for i in range(3):
            sqs.send_message(QueueUrl=src, MessageBody=f"m{i}")
        sb = SB(fail=True)
        job = _relay({"name": "orders", "source": {"kind": "sqs", "name": src, "region": "eu-west-1"},
                      "target": {"kind": "servicebus", "name": "orders-dr", "namespace": "dr.servicebus.windows.net"},
                      "max_messages": 3},
                     session_factory, clock, SimpleNamespace(sqs=lambda region: sqs, servicebus=lambda ns: sb))
        assert job["status"] == "FAILED" and "namespace unreachable" in job["error"]
        n = sqs.get_queue_attributes(QueueUrl=src, AttributeNames=["ApproximateNumberOfMessages"])
        assert n["Attributes"]["ApproximateNumberOfMessages"] == "3"
        assert sb.closed == 1


def test_pubsub_to_servicebus(session_factory, clock):
    pub = PubSub([(b"\x00\xffbinary", {"k": "v"}), (b"two", {})])
    sb = SB()
    job = _relay({"name": "ps", "source": {"kind": "pubsub", "name": "projects/p/subscriptions/orders"},
                  "target": {"kind": "servicebus", "name": "orders-dr", "namespace": "dr.servicebus.windows.net"}},
                 session_factory, clock, SimpleNamespace(pubsub_subscriber=lambda: pub, servicebus=lambda ns: sb))
    assert job["status"] == "SUCCEEDED" and job["state"]["relayed"] == 2
    assert pub.acked == ["ack-0", "ack-1"]
    first = sb.sent[0]
    assert b"".join(first.body) == b"\x00\xffbinary" and first.message_id == "ps-0"
    props = first.application_properties
    assert props["k"] == "v" and props["oplia-sha256"] == hashlib.sha256(b"\x00\xffbinary").hexdigest()


def test_binary_body_to_sqs_is_not_acknowledged(session_factory, clock):
    pub = PubSub([(b"\xff\xfe", {})])
    with mock_aws():
        sqs = boto3.client("sqs", region_name="eu-west-1")
        dst = sqs.create_queue(QueueName="dr")["QueueUrl"]
        job = _relay({"name": "ps", "source": {"kind": "pubsub", "name": "projects/p/subscriptions/orders"},
                      "target": {"kind": "sqs", "name": dst, "region": "eu-west-1"}},
                     session_factory, clock, SimpleNamespace(pubsub_subscriber=lambda: pub, sqs=lambda r: sqs))
    assert job["status"] == "FAILED" and "UnicodeDecodeError" in job["error"] and pub.acked == []


def test_servicebus_source_to_pubsub(session_factory, clock):
    received = [SimpleNamespace(message_id="sb-1", body=iter([b"hello"]), application_properties={b"a": b"x", b"n": 3})]
    done: list = []
    recv = SimpleNamespace(receive_messages=lambda max_message_count, max_wait_time: [] if done else received.copy(),
                           complete_message=lambda m: done.append(m.message_id), close=lambda: None)
    published: list = []

    def publish(topic, data, **attrs):
        published.append((topic, data, attrs))
        f: Future = Future()
        f.set_result("ps-99")
        return f

    sbc = SimpleNamespace(get_queue_receiver=lambda queue_name: recv)
    job = _relay({"name": "sb",
                  "source": {"kind": "servicebus", "name": "orders", "namespace": "p.servicebus.windows.net"},
                  "target": {"kind": "pubsub", "name": "projects/p/topics/orders-dr"}},
                 session_factory, clock, SimpleNamespace(servicebus=lambda ns: sbc,
                                                         pubsub_publisher=lambda: SimpleNamespace(publish=publish)))
    assert job["status"] == "SUCCEEDED" and done == ["sb-1"]
    topic, data, attrs = published[0]
    assert (topic, data) == ("projects/p/topics/orders-dr", b"hello")
    assert attrs["a"] == "x" and attrs["oplia-source-id"] == "sb-1" and job["state"]["dropped_attributes"] == {"n": 1}


def test_validation():
    with pytest.raises(ValueError, match="SNS cannot be read"):
        QueueSettings.model_validate({"pairs": [{"name": "a", "source": {"kind": "sns", "name": "arn", "region": "r"},
                                                 "target": {"kind": "sqs", "name": "u", "region": "r"}}]})
    with pytest.raises(ValueError, match="projects/P/topics/T"):
        QueueSettings.model_validate({"pairs": [{"name": "a", "source": {"kind": "sqs", "name": "u", "region": "r"},
                                                 "target": {"kind": "pubsub", "name": "projects/p/subscriptions/s"}}]})
    with pytest.raises(ValueError, match=r"servicebus\.windows\.net"):
        QueueSettings.model_validate({"pairs": [{"name": "a", "source": {"kind": "servicebus", "name": "q"},
                                                 "target": {"kind": "sqs", "name": "u", "region": "r"}}]})
