"""DR replication: tag/key mapping, VHD and tar.gz formats, object sync, image jobs, CDC pipelines.

Evidence used: moto for S3 (real boto3 calls, SSE-KMS included), botocore Stubber for EC2
(ExportImage / ImportImage requests checked against the EC2 API model), in-memory fakes for Azure
Blob / Compute and GCS / Compute Engine, respx for Kafka Connect, and two independent format
checkers: ``qemu-img`` for the VHDs and the ``tar`` CLI for the GCP disk archives (tests needing
them are skipped if the tool is missing; CI installs both). Nothing talks to a real cloud.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess  # nosec B404 - fixed local tools (qemu-img, tar)
import tarfile
from types import SimpleNamespace

import boto3
import httpx
import pytest
import respx
from botocore.stub import Stubber
from fastapi.testclient import TestClient
from moto import mock_aws

from oplia_ctl.api import create_app
from oplia_ctl.auth import OIDCVerifier
from oplia_ctl.http import ResilientClient
from oplia_ctl.replication.images import ImageReplicator, ImageSettings
from oplia_ctl.replication.keys import validate_key_ref
from oplia_ctl.replication.objects import ObjectPair, ObjectReplicator
from oplia_ctl.replication.pipelines import KafkaConnect, PipelineExecutor
from oplia_ctl.replication.stores import BlobStore, GCSStore, ObjectInfo, S3Store, StoreSpec
from oplia_ctl.replication.streams import write_disk_tar_gz
from oplia_ctl.replication.tags import map_tags
from oplia_ctl.replication.vhd import build_footer, padded_size, parse_footer
from oplia_ctl.secrets import StaticSecretProvider
from tests.test_api import AUD, ISS, KEY, SECRETS, bearer

QEMU = shutil.which("qemu-img")
TAR = shutil.which("tar")
if os.environ.get("CI") and (QEMU is None or TAR is None):  # CI installs both; never skip the format checks there
    raise RuntimeError("qemu-img and tar are required in CI")
KMS = "arn:aws:kms:ap-south-1:123456789012:key/11111111-2222-3333-4444-555555555555"


@pytest.fixture(autouse=True)
def _aws_env(monkeypatch):
    for k, v in {
        "AWS_ACCESS_KEY_ID": "test",
        "AWS_SECRET_ACCESS_KEY": "test",
        "AWS_DEFAULT_REGION": "ap-south-1",
    }.items():
        monkeypatch.setenv(k, v)


# ------------------------------------------------------------------- tag mapping
def test_gcp_label_rules():
    r = map_tags({"CostCenter": "Finance Dept", "1team": "a", "env": "PROD", "x" * 70: "y" * 70, "Env": "dup"}, "gcp")
    assert r.tags["costcenter"] == "finance_dept" and r.tags["k1team"] == "a" and r.tags["env"] == "dup"
    assert len(next(k for k in r.tags if k.startswith("xxx"))) == 63 and "y" * 63 in r.tags.values()
    assert any("already used" in d for d in r.dropped)  # 'env' collides with 'Env' -> 'env'
    assert any("'CostCenter' -> 'costcenter'" in c for c in r.changes)
    many = map_tags({f"k{i}": "v" for i in range(70)}, "gcp")
    assert len(many.tags) == 64 and len(many.dropped) == 6


def test_aws_and_azure_rules():
    a = map_tags({"aws:createdBy": "x", "Name": "web#1", "k" * 200: "v"}, "aws")
    assert (
        "aws:createdBy" not in a.tags
        and a.tags["Name"] == "web_1"
        and len(next(iter(k for k in a.tags if k.startswith("kkk")))) == 128
    )
    z = map_tags({"microsoftX": "1", "a/b?c": "v", "ok": "x" * 300}, "azure")
    assert "microsoftX" not in z.tags and z.tags["a_b_c"] == "v" and len(z.tags["ok"]) == 256
    assert len(map_tags({f"t{i}": "v" for i in range(60)}, "azure").tags) == 50


def test_key_refs():
    assert validate_key_ref("aws", KMS) and validate_key_ref("aws", "alias/dr-key")
    assert validate_key_ref("azure", "drscope01")
    validate_key_ref(
        "azure",
        "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/"
        "Microsoft.Compute/diskEncryptionSets/des1",
        "images",
    )
    assert validate_key_ref("gcp", "projects/my-proj-1/locations/asia-south1/keyRings/dr/cryptoKeys/obj")
    for cloud, bad in (("aws", "not-a-key"), ("azure", "has space"), ("gcp", "projects/x/keys/y")):
        with pytest.raises(ValueError):
            validate_key_ref(cloud, bad)
    with pytest.raises(ValueError, match="disk encryption set"):
        validate_key_ref("azure", "drscope01", "images")


# ------------------------------------------------------------ formats (VHD, tar.gz)
def _vhd(raw: bytes) -> bytes:
    n = padded_size(len(raw))
    return raw + b"\0" * (n - len(raw)) + build_footer(n)


def test_vhd_footer_roundtrip_and_rejections():
    raw = os.urandom(1024 * 1024 + 4096)
    v = _vhd(raw)
    assert parse_footer(v[-512:])["current_size"] == 2 * 1024 * 1024
    bad = bytearray(v[-512:])
    bad[100] ^= 1
    with pytest.raises(ValueError, match="checksum"):
        parse_footer(bytes(bad))
    with pytest.raises(ValueError, match="cookie"):
        parse_footer(b"\0" * 512)


@pytest.mark.skipif(QEMU is None, reason="qemu-img not installed")
def test_vhd_is_read_by_qemu_img_and_qemu_vhds_are_parsed(tmp_path):
    raw = os.urandom(3 * 1024 * 1024 + 777)
    (tmp_path / "ours.vhd").write_bytes(_vhd(raw))
    info = json.loads(
        subprocess.run(
            [QEMU, "info", "--output=json", "-f", "vpc", str(tmp_path / "ours.vhd")],
            capture_output=True,
            check=True,
            text=True,
        ).stdout
    )
    assert info["format"] == "vpc"
    subprocess.run(
        [
            QEMU,
            "convert",
            "-f",
            "vpc",
            "-O",
            "raw",
            str(tmp_path / "ours.vhd"),
            str(tmp_path / "back.raw"),
        ],
        check=True,
    )
    assert (tmp_path / "back.raw").read_bytes()[: len(raw)] == raw
    subprocess.run(
        [
            QEMU,
            "create",
            "-q",
            "-f",
            "vpc",
            "-o",
            "subformat=fixed,force_size=on",
            str(tmp_path / "q.vhd"),
            "4M",
        ],
        check=True,
    )
    assert parse_footer((tmp_path / "q.vhd").read_bytes()[-512:])["current_size"] == 4 * 1024 * 1024
    subprocess.run(
        [QEMU, "create", "-q", "-f", "vpc", "-o", "subformat=dynamic", str(tmp_path / "d.vhd"), "4M"],
        check=True,
    )
    with pytest.raises(ValueError, match="only fixed"):
        parse_footer((tmp_path / "d.vhd").read_bytes()[-512:])


@pytest.mark.skipif(TAR is None, reason="tar not installed")
def test_disk_tar_gz_is_read_by_gnu_tar(tmp_path):
    raw = os.urandom(2 * 1024 * 1024 + 3)
    with open(tmp_path / "d.tar.gz", "wb") as fh:
        write_disk_tar_gz(io.BytesIO(raw), len(raw), fh)
    out = subprocess.run([TAR, "-tvzf", str(tmp_path / "d.tar.gz")], capture_output=True, check=True, text=True).stdout
    assert "disk.raw" in out and str(len(raw)) in out
    subprocess.run([TAR, "-xzf", str(tmp_path / "d.tar.gz"), "-C", str(tmp_path)], check=True)
    assert (tmp_path / "disk.raw").read_bytes() == raw


# ------------------------------------------------------------------ fakes
class FakeStore:
    """In-memory Store (stands in for Blob/GCS in replicator tests)."""

    def __init__(self, spec: StoreSpec, corrupt: bool = False) -> None:
        self.spec, self.objs, self.puts, self.corrupt = spec, {}, [], corrupt

    def list(self, prefix):
        for k in sorted(self.objs):
            if k.startswith(prefix):
                yield ObjectInfo(k, len(self.objs[k]), f"e{hash(self.objs[k]) & 0xFFFF}")

    def open(self, key):
        return io.BytesIO(self.objs[key])

    def put(self, key, data, size, key_ref, tags):
        b = data.read()
        self.objs[key] = (b[:-1] + b"X") if self.corrupt and b else b
        self.puts.append({"key": key, "key_ref": key_ref, "tags": tags})

    def head(self, key):
        return (
            None if key not in self.objs else ObjectInfo(key, len(self.objs[key]), f"e{hash(self.objs[key]) & 0xFFFF}")
        )

    def delete(self, key):
        self.objs.pop(key, None)


S3_SRC = StoreSpec(cloud="aws", bucket="prod-data", region="ap-south-1")
AZ_DST = StoreSpec(cloud="azure", bucket="dr", account_url="https://dr.blob.core.windows.net")


def _rep(session_factory, stores, pairs=None):
    pairs = pairs or [
        ObjectPair(
            name="data", source=S3_SRC, target=AZ_DST, prefix="p/", target_key="drscope01", tags={"Owner": "SRE"}
        )
    ]
    return ObjectReplicator(pairs, session_factory, lambda spec: stores[(spec.cloud, spec.bucket)])


# ------------------------------------------------------------- object replication
@mock_aws
def test_object_sync_incremental_with_checksums(session_factory):
    s3 = boto3.client("s3", region_name="ap-south-1")
    s3.create_bucket(Bucket="prod-data", CreateBucketConfiguration={"LocationConstraint": "ap-south-1"})
    for k, v in {"p/a": b"alpha", "p/b": os.urandom(300_000), "other/x": b"ignored"}.items():
        s3.put_object(Bucket="prod-data", Key=k, Body=v)
    dst = FakeStore(AZ_DST)
    rep = _rep(session_factory, {("aws", "prod-data"): S3Store(S3_SRC, s3), ("azure", "dr"): dst})
    plan = rep.plan("data")
    assert [o["key"] for o in plan["objects"]] == ["p/a", "p/b"] and plan["tags"]["tags"] == {"Owner": "SRE"}
    res = rep({"pair": "data", "objects": plan["objects"]})
    assert res["status"] == "OK" and res["copied"] == 2
    assert dst.objs["p/a"] == b"alpha" and dst.puts[0]["key_ref"] == "drscope01"
    assert rep.plan("data")["objects"] == []  # incremental: nothing new
    s3.put_object(Bucket="prod-data", Key="p/a", Body=b"alpha-2")
    plan2 = rep.plan("data")
    assert [o["key"] for o in plan2["objects"]] == ["p/a"]
    s3.put_object(Bucket="prod-data", Key="p/a", Body=b"alpha-3")  # changes after the plan
    res2 = rep({"pair": "data", "objects": plan2["objects"]})
    assert res2["status"] == "PARTIAL" and res2["skipped"][0]["key"] == "p/a"
    s3.delete_object(Bucket="prod-data", Key="p/b")
    assert rep.plan("data")["missing_at_source"] == ["p/b"]  # reported, never deleted
    assert "p/b" in dst.objs
    st = rep.status()[0]
    assert st["replicated_objects"] == 2 and st["last_run"]["status"] == "PARTIAL"


def _del_rep(session_factory, src, dst, **kw):
    pair = ObjectPair(name="data", source=S3_SRC, target=AZ_DST, prefix="p/", replicate_deletions=True, **kw)
    return ObjectReplicator([pair], session_factory, lambda spec: {"aws": src, "azure": dst}[spec.cloud])


def _seed(rep, src, n):
    for i in range(n):
        src.objs[f"p/{i:03}"] = f"v{i}".encode()
    rep({"pair": "data", "objects": rep.plan("data")["objects"]})


def test_deletions_are_off_by_default(session_factory):
    src, dst = FakeStore(S3_SRC), FakeStore(AZ_DST)
    rep = _rep(session_factory, {("aws", "prod-data"): src, ("azure", "dr"): dst})
    src.objs["p/a"] = b"x"
    rep({"pair": "data", "objects": rep.plan("data")["objects"]})
    del src.objs["p/a"]
    assert rep.plan("data")["missing_at_source"] == ["p/a"]
    with pytest.raises(PermissionError, match="replicate_deletions is false"):
        rep.plan_deletions("data")
    with pytest.raises(PermissionError, match="replicate_deletions is false"):
        rep.deletion_executor()({"pair": "data", "keys": ["p/a"]})
    assert dst.objs["p/a"] == b"x"


def test_deletion_replication_rechecks_source_and_updates_manifest(session_factory):
    src, dst = FakeStore(S3_SRC), FakeStore(AZ_DST)
    rep = _del_rep(session_factory, src, dst, max_delete_fraction=0.5)
    _seed(rep, src, 10)
    del src.objs["p/001"], src.objs["p/002"], src.objs["p/003"]
    plan = rep.plan_deletions("data")
    assert plan["keys"] == ["p/001", "p/002", "p/003"] and plan["replicated_objects"] == 10
    src.objs["p/003"] = b"back"                       # re-created after the plan
    ex = rep.deletion_executor()
    assert "Delete 3 object(s)" in ex.describe({"pair": "data", "keys": plan["keys"]})
    res = ex({"pair": "data", "keys": plan["keys"]})
    assert res["status"] == "PARTIAL" and res["deleted"] == ["p/001", "p/002"]
    assert res["skipped"] == [{"key": "p/003", "reason": "exists at the source again"}]
    assert "p/001" not in dst.objs and "p/003" in dst.objs and "p/004" in dst.objs
    assert rep.plan_deletions("data")["keys"] == []   # manifest rows removed for deleted keys
    assert rep.status()[0]["last_run"]["summary"]["kind"] == "delete"


def test_mass_deletion_is_refused(session_factory):
    src, dst = FakeStore(S3_SRC), FakeStore(AZ_DST)
    rep = _del_rep(session_factory, src, dst)             # default limit 10%
    _seed(rep, src, 20)
    for i in range(5):
        del src.objs[f"p/{i:03}"]
    keys = rep.plan_deletions("data")["keys"]
    with pytest.raises(PermissionError, match="refusing to delete 5 of 20"):
        rep.deletion_executor().describe({"pair": "data", "keys": keys})
    with pytest.raises(PermissionError, match="refusing"):
        rep.delete({"pair": "data", "keys": keys})
    assert len(dst.objs) == 20


def test_deletion_proposal_goes_through_the_gate(session_factory):
    from oplia_ctl.replication.objects import ACTION_OBJECT_DELETE
    from oplia_ctl.safety.gate import FourEyesViolationError, SafetyGate

    src, dst = FakeStore(S3_SRC), FakeStore(AZ_DST)
    rep = _del_rep(session_factory, src, dst)
    _seed(rep, src, 20)
    del src.objs["p/007"]
    gate = SafetyGate(session_factory, dry_run=False)
    prop = gate.propose(action_type=ACTION_OBJECT_DELETE, target="data",
                        payload={"pair": "data", "keys": rep.plan_deletions("data")["keys"]},
                        reason="source cleanup", requested_by="olga")
    with pytest.raises(FourEyesViolationError):
        gate.approve(prop.id, "olga")
    gate.approve(prop.id, "ivan")
    done = gate.execute(prop.id, rep.deletion_executor(), "olga")
    assert done.status.value == "EXECUTED" and "p/007" not in dst.objs and len(dst.objs) == 19


@mock_aws
def test_s3_store_delete(session_factory):
    s3 = boto3.client("s3", region_name="ap-south-1")
    s3.create_bucket(Bucket="prod-data", CreateBucketConfiguration={"LocationConstraint": "ap-south-1"})
    s3.put_object(Bucket="prod-data", Key="p/a", Body=b"x")
    st = S3Store(S3_SRC, s3)
    st.delete("p/a")
    assert st.head("p/a") is None


@mock_aws
def test_object_sync_detects_corrupted_target(session_factory):
    s3 = boto3.client("s3", region_name="ap-south-1")
    s3.create_bucket(Bucket="prod-data", CreateBucketConfiguration={"LocationConstraint": "ap-south-1"})
    s3.put_object(Bucket="prod-data", Key="p/a", Body=b"payload")
    rep = _rep(session_factory, {("aws", "prod-data"): S3Store(S3_SRC, s3), ("azure", "dr"): FakeStore(AZ_DST, True)})
    with pytest.raises(RuntimeError, match="SHA-256"):
        rep({"pair": "data", "objects": rep.plan("data")["objects"]})
    assert rep.plan("data")["objects"][0]["key"] == "p/a"  # not in the manifest


@mock_aws
def test_s3_target_reencrypts_with_target_kms_key_and_tags(session_factory):
    s3 = boto3.client("s3", region_name="ap-south-1")
    kms = boto3.client("kms", region_name="ap-south-1")
    key_arn = kms.create_key()["KeyMetadata"]["Arn"]
    for b in ("dr-copy",):
        s3.create_bucket(Bucket=b, CreateBucketConfiguration={"LocationConstraint": "ap-south-1"})
    src = FakeStore(StoreSpec(cloud="gcp", bucket="gsrc"))
    src.objs["p/a"] = b"from-gcs"
    tgt = StoreSpec(cloud="aws", bucket="dr-copy", region="ap-south-1")
    pair = ObjectPair(
        name="g2a", source=src.spec, target=tgt, prefix="p/", target_key=key_arn, tags={"Data Class": "Internal"}
    )
    rep = _rep(session_factory, {("gcp", "gsrc"): src, ("aws", "dr-copy"): S3Store(tgt, s3)}, [pair])
    assert rep({"pair": "g2a", "objects": rep.plan("g2a")["objects"]})["status"] == "OK"
    h = s3.head_object(Bucket="dr-copy", Key="p/a")
    assert h["ServerSideEncryption"] == "aws:kms" and h["SSEKMSKeyId"] == key_arn
    tags = s3.get_object_tagging(Bucket="dr-copy", Key="p/a")["TagSet"]
    assert tags == [{"Key": "Data Class", "Value": "Internal"}]


def test_pair_validation():
    with pytest.raises(ValueError, match="same bucket"):
        ObjectPair(name="x", source=S3_SRC, target=S3_SRC)
    with pytest.raises(ValueError, match="encryption scope"):
        ObjectPair(name="x", source=S3_SRC, target=AZ_DST, target_key="arn:aws:kms:x")


def test_blob_and_gcs_adapters_pass_encryption_and_tags():
    calls = {}

    class Container:
        def upload_blob(self, name, data, **kw):
            calls["blob"] = (name, data.read(), kw)

    BlobStore(AZ_DST, Container()).put("k", io.BytesIO(b"abc"), 3, "drscope01", {"owner": "sre"})
    assert calls["blob"] == (
        "k",
        b"abc",
        {"overwrite": True, "length": 3, "encryption_scope": "drscope01", "tags": {"owner": "sre"}},
    )

    class Blob:
        def __init__(self, name, kms_key_name=None):
            self.name, self.kms, self.metadata = name, kms_key_name, None

        def upload_from_file(self, data, size, rewind):
            calls["gcs"] = (self.name, self.kms, self.metadata, data.read(), size, rewind)

    class Bucket:
        def blob(self, name, kms_key_name=None):
            return Blob(name, kms_key_name)

    gk = "projects/my-proj-1/locations/asia-south1/keyRings/dr/cryptoKeys/obj"
    GCSStore(StoreSpec(cloud="gcp", bucket="b"), Bucket()).put("k", io.BytesIO(b"xyz"), 3, gk, {"owner": "sre"})
    assert calls["gcs"] == ("k", gk, {"owner": "sre"}, b"xyz", 3, False)


# ---------------------------------------------------------------- CDC pipelines
KC = "http://connect.example.test:8083"


@respx.mock
def test_kafka_connect_status_and_gated_restart():
    respx.get(f"{KC}/connectors").mock(
        side_effect=lambda req: httpx.Response(
            200 if req.headers.get("authorization", "").startswith("Basic ") else 401,
            json={
                "pg-orders": {
                    "status": {
                        "connector": {"state": "RUNNING", "worker_id": "w1:8083"},
                        "tasks": [{"id": 0, "state": "FAILED", "trace": "org.postgresql.util.PSQLException"}],
                    },
                    "info": {
                        "type": "source",
                        "config": {"connector.class": "io.debezium.connector.postgresql.PostgresConnector"},
                    },
                }
            },
        )
    )
    restart = respx.post(f"{KC}/connectors/pg-orders/restart").mock(return_value=httpx.Response(202))
    respx.get(f"{KC}/connectors/pg-orders/status").mock(
        return_value=httpx.Response(
            200, json={"connector": {"state": "RUNNING"}, "tasks": [{"id": 0, "state": "RUNNING"}]}
        )
    )
    kc = KafkaConnect(KC, ResilientClient(max_retries=0), StaticSecretProvider({"kc": "oplia:pw"}), "kc")
    c = kc.connectors()[0]
    assert c["failed_tasks"] == 1 and c["class"].endswith("PostgresConnector") and c["tasks"][0]["trace"]
    out = PipelineExecutor(kc)({"connector": "pg-orders", "action": "restart"})
    assert out["state_after"] == "RUNNING" and out["tasks_after"] == ["RUNNING"]
    assert restart.calls[0].request.url.params["onlyFailed"] == "true"
    with pytest.raises(ValueError):
        PipelineExecutor(kc).describe({"connector": "pg-orders", "action": "delete"})


# ------------------------------------------------------------------ image jobs
class MemBlob:
    def __init__(self, bucket, name):
        self.b, self.name = bucket, name

    def open(self, mode):
        if mode == "rb":
            return io.BytesIO(self.b.data[self.name])
        bucket, name = self.b, self.name

        class W(io.BytesIO):
            def close(self):
                bucket.data[name] = self.getvalue()
                super().close()

        return W()

    def delete(self):
        del self.b.data[self.name]


class MemBucket:
    def __init__(self):
        self.data = {}

    def blob(self, name):
        return MemBlob(self, name)


class MemContainer:
    def __init__(self):
        self.data, self.kw = {}, {}

    def upload_blob(self, name, data, **kw):
        self.data[name], self.kw[name] = data.read(), kw

    def download_blob(self, name):
        d = self.data[name]
        return SimpleNamespace(chunks=lambda: (d[i : i + 1_000_000] for i in range(0, len(d), 1_000_000)))


class RangeContainer:
    """Source container for blob VHDs: properties + ranged downloads, like azure-storage-blob."""

    def __init__(self):
        self.data, self.reads = {}, []

    def get_blob_client(self, name):
        return SimpleNamespace(get_blob_properties=lambda: SimpleNamespace(size=len(self.data[name])))

    def download_blob(self, name, offset=None, length=None):
        self.reads.append((name, offset, length))
        d = self.data[name][offset : offset + length]
        return SimpleNamespace(readall=lambda: d)


class Clients:
    def __init__(self, ec2=None, s3=None, vhd=b""):
        self._ec2, self._s3, self.vhd = ec2, s3, vhd
        self.container, self.bucket = MemContainer(), MemBucket()
        self.source_container = RangeContainer()
        self.created, self.revoked, self.granted, self.inserted = [], [], [], []
        self.gcp_status = ["PENDING", "READY"]
        outer = self

        class Ops:
            def begin_grant_access(self, rg, name, data):
                outer.granted.append((rg, name, data.access, data.duration_in_seconds))
                return SimpleNamespace(result=lambda: SimpleNamespace(access_sas="https://sas.example/d?sig=SECRET"))

            def begin_revoke_access(self, rg, name):
                outer.revoked.append((rg, name))
                return SimpleNamespace(result=lambda: None)

        class Images:
            def begin_create_or_update(self, rg, name, img):
                outer.created.append((rg, name, img))

            def get(self, rg, name):
                return SimpleNamespace(id=f"/images/{name}", properties=SimpleNamespace(provisioning_state="Succeeded"))

        self.compute = SimpleNamespace(snapshots=Ops(), disks=Ops(), images=Images())

        class GImages:
            def insert(self, project, image_resource):
                outer.inserted.append((project, image_resource))

            def get(self, project, image):
                return SimpleNamespace(
                    status=outer.gcp_status.pop(0), self_link=f"projects/{project}/global/images/{image}"
                )

        self.gimages = GImages()

    def ec2(self, region):
        return self._ec2

    def s3(self, region):
        return self._s3

    def azure_compute(self, sub):
        return self.compute

    def azure_container(self, url, container):
        if url == "https://srcacct.blob.core.windows.net":
            assert container == "vhds"
            return self.source_container
        return self.container

    def gcs_bucket(self, name):
        return self.bucket

    def gcp_images(self):
        return self.gimages

    def http_get(self, url):
        assert "sig=SECRET" in url
        return len(self.vhd), io.BytesIO(self.vhd), lambda: None


AZ_SNAP = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/prod/providers/"
    "Microsoft.Compute/snapshots/web-os"
)
CFG = ImageSettings.model_validate(
    {
        "aws": {"region": "ap-south-1", "staging_bucket": "dr-stage", "kms_key": KMS},
        "azure": {
            "subscription_id": "00000000-0000-0000-0000-000000000000",
            "resource_group": "dr",
            "location": "centralindia",
            "staging_account_url": "https://drstage.blob.core.windows.net",
            "staging_container": "images",
            "disk_encryption_set_id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/dr/"
            "providers/Microsoft.Compute/diskEncryptionSets/des1",
        },
        "gcp": {
            "project": "dr-proj-1",
            "staging_bucket": "dr-stage",
            "kms_key": "projects/dr-proj-1/locations/asia-south1/keyRings/dr/cryptoKeys/img",
        },
    }
)


def _s3_with_export(raw, job_id_holder):
    s3 = boto3.client("s3", region_name="ap-south-1")
    s3.create_bucket(Bucket="dr-stage", CreateBucketConfiguration={"LocationConstraint": "ap-south-1"})
    return s3


def _queue(rep, src_cloud, src_id, tgt, name="web-img"):
    return rep(
        {"source_cloud": src_cloud, "source_id": src_id, "target_cloud": tgt, "name": name, "requested_by": "olga"}
    )["job_id"]


def _ec2_export_stub(job_id, raw_key_holder, s3, raw):
    ec2 = boto3.client("ec2", region_name="ap-south-1")
    stub = Stubber(ec2)
    stub.add_response(
        "export_image",
        {"ExportImageTaskId": "export-ami-0123456789abcdef0"},
        {
            "ImageId": "ami-0123456789abcdef0",
            "DiskImageFormat": "RAW",
            "RoleName": "vmimport",
            "S3ExportLocation": {"S3Bucket": "dr-stage", "S3Prefix": f"oplia-dr/{job_id}/"},
            "Description": f"OPLIA DR replication {job_id}",
        },
    )
    stub.add_response(
        "describe_export_image_tasks",
        {
            "ExportImageTasks": [
                {"ExportImageTaskId": "export-ami-0123456789abcdef0", "Status": "active", "Progress": "40"}
            ]
        },
        {"ExportImageTaskIds": ["export-ami-0123456789abcdef0"]},
    )
    stub.add_response(
        "describe_export_image_tasks",
        {"ExportImageTasks": [{"ExportImageTaskId": "export-ami-0123456789abcdef0", "Status": "completed"}]},
        {"ExportImageTaskIds": ["export-ami-0123456789abcdef0"]},
    )
    s3.put_object(Bucket="dr-stage", Key=f"oplia-dr/{job_id}/export-ami-0123456789abcdef0.raw", Body=raw)
    stub.activate()
    return ec2, stub


@mock_aws
def test_aws_ami_to_gcp_image(session_factory):
    raw = os.urandom(2 * 1024 * 1024 + 11)
    s3 = _s3_with_export(raw, None)
    c = Clients(s3=s3)
    rep = ImageReplicator(CFG, session_factory, c)
    jid = _queue(rep, "aws", "ami-0123456789abcdef0", "gcp")
    c._ec2, stub = _ec2_export_stub(jid, None, s3, raw)
    rep.run_pending()  # EXPORT, then WAIT_EXPORT sees "active" -> stops
    assert rep.jobs()[0]["step"] == "WAIT_EXPORT" and rep.jobs()[0]["state"]["export_progress"] == "40"
    rep.run_pending()  # completed -> TRANSFER -> CREATE -> WAIT (PENDING)
    job = rep.jobs()[0]
    assert job["step"] == "WAIT_CREATE" and job["state"]["verified"] is True
    project, img = c.inserted[0]
    assert project == "dr-proj-1" and img.raw_disk.source == f"gs://dr-stage/{job['state']['staged']}"
    assert img.image_encryption_key.kms_key_name.endswith("cryptoKeys/img")
    assert img.labels["replicated-by"] == "oplia" and all(k == k.lower() for k in img.labels)
    with gzip.open(io.BytesIO(c.bucket.data[job["state"]["staged"]])) as gz, tarfile.open(fileobj=gz) as t:
        assert t.extractfile("disk.raw").read() == raw
    rep.run_pending()
    job = rep.jobs()[0]
    assert job["status"] == "SUCCEEDED" and job["state"]["image_id"].endswith("/images/web-img")
    assert c.bucket.data == {}  # staging archive removed after READY
    stub.assert_no_pending_responses()


@mock_aws
def test_aws_ami_to_azure_fixed_vhd(session_factory, tmp_path):
    raw = os.urandom(1024 * 1024 + 4097)
    s3 = _s3_with_export(raw, None)
    c = Clients(s3=s3)
    rep = ImageReplicator(CFG, session_factory, c)
    jid = _queue(rep, "aws", "ami-0123456789abcdef0", "azure")
    c._ec2, _ = _ec2_export_stub(jid, None, s3, raw)
    for _ in range(3):
        rep.run_pending()
    job = rep.jobs()[0]
    assert job["status"] == "SUCCEEDED", job["error"]
    vhd = c.container.data[job["state"]["staged"]]
    assert len(vhd) == 2 * 1024 * 1024 + 512 and vhd[: len(raw)] == raw
    assert parse_footer(vhd[-512:])["current_size"] == 2 * 1024 * 1024
    assert c.container.kw[job["state"]["staged"]]["blob_type"] == "PageBlob"
    rg, name, img = c.created[0]
    disk = img.properties.storage_profile.os_disk
    assert (rg, name) == ("dr", "web-img") and disk.blob_uri.endswith(job["state"]["staged"])
    assert disk.disk_encryption_set.id.endswith("/des1") and disk.os_state == "Generalized"
    if QEMU:
        (tmp_path / "x.vhd").write_bytes(vhd)
        subprocess.run(
            [
                QEMU,
                "convert",
                "-f",
                "vpc",
                "-O",
                "raw",
                str(tmp_path / "x.vhd"),
                str(tmp_path / "x.raw"),
            ],
            check=True,
        )
        assert (tmp_path / "x.raw").read_bytes()[: len(raw)] == raw


@mock_aws
def test_azure_snapshot_to_aws_ami(session_factory):
    raw = os.urandom(1024 * 1024)
    s3 = _s3_with_export(raw, None)
    ec2 = boto3.client("ec2", region_name="ap-south-1")
    stub = Stubber(ec2)
    c = Clients(ec2=ec2, s3=s3, vhd=_vhd(raw))
    rep = ImageReplicator(CFG, session_factory, c)
    jid = _queue(rep, "azure", AZ_SNAP, "aws")
    key = f"oplia-dr/{jid}/web-img.vhd"
    stub.add_response(
        "import_image",
        {"ImportTaskId": "import-ami-0abc"},
        {
            "Description": "OPLIA DR web-img",
            "RoleName": "vmimport",
            "Encrypted": True,
            "KmsKeyId": KMS,
            "DiskContainers": [
                {"Description": "web-img", "Format": "VHD", "UserBucket": {"S3Bucket": "dr-stage", "S3Key": key}}
            ],
        },
    )
    stub.add_response(
        "describe_import_image_tasks",
        {
            "ImportImageTasks": [
                {"ImportTaskId": "import-ami-0abc", "Status": "completed", "ImageId": "ami-0fedcba9876543210"}
            ]
        },
        {"ImportTaskIds": ["import-ami-0abc"]},
    )
    stub.add_response(
        "create_tags",
        {},
        {
            "Resources": ["ami-0fedcba9876543210"],
            "Tags": [
                {"Key": "oplia-job", "Value": jid},
                {"Key": "oplia-source", "Value": AZ_SNAP},
                {"Key": "replicated-by", "Value": "oplia"},
            ],
        },
    )
    stub.activate()
    rep.run_pending()
    job = rep.jobs()[0]
    assert job["status"] == "SUCCEEDED", job["error"]
    assert job["state"]["image_id"] == "ami-0fedcba9876543210" and "sas" not in job["state"]
    assert c.granted == [("prod", "web-os", "Read", 14400)] and c.revoked == [("prod", "web-os")]
    with pytest.raises(s3.exceptions.ClientError):  # staged VHD removed after import
        s3.head_object(Bucket="dr-stage", Key=key)
    stub.assert_no_pending_responses()


@mock_aws
def test_azure_dynamic_vhd_is_refused_and_access_revoked(session_factory, tmp_path):
    if QEMU is None:
        pytest.skip("qemu-img not installed")
    subprocess.run(
        [QEMU, "create", "-q", "-f", "vpc", "-o", "subformat=dynamic", str(tmp_path / "d.vhd"), "4M"],
        check=True,
    )
    c = Clients(vhd=(tmp_path / "d.vhd").read_bytes())
    rep = ImageReplicator(CFG, session_factory, c)
    _queue(rep, "azure", AZ_SNAP, "gcp")
    rep.run_pending()
    job = rep.jobs()[0]
    assert job["status"] == "FAILED" and "only fixed VHDs" in job["error"]
    assert c.revoked == [("prod", "web-os")] and c.inserted == []


@mock_aws
def test_azure_snapshot_to_gcp_strips_footer(session_factory):
    raw = os.urandom(1024 * 1024)
    c = Clients(vhd=_vhd(raw))
    c.gcp_status = ["READY"]
    rep = ImageReplicator(CFG, session_factory, c)
    _queue(rep, "azure", AZ_SNAP, "gcp")
    staged = {}
    orig_delete = MemBlob.delete

    def keep(self):
        staged["data"] = self.b.data[self.name]
        orig_delete(self)

    MemBlob.delete = keep
    try:
        rep.run_pending()
    finally:
        MemBlob.delete = orig_delete
    assert rep.jobs()[0]["status"] == "SUCCEEDED", rep.jobs()[0]["error"]
    with gzip.open(io.BytesIO(staged["data"])) as gz, tarfile.open(fileobj=gz) as t:
        assert t.extractfile("disk.raw").read() == raw  # no footer, no padding


BLOB_CFG = CFG.model_copy(update={"azure_source_accounts": ["srcacct"]})


@mock_aws
def test_azure_blob_dynamic_vhd_to_gcp_matches_qemu(session_factory, tmp_path):
    if QEMU is None:
        raise RuntimeError("qemu-img is required (apt-get install qemu-utils)")
    raw = bytearray(5 * 1024 * 1024)
    raw[100:4100] = os.urandom(4000)
    raw[3 * 1024 * 1024 : 3 * 1024 * 1024 + 700] = os.urandom(700)
    (tmp_path / "s.raw").write_bytes(raw)
    subprocess.run([QEMU, "convert", "-f", "raw", "-O", "vpc", "-o", "subformat=dynamic",
                    str(tmp_path / "s.raw"), str(tmp_path / "d.vhd")], check=True)
    subprocess.run([QEMU, "convert", "-f", "vpc", "-O", "raw", str(tmp_path / "d.vhd"), str(tmp_path / "q.raw")],
                   check=True)
    expected = (tmp_path / "q.raw").read_bytes()
    c = Clients()
    c.source_container.data["vms/web.vhd"] = (tmp_path / "d.vhd").read_bytes()
    c.gcp_status = ["READY"]
    rep = ImageReplicator(BLOB_CFG, session_factory, c)
    _queue(rep, "azure", "https://srcacct.blob.core.windows.net/vhds/vms/web.vhd", "gcp")
    staged = {}
    orig_delete = MemBlob.delete

    def keep(self):
        staged["data"] = self.b.data[self.name]
        orig_delete(self)

    MemBlob.delete = keep
    try:
        rep.run_pending()
    finally:
        MemBlob.delete = orig_delete
    job = rep.jobs()[0]
    assert job["status"] == "SUCCEEDED", job["error"]
    assert job["state"]["source_disk_type"] == "dynamic" and c.granted == [] and c.revoked == []
    assert job["state"]["sha256"] == hashlib.sha256(expected).hexdigest()
    with gzip.open(io.BytesIO(staged["data"])) as gz, tarfile.open(fileobj=gz) as t:
        assert t.extractfile("disk.raw").read() == expected


def test_azure_blob_source_must_be_allowlisted(session_factory):
    rep = ImageReplicator(BLOB_CFG, session_factory, Clients())
    base = {"source_cloud": "azure", "target_cloud": "gcp", "name": "web"}
    with pytest.raises(ValueError, match="not in azure_source_accounts"):
        rep.describe({**base, "source_id": "https://evil.blob.core.windows.net/vhds/a.vhd"})
    with pytest.raises(ValueError, match=r"must not contain '\.\.'"):
        rep.describe({**base, "source_id": "https://srcacct.blob.core.windows.net/vhds/x/../a.vhd"})
    rep.describe({**base, "source_id": "https://srcacct.blob.core.windows.net/vhds/a.vhd"})


def test_image_request_validation(session_factory):
    rep = ImageReplicator(CFG, session_factory, Clients())
    for args, msg in (
        (("gcp", "projects/p/global/images/i", "aws", "web"), "GCP as a source"),
        (("aws", "i-123", "gcp", "web"), "AMI id"),
        (("azure", "/bad", "aws", "web"), "snapshot or disk"),
        (("aws", "ami-0123456789abcdef0", "aws", "web"), "same"),
        (("aws", "ami-0123456789abcdef0", "gcp", "Web_Img"), "lowercase"),
    ):
        with pytest.raises(ValueError, match=msg):
            rep.describe(dict(zip(("source_cloud", "source_id", "target_cloud", "name"), args, strict=True)))


# ------------------------------------------------------------------------ API
def _app(gate, **kw):
    return TestClient(
        create_app(
            gate=gate,
            secrets=SECRETS,
            verifier=OIDCVerifier(issuer=ISS, audience=AUD, jwks_url="", key_resolver=lambda _t: KEY.public_key()),
            executors={},
            webhook_secret_name="webhook_hmac_secret",
            webhook_max_skew_seconds=300,
            allowed_blueprints=["control-tower-standard"],
            approver_role="oplia-approver",
            operator_role="oplia-operator",
            **kw,
        )
    )


@mock_aws
def test_api_replication(gate, session_factory):
    s3 = boto3.client("s3", region_name="ap-south-1")
    s3.create_bucket(Bucket="prod-data", CreateBucketConfiguration={"LocationConstraint": "ap-south-1"})
    s3.put_object(Bucket="prod-data", Key="p/a", Body=b"1")
    rep = _rep(session_factory, {("aws", "prod-data"): S3Store(S3_SRC, s3), ("azure", "dr"): FakeStore(AZ_DST)})
    img = ImageReplicator(CFG, session_factory, Clients())
    api = _app(gate, object_replicator=rep, image_replicator=img)
    op = bearer("olga", "oplia-operator")
    assert api.get("/me", headers=op).json()["features"]["replication"] is True
    st = api.get("/dr/replication", headers=op).json()
    assert st["pipelines"]["configured"] is False and st["object_pairs"][0]["pair"] == "data"
    assert st["image_targets"] == {"aws": True, "azure": True, "gcp": True}
    r = api.post("/dr/replication/objects/data/plan", headers=op, json={"reason": "nightly DR sync"})
    assert r.status_code == 201 and r.json()["action_type"] == "dr.object_sync"
    assert api.post("/dr/replication/objects/nope/plan", headers=op, json={"reason": "nightly"}).status_code == 404
    r = api.post(
        "/dr/replication/images",
        headers=op,
        json={"source_cloud": "gcp", "source_id": "x" * 5, "target_cloud": "aws", "name": "web", "reason": "DR image"},
    )
    assert r.status_code == 422 and "GCP as a source" in r.json()["detail"]
    r = api.post(
        "/dr/replication/images",
        headers=op,
        json={
            "source_cloud": "aws",
            "source_id": "ami-0123456789abcdef0",
            "target_cloud": "gcp",
            "name": "web-img",
            "reason": "DR image",
        },
    )
    assert r.status_code == 201 and r.json()["action_type"] == "dr.image_replicate"
    r = api.post("/dr/replication/tags/preview", headers=op, json={"tags": {"Owner Team": "SRE"}, "target": "gcp"})
    assert r.json()["tags"] == {"owner_team": "sre"}
    assert api.post("/dr/replication/pipelines/x/restart", headers=op, json={"reason": "restart it"}).status_code == 503


def test_api_replication_not_configured(gate):
    api = _app(gate)
    assert api.get("/dr/replication", headers=bearer("olga", "oplia-operator")).status_code == 503


def test_api_deletion_proposals(gate, session_factory):
    src, dst = FakeStore(S3_SRC), FakeStore(AZ_DST)
    off = _rep(session_factory, {("aws", "prod-data"): src, ("azure", "dr"): dst})
    op = bearer("olga", "oplia-operator")
    api = _app(gate, object_replicator=off)
    r = api.post("/dr/replication/objects/data/deletions", headers=op, json={"reason": "cleanup"})
    assert r.status_code == 403 and "replicate_deletions is false" in r.json()["detail"]

    on = _del_rep(session_factory, src, dst)
    api = _app(gate, object_replicator=on)
    assert api.post("/dr/replication/objects/data/deletions", headers=op, json={"reason": "cleanup"}).status_code == 409
    _seed(on, src, 20)
    del src.objs["p/004"]
    r = api.post("/dr/replication/objects/data/deletions", headers=op, json={"reason": "cleanup"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["action_type"] == "dr.object_delete" and body["payload"]["keys"] == ["p/004"]
    for i in range(5, 12):
        del src.objs[f"p/{i:03}"]
    r = api.post("/dr/replication/objects/data/deletions", headers=op, json={"reason": "cleanup"})
    assert r.status_code == 409 and "refusing to delete 8 of 20" in r.json()["detail"]
    assert api.get("/dr/replication", headers=op).json()["object_pairs"][0]["replicate_deletions"] is True
