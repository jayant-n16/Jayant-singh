"""GCP image as a replication source: Cloud Build image export (fake Cloud Build returning the
documented Operation/Build JSON), the export archive built by the real ``tar`` CLI, then AWS (moto S3
+ botocore Stubber for EC2) and Azure (in-memory container) targets. No cloud account is used."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import shutil
import subprocess  # nosec B404 - fixed local test binary
import tarfile

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from oplia_ctl.replication.images import EXPORT_STEP, ImageReplicator
from oplia_ctl.replication.vhd import FOOTER_SIZE, padded_size, parse_footer
from tests.test_replication import CFG, KMS, Clients, _queue

SRC = "projects/prod-proj-1/global/images/web-2026-11"
TAR = shutil.which("tar")


class CloudBuild:
    def __init__(self, statuses):
        self.created, self.statuses = [], list(statuses)

    def create(self, project, body):
        self.created.append((project, body))
        return {"name": f"projects/{project}/operations/op-1",
                "metadata": {"@type": "type.googleapis.com/google.devtools.cloudbuild.v1.BuildOperationMetadata",
                             "build": {"id": "b-123", "status": "QUEUED"}}}

    def get(self, project, build_id):
        assert (project, build_id) == ("prod-proj-1", "b-123")
        s = self.statuses.pop(0)
        return {"id": build_id, "status": s, "statusDetail": "step exited non-zero" if s == "FAILURE" else ""}


def _archive(tmp_path, raw: bytes) -> bytes:
    """disk.raw packed the way the export tool documents it (tar.gz with disk.raw), by the tar CLI."""
    (tmp_path / "disk.raw").write_bytes(raw)
    if TAR is None:
        pytest.skip("tar not installed")
    subprocess.run([TAR, "-C", str(tmp_path), "-czf", str(tmp_path / "x.tar.gz"), "disk.raw"], check=True)  # nosec
    return (tmp_path / "x.tar.gz").read_bytes()


class GcpClients(Clients):
    def __init__(self, cb, **kw):
        super().__init__(**kw)
        self.cb = cb

    def cloud_build(self):
        return self.cb


def _export_done(c, jid, archive):
    c.bucket.data[f"oplia-dr/{jid}/export.tar.gz"] = archive


def test_gcp_image_to_azure(session_factory, tmp_path):
    raw = os.urandom(3 * 1024 * 1024 + 4096)
    cb = CloudBuild(["WORKING", "SUCCESS"])
    c = GcpClients(cb)
    rep = ImageReplicator(CFG, session_factory, c)
    assert "gcp image" in rep.describe({"source_cloud": "gcp", "source_id": SRC, "target_cloud": "azure",
                                         "name": "web-img"})
    jid = _queue(rep, "gcp", SRC, "azure")
    rep.run_pending()
    assert rep.jobs()[0]["step"] == "WAIT_GCP_EXPORT"
    project, body = cb.created[0]
    assert project == "prod-proj-1" and body["steps"][0]["name"] == EXPORT_STEP
    assert f"-source_image={SRC}" in body["steps"][0]["args"]
    assert f"-destination_uri=gs://dr-stage/oplia-dr/{jid}/export.tar.gz" in body["steps"][0]["args"]
    _export_done(c, jid, _archive(tmp_path, raw))
    rep.run_pending()
    job = rep.jobs()[0]
    assert job["status"] == "SUCCEEDED", job["error"]
    assert job["state"]["sha256"] == hashlib.sha256(raw).hexdigest() and job["state"]["export_deleted"] is True
    staged = c.container.data[f"oplia-dr/{jid}/web-img.vhd"]
    size = padded_size(len(raw))
    assert len(staged) == size + FOOTER_SIZE and staged[: len(raw)] == raw
    assert parse_footer(staged[-FOOTER_SIZE:])["current_size"] == size
    assert f"oplia-dr/{jid}/export.tar.gz" not in c.bucket.data


@mock_aws
def test_gcp_image_to_aws(session_factory, tmp_path):
    raw = os.urandom(2 * 1024 * 1024)
    s3 = boto3.client("s3", region_name="ap-south-1")
    s3.create_bucket(Bucket="dr-stage", CreateBucketConfiguration={"LocationConstraint": "ap-south-1"})
    ec2 = boto3.client("ec2", region_name="ap-south-1")
    stub = Stubber(ec2)
    c = GcpClients(CloudBuild(["SUCCESS"]), ec2=ec2, s3=s3)
    rep = ImageReplicator(CFG, session_factory, c)
    jid = _queue(rep, "gcp", SRC, "aws")
    rep.advance(jid)  # GCP_EXPORT
    _export_done(c, jid, _archive(tmp_path, raw))
    key = f"oplia-dr/{jid}/web-img.vhd"
    stub.add_response("import_image", {"ImportTaskId": "import-ami-0abc"}, {
        "Description": "OPLIA DR web-img", "RoleName": "vmimport", "Encrypted": True, "KmsKeyId": KMS,
        "DiskContainers": [{"Description": "web-img", "Format": "VHD",
                            "UserBucket": {"S3Bucket": "dr-stage", "S3Key": key}}]})
    stub.add_response("describe_import_image_tasks", {"ImportImageTasks": [
        {"ImportTaskId": "import-ami-0abc", "Status": "completed", "ImageId": "ami-0fedcba9876543210"}]},
        {"ImportTaskIds": ["import-ami-0abc"]})
    stub.add_response("create_tags", {}, {"Resources": ["ami-0fedcba9876543210"], "Tags": [
        {"Key": "oplia-job", "Value": jid}, {"Key": "oplia-source", "Value": SRC},
        {"Key": "replicated-by", "Value": "oplia"}]})
    stub.activate()
    # the staged VHD is read back before import; capture it on upload
    seen = {}
    orig = s3.upload_fileobj

    def capture(f, bucket, k):
        data = f.read()
        seen[k] = data
        return orig(io.BytesIO(data), bucket, k)

    s3.upload_fileobj = capture
    rep.run_pending()
    job = rep.jobs()[0]
    assert job["status"] == "SUCCEEDED", job["error"]
    assert job["state"]["image_id"] == "ami-0fedcba9876543210"
    vhd = seen[key]
    assert vhd[:-FOOTER_SIZE] == raw and parse_footer(vhd[-FOOTER_SIZE:])["current_size"] == len(raw)
    stub.assert_no_pending_responses()


def test_failed_export_and_bad_archive(session_factory, tmp_path):
    c = GcpClients(CloudBuild(["FAILURE"]))
    rep = ImageReplicator(CFG, session_factory, c)
    _queue(rep, "gcp", SRC, "azure")
    rep.run_pending()
    job = rep.jobs()[0]
    assert job["status"] == "FAILED" and "FAILURE: step exited non-zero" in job["error"]

    c2 = GcpClients(CloudBuild(["SUCCESS"]))
    rep2 = ImageReplicator(CFG, session_factory, c2)
    jid = _queue(rep2, "gcp", SRC, "azure", name="other-img")
    rep2.advance(jid)
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz, tarfile.open(fileobj=gz, mode="w") as tar:
        info = tarfile.TarInfo("evil.sh")
        info.size = 3
        tar.addfile(info, io.BytesIO(b"x=1"))
    c2.bucket.data[f"oplia-dr/{jid}/export.tar.gz"] = buf.getvalue()
    rep2.run_pending()
    job = next(j for j in rep2.jobs() if j["id"] == jid)
    assert job["status"] == "FAILED" and "disk.raw" in job["error"] and c2.container.data == {}


def test_gcp_source_validation(session_factory):
    rep = ImageReplicator(CFG, session_factory, Clients())
    base = {"source_cloud": "gcp", "target_cloud": "aws", "name": "web"}
    with pytest.raises(ValueError, match="projects/<project>/global/images"):
        rep.describe({**base, "source_id": "projects/p/global/images/i"})  # project id too short
    with pytest.raises(ValueError, match="same"):
        rep.describe({**base, "target_cloud": "gcp", "source_id": SRC})
