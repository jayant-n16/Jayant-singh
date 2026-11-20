"""VM image / disk replication between AWS, Azure and GCP.

Supported paths (each a persisted state machine advanced by the ``oplia-dr-image-worker``
CronJob; one step per call, so a restart resumes where it stopped):

* AWS AMI   -> Azure image : ExportImage (RAW) to S3 -> stream to a page blob as a *fixed* VHD
  (raw + zero padding to a whole MiB + footer built in vhd.py) -> managed image from the blob.
* AWS AMI   -> GCP image   : ExportImage (RAW) to S3 -> stream into GCS as tar.gz with disk.raw
  -> images.insert(rawDisk) -> wait until READY.
* Azure snapshot/disk -> AWS AMI : read-only SAS (grant access) -> stream the fixed VHD to S3,
  checking its footer -> ImportImage (VHD) -> wait -> tag the AMI. Access is revoked afterwards,
  also on failure.
* Azure snapshot/disk -> GCP image : SAS -> strip the 512-byte footer (validated) -> tar.gz ->
  images.insert.
* Azure *blob* VHD (an unmanaged page blob, ``https://<account>.blob.core.windows.net/<container>/<path>.vhd``)
  -> AWS / GCP : fixed, dynamic or differencing VHDs are read with range requests and expanded to the
  raw disk by vhd.VhdImage (a differencing disk's parent is looked up next to it in the same
  container and must carry the UUID the child records). Only storage accounts listed in
  ``azure_source_accounts`` are accepted. For AWS a fixed VHD footer is written after the raw disk.
* GCP as a source is refused: Compute Engine has no API that returns image bytes (``gcloud
  compute images export`` runs a Cloud Build workflow on a temporary VM). Not implemented.

Checksums: SHA-256 of the raw disk bytes is computed while streaming and the staged copy is read
back and hashed again before the target image is created; a mismatch fails the job. Target
images are encrypted with the target-side key (KMS key / disk encryption set / Cloud KMS key);
key material never moves. Tags are mapped with tags.map_tags (GCP label rules).
"""

from __future__ import annotations

import gzip
import json
import re
import tarfile
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from oplia_ctl.replication.keys import validate_key_ref
from oplia_ctl.replication.models import ImageJobRow
from oplia_ctl.replication.streams import ChainReader, HashingReader, Readable, Zeros, write_disk_tar_gz
from oplia_ctl.replication.tags import map_tags
from oplia_ctl.replication.vhd import FOOTER_SIZE, VhdImage, build_footer, padded_size, parse_footer

ACTION_IMAGE_REPLICATE = "dr.image_replicate"
_AMI = re.compile(r"^ami-[0-9a-f]{8,17}$")
_AZ_SRC = re.compile(r"^/subscriptions/([0-9a-f-]{36})/resourceGroups/([^/]+)/providers/Microsoft\.Compute/"
                     r"(snapshots|disks)/([^/]+)$", re.IGNORECASE)
_AZ_BLOB = re.compile(r"^https://([a-z0-9]{3,24})\.blob\.core\.windows\.net/([a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?)/"
                      r"([A-Za-z0-9._/-]{1,900}\.vhd)$")
_NAME = re.compile(r"^[a-z][a-z0-9-]{0,61}[a-z0-9]$")


class AwsTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")
    region: str
    staging_bucket: str
    role_name: str = "vmimport"
    kms_key: str | None = None


class AzureTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subscription_id: str
    resource_group: str
    location: str
    staging_account_url: str
    staging_container: str
    os_type: Literal["Linux", "Windows"] = "Linux"
    disk_encryption_set_id: str | None = None


class GcpTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project: str
    staging_bucket: str
    kms_key: str | None = None


class ImageSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    aws: AwsTarget | None = None
    azure: AzureTarget | None = None
    gcp: GcpTarget | None = None
    tags: dict[str, str] = Field(default_factory=lambda: {"replicated-by": "oplia"})
    azure_source_accounts: list[str] = Field(default_factory=list)   # storage accounts blob VHDs may come from

    def model_post_init(self, _: Any) -> None:
        if self.aws and self.aws.kms_key:
            validate_key_ref("aws", self.aws.kms_key, "images")
        if self.azure and self.azure.disk_encryption_set_id:
            validate_key_ref("azure", self.azure.disk_encryption_set_id, "images")
        if self.gcp and self.gcp.kms_key:
            validate_key_ref("gcp", self.gcp.kms_key, "images")


class CloudClients:
    """Real SDK clients (default credential chains). Tests pass a fake with the same methods."""

    def ec2(self, region: str) -> Any:
        import boto3
        return boto3.client("ec2", region_name=region)

    def s3(self, region: str) -> Any:
        import boto3
        return boto3.client("s3", region_name=region)

    def azure_compute(self, subscription: str) -> Any:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.compute import ComputeManagementClient
        return ComputeManagementClient(DefaultAzureCredential(), subscription)

    def azure_container(self, account_url: str, container: str) -> Any:
        from azure.identity import DefaultAzureCredential
        from azure.storage.blob import BlobServiceClient
        return BlobServiceClient(account_url, credential=DefaultAzureCredential()).get_container_client(container)

    def gcs_bucket(self, name: str) -> Any:
        from google.cloud import storage  # type: ignore[attr-defined]
        return storage.Client().bucket(name)

    def gcp_images(self) -> Any:
        from google.cloud import compute_v1
        return compute_v1.ImagesClient()

    def http_get(self, url: str) -> tuple[int, Readable, Callable[[], None]]:
        """Stream a (SAS) URL: returns (content length, reader, close). The URL is never logged."""
        import httpx
        client = httpx.Client(timeout=httpx.Timeout(60.0, read=600.0))
        resp = client.send(client.build_request("GET", url), stream=True)
        resp.raise_for_status()
        it = resp.iter_bytes(8 * 1024 * 1024)

        class R:
            buf = b""

            def read(self, n: int = -1, /) -> bytes:
                while n < 0 or len(self.buf) < n:
                    try:
                        self.buf += next(it)
                    except StopIteration:
                        break
                out = self.buf if n < 0 else self.buf[:n]
                self.buf = b"" if n < 0 else self.buf[n:]
                return out

        def close() -> None:
            resp.close()
            client.close()
        return int(resp.headers["content-length"]), R(), close


def validate_request(source_cloud: str, source_id: str, target_cloud: str, name: str,
                     cfg: ImageSettings) -> None:
    if source_cloud == "gcp":
        raise ValueError("GCP as a source is not supported: Compute Engine has no API that returns image bytes")
    if source_cloud == target_cloud:
        raise ValueError("source and target cloud are the same")
    if source_cloud == "aws" and not _AMI.match(source_id):
        raise ValueError("AWS source must be an AMI id (ami-...)")
    if source_cloud == "azure" and not _AZ_SRC.match(source_id):
        m = _AZ_BLOB.match(source_id)
        if m is None:
            raise ValueError("Azure source must be a managed snapshot or disk resource id, or a blob VHD URL")
        if ".." in m.group(3).split("/"):
            raise ValueError("blob path must not contain '..'")
        if m.group(1) not in cfg.azure_source_accounts:
            raise ValueError(f"storage account {m.group(1)!r} is not in azure_source_accounts")
    if source_cloud not in ("aws", "azure") or target_cloud not in ("aws", "azure", "gcp"):
        raise ValueError("unknown cloud")
    if not _NAME.match(name):
        raise ValueError("name must be lowercase letters, digits and hyphens (2-63), starting with a letter")
    if getattr(cfg, target_cloud) is None:
        raise ValueError(f"no {target_cloud} image target configured")
    if source_cloud == "aws" and cfg.aws is None:
        raise ValueError("exporting an AMI needs the aws section (export bucket, vmimport role)")


class ImageReplicator:
    def __init__(self, cfg: ImageSettings, session_factory: sessionmaker[Session],
                 clients: CloudClients | None = None,
                 now: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self.cfg = cfg
        self._sf = session_factory
        self._c = clients or CloudClients()
        self._now = now

    # ------------------------------------------------------------ gate executor
    def describe(self, payload: dict[str, Any]) -> str:
        validate_request(payload["source_cloud"], payload["source_id"], payload["target_cloud"], payload["name"],
                         self.cfg)
        return (f"Queue replication of {payload['source_cloud']} image {payload['source_id']} to "
                f"{payload['target_cloud']} as '{payload['name']}' (worker converts, verifies SHA-256, "
                f"creates an encrypted image)")

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.describe(payload)
        jid = str(uuid.uuid4())
        first = ("EXPORT" if payload["source_cloud"] == "aws"
                 else "TRANSFER" if _AZ_BLOB.match(payload["source_id"]) else "GRANT")
        now = self._now()
        with self._sf() as s, s.begin():
            s.add(ImageJobRow(id=jid, source_cloud=payload["source_cloud"], source_id=payload["source_id"],
                              target_cloud=payload["target_cloud"], name=payload["name"], status="QUEUED",
                              step=first, state_json="{}", created_at=now, updated_at=now,
                              requested_by=str(payload.get("requested_by", ""))))
        return {"job_id": jid, "status": "QUEUED", "step": first}

    # ------------------------------------------------------------------ reads
    def jobs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._sf() as s:
            return [{"id": r.id, "source_cloud": r.source_cloud, "source_id": r.source_id,
                     "target_cloud": r.target_cloud, "name": r.name, "status": r.status, "step": r.step,
                     "state": {k: v for k, v in json.loads(r.state_json).items() if k != "sas"},
                     "error": r.error, "created_at": r.created_at.isoformat(), "updated_at": r.updated_at.isoformat()}
                    for r in s.scalars(select(ImageJobRow).order_by(ImageJobRow.created_at.desc()).limit(limit))]

    # ----------------------------------------------------------------- worker
    def run_pending(self, max_steps: int = 20) -> list[dict[str, Any]]:
        with self._sf() as s:
            ids = [r.id for r in s.scalars(select(ImageJobRow).where(ImageJobRow.status.in_(("QUEUED", "RUNNING"))))]
        out = []
        for jid in ids:
            for _ in range(max_steps):
                before = self._load(jid)
                self.advance(jid)
                after = self._load(jid)
                if after.status in ("SUCCEEDED", "FAILED") or after.step == before.step:
                    break      # finished, or waiting on the cloud: next worker run continues
            r = self._load(jid)
            out.append({"id": jid, "status": r.status, "step": r.step, "error": r.error})
        return out

    def _load(self, jid: str) -> ImageJobRow:
        with self._sf() as s:
            row = s.get(ImageJobRow, jid)
            if row is None:
                raise KeyError(jid)
            s.expunge(row)
            return row

    def _save(self, jid: str, step: str, state: dict[str, Any], status: str = "RUNNING",
              error: str | None = None) -> None:
        with self._sf() as s, s.begin():
            row = s.get(ImageJobRow, jid)
            if row is None:
                raise RuntimeError("row is not available (configuration or source changed)")
            row.step, row.status, row.error = step, status, error
            row.state_json, row.updated_at = json.dumps(state), self._now()

    def advance(self, jid: str) -> None:
        job = self._load(jid)
        state: dict[str, Any] = json.loads(job.state_json)
        try:
            step = getattr(self, f"_step_{job.step.lower()}")(job, state)
            self._save(jid, step, state, "SUCCEEDED" if step == "DONE" else "RUNNING")
        except Exception as exc:
            if job.source_cloud == "azure" and state.get("granted"):
                try:
                    self._revoke(job)
                    state["granted"] = False
                except Exception as rexc:
                    state["revoke_error"] = f"{type(rexc).__name__}: {str(rexc)[:200]}"
            state.pop("sas", None)
            self._save(jid, job.step, state, "FAILED", f"{type(exc).__name__}: {str(exc)[:1000]}")

    # --- AWS source
    def _step_export(self, job: ImageJobRow, st: dict[str, Any]) -> str:
        aws = self.cfg.aws
        if aws is None:
            raise RuntimeError("aws is not available (configuration or source changed)")
        prefix = f"oplia-dr/{job.id}/"
        r = self._c.ec2(aws.region).export_image(
            ImageId=job.source_id, DiskImageFormat="RAW", RoleName=aws.role_name,
            S3ExportLocation={"S3Bucket": aws.staging_bucket, "S3Prefix": prefix},
            Description=f"OPLIA DR replication {job.id}")
        st.update(export_task=r["ExportImageTaskId"], prefix=prefix)
        return "WAIT_EXPORT"

    def _step_wait_export(self, job: ImageJobRow, st: dict[str, Any]) -> str:
        aws = self.cfg.aws
        if aws is None:
            raise RuntimeError("aws is not available (configuration or source changed)")
        t = self._c.ec2(aws.region).describe_export_image_tasks(
            ExportImageTaskIds=[st["export_task"]])["ExportImageTasks"][0]
        status = t.get("Status")
        if status in ("active", "pending"):
            st["export_progress"] = t.get("Progress")
            return "WAIT_EXPORT"
        if status != "completed":
            raise RuntimeError(f"export task {st['export_task']} {status}: {t.get('StatusMessage', '')}")
        st["export_key"] = f"{st['prefix']}{st['export_task']}.raw"
        return "TRANSFER"

    # --- Azure source
    def _az_src(self, job: ImageJobRow) -> tuple[str, str, str, str]:
        m = _AZ_SRC.match(job.source_id)
        if m is None:
            raise RuntimeError("m is not available (configuration or source changed)")
        return m.group(1), m.group(2), m.group(3).lower(), m.group(4)

    def _step_grant(self, job: ImageJobRow, st: dict[str, Any]) -> str:
        from azure.mgmt.compute.models import GrantAccessData

        sub, rg, kind, name = self._az_src(job)
        ops = getattr(self._c.azure_compute(sub), kind)
        res = ops.begin_grant_access(rg, name, GrantAccessData(access="Read", duration_in_seconds=4 * 3600)).result()
        st["granted"] = True
        st["sas"] = res.access_sas          # kept only until TRANSFER finishes; never returned by jobs()
        return "TRANSFER"

    def _revoke(self, job: ImageJobRow) -> None:
        sub, rg, kind, name = self._az_src(job)
        getattr(self._c.azure_compute(sub), kind).begin_revoke_access(rg, name).result()

    # --- transfer (all paths)
    def _source_raw(self, job: ImageJobRow, st: dict[str, Any]) -> tuple[int, Readable, Callable[[], bytes],
                                                                          Callable[[], None]]:
        """(raw size, raw reader, footer-or-empty reader, close)."""
        if job.source_cloud == "aws":
            aws = self.cfg.aws
            if aws is None:
                raise RuntimeError("aws is not available (configuration or source changed)")
            s3 = self._c.s3(aws.region)
            obj = s3.get_object(Bucket=aws.staging_bucket, Key=st["export_key"])
            return int(obj["ContentLength"]), obj["Body"], lambda: b"", lambda: None
        blob = _AZ_BLOB.match(job.source_id)
        if blob is not None:
            img = VhdImage(*self._blob_ranges(blob.group(1), blob.group(2), blob.group(3)))
            st["source_disk_type"] = {2: "fixed", 3: "dynamic", 4: "differencing"}[img.disk_type]
            return img.size, img.reader(), lambda: build_footer(img.size), lambda: None
        total, reader, close = self._c.http_get(st["sas"])
        if total < FOOTER_SIZE + 512:
            close()
            raise RuntimeError(f"source VHD too small ({total} bytes)")
        return total - FOOTER_SIZE, reader, lambda: reader.read(FOOTER_SIZE), close

    def _blob_ranges(self, account: str, container: str, path: str) -> tuple[Any, Any]:
        """RangeSource for the blob, and a parent resolver confined to the same container and folder."""
        client = self._c.azure_container(f"https://{account}.blob.core.windows.net", container)
        folder = path.rsplit("/", 1)[0] + "/" if "/" in path else ""

        class BlobRange:
            def __init__(self, name: str) -> None:
                self.name = name
                self.size = int(client.get_blob_client(name).get_blob_properties().size)

            def read_at(self, offset: int, length: int) -> bytes:
                if length <= 0 or offset >= self.size:
                    return b""
                return bytes(client.download_blob(self.name, offset=offset,
                                                  length=min(length, self.size - offset)).readall())

        def parent(recorded: str) -> BlobRange:
            # relative locator (".\\base.vhd") or absolute (Windows path): only the file name is used;
            # VhdImage then checks the parent's UUID against the one the child recorded
            base = recorded.replace("\\", "/").rsplit("/", 1)[-1]
            if not base or base in (".", "..") or not base.lower().endswith(".vhd"):
                raise ValueError(f"differencing parent {recorded!r} is not a .vhd file name")
            return BlobRange(folder + base)

        return BlobRange(path), parent

    def _step_transfer(self, job: ImageJobRow, st: dict[str, Any]) -> str:
        raw_size, src, footer_of, close = self._source_raw(job, st)
        raw = HashingReader(src, limit=raw_size)
        try:
            if job.target_cloud == "azure":
                self._to_azure_blob(job, st, raw, raw_size)
            elif job.target_cloud == "gcp":
                self._to_gcs(job, st, raw, raw_size)
            else:
                self._to_s3_vhd(job, st, raw, raw_size, footer_of)
            if raw.count != raw_size:
                raise RuntimeError(f"read {raw.count} of {raw_size} raw bytes from the source")
            if job.source_cloud == "azure" and job.target_cloud != "aws" and not _AZ_BLOB.match(job.source_id):
                parse_footer(footer_of())          # the source must be a valid fixed VHD
        finally:
            close()
        st.update(raw_size=raw_size, sha256=raw.hexdigest())
        self._verify_staged(job, st)
        st["verified"] = True
        if job.source_cloud == "azure" and not _AZ_BLOB.match(job.source_id):
            st.pop("sas", None)
            return "REVOKE"
        return "CREATE"

    def _step_revoke(self, job: ImageJobRow, st: dict[str, Any]) -> str:
        self._revoke(job)
        st["granted"] = False
        return "CREATE"

    def _to_azure_blob(self, job: ImageJobRow, st: dict[str, Any], raw: Readable, raw_size: int) -> None:
        az = self.cfg.azure
        if az is None:
            raise RuntimeError("az is not available (configuration or source changed)")
        size = padded_size(raw_size)
        name = f"oplia-dr/{job.id}/{job.name}.vhd"
        data = ChainReader([raw, Zeros(size - raw_size), _Bytes(build_footer(size))])
        self._c.azure_container(az.staging_account_url, az.staging_container).upload_blob(
            name, data, blob_type="PageBlob", length=size + FOOTER_SIZE, overwrite=True)
        st.update(staged=name, vhd_size=size)

    def _to_gcs(self, job: ImageJobRow, st: dict[str, Any], raw: Readable, raw_size: int) -> None:
        g = self.cfg.gcp
        if g is None:
            raise RuntimeError("g is not available (configuration or source changed)")
        name = f"oplia-dr/{job.id}/{job.name}.tar.gz"
        blob = self._c.gcs_bucket(g.staging_bucket).blob(name)
        with blob.open("wb") as fh:
            write_disk_tar_gz(raw, raw_size, fh)
        st["staged"] = name

    def _to_s3_vhd(self, job: ImageJobRow, st: dict[str, Any], raw: Readable, raw_size: int,
                   footer_of: Callable[[], bytes]) -> None:
        aws = self.cfg.aws
        if aws is None:
            raise RuntimeError("aws is not available (configuration or source changed)")
        cap = _FooterCapture(footer_of)
        key = f"oplia-dr/{job.id}/{job.name}.vhd"
        self._c.s3(aws.region).upload_fileobj(ChainReader([raw, cap]), aws.staging_bucket, key)
        st["staged"] = key
        parse_footer(cap.footer)                     # refuse dynamic / corrupt VHDs before importing

    def _verify_staged(self, job: ImageJobRow, st: dict[str, Any]) -> None:
        """Read the staged copy back and compare SHA-256 of the raw disk bytes."""
        size = int(st["raw_size"])
        if job.target_cloud == "azure":
            az = self.cfg.azure
            if az is None:
                raise RuntimeError("az is not available (configuration or source changed)")
            c = self._c.azure_container(az.staging_account_url, az.staging_container)
            back = HashingReader(_Chunks(c.download_blob(st["staged"]).chunks()), limit=size)
            _drain(back)
        elif job.target_cloud == "gcp":
            g = self.cfg.gcp
            if g is None:
                raise RuntimeError("g is not available (configuration or source changed)")
            with self._c.gcs_bucket(g.staging_bucket).blob(st["staged"]).open("rb") as fh, \
                    gzip.GzipFile(fileobj=fh) as gz, tarfile.open(fileobj=gz, mode="r|") as tar:
                member = tar.next()
                if member is None or member.name != "disk.raw" or member.size != size:
                    raise RuntimeError("staged archive does not contain disk.raw of the expected size")
                f = tar.extractfile(member)
                if f is None:
                    raise RuntimeError("f is not available (configuration or source changed)")
                back = HashingReader(f)
                _drain(back)
        else:
            aws = self.cfg.aws
            if aws is None:
                raise RuntimeError("aws is not available (configuration or source changed)")
            body = self._c.s3(aws.region).get_object(Bucket=aws.staging_bucket, Key=st["staged"])["Body"]
            back = HashingReader(body, limit=size)
            _drain(back)
        if back.count != size or back.hexdigest() != st["sha256"]:
            raise RuntimeError("SHA-256 of the staged copy differs from the source stream")

    # --- create target image
    def _tags(self, job: ImageJobRow, cloud: str) -> dict[str, str]:
        base = {**self.cfg.tags, "oplia-source": job.source_id[-120:], "oplia-job": job.id}
        return map_tags(base, cloud).tags  # type: ignore[arg-type]

    def _step_create(self, job: ImageJobRow, st: dict[str, Any]) -> str:
        if job.target_cloud == "azure":
            from azure.mgmt.compute.models import (
                DiskEncryptionSetParameters,
                Image,
                ImageOSDisk,
                ImageProperties,
                ImageStorageProfile,
            )
            az = self.cfg.azure
            if az is None:
                raise RuntimeError("az is not available (configuration or source changed)")
            url = f"{az.staging_account_url.rstrip('/')}/{az.staging_container}/{st['staged']}"
            disk = ImageOSDisk(os_type=az.os_type, os_state="Generalized", blob_uri=url,
                               disk_encryption_set=(DiskEncryptionSetParameters(id=az.disk_encryption_set_id)
                                                    if az.disk_encryption_set_id else None))
            self._c.azure_compute(az.subscription_id).images.begin_create_or_update(
                az.resource_group, job.name,
                Image(location=az.location, tags=self._tags(job, "azure"),
                      properties=ImageProperties(storage_profile=ImageStorageProfile(os_disk=disk))))
            return "WAIT_CREATE"
        if job.target_cloud == "gcp":
            from google.cloud import compute_v1
            g = self.cfg.gcp
            if g is None:
                raise RuntimeError("g is not available (configuration or source changed)")
            img = compute_v1.Image(name=job.name, labels=self._tags(job, "gcp"),
                                   raw_disk=compute_v1.RawDisk(source=f"gs://{g.staging_bucket}/{st['staged']}"))
            if g.kms_key:
                img.image_encryption_key = compute_v1.CustomerEncryptionKey(kms_key_name=g.kms_key)
            self._c.gcp_images().insert(project=g.project, image_resource=img)
            return "WAIT_CREATE"
        aws = self.cfg.aws
        if aws is None:
            raise RuntimeError("aws is not available (configuration or source changed)")
        kw: dict[str, Any] = {}
        if aws.kms_key:
            kw.update(Encrypted=True, KmsKeyId=aws.kms_key)
        r = self._c.ec2(aws.region).import_image(
            Description=f"OPLIA DR {job.name}", RoleName=aws.role_name,
            DiskContainers=[{"Description": job.name, "Format": "VHD",
                             "UserBucket": {"S3Bucket": aws.staging_bucket, "S3Key": st["staged"]}}], **kw)
        st["import_task"] = r["ImportTaskId"]
        return "WAIT_CREATE"

    def _step_wait_create(self, job: ImageJobRow, st: dict[str, Any]) -> str:
        if job.target_cloud == "azure":
            az = self.cfg.azure
            if az is None:
                raise RuntimeError("az is not available (configuration or source changed)")
            img = self._c.azure_compute(az.subscription_id).images.get(az.resource_group, job.name)
            ps = img.properties.provisioning_state if img.properties else None
            if ps == "Succeeded":
                st["image_id"] = img.id
                return "DONE"
            if ps in ("Failed", "Canceled"):
                raise RuntimeError(f"Azure image provisioning {ps}")
            return "WAIT_CREATE"
        if job.target_cloud == "gcp":
            g = self.cfg.gcp
            if g is None:
                raise RuntimeError("g is not available (configuration or source changed)")
            img = self._c.gcp_images().get(project=g.project, image=job.name)
            if img.status == "READY":
                st["image_id"] = img.self_link
                self._c.gcs_bucket(g.staging_bucket).blob(st["staged"]).delete()
                return "DONE"
            if img.status == "FAILED":
                raise RuntimeError("GCP image creation FAILED")
            return "WAIT_CREATE"
        aws = self.cfg.aws
        if aws is None:
            raise RuntimeError("aws is not available (configuration or source changed)")
        ec2 = self._c.ec2(aws.region)
        t = ec2.describe_import_image_tasks(ImportTaskIds=[st["import_task"]])["ImportImageTasks"][0]
        status = t.get("Status")
        if status == "completed":
            ami = t["ImageId"]
            ec2.create_tags(Resources=[ami], Tags=[{"Key": k, "Value": v} for k, v in self._tags(job, "aws").items()])
            self._c.s3(aws.region).delete_object(Bucket=aws.staging_bucket, Key=st["staged"])
            st["image_id"] = ami
            return "DONE"
        if status in ("deleted", "deleting") or t.get("StatusMessage", "").lower().startswith("clienterror"):
            raise RuntimeError(f"import task {status}: {t.get('StatusMessage', '')}")
        st["import_progress"] = t.get("Progress")
        return "WAIT_CREATE"


class _Bytes:
    def __init__(self, b: bytes) -> None:
        self._b = b

    def read(self, n: int = -1, /) -> bytes:
        out = self._b if n < 0 else self._b[:n]
        self._b = b"" if n < 0 else self._b[n:]
        return out


class _FooterCapture:
    """Reads the source VHD footer after the raw bytes and passes it on, keeping a copy."""

    def __init__(self, footer_of: Callable[[], bytes]) -> None:
        self._of = footer_of
        self._rest: bytes | None = None
        self.footer = b""

    def read(self, n: int = -1, /) -> bytes:
        if self._rest is None:
            self.footer = self._of()
            self._rest = self.footer
        out = self._rest if n < 0 else self._rest[:n]
        self._rest = b"" if n < 0 else self._rest[n:]
        return out


class _Chunks:
    def __init__(self, it: Any) -> None:
        self._it = iter(it)
        self._buf = b""

    def read(self, n: int = -1, /) -> bytes:
        while n < 0 or len(self._buf) < n:
            try:
                self._buf += next(self._it)
            except StopIteration:
                break
        out = self._buf if n < 0 else self._buf[:n]
        self._buf = b"" if n < 0 else self._buf[n:]
        return out


def _drain(r: HashingReader) -> None:
    while r.read(8 * 1024 * 1024):
        pass
