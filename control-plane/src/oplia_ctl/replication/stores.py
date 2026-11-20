"""Object store adapters for S3, Azure Blob and GCS. Credentials come from each SDK's default chain."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict

from oplia_ctl.replication.streams import Readable


class StoreSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cloud: Literal["aws", "azure", "gcp"]
    bucket: str                         # S3 bucket / Blob container / GCS bucket
    region: str = ""                    # aws
    account_url: str = ""               # azure, e.g. https://acct.blob.core.windows.net


@dataclass(frozen=True)
class ObjectInfo:
    key: str
    size: int
    etag: str


class Store(Protocol):
    spec: StoreSpec

    def list(self, prefix: str) -> Iterator[ObjectInfo]: ...
    def open(self, key: str) -> Readable: ...
    def put(self, key: str, data: Readable, size: int, key_ref: str | None, tags: dict[str, str]) -> None: ...
    def head(self, key: str) -> ObjectInfo | None: ...
    def delete(self, key: str) -> None: ...


class S3Store:
    def __init__(self, spec: StoreSpec, client: Any = None) -> None:
        import boto3

        self.spec = spec
        self._s3 = client or boto3.client("s3", region_name=spec.region or None)

    def list(self, prefix: str) -> Iterator[ObjectInfo]:
        for page in self._s3.get_paginator("list_objects_v2").paginate(Bucket=self.spec.bucket, Prefix=prefix):
            for o in page.get("Contents", []):
                yield ObjectInfo(o["Key"], int(o["Size"]), str(o["ETag"]).strip('"'))

    def open(self, key: str) -> Readable:
        body: Readable = self._s3.get_object(Bucket=self.spec.bucket, Key=key)["Body"]
        return body

    def put(self, key: str, data: Readable, size: int, key_ref: str | None, tags: dict[str, str]) -> None:
        extra: dict[str, Any] = {}
        if key_ref:
            extra.update(ServerSideEncryption="aws:kms", SSEKMSKeyId=key_ref)
        if tags:
            from urllib.parse import urlencode

            extra["Tagging"] = urlencode(tags)
        self._s3.upload_fileobj(data, self.spec.bucket, key, ExtraArgs=extra or None)

    def head(self, key: str) -> ObjectInfo | None:
        try:
            h = self._s3.head_object(Bucket=self.spec.bucket, Key=key)
        except self._s3.exceptions.ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound"):
                return None
            raise
        return ObjectInfo(key, int(h["ContentLength"]), str(h["ETag"]).strip('"'))

    def delete(self, key: str) -> None:
        self._s3.delete_object(Bucket=self.spec.bucket, Key=key)


class BlobStore:
    def __init__(self, spec: StoreSpec, container: Any = None) -> None:
        self.spec = spec
        if container is None:
            from azure.identity import DefaultAzureCredential
            from azure.storage.blob import BlobServiceClient

            container = BlobServiceClient(spec.account_url, credential=DefaultAzureCredential()) \
                .get_container_client(spec.bucket)
        self._c = container

    def list(self, prefix: str) -> Iterator[ObjectInfo]:
        for b in self._c.list_blobs(name_starts_with=prefix or None):
            yield ObjectInfo(b.name, int(b.size), str(b.etag).strip('"'))

    def open(self, key: str) -> Readable:
        return _ChunkReader(self._c.download_blob(key).chunks())

    def put(self, key: str, data: Readable, size: int, key_ref: str | None, tags: dict[str, str]) -> None:
        # Blob metadata keys must be C# identifiers; mapped tags are written as blob index tags.
        kw: dict[str, Any] = {"overwrite": True, "length": size}
        if key_ref:
            kw["encryption_scope"] = key_ref
        if tags:
            kw["tags"] = tags
        self._c.upload_blob(key, data, **kw)

    def head(self, key: str) -> ObjectInfo | None:
        from azure.core.exceptions import ResourceNotFoundError

        try:
            p = self._c.get_blob_client(key).get_blob_properties()
        except ResourceNotFoundError:
            return None
        return ObjectInfo(key, int(p.size), str(p.etag).strip('"'))

    def delete(self, key: str) -> None:
        self._c.delete_blob(key)


class GCSStore:
    def __init__(self, spec: StoreSpec, bucket: Any = None) -> None:
        self.spec = spec
        if bucket is None:
            from google.cloud import storage  # type: ignore[attr-defined]

            bucket = storage.Client().bucket(spec.bucket)
        self._b = bucket

    def list(self, prefix: str) -> Iterator[ObjectInfo]:
        for b in self._b.list_blobs(prefix=prefix or None):
            yield ObjectInfo(b.name, int(b.size), str(b.etag))

    def open(self, key: str) -> Readable:
        r: Readable = self._b.blob(key).open("rb")
        return r

    def put(self, key: str, data: Readable, size: int, key_ref: str | None, tags: dict[str, str]) -> None:
        blob = self._b.blob(key, kms_key_name=key_ref) if key_ref else self._b.blob(key)
        if tags:
            blob.metadata = tags
        blob.upload_from_file(data, size=size, rewind=False)

    def head(self, key: str) -> ObjectInfo | None:
        b = self._b.get_blob(key)
        return None if b is None else ObjectInfo(key, int(b.size), str(b.etag))

    def delete(self, key: str) -> None:
        self._b.blob(key).delete()


class _ChunkReader:
    def __init__(self, chunks: Iterator[bytes]) -> None:
        self._it = iter(chunks)
        self._buf = b""

    def read(self, n: int = -1, /) -> bytes:
        while n < 0 or len(self._buf) < n:
            try:
                self._buf += next(self._it)
            except StopIteration:
                break
        if n < 0:
            out, self._buf = self._buf, b""
        else:
            out, self._buf = self._buf[:n], self._buf[n:]
        return out


def build_store(spec: StoreSpec) -> Store:
    if spec.cloud == "aws":
        return S3Store(spec)
    if spec.cloud == "azure":
        return BlobStore(spec)
    return GCSStore(spec)
