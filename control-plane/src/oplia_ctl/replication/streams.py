"""Streaming helpers: hash while copying, concatenate sources, cap reads, GNU tar.gz for GCP."""

from __future__ import annotations

import gzip
import hashlib
import io
import tarfile
from collections.abc import Iterable
from typing import Any, BinaryIO, Protocol

CHUNK = 8 * 1024 * 1024


class Readable(Protocol):
    def read(self, n: int = -1, /) -> bytes: ...


class HashingReader(io.RawIOBase):
    """Passes bytes through and records SHA-256 and byte count of exactly what was read."""

    def __init__(self, src: Readable, limit: int | None = None) -> None:
        self._src = src
        self._left = limit
        self.sha256 = hashlib.sha256()
        self.count = 0

    def readable(self) -> bool:
        return True

    def read(self, n: int | None = -1, /) -> bytes:
        size = -1 if n is None else n
        if self._left is not None:
            if self._left <= 0:
                return b""
            size = self._left if size < 0 else min(size, self._left)
        data = self._src.read(size)
        if self._left is not None:
            self._left -= len(data)
        self.sha256.update(data)
        self.count += len(data)
        return data

    def readinto(self, b: Any) -> int:
        data = self.read(len(b))
        b[: len(data)] = data
        return len(data)

    def hexdigest(self) -> str:
        return self.sha256.hexdigest()


class ChainReader(io.RawIOBase):
    """Reads several sources one after another (raw disk, zero padding, VHD footer)."""

    def __init__(self, parts: Iterable[Readable]) -> None:
        self._parts = list(parts)

    def readable(self) -> bool:
        return True

    def read(self, n: int | None = -1, /) -> bytes:
        size = -1 if n is None else n
        out = bytearray()
        while self._parts and (size < 0 or len(out) < size):
            chunk = self._parts[0].read(-1 if size < 0 else size - len(out))
            if not chunk:
                self._parts.pop(0)
                continue
            out += chunk
        return bytes(out)

    def readinto(self, b: Any) -> int:
        data = self.read(len(b))
        b[: len(data)] = data
        return len(data)


class Zeros:
    def __init__(self, n: int) -> None:
        self._left = n

    def read(self, n: int = -1, /) -> bytes:
        k = self._left if n < 0 else min(n, self._left)
        self._left -= k
        return b"\0" * k


def copy(src: Readable, dst: BinaryIO, chunk: int = CHUNK) -> int:
    total = 0
    while True:
        data = src.read(chunk)
        if not data:
            return total
        dst.write(data)
        total += len(data)


def write_disk_tar_gz(raw: Readable, size: int, dst: BinaryIO) -> None:
    """Write a gzip-compressed GNU tar containing a single ``disk.raw`` of ``size`` bytes (the
    format Compute Engine requires for images.insert rawDisk.source)."""
    with gzip.GzipFile(fileobj=dst, mode="wb", mtime=0) as gz, \
            tarfile.open(fileobj=gz, mode="w|", format=tarfile.GNU_FORMAT) as tar:
        info = tarfile.TarInfo("disk.raw")
        info.size = size
        info.mode = 0o644
        tar.addfile(info, fileobj=raw)
