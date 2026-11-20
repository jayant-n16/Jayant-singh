"""Fixed-size VHD footer (Microsoft Virtual Hard Disk Image Format Specification, footer layout).

A *fixed* VHD is the raw disk followed by a 512-byte footer. Azure accepts only fixed VHDs whose
virtual size is a whole number of MiB, so raw disks are zero-padded up to the next MiB first.
"""

from __future__ import annotations

import struct
import time
import uuid
from collections.abc import Callable
from typing import Any, Protocol

FOOTER_SIZE = 512
MIB = 1024 * 1024
_EPOCH_2000 = 946684800        # 2000-01-01T00:00:00Z
_FMT = ">8sIIQI4sI4sQQHBBII16sB427s"


def padded_size(raw_size: int) -> int:
    return -(-raw_size // MIB) * MIB


def chs(size: int) -> tuple[int, int, int]:
    """CHS geometry exactly as in the specification's appendix."""
    total = size // 512
    if total > 65535 * 16 * 255:
        total = 65535 * 16 * 255
    if total >= 65535 * 16 * 63:
        spt, heads = 255, 16
        cth = total // spt
    else:
        spt = 17
        cth = total // spt
        heads = max((cth + 1023) // 1024, 4)
        if cth >= heads * 1024 or heads > 16:
            spt, heads = 31, 16
            cth = total // spt
        if cth >= heads * 1024:
            spt, heads = 63, 16
            cth = total // spt
    return cth // heads, heads, spt


def _checksum(footer: bytes) -> int:
    return ~sum(footer) & 0xFFFFFFFF


def build_footer(size: int, now: float | None = None, disk_uuid: bytes | None = None) -> bytes:
    if size % 512:
        raise ValueError("VHD virtual size must be a multiple of 512")
    cyl, heads, spt = chs(size)
    ts = int((now if now is not None else time.time()) - _EPOCH_2000)
    fields = [b"conectix", 2, 0x00010000, 0xFFFFFFFFFFFFFFFF, ts, b"oplc", 0x00010000, b"Wi2k",
              size, size, cyl, heads, spt, 2, 0, disk_uuid or uuid.uuid4().bytes, 0, b"\0" * 427]
    raw = struct.pack(_FMT, *fields)
    fields[14] = _checksum(raw)
    return struct.pack(_FMT, *fields)


def parse_footer(footer: bytes) -> dict[str, int]:
    """Validate a fixed-VHD footer; return its sizes. Raises ValueError for anything else."""
    if len(footer) != FOOTER_SIZE:
        raise ValueError("footer must be 512 bytes")
    f = struct.unpack(_FMT, footer)
    if f[0] != b"conectix":
        raise ValueError("not a VHD (cookie 'conectix' missing)")
    if f[13] != 2:
        raise ValueError(f"only fixed VHDs are supported (disk type {f[13]}; 3 = dynamic, 4 = differencing)")
    zeroed = footer[:64] + b"\0\0\0\0" + footer[68:]
    if _checksum(zeroed) != f[14]:
        raise ValueError("VHD footer checksum mismatch")
    return {"original_size": f[8], "current_size": f[9]}


# --- dynamic (3) and differencing (4) VHDs -------------------------------------------------------
# Layout (same specification): a copy of the footer at offset 0, a 1024-byte dynamic disk header at
# footer.data_offset (cookie "cxsparse"), a block allocation table (BAT) of big-endian uint32 sector
# offsets (0xFFFFFFFF = block not allocated), and blocks made of a sector bitmap (padded to a whole
# sector) followed by block_size bytes of data. A differencing disk takes a sector from itself only
# when that sector's bitmap bit (most significant bit first) is set; otherwise from its parent.

_HDR_FMT = ">8sQQIIII16sI4s512s192s256s"
HEADER_SIZE = 1024
_UNALLOCATED = 0xFFFFFFFF
DISK_FIXED, DISK_DYNAMIC, DISK_DIFFERENCING = 2, 3, 4


class RangeSource(Protocol):
    """Random access to a VHD file (a local file, or HTTP range reads of a blob)."""

    size: int

    def read_at(self, offset: int, length: int) -> bytes: ...


def parse_footer_any(footer: bytes) -> dict[str, Any]:
    """Validate a footer of any supported disk type (fixed, dynamic, differencing)."""
    if len(footer) != FOOTER_SIZE:
        raise ValueError("footer must be 512 bytes")
    f = struct.unpack(_FMT, footer)
    if f[0] != b"conectix":
        raise ValueError("not a VHD (cookie 'conectix' missing)")
    zeroed = footer[:64] + b"\0\0\0\0" + footer[68:]
    if _checksum(zeroed) != f[14]:
        raise ValueError("VHD footer checksum mismatch")
    if f[13] not in (DISK_FIXED, DISK_DYNAMIC, DISK_DIFFERENCING):
        raise ValueError(f"unsupported VHD disk type {f[13]}")
    return {"disk_type": f[13], "data_offset": f[3], "current_size": f[9], "uuid": f[15]}


def parse_header(raw: bytes) -> dict[str, Any]:
    if len(raw) != HEADER_SIZE:
        raise ValueError("dynamic disk header must be 1024 bytes")
    h = struct.unpack(_HDR_FMT, raw)
    if h[0] != b"cxsparse":
        raise ValueError("dynamic disk header cookie 'cxsparse' missing")
    zeroed = raw[:36] + b"\0\0\0\0" + raw[40:]
    if _checksum(zeroed) != h[6]:
        raise ValueError("dynamic disk header checksum mismatch")
    block_size = h[5]
    if block_size == 0 or block_size % 512 or block_size & (block_size - 1):
        raise ValueError(f"invalid block size {block_size}")
    locators = []
    for i in range(8):
        code, space, length, _r, off = struct.unpack(">4sIIIQ", h[11][i * 24:(i + 1) * 24])
        if code != b"\0\0\0\0":
            locators.append({"code": code.decode("latin-1"), "length": length, "offset": off, "space": space})
    return {"table_offset": h[2], "max_entries": h[4], "block_size": block_size, "parent_uuid": h[7],
            "parent_name": h[10].decode("utf-16-be").rstrip("\0"), "locators": locators}


class VhdImage:
    """Read the virtual disk of a fixed, dynamic or differencing VHD as raw bytes.

    ``resolve_parent(name)`` returns a RangeSource for a differencing disk's parent; the parent's
    identity is checked against the UUID recorded in the child's header.
    """

    def __init__(self, src: RangeSource, resolve_parent: Callable[[str], RangeSource] | None = None,
                 _depth: int = 0) -> None:
        if src.size < FOOTER_SIZE + 512:
            raise ValueError(f"VHD too small ({src.size} bytes)")
        if _depth > 16:
            raise ValueError("differencing chain deeper than 16 disks")
        self._src = src
        self.footer = parse_footer_any(src.read_at(src.size - FOOTER_SIZE, FOOTER_SIZE))
        self.size = int(self.footer["current_size"])
        self.disk_type = int(self.footer["disk_type"])
        self.parent: VhdImage | None = None
        if self.disk_type == DISK_FIXED:
            if src.size - FOOTER_SIZE < self.size:
                raise ValueError("fixed VHD is shorter than its virtual size")
            return
        self.header = parse_header(src.read_at(int(self.footer["data_offset"]), HEADER_SIZE))
        self.block_size = int(self.header["block_size"])
        n = int(self.header["max_entries"])
        if n * self.block_size < self.size:
            raise ValueError("block allocation table does not cover the virtual size")
        bat_raw = src.read_at(int(self.header["table_offset"]), 4 * n)
        if len(bat_raw) != 4 * n:
            raise ValueError("block allocation table truncated")
        self.bat = struct.unpack(f">{n}I", bat_raw)
        spb = self.block_size // 512
        bitmap_bytes = (spb + 7) // 8
        self.bitmap_size = (bitmap_bytes + 511) // 512 * 512
        if self.disk_type == DISK_DIFFERENCING:
            if resolve_parent is None:
                raise ValueError("differencing VHD needs its parent disk")
            name = self.parent_name()
            self.parent = VhdImage(resolve_parent(name), resolve_parent, _depth + 1)
            if self.parent.footer["uuid"] != self.header["parent_uuid"]:
                raise ValueError(f"parent {name!r} is not the disk this differencing VHD was made from")
            if self.parent.size != self.size:
                raise ValueError("parent virtual size differs from the child")

    def parent_name(self) -> str:
        """Parent path from the relative (W2ru) locator, else absolute (W2ku), else the header name."""
        by = {loc["code"]: loc for loc in self.header["locators"]}
        for code in ("W2ru", "W2ku"):
            loc = by.get(code)
            if loc and loc["length"]:
                raw = self._src.read_at(int(loc["offset"]), int(loc["length"]))
                return raw.decode("utf-16-le").rstrip("\0")
        if self.header["parent_name"]:
            return str(self.header["parent_name"])
        raise ValueError("differencing VHD records no parent name")

    def read_block(self, index: int) -> bytes:
        """Return the virtual bytes of block ``index`` (dynamic/differencing only)."""
        start = index * self.block_size
        length = min(self.block_size, self.size - start)
        entry = self.bat[index]
        if entry == _UNALLOCATED:
            return self.parent.read_range(start, length) if self.parent else bytes(length)
        base = entry * 512
        if self.parent is None:
            data = self._src.read_at(base + self.bitmap_size, length)
            if len(data) != length:
                raise ValueError(f"block {index} truncated")
            return data
        bitmap = self._src.read_at(base, self.bitmap_size)
        own = self._src.read_at(base + self.bitmap_size, length)
        if len(own) != length or len(bitmap) != self.bitmap_size:
            raise ValueError(f"block {index} truncated")
        inherited = self.parent.read_range(start, length)
        out = bytearray(inherited)
        for s in range(length // 512):
            if bitmap[s >> 3] & (0x80 >> (s & 7)):
                out[s * 512:(s + 1) * 512] = own[s * 512:(s + 1) * 512]
        return bytes(out)

    def read_range(self, offset: int, length: int) -> bytes:
        if self.disk_type == DISK_FIXED:
            return self._src.read_at(offset, length)
        out = bytearray()
        while length > 0:
            idx, within = divmod(offset, self.block_size)
            take = min(length, self.block_size - within)
            out += self.read_block(idx)[within:within + take]
            offset += take
            length -= take
        return bytes(out)

    def reader(self) -> RawDiskReader:
        return RawDiskReader(self)


class RawDiskReader:
    """Sequential reader over the whole virtual disk (feeds HashingReader / ChainReader)."""

    def __init__(self, img: VhdImage) -> None:
        self._img = img
        self._pos = 0
        self._buf = b""
        self._step = img.block_size if img.disk_type != DISK_FIXED else 8 * MIB

    def read(self, n: int = -1, /) -> bytes:
        while (n < 0 or len(self._buf) < n) and self._pos < self._img.size:
            take = min(self._step - self._pos % self._step, self._img.size - self._pos)
            self._buf += self._img.read_range(self._pos, take)
            self._pos += take
        out = self._buf if n < 0 else self._buf[:n]
        self._buf = b"" if n < 0 else self._buf[n:]
        return out


class FileRange:
    """RangeSource over a local file (tests, and a VHD already staged on disk)."""

    def __init__(self, path: str) -> None:
        import os
        self.path = path
        self.size = os.path.getsize(path)

    def read_at(self, offset: int, length: int) -> bytes:
        with open(self.path, "rb") as fh:
            fh.seek(offset)
            return fh.read(length)
