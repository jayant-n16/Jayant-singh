"""Fixed-size VHD footer (Microsoft Virtual Hard Disk Image Format Specification, footer layout).

A *fixed* VHD is the raw disk followed by a 512-byte footer. Azure accepts only fixed VHDs whose
virtual size is a whole number of MiB, so raw disks are zero-padded up to the next MiB first.
"""

from __future__ import annotations

import struct
import time
import uuid

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
