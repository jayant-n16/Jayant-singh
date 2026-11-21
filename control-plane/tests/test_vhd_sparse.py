"""Dynamic and differencing VHDs.

Independent checks: qemu-img (writes dynamic VHDs, converts them to raw) and libyal's libvhdi
(``pyvhdi``, reads differencing chains). Our reader must produce byte-identical raw disks.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
import uuid
from pathlib import Path

import pytest

from oplia_ctl.replication import vhd
from oplia_ctl.replication.vhd import FileRange, VhdImage

QEMU = shutil.which("qemu-img")
BLOCK = 2 * 1024 * 1024


def _qemu() -> str:
    if QEMU is None:  # CI installs qemu-utils; error rather than silently skip
        raise RuntimeError("qemu-img is required for these tests (apt-get install qemu-utils)")
    return QEMU


def _raw(path: Path, size: int, seed: int) -> bytes:
    rnd = __import__("random").Random(seed)
    b = bytearray(size)
    for off in range(0, size, 9 * 4096):
        b[off:off + 2048] = rnd.randbytes(2048)
    path.write_bytes(b)
    return bytes(b)


def _qemu_dynamic(tmp: Path, size: int, seed: int) -> tuple[Path, bytes]:
    raw = tmp / f"src{seed}.raw"
    _raw(raw, size, seed)
    out = tmp / f"dyn{seed}.vhd"
    subprocess.run([_qemu(), "convert", "-f", "raw", "-O", "vpc", "-o", "subformat=dynamic", str(raw), str(out)],
                   check=True)
    back = tmp / f"back{seed}.raw"
    subprocess.run([_qemu(), "convert", "-f", "vpc", "-O", "raw", str(out), str(back)], check=True)
    return out, back.read_bytes()


def _footer(size: int, disk_type: int, data_offset: int, disk_uuid: bytes) -> bytes:
    cyl, heads, spt = vhd.chs(size)
    fields = [b"conectix", 2, 0x00010000, data_offset, 0, b"oplc", 0x00010000, b"Wi2k",
              size, size, cyl, heads, spt, disk_type, 0, disk_uuid, 0, b"\0" * 427]
    raw = struct.pack(vhd._FMT, *fields)
    fields[14] = vhd._checksum(raw)
    return struct.pack(vhd._FMT, *fields)


def _differencing(path: Path, parent: VhdImage, parent_name: str, writes: dict[int, bytes]) -> None:
    """Write a differencing VHD by the specification: sectors in ``writes`` (sector -> 512 bytes)."""
    size = parent.size
    n = -(-size // BLOCK)
    name_utf16le = parent_name.encode("utf-16-le")
    loc_off = 512 + 1024
    bat_off = loc_off + 512
    bat_bytes = -(-(4 * n) // 512) * 512
    blocks: dict[int, tuple[bytearray, bytearray]] = {}
    for sector, data in writes.items():
        b, s = divmod(sector, BLOCK // 512)
        bm, dat = blocks.setdefault(b, (bytearray(512), bytearray(BLOCK)))
        bm[s >> 3] |= 0x80 >> (s & 7)
        dat[s * 512:(s + 1) * 512] = data
    bat = [0xFFFFFFFF] * n
    body = bytearray()
    pos = bat_off + bat_bytes
    for b in sorted(blocks):
        bat[b] = pos // 512
        bm, dat = blocks[b]
        body += bm + dat
        pos += 512 + BLOCK
    locators = struct.pack(">4sIIIQ", b"W2ru", 512, len(name_utf16le), 0, loc_off) + b"\0" * 24 * 7
    hdr = [b"cxsparse", 0xFFFFFFFFFFFFFFFF, bat_off, 0x00010000, n, BLOCK, 0, parent.footer["uuid"], 0,
           b"\0" * 4, parent_name.encode("utf-16-be").ljust(512, b"\0"), locators, b"\0" * 256]
    h = struct.pack(vhd._HDR_FMT, *hdr)
    hdr[6] = vhd._checksum(h)
    h = struct.pack(vhd._HDR_FMT, *hdr)
    foot = _footer(size, 4, 512, uuid.uuid4().bytes)
    bat_raw = struct.pack(f">{n}I", *bat).ljust(bat_bytes, b"\0")
    path.write_bytes(foot + h + name_utf16le.ljust(512, b"\0") + bat_raw + body + foot)


def test_dynamic_vhd_matches_qemu(tmp_path: Path) -> None:
    out, expected = _qemu_dynamic(tmp_path, 5 * 1024 * 1024 + 1536, 1)
    img = VhdImage(FileRange(str(out)))
    assert img.disk_type == vhd.DISK_DYNAMIC
    assert img.reader().read() == expected


def test_dynamic_vhd_sparse_blocks_read_as_zeros(tmp_path: Path) -> None:
    raw = tmp_path / "zero.raw"
    raw.write_bytes(b"\0" * (6 * 1024 * 1024))
    out = tmp_path / "zero.vhd"
    subprocess.run([_qemu(), "convert", "-f", "raw", "-O", "vpc", "-o", "subformat=dynamic", str(raw), str(out)],
                   check=True)
    img = VhdImage(FileRange(str(out)))
    assert all(e == 0xFFFFFFFF for e in img.bat)          # qemu allocated nothing
    assert img.reader().read() == b"\0" * img.size


def test_fixed_vhd_still_reads(tmp_path: Path) -> None:
    raw = _raw(tmp_path / "f.raw", 3 * 1024 * 1024, 4)
    out = tmp_path / "f.vhd"
    subprocess.run([_qemu(), "convert", "-f", "raw", "-O", "vpc", "-o", "subformat=fixed,force_size=on",
                    str(tmp_path / "f.raw"), str(out)], check=True)
    img = VhdImage(FileRange(str(out)))
    assert img.disk_type == vhd.DISK_FIXED
    assert img.reader().read()[: len(raw)] == raw


def test_differencing_chain_matches_libvhdi(tmp_path: Path) -> None:
    import pyvhdi
    parent_path, parent_raw = _qemu_dynamic(tmp_path, 6 * 1024 * 1024, 2)
    parent = VhdImage(FileRange(str(parent_path)))
    writes = {8: b"\x11" * 512, 7: b"\x22" * 512, 4096: b"\x33" * 512, 4097: b"\x44" * 512,
              (parent.size // 512) - 1: b"\x55" * 512}
    child_path = tmp_path / "child.vhd"
    _differencing(child_path, parent, parent_path.name, writes)

    def resolve(name: str) -> FileRange:
        assert name == parent_path.name
        return FileRange(str(tmp_path / name))

    ours = VhdImage(FileRange(str(child_path)), resolve).reader().read()

    expected = bytearray(parent_raw)
    for s, d in writes.items():
        expected[s * 512:(s + 1) * 512] = d
    assert ours == bytes(expected)

    p = pyvhdi.file()
    p.open(str(parent_path))
    c = pyvhdi.file()
    c.open(str(child_path))
    assert c.get_disk_type() == 4
    c.set_parent(p)
    theirs = c.read_buffer_at_offset(c.get_media_size(), 0)
    assert theirs == ours


def test_differencing_first_sector_follows_the_specification(tmp_path: Path) -> None:
    """Sector 0 written in the child: only sector 0 comes from the child, sectors 1-3 from the parent.

    Observed with libvhdi 20260901: it returns zeros for sectors 1-3 in this one case (it agrees
    for every other sector we tested), so this case is checked against the specification only.
    """
    parent_path, parent_raw = _qemu_dynamic(tmp_path, 4 * 1024 * 1024, 8)
    parent = VhdImage(FileRange(str(parent_path)))
    child = tmp_path / "c0.vhd"
    _differencing(child, parent, parent_path.name, {0: b"\x11" * 512})
    ours = VhdImage(FileRange(str(child)), lambda n: FileRange(str(tmp_path / n))).reader().read()
    assert ours[:512] == b"\x11" * 512
    assert ours[512:] == parent_raw[512:]


def test_differencing_rejects_wrong_parent(tmp_path: Path) -> None:
    parent_path, _ = _qemu_dynamic(tmp_path, 4 * 1024 * 1024, 5)
    other_path, _ = _qemu_dynamic(tmp_path, 4 * 1024 * 1024, 6)
    parent = VhdImage(FileRange(str(parent_path)))
    child = tmp_path / "c.vhd"
    _differencing(child, parent, "p.vhd", {1: b"\x01" * 512})
    with pytest.raises(ValueError, match="not the disk"):
        VhdImage(FileRange(str(child)), lambda _n: FileRange(str(other_path)))
    with pytest.raises(ValueError, match="needs its parent"):
        VhdImage(FileRange(str(child)))


def test_corrupt_header_and_truncated_block_are_refused(tmp_path: Path) -> None:
    out, _ = _qemu_dynamic(tmp_path, 4 * 1024 * 1024, 7)
    data = bytearray(out.read_bytes())
    off = struct.unpack(">Q", data[-512 + 16:-512 + 24])[0]
    bad = bytearray(data)
    bad[off + 40] ^= 0xFF                                    # inside the parent UUID: checksum breaks
    (tmp_path / "bad.vhd").write_bytes(bad)
    with pytest.raises(ValueError, match="checksum"):
        VhdImage(FileRange(str(tmp_path / "bad.vhd")))
    img = VhdImage(FileRange(str(out)))
    first = next(i for i, e in enumerate(img.bat) if e != 0xFFFFFFFF)
    cut = img.bat[first] * 512 + 512 + 100
    (tmp_path / "cut.vhd").write_bytes(bytes(data[:cut]) + bytes(data[-512:]))
    with pytest.raises(ValueError, match="truncated"):
        VhdImage(FileRange(str(tmp_path / "cut.vhd"))).reader().read()
