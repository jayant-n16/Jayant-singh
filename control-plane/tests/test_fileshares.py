"""File-share replication between two mounted shares. Real local directories stand in for the CSI
mounts (EFS / Azure Files / Filestore); no cloud account is used."""

from __future__ import annotations

import hashlib
import os

import pytest

from oplia_ctl.replication.fileshares import STATE_FILE, FileShareReplicator, FileShareSettings


def _cfg(src, dst, **kw):
    return FileShareSettings.model_validate({"pairs": [{"name": "home", "source_kind": "efs",
                                                         "target_kind": "azure_files", "source_path": str(src),
                                                         "target_path": str(dst), **kw}]})


@pytest.fixture
def shares(tmp_path):
    src, dst = tmp_path / "efs", tmp_path / "afs"
    src.mkdir()
    dst.mkdir()
    (src / "a.txt").write_bytes(b"alpha")
    (src / "d" / "e").mkdir(parents=True)
    (src / "d" / "e" / "big.bin").write_bytes(os.urandom(3 * 1024 * 1024 + 7))
    os.chmod(src / "a.txt", 0o640)
    os.symlink("e/big.bin", src / "d" / "link")
    os.symlink("/etc/passwd", src / "escape")
    os.mkfifo(src / "pipe")
    return src, dst


def _run(r, payload="home"):
    jid = r.queue("t", r.parse({"pair": payload}), "ann")["job_id"]
    for _ in range(20):  # each worker run copies at most max_files_per_run files
        r.run_pending()
        if r.get(jid)["status"] in ("SUCCEEDED", "FAILED"):
            break
    return r.get(jid)


def test_copies_verifies_and_is_incremental(shares, session_factory, clock):
    src, dst = shares
    events: list = []
    r = FileShareReplicator(_cfg(src, dst, max_files_per_run=1), session_factory, now=clock,
                            audit=lambda e, d: events.append((e, d)))
    assert "deletions are reported" in r.describe({"pair": "home"})
    jid = r.queue("t", {"pair": "home"}, "ann")["job_id"]
    r.run_pending()
    assert r.get(jid)["step"] == "COPY" and len(r.get(jid)["state"]["todo"]) == 1  # bounded per run
    r.run_pending()
    job = r.get(jid)
    assert job["status"] == "SUCCEEDED", job["error"]
    assert job["state"]["copied_count"] == 2 and job["state"]["verified"] == 2
    for rel in ("a.txt", "d/e/big.bin"):
        assert hashlib.sha256((dst / rel).read_bytes()).digest() == hashlib.sha256((src / rel).read_bytes()).digest()
        assert (dst / rel).stat().st_mtime_ns == (src / rel).stat().st_mtime_ns
    assert oct((dst / "a.txt").stat().st_mode & 0o777) == "0o640"
    assert os.readlink(dst / "d" / "link") == "e/big.bin"
    reasons = {s["path"]: s["reason"] for s in job["state"]["skipped"]}
    assert "special file" in reasons["pipe"] and "leaves the share" in reasons["escape"]
    assert not (dst / "escape").exists() and not list(dst.rglob("*.oplia-tmp"))
    assert (dst / STATE_FILE).exists() and events[-1][0] == "dr_fileshare_sync"
    # second run: nothing changed -> nothing copied
    assert _run(r)["state"]["copied_count"] == 0
    # change one file, delete another at the source
    (src / "a.txt").write_bytes(b"alpha v2")
    (src / "d" / "e" / "big.bin").unlink()
    job = _run(r)
    assert job["state"]["copied"] == ["a.txt"] and (dst / "a.txt").read_bytes() == b"alpha v2"
    assert job["state"]["deleted_at_source"] == ["d/e/big.bin"] and (dst / "d" / "e" / "big.bin").exists()


def test_file_changing_during_copy_is_not_written(shares, session_factory, clock, monkeypatch):
    src, dst = shares
    r = FileShareReplicator(_cfg(src, dst), session_factory, now=clock)
    jid = r.queue("t", {"pair": "home"}, "a")["job_id"]
    r.advance(jid)  # PLAN
    (src / "a.txt").write_bytes(b"changed after plan")
    os.utime(src / "a.txt", ns=(1, 1))
    r.run_pending()
    job = r.get(jid)
    assert job["status"] == "SUCCEEDED" and job["state"]["changed_during_copy"] == ["a.txt"]
    assert not (dst / "a.txt").exists()
    assert _run(r)["state"]["copied"] == ["a.txt"]  # picked up by the next run


def test_corruption_after_copy_fails_verification(shares, session_factory, clock):
    src, dst = shares
    r = FileShareReplicator(_cfg(src, dst), session_factory, now=clock)
    jid = r.queue("t", {"pair": "home"}, "a")["job_id"]
    r.advance(jid)  # PLAN
    r.advance(jid)  # COPY
    (dst / "a.txt").write_bytes(b"bitrot")
    r.advance(jid)  # VERIFY
    job = r.get(jid)
    assert job["status"] == "FAILED" and "corrupted after copy" in job["error"]
    assert not (dst / STATE_FILE).exists()


def test_missing_mount_fails_cleanly(tmp_path, session_factory, clock):
    (tmp_path / "t").mkdir()
    r = FileShareReplicator(_cfg(tmp_path / "nope", tmp_path / "t"), session_factory, now=clock)
    job = _run(r)
    assert job["status"] == "FAILED" and "is the share mounted" in job["error"]


def test_validation(tmp_path):
    with pytest.raises(ValueError, match="must be absolute"):
        _cfg("rel", tmp_path)
    with pytest.raises(ValueError, match="must not overlap"):
        _cfg(tmp_path, tmp_path / "sub")
    with pytest.raises(ValueError):
        FileShareSettings.model_validate({"pairs": [{"name": "a", "source_kind": "nfs", "target_kind": "efs",
                                                     "source_path": "/a", "target_path": "/b"}]})
    r = FileShareReplicator(_cfg(tmp_path / "x", tmp_path / "y"), session_factory=None)
    with pytest.raises(ValueError, match="unknown file-share pair"):
        r.parse({"pair": "nope"})
