"""Vault / OpenBao DR snapshots against REAL OpenBao servers on integrated (Raft) storage.

Two single-node OpenBao clusters are started (``bao`` binary, CI installs OpenBao 2.5.3), each
initialised with its own unseal key. A secret written to the source is snapshotted through the
module into an in-memory object store, verified, force-restored into the DR cluster, and read back
there after unsealing with the SOURCE cluster's key - the documented behaviour of a cross-cluster
Raft snapshot restore. No cloud object store is used (the store adapters are tested elsewhere).
"""

from __future__ import annotations

import gzip
import io
import os
import shutil
import socket
import subprocess  # nosec B404 - fixed local test binary
import time
from pathlib import Path

import httpx
import pytest

from oplia_ctl.replication.stores import ObjectInfo, StoreSpec
from oplia_ctl.replication.vault_dr import VaultDrSettings, VaultEndpoint, VaultSnapshots
from oplia_ctl.secrets import StaticSecretProvider

BAO = os.environ.get("BAO_BIN") or shutil.which("bao")
if os.environ.get("CI") and not BAO:
    raise RuntimeError("the bao binary is required in CI")
needs_bao = pytest.mark.skipif(not BAO, reason="bao (OpenBao) binary not installed")
STORE = StoreSpec(cloud="gcp", bucket="oplia-dr-vault")


class MemStore:
    def __init__(self, spec):
        self.spec, self.objs, self.puts = spec, {}, []

    def put(self, key, data, size, key_ref, tags):
        self.objs[key] = data.read()
        self.puts.append({"key": key, "size": size, "key_ref": key_ref, "tags": tags})

    def head(self, key):
        return ObjectInfo(key, len(self.objs[key]), "e") if key in self.objs else None

    def open(self, key):
        return io.BytesIO(self.objs[key])


def _port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Bao:
    def __init__(self, tmp: Path, name: str):
        self.dir = tmp / name
        (self.dir / "raft").mkdir(parents=True)
        p, cp = _port(), _port()
        self.addr = f"http://127.0.0.1:{p}"
        (self.dir / "config.hcl").write_text(f'''
storage "raft" {{
  path = "{self.dir / 'raft'}"
  node_id = "{name}"
}}
listener "tcp" {{
  address = "127.0.0.1:{p}"
  cluster_address = "127.0.0.1:{cp}"
  tls_disable = true
}}
api_addr = "{self.addr}"
cluster_addr = "http://127.0.0.1:{cp}"
disable_mlock = true
''')
        self.proc = subprocess.Popen([str(BAO), "server", f"-config={self.dir / 'config.hcl'}"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._wait(lambda: httpx.get(f"{self.addr}/v1/sys/health", params={"uninitcode": 200,
                                                                         "sealedcode": 200}).status_code == 200)
        init = httpx.put(f"{self.addr}/v1/sys/init", json={"secret_shares": 1, "secret_threshold": 1},
                         timeout=60).json()
        self.key, self.token = init["keys_base64"][0], init["root_token"]
        self.unseal(self.key)

    def _wait(self, ok, n=200):
        for _ in range(n):
            try:
                if ok():
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.1)
        raise RuntimeError("OpenBao did not become ready")

    def unseal(self, key):
        assert httpx.put(f"{self.addr}/v1/sys/unseal", json={"key": key}, timeout=60).json()["sealed"] is False
        self._wait(lambda: httpx.get(f"{self.addr}/v1/sys/leader").json().get("is_self") is True)

    def call(self, method, path, token=None, **kw):
        return httpx.request(method, f"{self.addr}{path}", headers={"X-Vault-Token": token or self.token},
                             timeout=60, **kw)

    def stop(self):
        self.proc.terminate()
        self.proc.wait(10)


@pytest.fixture
def clusters(tmp_path):
    src, dst = Bao(tmp_path, "src"), Bao(tmp_path, "dst")
    yield src, dst
    src.stop()
    dst.stop()


def _cfg(src, dst, **kw):
    return VaultDrSettings(source=VaultEndpoint(addr=src.addr, token_secret="src_tok"), store=STORE,
                           key_ref="projects/p/locations/europe-west1/keyRings/dr/cryptoKeys/vault",
                           target=VaultEndpoint(addr=dst.addr, token_secret="dst_tok") if dst else None, **kw)


@needs_bao
def test_snapshot_restore_into_dr_cluster_end_to_end(clusters, session_factory, clock):
    src, dst = clusters
    mount = src.call("POST", "/v1/sys/mounts/secret", json={"type": "kv", "options": {"version": "2"}})
    assert mount.status_code == 204
    # a new KV v2 mount upgrades itself in the background and answers 400 until it is ready
    for _ in range(100):
        w = src.call("POST", "/v1/secret/data/app/db", json={"data": {"password": "s3cr3t-v1"}})
        if w.status_code == 200:
            break
        assert w.status_code == 400, w.text
        time.sleep(0.1)
    assert w.status_code == 200, w.text
    store = MemStore(STORE)
    events: list = []
    vs = VaultSnapshots(_cfg(src, dst, allow_restore=True), session_factory,
                        secrets=StaticSecretProvider({"src_tok": src.token, "dst_tok": dst.token}),
                        store_factory=lambda spec: store, now=clock, audit=lambda e, d: events.append((e, d)))
    payload = vs.parse({"restore": True})
    assert "FORCE-RESTORE" in vs.describe(payload) and "unseal keys" in vs.describe(payload)
    jid = vs.queue(vs.target_of(payload), payload, "ann")["job_id"]
    vs.run_pending()
    job = vs.get(jid)
    assert job["status"] == "SUCCEEDED", job["error"]
    st = job["state"]
    put = store.puts[0]
    assert put["key"] == st["key"] and put["key"].startswith("vault-snapshots/oplia-vault-")
    assert put["key_ref"].endswith("cryptoKeys/vault") and put["tags"]["sha256"] == st["sha256"]
    gzip.decompress(store.objs[st["key"]])                 # a real gzip archive
    assert st["restored_to"] == dst.addr
    assert src.token not in str(job) and dst.token not in str(job)

    # the DR cluster now carries the source's keyring: sealed or not, the source key unseals it
    health = st["target_health"]
    if health["sealed"]:
        assert "SOURCE cluster's unseal keys" in st["action_needed"]
        dst.unseal(src.key)
    r = dst.call("GET", "/v1/secret/data/app/db", token=src.token)
    assert r.status_code == 200 and r.json()["data"]["data"]["password"] == "s3cr3t-v1"
    assert events[-1][0] == "dr_vault_snapshot" and events[-1][1]["sha256"] == st["sha256"]


@needs_bao
def test_snapshot_only_and_tamper_detection(clusters, session_factory, clock):
    src, dst = clusters
    store = MemStore(STORE)
    secrets = StaticSecretProvider({"src_tok": src.token, "dst_tok": dst.token})
    vs = VaultSnapshots(_cfg(src, dst, allow_restore=True), session_factory, secrets=secrets,
                        store_factory=lambda spec: store, now=clock)
    jid = vs.queue("s", vs.parse({}), "a")["job_id"]
    vs.run_pending()
    assert vs.get(jid)["status"] == "SUCCEEDED" and "restored_to" not in vs.get(jid)["state"]

    # restore job whose stored snapshot is changed between SNAPSHOT and RESTORE is refused
    jid2 = vs.queue("s", vs.parse({"restore": True}), "a")["job_id"]
    vs.advance(jid2)
    key = vs.get(jid2)["state"]["key"]
    store.objs[key] = store.objs[key][:-1] + bytes([store.objs[key][-1] ^ 0xFF])
    vs.advance(jid2)
    job = vs.get(jid2)
    assert job["status"] == "FAILED" and "changed since it was taken" in job["error"]


@needs_bao
def test_bad_token_and_non_raft_errors(clusters, session_factory, clock):
    src, _ = clusters
    vs = VaultSnapshots(_cfg(src, None), session_factory, secrets=StaticSecretProvider({"src_tok": "wrong"}),
                        store_factory=lambda spec: MemStore(STORE), now=clock)
    jid = vs.queue("s", vs.parse({}), "a")["job_id"]
    vs.run_pending()
    assert vs.get(jid)["status"] == "FAILED" and "HTTP 403" in vs.get(jid)["error"]


def test_restore_needs_explicit_setting_and_https():
    cfg = VaultDrSettings(source=VaultEndpoint(addr="https://vault.prod:8200", token_secret="t"), store=STORE,
                          target=VaultEndpoint(addr="https://vault.dr:8200", token_secret="t2"))
    vs = VaultSnapshots(cfg, session_factory=None)
    assert vs.fields() == [] and vs.summary()["restore"] == "disabled"
    with pytest.raises(ValueError, match="restore is not enabled"):
        vs.parse({"restore": True})
    assert "FORCE" not in vs.describe({})
    with pytest.raises(ValueError, match="https"):
        VaultEndpoint(addr="http://vault.prod:8200", token_secret="t")
    on = VaultSnapshots(cfg.model_copy(update={"allow_restore": True}), session_factory=None)
    assert on.fields()[0]["name"] == "restore"
