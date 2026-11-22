"""Vault Transit protection for DR data: encrypted, HMAC-signed incident dumps and bundle signatures.

The key never leaves Vault; the breaker only holds ciphertext and HMACs. An envelope can be
opened with ``vault write transit-dr-broker/decrypt/circuit-breaker-key ciphertext=...`` by
someone whose policy allows it, and its integrity checked with ``.../verify/...``.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from oplia_ctl.vault import VaultClient


class TransitProtector:
    def __init__(self, client: VaultClient, mount: str = "transit-dr-broker", key: str = "circuit-breaker-key") -> None:
        self._c = client
        self.mount = mount
        self.key = key

    def protect(self, plaintext: bytes) -> bytes:
        """Return a JSON envelope: ciphertext + HMAC (both by Vault) + SHA-256 of the plaintext."""
        ciphertext = self._c.encrypt(self.mount, self.key, plaintext)
        [mac] = self._c.hmac(self.mount, self.key, [plaintext])
        envelope = {"oplia_dump_envelope": 1, "transit": {"mount": self.mount, "key": self.key},
                    "ciphertext": ciphertext, "hmac": mac, "sha256": hashlib.sha256(plaintext).hexdigest()}
        return json.dumps(envelope, sort_keys=True).encode()

    def open(self, envelope: bytes) -> bytes:
        env: dict[str, Any] = json.loads(envelope)
        plaintext = self._c.decrypt(self.mount, self.key, env["ciphertext"])
        if not self._c.verify_hmac(self.mount, self.key, plaintext, env["hmac"]):
            raise ValueError("dump HMAC does not verify: the envelope was altered")
        if hashlib.sha256(plaintext).hexdigest() != env["sha256"]:
            raise ValueError("dump SHA-256 mismatch")
        return plaintext

    def sign(self, values: list[bytes]) -> list[str]:
        return self._c.hmac(self.mount, self.key, values)
