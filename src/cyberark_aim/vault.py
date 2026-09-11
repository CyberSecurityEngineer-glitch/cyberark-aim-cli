"""
Encrypted local vault — simulates CyberArk safe storage.

Design notes (write this in your own words for the README later):
- We use AES-256-GCM via the `cryptography` library.
- The master key is derived from a passphrase using PBKDF2-HMAC-SHA256
  with 600,000 iterations (OWASP 2023 recommendation).
- The vault file stores: salt | nonce | ciphertext.
- Every read/write appends an entry to an audit log — mimicking
  CyberArk's audit trail.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PBKDF2_ITERATIONS = 600_000
KEY_LEN = 32          # 256-bit key
SALT_LEN = 16
NONCE_LEN = 12        # GCM standard


@dataclass
class Secret:
    account: str
    username: str
    password: str
    metadata: dict[str, Any] = field(default_factory=dict)


class Vault:
    """Encrypted secret store with audit logging."""

    def __init__(self, vault_path: Path, log_path: Path, passphrase: str):
        self.vault_path = Path(vault_path)
        self.log_path = Path(log_path)
        self._key = self._derive_key(passphrase)

    def _derive_key(self, passphrase: str) -> bytes:
        salt = os.urandom(SALT_LEN)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LEN,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        key = kdf.derive(passphrase.encode())
        # Store salt alongside vault for decryption
        self._salt = salt
        return key

    def _audit(self, action: str, account: str, status: str) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "action": action,
            "account": account,
            "status": status,
        }
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def _load(self) -> dict[str, Any]:
        if not self.vault_path.exists():
            return {}
        raw = self.vault_path.read_bytes()
        salt, nonce, ct = raw[:SALT_LEN], raw[SALT_LEN:SALT_LEN + NONCE_LEN], raw[SALT_LEN + NONCE_LEN:]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LEN,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        key = kdf.derive(self._passphrase_cache)
        plaintext = AESGCM(key).decrypt(nonce, ct, None)
        return json.loads(plaintext.decode())

    def _save(self, data: dict[str, Any]) -> None:
        plaintext = json.dumps(data).encode()
        aes = AESGCM(self._key)
        nonce = os.urandom(NONCE_LEN)
        ct = aes.encrypt(nonce, plaintext, None)
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        self.vault_path.write_bytes(self._salt + nonce + ct)

    def get(self, account: str) -> Secret | None:
        data = self._load()
        if account not in data:
            self._audit("READ", account, "NOT_FOUND")
            return None
        self._audit("READ", account, "OK")
        return Secret(**data[account])

    def put(self, secret: Secret) -> None:
        data = self._load()
        data[secret.account] = asdict(secret)
        self._save(data)
        self._audit("WRITE", secret.account, "OK")

    def rotate(self, account: str, new_password: str) -> bool:
        data = self._load()
        if account not in data:
            self._audit("ROTATE", account, "NOT_FOUND")
            return False
        data[account]["password"] = new_password
        self._save(data)
        self._audit("ROTATE", account, "OK")
        return True
