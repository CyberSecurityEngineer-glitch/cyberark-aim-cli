"""
Encrypted local vault — simulates CyberArk safe storage.

Design notes:
- AES-256-GCM for authenticated encryption (confidentiality + integrity).
- Key derivation: PBKDF2-HMAC-SHA256, 600k iterations (OWASP 2023).
- File layout: [16-byte salt][12-byte nonce][ciphertext+tag]
- The salt is generated once (on first write) and reused for all
  subsequent reads/writes. This is critical — if the salt changed,
  the derived key would change and old ciphertext would be unreadable.
- Every operation is appended to an audit log — mimicking CyberArk's
  audit trail behavior.
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
        # Store the passphrase so we can re-derive keys on every load.
        # In production you would keep this in memory only and never
        # log it, print it, or serialize it.
        self._passphrase = passphrase

    # ---------- key derivation ----------

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive an AES key from the passphrase + given salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LEN,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return kdf.derive(self._passphrase.encode())

    # ---------- audit log ----------

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

    # ---------- load / save ----------

    def _load(self) -> dict[str, Any]:
        """Decrypt the vault file and return the secrets dict."""
        if not self.vault_path.exists():
            return {}
        raw = self.vault_path.read_bytes()
        if len(raw) < SALT_LEN + NONCE_LEN:
            # File exists but is truncated / corrupt
            return {}
        salt = raw[:SALT_LEN]
        nonce = raw[SALT_LEN:SALT_LEN + NONCE_LEN]
        ct = raw[SALT_LEN + NONCE_LEN:]
        key = self._derive_key(salt)
        plaintext = AESGCM(key).decrypt(nonce, ct, None)
        return json.loads(plaintext.decode())

    def _save(self, data: dict[str, Any]) -> None:
        """Encrypt the secrets dict and write it to disk."""
        # If the file already exists, reuse its salt so old and new
        # ciphertext share the same key. Otherwise, generate a fresh one.
        if self.vault_path.exists():
            raw = self.vault_path.read_bytes()
            salt = raw[:SALT_LEN] if len(raw) >= SALT_LEN else os.urandom(SALT_LEN)
        else:
            salt = os.urandom(SALT_LEN)

        key = self._derive_key(salt)
        nonce = os.urandom(NONCE_LEN)
        plaintext = json.dumps(data).encode()
        ct = AESGCM(key).encrypt(nonce, plaintext, None)

        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        self.vault_path.write_bytes(salt + nonce + ct)

    # ---------- public API ----------

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
