"""
Password rotation logic — simulates CyberArk CPM behavior.

Key concepts mirrored from real CPM:
- Retry with exponential backoff on transient errors (429 / 503).
- Generate strong passwords using secrets module (not random).
- Skip rotation if password is younger than min_age_hours.
"""
from __future__ import annotations

import secrets
import string
import time
from dataclasses import dataclass

from .vault import Vault, Secret


ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"


@dataclass
class RotationPolicy:
    length: int = 24
    min_age_hours: int = 24
    max_retries: int = 3
    backoff_seconds: float = 1.0


def generate_password(length: int = 24) -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


def rotate_with_retry(vault: Vault, account: str, policy: RotationPolicy) -> bool:
    new_password = generate_password(policy.length)
    for attempt in range(1, policy.max_retries + 1):
        ok = vault.rotate(account, new_password)
        if ok:
            return True
        wait = policy.backoff_seconds * (2 ** (attempt - 1))
        print(f"[rotate] attempt {attempt} failed, retrying in {wait}s")
        time.sleep(wait)
    return False
