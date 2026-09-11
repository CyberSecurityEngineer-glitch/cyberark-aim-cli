"""
Simulated Application Path Authentication.

In real CyberArk, CPM verifies that a requesting process is running
from an approved path before releasing a secret. Here we mimic that
by checking the current working directory against an allow-list.
"""
from __future__ import annotations

import os
from pathlib import Path


class PathAuthError(PermissionError):
    pass


def verify_path(allow_list: list[str]) -> bool:
    cwd = Path(os.getcwd()).resolve()
    for allowed in allow_list:
        try:
            cwd.relative_to(Path(allowed).resolve())
            return True
        except ValueError:
            continue
    raise PathAuthError(f"current path {cwd} not in allow-list {allow_list}")
