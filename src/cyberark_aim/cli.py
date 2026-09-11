"""Command-line interface for cyberark_aim."""
from __future__ import annotations

import os
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from .vault import Vault, Secret
from .rotation import rotate_with_retry, RotationPolicy


console = Console()
DEFAULT_VAULT = Path("vault.enc")
DEFAULT_LOG = Path("logs/audit.log")


def _get_vault() -> Vault:
    passphrase = os.environ.get("AIM_PASSPHRASE")
    if not passphrase:
        raise click.ClickException("Set AIM_PASSPHRASE environment variable")
    return Vault(DEFAULT_VAULT, DEFAULT_LOG, passphrase)


@click.group()
def main() -> None:
    """Simulated CyberArk AIM client."""


@main.command()
@click.option("--account", required=True)
@click.option("--username", required=True)
@click.option("--password", required=True)
def add(account: str, username: str, password: str) -> None:
    """Store a new secret in the vault."""
    v = _get_vault()
    v.put(Secret(account=account, username=username, password=password))
    console.print(f"[green]Stored secret for {account}[/green]")


@main.command()
@click.option("--account", required=True)
def get(account: str) -> None:
    """Retrieve a secret (password shown masked)."""
    v = _get_vault()
    s = v.get(account)
    if not s:
        console.print(f"[red]Secret {account} not found[/red]")
        return
    table = Table(title=f"Secret: {account}")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("username", s.username)
    table.add_row("password", "*" * len(s.password))
    console.print(table)


@main.command()
@click.option("--account", required=True)
def rotate(account: str) -> None:
    """Rotate a secret's password."""
    v = _get_vault()
    ok = rotate_with_retry(v, account, RotationPolicy())
    if ok:
        console.print(f"[green]Rotated {account}[/green]")
    else:
        console.print(f"[red]Rotation failed for {account}[/red]")


if __name__ == "__main__":
    main()
