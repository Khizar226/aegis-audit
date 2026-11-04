"""aegis-audit command-line interface."""

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from typing_extensions import Annotated

from . import __version__, crypto
from .store import DEFAULT_DIR, AuditLog


def _harden_stdio() -> None:
    """Escape unencodable characters on legacy (e.g. cp1252) consoles instead of crashing."""
    for stream in (sys.stdout, sys.stderr):
        enc = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
        if enc.startswith("utf"):
            continue
        try:
            stream.reconfigure(errors="backslashreplace")  # type: ignore[union-attr]
        except (AttributeError, ValueError, OSError):
            pass


_harden_stdio()
console = Console(highlight=False)
app = typer.Typer(
    name="aegis-audit",
    help="Tamper-evident, Ed25519-signed Merkle audit logs for AI agent execution.",
    no_args_is_help=True,
    add_completion=False,
)

DirOpt = Annotated[Path, typer.Option("--dir", "-d", help="Audit directory (keys + log).")]


def _version(value: bool) -> None:
    if value:
        console.print(f"aegis-audit {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[Optional[bool], typer.Option("--version", callback=_version, is_eager=True)] = None,
) -> None:
    """aegis-audit: cryptographic flight recorder for AI agents."""


@app.command()
def init(directory: DirOpt = DEFAULT_DIR, force: Annotated[bool, typer.Option("--force")] = False) -> None:
    """Generate an Ed25519 keypair for signing the audit log."""
    if (directory / crypto.PRIVATE_KEY_FILE).exists() and not force:
        console.print(f"[yellow]Keys already exist in {directory}. Use --force to overwrite.[/]")
        raise typer.Exit(1)
    priv_path, pub_path = crypto.generate_keypair(directory)
    fp = crypto.fingerprint(crypto.load_public_key(pub_path))
    console.print(
        Panel.fit(
            f"[green]Keypair created[/]\nPrivate key: [cyan]{priv_path}[/]\nPublic key:  [cyan]{pub_path}[/]\n"
            f"Fingerprint: [bold]{fp}[/]",
            title="aegis-audit init",
        )
    )


@app.command()
def log(message: Annotated[str, typer.Argument(help="Event to record.")], directory: DirOpt = DEFAULT_DIR) -> None:
    """Append a signed event to the audit log."""
    line = AuditLog(directory).append(message)
    ev = line["event"]
    console.print(f"[green]Logged[/] [dim]{ev['timestamp']} {ev['user']}[/] {message}")
    console.print(f"Merkle root: [bold cyan]{line['merkle_root']}[/]")


@app.command()
def verify(directory: DirOpt = DEFAULT_DIR) -> None:
    """Verify the integrity and signature of the audit log."""
    res = AuditLog(directory).verify()
    table = Table(title="Merkle root history")
    table.add_column("#", justify="right")
    table.add_column("Timestamp (UTC)")
    table.add_column("Merkle root", style="cyan")
    for i, ts, root in res.history[-10:]:
        table.add_row(str(i), ts, root)
    if res.history:
        console.print(table)
    if res.ok:
        console.print(Panel.fit(f"[bold green]✅ Log integrity verified[/] ({res.entries} entries)", border_style="green"))
    else:
        console.print(Panel.fit("[bold red]🚨 TAMPER DETECTED[/]\n" + "\n".join(res.errors), border_style="red"))
        raise typer.Exit(1)


def run() -> None:
    app()
