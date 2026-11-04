"""aegis-audit command-line interface."""

import json
import sys
import unicodedata
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from typing_extensions import Annotated

from . import __version__, crypto
from .store import DEFAULT_DIR, AuditLog, HistoryRow, TamperError, VerifyResult, trust_store_path


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
err = Console(stderr=True, highlight=False)
app = typer.Typer(
    name="aegis-audit",
    help="Tamper-evident, Ed25519-signed Merkle audit logs for AI agent execution.",
    no_args_is_help=True,
    add_completion=False,
)

DirOpt = Annotated[Path, typer.Option("--dir", "-d", help="Audit directory (keys + log).")]
VERIFIED = "✅ Log integrity verified"
TAMPERED = "🚨 TAMPER DETECTED"


def safe(s: str, limit: int = 80) -> Text:
    """Render untrusted log text literally.

    Red-team fix: messages are written by (possibly prompt-injected) agents.
    Passed to Rich as a str they were parsed as markup, so a message like
    "[bold green]✅ Log integrity verified" could spoof the verdict. Control
    and format characters (ANSI escapes, bidi overrides) are made visible.
    """
    out = []
    for ch in s:
        cat = unicodedata.category(ch)
        out.append(f"\\u{ord(ch):04x}" if cat in ("Cc", "Cf", "Cs", "Co", "Zl", "Zp") else ch)
    text = "".join(out)
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return Text(text)


def _version(value: bool) -> None:
    if value:
        console.print(f"aegis-audit {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[Optional[bool], typer.Option("--version", callback=_version, is_eager=True)] = None,
) -> None:
    """aegis-audit: a cryptographic flight recorder for AI agents."""


@app.command()
def init(
    directory: DirOpt = DEFAULT_DIR,
    force: Annotated[bool, typer.Option("--force", help="Overwrite existing keys (only if the log is empty).")] = False,
) -> None:
    """Generate an Ed25519 keypair for signing the audit log."""
    try:
        priv_path, pub_path = AuditLog(directory).init(force=force)
    except FileExistsError as exc:
        err.print(Text(f"{exc}" + ("" if "--force" in str(exc) or "archive" in str(exc) else ". Use --force to overwrite."), style="yellow"))
        raise typer.Exit(1)
    fp = crypto.fingerprint(crypto.load_public_key(pub_path))
    body = Text.assemble(
        ("Keypair created\n", "green"),
        "Private key: ", (str(priv_path), "cyan"), "  (keep secret, mode 0600)\n",
        "Public key:  ", (str(pub_path), "cyan"), "\n",
        "Fingerprint: ", (fp, "bold"), "\n\n",
        "Pinned in:   ", (str(trust_store_path()), "cyan"), "\n\n",
        ("Also store the fingerprint OFF this machine and verify with --fingerprint.", "yellow"),
    )
    console.print(Panel.fit(body, title="aegis-audit init"))


@app.command()
def log(
    message: Annotated[str, typer.Argument(help="Event to record.")],
    directory: DirOpt = DEFAULT_DIR,
) -> None:
    """Append a signed event (with UTC timestamp and OS user) to the audit log."""
    try:
        line = AuditLog(directory).append(message)
    except TamperError as exc:
        err.print(Panel.fit(Text(f"{TAMPERED}\n{exc}"), border_style="red"))
        raise typer.Exit(1)
    except FileNotFoundError:
        err.print(f"[red]No keys in {directory}. Run `aegis-audit init` first.[/]")
        raise typer.Exit(1)
    console.print(
        Text.assemble(("Logged ", "green"), (f"#{line['seq']} {line['timestamp']} {line['user']} ", "dim"), safe(message))
    )
    console.print(Text.assemble("Merkle root: ", (line["merkle_root"], "bold cyan"), f"  (tree size {line['tree_size']})"))


def _history_table(rows: List[HistoryRow], title: str) -> Table:
    table = Table(title=title, header_style="bold")
    table.add_column("#", justify="right")
    table.add_column("Timestamp (UTC)", style="dim")
    table.add_column("User")
    table.add_column("Event")
    table.add_column("Merkle root", style="cyan", no_wrap=True)
    for r in rows:
        table.add_row(str(r.seq), r.timestamp[:26], safe(r.user, 20), safe(r.message, 48), r.merkle_root[:16] + "…")
    return table


def _report(res: VerifyResult, show: int) -> None:
    if res.history and show:
        shown = res.history[-show:]
        console.print(_history_table(shown, f"Merkle root history (last {len(shown)} of {res.entries})"))
    for w in res.warnings:
        err.print(Text("! " + w, style="yellow"))
    if res.ok:
        detail = f"{res.entries} entries · root {res.root[:16]}… · key {res.key_id[:16]}…" if res.root else ""
        pin = f"key pinned via {res.pin_source}" if res.pinned else "UNPINNED key"
        console.print(Panel.fit(Text.assemble((VERIFIED, "bold green"), f"\n{detail} · {pin}"), border_style="green"))
    else:
        console.print(Panel.fit(Text.assemble((TAMPERED, "bold red"), "\n" + "\n".join(res.errors)), border_style="red"))


@app.command()
def verify(
    directory: DirOpt = DEFAULT_DIR,
    pubkey: Annotated[
        Optional[Path], typer.Option("--pubkey", help="Trusted public key (kept outside the audit directory).")
    ] = None,
    fingerprint: Annotated[
        Optional[str], typer.Option("--fingerprint", help="Pinned key fingerprint printed by `init` (or AEGIS_TRUSTED_FINGERPRINT).")
    ] = None,
    checkpoint: Annotated[
        Optional[Path], typer.Option("--checkpoint", help="Signed checkpoint from `aegis-audit checkpoint`; detects truncation/rollback.")
    ] = None,
    require_pin: Annotated[bool, typer.Option("--require-pin", help="Fail unless the key is pinned.")] = False,
    show: Annotated[int, typer.Option("--show", help="History rows to display (0 = none).")] = 10,
    json_out: Annotated[bool, typer.Option("--json", help="Machine-readable result.")] = False,
) -> None:
    """Recompute every hash, Merkle root and signature, and report tampering."""
    res = AuditLog(directory).verify(pubkey=pubkey, fingerprint_pin=fingerprint, checkpoint=checkpoint)
    if require_pin and not res.pinned:
        res.ok = False
        res.errors.append("--require-pin: no trusted key supplied (--pubkey / --fingerprint)")
    if json_out:
        typer.echo(json.dumps({
            "ok": res.ok, "verdict": VERIFIED if res.ok else TAMPERED, "entries": res.entries,
            "merkle_root": res.root, "key_id": res.key_id, "pinned": res.pinned,
            "errors": res.errors, "warnings": res.warnings,
        }, indent=2, ensure_ascii=False))
    else:
        _report(res, show)
    if not res.ok:
        raise typer.Exit(1)


@app.command()
def history(
    directory: DirOpt = DEFAULT_DIR,
    limit: Annotated[int, typer.Option("--limit", "-n", help="Show the last N entries.")] = 25,
) -> None:
    """Show the Merkle root history (entries are verified while reading)."""
    res = AuditLog(directory).verify()
    console.print(_history_table(res.history[-limit:], f"Merkle root history ({res.entries} entries)"))
    if not res.ok:
        console.print(Panel.fit(Text.assemble((TAMPERED, "bold red"), "\n" + "\n".join(res.errors)), border_style="red"))
        raise typer.Exit(1)


@app.command()
def checkpoint(
    directory: DirOpt = DEFAULT_DIR,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Write to file instead of stdout.")] = None,
) -> None:
    """Export the latest signed tree head. Store it somewhere the agent can't write."""
    try:
        cp = AuditLog(directory).checkpoint()
    except (TamperError, ValueError) as exc:
        err.print(Text(str(exc), style="red"))
        raise typer.Exit(1)
    data = json.dumps(cp, indent=2) + "\n"
    if output:
        output.write_text(data, encoding="utf-8")
        err.print(f"[green]Checkpoint written:[/] {output} (tree size {cp['tree_size']})")
    else:
        typer.echo(data, nl=False)


def run() -> None:
    app()
