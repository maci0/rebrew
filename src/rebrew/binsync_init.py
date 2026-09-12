"""binsync_init.py: initialize a BinSync git envelope for a target's state dir.

Upstream BinSync's ``Client`` requires a git repository whose
``binsync/__root__`` branch root commit carries ``.gitignore`` (``.git/*``)
and ``binary_hash`` (the target binary's MD5), plus a ``binsync/<user>``
branch created from that root.  rebrew writes BinSync-format files but never
creates the envelope, so upstream refuses the directory with "not a BinSync
repo".  This command builds it.

Typical flow::

    rebrew binsync-init ./binsync_state
    rebrew binsync-export ./binsync_state --git
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

import typer
from rich.console import Console

from rebrew.cli import TargetOption, error_exit, json_print, require_config
from rebrew.utils import atomic_write_text, md5_file

log = logging.getLogger(__name__)

console = Console(stderr=True)

#: Seconds any single git invocation may run.
_GIT_TIMEOUT = 30

#: The BinSync root branch (upstream resolves the state root from it).
_ROOT_BRANCH = "binsync/__root__"

#: The root commit's ignore file: exactly the pattern upstream writes.
_GITIGNORE_CONTENT = ".git/*\n"


def _one_line(text: str) -> str:
    """Collapse *text* to one sanitized line for an error message."""
    return " ".join(text.split())


def _run_git(directory: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run ``git -C directory <args>`` without raising on a non-zero exit."""
    try:
        return subprocess.run(
            ["git", "-C", str(directory), *args],
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT,
        )
    except FileNotFoundError:
        return subprocess.CompletedProcess(["git", *args], 127, "", "git not found")
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("git invocation failed", exc_info=True)
        return subprocess.CompletedProcess(["git", *args], 1, "", str(exc))


def _checked(result: subprocess.CompletedProcess[str], *, json_mode: bool) -> None:
    """Exit with the sanitized git stderr when *result* failed."""
    if result.returncode != 0:
        detail = _one_line(result.stderr or result.stdout) or f"git exited with {result.returncode}"
        error_exit(f"git failed: {detail}", json_mode=json_mode)


def _is_binsync_repo(directory: Path) -> bool:
    """True when *directory* already has a ``binsync/__root__`` branch."""
    if not (directory / ".git").exists():
        return False
    probe = _run_git(directory, "rev-parse", "--verify", "--quiet", _ROOT_BRANCH)
    return probe.returncode == 0


def _default_user(directory: Path) -> str:
    """``git config user.name`` when set, else ``"rebrew"``."""
    result = _run_git(directory, "config", "user.name")
    name = result.stdout.strip()
    return name if result.returncode == 0 and name else "rebrew"


def _write_root_files(directory: Path, digest: str) -> None:
    """Write the two files the root commit must carry."""
    atomic_write_text(directory / ".gitignore", _GITIGNORE_CONTENT, encoding="utf-8")
    atomic_write_text(directory / "binary_hash", digest, encoding="utf-8")


def _report(
    directory: Path,
    target: str,
    user_name: str,
    digest: str,
    *,
    dry_run: bool,
    json_output: bool,
) -> None:
    """Emit the result (JSON payload or one-line human summary)."""
    user_branch = f"binsync/{user_name}"
    if json_output:
        json_print(
            {
                "state_dir": str(directory),
                "target": target,
                "user": user_name,
                "binary_hash": digest,
                "root_branch": _ROOT_BRANCH,
                "user_branch": user_branch,
                "dry_run": dry_run,
            }
        )
        return
    if dry_run:
        console.print(
            f"[dim]dry-run: would initialize BinSync repo at {directory} "
            f"(root {_ROOT_BRANCH}, user {user_branch})[/dim]"
        )
    else:
        console.print(
            f"[green]Initialized[/green] BinSync repo at {directory} "
            f"(root {_ROOT_BRANCH}, user [cyan]{user_branch}[/cyan])"
        )


app = typer.Typer(
    help="Initialize a BinSync git repo (root + user branches) for a target.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew binsync-init ./binsync_state · · · · · · Initialize\n\n"
        "  rebrew binsync-init ./binsync_state --user alice\n\n"
        "  rebrew binsync-init ./binsync_state --dry-run --json · Preview\n\n"
        "[dim]Creates the git envelope upstream BinSync requires: the\n"
        "binsync/__root__ root commit (.gitignore + binary_hash) and a\n"
        "binsync/<user> branch created from it.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    state_dir: Path = typer.Argument(..., help="BinSync state directory to initialize"),
    user: str | None = typer.Option(
        None, "--user", help="BinSync user name (branch binsync/<user>)"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Initialize a BinSync git repo (root + user branches) for a target."""
    cfg = require_config(target=target, json_mode=json_output)

    binary = Path(cfg.target_binary)
    if not binary.is_file():
        error_exit(f"target binary not found: {binary}", json_mode=json_output)
    digest = md5_file(binary)

    try:
        resolved = state_dir.resolve()
    except OSError as exc:
        error_exit(f"Cannot resolve state directory {state_dir}: {exc}", json_mode=json_output)

    if _is_binsync_repo(resolved):
        error_exit("already a BinSync repository", json_mode=json_output)

    user_name = user or _default_user(resolved)

    if dry_run:
        _report(
            resolved,
            cfg.target_name,
            user_name,
            digest,
            dry_run=True,
            json_output=json_output,
        )
        return

    resolved.mkdir(parents=True, exist_ok=True)

    if not (resolved / ".git").exists():
        _checked(_run_git(resolved, "init", "-q"), json_mode=json_output)

    existing_name = _run_git(resolved, "config", "user.name").stdout.strip()
    existing_email = _run_git(resolved, "config", "user.email").stdout.strip()
    if not existing_name:
        _checked(_run_git(resolved, "config", "user.name", user_name), json_mode=json_output)
    if not existing_email:
        _checked(
            _run_git(resolved, "config", "user.email", f"{user_name}@binsync.local"),
            json_mode=json_output,
        )

    _checked(_run_git(resolved, "checkout", "-q", "--orphan", _ROOT_BRANCH), json_mode=json_output)
    _write_root_files(resolved, digest)
    _checked(_run_git(resolved, "add", "--", ".gitignore", "binary_hash"), json_mode=json_output)
    _checked(_run_git(resolved, "commit", "-q", "-m", "Root commit"), json_mode=json_output)
    _checked(
        _run_git(resolved, "checkout", "-q", "-b", f"binsync/{user_name}"), json_mode=json_output
    )

    _report(
        resolved,
        cfg.target_name,
        user_name,
        digest,
        dry_run=False,
        json_output=json_output,
    )


def main_entry() -> None:
    """Run the Typer CLI application."""
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
