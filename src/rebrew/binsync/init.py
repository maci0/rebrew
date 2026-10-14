"""init.py: initialize a BinSync git envelope for a target's state dir.

Upstream BinSync's ``Client`` requires a git repository whose
``binsync/__root__`` branch root commit carries ``.gitignore`` (``.git/*``)
and ``binary_hash`` (the target binary's MD5), plus a ``binsync/<user>``
branch created from that root.  rebrew writes BinSync-format files but never
creates the envelope, so upstream refuses the directory with "not a BinSync
repo".  This command builds it.

Typical flow::

    rebrew binsync init ./binsync_state
    rebrew binsync export ./binsync_state --git
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

import typer

from rebrew.binsync.git import one_line, run_git
from rebrew.binsync.repo import (
    ROOT_BRANCH,
    USER_CONFIG_KEY,
    is_binsync_repo,
    resolve_user,
    user_branch,
)
from rebrew.cli import TargetOption, console, error_exit, json_print, require_config
from rebrew.utils import atomic_write_text, md5_file

log = logging.getLogger(__name__)

#: The root commit's ignore file: exactly the pattern upstream writes.
_GITIGNORE_CONTENT = ".git/*\n"


def _checked(result: subprocess.CompletedProcess[str], *, json_mode: bool) -> None:
    """Exit with the sanitized git stderr when *result* failed."""
    if result.returncode != 0:
        detail = one_line(result.stderr or result.stdout) or f"git exited with {result.returncode}"
        error_exit(f"git failed: {detail}", json_mode=json_mode)


def _write_root_files(directory: Path, digest: str) -> None:
    """Write the two files the root commit must carry (writable: BinSync rewrites them)."""
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
    branch = user_branch(user_name)
    if json_output:
        json_print(
            {
                "state_dir": str(directory),
                "target": target,
                "user": user_name,
                "binary_hash": digest,
                "root_branch": ROOT_BRANCH,
                "user_branch": branch,
                "dry_run": dry_run,
            }
        )
        return
    if dry_run:
        console.print(
            f"[dim]dry-run: would initialize BinSync repo at {directory} "
            f"(root {ROOT_BRANCH}, user {branch})[/dim]"
        )
    else:
        console.print(
            f"[green]Initialized[/green] BinSync repo at {directory} "
            f"(root {ROOT_BRANCH}, user [cyan]{branch}[/cyan])"
        )


app = typer.Typer(
    help="Initialize a BinSync git repo (root + user branches) for a target.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew binsync init ./binsync_state  # Initialize\n\n"
        "  rebrew binsync init ./binsync_state --user alice\n\n"
        "  rebrew binsync init ./binsync_state --dry-run --json  # Preview\n\n"
        "[dim]Creates the git envelope upstream BinSync requires: the binsync/__root__ root commit (.gitignore + binary_hash) and a binsync/<user> branch created from it.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    state_dir: Path = typer.Argument(..., help="BinSync state directory to initialize"),
    user: str | None = typer.Option(
        None,
        "--user",
        help="BinSync user rebrew writes as (branch binsync/<user>; default: "
        "targets.<name>.binsync_user, else rebrew)",
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

    try:
        user_name = resolve_user(cfg, resolved, user)
    except ValueError as exc:
        error_exit(str(exc), json_mode=json_output)
    branch = user_branch(user_name)

    if is_binsync_repo(resolved):
        # Converge instead of erroring: a rerun after a crash past the root
        # commit, or a second user joining, only needs the user branch.
        root_hash = run_git(resolved, "show", f"{ROOT_BRANCH}:binary_hash")
        if root_hash.returncode != 0 or root_hash.stdout.strip() != digest:
            error_exit(
                f"{ROOT_BRANCH} binary_hash does not match the target binary",
                json_mode=json_output,
            )
        if not dry_run:
            has_branch = run_git(resolved, "rev-parse", "--verify", "--quiet", branch)
            args = (branch,) if has_branch.returncode == 0 else ("-b", branch, ROOT_BRANCH)
            _checked(run_git(resolved, "checkout", "-q", *args), json_mode=json_output)
            _checked(
                run_git(resolved, "config", "--local", USER_CONFIG_KEY, user_name),
                json_mode=json_output,
            )
        _report(
            resolved,
            cfg.target_name,
            user_name,
            digest,
            dry_run=dry_run,
            json_output=json_output,
        )
        return

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
        _checked(run_git(resolved, "init", "-q"), json_mode=json_output)

    existing_name = run_git(resolved, "config", "user.name").stdout.strip()
    existing_email = run_git(resolved, "config", "user.email").stdout.strip()
    if not existing_name:
        _checked(run_git(resolved, "config", "user.name", user_name), json_mode=json_output)
    if not existing_email:
        _checked(
            run_git(resolved, "config", "user.email", f"{user_name}@binsync.local"),
            json_mode=json_output,
        )

    _checked(
        run_git(resolved, "config", "--local", USER_CONFIG_KEY, user_name), json_mode=json_output
    )
    _checked(run_git(resolved, "checkout", "-q", "--orphan", ROOT_BRANCH), json_mode=json_output)
    _write_root_files(resolved, digest)
    _checked(run_git(resolved, "add", "--", ".gitignore", "binary_hash"), json_mode=json_output)
    _checked(run_git(resolved, "commit", "-q", "-m", "Root commit"), json_mode=json_output)
    _checked(run_git(resolved, "checkout", "-q", "-b", branch), json_mode=json_output)

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
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
