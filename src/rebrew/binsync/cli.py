"""cli.py: the ``rebrew binsync`` umbrella (push/pull/summary + flat commands).

Reuses the existing flat BinSync commands as subcommands and adds the
git-automation trio:

* ``push`` exports the project into a state directory and commits it, with an
  optional ``--git-push`` of the root and current branches.
* ``pull`` optionally fast-forwards the state directory's git repo, then
  imports the state into the project.
* ``summary`` previews both directions read-only.

The flat ``rebrew binsync-export/import/diff/init/overlay`` commands remain
for back-compat; this group is a thin orchestration layer over the same
functions.
"""

from __future__ import annotations

import contextlib
import io
import logging
import subprocess
from pathlib import Path

import typer
from rich.console import Console

from rebrew.binsync import diff, export, importer, init, overlay
from rebrew.binsync.init import _one_line, _run_git
from rebrew.cli import TargetOption, error_exit, json_print, require_config
from rebrew.config import ProjectConfig

log = logging.getLogger(__name__)

console = Console(stderr=True)

#: Counts surfaced by ``summary`` for each direction.
_PUSH_COUNTS: tuple[str, ...] = (
    "functions",
    "globals",
    "structs",
    "enums",
    "typedefs",
    "comments",
)
_PULL_COUNTS: tuple[str, ...] = (
    "applied_names",
    "applied_prototypes",
    "applied_globals",
    "applied_structs",
    "applied_enums",
    "applied_typedefs",
    "applied_locals",
    "applied_comments",
    "conflicts",
    "skipped",
)


app = typer.Typer(
    help="BinSync state sync: push/pull/summary plus the flat commands.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


# Register the existing callbacks directly (same mechanism as main.py's
# _register_single_module): the callbacks carry their own options.
app.command(name="init")(init.main)
app.command(name="diff")(diff.main)
app.command(name="overlay")(overlay.main)


def _resolve_state_dir(state_dir: Path, *, json_mode: bool) -> Path:
    """Resolve *state_dir*; abort when it is not an existing directory."""
    try:
        resolved = state_dir.resolve()
    except OSError as exc:
        error_exit(f"Cannot resolve state directory {state_dir}: {exc}", json_mode=json_mode)
    if not resolved.exists():
        error_exit(f"State directory not found: {state_dir}", json_mode=json_mode)
    if not resolved.is_dir():
        error_exit(f"Not a directory: {state_dir}", json_mode=json_mode)
    return resolved


def _git_failure(action: str, result: subprocess.CompletedProcess[str]) -> str:
    """One-line error for a failed git *action*."""
    detail = _one_line(result.stderr or result.stdout) or f"git exited with {result.returncode}"
    return f"{action} failed: {detail}"


def _require_state_repo(state_dir: Path, *, json_mode: bool) -> None:
    """Abort unless *state_dir* is itself a git repository.

    ``git -C <dir>`` on a non-repo directory walks up to the nearest ancestor
    repository, so an unguarded pull/push would act on the surrounding
    project instead of the state directory.
    """
    if not (state_dir / ".git").exists():
        error_exit(
            f"{state_dir} is not a git repository; run 'rebrew binsync init "
            f"{state_dir}' first, or pass --no-git",
            json_mode=json_mode,
        )


@app.command()
def push(
    state_dir: Path = typer.Argument(..., help="BinSync state directory to export into"),
    module: str | None = typer.Option(
        None, "--module", help="Only export this module (e.g. SERVER)"
    ),
    no_git: bool = typer.Option(False, "--no-git", help="Do not stage/commit the state directory"),
    git_push: bool = typer.Option(
        False, "--git-push", help="Push the root and current branches to the remote"
    ),
    remote: str = typer.Option("origin", "--remote", help="Git remote for --git-push"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Export the project into a BinSync state directory and commit it."""
    cfg: ProjectConfig = require_config(target=target, json_mode=json_output)

    # The git-commit helper prints a human "Committed ..." line to stderr; keep
    # the ``--json`` stream pure (warnings still ride in the JSON payload).
    sink = contextlib.redirect_stderr(io.StringIO()) if json_output else contextlib.nullcontext()
    with sink:
        result = export.export_state(
            cfg,
            state_dir,
            dry_run=dry_run,
            json_output=json_output,
            module=module,
            git_commit=(not no_git and not dry_run),
        )

    if git_push and not no_git and not dry_run:
        _require_state_repo(state_dir, json_mode=json_output)
        for ref in ("binsync/__root__", "HEAD"):
            pushed = _run_git(state_dir, "push", remote, ref)
            if pushed.returncode != 0:
                error_exit(_git_failure(f"git push {remote} {ref}", pushed), json_mode=json_output)

    export._print_export_result(result, json_output=json_output, dry_run=dry_run)


@app.command()
def pull(
    state_dir: Path = typer.Argument(..., help="BinSync state directory to import from"),
    no_git: bool = typer.Option(
        False, "--no-git", help="Do not pull the state directory's git repo"
    ),
    accept_binsync: bool = typer.Option(
        False, "--accept-binsync", help="Accept BinSync values for all conflicts"
    ),
    accept_local: bool = typer.Option(
        False, "--accept-local", help="Keep local values for all conflicts (records provenance)"
    ),
    module: str | None = typer.Option(
        None, "--module", help="Only import this module (e.g. SERVER)"
    ),
    create_missing: bool = typer.Option(
        False,
        "--create-missing",
        help="Create STUB files for BinSync functions not in the project catalog",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Pull a BinSync state directory into the project (optional git fast-forward)."""
    if accept_binsync and accept_local:
        error_exit(
            "--accept-binsync and --accept-local are mutually exclusive", json_mode=json_output
        )

    resolved = _resolve_state_dir(state_dir, json_mode=json_output)
    cfg: ProjectConfig = require_config(target=target, json_mode=json_output)

    if not no_git and not dry_run:
        _require_state_repo(resolved, json_mode=json_output)
        pulled = _run_git(resolved, "pull", "--ff-only")
        if pulled.returncode != 0:
            error_exit(
                _git_failure("git pull --ff-only", pulled)
                + "; resolve the state directory's git state by hand, or pass --no-git",
                json_mode=json_output,
            )

    result = importer.import_state(
        cfg,
        resolved,
        dry_run=dry_run,
        json_output=json_output,
        module=module,
        accept_binsync=accept_binsync,
        accept_local=accept_local,
        create_missing=create_missing,
    )
    importer._print_import_result(result, json_output=json_output, dry_run=dry_run)


@app.command()
def summary(
    state_dir: Path = typer.Argument(..., help="BinSync state directory to preview"),
    module: str | None = typer.Option(None, "--module", help="Only this module (e.g. SERVER)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Preview what push and pull would change, without writing or touching git."""
    resolved = _resolve_state_dir(state_dir, json_mode=json_output)
    cfg: ProjectConfig = require_config(target=target, json_mode=json_output)

    push_result = export.export_state(
        cfg,
        resolved,
        dry_run=True,
        json_output=False,
        module=module,
        git_commit=False,
    )
    pull_result = importer.import_state(
        cfg,
        resolved,
        dry_run=True,
        json_output=True,
        module=module,
        accept_binsync=False,
        accept_local=False,
        create_missing=False,
    )

    if json_output:
        json_print(
            {
                "state_dir": str(resolved),
                "target": cfg.target_name,
                "push": {key: push_result.get(key, 0) for key in _PUSH_COUNTS},
                "pull": {key: pull_result.get(key, 0) for key in _PULL_COUNTS},
            }
        )
        return

    console.print(f"[bold]binsync summary[/bold] {resolved} (target {cfg.target_name})")
    console.print(
        "  push: " + ", ".join(f"{push_result.get(key, 0)} {key}" for key in _PUSH_COUNTS)
    )
    console.print(
        "  pull: " + ", ".join(f"{pull_result.get(key, 0)} {key}" for key in _PULL_COUNTS)
    )


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
