"""rename_batch.py - Run a list of renames in one process.

Each line of the plan file holds the arguments of one ``rebrew source rename``.
The lines run in order through that command's planner and writer, each against
the tree the lines before it left. A refused line is reported and the lines
after it still run. One process parses each source once and later lines reuse
the parse caches, where separate commands each read the whole tree again.
"""

lazy import contextlib
lazy import io
lazy import shlex
lazy from pathlib import Path
lazy from typing import Any

import typer

from rebrew.cli import (
    EXIT_MISMATCH,
    CommandExit,
    TargetOption,
    console,
    error_exit,
    json_print,
    require_config,
    untrusted_text,
)
lazy from rebrew.metadata.bindings import BindingConflictError, strict_bindings
lazy from rebrew.utils import rel_display_path

#: Options a plan line may not carry: the batch sets the first two for every line.
_LINE_REFUSED_OPTIONS = ("--dry-run", "--json", "--help", "-h")

app = typer.Typer(
    help="Run a list of renames in one process, each line one `rebrew source rename`.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew source rename-batch renames.txt  # Apply every line\n\n"
        "  # Preview each line\n"
        "  rebrew source rename-batch renames.txt --dry-run --json\n\n"
        "[dim]A plan line holds the arguments of one rebrew source rename, such as "
        "'GOLD.0x405000 gm_Init --shared-definition'; blank lines and # comments are skipped. "
        "Lines apply in order and each sees the lines before it; a refused line is reported "
        "and the rest still run. --dry-run previews every line against the unchanged tree. "
        "Exit 1 when any line was refused.[/dim]"
    ),
)


def _rename_command() -> Any:
    """The ``rebrew source rename`` click command, used here only to parse a plan line."""
    from rebrew.source import rename

    parser = typer.Typer()
    parser.command()(rename.main)
    return typer.main.get_command(parser)


def _run_line(
    command: Any, arguments: list[str], target: str | None, dry_run: bool
) -> dict[str, Any]:
    """One plan line's outcome: the rename's report fields, or ``error`` with the refusal."""
    from typer._click.exceptions import ClickException

    from rebrew.source import rename

    blocked = [option for option in _LINE_REFUSED_OPTIONS if option in arguments]
    if blocked:
        return {"error": f"{blocked[0]} is not allowed in a plan line"}
    try:
        params = command.make_context("rebrew source rename", list(arguments)).params
    except ClickException as exc:
        return {"error": exc.format_message()}
    line_target = params.pop("target") or target
    params.pop("dry_run")
    params.pop("json_output")
    # A refusal prints its JSON envelope before it raises; the batch reports it once, below.
    try:
        with contextlib.redirect_stderr(io.StringIO()), strict_bindings():
            cfg = require_config(target=line_target, json_mode=True)
            plan, extra, updated = rename.run_rename(
                cfg,
                params.pop("target_ident"),
                params.pop("new_name"),
                **params,
                dry_run=dry_run,
                json_output=True,
            )
    except CommandExit as exc:
        return {"error": exc.message}
    except typer.Exit as exc:
        return {"error": f"rename exited with code {exc.exit_code}"}
    except BindingConflictError as exc:
        return {"error": str(exc)}
    # The failures `run_cli` turns into one error line for a single command.
    except (ValueError, OSError, KeyError, RuntimeError) as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    return {**plan.as_dict(getattr(cfg, "root", None)), **extra, "files_updated": updated}


@app.callback(invoke_without_command=True)
def main(
    plan_file: Path = typer.Argument(
        ...,
        metavar="plan_file",
        help="Text file: the arguments of one rebrew source rename per line",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Run a list of renames in one process, each line one `rebrew source rename`."""
    # The project is checked before the plan: a missing config is the first error either way.
    cfg = require_config(target=target, json_mode=json_output)
    try:
        text = plan_file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        error_exit(f"cannot read plan file {plan_file}: {exc}", json_mode=json_output)
    command = _rename_command()
    items: list[dict[str, Any]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        try:
            arguments = shlex.split(line, comments=True)
        except ValueError as exc:
            items.append({"line": number, "arguments": [], "error": f"unparsable line: {exc}"})
            continue
        if arguments:
            outcome = _run_line(command, arguments, target, dry_run)
            items.append({"line": number, "arguments": arguments, **outcome})
    refused = sum(1 for item in items if "error" in item)
    if json_output:
        json_print(
            {
                "dry_run": dry_run,
                "renamed": len(items) - refused,
                "refused": refused,
                "items": items,
            }
        )
    else:
        verb = "would rename" if dry_run else "renamed"
        for item in items:
            if "error" in item:
                console.print(
                    f"line {item['line']}: [red]refused[/red]: {untrusted_text(item['error'])}",
                    highlight=False,
                )
            else:
                console.print(
                    f"line {item['line']}: {verb} {item['old_name']} → {item['new_name']} "
                    f"({item['files_updated']} files)",
                    highlight=False,
                )
        shown = rel_display_path(plan_file, getattr(cfg, "root", None))
        console.print(f"{shown}: {len(items) - refused} {verb}, {refused} refused")
    if refused:
        raise typer.Exit(code=EXIT_MISMATCH)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
