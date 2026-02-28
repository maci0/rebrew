"""main.py – Umbrella CLI entry point for rebrew.

Lazily imports and registers all subcommand typer apps so that missing
optional dependencies don't prevent the entire CLI from loading.

Single-command modules are registered as flat ``app.command()`` entries,
avoiding the Typer "group" behaviour of ``add_typer()`` which expects a
``COMMAND [ARGS]...`` token after callback arguments.  Only true
multi-command modules (currently only ``cfg``) use ``add_typer()``.
"""

import importlib
import sys
from collections.abc import Callable

import typer

app = typer.Typer(
    help="Compiler-in-the-loop decompilation workbench for binary-matching reversing.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Typical workflow:[/bold]

rebrew next                  Pick the next function to reverse

rebrew skeleton 0x<VA>       Generate a .c skeleton from address

rebrew test src/<func>.c     Compile and byte-compare against target

rebrew match --diff-only f   Show byte diff for near-misses

rebrew verify                Bulk-verify all reversed functions

rebrew catalog               Regenerate coverage catalog + JSON

[dim]All subcommands read project settings from rebrew-project.toml.
Run 'rebrew init' to create a new project, or 'rebrew <cmd> --help' for details.[/dim]""",
)

# ---------------------------------------------------------------------------
# Subcommand registry
# ---------------------------------------------------------------------------

# Single-command modules – registered as flat commands via app.command().
_SINGLE_COMMANDS: list[tuple[str, str, str]] = [
    ("rename", "rebrew.rename", "Rename a function and update all cross-references."),
    ("test", "rebrew.test", "Quick compile-and-compare for reversed functions."),
    ("verify", "rebrew.verify", "Validate compiled bytes against target binary."),
    ("next", "rebrew.next", "Find the next best functions to work on."),
    ("skeleton", "rebrew.skeleton", "Generate skeleton C files for matching."),
    (
        "catalog",
        "rebrew.catalog",
        "Build coverage catalog, data JSON, and optional CSV/Ghidra exports.",
    ),
    ("sync", "rebrew.sync", "Sync annotations between decomp C files and Ghidra."),
    ("lint", "rebrew.lint", "Lint C annotations."),
    ("extract", "rebrew.extract", "Extract and disassemble functions from binary."),
    ("match", "rebrew.match", "GA engine for binary matching (diff, flag-sweep, GA)."),
    ("ga", "rebrew.ga", "Batch GA runner and flag sweep for STUB and MATCHING functions."),
    ("asm", "rebrew.asm", "Disassemble original bytes."),
    ("build-db", "rebrew.build_db", "Build SQLite coverage database."),
    ("init", "rebrew.init", "Initialize a new rebrew project."),
    ("status", "rebrew.status", "Project reversing status overview."),
    ("data", "rebrew.data", "Global data scanner for .data/.rdata/.bss sections."),
    ("graph", "rebrew.depgraph", "Function dependency graph visualization."),
    ("promote", "rebrew.promote", "Test + atomically update STATUS annotation."),
    ("triage", "rebrew.triage", "Cold-start triage: FLIRT scan + coverage summary."),
    ("flirt", "rebrew.flirt", "FLIRT signature scanning."),
    ("nasm", "rebrew.nasm", "NASM assembly extraction."),
    ("doctor", "rebrew.doctor", "Diagnostic checks for project health."),
]

# Multi-command modules – registered as groups via app.add_typer().
# Only modules with multiple @app.command() subcommands belong here.
_MULTI_COMMANDS: list[tuple[str, str, str]] = [
    ("cfg", "rebrew.cfg", "Read and edit rebrew-project.toml programmatically."),
]


def _make_stub_cmd(mod_name: str, err: ImportError) -> Callable[[], None]:
    """Create a stub command function that reports a missing dependency."""

    def _stub() -> None:
        print(f"Error: could not load '{mod_name}': {err}", file=sys.stderr)
        raise typer.Exit(code=1)

    return _stub


def _make_stub_app(mod_name: str, err: ImportError) -> typer.Typer:
    """Create a stub Typer app that reports a missing dependency."""
    stub = typer.Typer(help=f"[unavailable] {mod_name}")

    @stub.callback(invoke_without_command=True)
    def _stub_main() -> None:
        print(f"Error: could not load '{mod_name}': {err}", file=sys.stderr)
        raise typer.Exit(code=1)

    return stub


# Register single-command modules as flat commands.
# Help text and epilog are pulled from each module's own Typer app so there is
# a single source of truth.  The _help string in the registry is only used as a
# fallback when the module cannot be imported (stub commands).
for _name, _module, _help in _SINGLE_COMMANDS:
    try:
        _mod = importlib.import_module(_module)
        _mod_help = getattr(_mod.app.info, "help", None) or _help
        _epilog = getattr(_mod.app.info, "epilog", None)
        if not isinstance(_epilog, str):
            _epilog = None
        app.command(name=_name, help=_mod_help, epilog=_epilog)(_mod.main)
    except ImportError as _exc:
        app.command(name=_name, help=f"[unavailable] {_help}")(_make_stub_cmd(_module, _exc))

# Register multi-command modules as groups (Typer sub-apps).
# help= is intentionally passed here because add_typer() does not inherit the
# child app's help attribute automatically.
for _name, _module, _help in _MULTI_COMMANDS:
    try:
        _mod = importlib.import_module(_module)
        _mod_help = getattr(_mod.app.info, "help", None) or _help
        app.add_typer(_mod.app, name=_name, help=_mod_help)
    except ImportError as _exc:
        app.add_typer(_make_stub_app(_module, _exc), name=_name, help=f"[unavailable] {_help}")


def main() -> None:
    """Package entry point for the ``rebrew`` umbrella CLI."""
    app()


if __name__ == "__main__":
    main()
