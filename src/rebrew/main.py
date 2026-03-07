"""main.py – Umbrella CLI entry point for rebrew.

Lazily imports and registers all subcommand typer apps so that missing
optional dependencies don't prevent the entire CLI from loading.

Single-command modules are registered as flat ``app.command()`` entries,
avoiding the Typer "group" behaviour of ``add_typer()`` which expects a
``COMMAND [ARGS]...`` token after callback arguments.  Only true
multi-command modules (currently only ``cfg``) use ``add_typer()``.
"""

import importlib
from collections.abc import Callable

import typer

from rebrew import cli

app = typer.Typer(
    help="Compiler-in-the-loop decompilation workbench for binary-matching reversing.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Typical workflow:[/bold]

rebrew todo                  See what needs work (prioritized by ROI)

rebrew skeleton 0x<VA>       Generate a .c skeleton from address

rebrew test src/<func>.c     Compile, byte-compare, and auto-update STATUS

rebrew diff src/f.c          Show byte diff for near-misses

rebrew verify                Bulk-verify all reversed functions

[bold]Exit codes:[/bold]

0   Success (all functions matched / no errors)

1   Mismatch or test failure (actionable — fix your code)

2   Build error or config error (something is broken)

[dim]All subcommands read project settings from rebrew-project.toml.
Run 'rebrew init' to create a new project, or 'rebrew <cmd> --help' for details.[/dim]""",
)

# ---------------------------------------------------------------------------
# Global options callback
# ---------------------------------------------------------------------------


@app.callback()
def _global_options(
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True, help="Increase output verbosity."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress non-essential output."),
) -> None:
    """Compiler-in-the-loop decompilation workbench."""
    if quiet:
        cli.verbosity = -1
    elif verbose:
        cli.verbosity = verbose


# ---------------------------------------------------------------------------
# Subcommand registry
# ---------------------------------------------------------------------------

# Command panel groupings for rich help output.
# Style: short descriptive nouns, 5 balanced groups.
_COMMAND_PANELS: dict[str, str] = {
    # Project Setup — one-time / infrequent management tasks
    "init": "Project Setup",
    "doctor": "Project Setup",
    "cfg": "Project Setup",
    "cache": "Project Setup",
    # Development — the daily reversing loop
    "skeleton": "Development",
    "test": "Development",
    "verify": "Development",
    "lint": "Development",
    "rename": "Development",
    "split": "Development",
    "merge": "Development",
    # Analysis — understanding the binary and progress
    "todo": "Analysis",
    "data": "Analysis",
    "graph": "Analysis",
    "flirt": "Analysis",
    "crt-match": "Analysis",
    # Matching — solving byte-level differences
    "match": "Matching",
    "diff": "Matching",
    "ga": "Matching",
    "extract": "Matching",
    "asm": "Matching",
    "prove": "Matching",
    # Export & Sync — generating data and syncing with external tools
    "catalog": "Export & Sync",
    "sync": "Export & Sync",
    "binsync-export": "Export & Sync",
}

# Single-command modules – registered as flat commands via app.command().
_SINGLE_COMMANDS: list[tuple[str, str, str]] = [
    ("rename", "rebrew.rename", "Rename a function and update all cross-references."),
    ("test", "rebrew.test", "Compile, byte-compare, and auto-update STATUS annotation."),
    ("verify", "rebrew.verify", "Validate compiled bytes against target binary."),
    ("skeleton", "rebrew.skeleton", "Generate skeleton C files for matching."),
    ("sync", "rebrew.ghidra.cli", "Sync annotations between decomp C files and Ghidra."),
    ("lint", "rebrew.lint", "Lint C annotations."),
    ("extract", "rebrew.extract", "Extract and disassemble functions from binary."),
    ("match", "rebrew.match", "Flag sweep or GA matching engine."),
    ("diff", "rebrew.diff", "Compile and diff a reversed function against the target binary."),
    ("ga", "rebrew.ga", "Batch GA runner across all STUB/MATCHING functions."),
    ("asm", "rebrew.asm", "Disassemble a function (hex dump or NASM source)."),
    ("init", "rebrew.init", "Initialize a new rebrew project."),
    ("data", "rebrew.data", "Global data scanner for .data/.rdata/.bss sections."),
    (
        "graph",
        "rebrew.depgraph",
        "Function dependency graph visualization (--cu-map for CU boundaries).",
    ),
    ("todo", "rebrew.todo", "Prioritized action list: what to work on next."),
    ("crt-match", "rebrew.crt_match", "CRT source cross-reference matcher."),
    ("flirt", "rebrew.flirt", "FLIRT signature scanning."),
    ("doctor", "rebrew.doctor", "Diagnostic checks for project health."),
    ("split", "rebrew.split", "Split multi-function C files into single-function files."),
    ("merge", "rebrew.merge", "Merge single-function C files into one multi-function file."),
    ("prove", "rebrew.prove", "Prove semantic equivalence via symbolic execution."),
    (
        "binsync-export",
        "rebrew.binsync_export",
        "Export annotations to an experimental BinSync state directory.",
    ),
]

# Multi-command modules – registered as groups via app.add_typer().
# Only modules with multiple @app.command() subcommands belong here.
_MULTI_COMMANDS: list[tuple[str, str, str]] = [
    ("cfg", "rebrew.cfg", "Read and edit rebrew-project.toml programmatically."),
    ("cache", "rebrew.cache_cli", "Manage the compile result cache."),
    ("catalog", "rebrew.catalog", "Build coverage catalog, data JSON, CSV/Ghidra exports, and DB."),
]


def _make_stub_cmd(mod_name: str, err: Exception) -> Callable[[], None]:
    """Create a stub command function that reports a missing dependency."""

    def _stub() -> None:
        typer.echo(f"Error: could not load '{mod_name}': {err}", err=True)
        raise typer.Exit(code=1)

    return _stub


def _make_stub_app(mod_name: str, err: Exception) -> typer.Typer:
    """Create a stub Typer app that reports a missing dependency."""
    stub = typer.Typer(help=f"[unavailable] {mod_name}")

    @stub.callback(invoke_without_command=True)
    def _stub_main() -> None:
        typer.echo(f"Error: could not load '{mod_name}': {err}", err=True)
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
        _panel = _COMMAND_PANELS.get(_name)
        app.command(name=_name, help=_mod_help, epilog=_epilog, rich_help_panel=_panel)(_mod.main)
    except (ImportError, AttributeError) as _exc:
        _panel = _COMMAND_PANELS.get(_name)
        app.command(name=_name, help=f"[unavailable] {_help}", rich_help_panel=_panel)(
            _make_stub_cmd(_module, _exc)
        )

# Register multi-command modules as groups (Typer sub-apps).
# help= is intentionally passed here because add_typer() does not inherit the
# child app's help attribute automatically.
for _name, _module, _help in _MULTI_COMMANDS:
    try:
        _mod = importlib.import_module(_module)
        _mod_help = getattr(_mod.app.info, "help", None) or _help
        _panel = _COMMAND_PANELS.get(_name)
        app.add_typer(_mod.app, name=_name, help=_mod_help, rich_help_panel=_panel)
    except (ImportError, AttributeError) as _exc:
        _panel = _COMMAND_PANELS.get(_name)
        app.add_typer(
            _make_stub_app(_module, _exc),
            name=_name,
            help=f"[unavailable] {_help}",
            rich_help_panel=_panel,
        )


def main() -> None:
    """Package entry point for the ``rebrew`` umbrella CLI."""
    try:
        app()
    except (ValueError, FileNotFoundError, KeyError, RuntimeError) as e:
        from rebrew.cli import error_exit

        error_exit(str(e))
    except KeyboardInterrupt:
        from rebrew.cli import error_exit

        error_exit("Interrupted by user", code=130)


if __name__ == "__main__":
    main()
