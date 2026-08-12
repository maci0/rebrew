"""main.py – Umbrella CLI entry point for rebrew.

Lazily imports and registers all subcommand typer apps so that missing
optional dependencies don't prevent the entire CLI from loading.

Single-command modules are registered as flat ``app.command()`` entries,
avoiding the Typer "group" behaviour of ``add_typer()`` which expects a
``COMMAND [ARGS]...`` token after callback arguments.  Only true
multi-command modules (``extract``, ``cfg``, ``cache``, ``skills``,
``resource``, ``toolchain``) use ``add_typer()``.
"""

import importlib
import logging
import sys
from collections.abc import Callable

import typer
from rich.console import Console

from rebrew.cli import EXIT_ERROR

console = Console(stderr=True)
_stdout_console = Console()

app = typer.Typer(
    help="Compiler-in-the-loop decompilation workbench for binary-matching reversing.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Typical workflow:[/bold]\n\n"
        "rebrew todo · · · · · · · · See what needs work (prioritized by ROI)\n\n"
        "rebrew skeleton 0x<VA> · · · Generate a .c skeleton from address\n\n"
        "rebrew test src/<func>.c · · Compile, byte-compare, and auto-update STATUS\n\n"
        "rebrew diff src/f.c · · · · Show byte diff for near-misses\n\n"
        "rebrew verify · · · · · · · Bulk-verify all reversed functions\n\n"
        "[bold]test vs verify vs match:[/bold]\n\n"
        "rebrew test <file> · · · · · Single function — compile, compare, auto-promote STATUS\n\n"
        "rebrew test --all · · · · ·  Batch — same as verify but always recompiles\n\n"
        "rebrew verify · · · · · · ·  Batch — incremental verify with caching (--compare for CI)\n\n"
        "rebrew match <file> · · · ·  GA engine — iteratively mutate source to find byte match\n\n"
        "[bold]Status ladder (byte match, best → worst):[/bold]\n\n"
        "EXACT · · · · · · 100% byte match\n\n"
        "RELOC · · · · · · Match after masking relocation records\n\n"
        "NEAR_MATCHING · · ≥60% match — use rebrew diff / rebrew prove\n\n"
        "STUB · · · · · · <60% match — rewrite needed\n\n"
        "PROVEN · · · · · Side path: semantic equivalence via rebrew prove "
        "(NEAR_MATCHING only; sticky under test/verify)\n\n"
        "[bold]Exit codes:[/bold]\n\n"
        "0 — Success (all functions matched / no errors)\n\n"
        "1 — Mismatch or test failure (actionable — fix your code)\n\n"
        "2 — Build error or config error (something is broken)\n\n"
        "[dim]All subcommands read project settings from rebrew-project.toml. "
        "Run 'rebrew init' to create a new project, or 'rebrew <cmd> --help' for details.[/dim]"
    ),
)

# ---------------------------------------------------------------------------
# Global options callback
# ---------------------------------------------------------------------------


def _version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        from importlib.metadata import version

        _stdout_console.print(f"rebrew {version('rebrew')}")
        raise typer.Exit()


@app.callback()
def _global_options(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True, help="Increase output verbosity."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress non-essential output."),
) -> None:
    """Compiler-in-the-loop decompilation workbench."""
    if quiet:
        log_level = logging.WARNING
    elif verbose >= 2:
        log_level = logging.DEBUG
    elif verbose == 1:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=log_level,
    )


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
    "skills": "Project Setup",
    # Development — the daily reversing loop
    "skeleton": "Development",
    "test": "Development",
    "verify": "Development",
    "lint": "Development",
    "rename": "Development",
    "split": "Development",
    "merge": "Development",
    # Analysis — understanding the binary and progress
    "status": "Analysis",
    "todo": "Analysis",
    "data": "Analysis",
    "graph": "Analysis",
    "flirt": "Analysis",
    "gen-flirt-pat": "Analysis",
    "identify-library": "Analysis",
    "imports": "Analysis",
    "strings": "Analysis",
    "xrefs": "Analysis",
    "describe": "Analysis",
    "analyze": "Analysis",
    "report": "Analysis",
    "crt-match": "Analysis",
    # Matching — solving byte-level differences
    "match": "Matching",
    "diff": "Matching",
    "extract": "Matching",
    "asm": "Matching",
    "switch": "Matching",
    "prove": "Matching",
    "solutions": "Analysis",
    "round-trip": "Matching",
    # Export & Sync — generating data and syncing with external tools
    "catalog": "Export & Sync",
    "build-db": "Export & Sync",
    "dashboard": "Export & Sync",
    "sync": "Export & Sync",
    "binsync-export": "Export & Sync",
    "binsync-import": "Export & Sync",
    "binsync-diff": "Export & Sync",
}

# Single-command modules – registered as flat commands via app.command().
_SINGLE_COMMANDS: list[tuple[str, str, str]] = [
    ("rename", "rebrew.rename", "Rename a function and update all cross-references."),
    ("test", "rebrew.test", "Compile, byte-compare, and auto-update STATUS annotation."),
    ("verify", "rebrew.verify", "Validate compiled bytes against target binary."),
    ("skeleton", "rebrew.skeleton", "Generate skeleton C files for matching."),
    ("sync", "rebrew.ghidra.cli", "Sync annotations between decomp C files and Ghidra."),
    ("lint", "rebrew.lint", "Lint C annotations."),
    ("match", "rebrew.match", "GA matching engine — single file or batch (--all)."),
    ("diff", "rebrew.diff", "Compile and diff a reversed function against the target binary."),
    ("asm", "rebrew.asm", "Disassemble a function (hex dump or NASM source)."),
    (
        "switch",
        "rebrew.switch",
        "Decode jump-table switch dispatches in a function (case → handler map).",
    ),
    ("init", "rebrew.init", "Initialize a new rebrew project."),
    (
        "intake",
        "rebrew.intake",
        "One-shot binary onboarding: init + toolchain detect + functions + document.",
    ),
    (
        "document-unmatched",
        "rebrew.document_unmatched",
        "Document unmatched functions as STUB skeletons + blockers.",
    ),
    (
        "pdb-info",
        "rebrew.pdb_info",
        "Extract compiler version, flags, and function names from a sibling PDB.",
    ),
    (
        "discover-functions",
        "rebrew.discover",
        "Enumerate functions: rizin aaa/aap + capstone sweep, sizes validated.",
    ),
    ("data", "rebrew.data", "Global data scanner for .data/.rdata/.bss sections."),
    (
        "graph",
        "rebrew.depgraph",
        "Function dependency graph visualization (--cu-map for CU boundaries).",
    ),
    ("status", "rebrew.status", "At-a-glance reversing progress overview."),
    ("todo", "rebrew.todo", "Prioritized action list: what to work on next."),
    ("crt-match", "rebrew.crt_match", "CRT source cross-reference matcher."),
    ("imports", "rebrew.imports", "List PE import-table symbols and detect import stubs."),
    (
        "strings",
        "rebrew.strings",
        "Extract printable strings from data sections with cross-references.",
    ),
    (
        "xrefs",
        "rebrew.xrefs",
        "Cross-reference explorer: find code that references an address.",
    ),
    (
        "describe",
        "rebrew.describe",
        "Per-function recon dossier: callers, callees, strings, imports.",
    ),
    (
        "analyze",
        "rebrew.analyze",
        "One-shot intelligence dossier: toolchain, strings, imports, dispatch, FLIRT.",
    ),
    (
        "report",
        "rebrew.report",
        "Generate a static HTML documentation site for the project.",
    ),
    ("flirt", "rebrew.flirt", "FLIRT signature scanning."),
    (
        "identify-library",
        "rebrew.identify_library",
        "Identify library functions (FLIRT + imports + CRT) into library_*.h.",
    ),
    (
        "gen-flirt-pat",
        "rebrew.gen_flirt_pat",
        "Generate FLIRT .pat files from COFF .lib archives.",
    ),
    ("doctor", "rebrew.doctor", "Diagnostic checks for project health."),
    ("split", "rebrew.split", "Split multi-function C files into single-function files."),
    ("merge", "rebrew.merge", "Merge single-function C files into one multi-function file."),
    ("prove", "rebrew.prove", "Prove semantic equivalence via symbolic execution."),
    (
        "solutions",
        "rebrew.solutions_db",
        "Query the GA solutions database (winning fingerprints + run history).",
    ),
    ("round-trip", "rebrew.round_trip", "Splice matched functions back into target PE and verify."),
    ("build-db", "rebrew.build_db", "Build SQLite coverage database from data JSON."),
    (
        "dashboard",
        "rebrew.dashboard",
        "Serve a read-only web dashboard over the coverage database.",
    ),
    (
        "binsync-export",
        "rebrew.binsync_export",
        "Export annotations to an experimental BinSync state directory.",
    ),
    (
        "binsync-import",
        "rebrew.binsync_import",
        "Import a BinSync state directory into rebrew metadata.",
    ),
    (
        "binsync-diff",
        "rebrew.binsync_diff",
        "Show where rebrew and a BinSync state diverge (read-only).",
    ),
    (
        "catalog",
        "rebrew.catalog",
        "Build coverage catalog, data JSON, CSV/Ghidra exports, and DB.",
    ),
    (
        "similar",
        "rebrew.similar",
        "Find structurally similar functions in the target binary.",
    ),
    (
        "near-diag",
        "rebrew.near_diag",
        "Classify why a NEAR_MATCHING function does not byte-match.",
    ),
]

# Multi-command modules – registered as groups via app.add_typer().
# Only modules with multiple @app.command() subcommands belong here.
_MULTI_COMMANDS: list[tuple[str, str, str]] = [
    ("extract", "rebrew.extract", "Extract and disassemble functions from binary."),
    ("cfg", "rebrew.cfg", "Read and edit rebrew-project.toml programmatically."),
    ("cache", "rebrew.cache_cli", "Manage the compile result cache."),
    ("skills", "rebrew.skills", "Discover and display agent skills bundled with rebrew."),
    ("resource", "rebrew.resource", "Compare / extract PE resource (.rsrc) sections."),
    ("toolchain", "rebrew.toolchain_cli", "Manage toolchains (docker-first, host fallback)."),
]


def _make_stub_cmd(mod_name: str, err: Exception) -> Callable[[], None]:
    """Create a stub command function that reports a missing dependency."""

    def _stub() -> None:
        console.print(f"[red]Error:[/red] could not load '{mod_name}': {err}")
        raise typer.Exit(code=EXIT_ERROR)

    return _stub


def _make_stub_app(mod_name: str, err: Exception) -> typer.Typer:
    """Create a stub Typer app that reports a missing dependency."""
    stub = typer.Typer(help=f"[unavailable] {mod_name}")

    @stub.callback(invoke_without_command=True)
    def _stub_main() -> None:
        console.print(f"[red]Error:[/red] could not load '{mod_name}': {err}")
        raise typer.Exit(code=EXIT_ERROR)

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


def _json_requested(argv: list[str] | None = None) -> bool:
    """True when the invocation asked for JSON output.

    Checks the EXACT ``--json`` / ``--json=true`` tokens — the old
    substring scan (``"--json" in sys.argv``) matched any argument
    containing the literal, e.g. a file named ``x--json.c`` or
    ``--cflags "--json"``, switching the uncaught-exception envelope to
    JSON mode without the user passing ``--json`` (cli-review F11).
    """
    for arg in argv if argv is not None else sys.argv:
        if arg == "--json" or arg == "--json=true":
            return True
    return False


def main() -> None:
    """Package entry point for the ``rebrew`` umbrella CLI."""
    try:
        app()
    except (ValueError, OSError, KeyError, RuntimeError) as e:
        # error_exit() raises typer.Exit, which OUTSIDE click's handler
        # becomes an uncaught-exception traceback with a lying exit 1.
        # Print the friendly message (JSON envelope when --json was passed)
        # and exit with EXIT_ERROR instead.
        from rebrew.cli import EXIT_ERROR

        if _json_requested():
            import json

            print(json.dumps({"error": str(e), "code": EXIT_ERROR}))
        else:
            from rich.console import Console

            Console(stderr=True).print(f"[red]error:[/red] {e}")
        raise SystemExit(EXIT_ERROR) from None
    except KeyboardInterrupt:
        from rich.console import Console

        Console(stderr=True).print("[red]error:[/red] Interrupted by user")
        raise SystemExit(130) from None


if __name__ == "__main__":
    main()
