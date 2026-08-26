"""main.py – Umbrella CLI entry point for rebrew.

Lazily imports and registers all subcommand typer apps so that missing
optional dependencies don't prevent the entire CLI from loading.

Single-command modules are registered as flat ``app.command()`` entries,
avoiding the Typer "group" behaviour of ``add_typer()`` which expects a
``COMMAND [ARGS]...`` token after callback arguments.  Only true
multi-command modules (``extract``, ``cfg``, ``cache``, ``skills``,
``resource``, ``library``, ``toolchain``) use ``add_typer()``.
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
        raise typer.Exit


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
    "blocker": "Analysis",
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
    "diagnose": "Analysis",
    "crt-match": "Analysis",
    "refactor": "Analysis",
    # Matching — solving byte-level differences
    "match": "Matching",
    "diff": "Matching",
    "extract": "Matching",
    "asm": "Matching",
    "switch": "Matching",
    "prove": "Matching",
    "solutions": "Analysis",
    "round-trip": "Matching",
    "postlink": "Matching",
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
    (
        "fix",
        "rebrew.fixup",
        "Make raw decompiler output compilable (DecBench-style fixup: sanitize + inject).",
    ),
    (
        "recover-structs",
        "rebrew.struct_recover",
        "Recover struct definitions from decompiler output (offset evidence → typedefs).",
    ),
    (
        "decompile",
        "rebrew.name_decomp",
        "Decompile a function via kuna/r2ghidra/ghidra, optionally applying known struct names (--named).",
    ),
    ("match", "rebrew.match", "GA matching engine — single file or batch (--all)."),
    ("diff", "rebrew.diff", "Compile and diff a reversed function against the target binary."),
    (
        "postlink",
        "rebrew.postlink",
        "Normalize a built binary's layout onto a reference (import records, .data/.reloc, PE stamps).",
    ),
    (
        "stack-cmp",
        "rebrew.stack_cmp",
        "Compare the compiled function's stack frame against the target binary.",
    ),
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
        "gen-layout",
        "rebrew.gen_layout",
        "Generate linker-script scaffolding from the binary (.def, layout manifest, IAT seed).",
    ),
    (
        "cmake-toolchain",
        "rebrew.cmake_tc",
        "Write a CMake toolchain file that drives a docker toolchain via rebrew-cmake-*.",
    ),
    (
        "order-sources",
        "rebrew.order_sources",
        "Order source files by their first function's original VA (position-aligned .text).",
    ),
    (
        "calibrate-bss",
        "rebrew.calibrate_bss",
        "Calibrate a BSS tail pad so the raw link's .data VirtualSize matches the reference.",
    ),
    (
        "gen-link-stubs",
        "rebrew.gen_link_stubs",
        "Generate a link_stubs.c-style BSS placeholder TU from the data metadata.",
    ),
    (
        "gen-stubs",
        "rebrew.gen_stubs",
        "Generate a stub TU for unresolved linker symbols (LNK2001/LNK2019).",
    ),
    (
        "inline-strings",
        "rebrew.inline_strings",
        "Inline string-literal globals (s_<hint>_<0xADDR>) from the reference binary.",
    ),
    (
        "verify-placement",
        "rebrew.verify_placement",
        "Compare .data symbol VAs of the current build against the data metadata.",
    ),
    (
        "link-sweep",
        "rebrew.link_sweep",
        "Sweep LINK options to reproduce the reference PE header (find stamp-only fields).",
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
    (
        "unpack-lzexe",
        "rebrew.lzexe_cli",
        "Unpack an LZEXE 0.90/0.91 compressed DOS executable.",
    ),
    ("crt-match", "rebrew.crt_match", "CRT source cross-reference matcher."),
    ("imports", "rebrew.imports", "List PE import-table symbols and detect import stubs."),
    (
        "verify-exports",
        "rebrew.exports",
        "Verify the recompiled binary's export table matches the original target.",
    ),
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
    (
        "diagnose",
        "rebrew.diagnose",
        "Explain why a function compiles with its toolchain+flags (resolution trace).",
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
        "binary-similarity",
        "rebrew.binary_similarity",
        "Whole-binary structural similarity vs another binary (versions/DLL+EXE).",
    ),
    (
        "cross-import",
        "rebrew.cross_import",
        "Import matched functions from another target (same code, different VAs).",
    ),
    (
        "near-diag",
        "rebrew.near_diag",
        "Classify why a NEAR_MATCHING function does not byte-match.",
    ),
    (
        "refactor",
        "rebrew.refactor",
        "Analyse the source tree and suggest refactoring opportunities.",
    ),
    (
        "symbol-addrs",
        "rebrew.symbol_addrs",
        "Export function symbols as a splat-style symbol_addrs.csv.",
    ),
    (
        "context",
        "rebrew.context",
        "Emit a universal C context file (types + signatures) for decompiler backends.",
    ),
    (
        "objdiff",
        "rebrew.objdiff_project",
        "Generate an objdiff project (target objects + objdiff.json) for GUI diffing.",
    ),
    (
        "decompme",
        "rebrew.decompme",
        "Upload a function to decomp.me as a collaborative scratch (claim URL returned).",
    ),
]

# Multi-command modules – registered as groups via app.add_typer().
# Only modules with multiple @app.command() subcommands belong here.
_MULTI_COMMANDS: list[tuple[str, str, str]] = [
    ("blocker", "rebrew.blocker", "Manage BLOCKER metadata (set/clear/show) — programmatic only."),
    ("extract", "rebrew.extract", "Extract and disassemble functions from binary."),
    ("cfg", "rebrew.cfg", "Read and edit rebrew-project.toml programmatically."),
    ("cache", "rebrew.cache_cli", "Manage the compile result cache."),
    ("skills", "rebrew.skills", "Discover and display agent skills bundled with rebrew."),
    ("resource", "rebrew.resource", "Compare / extract PE resource (.rsrc) sections."),
    ("library", "rebrew.library", "Per-library toolchain/flags overrides (rebrew-library.toml)."),
    (
        "toolchain",
        "rebrew.toolchain_cli",
        "Manage toolchains (Windows/DOS profiles run in docker).",
    ),
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


#: Entry-point groups for third-party CLI commands (see registry.py).  A
#: ``rebrew.commands`` member is a single-command module (``module`` or
#: ``module:callable``); a ``rebrew.multicommands`` member is a Typer group
#: (``module`` or ``module:app``).  Built-ins register through the packaged
#: lists below; third parties register through these groups without editing
#: host source.
_COMMANDS_ENTRY_POINT_GROUP = "rebrew.commands"
_MULTI_COMMANDS_ENTRY_POINT_GROUP = "rebrew.multicommands"


def _register_single_module(name: str, module: str, fallback_help: str, panel: str | None) -> None:
    """Register a single-command module as a flat ``app.command()``.

    Help text and epilog are pulled from the module's own Typer app (single
    source of truth); *fallback_help* is used only for the stub that stands
    in when the module cannot be imported (missing optional dependency)."""
    try:
        _mod = importlib.import_module(module)
        _mod_help = getattr(_mod.app.info, "help", None) or fallback_help
        _epilog = getattr(_mod.app.info, "epilog", None)
        if not isinstance(_epilog, str):
            _epilog = None
        app.command(name=name, help=_mod_help, epilog=_epilog, rich_help_panel=panel)(_mod.main)
    except (ImportError, AttributeError) as exc:
        app.command(name=name, help=f"[unavailable] {fallback_help}", rich_help_panel=panel)(
            _make_stub_cmd(module, exc)
        )


def _register_multi_module(name: str, module: str, fallback_help: str, panel: str | None) -> None:
    """Register a multi-command module as a Typer group (sub-app)."""
    try:
        _mod = importlib.import_module(module)
        _mod_help = getattr(_mod.app.info, "help", None) or fallback_help
        app.add_typer(_mod.app, name=name, help=_mod_help, rich_help_panel=panel)
    except (ImportError, AttributeError) as exc:
        app.add_typer(
            _make_stub_app(module, exc),
            name=name,
            help=f"[unavailable] {fallback_help}",
            rich_help_panel=panel,
        )


def _register_discovered_commands() -> None:
    """Register third-party commands from the entry-point groups.

    Runs after the built-in lists, so the packaged commands always win the
    name space.  A plugin module that cannot be imported degrades to a stub
    command (same as a built-in with a missing optional dependency); a name
    that collides with an already-registered command is a configuration
    error — :class:`RegistryError` names both origins (single-source
    discipline: a command name has exactly one provider)."""
    from rebrew.registry import RegistryError, entry_point_registrations, import_registration

    existing = {_name for _name, _module, _help in _SINGLE_COMMANDS} | {
        _name for _name, _module, _help in _MULTI_COMMANDS
    }
    for group, is_multi in (
        (_COMMANDS_ENTRY_POINT_GROUP, False),
        (_MULTI_COMMANDS_ENTRY_POINT_GROUP, True),
    ):
        for reg in entry_point_registrations(group):
            if reg.name in existing:
                raise RegistryError(
                    f"duplicate CLI command {reg.name!r} from {reg.origin}: "
                    f"'{reg.name}' is already registered (single-source discipline)"
                )
            # Third-party commands group under a dedicated help panel, so
            # plugin commands are discoverable and clearly separated from
            # the packaged ones.
            _plugin_panel = "Plugins"
            try:
                obj = import_registration(reg)
            except RegistryError as exc:
                # A plugin that cannot be imported degrades to a stub, like
                # a built-in with a missing optional dependency.
                if is_multi:
                    app.add_typer(
                        _make_stub_app(reg.module, exc),
                        name=reg.name,
                        help=f"[unavailable] {reg.name}",
                        rich_help_panel=_plugin_panel,
                    )
                else:
                    app.command(
                        name=reg.name,
                        help=f"[unavailable] {reg.name}",
                        rich_help_panel=_plugin_panel,
                    )(_make_stub_cmd(reg.module, exc))
                existing.add(reg.name)
                continue
            if reg.attr:
                # module:attr form — the object is the command callable / app.
                if is_multi:
                    app.add_typer(obj, name=reg.name, help=reg.name, rich_help_panel=_plugin_panel)
                else:
                    cmd_help = getattr(obj, "__doc__", None) or reg.name
                    app.command(name=reg.name, help=cmd_help, rich_help_panel=_plugin_panel)(obj)
            elif is_multi:
                _register_multi_module(reg.name, reg.module, reg.name, _plugin_panel)
            else:
                _register_single_module(reg.name, reg.module, reg.name, _plugin_panel)
            existing.add(reg.name)


# Register single-command modules as flat commands.
# Help text and epilog are pulled from each module's own Typer app so there is
# a single source of truth.  The _help string in the registry is only used as a
# fallback when the module cannot be imported (stub commands).
for _name, _module, _help in _SINGLE_COMMANDS:
    _register_single_module(_name, _module, _help, _COMMAND_PANELS.get(_name))

# Register multi-command modules as groups (Typer sub-apps).
# help= is intentionally passed here because add_typer() does not inherit the
# child app's help attribute automatically.
for _name, _module, _help in _MULTI_COMMANDS:
    _register_multi_module(_name, _module, _help, _COMMAND_PANELS.get(_name))

# Third-party commands (entry-point groups) — must run last so the packaged
# command lists always win the name space.
_register_discovered_commands()


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
