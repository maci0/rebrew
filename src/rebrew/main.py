"""main.py – Umbrella CLI entry point for rebrew.

Lazily imports and registers all subcommand typer apps so that missing
optional dependencies don't prevent the entire CLI from loading.
"""

import importlib
import sys

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

[dim]All subcommands read project settings from rebrew.toml.
Run 'rebrew init' to create a new project, or 'rebrew <cmd> --help' for details.[/dim]""",
)

# Lazy-load subcommand modules to avoid crashing the entire CLI
# when an optional dependency is missing for one subcommand.
_SUBCOMMANDS: list[tuple[str, str, str]] = [
    ("test", "rebrew.test", "Quick compile-and-compare for reversed functions."),
    ("verify", "rebrew.verify", "Validate compiled bytes against original DLL."),
    ("next", "rebrew.next", "Find the next best functions to work on."),
    ("skeleton", "rebrew.skeleton", "Generate skeleton C files for matching."),
    ("catalog", "rebrew.catalog", "Build JSON coverage catalogs for the web UI."),
    ("sync", "rebrew.sync", "Sync GHIDRA annotations with rebrew."),
    ("lint", "rebrew.lint", "Lint C annotations."),
    ("batch", "rebrew.batch", "Batch extract assembly or functions."),
    ("match", "rebrew.match", "GA engine for binary matching (diff, flag-sweep, GA)."),
    ("ga", "rebrew.ga", "Batch GA runner for STUB functions."),
    ("asm", "rebrew.asm", "Disassemble original bytes."),
    ("build-db", "rebrew.build_db", "Build SQLite coverage database."),
    ("init", "rebrew.init", "Initialize a new rebrew project."),
    ("cfg", "rebrew.cfg", "Read and edit rebrew.toml programmatically."),
    ("status", "rebrew.status", "Project reversing status overview."),
    ("data", "rebrew.data", "Global data scanner for .data/.rdata/.bss sections."),
    ("graph", "rebrew.depgraph", "Function dependency graph visualization."),
    ("promote", "rebrew.promote", "Test + atomically update STATUS annotation."),
    ("triage", "rebrew.triage", "Cold-start triage: FLIRT scan + coverage summary."),
]

for _name, _module, _help in _SUBCOMMANDS:
    try:
        _mod = importlib.import_module(_module)
        app.add_typer(_mod.app, name=_name, help=_help)
    except ImportError as _exc:
        # Create a stub that reports the missing dependency
        def _make_stub(mod_name: str, err: ImportError) -> typer.Typer:
            stub = typer.Typer(help=f"[unavailable] {mod_name}")

            @stub.callback(invoke_without_command=True)
            def _stub_main() -> None:
                print(f"Error: could not load '{mod_name}': {err}", file=sys.stderr)
                raise typer.Exit(code=1)

            return stub

        app.add_typer(_make_stub(_module, _exc), name=_name, help=f"[unavailable] {_help}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
