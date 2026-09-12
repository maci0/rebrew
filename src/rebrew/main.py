"""main.py — umbrella CLI entry point for rebrew.

The ``rebrew`` app is composed from components.  Every built-in tool is a
:class:`rebrew.plugin.CliComponent` in :data:`rebrew.builtins.BUILTIN_COMPONENTS`;
third-party components come from the ``rebrew.commands`` and
``rebrew.multicommands`` entry-point groups.  Both mount through the same
:func:`rebrew.plugin.activate` call, so built-ins hold no privileged path and a
component's declared service dependencies decide activation order.
"""

from __future__ import annotations

import logging
import sys

import typer
from rich.console import Console

from rebrew.builtins import BUILTIN_COMPONENTS
from rebrew.cli import EXIT_ERROR
from rebrew.plugin import (
    CLI_SERVICE,
    CONSOLE_SERVICE,
    CliComponent,
    Context,
    activate,
    entry_point_components,
)

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
# Composition
# ---------------------------------------------------------------------------


def cli_components() -> list[CliComponent]:
    """The packaged components plus every third-party CLI plugin.

    Built-in names are registered first; a plugin that collides with one is
    ignored with a warning rather than shadowing it (Typer's command map is
    name-keyed, so last registration would otherwise win).
    """
    components = list(BUILTIN_COMPONENTS)
    components.extend(entry_point_components({c.name for c in components}, console))
    return components


def compose() -> Context:
    """Build the CLI context and activate every component on it."""
    ctx = Context()
    ctx.provide(CLI_SERVICE, app)
    ctx.provide(CONSOLE_SERVICE, console)
    activate(cli_components(), ctx)
    return ctx


_CONTEXT = compose()


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
        if _json_requested():
            import json

            print(json.dumps({"error": str(e), "code": EXIT_ERROR}))
        else:
            Console(stderr=True).print(f"[red]error:[/red] {e}")
        raise SystemExit(EXIT_ERROR) from None
    except KeyboardInterrupt:
        Console(stderr=True).print("[red]error:[/red] Interrupted by user")
        raise SystemExit(130) from None


if __name__ == "__main__":
    main()
