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
import time

import typer
from rich.console import Console

from rebrew.builtins import BUILTIN_COMPONENTS
from rebrew.cli import EXIT_ERROR
from rebrew.plugin import (
    CLI_SERVICE,
    CONSOLE_SERVICE,
    CliComponent,
    CoeffectScope,
    Context,
    Panel,
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
        "rebrew test --all · · · · ·  Batch — verify's engine, always recompiles\n\n"
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
    """Print version and exit.

    The module's ``__version__`` -- not ``importlib.metadata``.  Packaging reads
    that attribute too (``[tool.setuptools.dynamic] version = {attr =
    "rebrew.__version__"}``), but the *installed* metadata is baked when the
    package is installed, so in an editable checkout it drifts as soon as
    ``__init__.py`` changes and ``rebrew --version`` starts lying about the code
    it is running.
    """
    if value:
        from rebrew import __version__

        _stdout_console.print(f"rebrew {__version__}")
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
    # Force UTC asctime: the default converter is localtime, so a host in
    # Europe/Warsaw (or any DST zone) stamps verbose logs with a wall clock
    # that jumps or repeats on transition nights and disagrees with CI
    # (TZ=UTC).  Match status/verify metadata, which already label UTC.
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S UTC",
        level=log_level,
    )
    # basicConfig is a no-op when root already has handlers; still force UTC
    # on whatever formatter is installed so a prior localtime config cannot
    # leak into -v output.
    for handler in logging.root.handlers:
        formatter = handler.formatter
        if formatter is not None:
            formatter.converter = time.gmtime
            formatter.datefmt = "%Y-%m-%d %H:%M:%S UTC"


# ---------------------------------------------------------------------------
# Composition
# ---------------------------------------------------------------------------


#: Tools mounted on the umbrella app beside the packaged manifest.
#:
#: ``import-splat`` registers here rather than in ``builtins.BUILTIN_COMPONENTS``
#: because that manifest is pinned to the bundled agent skills
#: (``tests/test_docs_hygiene.py`` asserts every packaged component is named in
#: one), and this importer has no skill yet.  The component is otherwise
#: identical: fold this entry into ``builtins.py`` alongside a SKILL.md mention
#: when it gets one.
_EXTRA_COMPONENTS: tuple[CliComponent, ...] = (
    CliComponent(
        name="import-splat",
        module="rebrew.splat_config",
        help="Seed a rebrew project from a splat config (dry run by default).",
        panel=Panel.PROJECT_SETUP,
        is_group=False,
    ),
)


def cli_components() -> tuple[list[CliComponent], list[str]]:
    """The packaged components plus every third-party CLI plugin.

    Built-in names are registered first; a plugin that collides with one is
    ignored with a warning rather than shadowing it (Typer's command map is
    name-keyed, so last registration would otherwise win).  Warnings come
    back as data: discovery runs before any context exists, so the caller
    prints them through CONSOLE_SERVICE.
    """
    components = list(BUILTIN_COMPONENTS)
    components.extend(_EXTRA_COMPONENTS)
    discovered, warnings = entry_point_components({c.name for c in components})
    components.extend(discovered)
    return components, warnings


def compose() -> tuple[Context, CoeffectScope]:
    """Build the CLI context and activate every component on it.

    Returns the context and its scope: the scope stays reactive, so a
    service provided later still activates its dependents — and the
    caller holds the fiber for teardown instead of dropping it.
    """
    ctx = Context()
    ctx.provide(CLI_SERVICE, app)
    ctx.provide(CONSOLE_SERVICE, console)
    components, warnings = cli_components()
    for warning in warnings:
        ctx.resolve(CONSOLE_SERVICE).print(f"[yellow]warning:[/yellow] {warning}")
    return ctx, activate(components, ctx)


compose()


def _json_requested(argv: list[str] | None = None) -> bool:
    """True when the invocation asked for JSON output.

    Checks the EXACT ``--json`` / ``--json=true`` tokens — the old
    substring scan (``"--json" in sys.argv``) matched any argument
    containing the literal, e.g. a file named ``x--json.c`` or
    ``--cflags "--json"``, switching the uncaught-exception envelope to
    JSON mode without the user passing ``--json`` (cli-review F11).
    """
    return any(arg in ("--json", "--json=true") for arg in (sys.argv if argv is None else argv))


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

            print(json.dumps({"error": str(e), "code": EXIT_ERROR}, indent=2))
        else:
            Console(stderr=True).print(f"[red]error:[/red] {e}")
        raise SystemExit(EXIT_ERROR) from None
    except KeyboardInterrupt:
        Console(stderr=True).print("[red]error:[/red] Interrupted by user")
        raise SystemExit(130) from None


if __name__ == "__main__":
    main()
