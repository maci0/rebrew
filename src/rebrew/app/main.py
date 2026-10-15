"""app/main.py — umbrella CLI entry point for rebrew.

The ``rebrew`` app is composed from components.  Every built-in tool is a
:class:`rebrew.app.plugin.CliComponent` in :data:`rebrew.app.builtins.BUILTIN_COMPONENTS`
;
third-party components come from the ``rebrew.commands`` and
``rebrew.multicommands`` entry-point groups.  Both mount through the same
:func:`rebrew.app.plugin.activate` call, so built-ins hold no privileged path and a
component's declared service dependencies decide activation order.
"""

from __future__ import annotations

import typer
from rich.console import Console

from rebrew.app.builtins import BUILTIN_COMPONENTS
from rebrew.app.plugin import (
    CLI_SERVICE,
    CONSOLE_SERVICE,
    CliComponent,
    CoeffectScope,
    Context,
    activate,
    entry_point_components,
)
from rebrew.cli import (
    QUIET_HELP,
    VERBOSE_HELP,
    VERSION_HELP,
    VersionedGroup,
    configure_logging,
    console,
    run_cli,
)

_stdout_console = Console()
_OUTPUT_FORMATS = frozenset({"auto", "text", "json"})


def _accept_output_format(value: str) -> str:
    """Keep a root format of auto, text, or json."""
    if value not in _OUTPUT_FORMATS:
        raise typer.BadParameter("must be auto, text, or json")
    return value


app = typer.Typer(
    cls=VersionedGroup,
    help="Compiler-in-the-loop decompilation workbench for binary-matching reversing.",
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["--help", "-h"]},
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  # Create a project\n"
        "  rebrew init\n\n"
        "  # See reversing progress\n"
        "  rebrew status\n\n"
        "  # Choose the next function\n"
        "  rebrew todo\n\n"
        "  # Generate C source at an address\n"
        "  rebrew skeleton 0x401000\n\n"
        "  # Compile, compare, and record the verdict\n"
        "  rebrew test src/game/f.c\n\n"
        "  # Verify the project and report regressions\n"
        "  rebrew verify --compare\n\n"
        "  # Search for a byte match\n"
        "  rebrew match run src/game/f.c\n\n"
        "  # Machine-readable command document\n"
        "  rebrew schema\n\n"
        "test checks one function; test --all recompiles a batch; verify reuses cached results when inputs are unchanged. Use test --no-promote to measure without recording metadata.\n\n"
        "Use rebrew <command> --help for inputs and examples. Commands with --target use the project default unless you select another target; a final --target lists configured targets.\n\n"
        "The schema command prints the clispec 0.3 document. Before a subcommand, -o or --output selects auto, text, or json; auto stays text. After a command that writes a file, -o remains the destination path.\n\n"
        "Exit codes: 0 success; 1 mismatch or failed check; 2 usage/config/build error; 130 interrupted; 141 output pipe closed."
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
        "-V",
        callback=_version_callback,
        is_eager=True,
        help=VERSION_HELP,
        rich_help_panel="Global options",
    ),
    verbose: int = typer.Option(
        0,
        "--verbose",
        "-v",
        count=True,
        metavar="",
        show_default=False,
        help=VERBOSE_HELP,
        rich_help_panel="Global options",
    ),
    # Logging only. Command tables stay; `lint --quiet` is a different flag.
    # The default level is already WARNING, so this exists to cancel --verbose.
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help=QUIET_HELP,
        rich_help_panel="Global options",
    ),
    output_format: str = typer.Option(
        "auto",
        "--output",
        "-o",
        callback=_accept_output_format,
        help=(
            "Format before the subcommand: auto, text, or json. auto stays text."
            " A command's own -o is a path."
        ),
        rich_help_panel="Global options",
    ),
) -> None:
    """Compiler-in-the-loop decompilation workbench."""
    del output_format  # read from the click context by cli._apply_output_choice
    configure_logging(verbose, quiet=quiet)


# ---------------------------------------------------------------------------
# Composition
# ---------------------------------------------------------------------------


def cli_components() -> tuple[list[CliComponent], list[str]]:
    """The packaged components plus every third-party CLI plugin.

    Built-in names are registered first; a plugin that collides with one is
    ignored with a warning rather than shadowing it (Typer's command map is
    name-keyed, so last registration would otherwise win).  Warnings come
    back as data: discovery runs before any context exists, so the caller
    prints them through CONSOLE_SERVICE.
    """
    components = list(BUILTIN_COMPONENTS)
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


# Import-time composition: importing this module mounts the CLI (library
# callers introspect `app` without running the CLI). The module owns the
# fiber, so the inverse accumulator is held instead of dropped —
# compose()'s contract. Lifetime is the process: nothing unloads the
# components before interpreter exit, so no earlier teardown point exists.
_COMPOSED: tuple[Context, CoeffectScope] = compose()


def main() -> None:
    """Package entry point for the ``rebrew`` umbrella CLI."""
    run_cli(app)


if __name__ == "__main__":
    main()
