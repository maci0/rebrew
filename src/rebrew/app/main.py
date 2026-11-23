"""app/main.py — umbrella CLI entry point for rebrew.

The ``rebrew`` app is composed from components.  Every built-in tool is a
:class:`rebrew.app.plugin.CliComponent` in
:data:`rebrew.app.builtins.BUILTIN_COMPONENTS`; third-party components come from the ``rebrew.commands`` and
``rebrew.multicommands`` entry-point groups.  Both mount through the same
:func:`rebrew.app.plugin.activate` call, so built-ins hold no privileged path and a
component's declared service dependencies decide activation order.

``app`` is composed on first access. :func:`main` mounts only the invoked
command when argv names a built-in after root options alone, which skips
importing the other ~130 command modules; anything else runs on ``app``.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING
lazy import gc
lazy import os
lazy import re
lazy import sys
lazy import threading

import typer
from rich.console import Console

from rebrew.cli import (
    QUIET_HELP,
    VERBOSE_HELP,
    VERSION_HELP,
    VersionedGroup,
    configure_logging,
    console,
    run_cli,
)
lazy from rebrew import telemetry
lazy from rebrew.app.builtins import BUILTIN_COMPONENTS
lazy from rebrew.app.plugin import (
    CLI_SERVICE,
    CONSOLE_SERVICE,
    CliComponent,
    CoeffectScope,
    Context,
    activate,
    entry_point_components,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

_stdout_console = Console()
_OUTPUT_FORMATS = frozenset({"auto", "text", "json"})


def _accept_output_format(value: str) -> str:
    """Keep a root format of auto, text, or json."""
    if value not in _OUTPUT_FORMATS:
        raise typer.BadParameter("must be auto, text, or json")
    return value


def _new_root() -> typer.Typer:
    """An umbrella app with the global options and no commands mounted."""
    root = typer.Typer(
        cls=VersionedGroup,
        help="Compiler-in-the-loop decompilation workbench for binary-matching reversing.",
        rich_markup_mode="rich",
        context_settings={"help_option_names": ["--help", "-h"]},
        epilog=_ROOT_EPILOG,
    )
    root.callback()(_global_options)
    return root


_ROOT_EPILOG = (
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
    "test checks one function. test --all rechecks every file in the selected target without saved verdicts. verify covers every function and reuses cached verdicts unless --no-cache. --all-targets repeats a command for every configured target. Use test --no-promote to measure without recording metadata.\n\n"
    "Use rebrew <command> --help for inputs and examples. Commands with --target use the project default unless you select another target; a final --target lists configured targets.\n\n"
    "The schema command prints the clispec 0.3 document and stays JSON under -o text. Before any other subcommand, -o or --output selects auto, text, or json; auto stays text. After a command that writes a file, -o remains the destination path.\n\n"
    "Exit codes: 0 success; 1 mismatch or failed check; 2 usage/config/build error; 130 interrupted; 141 output pipe closed."
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
    it is running. An explicit ``-o json`` before the version flag selects one
    JSON document on stdout, like every other command; text stays the default.
    """
    if value:
        from rebrew import __version__
        from rebrew.cli import json_mode_active, json_print

        if json_mode_active():
            json_print({"name": "rebrew", "version": __version__})
        else:
            _stdout_console.print(f"rebrew {__version__}")
        raise typer.Exit


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


def _cli_context(root: typer.Typer) -> Context:
    """A context providing *root* as the CLI service and the shared console."""
    ctx = Context()
    ctx.provide(CLI_SERVICE, root)
    ctx.provide(CONSOLE_SERVICE, console)
    return ctx


#: The umbrella app; :func:`compose` mounts every component on it.
_UMBRELLA = _new_root()
_COMPOSE_LOCK = threading.Lock()


def compose() -> tuple[Context, CoeffectScope]:
    """Build the CLI context and activate every component on the umbrella.

    Returns the context and its scope: the scope stays reactive, so a
    service provided later still activates its dependents — and the
    caller holds the fiber for teardown instead of dropping it.
    """
    ctx = _cli_context(_UMBRELLA)
    components, warnings = cli_components()
    for warning in warnings:
        ctx.resolve(CONSOLE_SERVICE).print(f"[yellow]warning:[/yellow] {warning}")
    return ctx, activate(components, ctx)


# `app` and `_COMPOSED` are composed on first access (module __getattr__), so
# library callers that introspect `app` see every command while a CLI run of
# one built-in (main) composes nothing else. The module owns the fiber, so the
# inverse accumulator is held instead of dropped (compose()'s contract).
# Lifetime is the process: nothing unloads the components before interpreter
# exit, so no earlier teardown point exists.
app: typer.Typer
_COMPOSED: tuple[Context, CoeffectScope]


def __getattr__(name: str) -> object:
    if name not in ("app", "_COMPOSED"):
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    with _COMPOSE_LOCK:
        if "_COMPOSED" not in globals():
            globals()["_COMPOSED"] = compose()
            globals()["app"] = _UMBRELLA
    return globals()[name]


#: Root options that take no value, and those that take the next argument.
_ROOT_FLAGS = frozenset({"--version", "-V", "--verbose", "--quiet", "-q"})
_ROOT_VALUE_OPTIONS = frozenset({"--output", "-o"})


def _invoked_builtin(argv: list[str]) -> CliComponent | None:
    """The built-in component *argv* runs, when only root options precede its name.

    ``None`` for anything else (no command, ``--help``, a plugin or unknown
    name, an option this scan does not know): the caller mounts the whole
    umbrella, which handles every invocation. A plugin cannot take a built-in
    name, so a built-in name always selects that built-in.
    """
    tokens = iter(argv)
    for token in tokens:
        if token in _ROOT_VALUE_OPTIONS:
            next(tokens, None)
        elif token in _ROOT_FLAGS or token.startswith("--output=") or _VERBOSE.fullmatch(token):
            continue
        elif token.startswith("-"):
            return None
        else:
            return next((c for c in BUILTIN_COMPONENTS if c.name == token), None)
    return None


_VERBOSE = re.compile(r"-v+")


def _single_command_app(
    component: CliComponent,
) -> tuple[typer.Typer, tuple[Context, CoeffectScope]]:
    """A root with the global options and only *component* mounted, and its fiber."""
    root = _new_root()
    ctx = _cli_context(root)
    return root, (ctx, activate([component], ctx))


_STARTUP_GC_FROZEN = False

#: Young-generation collection threshold for a CLI run (CPython's is 2000).
#: Older generations are collected every N young collections, so this also
#: paces the full collections that traverse every parsed metadata row. On
#: guild-rebrew, ``lint`` ran 2,482/225/17 collections at 2000 and 140/11/1
#: at 20,000: 12% less CPU time, 1.7% fewer instructions, the same peak RSS.
_GC_YOUNG_THRESHOLD = 20_000


def _freeze_startup_objects() -> None:
    """Move the import-time CLI graph to the permanent generation, once.

    typer/click/rich and the registries are live for the whole process, but a
    command that walks thousands of rows triggers full collections that
    rescan them. Frozen objects are not rescanned; everything allocated after
    this point stays collectable, so watch and server modes keep collecting
    their own garbage.
    """
    global _STARTUP_GC_FROZEN
    if _STARTUP_GC_FROZEN:
        return
    _STARTUP_GC_FROZEN = True
    # Freeze without a preceding collect: the collect scanned the whole import
    # graph for ~30ms. Unreachable startup cycles are retained for the process
    # lifetime, including watch/server modes; later allocations stay collectable.
    gc.freeze()


@contextlib.contextmanager
def _traced_command() -> Iterator[None]:
    """Run the command under the caller's trace when it handed one over (``TRACEPARENT``).

    The ops server runs the commands that compile as child processes; the child exports a span of
    its own, named after the command, so the remote compile's client span and the ``traceparent``
    it sends stay in the caller's trace. Without ``TRACEPARENT`` and ``REBREW_OTLP_ENDPOINT``
    nothing changes.
    """
    inbound = os.environ.get(telemetry.TRACEPARENT_ENV)
    if not telemetry.valid_traceparent(inbound):
        yield
        return
    from rebrew import __version__

    stop = telemetry.configure_from_env("relumea-rebrew", __version__)
    words = [word for word in sys.argv[1:3] if not word.startswith("-")]
    try:
        with telemetry.span(" ".join(["rebrew", *words]), traceparent=inbound):
            yield
    finally:
        stop()


def main() -> None:
    """Package entry point for the ``rebrew`` umbrella CLI.

    A run of one built-in command mounts only that command; every other
    invocation mounts the whole umbrella.
    """
    component = _invoked_builtin(sys.argv[1:])
    # _fiber holds the single command's scope until the command returns. The
    # module attribute (not a global lookup) reaches the lazy `app`.
    entry, _fiber = (
        _single_command_app(component) if component else (sys.modules[__name__].app, None)
    )
    # The startup CLI graph (typer options, rich, registries) is live for the
    # whole process but would be rescanned by every full collection. Move it
    # to the permanent generation once, before the command allocates:
    # `rebrew status` on 5,000 functions measured 0.16s of CPU in those scans.
    # Objects created after this point (including lazy command imports) stay
    # collectable, so watch and server modes keep collecting their own garbage.
    _freeze_startup_objects()
    gc.set_threshold(_GC_YOUNG_THRESHOLD, *gc.get_threshold()[1:])
    with _traced_command():
        run_cli(entry)


if __name__ == "__main__":
    main()
