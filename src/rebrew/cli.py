"""Shared CLI utilities for rebrew tools.

Provides common Typer options, config-loading helpers, and standardised
output / error helpers so that every tool gets consistent ``--target``
support, error reporting, VA parsing, and JSON output without boilerplate.

Usage in a tool::

    import typer
    from rebrew.cli import TargetOption, require_config, error_exit, json_print, parse_va

    app = typer.Typer()

    @app.callback(invoke_without_command=True)
    def main(target: str | None = TargetOption) -> None:
        cfg = require_config(target)
        ...
"""

from __future__ import annotations

import json
import logging
import os
import stat
import sys
import time
import unicodedata
import warnings
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, NoReturn, override

import typer
from rich.console import Console
from rich.markup import escape
from typer._click.core import Command as TyperBaseCommand
from typer._click.core import Context as TyperContext
from typer._click.core import Parameter as TyperParameter
from typer.core import TyperGroup, TyperOption

from rebrew.annotation import Annotation, parse_c_file_multi
from rebrew.config import (
    DEFAULT_LOG_LEVEL,
    ConfigError,
    ConfigWarning,
    ProjectConfig,
    load_config,
    parse_env_log_level,
)
from rebrew.sources import iter_sources, target_marker
from rebrew.utils import (
    console,
    parse_int_literal,
    untrusted_literal,
    untrusted_text,
)

#: Timestamp format shared by every log line.  UTC is forced in
#: :func:`configure_logging`; the default converter is localtime, so a host in
#: a DST zone stamps verbose logs with a wall clock that jumps or repeats and
#: disagrees with CI.  Match status/verify metadata, which label UTC.
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S UTC"

# ---------------------------------------------------------------------------
# Standardised exit codes
# ---------------------------------------------------------------------------

EXIT_OK = 0  # Success (all functions matched / no errors)
EXIT_MISMATCH = 1  # Actionable failure (fix your code)
EXIT_ERROR = 2  # Infrastructure error (build/config broken)
#: Exit status of a process killed by SIGPIPE (128 + 13), what a shell reports
#: for ``yes | head``.
EXIT_SIGPIPE = 141
#: Exit status after Ctrl+C (128 + SIGINT).
EXIT_INTERRUPTED = 130

# Re-usable Typer option for --target
TargetOption: str | None = typer.Option(
    None,
    "--target",
    "-t",
    help="Target name from rebrew-project.toml (default: project default target).",
)


# Re-usable Typer option for --all-targets
AllTargetsOption: bool = typer.Option(
    False,
    "--all-targets",
    help="Run across EVERY configured target (default: project default target only).",
)


def run_for_each_target(
    names: list[str],
    run_one: Any,
    *,
    json_mode: bool = False,
) -> int:
    """Run ``run_one(target_name)`` once per target and aggregate.

    Shared mechanics behind ``--all-targets``: the per-target run is usually
    the tool's own entry point re-invoked with ``target=<name>``.  One bad
    target must not discard the others' results, so ``typer.Exit`` and
    unexpected errors are caught per target and the WORST exit code is
    returned (0 all ok, 1 any mismatch, 2 any error).

    In JSON mode each run's stdout is captured and nested under a single
    ``{"targets": {name: <doc>}}`` envelope — the aggregate stays one
    parseable document instead of interleaved fragments.
    """
    import contextlib
    import io
    import logging

    collected: dict[str, Any] = {}
    worst = 0
    for name in names:
        buf: Any = None
        try:
            if json_mode:
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    run_one(name)
            else:
                console.print(f"\n[bold cyan]=== Target {name} ===[/]")
                run_one(name)
        except typer.Exit as exc:
            worst = max(worst, int(getattr(exc, "exit_code", 0) or 0))
        except Exception as exc:
            logging.warning("target %s failed", name, exc_info=True)
            worst = max(worst, EXIT_ERROR)
            if not json_mode:
                console.print(
                    f"[yellow]warning:[/yellow] target {name} failed: {type(exc).__name__}: {exc}"
                )
        if json_mode:
            raw = (buf.getvalue() if buf is not None else "").strip()
            if raw:
                try:
                    collected[name] = json.loads(raw)
                except ValueError:
                    collected[name] = {"raw": raw}
            else:
                collected[name] = None
    if json_mode:
        json_print({"targets": collected})
    return worst


def all_targets_run(
    *,
    target: str | None,
    all_targets: bool,
    json_mode: bool,
    run_one: Any,
) -> bool:
    """Dispatch an ``--all-targets`` sweep; return True when it handled the run.

    Entry points call this first::

        if all_targets_run(
            target=target, all_targets=all_targets, json_mode=json_output,
            run_one=lambda n: main(..., target=n, all_targets=False),
        ):
            return

    Validates mutual exclusion of ``--target`` and ``--all-targets``, takes
    the target list from the project config, delegates to
    :func:`run_for_each_target`, and raises ``typer.Exit`` with the worst
    per-target code.  Returns False when the caller should run normally for
    a single target.
    """
    if not all_targets:
        return False
    if target is not None:
        error_exit(
            "--all-targets and --target are mutually exclusive — pick one target or sweep them all",
            json_mode=json_mode,
        )
    cfg = require_config(target=None, json_mode=json_mode)
    names = list(getattr(cfg, "all_targets", []) or []) or [cfg.target_name]
    code = run_for_each_target(names, run_one, json_mode=json_mode)
    if code:
        raise typer.Exit(code=code)
    return True


def require_config(
    target: str | None = None,
    *,
    json_mode: bool = False,
    root: Path | None = None,
) -> ProjectConfig:
    """Load the project config, exiting with a user-friendly error on failure.

    Each except branch calls error_exit() which is typed ``NoReturn``; the
    explicit ``return cfg`` makes the successful code path unambiguous to
    static analysers (mypy/pyright) and avoids an implicit ``None`` return.
    """
    try:
        cfg = load_config(root=root, target=target)
    except FileNotFoundError as exc:
        error_exit(str(exc), json_mode=json_mode, code=EXIT_ERROR)
    except (KeyError, ValueError) as exc:
        error_exit(f"Config error: {exc}", json_mode=json_mode, code=EXIT_ERROR)
    return cfg  # reached only when load_config() succeeds; branches above are NoReturn


# ---------------------------------------------------------------------------
# Standardised output helpers
# ---------------------------------------------------------------------------


def error_exit(msg: str, *, json_mode: bool = False, code: int = EXIT_ERROR) -> NoReturn:
    """Print *msg* as an error and ``raise typer.Exit(code)``.

    In JSON mode the envelope is ``{"error": <msg>, "code": <exit_code>}`` so
    callers can distinguish mismatch (1) from infrastructure errors (2) without
    relying solely on the process exit status.

    On the Rich branch *msg* is rendered literally (markup escaped, terminal
    control characters other than tab/newline shown as ``\\xNN``): error text
    often embeds file contents, paths, and remote responses that must not be
    interpreted as markup or escape sequences.  The JSON branch carries *msg*
    verbatim, because the value is JSON-escaped and a consumer parses it.
    """
    if json_mode or _json_requested():
        print(json.dumps({"error": msg, "code": code}, indent=2))
    else:
        # soft_wrap keeps embedded commands/paths contiguous — without it
        # Rich folds mid-token (e.g. `rebrew catalog …` → `rebrew\ncatalog`).
        safe = untrusted_text(msg)
        console.print(f"[red bold]error:[/red bold] {safe}", soft_wrap=True)
    raise typer.Exit(code=code)


def json_print(data: dict[str, Any] | list[Any]) -> None:
    """Print *data* as pretty-printed JSON to stdout."""
    print(json.dumps(data, indent=2))


def _standalone_command_kwargs(main: Any) -> dict[str, Any]:
    """Help-facing Typer settings copied from the calling module's ``app``.

    ``rebrew diff --help`` and ``rebrew-diff --help`` are the same command,
    so they must print the same help, examples, and exit codes.  Building a
    bare ``typer.Typer()`` dropped the module's ``help=`` / ``epilog=``,
    leaving the console script with a bare option list.  Typer reads them
    from the *command* registration, not the app, for a single-command app.
    Unset fields hold a ``DefaultPlaceholder``, which the constructor would
    not accept, so only plain values are copied.
    """
    from typer.models import DefaultPlaceholder

    module = sys.modules.get(getattr(main, "__module__", None) or "")
    source = getattr(module, "app", None)
    info = getattr(source, "info", None)
    if info is None:
        return {}
    return {
        name: value
        for name in ("help", "epilog", "short_help", "context_settings", "options_metavar")
        if not isinstance(value := getattr(info, name, None), DefaultPlaceholder)
    }


#: Help text for the options :func:`add_global_options` attaches everywhere.
VERSION_HELP = "Show version and exit."
VERBOSE_HELP = "Increase output verbosity."
QUIET_HELP = "Cancel --verbose; leave logs at warning."


def _print_version(ctx: TyperContext, param: TyperParameter, value: bool) -> None:
    """Eager ``--version`` callback: print ``rebrew <version>`` and exit 0.

    The module's ``__version__``, not ``importlib.metadata``: the installed
    metadata is baked at install time, so in an editable checkout it drifts
    from the code that is actually running.
    """
    if not value or ctx.resilient_parsing:
        return
    from rebrew import __version__

    Console().print(f"rebrew {__version__}")
    ctx.exit(EXIT_OK)


#: Verbosity flags recorded so far, keyed by flag.  The umbrella's own
#: ``--verbose``/``--quiet`` and the injected per-command copies both land
#: here before the level is computed, so the two spellings of one invocation
#: (``rebrew -vv diff``, ``rebrew diff -vv``) agree and neither resets the
#: other to its default.
_verbosity: dict[str, int] = {"verbose": 0, "quiet": 0}
_log_level: int = DEFAULT_LOG_LEVEL


def effective_log_level() -> int:
    """The level the last :func:`configure_logging` call resolved to."""
    return _log_level


def reset_verbosity() -> None:
    """Forget the verbosity flags recorded so far.

    :func:`run_cli` calls this before each run so a long-lived process that
    drives two commands in a row (an embedding app, a test) does not carry the
    first command's ``-v`` into the second.
    """
    global _log_level
    _verbosity["verbose"] = 0
    _verbosity["quiet"] = 0
    _log_level = DEFAULT_LOG_LEVEL


def configure_logging(verbose: int = 0, *, quiet: bool = False) -> None:
    """Set the root log level from the verbosity flags, in UTC."""
    global _log_level
    if quiet:
        _verbosity["quiet"] = 1
    if verbose > 0:
        _verbosity["verbose"] = verbose
    if _verbosity["quiet"]:
        level = logging.WARNING
    elif _verbosity["verbose"] >= 2:
        level = logging.DEBUG
    elif _verbosity["verbose"] == 1:
        level = logging.INFO
    else:
        try:
            level = parse_env_log_level(
                os.environ.get("REBREW_LOG_LEVEL", ""), default=DEFAULT_LOG_LEVEL
            )
        except ConfigError as exc:
            # Warn and keep the default rather than exit: `rebrew cfg effective`
            # is the command that names the bad knob, and it is unusable while
            # every run aborts on one.
            console.print(f"[yellow]warning:[/yellow] {exc}")
            level = DEFAULT_LOG_LEVEL
    _log_level = level
    logging.basicConfig(format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT, level=level)
    # basicConfig is a no-op when root already has handlers; still force UTC
    # on whatever formatter is installed so a prior localtime config cannot
    # leak into -v output.
    for handler in logging.root.handlers:
        formatter = handler.formatter
        if formatter is not None:
            formatter.converter = time.gmtime
            formatter.datefmt = LOG_DATE_FORMAT


def _apply_verbose(ctx: TyperContext, param: TyperParameter, value: int) -> None:
    """Eager ``--verbose`` callback: raise the log level before the body runs."""
    if value and not ctx.resilient_parsing:
        configure_logging(value)


def _apply_quiet(ctx: TyperContext, param: TyperParameter, value: bool) -> None:
    """Eager ``--quiet`` callback: pin logs at warning."""
    if value and not ctx.resilient_parsing:
        configure_logging(quiet=True)


def _declares(cmd: TyperBaseCommand, *names: str) -> bool:
    """True when *cmd* already declares any of *names* (long or short form)."""
    return any(name in param.opts for param in cmd.params for name in names)


def add_global_options(cmd: TyperBaseCommand) -> TyperBaseCommand:
    """Give *cmd* the umbrella's ``--version``/``--verbose``/``--quiet`` flags.

    ``rebrew --version`` covers the group, but each tool also ships as its own
    console script (``rebrew-diff``, ``rebrew-test``, …) and each is a
    subcommand of the umbrella, so asking one of those for its version or for
    ``-v`` got click's ``No such option`` and exit 2.  Injected as eager,
    ``expose_value=False`` Typer options so the tool callbacks keep their own
    signatures: no wrapper, no re-annotated copy of every command.  Groups
    recurse, so ``rebrew binsync push --version`` works like the flat form.

    A command that declares a flag itself keeps it: ``lint --quiet`` means
    "errors only", not "logs at warning", so the injector adds ``--verbose``
    there and leaves ``--quiet`` alone.
    """
    if not _declares(cmd, "--version"):
        cmd.params.append(
            TyperOption(
                param_decls=["--version", "-V"],
                is_flag=True,
                is_eager=True,
                expose_value=False,
                callback=_print_version,
                help=VERSION_HELP,
            )
        )
    if not _declares(cmd, "--verbose", "-v"):
        cmd.params.append(
            TyperOption(
                param_decls=["--verbose", "-v"],
                count=True,
                default=0,
                # click renders a count option as `<int range>`; the umbrella
                # spells it `<int>`, and one flag should look the same in both
                # help screens.
                metavar="<int>",
                show_default=True,
                is_eager=True,
                expose_value=False,
                callback=_apply_verbose,
                help=VERBOSE_HELP,
            )
        )
    if not _declares(cmd, "--quiet", "-q"):
        cmd.params.append(
            TyperOption(
                param_decls=["--quiet", "-q"],
                is_flag=True,
                is_eager=True,
                expose_value=False,
                callback=_apply_quiet,
                help=QUIET_HELP,
            )
        )
    for sub in getattr(cmd, "commands", {}).values():
        add_global_options(sub)
    return cmd


class VersionedGroup(TyperGroup):
    """Umbrella group offering the shared options on every subcommand.

    The umbrella registers its commands from the plugin component graph at
    startup, so ``run_cli``'s eager walk of ``cmd.commands`` runs before they
    exist.  Hooking ``get_command`` covers them the moment click resolves one,
    which is also what makes ``rebrew diff --version`` work next to the
    group-level ``rebrew --version``.
    """

    @override
    def get_command(self, ctx: TyperContext, name: str) -> TyperBaseCommand | None:
        cmd = super().get_command(ctx, name)
        return None if cmd is None else add_global_options(cmd)


def run_standalone(main: Any) -> None:
    """Run a module's ``main`` callback as a plain command on a fresh app.

    The group-style ``invoke_without_command`` callback fails to parse
    positional-then-option invocations (``rebrew-<cmd> ARG --opt`` — click
    treats the positional as a command name), while the umbrella's command
    registration parses both orderings.
    """
    module = sys.modules.get(getattr(main, "__module__", None) or "")
    markup: Literal["markdown", "rich"] | None = getattr(
        getattr(module, "app", None), "rich_markup_mode", "rich"
    )
    _standalone = typer.Typer(rich_markup_mode=markup)
    _standalone.command(**_standalone_command_kwargs(main))(main)
    run_cli(_standalone)


def _json_requested(argv: list[str] | None = None) -> bool:
    """True when the invocation passed the exact ``--json`` / ``--json=true`` token.

    A substring scan would match a file named ``x--json.c`` or
    ``--cflags "--json"``.
    """
    return any(arg in ("--json", "--json=true") for arg in (sys.argv if argv is None else argv))


def _stdout_is_fifo() -> bool:
    try:
        return stat.S_ISFIFO(os.fstat(sys.stdout.fileno()).st_mode)
    except (OSError, ValueError):  # stdout replaced by an in-memory stream
        return False


def _stdout_pipe_closed(stdout_was_fifo: bool) -> bool:
    """True when a library swallowed an EPIPE on stdout into ``exit(1)``.

    click/typer swap ``sys.stdout`` for a ``PacifyFlushWrapper``; Rich's
    ``Console.on_broken_pipe`` dups ``/dev/null`` over the stdout fd.  Either
    is the only sign distinguishing a closed pipe from a real
    ``EXIT_MISMATCH``.
    """
    if type(sys.stdout).__name__.endswith("PacifyFlushWrapper"):
        return True
    return stdout_was_fifo and not _stdout_is_fifo()


def exit_130_on_interrupt(cmd: TyperBaseCommand) -> TyperBaseCommand:
    """Make *cmd* report Ctrl+C as :data:`EXIT_INTERRUPTED` instead of click's 1.

    click's standalone handler catches ``KeyboardInterrupt``, converts it to
    ``Abort`` and calls ``sys.exit(1)`` — the same code a byte mismatch
    returns, so a shell cannot tell "you stopped it" from "it did not match".
    :data:`SystemExit` is a ``BaseException`` that none of click's handlers
    match, so raising it from ``invoke`` reaches the shell untouched.
    """
    original = cmd.invoke

    def invoke(ctx: TyperContext) -> Any:
        try:
            return original(ctx)
        except KeyboardInterrupt:
            console.print("[red]error:[/red] Interrupted by user")
            raise SystemExit(EXIT_INTERRUPTED) from None

    cmd.invoke = invoke  # type: ignore[method-assign]
    return cmd


def run_cli(app: Callable[[], Any]) -> None:
    """Run a Typer *app* as a process entry point with rebrew's exit contract.

    - reader closed the pipe early (``rebrew ... --json | head``): exit
      ``EXIT_SIGPIPE`` silently, never click's ``1`` (which reads as
      ``EXIT_MISMATCH``) or Python's ``120``
    - ``error_exit`` raised outside click (plain entry functions): its code
    - an uncaught ``ValueError`` / ``OSError`` / ``KeyError`` / ``RuntimeError``:
      one-line error (JSON envelope under ``--json``) and ``EXIT_ERROR``
    - Ctrl+C: ``EXIT_INTERRUPTED``
    - ``ConfigWarning`` stays out of Python's warning display: ``_config_warn``
      already printed it to stderr

    A :class:`typer.Typer` argument is converted to its click command first so
    every entry point — umbrella, flat tool, group subcommand — gets the
    shared ``--version``/``--verbose``/``--quiet`` flags from
    :func:`add_global_options`.
    """
    warnings.simplefilter("ignore", ConfigWarning)
    reset_verbosity()

    def entry() -> None:
        if isinstance(app, typer.Typer):
            add_global_options(exit_130_on_interrupt(typer.main.get_command(app)))()
        else:
            app()

    stdout_was_fifo = _stdout_is_fifo()
    try:
        try:
            entry()
        except SystemExit as exc:
            if exc.code == EXIT_MISMATCH and _stdout_pipe_closed(stdout_was_fifo):
                raise BrokenPipeError from None
            raise
        finally:
            # Flush here, not at interpreter exit, so a closed pipe raises
            # inside this handler instead of printing "Exception ignored".
            sys.stdout.flush()
    except BrokenPipeError:
        devnull_fd = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull_fd, sys.stdout.fileno())
        finally:
            os.close(devnull_fd)
        raise SystemExit(EXIT_SIGPIPE) from None
    except typer.Exit as e:
        # error_exit() outside click's handler: the message is already out.
        raise SystemExit(e.exit_code) from None
    except (ValueError, OSError, KeyError, RuntimeError) as e:
        if _json_requested():
            print(json.dumps({"error": str(e), "code": EXIT_ERROR}, indent=2))
        else:
            console.print(f"[red]error:[/red] {escape(str(e))}", soft_wrap=True)
        raise SystemExit(EXIT_ERROR) from None
    except KeyboardInterrupt:
        console.print("[red]error:[/red] Interrupted by user")
        raise SystemExit(EXIT_INTERRUPTED) from None


def option_default(value: Any, default: Any) -> Any:
    """Coerce a possibly-leaked typer option back to its declared default.

    Direct Python calls to a typer callback (the unit-test convention in this
    codebase) pass ``typer.models.OptionInfo`` as the value of **omitted**
    parameters — typer's wrapper does not resolve the declared default for
    non-CLI invocations.  An ``OptionInfo`` object is truthy and not a
    ``Path``/``str``, so ``if x is not None`` and ``Path(x)`` both misbehave
    (this crashed ``rebrew init --link-tools-from`` when tests omitted the
    new option, and leaked a truthy ``--flag-sweep-toolchains`` into ``match``'s
    watch re-test).

    Callbacks that unit tests invoke directly must guard every new option::

        if toolchain_dir is not None and not isinstance(toolchain_dir, Path):
            toolchain_dir = None

    or, equivalently and self-documenting::

        toolchain_dir = option_default(toolchain_dir, None)

    See docs/DEVELOPMENT.md ("Typer quirks") for the full convention.
    """
    from typer.models import OptionInfo

    return default if isinstance(value, OptionInfo) else value


def parse_va(va_str: str, *, json_mode: bool = False) -> int:
    """Parse a hexadecimal virtual-address string, exiting on invalid input.

    Always interprets as base-16 (with or without ``0x`` prefix).  A bad
    argument is a usage error — exit ``EXIT_ERROR`` (2), not ``EXIT_MISMATCH``
    (1), so scripts can distinguish "bad invocation" from "needs code work".
    """
    try:
        va = parse_int_literal(va_str, base=16)
    except ValueError:
        va = -1
    if va < 0:
        error_exit(f"Invalid hex VA: {va_str!r}", json_mode=json_mode, code=EXIT_ERROR)
    return va


def _stdin_is_tty() -> bool:
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError, OSError):  # stdin closed or replaced
        return False


def confirm_abort(prompt: str, *, skip_flag: str = "--force") -> None:
    """Ask *prompt* on stderr for a destructive action, aborting on "no".

    An abort is a usage error, not a mismatch: ``typer.confirm(abort=True)``
    raises on "no" *and* on EOF, and Click reports both as ``Aborted.`` with
    exit 1 — the code rebrew reserves for "the code needs work", per the exit
    table in ``rebrew --help``.  Route both to ``EXIT_ERROR`` and, when there
    was no terminal to answer the question, name the flag that skips the
    prompt.
    """
    # typer.confirm raises typer's own Abort on "no" and on EOF; click's
    # Abort is a sibling class, not a base of it.
    from click.exceptions import Abort as ClickAbort

    eof = False
    try:
        answer = typer.confirm(prompt, err=True)
    except (typer.Abort, ClickAbort, EOFError, OSError):
        answer, eof = False, not _stdin_is_tty()
    if answer:
        return
    hint = f" (stdin is not a terminal; pass {skip_flag})" if eof else ""
    error_exit(f"aborted: {prompt}{hint}")


def resolve_binary_arg(
    binary: Path | None,
    *,
    target: str | None,
    json_mode: bool,
) -> Path:
    """Return *binary*, or the project target when the argument is omitted.

    A missing project target exits with ``target binary missing``; a path
    that was passed but does not exist exits with ``binary not found``.
    """
    if binary is None:
        cfg = require_config(target=target, json_mode=json_mode)
        binary = Path(cfg.target_binary)
        if not binary.exists():
            error_exit(
                f"target binary missing: {binary}",
                json_mode=json_mode,
                code=EXIT_ERROR,
            )
    if not binary.exists():
        error_exit(f"binary not found: {binary}", json_mode=json_mode)
    return binary


def resolve_source_arg(cfg: ProjectConfig, source_arg: str) -> Path:
    """Resolve a source argument to an existing source file path.

    Accepts a direct file path, a symbol name (matched against the file stem,
    tolerating the MSVC leading underscore), or a hex VA (e.g. ``0x01006364``,
    matched against function annotations).  Returns *source_arg* unchanged
    when nothing matches — the caller then reports the failure with context.
    """
    import contextlib
    import logging

    p = Path(source_arg)
    if p.exists() and p.is_file():
        return p

    # Defensive access: a config without a source tree (e.g. a minimal mock)
    # cannot be scanned — return the argument unchanged, as documented.
    src_dir = getattr(cfg, "reversed_dir", None)
    if src_dir is None:
        return p

    # Hex VA lookup — scan annotations for a matching VA.
    va_int: int | None = None
    stripped = source_arg.strip().lower()
    if stripped.startswith("0x"):
        with contextlib.suppress(ValueError):
            va_int = int(stripped, 16)

    if va_int is not None:
        tm = target_marker(cfg)
        for src in iter_sources(src_dir, cfg):
            try:
                annos = parse_c_file_multi(src, target_name=tm, metadata_dir=cfg.metadata_dir)
            except Exception:  # per-file parse noise in a scan
                logging.debug("Skipping %s during source resolution", src, exc_info=True)
                continue
            for a in annos:
                if a.va == va_int:
                    return src

    # Symbol name — match against the file stem, tolerating the MSVC leading
    # underscore on either side (``_foo.c`` for symbol ``foo``, ``foo.c`` for
    # ``_foo``).  The EXACT stem must win over an underscore variant: comparing
    # both sides stripped made `__foo.c`/`_foo.c` (path order 0x5F) beat
    # `foo.c`, so the wrong file was compiled and its VA got the STATUS write.
    sources = iter_sources(src_dir, cfg)
    arg_norm = unicodedata.normalize("NFC", source_arg)
    arg_p = Path(arg_norm)

    for src in sources:
        if (
            unicodedata.normalize("NFC", str(src)) == arg_norm
            or unicodedata.normalize("NFC", src.as_posix()) == arg_norm
        ):
            return src
        try:
            rel = unicodedata.normalize("NFC", str(src.relative_to(src_dir)))
            if (
                rel == arg_norm
                or unicodedata.normalize("NFC", src.relative_to(src_dir).as_posix()) == arg_norm
            ):
                return src
        except (ValueError, TypeError):
            pass

    for src in sources:
        if (
            unicodedata.normalize("NFC", src.name) == arg_norm
            or unicodedata.normalize("NFC", src.name) == arg_p.name
        ):
            return src

    target_stem = arg_p.stem if arg_norm.endswith((".c", ".cpp", ".cxx")) else arg_norm
    for src in sources:
        if unicodedata.normalize("NFC", src.stem) == target_stem:
            return src
    arg_stem = target_stem.lstrip("_")
    for src in sources:
        if unicodedata.normalize("NFC", src.stem).lstrip("_") == arg_stem:
            return src

    return p


def require_source_arg(cfg: ProjectConfig, source_arg: str, *, json_mode: bool = False) -> Path:
    """Resolve *source_arg* to an existing source file, exiting when it is missing.

    :func:`resolve_source_arg` returns the argument unchanged when nothing
    matches, so every caller that forgets the existence check reports a
    downstream symptom instead (``Could not derive symbol…``, ``No annotations
    found in …``).  One wording and one exit code for the condition.
    """
    path = Path(resolve_source_arg(cfg, source_arg))
    if not path.is_file():
        error_exit(f"Source file not found: {path}", json_mode=json_mode, code=EXIT_ERROR)
    return path


def require_positive_size(size: int, *, json_mode: bool = False) -> int:
    """Return *size* when it is a positive byte count, exiting when it is not.

    A ``// SIZE: -4`` annotation or a negative ``--size`` otherwise reaches
    ``bytes[:-4]`` (dropping the last four bytes instead of none) and the
    ``matched / size * 100`` percent, which reports a negative match
    percentage with no error.  Zero is the same defect: every slice is empty.
    """
    if size <= 0:
        error_exit(f"Invalid size {size}: pass a positive byte count", json_mode=json_mode)
    return size


def select_annotation(
    cfg: ProjectConfig, source_arg: str, va: str | None, *, json_mode: bool = False
) -> tuple[Path, Annotation, int | None]:
    """Resolve *source_arg* and pick its annotation, exiting when either is missing.

    Returns ``(path, annotation, va)``: the annotation whose VA equals *va*
    (else the file's first), and *va* parsed when given, else the
    annotation's own VA (``None`` when it has none).
    """
    path = require_source_arg(cfg, source_arg, json_mode=json_mode)

    annos = parse_c_file_multi(path, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir)
    if not annos:
        error_exit("No // FUNCTION annotation found in the source", json_mode=json_mode)
    if not va:
        if not source_arg.strip().lower().startswith("0x") and not Path(source_arg).exists():
            from rebrew.utils import fold_ident

            want_sym = fold_ident(source_arg.strip()).lstrip("_")
            for a in annos:
                for candidate in (a.symbol or "", a.name or ""):
                    if fold_ident(candidate.strip()).lstrip("_") == want_sym:
                        return path, a, a.va
        return path, annos[0], annos[0].va
    want = parse_va(va, json_mode=json_mode)
    return path, next((a for a in annos if a.va == want), annos[0]), want


__all__ = [
    "AllTargetsOption",
    "EXIT_ERROR",
    "EXIT_INTERRUPTED",
    "EXIT_MISMATCH",
    "EXIT_OK",
    "EXIT_SIGPIPE",
    "QUIET_HELP",
    "TargetOption",
    "VERBOSE_HELP",
    "VERSION_HELP",
    "VersionedGroup",
    "add_global_options",
    "all_targets_run",
    "confirm_abort",
    "configure_logging",
    "console",
    "effective_log_level",
    "error_exit",
    "exit_130_on_interrupt",
    "json_print",
    "option_default",
    "parse_va",
    "require_config",
    "require_positive_size",
    "require_source_arg",
    "resolve_binary_arg",
    "resolve_source_arg",
    "reset_verbosity",
    "run_cli",
    "run_for_each_target",
    "run_standalone",
    "select_annotation",
    "untrusted_literal",
    "untrusted_text",
]
