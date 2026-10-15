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

import click
import typer
from rich.console import Console
from typer import rich_utils
from typer._click.core import Command as TyperBaseCommand
from typer._click.core import Context as TyperContext
from typer._click.core import Parameter as TyperParameter
from typer._click.exceptions import BadOptionUsage
from typer.core import TyperGroup, TyperOption

from rebrew.config import (
    DEFAULT_LOG_LEVEL,
    ConfigError,
    ConfigNotFoundError,
    ConfigWarning,
    ProjectConfig,
    find_root,
    load_config,
    parse_env_log_level,
)
from rebrew.metadata.bindings import SourceBinding, read_source_bindings
from rebrew.sources import iter_sources, target_marker
from rebrew.utils import (
    console,
    parse_int_literal,
    untrusted_ident,
    untrusted_literal,
    untrusted_text,
)

log = logging.getLogger(__name__)

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
    help="Target name from rebrew-project.toml (default: project default target); a final --target lists targets.",
)


# Re-usable Typer option for --root
RootOption: Path | None = typer.Option(
    None,
    "--root",
    help="Project root directory (default: auto-detected from rebrew-project.toml).",
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

    collected: dict[str, Any] = {}
    worst = 0
    for name in names:
        buf: Any = None
        failure = ""
        code = 0
        try:
            if json_mode:
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    run_one(name)
            else:
                console.print(f"\n[bold cyan]=== Target {name} ===[/]")
                run_one(name)
        except typer.Exit as exc:
            code = int(getattr(exc, "exit_code", 0) or 0)
            worst = max(worst, code)
            if code:
                failure = f"target command exited with code {code}"
        except Exception as exc:
            log.warning("target %s failed", name, exc_info=True)
            worst = max(worst, EXIT_ERROR)
            code = EXIT_ERROR
            failure = f"{type(exc).__name__}: {exc}"
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
                    collected[name] = {"error": "target command emitted invalid JSON"}
                    worst = max(worst, EXIT_ERROR)
            else:
                collected[name] = {"error": failure} if failure else None
            if code == EXIT_ERROR and failure:
                collected[name] = {"error": failure, "result": collected[name]}
    if json_mode:
        json_print({"targets": collected})
    return worst


def all_targets_run(
    *,
    target: str | None,
    all_targets: bool,
    json_mode: bool,
    run_one: Any,
    root: Path | None = None,
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
    names = configured_target_names(root, json_mode=json_mode)
    if len(set(names)) != len(names):
        # A target repeated in all_targets would compile (and write STATUS)
        # twice; the second pass reports the first pass's work as its own.
        log.warning(
            "duplicate target(s) in all_targets: %s; running each once",
            ", ".join(sorted(set(names))),
        )
        names = list(dict.fromkeys(names))
    code = run_for_each_target(names, run_one, json_mode=json_mode)
    if code:
        raise typer.Exit(code=code)
    return True


SourceTargetsOption: bool = typer.Option(
    False,
    "--source-targets",
    help="Run only targets bound to the explicit source file; report unbound targets as skipped",
)


def configured_target_names(root: Path | None = None, *, json_mode: bool = False) -> list[str]:
    """Enumerate configured targets without loading the default target's settings."""
    from rebrew.workspace.config import WorkspaceConfigError, read_config

    resolved = require_root(root, json_mode=json_mode)
    try:
        document = read_config(resolved)
        targets = document.get("targets")
        if not isinstance(targets, dict) or not targets:
            raise ValueError("rebrew-project.toml has no [targets] section")
        return list(targets)
    except (OSError, ValueError, WorkspaceConfigError) as exc:
        error_exit(str(exc), json_mode=json_mode)


def source_targets_run(
    source: str | None,
    *,
    enabled: bool,
    target: str | None,
    all_targets: bool,
    json_mode: bool,
    run_one: Any,
    root: Path | None = None,
) -> bool:
    """Preflight exact source bindings before running a source-scoped target sweep.

    Unbound targets are explicit skips. Invalid configurations or bindings are
    errors, isolated from healthy targets; an entirely unbound scope fails.
    """
    if not enabled:
        return False
    if target is not None or all_targets:
        error_exit("--source-targets excludes --target and --all-targets", json_mode=json_mode)
    path = Path(source).resolve() if source else None
    if path is None or not path.is_file():
        error_exit("--source-targets requires an existing source file", json_mode=json_mode)
    try:
        source_bytes = path.read_bytes()
    except OSError as exc:
        error_exit(str(exc), json_mode=json_mode)
    resolved = require_root(root, json_mode=json_mode)
    names = configured_target_names(resolved, json_mode=json_mode)
    plans: dict[str, dict[str, Any]] = {}
    for name in names:
        try:
            cfg = load_config(root=resolved, target=name)
            bindings = read_source_bindings(
                path,
                target_name=target_marker(cfg),
                metadata_dir=cfg.metadata_dir,
                project_root=resolved,
            )
            bound = any(row.is_function for row in bindings)
            plans[name] = (
                {} if bound else {"skipped": "source has no function binding for this target"}
            )
        except (OSError, ValueError) as exc:
            plans[name] = {"error": str(exc)}
    if path.read_bytes() != source_bytes:
        error_exit("source changed during target preflight; retry", json_mode=json_mode)

    def run(name: str) -> None:
        plan = plans[name]
        if plan:
            if json_mode:
                json_print(plan)
            else:
                console.print(untrusted_text(next(iter(plan.values()))))
            if "error" in plan:
                raise typer.Exit(code=EXIT_ERROR)
            return
        if path.read_bytes() != source_bytes:
            error_exit("source changed after target preflight; retry", json_mode=json_mode)
        run_one(name)

    code = run_for_each_target(names, run, json_mode=json_mode)
    if not any(not plan for plan in plans.values()) and not code:
        code = EXIT_MISMATCH
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


def require_root(root: Path | None = None, *, json_mode: bool = False) -> Path:
    """Return the project root: *root* verbatim, else the enclosing project.

    Every command that takes ``--root`` resolves it here, so one flag means one
    thing across the umbrella.  The commands that used to default to the current
    directory answered differently from the ones that went through
    :func:`require_config`: ``rebrew verify`` found the project from a
    subdirectory while ``rebrew coverage export --output snapshots/`` reported a missing
    ``rebrew-project.toml`` there and created a stray ``db/`` beside it.

    An explicit *root* is checked for being an existing directory before any
    work starts.  :func:`require_config` already reports a file or a missing
    directory as ``Config not found: <root>/rebrew-project.toml``, but the
    commands that walk or create under the tree themselves (``build-db``)
    reached that work first and surfaced ``[Errno 20] Not a directory:
    .../rebrew-project.toml/db`` or, for a missing root, ``[Errno 13] Permission
    denied`` — an errno naming a path deep inside rebrew's own output layout
    rather than the flag that caused it.  A root that exists but cannot be
    written to is left to the writer that hits it: that is a filesystem
    condition, not a bad argument.
    """
    if root is not None:
        resolved = root.resolve()
        if not resolved.exists():
            error_exit(f"--root does not exist: {resolved}", json_mode=json_mode, code=EXIT_ERROR)
        if not resolved.is_dir():
            error_exit(
                f"--root must be a directory, not a file: {resolved}",
                json_mode=json_mode,
                code=EXIT_ERROR,
            )
        return resolved
    try:
        return find_root()
    except ConfigNotFoundError as exc:
        error_exit(str(exc), json_mode=json_mode, code=EXIT_ERROR)


# ---------------------------------------------------------------------------
# Standardised output helpers
# ---------------------------------------------------------------------------


def _output_choice_from(ctx: TyperContext | None) -> str:
    """The root ``--output`` value visible from *ctx*, or ``auto``."""
    while ctx is not None:
        params = ctx.params or {}
        if "output_format" in params and params["output_format"] is not None:
            return str(params["output_format"])
        ctx = ctx.parent
    return "auto"


def _argv_format_choice(argv: list[str] | None = None) -> str | None:
    """Format selected before the subcommand, from argv when click has no context.

    ``-o`` / ``--output`` counts only before the first positional and only when
    the value is ``auto``, ``text``, or ``json``. A later ``-o`` is a path.
    ``--output text`` wins over ``--json``.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    saw_text = False
    saw_json = False
    saw_command = False
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            break
        if arg in ("--json", "--json=true") and not saw_text:
            saw_json = True
        elif arg.startswith("--output="):
            value = arg.split("=", 1)[1]
            if not saw_command and value == "text":
                saw_text = True
            elif not saw_command and value == "json":
                saw_json = True
        elif arg in ("-o", "--output") and index + 1 < len(args):
            value = args[index + 1]
            if not saw_command and value in {"auto", "text", "json"}:
                if value == "text":
                    saw_text = True
                elif value == "json":
                    saw_json = True
                index += 1
        elif not arg.startswith("-"):
            saw_command = True
        index += 1
    if saw_text:
        return "text"
    if saw_json:
        return "json"
    return None


def _json_mode_active(*, explicit: bool = False) -> bool:
    """True when this invocation asked for JSON.

    ``--output text`` wins over ``--json``. ``auto`` stays text, including
    when stdout is not a terminal: rebrew's pipe contract is text unless the
    caller asks. ``--json`` remains the explicit request.
    """
    choice = "auto"
    found_format = False
    flagged = explicit
    ctx = click.get_current_context(silent=True)
    while ctx is not None:
        params = ctx.params or {}
        if params.get("json_output"):
            flagged = True
        if "output_format" in params and params["output_format"] is not None:
            choice = str(params["output_format"])
            found_format = True
            break
        ctx = ctx.parent
    if not found_format:
        argv_choice = _argv_format_choice()
        if argv_choice is not None:
            choice = argv_choice
    if choice == "json":
        return True
    if choice == "text":
        return False
    return flagged or _json_requested()


def _apply_output_choice(ctx: TyperContext) -> None:
    """Copy a root ``--output json|text`` onto a command's ``--json`` parameter."""
    if "json_output" not in ctx.params:
        return
    choice = _output_choice_from(ctx)
    if choice == "json":
        ctx.params["json_output"] = True
    elif choice == "text":
        ctx.params["json_output"] = False


def _write_error(kind: str, message: str, hint: str) -> None:
    """Write one clispec error object as the next stderr line."""
    payload = {"error": {"kind": kind, "message": message, "hint": hint}}
    sys.stderr.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stderr.flush()


def _install_click_error_hook() -> None:
    """JSON mode turns Click errors into the stderr envelope. Text mode stays human."""
    from click.exceptions import ClickException
    from click.exceptions import UsageError as ClickUsageError

    original = ClickException.show
    if getattr(original, "_rebrew_hook", False):
        return

    def show(self: ClickException, file: Any = None) -> None:
        if _json_mode_active():
            kind = "usage" if isinstance(self, ClickUsageError) else "failure"
            _write_error(kind, self.format_message(), "")
            return
        original(self, file=file)

    show._rebrew_hook = True  # type: ignore[attr-defined]
    ClickException.show = show  # type: ignore[method-assign]


_install_click_error_hook()


def _emit_outcome(message: str, *, json_mode: bool) -> None:
    """Report an exit-1 mismatch without an error envelope."""
    if json_mode:
        json_print({"outcome": "mismatch", "message": message})
        return
    console.print(f"[red bold]error:[/red bold] {untrusted_text(message)}", soft_wrap=True)


def error_exit(
    msg: str,
    *,
    json_mode: bool = False,
    code: int = EXIT_ERROR,
    kind: str = "failure",
    hint: str = "",
) -> NoReturn:
    """Print *msg* as an error and ``raise typer.Exit(code)``.

    JSON mode writes ``{"error": {"kind", "message", "hint"}}`` as one stderr
    line. Exit :data:`EXIT_MISMATCH` is an outcome, not an error kind: stdout
    carries ``{"outcome": "mismatch", "message": ...}`` and stderr carries no
    error envelope.

    On the text branch *msg* is rendered literally (markup escaped, terminal
    control characters other than tab/newline shown as ``\\xNN``): error text
    often embeds file contents, paths, and remote responses that must not be
    interpreted as markup or escape sequences. The JSON branch carries *msg*
    verbatim, because the value is JSON-escaped and a consumer parses it.
    """
    use_json = json_mode or _json_mode_active()
    if code == EXIT_MISMATCH:
        _emit_outcome(msg, json_mode=use_json)
        raise typer.Exit(code=code)
    if use_json:
        _write_error(kind, msg, hint)
    else:
        # soft_wrap keeps embedded commands/paths contiguous. Without it
        # Rich folds mid-token (for example `rebrew coverage catalog …`).
        safe = untrusted_text(msg)
        suffix = f" {hint}" if hint else ""
        console.print(f"[red bold]error:[/red bold] {safe}{suffix}", soft_wrap=True)
    raise typer.Exit(code=code)


def json_print(data: dict[str, Any] | list[Any]) -> None:
    """Print *data* as one JSON document on stdout.

    A bare list is a collection and is wrapped in an items envelope. The
    document is indented on a terminal and compact otherwise.
    """
    if isinstance(data, list):
        data = {"items": data, "total": len(data)}
    if sys.stdout.isatty():
        text = json.dumps(data, indent=2)
    else:
        text = json.dumps(data, separators=(",", ":"))
    print(text)


def _standalone_command_kwargs(main: Any) -> dict[str, Any]:
    """Help-facing Typer settings copied from the calling module's ``app``.

    ``rebrew diff --help`` and ``python -m rebrew.diff --help`` run the same command,
    so they must print the same help, examples, and exit codes.  Building a
    bare ``typer.Typer()`` dropped the module's ``help=`` / ``epilog=``,
    leaving module execution with a bare option list. Typer reads them
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
VERBOSE_HELP = "Increase log verbosity (-v: info, -vv: debug)."
QUIET_HELP = "Cancel --verbose; leave logs at warning."

#: Inputs accepted by source-resolving commands, rather than identity-only selectors.
SOURCE_HELP = "Source file, symbol name, or VA (hex)"


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

    The root callback covers flags before the subcommand name; injection also
    accepts them after it (``rebrew diff --version``). Direct module execution
    uses the same options. Injected as eager,
    ``expose_value=False`` Typer options so the tool callbacks keep their own
    signatures: callbacks keep their parameters. Groups
    recurse, so ``rebrew binsync push --version`` works like the flat form.

    A command that declares a flag itself keeps it: ``lint --quiet`` means
    "errors only", not "logs at warning", so the injector adds ``--verbose``
    there and leaves ``--quiet`` alone.

    The invoke wrapper copies a root ``--output json|text`` onto ``--json``.
    Wrapping is once per command object: ``get_command`` and ``run_cli`` both
    call this, and a second wrap would apply the choice twice.
    """
    if getattr(cmd, "_rebrew_global_options", False):
        return cmd
    cmd._rebrew_global_options = True  # type: ignore[attr-defined]
    original_invoke = cmd.invoke

    def invoke(ctx: TyperContext) -> Any:
        _apply_output_choice(ctx)
        return original_invoke(ctx)

    cmd.invoke = invoke  # type: ignore[method-assign]
    # Rich accepts four-sided padding; one column gap keeps full flags visible at 60 columns.
    rich_utils.__dict__["STYLE_OPTIONS_TABLE_PADDING"] = (0, 1, 0, 0)
    cmd.context_settings.setdefault("help_option_names", ["--help", "-h"])
    target_option = next(
        (
            param
            for param in cmd.params
            if isinstance(param, TyperOption)
            and "--target" in param.opts
            and param.help
            and param.help.startswith("Target name from rebrew-project.toml")
        ),
        None,
    )
    if target_option is not None and not getattr(cmd, "_rebrew_target_listing", False):
        original_parse_args = cmd.parse_args

        def parse_args(ctx: TyperContext, args: list[str]) -> list[str]:
            argv = list(args)
            try:
                return original_parse_args(ctx, args)
            except BadOptionUsage as exc:
                if exc.option_name not in target_option.opts:
                    raise
                values, _, _ = cmd.make_parser(ctx).parse_args(args=argv[:-1])
                json_mode = bool(values.get("json_output"))
                root = values.get("root")
                cfg = require_config(root=Path(root) if root else None, json_mode=json_mode)
                names = list(cfg.all_targets) or [cfg.target_name]
                if json_mode:
                    json_print({"targets": names, "default_target": cfg.target_name})
                else:
                    console.print("Configured targets:")
                    for name in names:
                        suffix = " (default)" if name == cfg.target_name else ""
                        console.print(f"  {untrusted_text(name)}{suffix}")
                ctx.exit(EXIT_OK)

        cmd.parse_args = parse_args  # type: ignore[method-assign]
        cmd._rebrew_target_listing = True  # type: ignore[attr-defined]
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
                metavar="",
                show_default=False,
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
    for param in cmd.params:
        if not isinstance(param, TyperOption) or param.rich_help_panel is not None:
            continue
        flags = set(param.opts)
        if flags & {"--root", "--target", "--all-targets"}:
            param.rich_help_panel = "Project options"
        elif flags & {"--json", "--output", "--dry-run", "--apply"}:
            param.rich_help_panel = "Output options"
        elif flags & {"--version", "--verbose", "--quiet"} and param.help in {
            VERSION_HELP,
            VERBOSE_HELP,
            QUIET_HELP,
        }:
            param.rich_help_panel = "Global options"
    panel_order = {"Output options": 1, "Project options": 2, "Global options": 3}
    cmd.params.sort(
        key=lambda param: panel_order.get(getattr(param, "rich_help_panel", None) or "", 0)
    )
    for sub in getattr(cmd, "commands", {}).values():
        add_global_options(sub)
    if "Exit codes:" not in (cmd.epilog or ""):
        cmd.epilog = (cmd.epilog or "").rstrip() + (
            "\n\nExit codes: 0 success; 1 mismatch or failed check where applicable; 2 usage/config/build error; "
            "130 interrupted; 141 output pipe closed."
        )
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
    positional-then-option invocations (``python -m rebrew.diff ARG --opt`` — click
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
        if _json_mode_active():
            _write_error("failure", str(e), "")
        else:
            console.print(f"[red]error:[/red] {untrusted_text(str(e))}", soft_wrap=True)
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
        error_exit(
            f"Invalid hex VA: {va_str!r}",
            json_mode=json_mode,
            code=EXIT_ERROR,
            kind="usage",
        )
    return va


def stdin_is_tty() -> bool:
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
        answer, eof = False, not stdin_is_tty()
    if answer:
        return
    if eof:
        error_exit(
            f"aborted: {prompt} (stdin is not a terminal; pass {skip_flag})",
            kind="confirmation_required",
            hint=f"Pass {skip_flag} to skip the prompt.",
        )
    error_exit(f"aborted: {prompt}")


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

    Accepts a direct file path, a symbol name (file stem or stored function
    identity, tolerating compiler decoration), or a hex VA (e.g. ``0x01006364``,
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

    # One directory walk, reused by the VA scan and every stem pass below.
    sources = iter_sources(src_dir, cfg)

    if va_int is not None:
        tm = target_marker(cfg)
        from rebrew.function_providers import bind_library_source
        from rebrew.metadata.bindings import SourceBinding
        from rebrew.metadata.functions import load_metadata
        from rebrew.utils import preset_module_key

        metadata_root = getattr(cfg, "metadata_dir", None)
        identities = load_metadata(metadata_root, deepcopy=False) if metadata_root else {}
        for (module, address), identity in identities.items():
            if (
                address == va_int
                and preset_module_key(module) == preset_module_key(tm or "")
                and identity.get("kind") == "LIBRARY"
                and identity.get("file")
            ):
                bound = bind_library_source(cfg, SourceBinding(va=address, module=module), identity)
                candidate = (Path(src_dir) / bound.filepath).resolve()
                if candidate.is_file():
                    return candidate
        for src in sources:
            try:
                annos = read_source_bindings(
                    src,
                    target_name=tm,
                    metadata_dir=cfg.metadata_dir,
                    project_root=getattr(cfg, "root", None),
                )
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

    if va_int is None:
        from rebrew.rename_ops import c_name_from_symbol
        from rebrew.utils import fold_ident

        want = fold_ident(arg_norm.strip())
        tm = target_marker(cfg)
        for src in sources:
            try:
                annos = read_source_bindings(
                    src,
                    target_name=tm,
                    metadata_dir=getattr(cfg, "metadata_dir", None),
                    project_root=getattr(cfg, "root", None),
                )
            except (OSError, ValueError):
                logging.debug("Skipping %s during source resolution", src, exc_info=True)
                continue
            for ann in annos:
                if not ann.is_function:
                    continue
                names = (ann.name, ann.symbol, c_name_from_symbol(ann.symbol))
                if any(name and fold_ident(name.strip()) == want for name in names):
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


def require_non_negative(value: int, flag: str, *, json_mode: bool = False) -> int:
    """Return *value* when it is zero or positive, exiting when it is negative.

    The "how many rows" options (``--count``, ``--limit``, ``--top``) reach
    Python as plain ints and end in a slice, where a negative value silently
    keeps everything *but* the last N rows and still exits 0.  A script that
    trusts the exit code then stores a truncated report as if it were the
    whole one.  ``0`` stays legal: several commands spell it "no cap".
    """
    if value < 0:
        error_exit(f"{flag} must be zero or positive, got {value}", json_mode=json_mode)
    return value


def select_annotation(
    cfg: ProjectConfig, source_arg: str, va: str | None, *, json_mode: bool = False
) -> tuple[Path, SourceBinding, int | None]:
    """Resolve *source_arg* and pick its annotation, exiting when either is missing.

    Returns ``(path, annotation, va)``. An explicit ``--va`` or positional
    hex VA selects that entry in the active target; a missing entry errors.
    Without a VA, select the requested symbol or the file's first entry.
    """
    path = require_source_arg(cfg, source_arg, json_mode=json_mode)

    annos = read_source_bindings(
        path,
        target_name=target_marker(cfg),
        metadata_dir=cfg.metadata_dir,
        project_root=getattr(cfg, "root", None),
    )
    if not annos:
        error_exit("No function binding found in the source", json_mode=json_mode)
    requested_va = va
    if (
        requested_va is None
        and source_arg.strip().lower().startswith("0x")
        and not Path(source_arg).is_file()
    ):
        requested_va = source_arg
    if requested_va is not None:
        want = parse_va(requested_va, json_mode=json_mode)
        selected = next((a for a in annos if a.va == want), None)
        if selected is None:
            error_exit(f"No function annotation at 0x{want:x} in {path}", json_mode=json_mode)
        return path, selected, want
    if not source_arg.strip().lower().startswith("0x") and not Path(source_arg).exists():
        from rebrew.rename_ops import c_name_from_symbol
        from rebrew.utils import fold_ident

        # The C name and the symbol both count. ``hook@@12`` answers
        # ``hook``. ``__foo`` answers ``_foo``, not ``foo``.
        want_sym = fold_ident(source_arg.strip())
        for a in annos:
            candidates = []
            if a.name:
                candidates.append(fold_ident(a.name.strip()))
            if a.symbol:
                symbol = a.symbol.strip()
                candidates.append(fold_ident(symbol))
                candidates.append(fold_ident(c_name_from_symbol(symbol)))
            if want_sym in candidates:
                return path, a, a.va
    return path, annos[0], annos[0].va


__all__ = [
    "source_targets_run",
    "configured_target_names",
    "SourceTargetsOption",
    "AllTargetsOption",
    "EXIT_ERROR",
    "EXIT_INTERRUPTED",
    "EXIT_MISMATCH",
    "EXIT_OK",
    "EXIT_SIGPIPE",
    "QUIET_HELP",
    "RootOption",
    "SOURCE_HELP",
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
    "require_non_negative",
    "require_positive_size",
    "require_root",
    "require_source_arg",
    "resolve_binary_arg",
    "resolve_source_arg",
    "reset_verbosity",
    "run_cli",
    "run_for_each_target",
    "run_standalone",
    "select_annotation",
    "stdin_is_tty",
    "untrusted_ident",
    "untrusted_literal",
    "untrusted_text",
]
