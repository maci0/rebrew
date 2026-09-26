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
import os
import stat
import sys
import unicodedata
import warnings
from collections.abc import Callable
from pathlib import Path
from typing import Any, NoReturn

import typer
from rich.console import Console
from rich.markup import escape

from rebrew.annotation import Annotation, parse_c_file_multi
from rebrew.config import ConfigWarning, ProjectConfig, load_config
from rebrew.sources import iter_sources, target_marker
from rebrew.utils import parse_int_literal
from rebrew.workspace.status import MATCHED_STATUSES

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

# Canonical Rich colour tags for status strings — used across CLI tools
# for consistent output formatting.
STATUS_COLORS: dict[str, str] = {
    "EXACT": "bold green",
    "RELOC": "green",
    "PROVEN": "bold cyan",
    "NEAR_MATCHING": "yellow",
    "SIZE_MISMATCH": "yellow",
    "STUB": "dim",
    "COMPILE_ERROR": "red",
    "EXTRACT_ERROR": "red",
    "MISSING_FILE": "red",
    "MISSING_SIZE": "red",
    "INVALID_VA": "red",
    "INTERNAL_ERROR": "red",
    "SKIP": "dim",
}

# Page and call-graph marks for the same statuses. Text on white (report,
# dashboard) and white on the fill (Mermaid, DOT) both meet WCAG AA.
# STUB is slate, like the dim terminal tag, not an error red. DISPATCH is
# the report header ink: a jump table is structure, not a match status.
STATUS_HEX: dict[str, str] = {
    "EXACT": "#15803d",
    "RELOC": "#0369a1",
    "PROVEN": "#0e7490",
    "NEAR_MATCHING": "#b45309",
    "STUB": "#475569",
    "UNKNOWN": "#555",
    "DISPATCH": "#1a1a1a",
}

# User-visible classification statuses, in canonical display order: the
# byte-matched ones, then PROVEN (semantically equivalent, bytes differ),
# then the unmatched ones.
DISPLAY_STATUSES: tuple[str, ...] = (*MATCHED_STATUSES, "PROVEN", "NEAR_MATCHING", "STUB")


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

console = Console(stderr=True)

#: C0/C1 controls except tab and newline, rendered as ``\xNN``.  Error text
#: carries remote response bodies and binary-derived names; a raw ESC would
#: let them drive the terminal (OSC title/clipboard writes, screen clears).
_TERMINAL_CONTROL_CHARS = {
    code: f"\\x{code:02x}"
    for code in (*range(0x20), *range(0x7F, 0xA0))
    if code not in (ord("\t"), ord("\n"))
}


def error_exit(msg: str, *, json_mode: bool = False, code: int = EXIT_ERROR) -> NoReturn:
    """Print *msg* as an error and ``raise typer.Exit(code)``.

    In JSON mode the envelope is ``{"error": <msg>, "code": <exit_code>}`` so
    callers can distinguish mismatch (1) from infrastructure errors (2) without
    relying solely on the process exit status.

    *msg* is rendered literally (Rich markup escaped, terminal control
    characters other than tab/newline shown as ``\\xNN``): error text often
    embeds file contents, paths, and remote responses that must not be
    interpreted as markup or escape sequences.
    """
    if json_mode:
        print(json.dumps({"error": msg, "code": code}, indent=2))
    else:
        # soft_wrap keeps embedded commands/paths contiguous — without it
        # Rich folds mid-token (e.g. `rebrew catalog …` → `rebrew\ncatalog`).
        safe = escape(msg.translate(_TERMINAL_CONTROL_CHARS))
        console.print(f"[red bold]error:[/red bold] {safe}", soft_wrap=True)
    raise typer.Exit(code=code)


def json_print(data: dict[str, Any] | list[Any]) -> None:
    """Print *data* as pretty-printed JSON to stdout."""
    print(json.dumps(data, indent=2))


def run_standalone(main: Any) -> None:
    """Run a module's ``main`` callback as a plain command on a fresh app.

    The group-style ``invoke_without_command`` callback fails to parse
    positional-then-option invocations (``rebrew-<cmd> ARG --opt`` — click
    treats the positional as a command name), while the umbrella's command
    registration parses both orderings.
    """
    _standalone = typer.Typer()
    _standalone.command()(main)
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
    """
    warnings.simplefilter("ignore", ConfigWarning)
    stdout_was_fifo = _stdout_is_fifo()
    try:
        try:
            app()
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
    for src in sources:
        if unicodedata.normalize("NFC", src.stem) == arg_norm:
            return src
    arg_stem = arg_norm.lstrip("_")
    for src in sources:
        if unicodedata.normalize("NFC", src.stem).lstrip("_") == arg_stem:
            return src

    return p


def select_annotation(
    cfg: ProjectConfig, source_arg: str, va: str | None, *, json_mode: bool = False
) -> tuple[Path, Annotation, int | None]:
    """Resolve *source_arg* and pick its annotation, exiting when either is missing.

    Returns ``(path, annotation, va)``: the annotation whose VA equals *va*
    (else the file's first), and *va* parsed when given, else the
    annotation's own VA (``None`` when it has none).
    """
    path = resolve_source_arg(cfg, source_arg)
    if not path.is_file():
        error_exit(f"Source file not found: {path}", json_mode=json_mode)

    annos = parse_c_file_multi(path, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir)
    if not annos:
        error_exit("No // FUNCTION annotation found in the source", json_mode=json_mode)
    if not va:
        return path, annos[0], annos[0].va
    want = parse_va(va, json_mode=json_mode)
    return path, next((a for a in annos if a.va == want), annos[0]), want


__all__ = [
    "AllTargetsOption",
    "DISPLAY_STATUSES",
    "EXIT_ERROR",
    "EXIT_INTERRUPTED",
    "EXIT_MISMATCH",
    "EXIT_OK",
    "EXIT_SIGPIPE",
    "STATUS_COLORS",
    "STATUS_HEX",
    "TargetOption",
    "all_targets_run",
    "console",
    "error_exit",
    "json_print",
    "option_default",
    "parse_va",
    "require_config",
    "resolve_binary_arg",
    "resolve_source_arg",
    "run_cli",
    "run_for_each_target",
    "run_standalone",
    "select_annotation",
]
