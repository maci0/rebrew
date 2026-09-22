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
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn

import typer
from rich.console import Console
from rich.markup import escape

from rebrew.config import ProjectConfig, load_config
from rebrew.sources import iter_sources, target_marker
from rebrew.utils import parse_int_literal
from rebrew.workspace.status import MATCHED_STATUSES

if TYPE_CHECKING:
    from rebrew.annotation import Annotation

# ---------------------------------------------------------------------------
# Standardised exit codes
# ---------------------------------------------------------------------------

EXIT_OK = 0  # Success (all functions matched / no errors)
EXIT_MISMATCH = 1  # Actionable failure (fix your code)
EXIT_ERROR = 2  # Infrastructure error (build/config broken)

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

# User-visible classification statuses, in canonical display order.
DISPLAY_STATUSES: tuple[str, ...] = (*MATCHED_STATUSES, "NEAR_MATCHING", "STUB")


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


def iter_target_configs(cfg: ProjectConfig, *, json_mode: bool = False) -> list[ProjectConfig]:
    """Per-target configs for an --all-targets run.

    Expands the already-loaded (default or explicit) config to one config
    per configured target, preserving project root.  Returns ``[cfg]`` when
    the project has one target.  A broken target raises here — callers that
    must survive one bad target (batch runners) should iterate
    ``cfg.all_targets`` with their own try/except instead.
    """
    names = list(getattr(cfg, "all_targets", []) or [])
    if len(names) <= 1:
        return [cfg]
    out: list[ProjectConfig] = []
    for name in names:
        try:
            out.append(load_config(root=cfg.root, target=name))
        except (FileNotFoundError, KeyError, ValueError) as exc:
            error_exit(f"Config error for target {name!r}: {exc}", json_mode=json_mode)
    return out


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
                _err_console.print(f"\n[bold cyan]=== Target {name} ===[/]")
                run_one(name)
        except typer.Exit as exc:
            worst = max(worst, int(getattr(exc, "exit_code", 0) or 0))
        except Exception as exc:
            logging.warning("target %s failed", name, exc_info=True)
            worst = max(worst, EXIT_ERROR)
            if not json_mode:
                _err_console.print(
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

_err_console = Console(stderr=True)


def error_exit(msg: str, *, json_mode: bool = False, code: int = EXIT_ERROR) -> NoReturn:
    """Print *msg* as an error and ``raise typer.Exit(code)``.

    In JSON mode the envelope is ``{"error": <msg>, "code": <exit_code>}`` so
    callers can distinguish mismatch (1) from infrastructure errors (2) without
    relying solely on the process exit status.

    *msg* is rendered literally (Rich markup escaped): error text often
    embeds file contents and paths that must not be interpreted as markup.
    """
    if json_mode:
        print(json.dumps({"error": msg, "code": code}, indent=2))
    else:
        # soft_wrap keeps embedded commands/paths contiguous — without it
        # Rich folds mid-token (e.g. `rebrew catalog …` → `rebrew\ncatalog`).
        _err_console.print(f"[red bold]error:[/red bold] {escape(msg)}", soft_wrap=True)
    raise typer.Exit(code=code)


def json_print(data: dict[str, Any] | list[Any]) -> None:
    """Print *data* as pretty-printed JSON to stdout."""
    print(json.dumps(data, indent=2))


def run_standalone(main: Any) -> None:
    """Run a module's ``main`` callback as a plain command on a fresh app.

    The group-style ``invoke_without_command`` callback fails to parse
    positional-then-option invocations (``rebrew-<cmd> ARG --opt`` — click
    treats the positional as a command name), while the umbrella's command
    registration parses both orderings (cli-review F1).
    """
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


def option_default(value: Any, default: Any) -> Any:
    """Coerce a possibly-leaked typer option back to its declared default.

    Direct Python calls to a typer callback (the unit-test convention in this
    codebase) pass ``typer.models.OptionInfo`` as the value of **omitted**
    parameters — typer's wrapper does not resolve the declared default for
    non-CLI invocations.  An ``OptionInfo`` object is truthy and not a
    ``Path``/``str``, so ``if x is not None`` and ``Path(x)`` both misbehave
    (this crashed ``rebrew init --link-tools-from`` when tests omitted the
    new option, and leaked a truthy ``--sweep-toolchain`` into ``match``'s
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


def resolve_source_arg(cfg: ProjectConfig, source_arg: str) -> Path:
    """Resolve a source argument to an existing source file path.

    Accepts a direct file path, a symbol name (matched against the file stem,
    tolerating the MSVC leading underscore), or a hex VA (e.g. ``0x01006364``,
    matched against function annotations).  Returns *source_arg* unchanged
    when nothing matches — the caller then reports the failure with context.
    """
    import contextlib
    import logging

    from rebrew.annotation import parse_c_file_multi  # local import to avoid cycle

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
    for src in iter_sources(src_dir, cfg):
        if src.stem == source_arg:
            return src
    arg_stem = source_arg.lstrip("_")
    for src in iter_sources(src_dir, cfg):
        if src.stem.lstrip("_") == arg_stem:
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
    from rebrew.annotation import parse_c_file_multi  # local import to avoid cycle

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


def angr_available() -> bool:
    """Return True when angr imports cleanly, without angr's import-time log spam.

    angr logs an ERROR about its optional unicorn engine at import time; a
    bare capability probe (``with contextlib.suppress(ImportError): import
    angr``) would print that alarming line to stderr on every CLI run that
    merely checks for the optional dependency.  Silence the ``angr`` logger
    for the duration of the probe — nothing else in the process uses it.
    """
    import contextlib
    import logging

    with contextlib.suppress(ImportError):
        logging.getLogger("angr").setLevel(logging.CRITICAL)
        import angr  # noqa: F401  # presence probe; name unused

        return True
    return False


__all__ = [
    "DISPLAY_STATUSES",
    "EXIT_ERROR",
    "EXIT_MISMATCH",
    "EXIT_OK",
    "STATUS_COLORS",
    "TargetOption",
    "angr_available",
    "error_exit",
    "json_print",
    "option_default",
    "parse_va",
    "require_config",
    "resolve_source_arg",
    "run_standalone",
]
