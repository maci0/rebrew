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

import copy
import json
import logging
import threading
from pathlib import Path
from typing import Any, NoReturn

import typer
from rich.console import Console
from rich.markup import escape

from rebrew.config import ProjectConfig, load_config
from rebrew.metadata import MATCHED_STATUSES
from rebrew.sources import iter_sources, target_marker
from rebrew.utils import parse_int_literal

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


#: mtime-keyed memo of the raw verify-cache JSON (perf-review F4): status and
#: todo both decode .rebrew/verify_cache.json every run — sometimes twice per
#: command — and the decode is linear in cache size.  At most one entry per
#: path: a rewrite changes mtime/size, and keeping the old key would retain
#: the previous full JSON payload for the process lifetime.  Cap distinct
#: paths so a long-lived process that touches many project roots cannot
#: retain every decoded payload.
#: Guarded: eviction is a multi-step mutation on a shared dict; concurrent
#: status/todo/build-db callers (or a ThreadingHTTPServer) must not race it.
_VERIFY_CACHE_MEMO: dict[tuple[str, int, int], dict[str, Any] | None] = {}
_VERIFY_CACHE_MEMO_MAX = 8
_VERIFY_CACHE_MEMO_LOCK = threading.Lock()


def load_verify_cache_raw(cfg: Any) -> dict[str, Any] | None:
    """Load the shared ``.rebrew/verify_cache.json`` as a raw dict (memoized).

    Returns ``None`` when the file is missing or corrupt.  Target/version
    validation is the caller's responsibility — readers apply their own
    guards (status vs todo differ slightly).  Memoized by (path, mtime,
    size), so repeated loads within one command are free.
    """
    cache_path = Path(cfg.root) / ".rebrew" / "verify_cache.json"
    try:
        st = cache_path.stat()
    except OSError:
        return None
    path_key = str(cache_path)
    key = (path_key, st.st_mtime_ns, st.st_size)
    with _VERIFY_CACHE_MEMO_LOCK:
        if key in _VERIFY_CACHE_MEMO:
            cached = _VERIFY_CACHE_MEMO[key]
            return copy.deepcopy(cached) if cached is not None else None
    try:
        raw: dict[str, Any] | None = json.loads(cache_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        # UnicodeDecodeError is a ValueError, not an OSError: a cache holding
        # non-UTF-8 bytes (truncated/tampered) used to escape this guard and
        # crash `status`/`todo` instead of degrading to "no cache".
        # Log so a corrupt cache is not mistaken for a cold start.
        logging.getLogger(__name__).warning("Ignoring corrupt verify cache %s: %s", cache_path, exc)
        raw = None
    with _VERIFY_CACHE_MEMO_LOCK:
        # Another thread may have filled the same key while we decoded.
        if key in _VERIFY_CACHE_MEMO:
            cached = _VERIFY_CACHE_MEMO[key]
            return copy.deepcopy(cached) if cached is not None else None
        # Drop prior fingerprints for this path before storing — otherwise each
        # verify rewrite orphans a full decoded dict under the old mtime key.
        stale = [k for k in _VERIFY_CACHE_MEMO if k[0] == path_key]
        for old in stale:
            del _VERIFY_CACHE_MEMO[old]
        # Evict another path's entry when at capacity (FIFO on insertion order).
        while len(_VERIFY_CACHE_MEMO) >= _VERIFY_CACHE_MEMO_MAX:
            oldest = next(iter(_VERIFY_CACHE_MEMO))
            del _VERIFY_CACHE_MEMO[oldest]
        _VERIFY_CACHE_MEMO[key] = raw
    return copy.deepcopy(raw) if raw is not None else None


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
        return parse_int_literal(va_str, base=16)
    except ValueError:
        error_exit(f"Invalid hex VA: {va_str!r}", json_mode=json_mode, code=EXIT_ERROR)


def iter_annotations(
    sources: list[Path],
    *,
    target: str | None = None,
    metadata_dir: Path | None = None,
) -> list[tuple[Path, list[Any]]]:
    """Parse annotations from each source in *sources*, silently skipping failures.

    Returns a list of ``(path, annotations)`` pairs — only entries where at
    least one annotation was parsed are included.  Uses
    :func:`rebrew.annotation.parse_c_file_multi` internally.

    This is the single shared idiom for batch-mode annotation loading,
    replacing the copy-pasted try/except pattern that was spread across
    ``todo.py``, ``verify.py``, ``test.py``, ``match.py``, and others.

    :param sources: List of paths returned by :func:`iter_sources`.
    :param target:  Optional marker string passed through to
        ``parse_c_file_multi`` (use :func:`target_marker` to obtain it).
    :param metadata_dir: Parent of ``reversed_dir`` where ``rebrew-functions.toml``
        lives.  When ``None``, metadata is not merged (only source annotations
        are parsed).
    """
    import logging

    from rebrew.annotation import parse_c_file_multi  # local import to avoid cycle

    results: list[tuple[Path, list[Any]]] = []
    for src in sources:
        try:
            annos = parse_c_file_multi(src, target_name=target, metadata_dir=metadata_dir)
        except Exception:
            # Any per-source failure (parse error, I/O, encoding) silently
            # drops the whole function from verify/todo/status output — one
            # bad file must never abort a batch run.  Visible at WARNING.
            logging.warning("Skipping %s due to annotation parse error", src, exc_info=True)
            continue
        if annos:
            results.append((src, annos))
    return results


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
        import angr  # noqa: F401

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
    "iter_annotations",
    "json_print",
    "load_verify_cache_raw",
    "option_default",
    "parse_va",
    "require_config",
    "resolve_source_arg",
    "run_standalone",
]
