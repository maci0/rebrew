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
from typing import Any, NoReturn

import typer
from rich.console import Console
from rich.markup import escape

from rebrew.config import ProjectConfig, load_config
from rebrew.metadata import MATCHED_STATUSES
from rebrew.sources import iter_sources, target_marker

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
#: command — and the decode is linear in cache size.
_VERIFY_CACHE_MEMO: dict[tuple[str, int, int], dict[str, Any] | None] = {}


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
    key = (str(cache_path), st.st_mtime_ns, st.st_size)
    if key in _VERIFY_CACHE_MEMO:
        return _VERIFY_CACHE_MEMO[key]
    try:
        raw: dict[str, Any] | None = json.loads(cache_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        raw = None
    _VERIFY_CACHE_MEMO[key] = raw
    return raw


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
        _err_console.print(f"[red bold]error:[/red bold] {escape(msg)}")
    raise typer.Exit(code=code)


def json_print(data: dict[str, Any] | list[Any]) -> None:
    """Print *data* as pretty-printed JSON to stdout."""
    print(json.dumps(data, indent=2))


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
        return int(va_str.strip(), 16)
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
    :param metadata_dir: Parent of ``reversed_dir`` where ``rebrew-function.toml``
        lives.  When ``None``, metadata is not merged (only source annotations
        are parsed).
    """
    import logging

    from rebrew.annotation import parse_c_file_multi  # local import to avoid cycle

    results: list[tuple[Path, list[Any]]] = []
    for src in sources:
        try:
            annos = parse_c_file_multi(src, target_name=target, metadata_dir=metadata_dir)
        except ValueError:
            # A malformed annotation block silently drops the whole function
            # from verify/todo/status output — visible at WARNING, not DEBUG.
            logging.warning("Skipping %s due to annotation parse error", src, exc_info=True)
            continue
        if annos:
            results.append((src, annos))
    return results


def resolve_cflags(
    cfg: ProjectConfig | None, per_function_cflags: str | None, module: str = ""
) -> str:
    """Resolve the effective CFLAGS for a function.

    Fallback chain: per-function metadata CFLAGS → per-module
    ``cflags_presets`` (``rebrew cfg set-cflags``) → ``[compiler].cflags``
    → ``"/O2 /Gd"``.  Single source of truth so match/diff/verify/test/
    prove agree on the flags a function compiles with — a per-module preset
    must not make ``rebrew match`` report EXACT while ``rebrew verify``
    recompiles with different flags and demotes it.
    """
    cflags = (per_function_cflags or "").strip()
    if not cflags and cfg is not None:
        cflags = getattr(cfg, "cflags_presets", {}).get(module.upper(), "")
    if not cflags:
        cfg_cflags = getattr(cfg, "cflags", "") if cfg is not None else ""
        # An EXPLICITLY set empty cflags means "no default flags" — the
        # /O2 /Gd fallback applies only when the key is absent (config-review
        # F5: `cflags = ""` previously compiled with /O2 /Gd silently).
        if not (cfg is not None and getattr(cfg, "cflags_explicit", False)):
            # The /O2 /Gd fallback is MSVC-only: gcc/watcom/tcc reject "/O2"
            # as a nonexistent input file.  Posix-style profiles fall back to
            # no user flags instead — mirroring the base_cflags loader
            # default in config.py, which fixed this same bug class there.
            msvc_default = "" if getattr(cfg, "posix_style", False) else "/O2 /Gd"
            cfg_cflags = cfg_cflags or msvc_default
        cflags = cfg_cflags
    return cflags


def _resolve_overrides_steps(
    cfg: ProjectConfig | None,
    source_dir: str | Path,
    per_function_toolchain: str | None,
    per_function_cflags: str | None,
    module: str = "",
) -> tuple[str | None, str, list[dict[str, Any]]]:
    """Resolve the effective (toolchain, cflags) and record the decision chain.

    Core of :func:`resolve_compile_overrides` — same fallback chain, plus a
    list of *steps* documenting every decision point so ``rebrew diagnose``
    can explain *why* a function compiles with the compiler+flags it does.
    Each step is a dict with a ``source`` key: ``"function"`` (per-function
    metadata), ``"library"`` (nearest ``rebrew-library.toml`` + presets), or
    ``"project"`` (project defaults and which fallbacks applied)."""
    steps: list[dict[str, Any]] = []
    toolchain = (per_function_toolchain or "").strip() or None
    cflags = (per_function_cflags or "").strip()
    steps.append({"source": "function", "toolchain": toolchain or "", "cflags": cflags})
    if toolchain is None or not cflags:
        from rebrew.metadata import find_library_override

        root = getattr(cfg, "root", None) if cfg is not None else None
        ovr = find_library_override(source_dir, root)
        if ovr is not None:
            if toolchain is None and ovr.toolchain:
                toolchain = ovr.toolchain
            if not cflags and ovr.cflags:
                cflags = ovr.cflags
            steps.append(
                {
                    "source": "library",
                    "path": str(ovr.path),
                    "toolchain": ovr.toolchain,
                    "cflags": ovr.cflags,
                    "presets": list(ovr.presets),
                }
            )
        else:
            steps.append({"source": "library", "path": None})
    final_cflags = resolve_cflags(cfg, cflags or None, module)
    steps.append(
        {
            "source": "project",
            "profile": getattr(cfg, "compiler_profile", "") if cfg is not None else "",
            "cflags": getattr(cfg, "cflags", "") if cfg is not None else "",
            "cflags_explicit": bool(getattr(cfg, "cflags_explicit", False))
            if cfg is not None
            else False,
            "posix_style": bool(getattr(cfg, "posix_style", False)) if cfg is not None else False,
            "module_preset": (
                getattr(cfg, "cflags_presets", {}).get(module.upper(), "")
                if cfg is not None
                else ""
            ),
        }
    )
    return toolchain, final_cflags, steps


def resolve_compile_overrides(
    cfg: ProjectConfig | None,
    source_dir: str | Path,
    per_function_toolchain: str | None,
    per_function_cflags: str | None,
    module: str = "",
) -> tuple[str | None, str]:
    """Resolve the effective (toolchain, cflags) for one source file.

    Fallback chain, most specific first:

    1. per-function metadata (rebrew-function.toml TOOLCHAIN / CFLAGS),
    2. the nearest per-library ``rebrew-library.toml`` (walk-up from
       *source_dir*; its known-library presets fill missing fields),
    3. project defaults (``[compiler]`` profile/cflags via ``resolve_cflags``).

    This is the single source of truth so verify / test / match / prove all
    compile every function of a library with the same compiler + flags.
    Returns ``(toolchain, cflags)`` — toolchain is ``None`` when no override
    names a compiler (project default profile applies)."""
    toolchain, cflags, _steps = _resolve_overrides_steps(
        cfg, source_dir, per_function_toolchain, per_function_cflags, module
    )
    return toolchain, cflags


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

    # Symbol name — match against the file stem.
    for src in iter_sources(src_dir, cfg):
        if src.stem == source_arg or src.stem == source_arg.lstrip("_"):
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
