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

from rebrew.config import ProjectConfig, load_config

# ---------------------------------------------------------------------------
# Standardised exit codes
# ---------------------------------------------------------------------------

EXIT_OK = 0  # Success (all functions matched / no errors)
EXIT_MISMATCH = 1  # Actionable failure (fix your code)
EXIT_ERROR = 2  # Infrastructure error (build/config broken)

# Match-quality threshold for NEAR_MATCHING vs STUB classification.
# A function that matches >= 60 % of bytes is NEAR_MATCHING; below is STUB.
NEAR_MATCH_THRESHOLD = 0.60

# Minimum plausible virtual address.  VAs below this threshold are almost
# certainly invalid (PE image base is typically 0x10000000 or higher).
# Used across verify, annotation, and naming to reject bad entries early.
MIN_VALID_VA = 0x1000

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
    "MISSING_FILE": "red",
    "MISSING_SIZE": "red",
    "SKIP": "dim",
}


def is_matched(status: str) -> bool:
    """True when *status* indicates a fully matched function (EXACT, RELOC, or PROVEN)."""
    return status in ("EXACT", "RELOC", "PROVEN")


def is_status_sticky(current_status: str) -> bool:
    """True when *current_status* should never be demoted by test/verify.

    PROVEN is a post-verify promotion from ``rebrew prove`` — byte-level
    comparison cannot reproduce it, so test/verify must preserve it.
    """
    return current_status == "PROVEN"


def should_promote_status(current_status: str, new_status: str) -> bool:
    """True when *new_status* should overwrite *current_status* in metadata.

    Single canonical promotion decision shared by ``rebrew test`` and
    ``rebrew verify``.  Refuses to promote when the current status is sticky
    (PROVEN), when a STUB's placeholder size-mismatch would erase the user's
    STUB classification, or when the status did not change.
    """
    if is_status_sticky(current_status):
        return False
    if current_status == "STUB" and new_status == "SIZE_MISMATCH":
        return False
    return current_status != new_status


def classify_match_status(
    matched: bool,
    match_count: int,
    total: int,
    relocs: list[int] | tuple[()] = (),
) -> str:
    """Determine the canonical status string from match results.

    Centralises the EXACT / RELOC / NEAR_MATCHING / STUB decision for
    raw match results.

    :param matched: True when all non-reloc bytes match.
    :param match_count: Number of matching bytes.
    :param total: Total byte count considered.
    :param relocs: Relocation offsets (non-empty → RELOC instead of EXACT).
    """
    if matched:
        return "RELOC" if relocs else "EXACT"
    if total > 0 and (match_count / total) >= NEAR_MATCH_THRESHOLD:
        return "NEAR_MATCHING"
    return "STUB"


# Re-usable Typer option for --target
TargetOption: str | None = typer.Option(
    None,
    "--target",
    "-t",
    help="Target name from rebrew-project.toml (default: project default target).",
)


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


def error_exit(msg: str, *, json_mode: bool = False, code: int = 1) -> NoReturn:
    """Print *msg* as an error and ``raise typer.Exit(code)``.

    In JSON mode the envelope is ``{"error": <msg>, "code": <exit_code>}`` so
    callers can distinguish mismatch (1) from infrastructure errors (2) without
    relying solely on the process exit status.
    """
    if json_mode:
        print(json.dumps({"error": msg, "code": code}, indent=2))
    else:
        _err_console.print(f"[red bold]error:[/red bold] {msg}")
    raise typer.Exit(code=code)


def json_print(data: dict[str, Any] | list[Any]) -> None:
    """Print *data* as pretty-printed JSON to stdout."""
    print(json.dumps(data, indent=2))


def parse_va(va_str: str, *, json_mode: bool = False) -> int:
    """Parse a hexadecimal virtual-address string, exiting on invalid input.

    Always interprets as base-16 (with or without ``0x`` prefix).
    """
    try:
        return int(va_str.strip(), 16)
    except ValueError:
        error_exit(f"Invalid hex VA: {va_str!r}", json_mode=json_mode)


def source_glob(cfg: ProjectConfig | None) -> str:
    """Return glob pattern for source files based on the configured extension.

    Uses ``cfg.source_ext`` (e.g. ``".c"``, ``".cpp"``) to build a pattern
    like ``"*.c"`` or ``"*.cpp"``.  Falls back to ``"*.c"`` if the attribute
    is missing.
    """
    ext = cfg.source_ext if cfg is not None else ".c"
    return f"*{ext}"


def target_marker(cfg: ProjectConfig | None) -> str | None:
    """Return the target marker name from *cfg*, or ``None`` if unavailable.

    Shorthand for the ``cfg.marker if cfg else None`` pattern that appears
    at every ``parse_c_file_multi`` / ``parse_library_header`` call site.
    """
    return cfg.marker if cfg is not None else None


def rel_display_path(filepath: Path, base_dir: Path | None = None) -> str:
    """Return a display-friendly relative path for a source file.

    If *base_dir* is provided, returns the path relative to it (e.g.
    ``"game/pool_free.c"`` for nested dirs, or ``"pool_free.c"`` for flat
    layouts).  Falls back to ``filepath.name`` if the file is not under
    *base_dir*.
    """
    if base_dir is not None:
        try:
            return str(filepath.relative_to(base_dir))
        except ValueError:
            pass
    return filepath.name


def iter_library_headers(directory: Path) -> list[Path]:
    """Return all library_*.h files under *directory*, recursively."""
    return sorted(directory.rglob("library_*.h"))


def iter_sources(directory: Path, cfg: ProjectConfig | None = None) -> list[Path]:
    """Return all source files under *directory*, recursively, sorted by path.

    Uses :func:`source_glob` to determine the file extension and ``rglob``
    to descend into nested subdirectories.  This is the single entry point
    for discovering reversed source files — using it everywhere ensures
    consistent support for both flat and nested directory layouts.
    """
    pattern = source_glob(cfg)
    return sorted(directory.rglob(pattern))


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
            logging.debug("Skipping %s due to parse error", src, exc_info=True)
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
            except Exception:  # noqa: BLE001 — per-file parse noise in a scan
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
