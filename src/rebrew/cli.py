"""Shared CLI utilities for rebrew tools.

Provides common Typer options, config-loading helpers, and standardised
output / error helpers so that every tool gets consistent ``--target``
support, error reporting, VA parsing, and JSON output without boilerplate.

Usage in a tool::

    import typer
    from rebrew.cli import TargetOption, require_config, error_exit, json_print, parse_va

    app = typer.Typer()

    @app.command()
    def main(target: str = TargetOption) -> None:
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
# Global verbosity state — set by the top-level app callback in main.py.
# ---------------------------------------------------------------------------

verbosity: int = 0  # -1 = quiet, 0 = normal, 1+ = verbose


# Re-usable Typer option for --target
TargetOption: str | None = typer.Option(
    None,
    "--target",
    "-t",
    help="Target name from rebrew-project.toml (default: first target).",
)


def get_config(target: str | None = None) -> ProjectConfig:
    """Load the project config for the given target."""
    return load_config(target=target)


def require_config(target: str | None = None, *, json_mode: bool = False) -> ProjectConfig:
    """Load the project config, exiting with a user-friendly error on failure.

    Each except branch calls error_exit() which is typed ``NoReturn``; the
    explicit ``return cfg`` makes the successful code path unambiguous to
    static analysers (mypy/pyright) and avoids an implicit ``None`` return.
    """
    try:
        cfg = load_config(target=target)
    except FileNotFoundError as exc:
        error_exit(str(exc), json_mode=json_mode)
    except (KeyError, ValueError) as exc:
        error_exit(f"Config error: {exc}", json_mode=json_mode)
    return cfg  # reached only when load_config() succeeds; branches above are NoReturn


# ---------------------------------------------------------------------------
# Standardised output helpers
# ---------------------------------------------------------------------------

_err_console = Console(stderr=True)


def error_exit(msg: str, *, json_mode: bool = False, code: int = 1) -> NoReturn:
    """Print *msg* as an error and ``raise typer.Exit(code)``."""
    if json_mode:
        print(json.dumps({"error": msg}, indent=2))
    else:
        _err_console.print(f"[red bold]error:[/red bold] {msg}")
    raise typer.Exit(code=code)


def json_print(data: dict[str, Any] | list[Any]) -> None:
    """Print *data* as pretty-printed JSON to stdout."""
    print(json.dumps(data, indent=2))


def parse_va(va_str: str, *, json_mode: bool = False) -> int:
    """Parse a hex virtual-address string, exiting on invalid input.

    Accepts ``0x``-prefixed or bare hex strings.
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
    :param metadata_dir: The ``reversed_dir`` root where ``rebrew-function.toml``
        lives.  Required for metadata merging.
    """
    import logging

    from rebrew.annotation import parse_c_file_multi  # local import to avoid cycle

    results: list[tuple[Path, list[Any]]] = []
    for src in sources:
        try:
            annos = parse_c_file_multi(src, target_name=target, metadata_dir=metadata_dir)
        except ValueError as exc:
            logging.debug(f"Skipping {src} due to parse error: {exc}")
            continue
        if annos:
            results.append((src, annos))
    return results
