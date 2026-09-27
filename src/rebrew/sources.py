"""Source-tree discovery for reversed C/C++ sources.

Single home for locating the source files that make up a target: configured
extensions (:func:`source_exts`), glob patterns (:func:`source_glob`),
recursive enumeration incl. shared sources (:func:`iter_sources`), library
headers (:func:`iter_library_headers`), and the per-target annotation marker
(:func:`target_marker`).  Pure pathlib/config logic — no CLI or output
concerns — so library modules (catalog, matcher, core) can depend on it
without pulling in the presentation layer.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from pathlib import Path

from rebrew.config import ProjectConfig

logger = logging.getLogger(__name__)


def source_exts(cfg: ProjectConfig | None) -> list[str]:
    """Return the configured source extensions as a list, e.g. ``[".c", ".cpp"]``.

    ``cfg.source_ext`` may hold a single extension or a comma-separated
    list (``".c,.cpp"``); falls back to ``[".c"]`` when ``cfg`` is ``None`` or
    the value is empty.
    """
    raw = getattr(cfg, "source_ext", None) if cfg is not None else None
    if not raw:
        return [".c"]
    return [ext for ext in (part.strip() for part in raw.split(",")) if ext]


def source_glob(cfg: ProjectConfig | None) -> str:
    """Return glob pattern for source files based on the configured extension.

    Uses ``cfg.source_ext`` (e.g. ``".c"``, ``".cpp"``, ``".c,.cpp"``) to
    build a pattern like ``"*.c"``, ``"*.cpp"`` or ``"*.{c,cpp}"``.  Falls
    back to ``"*.c"`` if ``cfg`` is ``None`` or ``source_ext`` is empty.  The brace form is a
    display/validation convenience — :func:`iter_sources` expands multi-
    extension configs by filtering suffixes rather than relying on brace
    support in ``pathlib``.
    """
    exts = source_exts(cfg)
    if not exts:
        return "*.c"
    if len(exts) == 1:
        return f"*{exts[0]}"
    return f"*.{{{','.join(e.lstrip('.') for e in exts)}}}"


def target_marker(cfg: ProjectConfig | None) -> str | None:
    """Return the target marker name from *cfg*, or ``None`` if unavailable.

    Shorthand for the ``cfg.marker if cfg else None`` pattern that appears
    at every ``parse_c_file_multi`` / ``parse_library_header`` call site.
    """
    return cfg.marker if cfg is not None else None


#: Directories the source walk must not descend into (see :func:`_files_matching`).
_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    "__pycache__",
    ".venv",
    "venv",
    "build",
    "dist",
    ".tox",
    "node_modules",
}


def _files_matching(directory: Path | str, predicate: Callable[[Path], bool]) -> list[Path]:
    """Sorted non-symlink files under *directory* matching *predicate*, skipping :data:`_EXCLUDE_DIRS`.

    A directory the walk cannot enter is logged and skipped rather than
    silently dropped: every consumer (``verify``, ``test``, ``rename``,
    orphan pruning) treats the result as the complete inventory, so a
    permission-denied or stale-mount subtree would otherwise look like an
    absent one.
    """
    dir_path = Path(directory)

    def _on_walk_error(exc: OSError) -> None:
        logger.warning("skipping unreadable source directory %s: %s", exc.filename, exc)

    matches: list[Path] = []
    for root, dirs, files in os.walk(dir_path, onerror=_on_walk_error):
        dirs[:] = [name for name in dirs if name not in _EXCLUDE_DIRS]
        for f in files:
            p = Path(root) / f
            if not p.is_symlink() and predicate(p):
                matches.append(p)
    return sorted(matches)


def _library_headers_under(directory: Path | str) -> list[Path]:
    """``library_*.h`` files under *directory*, skipping :data:`_EXCLUDE_DIRS`.

    The exclusion set matches :func:`files_with_ext` — without it the header
    scan descended into ``build/``, ``.venv/``, and a copied dependency tree,
    counting their headers as the project's own library markers.
    """
    return _files_matching(
        directory, lambda p: p.name.startswith("library_") and p.name.endswith(".h")
    )


def _resolve_dir_and_cfg(
    directory: Path | str | ProjectConfig,
    cfg: ProjectConfig | None,
) -> tuple[Path, ProjectConfig | None]:
    if isinstance(directory, ProjectConfig) or hasattr(directory, "reversed_dir"):
        if cfg is None:
            cfg = directory  # type: ignore[assignment]
        target_dir = getattr(directory, "reversed_dir", "")
    else:
        target_dir = directory
    return Path(target_dir), cfg


def _should_include_shared(dir_path: Path, cfg: ProjectConfig | None) -> Path | None:
    if cfg is None:
        return None
    shared = getattr(cfg, "shared_dir", None)
    reversed_dir = getattr(cfg, "reversed_dir", None)
    if (
        shared is not None
        and reversed_dir is not None
        and dir_path.resolve() == Path(reversed_dir).resolve()
        and shared.is_dir()
        and Path(shared).resolve() != dir_path.resolve()
    ):
        return Path(shared)
    return None


def iter_library_headers(
    directory: Path | str | ProjectConfig,
    cfg: ProjectConfig | None = None,
) -> list[Path]:
    """Return all library_*.h files under *directory*, recursively.

    *directory* may be a :class:`pathlib.Path`, string path, or a
    :class:`ProjectConfig` instance (which defaults *directory* to
    ``cfg.reversed_dir``).

    With *cfg*, the project's shared root (``cfg.shared_dir``) joins the scan
    when *directory* IS the target's ``reversed_dir`` — the same rule
    :func:`iter_sources` applies to sources, and what
    :func:`rebrew.catalog.scan_reversed_dir` already did for headers.  Without
    it, shared ``library_*.h`` markers are invisible to coverage (`status`,
    `todo`), `crt-match`, the call graph, and ``rebrew context``.
    """
    dir_path, cfg = _resolve_dir_and_cfg(directory, cfg)
    files = _library_headers_under(dir_path)
    shared = _should_include_shared(dir_path, cfg)
    if shared is not None:
        files = sorted(set(files) | set(_library_headers_under(shared)))
    return files


def files_with_ext(directory: Path | str, wanted: set[str]) -> list[Path]:
    """Sorted files under *directory* whose lower-cased suffix is in *wanted*.

    Shared by the target's own scan and the shared-sources scan so both halves
    apply the same extension set and the same exclusion rules.
    """
    return _files_matching(directory, lambda p: p.suffix.lower() in wanted)


def iter_sources(
    directory: Path | str | ProjectConfig,
    cfg: ProjectConfig | None = None,
) -> list[Path]:
    """Return all source files under *directory*, recursively, sorted by path.

    *directory* may be a :class:`pathlib.Path`, string path, or a
    :class:`ProjectConfig` instance (which defaults *directory* to
    ``cfg.reversed_dir``).

    Uses :func:`source_exts` to determine the file extensions and an
    ``os.walk`` to descend into nested subdirectories, skipping
    :data:`_EXCLUDE_DIRS` (``.git``, ``.venv``, ``build``, …) at every
    level.  Extension matching is case-insensitive (``FOO.C`` counts as
    ``.c``), uniformly for single- and
    multi-extension configs (e.g. ``source_ext = ".c,.cpp"``).  This is the
    single entry point for discovering reversed source files — using it
    everywhere ensures consistent support for both flat and nested directory
    layouts.

    When *cfg* is provided and *directory* is the target's ``reversed_dir``,
    the project's shared-sources root (``cfg.shared_dir``, e.g.
    ``src/shared``) is merged in: files there serve **every** target, with
    one ``// FUNCTION: <target> <va>`` marker per target and ``#ifdef``
    deltas driven by the per-target ``defines``.
    """
    dir_path, cfg = _resolve_dir_and_cfg(directory, cfg)
    exts = source_exts(cfg) or [".c"]
    wanted = {ext.lower() for ext in exts}
    base = files_with_ext(dir_path, wanted)

    shared = _should_include_shared(dir_path, cfg)
    if shared is not None:
        shared_files = files_with_ext(shared, wanted)
        return sorted(set(base) | set(shared_files))
    return base


def iter_headers(
    directory: Path | str | ProjectConfig,
    cfg: ProjectConfig | None = None,
) -> list[Path]:
    """Project ``*.h`` files under *directory*, including the shared root.

    Headers are not translation units, so :func:`iter_sources` stays on the
    configured source extension and a ``.h`` is never compiled or counted as
    a function file. Data declarations live here too: the data scan and
    rename walk this list beside the sources.
    """
    dir_path, cfg = _resolve_dir_and_cfg(directory, cfg)
    files = files_with_ext(dir_path, {".h"})
    shared = _should_include_shared(dir_path, cfg)
    if shared is not None:
        files = sorted(set(files) | set(files_with_ext(shared, {".h"})))
    return files


def iter_sources_and_headers(
    directory: Path | str | ProjectConfig,
    cfg: ProjectConfig | None = None,
) -> list[Path]:
    """Sources first, then headers that are not already in that list.

    Sources come first so a ``.c`` definition is recorded before a header
    redeclaration of the same name. A header the source-extension list
    already includes is not yielded twice.
    """
    sources = list(iter_sources(directory, cfg))
    seen = {path.resolve() for path in sources}
    return sources + [path for path in iter_headers(directory, cfg) if path.resolve() not in seen]


__all__ = [
    "files_with_ext",
    "iter_headers",
    "iter_library_headers",
    "iter_sources",
    "iter_sources_and_headers",
    "source_exts",
    "source_glob",
    "target_marker",
]
