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

from pathlib import Path

from rebrew.config import ProjectConfig


def source_exts(cfg: ProjectConfig | None) -> list[str]:
    """Return the configured source extensions as a list, e.g. ``[".c", ".cpp"]``.

    ``cfg.source_ext`` may hold a single extension or a comma-separated
    list (``".c,.cpp"``); falls back to ``[".c"]`` when the attribute is
    missing or empty.
    """
    raw = cfg.source_ext if cfg is not None else ".c"
    if not raw:
        return [".c"]
    return [ext for ext in (part.strip() for part in raw.split(",")) if ext]


def source_glob(cfg: ProjectConfig | None) -> str:
    """Return glob pattern for source files based on the configured extension.

    Uses ``cfg.source_ext`` (e.g. ``".c"``, ``".cpp"``, ``".c,.cpp"``) to
    build a pattern like ``"*.c"``, ``"*.cpp"`` or ``"*.{c,cpp}"``.  Falls
    back to ``"*.c"`` if the attribute is missing.  The brace form is a
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


def _library_headers_under(directory: Path) -> list[Path]:
    """``library_*.h`` files under *directory*, skipping :data:`_EXCLUDE_DIRS`.

    The exclusion set matches :func:`_files_with_ext` — without it the header
    scan descended into ``build/``, ``.venv/``, and a copied dependency tree,
    counting their headers as the project's own library markers.
    """
    return sorted(
        p
        for p in directory.rglob("library_*.h")
        if not p.is_symlink()
        and not any(part in _EXCLUDE_DIRS for part in p.relative_to(directory).parts[:-1])
    )


def iter_library_headers(directory: Path, cfg: ProjectConfig | None = None) -> list[Path]:
    """Return all library_*.h files under *directory*, recursively.

    With *cfg*, the project's shared root (``cfg.shared_dir``) joins the scan
    when *directory* IS the target's ``reversed_dir`` — the same rule
    :func:`iter_sources` applies to sources, and what
    :func:`rebrew.catalog.scan_reversed_dir` already did for headers.  Without
    it, shared ``library_*.h`` markers are invisible to coverage (`status`,
    `todo`), `crt-match`, the call graph, and ``rebrew context``.
    """
    files = _library_headers_under(directory)
    if cfg is None:
        return files
    shared = getattr(cfg, "shared_dir", None)
    reversed_dir = getattr(cfg, "reversed_dir", None)
    if (
        shared is not None
        and reversed_dir is not None
        and Path(directory).resolve() == Path(reversed_dir).resolve()
        and shared.is_dir()
        and Path(shared).resolve() != Path(directory).resolve()
    ):
        files = sorted(set(files) | set(_library_headers_under(shared)))
    return files


#: Directories rglob must not descend into when scanning for sources.
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


def _files_with_ext(directory: Path, wanted: set[str]) -> list[Path]:
    """Sorted files under *directory* whose lower-cased suffix is in *wanted*.

    Shared by the target's own scan and the shared-sources scan so both halves
    apply the same extension set and the same exclusion rules.
    """
    return sorted(
        p
        for p in directory.rglob("*")
        if p.is_file()
        and p.suffix.lower() in wanted
        and not any(part in _EXCLUDE_DIRS for part in p.relative_to(directory).parts[:-1])
        and not p.is_symlink()
    )


def iter_sources(directory: Path, cfg: ProjectConfig | None = None) -> list[Path]:
    """Return all source files under *directory*, recursively, sorted by path.

    Uses :func:`source_exts` to determine the file extensions and ``rglob``
    to descend into nested subdirectories.  Extension matching is
    case-insensitive (``FOO.C`` counts as ``.c``), uniformly for single- and
    multi-extension configs (e.g. ``source_ext = ".c,.cpp"``).  This is the
    single entry point for discovering reversed source files — using it
    everywhere ensures consistent support for both flat and nested directory
    layouts.

    When *cfg* is provided and *directory* is the target's ``reversed_dir``,
    the project's shared-sources root (``cfg.shared_dir``, e.g.
    ``src/shared``) is appended: files there serve **every** target, with
    one ``// FUNCTION: <target> <va>`` marker per target and ``#ifdef``
    deltas driven by the per-target ``defines``.
    """
    exts = source_exts(cfg) or [".c"]
    wanted = {ext.lower() for ext in exts}
    base = _files_with_ext(directory, wanted)

    if cfg is None:
        return base
    shared = getattr(cfg, "shared_dir", None)
    reversed_dir = getattr(cfg, "reversed_dir", None)
    if (
        shared is not None
        and reversed_dir is not None
        # Shared sources belong to the target's reversed_dir scan ONLY —
        # a scan of any other directory with cfg must not pull them in.
        and Path(directory).resolve() == Path(reversed_dir).resolve()
        and shared.is_dir()
        and Path(shared).resolve() != Path(directory).resolve()
    ):
        # Same extension set as the target's own scan: the shared half used to
        # be globbed through a `cfg=None` recursive call, which silently fell
        # back to `[".c"]` and dropped every shared `.cpp`/`.cc` source.
        shared_files = _files_with_ext(shared, wanted)
        return sorted(set(base) | set(shared_files))
    return base
