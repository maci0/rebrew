"""``rebrew-project.toml`` lookup and coverage.db path resolution.

One implementation of the resolution recoverage, reportal and rebrew each
carried separately: recoverage's ``_paths._db_path``, reportal's
``cli._resolve_rebrew_db`` / ``auto_llm_worker.target_config`` and rebrew's
``config.walk_up_to_root`` / ``find_root``.

Reading the config is deliberately tolerant: :func:`read_config` returns ``{}``
for a missing, unreadable or invalid file so path resolution can fall back to
its defaults.  :func:`find_root` is the one hard failure, for callers that
cannot proceed without a workspace.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

CONFIG_NAME = "rebrew-project.toml"

#: Directory used when ``[project].db_dir`` is absent or empty.
DEFAULT_DB_DIR = "db"

#: Filename inside :func:`db_dir`.
DB_FILENAME = "coverage.db"

#: Default reversed-source root when a target sets no ``reversed_dir``.
DEFAULT_REVERSED_ROOT = "src"

#: Characters kept in a derived target marker (identifier-shaped only).
_MARKER_KEEP = re.compile(r"[^A-Za-z0-9_]")


class WorkspaceNotFound(FileNotFoundError):
    """No directory containing ``rebrew-project.toml`` was found."""


def walk_up_to_root(start: Path) -> Path | None:
    """Walk up from *start* (inclusive) looking for ``rebrew-project.toml``.

    Returns the directory containing the marker file, or ``None`` when the
    walk reaches the filesystem root without finding one.  The marker must be
    a regular file, so a directory named ``rebrew-project.toml`` does not
    satisfy the search.
    """
    candidate = start.resolve()
    while candidate != candidate.parent:
        if (candidate / CONFIG_NAME).is_file():
            return candidate
        candidate = candidate.parent
    return None


def find_root(start: Path | None = None) -> Path:
    """Return the workspace root holding ``rebrew-project.toml``.

    *start*, when given, is checked first and returned as-is (resolved) if it
    carries the marker; otherwise the walk-up proceeds from *start*.  With no
    *start* the walk begins at the current working directory.

    Raises :class:`WorkspaceNotFound` when no ancestor carries the marker.
    Unlike rebrew's ``find_root``, a bare directory is not passed through
    unchanged: this function either finds a workspace or raises.
    """
    origin = Path.cwd() if start is None else start.resolve()
    if start is not None and (origin / CONFIG_NAME).is_file():
        return origin
    found = walk_up_to_root(origin)
    if found is None:
        raise WorkspaceNotFound(
            f"Could not find {CONFIG_NAME} in any parent of {origin}. "
            f"Run this command from within a project that contains {CONFIG_NAME}."
        )
    return found


def read_config(root: Path) -> dict[str, Any]:
    """Parse ``<root>/rebrew-project.toml``.

    Returns ``{}`` when the file is missing, unreadable, not UTF-8 or not
    valid TOML.  Never raises.
    """
    try:
        return tomllib.loads((root / CONFIG_NAME).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return {}


def project_table(config: dict[str, Any]) -> dict[str, Any]:
    """The ``[project]`` table, or ``{}`` when it is absent or not a table."""
    project = config.get("project")
    return project if isinstance(project, dict) else {}


def targets_table(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The ``[targets]`` entries that are tables, keyed by target name."""
    targets = config.get("targets")
    if not isinstance(targets, dict):
        return {}
    entries: dict[str, dict[str, Any]] = {}
    for name, entry in targets.items():
        if isinstance(name, str) and isinstance(entry, dict):
            entries[name] = entry
    return entries


def default_target(config: dict[str, Any]) -> str | None:
    """``[project].default_target`` when it names a target, else the first one."""
    targets = targets_table(config)
    configured = project_table(config).get("default_target")
    if isinstance(configured, str) and configured in targets:
        return configured
    return next(iter(targets), None)


def target_marker(name: str, entry: dict[str, Any]) -> str:
    """Annotation marker for *name*: its ``marker``, else the name sanitized."""
    marker = entry.get("marker")
    if isinstance(marker, str) and marker.strip():
        return marker
    return _MARKER_KEEP.sub("", name).upper()


def target_reversed_dir(root: Path, name: str, entry: dict[str, Any]) -> Path:
    """Reversed-source directory: ``reversed_dir``, else ``root/src/<name>``."""
    configured = entry.get("reversed_dir")
    if isinstance(configured, str) and configured.strip():
        return root / configured
    return root / DEFAULT_REVERSED_ROOT / name


def target_binary(root: Path, entry: dict[str, Any]) -> Path | None:
    """The target binary: ``binary`` resolved against *root*, or ``None``.

    An absolute ``binary`` is returned unchanged; a missing or empty value
    yields ``None`` (callers decide whether that is fatal).
    """
    configured = entry.get("binary")
    if not isinstance(configured, str) or not configured.strip():
        return None
    path = Path(configured)
    return path if path.is_absolute() else root / path


def db_dir(root: Path) -> Path:
    """Directory holding coverage.db: ``[project].db_dir``, else ``root/db``."""
    configured = project_table(read_config(root)).get("db_dir")
    if isinstance(configured, str) and configured.strip():
        return (root / configured.strip()).resolve()
    return (root / DEFAULT_DB_DIR).resolve()


def db_path(root: Path) -> Path:
    """``<db_dir>/coverage.db``."""
    return db_dir(root) / DB_FILENAME
