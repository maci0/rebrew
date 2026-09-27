"""``rebrew-project.toml`` lookup and coverage.db path resolution.

One implementation of the resolution recovery, reportal and rebrew each
carried separately: recovery's ``_paths._db_path``, reportal's
``cli._resolve_rebrew_db`` / ``auto_llm_worker.target_config`` and rebrew's
``config.walk_up_to_root`` / ``find_root``.

Reading the config tolerates its *absence*: :func:`read_config` returns ``{}``
when there is no ``rebrew-project.toml`` so path resolution can fall back to
its defaults.  A file that is there and cannot be parsed raises
:class:`WorkspaceConfigError` instead, because the defaults it would fall back
to (``db/``, the first target, ``src/<name>``) point somewhere else entirely
and the result reads as a healthy empty workspace.  :func:`find_root` is the
other hard failure, for callers that cannot proceed without a workspace.
"""

from __future__ import annotations

import os
import re
import tomllib
import unicodedata
from pathlib import Path
from typing import Any

from rebrew.errors import RebrewError

CONFIG_NAME = "rebrew-project.toml"


def config_path(rel: str | Path) -> Path:
    """Build a :class:`~pathlib.Path` from a config / YAML / CLI path string.

    Project files and splat YAML may use Windows separators.  On POSIX,
    ``Path("src\\\\foo.c")`` is a single name component containing a
    literal backslash, so ``src\\\\foo.c`` never resolves to ``src/foo.c``.
    Absolute Windows drive paths (``C:/…``) stay non-absolute on POSIX and
    are left for the caller to reject.
    """
    return Path(os.fspath(rel).replace("\\", "/"))


#: Directory used when ``[project].db_dir`` is absent or empty.
DEFAULT_DB_DIR = "db"

#: Filename inside :func:`db_dir`.
DB_FILENAME = "coverage.db"

#: Default reversed-source root when a target sets no ``reversed_dir``.
DEFAULT_REVERSED_ROOT = "src"

#: Characters kept in a derived target marker (identifier-shaped only).
_MARKER_KEEP = re.compile(r"[^A-Za-z0-9_]")


class WorkspaceNotFound(RebrewError, FileNotFoundError):
    """No directory containing ``rebrew-project.toml`` was found."""


class WorkspaceConfigError(RebrewError):
    """``rebrew-project.toml`` exists but cannot be read as TOML.

    Distinct from :class:`WorkspaceNotFound`: the workspace is there, so
    there is nothing to search for, and every path this module resolves is
    about to be a guess.
    """


def walk_up_to_root(start: Path | str) -> Path | None:
    """Walk up from *start* (inclusive) looking for ``rebrew-project.toml``.

    Returns the directory containing the marker file, or ``None`` when the
    walk reaches the filesystem root without finding one.  The marker must be
    a regular file, so a directory named ``rebrew-project.toml`` does not
    satisfy the search.
    """
    candidate = Path(start).resolve()
    while candidate != candidate.parent:
        if (candidate / CONFIG_NAME).is_file():
            return candidate
        candidate = candidate.parent
    return None


def find_root(start: Path | str | None = None) -> Path:
    """Return the workspace root holding ``rebrew-project.toml``.

    *start*, when given, is checked first and returned as-is (resolved) if it
    carries the marker; otherwise the walk-up proceeds from *start*.  With no
    *start* the walk begins at the current working directory.

    Raises :class:`WorkspaceNotFound` when no ancestor carries the marker.
    Unlike ``rebrew.config.find_root``, which treats an explicit *start* as
    the project root verbatim, this one checks the marker and walks up.
    """
    origin = Path.cwd() if start is None else Path(start).resolve()
    if start is not None and (origin / CONFIG_NAME).is_file():
        return origin
    found = walk_up_to_root(origin)
    if found is None:
        raise WorkspaceNotFound(
            f"Could not find {CONFIG_NAME} in any parent of {origin}. "
            f"Run this command from within a project that contains {CONFIG_NAME}."
        )
    return found


def read_config(root: Path | str) -> dict[str, Any]:
    """Parse ``<root>/rebrew-project.toml``.

    Returns ``{}`` when there is no config file, so a caller that only wants
    a default path does not have to know whether the workspace has one.
    Raises :class:`WorkspaceConfigError` when the file is present but is not
    readable UTF-8 TOML (bad syntax, wrong encoding, a directory or an
    unreadable path under that name): every value this module reads from it
    would then come from a default that names a different workspace.
    """
    path = Path(root) / CONFIG_NAME
    try:
        text = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeDecodeError) as exc:
        raise WorkspaceConfigError(f"cannot read {path}: {exc}") from exc
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise WorkspaceConfigError(f"{path} is not valid TOML: {exc}") from exc


def project_table(config: dict[str, Any]) -> dict[str, Any]:
    """The ``[project]`` table, or ``{}`` when it is absent or not a table."""
    project = config.get("project")
    return project if isinstance(project, dict) else {}


def targets_table(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The ``[targets]`` entries that are tables, keyed by target name."""
    targets = config.get("targets")
    if not isinstance(targets, dict):
        return {}
    return {
        name: entry
        for name, entry in targets.items()
        if isinstance(name, str) and isinstance(entry, dict)
    }


def default_target(config: dict[str, Any]) -> str | None:
    """``[project].default_target`` when it names a target, else the first one."""
    targets = targets_table(config)
    configured = project_table(config).get("default_target")
    if isinstance(configured, str) and configured in targets:
        return configured
    return next(iter(targets), None)


def target_marker(name: str, entry: dict[str, Any]) -> str:
    """Annotation marker for *name*: its ``marker``, else the name sanitized.

    An explicit marker is normalized to NFC, matching
    :func:`rebrew.config.module_marker`: the marker is the ``MODULE`` half of
    every ``MODULE.0xVA`` metadata key, so an NFD-spelled config value would
    miss the NFC-spelled entry a reader derives from the source.  The derived
    branch keeps only ASCII, so it needs no normalization.
    """
    marker = entry.get("marker")
    if isinstance(marker, str) and marker.strip():
        return unicodedata.normalize("NFC", marker)
    return _MARKER_KEEP.sub("", name).upper()


def target_reversed_dir(root: Path, name: str, entry: dict[str, Any]) -> Path:
    """Reversed-source directory: ``reversed_dir``, else ``root/src/<name>``."""
    configured = entry.get("reversed_dir")
    if isinstance(configured, str) and configured.strip():
        return root / config_path(configured)
    return root / DEFAULT_REVERSED_ROOT / name


def target_binary(root: Path, entry: dict[str, Any]) -> Path | None:
    """The target binary: ``binary`` resolved against *root*, or ``None``.

    An absolute ``binary`` is returned unchanged; a missing or empty value
    yields ``None`` (callers decide whether that is fatal).
    """
    configured = entry.get("binary")
    if not isinstance(configured, str) or not configured.strip():
        return None
    path = config_path(configured)
    return path if path.is_absolute() else root / path


def db_dir(root: Path) -> Path:
    """Directory holding coverage.db: ``[project].db_dir``, else ``root/db``."""
    configured = project_table(read_config(root)).get("db_dir")
    if isinstance(configured, str) and configured.strip():
        return (root / config_path(configured.strip())).resolve()
    return (root / DEFAULT_DB_DIR).resolve()


def db_path(root: Path) -> Path:
    """``<db_dir>/coverage.db``."""
    return db_dir(root) / DB_FILENAME
