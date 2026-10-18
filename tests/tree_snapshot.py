"""Whole-tree snapshots that ignore regenerable runtime caches.

A project's ``.rebrew`` directory holds derived state: parsed-document
sidecars, the verify cache, extern-name and name-map covers. Read and preview
commands may fill it without changing project content, so a snapshot that
counts those files as writes reports a false regression. These helpers keep
the "writes nothing" assertions about the user's project files.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

CACHE_DIRNAME = ".rebrew"


def project_files(root: Path) -> list[Path]:
    """Every file under *root* outside the runtime cache directory, sorted."""
    return [
        path
        for path in sorted(root.rglob("*"))
        if path.is_file() and CACHE_DIRNAME not in path.relative_to(root).parts
    ]


def snapshot(root: Path) -> dict[Path, bytes]:
    """Map every project file to its bytes."""
    return {path: path.read_bytes() for path in project_files(root)}


def snapshot_with_stat(root: Path) -> dict[Path, tuple[bytes, os.stat_result]]:
    """Map every project file to its bytes and stat, for no-touch assertions."""
    return {path: (path.read_bytes(), path.stat()) for path in project_files(root)}


def top_level_snapshot(root: Path) -> dict[Path, bytes]:
    """Map every direct child file of *root* to its bytes, skipping directories."""
    return {path: path.read_bytes() for path in sorted(root.iterdir()) if path.is_file()}


def digest(root: Path) -> dict[str, str]:
    """Map every project-relative file path to the sha256 of its bytes."""
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in project_files(root)
    }
