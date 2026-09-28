"""Shared workspace/config resolution for the rebrew tools.

Stdlib-only apart from ``rebrew.errors``, a leaf module that imports nothing
and gives :class:`WorkspaceNotFound` and :class:`WorkspaceConfigError` the
shared ``RebrewError`` base.  Resolving a workspace never pulls in the rebrew
toolchain (no LIEF, capstone or tree-sitter), so a tool that only needs the
project's directories and target names pays nothing for the rest of the
package.

Coverage data itself lives in the clear-text ``coverage-<target>.toml``
documents, which this package no longer resolves: ``db_dir`` answers which
directory they are in, and :mod:`rebrew.coverage_toml` reads and writes them.
The SQLite helpers that used to live beside this module went with the
database.
"""

from rebrew.workspace.config import (
    CONFIG_NAME,
    DEFAULT_DB_DIR,
    DEFAULT_REVERSED_ROOT,
    WorkspaceConfigError,
    WorkspaceNotFound,
    db_dir,
    default_target,
    find_root,
    project_table,
    read_config,
    target_binary,
    target_marker,
    target_reversed_dir,
    targets_table,
    walk_up_to_root,
)
from rebrew.workspace.status import EARNED_STATUSES, KNOWN_STATUSES, MATCHED_STATUSES
from rebrew.workspace.va import VA_MAX, parse_va_candidates

__all__ = [
    "CONFIG_NAME",
    "DEFAULT_DB_DIR",
    "DEFAULT_REVERSED_ROOT",
    "EARNED_STATUSES",
    "KNOWN_STATUSES",
    "MATCHED_STATUSES",
    "VA_MAX",
    "WorkspaceConfigError",
    "WorkspaceNotFound",
    "db_dir",
    "default_target",
    "find_root",
    "parse_va_candidates",
    "project_table",
    "read_config",
    "target_binary",
    "target_marker",
    "target_reversed_dir",
    "targets_table",
    "walk_up_to_root",
]
