"""Shared workspace/config and coverage.db resolution for the rebrew tools.

Stdlib-only (``tomllib``, ``sqlite3``, ``pathlib``, ``json``, ``contextlib``),
so recoverage and reportal can use it without importing the rebrew stack
(LIEF, capstone, tree-sitter).
"""

from rebrew.workspace.config import (
    CONFIG_NAME,
    DB_FILENAME,
    DEFAULT_DB_DIR,
    DEFAULT_REVERSED_ROOT,
    WorkspaceNotFound,
    db_dir,
    db_path,
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
from rebrew.workspace.db import (
    DB_VERSION_KEY,
    SCHEMA_TARGET,
    db_version_matches,
    read_db_version,
    sqlite_ro_uri,
)
from rebrew.workspace.status import MATCHED_STATUSES
from rebrew.workspace.va import VA_MAX, parse_va_candidates

__all__ = [
    "CONFIG_NAME",
    "DB_FILENAME",
    "DB_VERSION_KEY",
    "DEFAULT_DB_DIR",
    "DEFAULT_REVERSED_ROOT",
    "MATCHED_STATUSES",
    "SCHEMA_TARGET",
    "VA_MAX",
    "WorkspaceNotFound",
    "db_dir",
    "db_path",
    "db_version_matches",
    "default_target",
    "find_root",
    "parse_va_candidates",
    "project_table",
    "read_config",
    "read_db_version",
    "sqlite_ro_uri",
    "target_binary",
    "target_marker",
    "target_reversed_dir",
    "targets_table",
    "walk_up_to_root",
]
