"""Shared workspace/config and coverage.db resolution for the rebrew tools.

Stdlib-only for everything except the ``section_cells_json`` codec
(``encode``/``decode_section_cells``, which defer their ``zstandard`` import to
the call).  Resolving a workspace and reading a coverage.db never pulls in the
rebrew toolchain — no LIEF, capstone or tree-sitter — and never requires a
compression dependency either.  The codec is still shared rather than
duplicated per consumer: one definition, imported only by callers that actually
move cell blobs.
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
    CELLS_JSON_OBJECT_SQL,
    DB_VERSION_KEY,
    SCHEMA_TARGET,
    SECTION_CELLS_COLUMN,
    SECTION_CELLS_TABLE,
    db_version_matches,
    decode_section_cells,
    encode_section_cells,
    read_db_version,
    sqlite_ro_uri,
)
from rebrew.workspace.status import MATCHED_STATUSES
from rebrew.workspace.va import VA_MAX, parse_va_candidates

__all__ = [
    "CELLS_JSON_OBJECT_SQL",
    "CONFIG_NAME",
    "DB_FILENAME",
    "DB_VERSION_KEY",
    "DEFAULT_DB_DIR",
    "DEFAULT_REVERSED_ROOT",
    "MATCHED_STATUSES",
    "SCHEMA_TARGET",
    "SECTION_CELLS_COLUMN",
    "SECTION_CELLS_TABLE",
    "VA_MAX",
    "WorkspaceNotFound",
    "db_dir",
    "db_path",
    "db_version_matches",
    "decode_section_cells",
    "encode_section_cells",
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
