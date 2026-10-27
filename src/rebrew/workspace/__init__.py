"""Lightweight project resolution and shared STATUS/address vocabulary.

No coverage directory or database is configured here. Consumers resolve a project
root; portable export directories are explicit inputs to the coverage reader.
"""

lazy from rebrew.workspace.config import (
    CONFIG_NAME,
    DEFAULT_REVERSED_ROOT,
    WorkspaceConfigError,
    WorkspaceNotFound,
    default_target,
    find_root,
    project_table,
    read_config,
    target_binary,
    target_module,
    target_reversed_dir,
    targets_table,
    walk_up_to_root,
)
lazy from rebrew.workspace.status import EARNED_STATUSES, KNOWN_STATUSES, MATCHED_STATUSES
lazy from rebrew.workspace.va import VA_MAX, parse_va_candidates

__all__ = [
    "CONFIG_NAME",
    "DEFAULT_REVERSED_ROOT",
    "EARNED_STATUSES",
    "KNOWN_STATUSES",
    "MATCHED_STATUSES",
    "VA_MAX",
    "WorkspaceConfigError",
    "WorkspaceNotFound",
    "default_target",
    "find_root",
    "parse_va_candidates",
    "project_table",
    "read_config",
    "target_binary",
    "target_module",
    "target_reversed_dir",
    "targets_table",
    "walk_up_to_root",
]
