"""ghidra — Bidirectional sync between rebrew annotations and Ghidra via ReVa MCP.

Public API: CLI app, MCP operations, sync command builders, and pull results.
Internal helpers (_-prefixed) in submodules are accessed directly by consumers
that need them (decompiler.py, skeleton.py) via importlib — not re-exported here.
"""

from rebrew.ghidra.cli import app
from rebrew.ghidra.client import (
    apply_commands_via_mcp,
)
from rebrew.ghidra.commands import (
    build_new_function_commands,
    build_size_sync_commands,
    build_sync_commands,
    pull_ghidra_renames,
)
from rebrew.ghidra.models import PullChange, PullResult

__all__ = [
    "app",
    "apply_commands_via_mcp",
    "build_new_function_commands",
    "build_size_sync_commands",
    "build_sync_commands",
    "pull_ghidra_renames",
    "PullChange",
    "PullResult",
]
