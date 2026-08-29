"""ghidra — Sync rebrew annotations with Ghidra.

Field-level sync is BinSync-primary (the state dir + the BinSync Ghidra
plugin); the ReVa MCP surface here covers the structural ops BinSync cannot
express: function creation, bookmarks, and data pulls.
"""

from rebrew.ghidra.cli import app as app
from rebrew.ghidra.cli_backend import (
    resolve_ghidra_cli as resolve_ghidra_cli,
)
from rebrew.ghidra.client import (
    apply_commands_via_mcp as apply_commands_via_mcp,
)
from rebrew.ghidra.commands import (
    build_bookmark_commands as build_bookmark_commands,
)
from rebrew.ghidra.commands import (
    build_new_function_commands as build_new_function_commands,
)

__all__ = [
    "app",
    "apply_commands_via_mcp",
    "build_bookmark_commands",
    "build_new_function_commands",
    "resolve_ghidra_cli",
]
