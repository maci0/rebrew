"""ghidra — Sync rebrew annotations with Ghidra.

Field-level sync is BinSync-primary (the state dir + the BinSync Ghidra
plugin); the ReVa MCP surface here covers the structural ops BinSync cannot
express: function creation, bookmarks, and data pulls.

Public names resolve lazily via :func:`__getattr__`, so a caller that needs
only :data:`DEFAULT_MCP_ENDPOINT` does not pull the MCP client, the command
builders and the ``ghidra-cli`` backend in with it.  Resolution reads through
to the defining submodule on every access rather than caching into
``globals()``, so a caller that swaps an attribute on ``rebrew.ghidra.client``
(a test stand-in for the transport) is seen here too.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    # Mirrors _LAZY_EXPORTS so a consumer type-checking
    # ``from rebrew.ghidra import fetch_mcp_tool_raw`` sees the real signature
    # instead of ``Any`` from __getattr__.  tests/test_sdk_surface.py fails
    # when the two lists drift.  Nothing here runs at import time.
    from .cli_backend import (
        resolve_ghidra_cli as resolve_ghidra_cli,
    )
    from .client import (
        DEFAULT_MCP_ENDPOINT as DEFAULT_MCP_ENDPOINT,
    )
    from .client import (
        MCP_REQUEST_TIMEOUT_S as MCP_REQUEST_TIMEOUT_S,
    )
    from .client import (
        McpApplyAborted as McpApplyAborted,
    )
    from .client import (
        McpApplyResult as McpApplyResult,
    )
    from .client import (
        McpError as McpError,
    )
    from .client import (
        McpErrorKind as McpErrorKind,
    )
    from .client import (
        apply_commands_via_mcp as apply_commands_via_mcp,
    )
    from .client import (
        end_mcp_session as end_mcp_session,
    )
    from .client import (
        fetch_mcp_tool_raw as fetch_mcp_tool_raw,
    )
    from .client import (
        init_mcp_session as init_mcp_session,
    )
    from .commands import (
        build_bookmark_commands as build_bookmark_commands,
    )
    from .commands import (
        build_new_function_commands as build_new_function_commands,
    )
    from .commands import (
        resolve_program_path as resolve_program_path,
    )

_LAZY_EXPORTS: dict[str, str] = {
    "DEFAULT_MCP_ENDPOINT": ".client",
    "MCP_REQUEST_TIMEOUT_S": ".client",
    "McpApplyAborted": ".client",
    "McpApplyResult": ".client",
    "McpError": ".client",
    "McpErrorKind": ".client",
    "apply_commands_via_mcp": ".client",
    "end_mcp_session": ".client",
    "fetch_mcp_tool_raw": ".client",
    "init_mcp_session": ".client",
    "build_bookmark_commands": ".commands",
    "build_new_function_commands": ".commands",
    "resolve_program_path": ".commands",
    "resolve_ghidra_cli": ".cli_backend",
}

__all__ = [
    "DEFAULT_MCP_ENDPOINT",
    "MCP_REQUEST_TIMEOUT_S",
    "McpApplyAborted",
    "McpApplyResult",
    "McpError",
    "McpErrorKind",
    "apply_commands_via_mcp",
    "build_bookmark_commands",
    "build_new_function_commands",
    "end_mcp_session",
    "fetch_mcp_tool_raw",
    "init_mcp_session",
    "resolve_ghidra_cli",
    "resolve_program_path",
]


def __getattr__(name: str) -> Any:
    if name in _LAZY_EXPORTS:
        return getattr(import_module(_LAZY_EXPORTS[name], __name__), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(__all__) | {n for n in globals() if not n.startswith("_")})
