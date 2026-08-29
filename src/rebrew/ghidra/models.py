"""models.py - Data models for Ghidra/ReVa MCP responses and JSON-RPC protocol."""

from dataclasses import dataclass
from typing import Any


@dataclass
class JsonRpcError:
    """JSON-RPC error payload."""

    code: int
    message: str
    data: Any | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any] | str | Any) -> "JsonRpcError":
        """Reconstruct from dictionary."""
        if isinstance(d, str):
            return cls(code=-1, message=d, data=None)
        if not isinstance(d, dict):
            return cls(code=-1, message="Unknown error format", data=None)
        return cls(
            code=int(d.get("code", -1)),
            message=str(d.get("message", "Unknown error")),
            data=d.get("data"),
        )


@dataclass
class JsonRpcResponse:
    """JSON-RPC response payload."""

    jsonrpc: str
    id: int | str | None = None
    result: dict[str, Any] | None = None
    error: JsonRpcError | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "JsonRpcResponse":
        """Reconstruct from dictionary."""
        err = d.get("error")
        return cls(
            jsonrpc=str(d.get("jsonrpc", "2.0")),
            id=d.get("id"),
            result=d.get("result"),
            error=JsonRpcError.from_dict(err) if err else None,
        )


@dataclass
class McpToolContent:
    """Content item within a tool result."""

    type: str
    text: str

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "McpToolContent":
        """Reconstruct from dictionary."""
        return cls(type=str(d.get("type", "")), text=str(d.get("text", "")))


@dataclass
class McpToolResult:
    """Result from invoking an MCP tool."""

    content: list[McpToolContent]
    isError: bool = False

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "McpToolResult":
        """Reconstruct from dictionary."""
        return cls(
            content=[
                McpToolContent.from_dict(c) for c in d.get("content", []) if isinstance(c, dict)
            ],
            isError=bool(d.get("isError", False)),
        )
