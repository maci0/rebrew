from dataclasses import dataclass, field
from typing import Any


@dataclass
class PullChange:
    """A single proposed change from a pull operation."""

    va: int
    field: str
    local_value: str
    ghidra_value: str
    filepath: str
    action: str  # "update", "conflict", "skip"
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        d: dict[str, Any] = {
            "va": f"0x{self.va:08x}",
            "field": self.field,
            "local": self.local_value,
            "ghidra": self.ghidra_value,
            "file": self.filepath,
            "action": self.action,
        }
        if self.reason:
            d["reason"] = self.reason
        return d


@dataclass
class PullResult:
    """Aggregated result of a pull operation."""

    changes: list[PullChange] = field(default_factory=list)
    updated: int = 0
    skipped: int = 0
    conflicts: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        return {
            "updated": self.updated,
            "skipped": self.skipped,
            "conflicts": self.conflicts,
            "changes": [c.to_dict() for c in self.changes],
        }


@dataclass
class JsonRpcError:
    code: int
    message: str
    data: Any | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any] | str | Any) -> "JsonRpcError":
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
    jsonrpc: str
    id: int | str | None = None
    result: dict[str, Any] | None = None
    error: JsonRpcError | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "JsonRpcResponse":
        err = d.get("error")
        return cls(
            jsonrpc=str(d.get("jsonrpc", "2.0")),
            id=d.get("id"),
            result=d.get("result"),
            error=JsonRpcError.from_dict(err) if err else None,
        )


@dataclass
class McpToolContent:
    type: str
    text: str

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "McpToolContent":
        return cls(type=str(d.get("type", "")), text=str(d.get("text", "")))


@dataclass
class McpToolResult:
    content: list[McpToolContent]
    isError: bool = False

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "McpToolResult":
        return cls(
            content=[
                McpToolContent.from_dict(c) for c in d.get("content", []) if isinstance(c, dict)
            ],
            isError=bool(d.get("isError", False)),
        )


@dataclass
class RevaProgramInfo:
    programPath: str

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RevaProgramInfo":
        return cls(programPath=str(d.get("programPath", "")))


@dataclass
class RevaFunction:
    address: str
    size: int
    name: str = ""
    signature: str = ""
    decompilation: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RevaFunction":
        return cls(
            address=str(d.get("address") or d.get("va") or ""),
            size=int(d.get("size", 0)),
            name=str(d.get("name") or d.get("ghidra_name", "")),
            signature=str(d.get("signature", "")),
            decompilation=str(d.get("decompilation", "")),
        )


@dataclass
class RevaPageHeader:
    totalCount: int
    nextStartIndex: int

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RevaPageHeader":
        return cls(
            totalCount=int(d.get("totalCount", 0)), nextStartIndex=int(d.get("nextStartIndex", 0))
        )


@dataclass
class RevaDataType:
    name: str
    size: int = 0
    cDefinition: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any] | str) -> "RevaDataType":
        if isinstance(d, str):
            return cls(name=d)
        return cls(
            name=str(d.get("name", "")),
            size=int(d.get("size", 0)),
            cDefinition=str(d.get("cDefinition", "")),
        )


@dataclass
class RevaDataLabel:
    address: str
    size: int
    name: str = ""
    displayString: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RevaDataLabel":
        return cls(
            address=str(d.get("address", "")),
            size=int(d.get("size", 0)),
            name=str(d.get("name", "")),
            displayString=str(d.get("displayString", "")),
        )


@dataclass
class RevaDataInfo:
    address: str
    name: str = ""
    byteLength: int = 0
    dataType: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RevaDataInfo":
        return cls(
            address=str(d.get("address", "")),
            name=str(d.get("name", "")),
            byteLength=int(d.get("byteLength", 0)),
            dataType=str(d.get("dataType", "")),
        )
