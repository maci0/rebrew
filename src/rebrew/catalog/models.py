from dataclasses import dataclass
from typing import Any


def _parse_int(value: Any) -> int:
    """Parse an integer from various formats (int, hex string, decimal string)."""
    if isinstance(value, int):
        return value
    s = str(value).strip()
    try:
        return int(s, 0)  # auto-detect base: 0x prefix → hex, plain digits → decimal
    except (ValueError, TypeError) as e:
        raise ValueError(f"Cannot parse integer from {value!r}: {e}")


@dataclass
class FunctionEntry:
    """A discovered function boundary from any RE tool (Ghidra, r2, rizin).

    ``va`` and ``size`` are the structural authority.
    ``tool_name`` is an optional hint (e.g. Ghidra's auto-generated label)
    used only for stub filename generation when no source annotation exists.
    """

    va: int
    size: int
    name: str = ""
    tool_name: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "FunctionEntry":
        va = d.get("va")
        size = d.get("size")
        if va is None or size is None:
            raise ValueError("FunctionEntry dictionary must contain 'va' and 'size' keys")
        va = _parse_int(va)
        size = _parse_int(size)
        return cls(
            va=va,
            size=size,
            name=str(d.get("name") or d.get("ghidra_name") or d.get("tool_name", "")),
            tool_name=str(d.get("tool_name") or d.get("ghidra_name", "")),
        )


@dataclass
class GhidraDataLabel:
    va: int
    size: int
    label: str = ""
    state: str = "data"

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GhidraDataLabel":
        return cls(
            va=d.get("va", 0),
            size=d.get("size", 0),
            label=d.get("label", ""),
            state=d.get("state", "data"),
        )
