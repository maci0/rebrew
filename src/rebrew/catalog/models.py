from dataclasses import dataclass
from typing import Any


@dataclass
class GhidraFunction:
    va: int
    size: int
    name: str = ""
    ghidra_name: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GhidraFunction":
        return cls(
            va=d.get("va", 0),
            size=d.get("size", 0),
            name=d.get("name") or d.get("ghidra_name", ""),
            ghidra_name=d.get("ghidra_name", ""),
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
