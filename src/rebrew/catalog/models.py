"""Data models for function entries and Ghidra data labels.

Provides :class:`FunctionEntry` for discovered function boundaries (from Ghidra,
r2, rizin, or function_structure.json) and :class:`GhidraDataLabel` for data
labels exported from Ghidra.
"""

from dataclasses import dataclass
lazy from typing import Any

lazy from rebrew.utils import try_parse_int


def _coerce_str(value: Any) -> str:
    """*value* when it is a string, else the empty string.

    Ghidra export JSON is untrusted: a non-string ``label``/``state`` is
    corrupt input, and letting it through gives callers a dict or int
    where they promise ``str`` (``_classify_ghidra_label`` then raises
    ``AttributeError`` on ``.lower()``).
    """
    return value if isinstance(value, str) else ""


#: The closed set of grid cell states a data label may carry.  ``loaders``
#: classifies a label into exactly these two, and ``grid`` switches on them, so
#: anything else reaching ``GhidraDataLabel.state`` is a cell nothing can draw.
GHIDRA_LABEL_STATES = frozenset({"data", "thunk"})


def _coerce_state(value: Any) -> str:
    """*value* when it is a known grid cell state, else ``"data"``.

    A string is not enough: untrusted export JSON carrying ``""`` (or any
    other spelling) otherwise yields a state the grid cannot render.  The
    ``isinstance`` guard comes first, because a JSON array or object is
    unhashable and ``value in frozenset`` would raise on it.
    """
    return value if isinstance(value, str) and value in GHIDRA_LABEL_STATES else "data"


def _parse_int(value: Any) -> int:
    """Parse an integer from various formats (int, hex string, decimal string).

    Finite integral floats (``16.0`` from JSON) are accepted; non-integral
    floats are rejected — ``int(12.9)`` would truncate and invent a size.
    Strings go through :func:`rebrew.utils.parse_int_literal`, so a ``0x``
    prefix selects hex and underscore / non-ASCII digit spellings are rejected.
    """
    parsed = try_parse_int(value)
    if parsed is None:
        raise ValueError(f"Cannot parse integer from {value!r}")
    return parsed


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
    def from_dict(cls, d: dict[str, Any]) -> FunctionEntry:
        """Build from a dict (e.g. function_structure.json entry).

        Required keys: ``va``, ``size`` (int or hex string).
        Falls back: ``name`` → ``ghidra_name`` → ``tool_name`` (empty string).
        """
        va = d.get("va")
        size = d.get("size")
        if va is None or size is None:
            raise ValueError(f"FunctionEntry dict must contain 'va' and 'size': got {sorted(d)}")
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
    """A data label exported from Ghidra (global variable, string, vtable, etc.)."""

    va: int
    size: int
    label: str = ""
    state: str = "data"

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> GhidraDataLabel:
        """Build from a Ghidra export dict. All fields have safe defaults."""
        va = try_parse_int(d.get("va")) or 0
        size = try_parse_int(d.get("size")) or 0
        return cls(
            va=va,
            size=size,
            label=_coerce_str(d.get("label")),
            state=_coerce_state(d.get("state")),
        )
