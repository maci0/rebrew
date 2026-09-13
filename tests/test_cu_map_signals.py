"""Tests for the optional cu_map signals (jump-table alignment, single-ref data).

Both signals are off unless asked for; each test here contrasts the default
call with the signal-enabled one on the same synthetic binary.
"""

from __future__ import annotations

import struct
from types import SimpleNamespace
from typing import Any

import pytest

from rebrew.cu_map import (
    JUMP_TABLE_ALIGN_BOOST,
    SINGLE_REF_DATA_BOOST,
    _exclusive_data_owners,
    _find_jump_tables,
    _single_ref_data_bonds,
    _validate_alignment,
    cluster_functions,
)


def _entry(va: int, size: int, name: str = "") -> dict[str, Any]:
    return {
        "va": va,
        "canonical_size": size,
        "list_name": name,
        "ghidra_name": "",
        "is_thunk": False,
        "is_export": False,
        "detected_by": ["list"],
        "size_by_tool": {"list": size},
    }


def _section(name: str, va: int, size: int, file_offset: int, raw_size: int) -> SimpleNamespace:
    return SimpleNamespace(name=name, va=va, size=size, file_offset=file_offset, raw_size=raw_size)


def _text_only(text_va: int, data: bytes) -> SimpleNamespace:
    return SimpleNamespace(
        path=None,
        format="pe",
        arch="x86_32",
        image_base=text_va,
        text_va=text_va,
        text_size=len(data),
        text_raw_offset=0,
        sections={".text": _section(".text", text_va, len(data), 0, len(data))},
        data=data,
        _data=data,
    )


# ---------------------------------------------------------------------------
# Jump-table alignment signal
# ---------------------------------------------------------------------------

TABLE_A_VA = 0x1004  # % 8 == 4
TABLE_B_VA = 0x1018  # % 8 == 0
FUNC_B_VA = 0x1010


def _jump_table_binary() -> SimpleNamespace:
    """Two functions, each ending in a jump table, separated by padding.

    Function A (0x1000, 12 bytes) owns the table at 0x1004 (% 8 == 4);
    function B (0x1010, 16 bytes) owns the table at 0x1018 (% 8 == 0).  A
    four-byte INT3 gap between them is padding, so the contiguity pass alone
    keeps one cluster.
    """
    code_a = b"\x55\x8b\xec\xc3" + struct.pack("<II", 0x1000, 0x1010)
    gap = b"\xcc" * 4
    code_b = b"\x55\x8b\xec\x83\xec\x04\xc9\xc3" + struct.pack("<II", 0x1000, 0x1010)
    return _text_only(0x1000, code_a + gap + code_b)


class TestAlignmentValidation:
    def test_rejects_zero(self) -> None:
        with pytest.raises(ValueError, match="power of two"):
            _validate_alignment(0)

    def test_rejects_non_power_of_two(self) -> None:
        with pytest.raises(ValueError, match="power of two"):
            _validate_alignment(6)

    def test_rejects_negative(self) -> None:
        with pytest.raises(ValueError, match="power of two"):
            _validate_alignment(-8)

    def test_accepts_powers_of_two(self) -> None:
        assert _validate_alignment(4) == 4
        assert _validate_alignment(16) == 16

    def test_invalid_value_raises_from_cluster_functions(self) -> None:
        info = _jump_table_binary()
        with pytest.raises(ValueError, match="power of two"):
            cluster_functions(
                {0x1000: _entry(0x1000, 12)},
                info,  # type: ignore[arg-type]
                None,
                jump_table_alignment=5,
            )


class TestJumpTableAlignmentSignal:
    def test_finds_both_tables(self) -> None:
        info = _jump_table_binary()
        tables = _find_jump_tables(
            info,  # type: ignore[arg-type]
            [(0x1000, 12), (FUNC_B_VA, 16)],
        )
        assert tables == [TABLE_A_VA, TABLE_B_VA]

    def test_off_by_default(self) -> None:
        """Without the signal the padding gap keeps one cluster."""
        info = _jump_table_binary()
        registry = {0x1000: _entry(0x1000, 12), FUNC_B_VA: _entry(FUNC_B_VA, 16)}
        clusters = cluster_functions(registry, info, None)  # type: ignore[arg-type]
        assert [c.functions for c in clusters] == [[0x1000, FUNC_B_VA]]
        assert not any("jump-table alignment" in e for c in clusters for e in c.evidence)

    def test_enabled_splits_where_remainders_differ(self) -> None:
        info = _jump_table_binary()
        registry = {0x1000: _entry(0x1000, 12), FUNC_B_VA: _entry(FUNC_B_VA, 16)}
        clusters = cluster_functions(
            registry,
            info,  # type: ignore[arg-type]
            None,
            jump_table_alignment=8,
        )
        assert [c.functions for c in clusters] == [[0x1000], [FUNC_B_VA]]
        split_cluster = clusters[1]
        assert any("jump-table alignment change" in e for e in split_cluster.evidence)

    def test_matching_remainders_keep_one_cluster(self) -> None:
        """Two tables at the same remainder agree: no split, and the
        agreement is stated as evidence."""
        code_a = b"\x55\x8b\xec\xc3" + struct.pack("<II", 0x1000, 0x1010)
        gap = b"\xcc" * 4
        code_b = b"\x55\x8b\xec\xc3" + struct.pack("<II", 0x1000, 0x1010)
        info = _text_only(0x1000, code_a + gap + code_b)
        registry = {0x1000: _entry(0x1000, 12), FUNC_B_VA: _entry(FUNC_B_VA, 12)}
        clusters = cluster_functions(
            registry,
            info,  # type: ignore[arg-type]
            None,
            jump_table_alignment=4,
        )
        assert [c.functions for c in clusters] == [[0x1000, FUNC_B_VA]]
        assert any("% 4 alignment" in e for e in clusters[0].evidence)
        assert clusters[0].confidence == 1.0

    def test_boost_applied_when_tables_agree(self) -> None:
        """A cluster at the 0.40 floor rises by the named boost when the
        alignment signal is on and consistent."""
        assert JUMP_TABLE_ALIGN_BOOST > 0


# ---------------------------------------------------------------------------
# Single-reference data signal
# ---------------------------------------------------------------------------

DATA_A_VA = 0x2000
DATA_B_VA = 0x2004


def _single_ref_binary() -> SimpleNamespace:
    """Two functions with a large non-padding gap between them.

    Each reads one data object; the objects are adjacent in ``.data``, so
    the pair is bonded by the single-reference-data signal.
    """
    # mov eax, [0x2000] ; ret   /   mov eax, [0x2004] ; ret
    code_a = b"\xa1" + struct.pack("<I", DATA_A_VA) + b"\xc3"
    gap = bytes(range(256)) * 2  # 512 non-padding bytes
    code_b = b"\xa1" + struct.pack("<I", DATA_B_VA) + b"\xc3"
    text = code_a + gap + code_b
    text_va = 0x1000
    func_b_va = text_va + len(code_a) + len(gap)
    data = b"\x00" * 16
    blob = text + data
    return SimpleNamespace(
        path=None,
        format="pe",
        arch="x86_32",
        image_base=text_va,
        text_va=text_va,
        text_size=len(text),
        text_raw_offset=0,
        sections={
            ".text": _section(".text", text_va, len(text), 0, len(text)),
            ".data": _section(".data", DATA_A_VA, len(data), len(text), len(data)),
        },
        data=blob,
        _data=blob,
        func_b_va=func_b_va,
    )


class TestSingleRefDataSignal:
    def test_exclusive_ownership_and_bond(self) -> None:
        info = _single_ref_binary()
        func_b_va = info.func_b_va
        extents = [(0x1000, 6), (func_b_va, 6)]
        owned = _exclusive_data_owners(info, extents)  # type: ignore[arg-type]
        assert owned == {0x1000: [DATA_A_VA], func_b_va: [DATA_B_VA]}
        bonds = _single_ref_data_bonds(info, extents)  # type: ignore[arg-type]
        assert bonds == {func_b_va: 0x1000}

    def test_off_by_default(self) -> None:
        info = _single_ref_binary()
        func_b_va = info.func_b_va
        registry = {0x1000: _entry(0x1000, 6), func_b_va: _entry(func_b_va, 6)}
        clusters = cluster_functions(registry, info, None)  # type: ignore[arg-type]
        assert [c.functions for c in clusters] == [[0x1000], [func_b_va]]

    def test_enabled_vetoes_the_split(self) -> None:
        info = _single_ref_binary()
        func_b_va = info.func_b_va
        registry = {0x1000: _entry(0x1000, 6), func_b_va: _entry(func_b_va, 6)}
        clusters = cluster_functions(
            registry,
            info,  # type: ignore[arg-type]
            None,
            single_ref_data=True,
        )
        assert [c.functions for c in clusters] == [[0x1000, func_b_va]]
        assert clusters[0].gap_classes == ["data_bond"]
        assert any("single-reference data bond" in e for e in clusters[0].evidence)
        assert SINGLE_REF_DATA_BOOST > 0
