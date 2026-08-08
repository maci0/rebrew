"""Tests for rebrew.matcher core, compiler, scoring, and parsers."""

import struct
from pathlib import Path

from rebrew.matcher import (
    diff_functions,
    generate_flag_combinations,
    list_obj_symbols,
    parse_obj_symbol_bytes,
    score_candidate,
)

# -------------------------
# COFF parser tests
# -------------------------


def _make_minimal_coff_obj(symbol_name: str, code: bytes) -> bytes:
    """Build a minimal valid COFF .obj with one .text section and one symbol."""
    # Section: .text
    sec_name = b".text\x00\x00\x00"
    raw_size = len(code)
    # Section header starts at offset 20 (after FILE_HEADER)
    raw_ptr = 20 + 40  # FILE_HEADER + 1 section header

    # Symbol table starts after raw data
    ptr_symtab = raw_ptr + raw_size

    # Build symbol name (8 bytes). If <= 8 chars, inline; else use string table.
    sym_name_bytes = symbol_name.encode("ascii")
    if len(sym_name_bytes) <= 8:
        sym_name_field = sym_name_bytes.ljust(8, b"\x00")
        string_table = struct.pack("<I", 4)  # empty string table (just size)
    else:
        # Long name: zeros(4) + offset into string table
        str_offset = 4  # right after the size field
        sym_name_field = b"\x00\x00\x00\x00" + struct.pack("<I", str_offset)
        str_data = sym_name_bytes + b"\x00"
        string_table = struct.pack("<I", 4 + len(str_data)) + str_data

    num_symbols = 1

    # IMAGE_FILE_HEADER
    file_header = struct.pack(
        "<HHIIIHH",
        0x14C,  # Machine: i386
        1,  # NumberOfSections
        0,  # TimeDateStamp
        ptr_symtab,  # PointerToSymbolTable
        num_symbols,  # NumberOfSymbols
        0,  # SizeOfOptionalHeader
        0,  # Characteristics
    )

    # Section header
    section_header = sec_name + struct.pack(
        "<IIIIIIHHI",
        0,  # VirtualSize
        0,  # VirtualAddress
        raw_size,  # SizeOfRawData
        raw_ptr,  # PointerToRawData
        0,  # PointerToRelocations
        0,  # PointerToLinenumbers
        0,  # NumberOfRelocations
        0,  # NumberOfLinenumbers
        0x60000020,  # Characteristics (CODE|EXECUTE|READ)
    )

    # Symbol table entry (18 bytes)
    symbol_entry = sym_name_field + struct.pack(
        "<IhHBB",
        0,  # Value (offset in section)
        1,  # SectionNumber (1-based)
        0x20,  # Type (function)
        2,  # StorageClass (EXTERNAL)
        0,  # NumberOfAuxSymbols
    )

    return file_header + section_header + code + symbol_entry + string_table


def test_parse_coff_obj_basic(tmp_path: Path) -> None:
    """Test COFF parser with a minimal synthetic .obj."""
    code = b"\x55\x8b\xec\x33\xc0\x5d\xc3"  # push ebp; mov ebp,esp; xor eax,eax; pop ebp; ret
    obj_data = _make_minimal_coff_obj("_myfunc", code)
    obj_path = tmp_path / "test.obj"
    obj_path.write_bytes(obj_data)

    code_result, relocs = parse_obj_symbol_bytes(obj_path, "_myfunc")
    assert code_result is not None
    assert code_result == code
    assert relocs is not None


def test_parse_coff_obj_long_name(tmp_path: Path) -> None:
    """Test COFF parser with symbol name longer than 8 chars (string table)."""
    code = b"\xc2\x0c\x00"  # ret 0xC
    obj_data = _make_minimal_coff_obj("_DllMainCRTStartup@12", code)
    obj_path = tmp_path / "test.obj"
    obj_path.write_bytes(obj_data)

    code_result, relocs = parse_obj_symbol_bytes(obj_path, "_DllMainCRTStartup@12")
    assert code_result is not None
    assert code_result == code


def test_parse_coff_obj_symbol_not_found(tmp_path: Path) -> None:
    """Test COFF parser returns None for missing symbol."""
    code = b"\xc3"
    obj_data = _make_minimal_coff_obj("_other", code)
    obj_path = tmp_path / "test.obj"
    obj_path.write_bytes(obj_data)

    code_result, relocs = parse_obj_symbol_bytes(obj_path, "_nothere")
    assert code_result is None


def test_list_obj_symbols(tmp_path: Path) -> None:
    """Test listing symbols from a synthetic .obj."""
    code = b"\xc3"
    obj_data = _make_minimal_coff_obj("_myfunc", code)
    obj_path = tmp_path / "test.obj"
    obj_path.write_bytes(obj_data)

    names = list_obj_symbols(obj_path)
    assert "_myfunc" in names


def test_parse_coff_obj_trims_padding(tmp_path: Path) -> None:
    """Test that trailing 0xCC/0x90 is trimmed but not 0x00."""
    code = b"\x55\x8b\xec\xc2\x0c\x00\xcc\xcc\x90"
    obj_data = _make_minimal_coff_obj("_func", code)
    obj_path = tmp_path / "test.obj"
    obj_path.write_bytes(obj_data)

    code_result, relocs = parse_obj_symbol_bytes(obj_path, "_func")
    assert code_result is not None
    # Should keep 0x00 (part of ret 0xC) but trim 0xCC and 0x90
    assert code_result == b"\x55\x8b\xec\xc2\x0c\x00"


def test_parse_coff_obj_too_small(tmp_path: Path) -> None:
    """Test that files smaller than COFF header return None gracefully."""
    obj_path = tmp_path / "tiny.obj"
    obj_path.write_bytes(b"\x00" * 10)

    code, relocs = parse_obj_symbol_bytes(obj_path, "_func")
    assert code is None
    assert relocs is None


# -------------------------
# Flag sweep tests
# -------------------------


def test_generate_flag_combinations_basic() -> None:
    """Test flag combination generation returns non-empty list of strings."""
    combos = generate_flag_combinations()
    assert isinstance(combos, list)
    assert len(combos) >= 2
    for c in combos:
        assert isinstance(c, str)


def test_generate_flag_combinations_dedup() -> None:
    """Test that generated combinations have no duplicates."""
    combos = generate_flag_combinations()
    assert len(combos) == len(set(combos))


def test_generate_flag_combinations_max_limit() -> None:
    """Test that quick tier produces a bounded number of combinations.

    The 2000 upper bound prevents combinatorial explosion from silently
    degrading GA sweep performance.
    """
    combos = generate_flag_combinations()  # defaults to "quick"
    assert len(combos) < 2000, f"Quick tier produced {len(combos)} combos (limit: 2000)"


def test_generate_flag_combinations_full_axes() -> None:
    """Test that generated combos contain expected MSVC flag substrings."""
    combos = generate_flag_combinations()
    has_opt = any("/O" in c for c in combos)
    assert has_opt


# -------------------------
# Checkpoint tests
# -------------------------


def test_diff_functions_identical() -> None:
    """Test diff with identical bytes produces all-match results."""
    code = b"\x55\x8b\xec\x33\xc0\x5d\xc3"
    result = diff_functions(code, code, as_dict=True)
    assert isinstance(result, dict)
    assert result["target_size"] == len(code)
    # All instructions should match exactly
    assert result["summary"]["structural"] == 0


def test_diff_functions_different() -> None:
    """Test diff detects structural differences."""
    target = b"\x55\x8b\xec\x33\xc0\x5d\xc3"
    cand = b"\x55\x8b\xec\x8b\xc1\x5d\xc3"
    result = diff_functions(target, cand, as_dict=True)
    assert isinstance(result, dict)
    assert result["summary"]["structural"] > 0


def test_diff_functions_length_mismatch() -> None:
    """Test diff handles different lengths."""
    target = b"\x55\x8b\xec\xc3"
    cand = b"\x55\x8b\xec\x33\xc0\xc3"
    result = diff_functions(target, cand, as_dict=True)
    assert isinstance(result, dict)
    assert result["target_size"] != result["candidate_size"]


# -------------------------
# Score function tests
# -------------------------


def test_score_exact_match() -> None:
    """Test that identical bytes produce a low/perfect score."""
    code = b"\x55\x8b\xec\x33\xc0\x5d\xc3"
    sc = score_candidate(code, code)
    assert sc.length_diff == 0
    assert sc.byte_score == 0.0
    assert sc.total <= 0.0  # prologue_bonus can make it negative


def test_score_empty_candidate() -> None:
    """Test scoring with empty candidate gives high total."""
    sc = score_candidate(b"\xc3", b"")
    assert sc.length_diff == 1
    assert sc.total > 0


class TestDiffFunctionsEdges:
    def test_invalid_reloc_xx(self, capsys) -> None:
        from rebrew.matcher.scoring import diff_functions

        # Differing bytes inside a reloc window with an invalid reloc at offset 0
        # → "XX" classification in print mode; folded into structural in as_dict.
        target = b"\x55\x89\xe5\xc3"
        cand = b"\x57\x89\xe5\xc3"
        diff_functions(target, cand, reloc_offsets=[0], invalid_relocs=[0])
        out = capsys.readouterr().out
        assert "| XX |" in out
        result = diff_functions(target, cand, reloc_offsets=[0], invalid_relocs=[0], as_dict=True)
        assert result is not None
        assert result["summary"]["structural"] == 1

    def test_reloc_normalized_not_invalid(self, capsys) -> None:
        """A differing reloc slot WITHOUT an invalid reloc marker shows the
        reloc-normalized marker (~~), not XX."""
        from rebrew.matcher.scoring import diff_functions

        target = b"\x55\x89\xe5\xc3"
        cand = b"\x57\x89\xe5\xc3"
        diff_functions(target, cand, reloc_offsets=[0], invalid_relocs=None)
        out = capsys.readouterr().out
        assert "| XX |" not in out
        assert "| ~~ |" in out

    def test_invalid_reloc_outside_code_still_normalized(self, capsys) -> None:
        """An invalid reloc entirely beyond the code does not mark any byte XX;
        the reloc-normalized comparison still shows ~~."""
        from rebrew.matcher.scoring import diff_functions

        target = b"\x55\x89\xe5\xc3"
        cand = b"\x57\x89\xe5\xc3"
        diff_functions(target, cand, reloc_offsets=[0], invalid_relocs=[100])
        out = capsys.readouterr().out
        assert "| XX |" not in out
        assert "| ~~ |" in out

    def test_build_invalid_reloc_mask_boundaries(self) -> None:
        from rebrew.matcher.scoring import _build_invalid_reloc_mask

        # Empty / None input → empty mask.
        assert _build_invalid_reloc_mask(b"\x00\x01\x02", None) == []
        assert _build_invalid_reloc_mask(b"\x00\x01\x02", []) == []

        # Pointer-size span at offset 0.
        assert _build_invalid_reloc_mask(b"abcd", [0]) == [True, True, True, True]

        # Negative offset cannot overlap the buffer (end clamps negative) →
        # all-False, no bytes wrongly marked.
        mask = _build_invalid_reloc_mask(b"abcd", [-5])
        assert mask == [False, False, False, False]

        # Offset entirely beyond the buffer → all-False mask (never True).
        mask = _build_invalid_reloc_mask(b"abcd", [100])
        assert mask == [False, False, False, False]

        # Partial overlap at the tail: offset 2 in a 5-byte buffer marks 2-5.
        mask = _build_invalid_reloc_mask(b"abcde", [2])
        assert mask == [False, False, True, True, True]

    def test_print_mode_output(self, capsys) -> None:
        from rebrew.matcher.scoring import diff_functions

        diff_functions(b"\x55\xc3", b"\x55\xc3")
        out = capsys.readouterr().out
        assert "Target" in out
        assert "exact match" in out or "==" in out

    def test_mismatches_only_filters(self, capsys) -> None:
        from rebrew.matcher.scoring import diff_functions

        diff_functions(b"\x55\xc3", b"\x90\xc3", mismatches_only=True)
        out = capsys.readouterr().out
        assert "structural differences only" in out
