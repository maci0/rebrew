import os
import random
import struct
import tempfile
from pathlib import Path

import pytest

from rebrew.matcher import (
    GACheckpoint,
    compute_args_hash,
    diff_functions,
    generate_flag_combinations,
    list_obj_symbols,
    load_checkpoint,
    parse_obj_symbol_bytes,
    save_checkpoint,
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


def test_parse_coff_obj_basic() -> None:
    """Test COFF parser with a minimal synthetic .obj."""
    code = b"\x55\x8b\xec\x33\xc0\x5d\xc3"  # push ebp; mov ebp,esp; xor eax,eax; pop ebp; ret
    obj_data = _make_minimal_coff_obj("_myfunc", code)

    with tempfile.NamedTemporaryFile(suffix=".obj", delete=False) as f:
        f.write(obj_data)
        f.flush()
        obj_path = Path(f.name)

    try:
        code_result, relocs = parse_obj_symbol_bytes(obj_path, "_myfunc")
        assert code_result is not None
        assert code_result == code
        assert relocs is not None
    finally:
        obj_path.unlink()


def test_parse_coff_obj_long_name() -> None:
    """Test COFF parser with symbol name longer than 8 chars (string table)."""
    code = b"\xc2\x0c\x00"  # ret 0xC
    obj_data = _make_minimal_coff_obj("_DllMainCRTStartup@12", code)

    with tempfile.NamedTemporaryFile(suffix=".obj", delete=False) as f:
        f.write(obj_data)
        f.flush()
        obj_path = Path(f.name)

    try:
        code_result, relocs = parse_obj_symbol_bytes(obj_path, "_DllMainCRTStartup@12")
        assert code_result is not None
        assert code_result == code
    finally:
        obj_path.unlink()


def test_parse_coff_obj_symbol_not_found() -> None:
    """Test COFF parser returns None for missing symbol."""
    code = b"\xc3"
    obj_data = _make_minimal_coff_obj("_other", code)

    with tempfile.NamedTemporaryFile(suffix=".obj", delete=False) as f:
        f.write(obj_data)
        f.flush()
        obj_path = Path(f.name)

    try:
        code_result, relocs = parse_obj_symbol_bytes(obj_path, "_nothere")
        assert code_result is None
    finally:
        obj_path.unlink()


def test_list_obj_symbols() -> None:
    """Test listing symbols from a synthetic .obj."""
    code = b"\xc3"
    obj_data = _make_minimal_coff_obj("_myfunc", code)

    with tempfile.NamedTemporaryFile(suffix=".obj", delete=False) as f:
        f.write(obj_data)
        f.flush()
        obj_path = Path(f.name)

    try:
        names = list_obj_symbols(obj_path)
        assert "_myfunc" in names
    finally:
        obj_path.unlink()


def test_parse_coff_obj_trims_padding() -> None:
    """Test that trailing 0xCC/0x90 is trimmed but not 0x00."""
    code = b"\x55\x8b\xec\xc2\x0c\x00\xcc\xcc\x90"
    obj_data = _make_minimal_coff_obj("_func", code)

    with tempfile.NamedTemporaryFile(suffix=".obj", delete=False) as f:
        f.write(obj_data)
        f.flush()
        obj_path = Path(f.name)

    try:
        code_result, relocs = parse_obj_symbol_bytes(obj_path, "_func")
        assert code_result is not None
        # Should keep 0x00 (part of ret 0xC) but trim 0xCC and 0x90
        assert code_result == b"\x55\x8b\xec\xc2\x0c\x00"
    finally:
        obj_path.unlink()


def test_parse_coff_obj_too_small() -> None:
    """Test that files smaller than COFF header return None gracefully."""
    with tempfile.NamedTemporaryFile(suffix=".obj", delete=False) as f:
        f.write(b"\x00" * 10)
        f.flush()
        obj_path = Path(f.name)

    try:
        code, relocs = parse_obj_symbol_bytes(obj_path, "_func")
        assert code is None
        assert relocs is None
    finally:
        obj_path.unlink()


# -------------------------
# Flag sweep tests
# -------------------------


def test_generate_flag_combinations_basic() -> None:
    """Test flag combination generation returns non-empty list of strings."""
    combos = generate_flag_combinations()
    assert isinstance(combos, list)
    assert len(combos) > 0
    for c in combos:
        assert isinstance(c, str)


def test_generate_flag_combinations_dedup() -> None:
    """Test that generated combinations have no duplicates."""
    combos = generate_flag_combinations()
    assert len(combos) == len(set(combos))


def test_generate_flag_combinations_max_limit() -> None:
    """Test that quick tier produces a bounded number of combinations."""
    combos = generate_flag_combinations()  # defaults to "quick"
    # Quick tier should be small — well under 1000 combos
    assert len(combos) < 1000


def test_generate_flag_combinations_full_axes() -> None:
    """Test that generated combos contain expected MSVC flag substrings."""
    combos = generate_flag_combinations()
    has_opt = any("/O" in c for c in combos)
    assert has_opt


# -------------------------
# Checkpoint tests
# -------------------------


def test_checkpoint_round_trip() -> None:
    """Test save/load checkpoint preserves all fields."""
    with tempfile.TemporaryDirectory() as td:
        ckpt_path = os.path.join(td, "ckpt.json")
        rng = random.Random(42)
        pop = ["int main(){return 0;}", "int main(){return 1;}"]
        args_hash = "abc123"

        ckpt = GACheckpoint(
            generation=10,
            best_score=42.5,
            best_source="int main(){return 0;}",
            population=pop,
            rng_state=rng.getstate(),
            stagnant_gens=3,
            elapsed_sec=123.4,
            args_hash=args_hash,
        )
        save_checkpoint(ckpt_path, ckpt)

        assert os.path.exists(ckpt_path)

        loaded = load_checkpoint(ckpt_path, args_hash)
        assert loaded is not None
        assert loaded.generation == 10
        assert loaded.best_score == 42.5
        assert loaded.best_source == "int main(){return 0;}"
        assert loaded.population == pop
        assert loaded.stagnant_gens == 3
        assert loaded.elapsed_sec == 123.4
        assert loaded.args_hash == args_hash


def test_checkpoint_wrong_hash() -> None:
    """Test that mismatched args_hash returns None."""
    with tempfile.TemporaryDirectory() as td:
        ckpt_path = os.path.join(td, "ckpt.json")
        rng = random.Random(1)
        ckpt = GACheckpoint(
            generation=5,
            best_score=10.0,
            best_source="x",
            population=["x"],
            rng_state=rng.getstate(),
            stagnant_gens=0,
            elapsed_sec=1.0,
            args_hash="hash_a",
        )
        save_checkpoint(ckpt_path, ckpt)
        with pytest.warns(UserWarning, match="args hash mismatch"):
            loaded = load_checkpoint(ckpt_path, "hash_b")
        assert loaded is None


def test_checkpoint_missing_file() -> None:
    """Test that missing checkpoint file returns None."""
    loaded = load_checkpoint("/nonexistent/ckpt.json", "hash")
    assert loaded is None


def test_checkpoint_corrupt_json() -> None:
    """Test that corrupt JSON returns None."""
    with tempfile.TemporaryDirectory() as td:
        ckpt_path = os.path.join(td, "ckpt.json")
        with open(ckpt_path, "w", encoding="utf-8") as f:
            f.write("not valid json{{{")
        with pytest.warns(UserWarning, match="Failed to load checkpoint"):
            loaded = load_checkpoint(ckpt_path, "hash")
        assert loaded is None


def test_compute_args_hash() -> None:
    """Test that args hash is deterministic."""
    d1 = {
        "target_exe": "server.dll",
        "target_va": "0x10001000",
        "target_size": 100,
        "symbol": "_func",
        "cflags": "/c /O1",
        "pop_size": 48,
        "generations": 100,
    }
    h1 = compute_args_hash(d1)
    h2 = compute_args_hash(d1)
    assert h1 == h2
    assert len(h1) == 16

    # Different args -> different hash
    d2 = dict(d1)
    d2["cflags"] = "/c /O2"
    assert compute_args_hash(d2) != h1


# -------------------------
# Diff function tests
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
