"""Tests for parse_obj_relocs_full: type-aware COFF relocation extraction."""

import struct
from pathlib import Path

import pytest

from rebrew.matcher.parsers import CoffRelocRecord, parse_obj_relocs_full


def _make_coff_blob(code: bytes, reloc_offset: int, reloc_type: int, sym: str) -> bytes:
    """Build a minimal valid COFF .obj blob in memory.

    Layout (little-endian, IMAGE_FILE_MACHINE_I386 = 0x014C):

      [0x00]  File header        (20 bytes)
      [0x14]  Section header     (40 bytes)  — one .text section
      [0x3C]  Section data       (len(code) bytes, padded to 4-byte boundary)
      [0x3C + pad_code]  Reloc records  (10 bytes each)
      [0x3C + pad_code + reloc_bytes]  Symbol table (18 bytes × num_syms)
      [...]  String table        (4-byte length prefix + strings)

    Symbols:
      0: _myfunc  — EXTERNAL, section 1, value 0 (function defined in .text)
      1: _extern_var — EXTERNAL, section 0 (undefined), value 0 (external ref)

    Reloc record (10 bytes):
      VirtualAddress  4
      SymbolTableIndex 4
      Type            2
    """
    # Sizes and counts
    num_sections = 1
    num_syms = 2

    # Pad code to 4-byte alignment
    pad_len = (4 - len(code) % 4) % 4
    padded_code = code + b"\x00" * pad_len

    # String table: holds long symbol names (> 8 chars)
    # Both "_myfunc" (7) and "_extern_var" (11) — _myfunc fits in 8 bytes, but
    # "_extern_var" is 11 chars so it must go in the string table.
    # COFF inline name: if len <= 8, pad with NUL; else first 4 bytes = 0, next 4 = offset into strtab.
    # String table layout: 4-byte total-size, then null-terminated strings.
    strtab_strings = b"_extern_var\x00"
    strtab_size = 4 + len(strtab_strings)
    strtab = struct.pack("<I", strtab_size) + strtab_strings
    extern_var_strtab_offset = 4  # offset of "_extern_var" within the string table

    # Offsets
    off_file_hdr = 0
    off_sec_hdr = off_file_hdr + 20
    off_sec_data = off_sec_hdr + 40
    off_relocs = off_sec_data + len(padded_code)
    num_relocs = 1
    reloc_bytes = num_relocs * 10
    off_symtab = off_relocs + reloc_bytes

    # --- File Header (IMAGE_FILE_HEADER, 20 bytes) ---
    # Machine           2   0x014C = I386
    # NumberOfSections  2
    # TimeDateStamp     4
    # PointerToSymbolTable 4
    # NumberOfSymbols   4
    # SizeOfOptionalHeader 2   (0 for .obj)
    # Characteristics   2
    file_hdr = struct.pack(
        "<HHIIIHH",
        0x014C,  # Machine: IMAGE_FILE_MACHINE_I386
        num_sections,
        0,  # TimeDateStamp
        off_symtab,  # PointerToSymbolTable
        num_syms,  # NumberOfSymbols
        0,  # SizeOfOptionalHeader
        0,  # Characteristics
    )
    assert len(file_hdr) == 20

    # --- Section Header (.text, 40 bytes) ---
    # Name              8   (null-padded)
    # VirtualSize       4   (0 for COFF obj)
    # VirtualAddress    4   (0 for COFF obj)
    # SizeOfRawData     4
    # PointerToRawData  4
    # PointerToRelocations 4
    # PointerToLinenumbers 4
    # NumberOfRelocations 2
    # NumberOfLinenumbers 2
    # Characteristics   4
    TEXT_CHARS = 0x60000020  # CODE | EXECUTE | READ | CNT_CODE
    sec_hdr = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",  # Name (8 bytes, null-padded)
        0,  # VirtualSize
        0,  # VirtualAddress
        len(padded_code),  # SizeOfRawData
        off_sec_data,  # PointerToRawData
        off_relocs,  # PointerToRelocations
        0,  # PointerToLinenumbers
        num_relocs,  # NumberOfRelocations
        0,  # NumberOfLinenumbers
        TEXT_CHARS,  # Characteristics
    )
    assert len(sec_hdr) == 40

    # --- Relocation Record (10 bytes) ---
    # VirtualAddress    4   (offset within section)
    # SymbolTableIndex  4   (index of target symbol; symbol 1 = _extern_var)
    # Type              2   (IMAGE_REL_I386_DIR32 = 0x0006)
    reloc_rec = struct.pack(
        "<IIH",
        reloc_offset,  # VirtualAddress = byte offset inside section
        1,  # SymbolTableIndex = 1 (_extern_var)
        reloc_type,  # Type
    )
    assert len(reloc_rec) == 10

    # --- Symbol Table Records (18 bytes each, COFF symbol record) ---
    # Name              8   (inline if <= 8 chars, else 0x00000000 + strtab offset)
    # Value             4
    # SectionNumber     2   (1-based; 0 = undefined external)
    # Type              2   (0x20 = function)
    # StorageClass      1   (2 = IMAGE_SYM_CLASS_EXTERNAL)
    # NumberOfAuxSymbols 1

    # Symbol 0: _myfunc (7 chars, fits inline)
    sym0_name = b"_myfunc\x00"  # exactly 8 bytes
    sym0 = struct.pack(
        "<8sIhHBB",
        sym0_name,
        0,  # Value (offset 0 in section)
        1,  # SectionNumber (1-based, section 1 = .text)
        0x20,  # Type: function
        2,  # StorageClass: EXTERNAL
        0,  # NumberOfAuxSymbols
    )
    assert len(sym0) == 18

    # Symbol 1: _extern_var (11 chars, must use string table)
    sym1 = struct.pack(
        "<IIIhHBB",
        0,  # Name[0:4] = 0 means use string table
        extern_var_strtab_offset,  # Name[4:8] = offset in string table
        0,  # Value
        0,  # SectionNumber = 0 (undefined external)
        0,  # Type
        2,  # StorageClass: EXTERNAL
        0,  # NumberOfAuxSymbols
    )
    assert len(sym1) == 18

    return file_hdr + sec_hdr + padded_code + reloc_rec + sym0 + sym1 + strtab


def _build_coff_with_one_dir32_reloc(tmp_path: Path) -> Path:
    """Drop a real MSVC-style COFF .obj on disk containing one DIR32 reloc.

    We bake the bytes directly because lief.COFF doesn't have a builder; the
    layout below is the minimum a LIEF parse will accept:
        - File header (machine=I386, 1 section, 2 symbols, no opt header)
        - One .text section, 8 bytes of code, 1 relocation entry
        - String table with the external symbol name "_extern_var"
    """
    obj = tmp_path / "fixture.obj"
    code = b"\x90\x90\xa1\x00\x00\x00\x00\xc3"  # nop;nop; mov eax,[0]; ret
    obj.write_bytes(_make_coff_blob(code, reloc_offset=2, reloc_type=0x0006, sym="_extern_var"))
    return obj


def test_parse_obj_relocs_full_returns_typed_records(tmp_path: Path) -> None:
    obj = _build_coff_with_one_dir32_reloc(tmp_path)
    records = parse_obj_relocs_full(obj, "_myfunc")
    assert len(records) == 1
    r = records[0]
    assert isinstance(r, CoffRelocRecord)
    assert r.offset == 2
    assert r.type == 0x0006  # IMAGE_REL_I386_DIR32
    assert r.symbol == "_extern_var"


def test_parse_obj_relocs_full_unknown_symbol_returns_empty(tmp_path: Path) -> None:
    obj = _build_coff_with_one_dir32_reloc(tmp_path)
    assert parse_obj_relocs_full(obj, "_does_not_exist") == []


# ---------------------------------------------------------------------------
# OMF objects (Open Watcom wcc386) — converted to COFF via vendored objconv
# ---------------------------------------------------------------------------

_FIXTURES = Path(__file__).parent / "fixtures"


def test_omf_format_detected() -> None:
    from rebrew.matcher.parsers import _detect_obj_format

    omf = _FIXTURES / "tg_watcom.o"
    assert omf.exists()
    assert _detect_obj_format(str(omf)) == "omf"


def test_omf_converted_and_parsed() -> None:
    """A raw Watcom OMF object is converted to COFF via objconv and yields
    the same reloc offsets as the direct COFF parse — the e8/a1 slots of
    `callg_` (push 4; call __CHK; call f_; add eax,[_g]; ret).  Skips when
    the objconv binary is not present (tools/objconv is gitignored)."""
    import shutil

    from rebrew.matcher.parsers import parse_obj_symbol_and_relocs

    if (
        shutil.which("objconv") is None
        and not (Path(__file__).resolve().parents[2] / "tools" / "objconv" / "objconv").exists()
    ):
        pytest.skip("objconv not present (tools/objconv is gitignored)")

    omf = _FIXTURES / "tg_watcom.o"
    code, relocs, records = parse_obj_symbol_and_relocs(omf, "callg_")
    assert code is not None
    assert code[:2] == bytes.fromhex("68 04")  # push 4
    assert code[-1] == 0xC3  # ret
    assert relocs == {6: "__CHK", 11: "f_", 17: "_g"}
    assert sorted(r.offset for r in records) == [6, 11, 17]


def test_watcom_trailing_underscore_symbol_matches() -> None:
    """The annotation layer derives MSVC-style `_name` symbols, but wcc386
    emits trailing underscores (`callg_`) — the lookup must try the
    compiler conventions."""
    from rebrew.matcher.parsers import parse_obj_symbol_and_relocs

    omf = _FIXTURES / "tg_watcom.o"
    code, relocs, records = parse_obj_symbol_and_relocs(omf, "_callg")
    assert code is not None
    assert relocs == {6: "__CHK", 11: "f_", 17: "_g"}


def test_msvc16_omf_code_extraction() -> None:
    """MSVC 1.52's 16-bit OMF (objconv crashes on it) decodes via the
    built-in parser — _add/_main extract with correct function bytes."""
    from rebrew.matcher.parsers import parse_obj_symbol_and_relocs

    obj = _FIXTURES / "tg_msvc16.obj"
    assert obj.exists()
    code, relocs, recs = parse_obj_symbol_and_relocs(obj, "_add")
    assert code is not None
    assert code[:2] == bytes.fromhex("55 8b")  # push bp; mov bp,sp
    assert code[-1] == 0xC3  # ret
    # reloc slots: the __aNchkstk prolog call (e8 at 6) and the tail jmp (e9)
    assert relocs == {7: "rel16", 18: "rel16"}
    code_main, relocs_main, _ = parse_obj_symbol_and_relocs(obj, "_main")
    assert code_main is not None
    assert code_main != code  # distinct function bodies
    assert 7 in relocs_main  # the prolog chkstk call slot


def test_msvc16_omf_optimized_dialect_code_extraction() -> None:
    """MSVC 1.52 compiled with /O1 switches to a different OMF dialect
    (0xC2 code records + 0x96/0xCA name lists) that also crashes objconv —
    the parser must decode it too (this is what the GA flag sweep emits)."""
    from rebrew.matcher.parsers import parse_obj_symbol_and_relocs

    obj = _FIXTURES / "tg_msvc16_o1.obj"
    assert obj.exists()

    # int f(void) { return g; } -> mov ax,[g]; ret
    code_f, relocs_f, _ = parse_obj_symbol_and_relocs(obj, "_f")
    assert code_f is not None
    assert code_f.hex() == "a10000c3"
    assert relocs_f == {1: "disp16"}  # the mov ax,[g] absolute operand

    # int callg(void) { return f() + g; } -> call f; add ax,[g]; ret
    code_c, relocs_c, _ = parse_obj_symbol_and_relocs(obj, "_callg")
    assert code_c is not None
    assert code_c.hex() == "e8000003060000c3"
    assert relocs_c == {1: "rel16", 5: "disp16"}  # call f slot + add ax,[g] disp


def test_msvc16_omf_optimized_dialect_static_and_publics() -> None:
    """The optimized dialect's 0xCA (static) + 0x96 (public) name records
    map to 0xC2 code records in stream order."""
    from rebrew.matcher.omf16 import Omf16Module, parse_omf16

    data = (_FIXTURES / "tg_msvc16_o1.obj").read_bytes()
    mod = parse_omf16(data)
    assert isinstance(mod, Omf16Module)
    assert mod.names == ["_f", "_callg"]
    assert [r.hex() for r in mod.code_records] == ["a10000c3", "e8000003060000c3"]
    assert mod.code == b"".join(mod.code_records)


def test_msvc16_omf_far_code_model() -> None:
    """MSVC 1.52 far-code models (/AM medium, /AL large) name the code
    segment SRC_TEXT and use a 7-byte 0xC2 header — retf endings and
    lcall/ljmp patch slots.  This is the dialect 16-bit Windows games
    (e.g. skifree16's NE target) are built with."""
    from rebrew.matcher.parsers import parse_obj_symbol_and_relocs

    obj = _FIXTURES / "tg_msvc16_far.obj"
    assert obj.exists()

    # int f(void) { return g; } -> mov ax,[g]; retf
    code_f, relocs_f, _ = parse_obj_symbol_and_relocs(obj, "_f")
    assert code_f is not None
    assert code_f.hex() == "a10000cb"  # retf, not ret
    assert relocs_f == {1: "disp16"}

    # int callg(void) { return f() + g; } -> lcall f; add ax,[g]; retf
    code_c, relocs_c, _ = parse_obj_symbol_and_relocs(obj, "_callg")
    assert code_c is not None
    assert code_c.hex() == "9a0000000003060000cb"  # lcall + patch slot
    assert relocs_c == {1: "far16", 7: "disp16"}
