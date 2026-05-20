"""Tests for apply_coff_relocations."""

import struct

import pytest

from rebrew.core.matching import UnresolvedSymbolError, apply_coff_relocations
from rebrew.matcher.parsers import CoffRelocRecord


def _resolve(sym: str) -> int | None:
    return {"_g_var": 0x10025000, "_other_func": 0x10001500}.get(sym)


def test_dir32_writes_absolute_va() -> None:
    text = bytearray(b"\xa1\x00\x00\x00\x00\xc3")  # mov eax,[0]; ret
    relocs = [CoffRelocRecord(offset=1, type=0x0006, symbol="_g_var")]
    patched = apply_coff_relocations(
        bytes(text), relocs, _resolve, image_base=0x10000000, section_va=0x10001000
    )
    assert struct.unpack("<I", patched[1:5])[0] == 0x10025000


def test_rel32_writes_pc_relative_displacement() -> None:
    text = bytearray(b"\xe8\x00\x00\x00\x00")  # call <offset>
    # Function at section_va=0x10001000, reloc at offset 1, call target at
    # _other_func=0x10001500. Displacement = target - (section_va + offset + 4).
    relocs = [CoffRelocRecord(offset=1, type=0x0014, symbol="_other_func")]
    patched = apply_coff_relocations(
        bytes(text), relocs, _resolve, image_base=0x10000000, section_va=0x10001000
    )
    disp = struct.unpack("<i", patched[1:5])[0]
    assert disp == 0x10001500 - (0x10001000 + 1 + 4)


def test_unresolved_symbol_raises() -> None:
    text = bytearray(b"\xa1\x00\x00\x00\x00\xc3")
    relocs = [CoffRelocRecord(offset=1, type=0x0006, symbol="_undefined_thing")]
    with pytest.raises(UnresolvedSymbolError) as excinfo:
        apply_coff_relocations(
            bytes(text), relocs, _resolve, image_base=0x10000000, section_va=0x10001000
        )
    assert "_undefined_thing" in str(excinfo.value)


def test_unsupported_reloc_type_raises() -> None:
    text = bytearray(b"\xa1\x00\x00\x00\x00\xc3")
    relocs = [CoffRelocRecord(offset=1, type=0x0099, symbol="_g_var")]  # bogus type
    with pytest.raises(NotImplementedError):
        apply_coff_relocations(
            bytes(text), relocs, _resolve, image_base=0x10000000, section_va=0x10001000
        )
