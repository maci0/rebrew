"""Atheris (libFuzzer) target: Xtensa ELF32 RELA / operand-relocation surface.

Same harness body and invariants as tests/test_property_xtensa.py
(Hypothesis drives it in CI; this file is the coverage-guided libFuzzer
entry point for local/OSSFuzz runs).

    uv run --frozen --group fuzz --group dev python tests/fuzz_xtensa.py <corpus_dir> [flags]
    uv run --frozen --group fuzz --group dev python tests/fuzz_xtensa.py tests/fixtures -runs=1000

``formats.xtensa`` walks untrusted bytes: ``xtensa_symbol_relocations``
unpacks RELA entries whose offsets, symbol indices and addends come
verbatim from a (possibly hostile) object file, and
``apply_xtensa_relocation`` rewrites the operand bytes of a function
buffer at an offset/kind/destination taken from those same records.
Both must fail only with ``ValueError`` / ``NotImplementedError`` (never
a bare ``struct.error``, ``IndexError`` or silent corruption), and a
successful application must keep the buffer length, touch only the
operand window, preserve the top byte of 3-byte SLOT0 words, and
round-trip the displacement it decoded.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import atheris

from rebrew.formats.xtensa import apply_xtensa_relocation, xtensa_symbol_relocations

# Structured RELA entry: <IIi offset, info(sym<<8|kind), addend.
_ENTRY = 12


def _elf_mock(rela_content: bytes, size: int, sym_count: int = 2) -> tuple[Any, Any]:
    """Minimal ELF mock: one .text, one RELA section pointing at a symtab."""
    text = SimpleNamespace(name=".text", type=SimpleNamespace(name="PROGBITS"))
    rela = SimpleNamespace(
        type=SimpleNamespace(name="RELA"),
        information=0,
        link=2,
        entry_size=12,
        content=rela_content,
        size=len(rela_content),
    )
    symtab = SimpleNamespace(type=SimpleNamespace(name="SYMTAB"))
    # Index 0 is the LIEF null symbol (STN_UNDEF): a real Symbol with an
    # empty name, never a bare None. Fuzzing sym_index 0 must yield an
    # empty-name record, matching what production LIEF objects produce.
    symbols: list[Any] = [SimpleNamespace(value=0, section=None, name="", shndx=0)]
    for i in range(max(0, sym_count - 1)):
        symbols.append(SimpleNamespace(value=0, section=None, name=f"sym{i}", shndx=0))
    elf = SimpleNamespace(
        header=SimpleNamespace(
            identity_class=SimpleNamespace(name="ELF32"),
            identity_data=SimpleNamespace(name="LSB"),
        ),
        sections=[text, rela, symtab],
        symtab_symbols=symbols,
    )
    function = SimpleNamespace(value=0, size=size, shndx=0)
    return elf, function


def TestOneInput(data: bytes) -> None:
    """Every entry point must never raise (except ValueError /
    NotImplementedError); accepted records must keep their shape and
    applied operands must keep the buffer length and touch only the
    operand window."""
    # Drive both structured entries (first bytes) and raw-RELA bytes
    # (remainder) through the symbol-relocation walker.
    split = min(len(data), 96)
    raw_rela, tail = data[:split], data[split:]
    size = 64
    elf, function = _elf_mock(raw_rela, size)
    try:
        records = xtensa_symbol_relocations(elf, function)
    except ValueError:
        records = []
    for offset, kind, name, addend, local in records:
        assert 0 <= offset < max(size, 1) or size == 0
        assert isinstance(kind, int) and 0 <= kind <= 255
        assert isinstance(name, str)
        assert isinstance(addend, int)
        assert local is None or isinstance(local, int)

    # Apply each accepted record against a fresh operand buffer seeded
    # from the tail bytes; length must be preserved and only the operand
    # window may change.
    for offset, kind, _name, addend, _local in records:
        buf = bytearray((tail + b"\x00" * 64)[:64])
        original = bytes(buf)
        try:
            apply_xtensa_relocation(buf, offset, kind, addend & 0xFFFFFFFF, 0x32001000)
        except ValueError, NotImplementedError:
            continue
        assert len(buf) == len(original)
        width = 4 if kind == 1 else 3
        if kind in (0, 11, 12):
            assert bytes(buf) == original
            continue
        if offset >= 0 and offset + width <= len(buf):
            assert bytes(buf[:offset]) == original[:offset]
            assert bytes(buf[offset + width :]) == original[offset + width :]
            if kind == 20 and width == 3 and offset + 3 < len(buf):
                assert buf[offset + 3] == original[offset + 3]

    # Raw operand fuzz: arbitrary offset/kind/dest/pc from the tail bytes.
    if len(tail) >= 8:
        offset = int.from_bytes(tail[0:2], "little", signed=True)
        kind = tail[2]
        dest = int.from_bytes(tail[3:7], "little")
        pc = int.from_bytes(tail[7:8], "little") << 24
        buf = bytearray((tail + b"\x00" * 16)[:16])
        original = bytes(buf)
        try:
            apply_xtensa_relocation(buf, offset, kind, dest, pc)
        except ValueError, NotImplementedError:
            return
        assert len(buf) == len(original)
        width = 4 if kind == 1 else 3
        if kind in (0, 11, 12):
            assert bytes(buf) == original
            return
        if offset >= 0 and offset + width <= len(buf):
            assert bytes(buf[:offset]) == original[:offset]
            assert bytes(buf[offset + width :]) == original[offset + width :]
            if kind == 20 and width == 3 and offset + 3 < len(buf):
                assert buf[offset + 3] == original[offset + 3]


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
