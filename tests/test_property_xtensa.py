"""Property-based fuzz tests for the Xtensa ELF32 RELA / operand-relocation surface.

``formats.xtensa`` walks untrusted bytes: ``xtensa_symbol_relocations``
unpacks RELA entries whose offsets, symbol indices and addends come
verbatim from a (possibly hostile) object file, and
``apply_xtensa_relocation`` rewrites the operand bytes of a function
buffer at an offset/kind/destination taken from those same records.
Both must fail only with ``ValueError`` / ``NotImplementedError``
(never a bare ``struct.error``, ``IndexError`` or silent corruption),
and a successful application must keep the buffer length, touch only
the operand window, preserve the top byte of 3-byte SLOT0 words, and
round-trip the displacement it decoded.
"""

from __future__ import annotations

import struct
from types import SimpleNamespace
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.formats.xtensa import apply_xtensa_relocation, xtensa_symbol_relocations

_SETTINGS = settings(max_examples=200, deadline=None)


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
    symbols: list[Any] = [None]
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


class TestApplyXtensaRelocationFuzz:
    @_SETTINGS
    @given(
        st.binary(max_size=16),
        st.integers(min_value=-5, max_value=20),
        st.integers(min_value=0, max_value=300),
        st.integers(min_value=-(2**31), max_value=2**33),
        st.integers(min_value=0, max_value=2**32 - 1),
    )
    def test_never_raises_unexpected(
        self, raw: bytes, offset: int, kind: int, dest: int, pc: int
    ) -> None:
        buf = bytearray(raw)
        try:
            apply_xtensa_relocation(buf, offset, kind, dest, pc)
        except ValueError, NotImplementedError:
            return
        # On success: length preserved, only operand window may change.
        assert len(buf) == len(raw)
        width = 4 if kind == 1 else 3
        if kind in (0, 11, 12):
            assert bytes(buf) == raw
            return
        if offset >= 0 and offset + width <= len(buf):
            assert bytes(buf[:offset]) == raw[:offset]
            assert bytes(buf[offset + width :]) == raw[offset + width :]
            if kind == 20 and width == 3 and offset + 3 < len(buf):
                # SLOT0 rewrite preserves the top byte (fourth byte / opcode extension).
                assert buf[offset + 3] == raw[offset + 3]

    @_SETTINGS
    @given(st.binary(max_size=16), st.integers(min_value=0, max_value=2**32 - 1))
    def test_kind1_writes_exact_destination(self, raw: bytes, dest: int) -> None:
        if len(raw) < 4:
            return
        buf = bytearray(raw)
        apply_xtensa_relocation(buf, 0, 1, dest, 0x32001000)
        assert bytes(buf[:4]) == dest.to_bytes(4, "little")
        assert bytes(buf[4:]) == raw[4:]

    @_SETTINGS
    @given(
        st.binary(max_size=16),
        st.integers(min_value=0, max_value=2**32 - 1),
    )
    def test_relaxation_kinds_are_noops(self, raw: bytes, dest: int) -> None:
        for kind in (0, 11, 12):
            buf = bytearray(raw)
            apply_xtensa_relocation(buf, 0, kind, dest, 0x32001000)
            assert bytes(buf) == raw

    @_SETTINGS
    @given(
        st.integers(min_value=0, max_value=2**32 - 1),
        st.integers(min_value=0, max_value=2**32 - 1),
    )
    def test_j_displacement_roundtrip(self, pc: int, dest: int) -> None:
        # Use a J word (low 6 bits == 6) so the J branch is taken.
        word = 6 | (0xA7 << 24)  # top byte is outside the 3-byte window check below
        buf = bytearray((word & 0xFFFFFF).to_bytes(3, "little") + b"\xa7")
        # Only encoded when dest in range; otherwise ValueError is the correct outcome.
        try:
            apply_xtensa_relocation(buf, 0, 20, dest, pc)
        except ValueError:
            displacement = dest - (pc + 4)
            assert not (-131072 <= displacement <= 131071)
            return
        encoded = int.from_bytes(buf[:3], "little") >> 6
        displacement = encoded - (1 << 18) if encoded & (1 << 17) else encoded
        assert (pc + 4 + displacement) & 0xFFFFFFFF == dest & 0xFFFFFFFF
        assert buf[3] == 0xA7  # byte past the 3-byte operand untouched


class TestXtensaSymbolRelocationsFuzz:
    @_SETTINGS
    @given(st.binary(max_size=48), st.integers(min_value=0, max_value=32))
    def test_random_rela_never_crashes_unexpectedly(self, raw: bytes, size: int) -> None:
        elf, function = _elf_mock(raw, size)
        try:
            records = xtensa_symbol_relocations(elf, function)
        except ValueError:
            return
        for offset, kind, name, addend, local in records:
            assert 0 <= offset < max(size, 1) or size == 0
            assert isinstance(kind, int) and 0 <= kind <= 255
            assert isinstance(name, str)
            assert isinstance(addend, int)
            assert local is None or isinstance(local, int)

    @_SETTINGS
    @given(
        st.lists(
            st.tuples(
                st.integers(min_value=0, max_value=64),
                st.integers(min_value=0, max_value=2**16),
                st.integers(min_value=-(2**31), max_value=2**31 - 1),
            ),
            max_size=5,
        ),
        st.integers(min_value=1, max_value=64),
    )
    def test_structured_rela_offsets_in_range(
        self, entries: list[tuple[int, int, int]], size: int
    ) -> None:
        raw = b"".join(
            struct.pack("<IIi", off, (1 << 8) | (kind & 0xFF), add) for off, kind, add in entries
        )
        elf, function = _elf_mock(raw, size)
        try:
            records = xtensa_symbol_relocations(elf, function)
        except ValueError:
            return
        for offset, _kind, _name, _addend, _local in records:
            assert 0 <= offset < size

    def test_truncated_rela_raises_value_error(self) -> None:
        elf, function = _elf_mock(b"\x00" * 11, 32)
        with pytest.raises(ValueError, match="truncated"):
            xtensa_symbol_relocations(elf, function)

    def test_invalid_symbol_index_raises_value_error(self) -> None:
        # Symbol index 99 with only 2 symbols in the table.
        raw = struct.pack("<IIi", 0, (99 << 8) | 1, 0)
        elf, function = _elf_mock(raw, 32)
        with pytest.raises(ValueError, match="invalid Xtensa relocation symbol"):
            xtensa_symbol_relocations(elf, function)
