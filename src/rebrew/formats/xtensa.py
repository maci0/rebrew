"""Little-endian Xtensa ELF32 RELA decoding and exact operand relocation.

LIEF owns the ELF layout and symbols but currently loses Xtensa relocation
kinds. Read only the standard RELA entries from its section contents.
"""

from __future__ import annotations

lazy import struct
lazy from typing import Any


def xtensa_symbol_relocations(elf: Any, symbol: Any) -> list[tuple[int, int, str, int, int | None]]:
    """Return function-relative RELA records, preserving type and explicit addend."""
    if elf.header.identity_class.name != "ELF32" or elf.header.identity_data.name != "LSB":
        raise ValueError("Xtensa relocation extraction requires little-endian ELF32")
    sections = list(elf.sections)
    symbols = list(elf.symtab_symbols)
    start, end = symbol.value, symbol.value + symbol.size
    records = []
    for section in sections:
        if section.type.name not in ("REL", "RELA"):
            continue
        index = section.information
        if index >= len(sections):
            raise ValueError("invalid Xtensa relocation target section")
        if index != symbol.shndx:
            continue
        if section.type.name != "RELA" or section.entry_size != 12:
            raise ValueError("Xtensa object requires 12-byte RELA entries")
        if section.link >= len(sections) or sections[section.link].type.name != "SYMTAB":
            raise ValueError("invalid Xtensa relocation symbol table")
        raw = bytes(section.content)
        if len(raw) != section.size or len(raw) % 12:
            raise ValueError("truncated Xtensa RELA section")
        for offset, info, addend in struct.iter_unpack("<IIi", raw):
            if not start <= offset < end:
                continue
            sym_index, kind = info >> 8, info & 255
            if sym_index >= len(symbols):
                raise ValueError("invalid Xtensa relocation symbol")
            target = symbols[sym_index]
            local = None
            name = target.name
            if target.section is not None:
                name = name or target.section.name
                if target.shndx == symbol.shndx:
                    local = target.value - start
                else:
                    addend += target.value
            records.append((offset - start, kind, name, addend, local))
    return records


def apply_xtensa_relocation(
    buf: bytearray, offset: int, kind: int, destination: int, section_va: int
) -> None:
    """Resolve R_XTENSA_32 and standard 24-bit SLOT0 operands without masking.

    Relaxation hints carry no operand. Bundled/TIE slots and other instruction
    forms require their core's ISA description and are deliberately rejected.
    """
    if kind in (0, 11, 12):
        return
    width = 4 if kind == 1 else 3
    if offset < 0 or offset + width > len(buf):
        raise ValueError("Xtensa relocation extends outside function")
    if not 0 <= destination <= 0xFFFFFFFF:
        raise ValueError("Xtensa relocation address overflows ELF32")
    if kind == 1:
        buf[offset : offset + 4] = destination.to_bytes(4, "little")
        return
    if kind != 20:
        raise NotImplementedError(f"unsupported Xtensa relocation type {kind}")
    word = int.from_bytes(buf[offset : offset + 3], "little")
    pc = section_va + offset
    if word & 15 == 1:  # L32R: aligned PC plus an implicit negative 18-bit offset.
        displacement = destination - ((pc + 3) & ~3)
        if displacement % 4 or not -262144 <= displacement <= -4:
            raise ValueError("Xtensa L32R destination is unaligned or out of range")
        word = (word & 255) | ((displacement // 4) & 65535) << 8
    elif word & 15 == 5:  # CALL0/4/8/12 share the 18-bit word displacement.
        displacement = destination - ((pc & ~3) + 4)
        if displacement % 4 or not -524288 <= displacement <= 524284:
            raise ValueError("Xtensa CALL destination is unaligned or out of range")
        word = (word & 63) | ((displacement // 4) & 262143) << 6
    elif word & 63 == 6:  # J: signed byte displacement from PC + 4.
        displacement = destination - (pc + 4)
        if not -131072 <= displacement <= 131071:
            raise ValueError("Xtensa J destination is out of range")
        word = (word & 63) | (displacement & 262143) << 6
    else:
        raise NotImplementedError("unsupported Xtensa SLOT0 instruction; use the core-aware linker")
    buf[offset : offset + 3] = word.to_bytes(3, "little")
