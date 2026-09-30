"""Typed relocation spans for digest clients, independent of similarity heuristics."""

from __future__ import annotations

import lief

from rebrew.binary_loader import extract_bytes_at_va
from rebrew.binary_model import BinaryInfo

_MAX_SPANS = 1_000_000


def relocation_spans(info: BinaryInfo) -> list[tuple[int, int]]:
    """Absolute addresses and byte widths of supported linked-image fixups.

    Parse once per image, then intersect these spans with function ranges.
    Unsupported formats and relocation kinds raise instead of supplying an
    incomplete mask. Integer constants are never inferred to be addresses.
    """
    if info.arch not in ("x86_32", "x86_64") or info.format not in ("pe", "elf"):
        raise NotImplementedError(f"relocation spans unavailable for {info.format}/{info.arch}")
    spans = _pe_spans(info) if info.format == "pe" else _elf_spans(info)
    if len(spans) > _MAX_SPANS:
        raise ValueError("relocation span limit exceeded")
    for address, width in spans:
        raw = extract_bytes_at_va(info, address, width, trim_padding=False)
        if raw is None or len(raw) != width:
            raise ValueError("relocation extends outside file-backed image bytes")
    return sorted(set(spans))


def _pe_spans(info: BinaryInfo) -> list[tuple[int, int]]:
    binary = lief.PE.parse(info.data)
    if binary is None or binary.optional_header.imagebase != info.image_base:
        raise ValueError("PE relocation image does not match its loaded layout")
    kinds = lief.PE.RelocationEntry.BASE_TYPES
    widths = {kinds.HIGHLOW: 4, kinds.DIR64: 8}
    spans: list[tuple[int, int]] = []
    for block in binary.relocations:
        if block.virtual_address % 4096:
            raise ValueError("PE relocation block is not page aligned")
        for entry in block.entries:
            if entry.type == kinds.ABS:
                continue
            width = widths.get(entry.type)
            if width is None:
                raise NotImplementedError(f"unsupported PE relocation: {entry.type}")
            spans.append((info.image_base + entry.address, width))
            if len(spans) > _MAX_SPANS:
                raise ValueError("relocation span limit exceeded")
    return spans


def _elf_spans(info: BinaryInfo) -> list[tuple[int, int]]:
    binary = lief.ELF.parse(info.data)
    if binary is None or binary.imagebase != info.image_base:
        raise ValueError("ELF relocation image does not match its loaded layout")
    if binary.header.file_type not in (
        lief.ELF.Header.FILE_TYPE.EXEC,
        lief.ELF.Header.FILE_TYPE.DYN,
    ):
        raise NotImplementedError("ELF relocation spans require a linked image")
    kinds = lief.ELF.Relocation.TYPE
    widths = {
        kinds.X86_32: 4,
        kinds.X86_PC32: 4,
        kinds.X86_GOT32: 4,
        kinds.X86_PLT32: 4,
        kinds.X86_GLOB_DAT: 4,
        kinds.X86_JUMP_SLOT: 4,
        kinds.X86_RELATIVE: 4,
        kinds.X86_GOTOFF: 4,
        kinds.X86_GOTPC: 4,
        kinds.X86_64_64: 8,
        kinds.X86_64_PC32: 4,
        kinds.X86_64_PLT32: 4,
        kinds.X86_64_GLOB_DAT: 8,
        kinds.X86_64_JUMP_SLOT: 8,
        kinds.X86_64_RELATIVE: 8,
        kinds.X86_64_GOTPCREL: 4,
        kinds.X86_64_32: 4,
        kinds.X86_64_32S: 4,
        kinds.X86_64_IRELATIVE: 8,
    }
    spans: list[tuple[int, int]] = []
    for entry in binary.relocations:
        if entry.type in (kinds.X86_NONE, kinds.X86_64_NONE):
            continue
        width = widths.get(entry.type)
        if width is None:
            raise NotImplementedError(f"unsupported ELF relocation: {entry.type}")
        spans.append((entry.address, width))
        if len(spans) > _MAX_SPANS:
            raise ValueError("relocation span limit exceeded")
    return spans
