"""NE (New Executable) loader for 16-bit Windows 3.x binaries.

Borland Delphi 1.0 / Turbo Pascal Windows applications ship as NE
executables (MZ stub + "NE" header) — e.g. ``holiday.exe``.  rebrew's
flat-VA model (PE/ELF/Mach-O) does not apply directly: NE uses segmented
addressing, so this module maps each segment to a synthetic flat VA of
``(segment_index << 16) | offset`` (segment 1 → 0x10000..0x1FFFF, …).

Parses the NE header, segment table, resident name table (named exports),
module reference table + imported names table (Win16 imports).  Exposes
:func:`load_ne_binary` which produces a :class:`rebrew.binary_loader.BinaryInfo`
(``format="ne"``) so the rest of rebrew (strings, analyze, asm, discover)
can operate on 16-bit targets.

References: the NE format documentation in the Windows 3.1 SDK / Wine
source (``dlls/winedump/ne.c``) — field offsets below follow that layout.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from rebrew.binary_loader import BinaryInfo, SectionInfo

NE_MAGIC = b"NE"

# Segment flags (low byte bits we care about)
SEG_CODE = 0x01
SEG_ITERATED = 0x02  # iterated data (not supported for raw extraction)
SEG_MOVEABLE = 0x10
SEG_SHARED = 0x20
SEG_PRELOAD = 0x40
SEG_DISCARDABLE = 0x80
SEG_DATA = 0x04  # not code


@dataclass
class NeHeader:
    """Parsed NE header fields."""

    linker_version: int
    entry_table_offset: int
    entry_table_length: int
    flags: int
    autodata_segment: int
    heap_size: int
    stack_size: int
    entry_ip: int
    entry_cs: int
    stack_sp: int
    stack_ss: int
    segment_count: int
    module_reference_count: int
    segment_table_offset: int
    resource_table_offset: int
    resident_names_offset: int
    module_ref_table_offset: int
    imported_names_offset: int
    nonresident_names_offset: int
    alignment_shift: int

    @property
    def sector_size(self) -> int:
        """Logical sector size: segments are byte-aligned to this."""
        return 1 << self.alignment_shift


@dataclass
class NeSegment:
    """One entry from the NE segment table."""

    index: int  # 1-based
    file_offset: int  # absolute file offset of the segment data
    length: int  # length of the segment data on disk
    flags: int
    min_allocation: int
    is_code: bool = False  # set by load_ne_binary via a content probe

    @property
    def is_iterated(self) -> bool:
        return bool(self.flags & SEG_ITERATED)

    @property
    def base_va(self) -> int:
        """Synthetic flat VA for segment:offset addressing (segment 1 → 0x10000)."""
        return self.index << 16


#: x86-16 opcodes that mark a likely code start in a Borland segment.
#: Delphi 1.0 prologs are ``enter`` (0xC8) or ``push bp`` (0x55); the
#: startup segment begins with a chain of far calls (0x9A).
_CODE_ANCHORS = frozenset({0x55, 0xC8, 0x9A, 0xE8, 0xEB, 0xE9})


def _looks_like_name_string(data: bytes, off: int) -> bool:
    """True when *off* starts a length-prefixed printable string (Borland
    segment-name convention: ``\\xNN`` followed by *NN* ASCII chars)."""
    ln = data[off]
    if not (1 <= ln <= 40):
        return False
    return all(0x20 <= c < 0x7F for c in data[off + 1 : off + 1 + ln])


def probe_is_code(data: bytes, file_offset: int, length: int) -> bool:
    """Heuristically decide whether a segment holds 16-bit code.

    Borland NE segments are ``[index\\x00][name-string][content]`` — the
    leading string is a Delphi unit/app name and the content that follows
    may be code or data.  This finds the first *code anchor* (ENTER / PUSH
    BP / call / jmp) after any name string and verifies it with a clean
    capstone x86-16 decode: code when ≥ 8 instructions decode with control
    flow before hitting invalid bytes.
    """
    import capstone

    content = file_offset + 2  # skip the Borland index marker
    window = data[content : content + min(length - 2, 512)]
    if len(window) < 4:
        return False

    # Skip a leading name string (length-prefixed printable ASCII).
    pos = 0
    while _looks_like_name_string(window, pos):
        pos += 1 + window[pos]
        if pos + 1 >= len(window):
            return False

    # Find the first code anchor within the remaining window.
    anchor = None
    for i in range(pos, min(pos + 128, len(window))):
        if window[i] in _CODE_ANCHORS:
            anchor = i
            break
    if anchor is None:
        return False

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoded = list(md.disasm(window[anchor:], 0))
    if len(decoded) < 5:
        return False
    return any(i.mnemonic in ("call", "jmp", "ret", "retf", "loop", "jcxz", "int") for i in decoded)


# ---------------------------------------------------------------------------
# Function enumeration (16-bit linear sweep)
# ---------------------------------------------------------------------------


@dataclass
class NeFunction:
    """A function discovered by :func:`enumerate_ne_functions`."""

    va: int  # synthetic flat VA (segment << 16 | offset)
    segment: int  # 1-based segment index
    offset: int  # offset within the segment
    size: int
    name: str


def _is_prolog(raw: bytes, off: int) -> bool:
    """True when *off* starts a Delphi 1.0 function prolog.

    Prologs are ``push bp`` (55) — optionally followed by ``mov bp,sp``
    (8b ec) — or ``enter imm16, 0`` (c8 XX XX 00).  An ``enter`` with a
    non-zero level byte is unusual; accept level 0.
    """
    b = raw[off]
    if b == 0x55:  # push bp
        return True
    if b == 0xC8:  # enter
        if off + 4 > len(raw):
            return False
        return raw[off + 3] == 0x00  # enter imm16, 0
    return False


def _is_epilog(mnemonic: str) -> bool:
    return mnemonic in ("ret", "retf", "retn")


def enumerate_ne_functions(info: BinaryInfo) -> list[NeFunction]:
    """Linear-sweep function discovery over an NE binary's code segments.

    Scans each code segment (as classified by :func:`probe_is_code`) for
    Delphi 1.0 prologs (``push bp`` / ``enter``) and walks the instruction
    stream to the next ``ret``/``retf`` to size each function.  Functions
    whose body fails to decode or whose size is implausible (< 3 bytes) are
    dropped.  Returns a list sorted by VA with synthetic flat VAs
    (``segment << 16 | offset``).
    """
    import capstone

    data = info.data
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    funcs: list[NeFunction] = []
    for seg in info.ne_segments:  # type: ignore[attr-defined]
        if not seg.is_code:
            continue
        raw = data[seg.file_offset : seg.file_offset + seg.length]
        if len(raw) < 4:
            continue
        # Find candidate prologs.
        candidates: list[int] = []
        for off in range(len(raw) - 3):
            if _is_prolog(raw, off):
                candidates.append(off)
        if not candidates:
            continue
        # Disassemble from each candidate; the function ends at the first
        # ret/retf that terminates a balanced run (bounded to segment end).
        for start in candidates:
            body = raw[start:]
            va = seg.base_va + start
            size = 0
            insn_count = 0
            found_epilog = False
            for insn in md.disasm(body, va):
                insn_count += 1
                size = insn.address - va + insn.size
                if _is_epilog(insn.mnemonic):
                    found_epilog = True
                    break
            # Keep the function only when the body is credible: a real epilog
            # (ret/retf) or a long decoded run.  A lone `enter`/`push bp` in
            # data decodes to 1-2 instructions and is a false positive.
            if not found_epilog and insn_count < 10:
                continue
            if 3 <= size <= len(raw) - start:
                funcs.append(
                    NeFunction(
                        va=va,
                        segment=seg.index,
                        offset=start,
                        size=size,
                        name=f"sub_{va:05x}",
                    )
                )
    # De-duplicate overlapping candidates (a prolog inside another function
    # would otherwise double-count) — keep the earliest start per address.
    funcs.sort(key=lambda f: (f.va, f.size))
    deduped: list[NeFunction] = []
    last_end = -1
    for f in funcs:
        if f.va <= last_end:
            continue  # inside an already-covered function
        deduped.append(f)
        last_end = f.va + f.size
    return deduped


@dataclass
class NeImport:
    """A single Win16 import: by name or by ordinal."""

    name: str | None = None
    ordinal: int | None = None

    def __str__(self) -> str:
        return self.name if self.name is not None else f"ordinal {self.ordinal}"


@dataclass
class NeImportModule:
    """One imported DLL (module) and its imports."""

    module: str
    imports: list[NeImport] = field(default_factory=list)


@dataclass
class NeExport:
    """A named export from the resident name table."""

    name: str
    ordinal: int


class NeParseError(ValueError):
    """Raised when a file claims to be NE but its tables are malformed."""


def _u8(data: bytes, off: int) -> int:
    return int(data[off])


def _u16(data: bytes, off: int) -> int:
    return int(struct.unpack_from("<H", data, off)[0])


def _u32(data: bytes, off: int) -> int:
    return int(struct.unpack_from("<I", data, off)[0])


def parse_ne_header(data: bytes, ne_offset: int) -> NeHeader:
    """Parse the NE header at *ne_offset* (the MZ ``e_lfanew``)."""
    if data[ne_offset : ne_offset + 2] != NE_MAGIC:
        raise NeParseError("not an NE executable")
    h = ne_offset
    return NeHeader(
        linker_version=data[h + 0x02],
        entry_table_offset=_u16(data, h + 0x04),
        entry_table_length=_u16(data, h + 0x06),
        flags=_u16(data, h + 0x0C),
        autodata_segment=_u16(data, h + 0x0E),
        heap_size=_u16(data, h + 0x10),
        stack_size=_u16(data, h + 0x12),
        entry_ip=_u16(data, h + 0x14),
        entry_cs=_u16(data, h + 0x16),
        stack_sp=_u16(data, h + 0x18),
        stack_ss=_u16(data, h + 0x1A),
        segment_count=_u16(data, h + 0x1C),
        module_reference_count=_u16(data, h + 0x1E),
        segment_table_offset=_u16(data, h + 0x22),
        resource_table_offset=_u16(data, h + 0x24),
        resident_names_offset=_u16(data, h + 0x26),
        module_ref_table_offset=_u16(data, h + 0x28),
        imported_names_offset=_u16(data, h + 0x2A),
        nonresident_names_offset=_u32(data, h + 0x2C),
        alignment_shift=_u16(data, h + 0x32),
    )


def parse_segments(data: bytes, ne_offset: int, header: NeHeader) -> list[NeSegment]:
    """Parse the segment table into :class:`NeSegment` entries."""
    h = ne_offset
    sector = header.sector_size
    segments: list[NeSegment] = []
    for i in range(header.segment_count):
        off = h + header.segment_table_offset + i * 8
        sector_off, length, flags, min_alloc = struct.unpack_from("<HHHH", data, off)
        segments.append(
            NeSegment(
                index=i + 1,
                file_offset=sector_off * sector,
                length=length,
                flags=flags,
                min_allocation=min_alloc,
            )
        )
    return segments


def _pascal_string(data: bytes, off: int) -> tuple[str, int]:
    """Read a length-prefixed (Pascal) string at *off*; return (str, next_off)."""
    ln = data[off]
    end = off + 1 + ln
    return data[off + 1 : end].decode("latin-1", "replace"), end


def parse_imports(data: bytes, ne_offset: int, header: NeHeader) -> list[NeImportModule]:
    """Parse the module reference + imported names tables into imports.

    The module reference table holds offsets into the imported names table
    (Pascal strings = module names).  The import table follows the entry
    table: per module, a uint16 count then that many uint16 entries — bit 15
    set = import by name (low 15 bits = offset into the imported names table),
    clear = import by ordinal (the value itself).

    The per-import detail is best-effort: Borland linkers emit non-standard
    layouts and some binaries carry no import table at all, so a malformed
    block degrades to the module list only rather than failing the load.
    """
    h = ne_offset
    impnames = h + header.imported_names_offset
    modtab = h + header.module_ref_table_offset

    modules: list[NeImportModule] = []
    for i in range(header.module_reference_count):
        name_off = _u16(data, modtab + i * 2)
        name, _ = _pascal_string(data, impnames + name_off)
        modules.append(NeImportModule(module=name))

    try:
        # Import table starts right after the entry table.
        pos = h + header.entry_table_offset + header.entry_table_length
        for mod in modules:
            if pos + 2 > len(data):
                break
            count = _u16(data, pos)
            pos += 2
            if count == 0xFFFF:
                break  # table terminator
            if pos + count * 2 > len(data):
                break
            for _ in range(count):
                v = _u16(data, pos)
                pos += 2
                if v & 0x8000:
                    nm, _ = _pascal_string(data, impnames + (v & 0x7FFF))
                    mod.imports.append(NeImport(name=nm))
                else:
                    mod.imports.append(NeImport(ordinal=v))
    except (struct.error, IndexError):
        # Malformed import table — keep the module names we already have.
        pass
    return modules


def parse_exports(data: bytes, ne_offset: int, header: NeHeader) -> list[NeExport]:
    """Parse the resident name table (named exports: name + ordinal)."""
    h = ne_offset
    pos = h + header.resident_names_offset
    # The resident name table ends at the next table after it (module ref →
    # imported names → entry table); fall back to the file length when the
    # linker left the later offsets zero (import-free binaries).
    candidates = [
        header.module_ref_table_offset,
        header.imported_names_offset,
        header.entry_table_offset,
    ]
    end = h + min(
        (o for o in candidates if o > header.resident_names_offset),
        default=len(data),
    )
    exports: list[NeExport] = []
    while pos < end:
        ln = data[pos]
        if ln == 0 or ln > 63:
            break  # empty name or implausible length ends the table
        if pos + 1 + ln + 2 > end:
            break
        name, pos = _pascal_string(data, pos)
        ordinal = _u16(data, pos)
        pos += 2
        exports.append(NeExport(name=name, ordinal=ordinal))
    return exports


def load_ne_binary(path: Path) -> BinaryInfo:
    """Parse a 16-bit NE executable into a rebrew ``BinaryInfo``.

    Segments become sections named ``SEG1``..``SEGn`` with synthetic flat VAs
    of ``(index << 16)`` so segment:offset addressing maps onto rebrew's
    flat-VA tools (asm, strings, analyze).  Iterated-data segments (flag
    SEG_ITERATED) have no on-disk raw form; their raw_size is reported as 0.
    """
    path = Path(path)
    data = path.read_bytes()
    ne_offset = _u32(data, 0x3C)
    header = parse_ne_header(data, ne_offset)
    segments = parse_segments(data, ne_offset, header)

    sections: dict[str, SectionInfo] = {}
    for seg in segments:
        raw_size = 0 if seg.is_iterated else min(seg.length, len(data) - seg.file_offset)
        seg.is_code = probe_is_code(data, seg.file_offset, seg.length)
        sections[f"SEG{seg.index}"] = SectionInfo(
            name=f"SEG{seg.index}",
            va=seg.base_va,
            size=max(seg.length, seg.min_allocation),
            file_offset=seg.file_offset,
            raw_size=raw_size,
        )

    info = BinaryInfo(
        path=path,
        format="ne",
        image_base=0,
        sections=sections,
        _data=data,
    )
    # Attach parsed NE tables for tools that need them.
    info.ne_header = header  # type: ignore[attr-defined]
    info.ne_segments = segments  # type: ignore[attr-defined]
    info.ne_imports = parse_imports(data, ne_offset, header)  # type: ignore[attr-defined]
    info.ne_exports = parse_exports(data, ne_offset, header)  # type: ignore[attr-defined]
    return info
