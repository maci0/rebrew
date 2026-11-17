"""Generate FLIRT .pat files from COFF .lib and ELF .a archives.

This reads the object files inside an archive, extracts every public
function symbol with its relocations, and emits a .pat-format line for
each one with relocation bytes masked as '..'.

MSVC COFF objects (``.lib``) are parsed via LIEF's COFF module; console-era
IDO/MWCC archives (ELF ``.a``) via LIEF's ELF module — ELF objects carry
exact function sizes in the symbol table, so no next-symbol heuristic is
needed.  MIPS relocations mask the whole 4-byte instruction word (the fixup
target field shares the word with the opcode).
"""

import logging
from typing import NamedTuple
lazy import bisect
lazy import struct
lazy from collections.abc import Iterator
lazy from pathlib import Path
lazy from typing import Any

import typer

lazy from rebrew.cli import console, error_exit, json_print
lazy from rebrew.formats.archives import parse_archive as parse_archive
lazy from rebrew.formats.coff import load_coff
lazy from rebrew.utils import atomic_write_text, fold_ident

logger = logging.getLogger(__name__)

app = typer.Typer(
    help="Generate FLIRT .pat files from COFF .lib and ELF .a archives.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew library signatures source/VC98/Lib/LIBCMT.LIB\n\n"
        "  rebrew library signatures LIBCMT.LIB --output flirt_sigs/libcmt.pat\n\n"
        "  rebrew library signatures libultra.a --output flirt_sigs/libultra.pat\n\n"
        "[dim]Reads COFF .obj or ELF .o members from an ar archive, extracts public function symbols with relocations, and emits FLIRT .pat-format signatures.[/dim]"
    ),
)


#: LIEF's name of the i386 32-bit absolute relocation type.
_I386_DIR32 = "I386_DIR32"


class ObjectFunction(NamedTuple):
    """One function of an object file (:func:`parse_coff_obj`, :func:`parse_elf_obj`)."""

    name: str
    code: bytes
    #: Byte positions in *code* covered by relocations (the full fixup width).
    relocations: set[int]
    #: i386 DIR32 fields that name a symbol of the function's own section (a
    #: jump table's ``$L`` label, a label of the function): field offset in
    #: *code* -> that symbol's offset from the function start.  The field holds
    #: the addend; an unlinked object leaves the address unset, which
    #: :func:`rebrew.cfg_ged.apply_self_relocations` fills in.  Empty for ELF.
    self_relocations: dict[int, int]
    #: Named symbols inside the function that start no function of their own
    #: (offset in *code* -> name): the internal labels of a hand-written
    #: assembly routine, its jump tables.  Empty for ELF.
    labels: dict[int, str]


#: IMAGE_FILE_MACHINE_I386, the COFF machine :func:`_i386_function_starts` reads.
_COFF_MACHINE_I386 = 0x14C
#: Longest x86 instruction, in bytes.
_X86_MAX_INSN = 15
#: Instructions after which execution does not continue at the next byte.
_X86_NO_FALLTHROUGH = frozenset(
    {"ret", "retf", "iret", "iretd", "iretq", "jmp", "ljmp", "ud2", "hlt", "int3"}
)


def _i386_function_starts(
    section_idx: int,
    content: bytes,
    candidates: list[tuple[int, bool]],
    relocated: set[int],
    refs: dict[int, tuple[int, int]],
    entries: dict[tuple[int, int], int],
) -> set[int]:
    """Offsets of *candidates* (``(offset, external)``) that start functions.

    *content* is the code of section *section_idx*; *relocated* is every
    byte of it a relocation fixes up; *refs*
    maps each of its DIR32 fields that names a defined symbol to that
    symbol's ``(section index, offset)``; *entries* maps each DIR32 field of
    the object (``(section index, offset)``) that addresses this section to
    the offset it resolves to (the symbol plus the signed addend).  See
    :func:`parse_coff_obj`.
    """
    import capstone

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    reached: set[int] = set()
    called: set[int] = set()
    tables_read: set[tuple[int, int]] = set()

    def table(section: int, at: int) -> list[int]:
        """The case offsets of the jump table at *at*: a run of entry fields."""
        cases = []
        while (section, at) in entries and (section, at) not in tables_read:
            tables_read.add((section, at))
            cases.append(entries[section, at])
            at += 4
        return cases

    def descend(start: int) -> None:
        work = [start]
        while work:
            at = work.pop()
            while 0 <= at < len(content) and at not in reached:
                reached.add(at)
                insn = next(md.disasm(content[at : at + _X86_MAX_INSN], at, 1), None)
                if insn is None:
                    break
                end = at + insn.size
                in_place = relocated.isdisjoint(range(at, end))
                is_call = insn.group(capstone.CS_GRP_CALL)
                if in_place and insn.op_count(capstone.x86.X86_OP_IMM):
                    target = insn.op_find(capstone.x86.X86_OP_IMM, 1).imm
                    if is_call:
                        called.add(target)
                    elif insn.group(capstone.CS_GRP_JUMP):
                        work.append(target)
                if not is_call:
                    for field in range(at, end):
                        if field in refs and (cases := table(*refs[field])):
                            work.extend(cases)
                            if refs[field][0] == section_idx:
                                reached.add(refs[field][1])
                if insn.mnemonic in _X86_NO_FALLTHROUGH:
                    break
                at = end

    starts: set[int] = set()
    for offset, external in sorted(candidates):
        if offset in starts:
            continue
        if external or offset in called or offset not in reached:
            starts.add(offset)
            descend(offset)
    return starts


def parse_coff_obj(obj_data: bytes) -> Iterator[ObjectFunction]:
    """Parse a COFF .obj and yield its functions (:class:`ObjectFunction`).

    Uses LIEF for parsing. ``obj_data`` is raw bytes of a COFF .obj file.

    A function runs from its symbol to the next function's symbol in the same
    section.  The candidates are the EXTERNAL and STATIC named symbols of a code
    section; on i386 and AMD64 a candidate starts a function when it is
    EXTERNAL, when code of the section calls it, or when no function before it
    reaches it.  Reaching follows each start's code by fall-through and by
    direct ``jmp``/``jcc`` the assembler resolved in place (a branch through a
    relocation goes to another function), and through jump tables: a
    non-call instruction whose DIR32 field names a run of DIR32 fields of the
    same section dispatches through every entry of the run.  An address taken
    by ``push``/``mov`` is not reached.  The symbol type does not count: MSVC's
    hand-written ``memcpy.obj`` marks ``LeadUp1``, ``TrailUp0`` and the other
    internal labels of ``_memcpy`` as functions, and each was its own
    function, cutting ``_memcpy`` to 100 bytes.  A candidate that does not
    start a function stays in :attr:`ObjectFunction.labels` of the function
    holding it.  Known misses: a STATIC function that only follows a
    no-return call (``call _exit``) with nothing between is reached by
    fall-through and becomes a label, unless the section calls it; other
    machines keep every candidate a function.  COMDAT sections need no rule
    of their own: each section is read on its own.
    """
    import lief

    loaded = load_coff(obj_data)
    if loaded is None:
        return
    coff, symbols, names = loaded

    # EXTERNAL alone is not enough: MSVC marks CRT helpers such as _initterm
    # and _parse_cmdline STATIC, so they are absent from the archive symbol
    # index. They are still linked into the target and still need signatures,
    # and code that looks only at EXTERNAL reports them as "not in the library".
    _FUNC_CLASSES = (
        lief.COFF.Symbol.STORAGE_CLASS.EXTERNAL,
        lief.COFF.Symbol.STORAGE_CLASS.STATIC,
    )
    # Named symbols of each code section, by section index (names can repeat).
    # STATIC is also the class of section symbols (".text"), which alias the
    # first function; "$" labels are the compiler's own.
    candidates: dict[int, list[tuple[Any, str]]] = {}
    for sym, sym_name in zip(symbols, names, strict=True):
        if (
            sym.storage_class in _FUNC_CLASSES
            and sym.section is not None
            and sym.section.characteristics & 0x20  # IMAGE_SCN_CNT_CODE
            and not sym_name.startswith((".", "$"))
        ):
            candidates.setdefault(sym.section_idx, []).append((sym, sym_name))

    i386 = int.from_bytes(obj_data[:2], "little") == _COFF_MACHINE_I386
    # Every DIR32 field naming a defined symbol: (section, field offset) ->
    # (symbol's section, symbol's offset, the offset the field resolves to).
    dir32: dict[tuple[int, int], tuple[int, int, int]] = {}
    for section_idx, section in enumerate(coff.sections, 1) if i386 else ():
        content = bytes(section.content)
        for reloc in section.relocations:
            target = reloc.symbol
            if (
                str(reloc.type).rsplit(".", 1)[-1] == _I386_DIR32
                and target is not None
                and target.section_idx > 0
                and reloc.address + 4 <= len(content)
            ):
                field = content[reloc.address : reloc.address + 4]
                addend = int.from_bytes(field, "little", signed=True)
                dir32[section_idx, reloc.address] = (
                    target.section_idx,
                    target.value,
                    target.value + addend,
                )
    for section_idx, section_syms in candidates.items():
        section = section_syms[0][0].section
        content = bytes(section.content)
        if not i386:
            starts = {sym.value for sym, _ in section_syms}
        else:
            relocated: set[int] = set()
            for reloc in section.relocations:
                relocated.update(range(reloc.address, reloc.address + _reloc_fixup_width(reloc)))
            starts = _i386_function_starts(
                section_idx,
                content,
                [
                    (sym.value, sym.storage_class == lief.COFF.Symbol.STORAGE_CLASS.EXTERNAL)
                    for sym, _ in section_syms
                ],
                relocated,
                {
                    at: (target_section, value)
                    for (field_section, at), (target_section, value, _) in dir32.items()
                    if field_section == section_idx
                },
                {
                    field: resolved
                    for field, (target_section, _, resolved) in dir32.items()
                    if target_section == section_idx
                },
            )
        ordered = sorted(starts)
        for sym, sym_name in section_syms:
            if sym.value not in starts:
                continue
            func_start = sym.value
            idx = bisect.bisect_right(ordered, func_start)
            func_end = ordered[idx] if idx < len(ordered) else len(content)
            if func_end > len(content) or func_end - func_start < 4:
                continue
            labels = {
                other.value - func_start: name
                for other, name in section_syms
                if func_start < other.value < func_end
            }
            # Relocation byte offsets, expanded to the full fixup width.
            reloc_offsets: set[int] = set()
            self_relocations: dict[int, int] = {}
            for reloc in section.relocations:
                rva = reloc.address
                if func_start <= rva < func_end:
                    func_rel = rva - func_start
                    reloc_offsets.update(range(func_rel, func_rel + _reloc_fixup_width(reloc)))
                    target = reloc.symbol
                    if (
                        str(reloc.type).rsplit(".", 1)[-1] == _I386_DIR32
                        and target is not None
                        and target.section_idx == section_idx
                    ):
                        self_relocations[func_rel] = target.value - func_start
            yield ObjectFunction(
                sym_name, content[func_start:func_end], reloc_offsets, self_relocations, labels
            )


def parse_coff_aliases(obj_data: bytes) -> Iterator[tuple[str, str]]:
    """Yield weak SEARCH_ALIAS names and their targets, including MSVC tcmap objects."""
    import lief

    loaded = load_coff(obj_data)
    if loaded is None:
        return
    coff, symbols, names = loaded
    # Weak auxiliary records use raw symbol indices, which count other AUX records.
    by_index: dict[int, str] = {}
    index = 0
    for sym, name in zip(symbols, names, strict=True):
        by_index[index] = name
        index += 1 + len(list(sym.auxiliary_symbols))
    for sym, name in zip(symbols, names, strict=True):
        if sym.storage_class != lief.COFF.Symbol.STORAGE_CLASS.WEAK_EXTERNAL:
            continue
        for aux in sym.auxiliary_symbols:
            if (
                isinstance(aux, lief.COFF.AuxiliaryWeakExternal)
                and aux.characteristics
                == lief.COFF.AuxiliaryWeakExternal.CHARACTERISTICS.SEARCH_ALIAS
                and name
                and (target := by_index.get(aux.sym_idx))
            ):
                yield name, target


#: No relocation fixes up more than 8 bytes (the widest is a 64-bit address).
_MAX_RELOC_SPAN = 8


def _reloc_span(size_bits: int) -> int:
    """Bytes masked around an ELF relocation, from LIEF's bit-size.

    LIEF reports a garbage bit-size for some targets — observed on ppc64le
    ``libm`` objects, where the value made ``range(width)`` run for hours
    instead of microseconds.  A bogus size must not turn that loop unbounded.
    """
    span = max(int(size_bits) // 8, 1)
    return min(span, _MAX_RELOC_SPAN)


def parse_elf_obj(obj_data: bytes, *, include_local: bool = False) -> Iterator[ObjectFunction]:
    """Parse an ELF .o member (console .a archives) into :class:`ObjectFunction` rows.

    Only external (GLOBAL/WEAK) functions by default, the ones a FLIRT
    signature names; *include_local* adds file-static (LOCAL) functions, which
    are linked into a target all the same (``parse_coff_obj`` takes COFF's
    STATIC class for the same reason).

    ELF objects carry exact function sizes in the symbol table (unlike
    COFF), so each external FUNC symbol's bytes are
    ``section.content[value:value+size]`` — no next-symbol heuristic.  Fixup
    widths come from LIEF's per-type size (reliable for ELF, unlike MSVC6
    COFF).  MIPS relocations mask the whole containing 4-byte instruction
    word: the fixup target field shares the word with the opcode, and the
    object's reloc slots differ from the linked binary's.
    """
    import tempfile

    import lief

    if len(obj_data) < 20:
        return
    # shortcut: LIEF has no MOS fixup widths, add them before admitting MOS signatures.
    if int.from_bytes(obj_data[18:20], "little" if obj_data[5] == 1 else "big") == 6502:
        return

    with tempfile.TemporaryDirectory(prefix="flirt_elf_") as td:
        tmp_path = Path(td) / "temp.o"
        tmp_path.write_bytes(obj_data)
        elf = lief.ELF.parse(str(tmp_path))

    if elf is None:
        return
    if elf.header.machine_type == lief.ELF.ARCH.M68K and any(
        not 0 < int(reloc.size) <= 512 for reloc in elf.relocations
    ):
        return  # LIEF does not publish M68K relocation widths yet.

    is_mips = elf.header.machine_type in (lief.ELF.ARCH.MIPS, lief.ELF.ARCH.MIPS_X)
    is_arm = elf.header.machine_type == lief.ELF.ARCH.ARM
    bindings = {lief.ELF.Symbol.BINDING.GLOBAL, lief.ELF.Symbol.BINDING.WEAK}
    if include_local:
        bindings.add(lief.ELF.Symbol.BINDING.LOCAL)

    for sym in elf.symbols:
        if sym.type != lief.ELF.Symbol.TYPE.FUNC:
            continue
        if sym.binding not in bindings:
            continue
        section = sym.section
        if section is None or sym.size <= 0:
            continue
        if not (section.flags & 0x4):  # SHF_EXECINSTR
            continue

        content = bytes(section.content)
        func_start = int(sym.value)
        if is_arm:
            # An ARM ELF marks a Thumb function by setting bit 0 of st_value.
            # Slicing from the raw value starts one byte late, so every Thumb
            # signature came out shifted by a byte and one byte short — it
            # could never match the linked code.  Verified on devkitARM's
            # newlib `printf` (st_value 0x1): the correct bytes are
            # 0fb430b5…, the shifted ones b430b583….
            func_start &= ~1
        func_end = func_start + sym.size
        if func_start >= func_end or func_end > len(content):
            continue
        code = content[func_start:func_end]
        if len(code) < 4:
            continue

        # Only relocations whose owning section is this function's section —
        # in ET_REL, reloc addresses are section-relative, so a raw .rela.text
        # offset could collide with an .eh_frame address.
        reloc_offsets: set[int] = set()
        for reloc in elf.relocations:
            if not reloc.has_section or reloc.section is not section:
                continue
            rva = reloc.address
            if not (func_start <= rva < func_end):
                continue
            func_rel = rva - func_start
            if is_mips:
                # Mask the whole 4-byte instruction word containing the fixup.
                word_start = func_rel - (func_rel % 4)
                for k in range(word_start, min(word_start + 4, len(code))):
                    reloc_offsets.add(k)
            else:
                # 4 bytes is the instruction word on every target reached here,
                # and is the right fallback when the width is unknown.
                width = _elf_fixup_width(reloc)
                for k in range(width):
                    if func_rel + k < len(code):
                        reloc_offsets.add(func_rel + k)

        yield ObjectFunction(str(sym.name), code, reloc_offsets, {}, {})


# x86 COFF fixup widths by relocation type (bytes); LIEF reports size 0.
# Field widths follow https://learn.microsoft.com/en-us/windows/win32/debug/pe-format.
_COFF_FIXUP_WIDTHS: dict[str, int] = {
    "I386_DIR16": 2,
    "I386_REL16": 2,
    "I386_SEG12": 2,
    "I386_DIR32": 4,
    "I386_DIR32NB": 4,
    "I386_REL32": 4,
    "I386_SECREL": 4,
    "I386_SECTION": 2,  # 16-bit section index
    "I386_SECREL7": 1,  # Seven-bit section-relative offset.
    "AMD64_ADDR64": 8,
    "AMD64_ADDR32": 4,
    "AMD64_ADDR32NB": 4,
    "AMD64_REL32": 4,
    "AMD64_REL32_1": 4,
    "AMD64_REL32_2": 4,
    "AMD64_REL32_3": 4,
    "AMD64_REL32_4": 4,
    "AMD64_REL32_5": 4,
    "AMD64_SECTION": 2,
    "AMD64_SECREL": 4,
    "AMD64_SECREL7": 1,
}


#: RISC-V fixup widths by relocation type (bytes).  LIEF reports
#: ``size == -1`` (as unsigned, 2**64-1) for *every* RISC-V relocation, so the
#: size field cannot be used and every fixup was masked one byte wide — three
#: bytes of a link-time-varying immediate stayed in each pattern and nothing
#: matched a linked image (a 33,128-signature set identified 0 functions in a
#: picolibc RV64 firmware).  Branch and jump offsets live inside a 4-byte
#: instruction, so masking the whole word is the safe width; the compressed
#: ``RVC_*`` forms are 2 bytes.
_RISCV_FIXUP_WIDTHS: dict[str, int] = {
    "RISCV_32": 4,
    "RISCV_64": 8,
    "RISCV_BRANCH": 4,
    "RISCV_JAL": 4,
    "RISCV_CALL": 8,
    "RISCV_CALL_PLT": 8,
    "RISCV_GOT_HI20": 4,
    "RISCV_TLS_GOT_HI20": 4,
    "RISCV_TLS_GD_HI20": 4,
    "RISCV_PCREL_HI20": 4,
    "RISCV_PCREL_LO12_I": 4,
    "RISCV_PCREL_LO12_S": 4,
    "RISCV_HI20": 4,
    "RISCV_LO12_I": 4,
    "RISCV_LO12_S": 4,
    "RISCV_GPREL_I": 4,
    "RISCV_GPREL_S": 4,
    "RISCV_ADD8": 4,
    "RISCV_ADD16": 4,
    "RISCV_ADD32": 4,
    "RISCV_ADD64": 4,
    "RISCV_SUB8": 4,
    "RISCV_SUB16": 4,
    "RISCV_SUB32": 4,
    "RISCV_SUB64": 4,
    "RISCV_SET6": 4,
    "RISCV_SET8": 4,
    "RISCV_SET16": 4,
    "RISCV_SET32": 4,
    "RISCV_RVC_BRANCH": 2,
    "RISCV_RVC_JUMP": 2,
    "RISCV_RVC_LUI": 2,
}


def _elf_fixup_width(reloc: Any) -> int:
    """Fixup width in bytes for an ELF relocation.

    LIEF's ``size`` field is authoritative when it is sane, which it is on the
    architectures that were validated (x86-64, AArch64, ARM, MIPS).  Where LIEF
    reports no usable size — every RISC-V relocation, and every AVR one — the
    width comes from the relocation *type*, and failing that from the target's
    4-byte instruction word.
    """
    size_bits = int(getattr(reloc, "size", 0))
    if 0 < size_bits <= 8 * 64:
        return _reloc_span(size_bits)
    name = str(getattr(reloc, "type", "")).rsplit(".", 1)[-1]
    width = _RISCV_FIXUP_WIDTHS.get(name)
    if width is not None:
        return width
    return 4


def _reloc_fixup_width(reloc: Any) -> int:
    """Fixup width in bytes for a COFF relocation, derived from its type.

    Falls back to the LIEF ``size`` field (bits) when the type is unknown.
    """
    name = str(reloc.type).rsplit(".", 1)[-1]
    if name.endswith("_ABSOLUTE"):
        return 0  # COFF padding records do not modify the image.
    width = _COFF_FIXUP_WIDTHS.get(name)
    if width is not None:
        return width
    return max(int(reloc.size) // 8, 1)


def _build_crc16_table() -> list[int]:
    """Build the 256-entry lookup table for IDA's FLIRT CRC16 variant."""
    table = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
        table.append(crc & 0xFFFF)
    return table


_CRC16_TABLE = _build_crc16_table()


def _crc16_flirt(buf: bytes) -> int:
    """IDA's FLIRT CRC16 — the exact variant sigmake emits and python-flirt
    verifies (ported from flair/crc16.cpp as in lancelot's flirt crate):
    reflected poly 0x8408, init 0xFFFF, final bitwise invert, byte-swapped.

    Table-driven: one lookup per byte instead of the 8-iteration bit loop.
    """
    if not buf:
        return 0
    table = _CRC16_TABLE
    crc = 0xFFFF
    for b in buf:
        crc = (crc >> 8) ^ table[(crc ^ b) & 0xFF]
    crc = (~crc) & 0xFFFF
    return ((crc & 0xFF) << 8) | (crc >> 8)


def bytes_to_pat_line(
    name: str,
    code_bytes: bytes,
    reloc_offsets: set[int],
    max_lead: int = 32,
    labels: dict[int, str] | None = None,
) -> str:
    """Convert function name + bytes into a FLIRT .pat format line.

    Relocation bytes are masked with '..' in the leading portion; the CRC
    window covers the tail up to the first tail relocation (sigmake rule).
    Each of *labels* (:attr:`ObjectFunction.labels`) follows the name as a
    local name at its offset, ``:0064@ LeadUpVec``.
    """
    lead_len = min(len(code_bytes), max_lead)
    lead_parts: list[str] = [
        ".." if i in reloc_offsets else f"{code_bytes[i]:02X}" for i in range(lead_len)
    ]
    lead = "".join(lead_parts)

    # CRC16 of non-reloc bytes after the leading portion.  Uses IDA's exact
    # CRC variant; see _crc16_flirt.
    #
    # The window stops BEFORE the first relocation in the tail (sigmake
    # behavior): a reloc byte holds a linker-filled address in the binary, so
    # including it in the CRC would guarantee a mismatch — the matcher CRCs
    # the real bytes, and the object's reloc slot is zeroed.  Truncating the
    # window is what makes functions with tail relocs (e.g. MSVC6 isalpha,
    # which references __pctype at offset 0x20) matchable at all.
    crc_start = lead_len
    tail_relocs = sorted(r for r in reloc_offsets if r >= crc_start)
    crc_end = tail_relocs[0] if tail_relocs else len(code_bytes)
    crc_len = min(max(crc_end - crc_start, 0), len(code_bytes) - crc_start, 255)

    crc_window = bytes(code_bytes[i] for i in range(crc_start, crc_start + crc_len))
    crc = _crc16_flirt(crc_window)

    total_size = len(code_bytes)

    local = "".join(f" :{at:04X}@ {label}" for at, label in sorted((labels or {}).items()))
    return f"{lead} {crc_len:02X} {crc:04X} {total_size:04X} :0000 {name}{local}"


# IDA's guidance: a .pat signature without CRC protection needs at least 16
# non-wildcard lead bytes to be discriminative.  Below that, the sig matches
# any function sharing the same generic prolog — mass false positives.
_MIN_LITERAL_LEAD_BYTES = 16


def is_weak_signature(line: str) -> bool:
    """True when a generated .pat line is too weak to be useful.

    A line is weak when its lead has fewer than 16 literal bytes AND the CRC
    window is empty or nearly so (< 8 bytes) — nothing meaningfully protects
    the tail.  Observed in practice: one such libc sig matched 30 unrelated
    offsets in a real DLL.
    """
    parts = line.split()
    if len(parts) < 6:
        return False
    lead = parts[0]
    literal = sum(1 for i in range(0, len(lead), 2) if lead[i : i + 2] != "..")
    if literal >= _MIN_LITERAL_LEAD_BYTES:
        return False
    return int(parts[1], 16) < 8


def generate_pat(lib_file: Path, out_path: Path) -> dict[str, int | bool]:
    """Generate a FLIRT .pat file from one COFF .lib or ELF .a archive.

    Members are dispatched by their magic: ELF objects (``\\x7fELF``) go
    through :func:`parse_elf_obj` (IDO/MWCC console archives), everything
    else through :func:`parse_coff_obj` (MSVC .lib).

    Returns ``{"signatures": n, "skipped_members": n, "skipped_weak": n,
    "written": bool}``. A library with no signable code (an import library,
    or one whose members were all skipped) does not leave a ``---``-only
    ``.pat`` behind: ``rebrew doctor`` treats that file as a problem, and
    writing it again does not create signatures. An existing file at
    *out_path* is removed in that case.

    Shared by ``rebrew library signatures`` and ``rebrew library identify
    --build-sigs`` (batch over a toolchain Lib dir).
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)

    pat_lines: list[str] = []
    # Dedupe on the generated *line*, not on the symbol name: an archive that
    # ships several members defining the same symbol (picolibc's
    # `nano-malloc.c.o` next to its full allocator, newlib's C and assembly
    # `memcpy`, several console SDK libraries) contributes one pattern per
    # implementation, and the linker may pick any of them.  Keying on the name
    # kept only whichever member came first and silently threw the rest away —
    # measured on a picolibc RV32IMAC firmware, where the surviving `malloc`
    # pattern described a 580-byte function while the linked one was 158 bytes.
    seen: set[str] = set()

    skipped = 0
    weak_skipped = 0
    for member_name, obj_data in parse_archive(str(lib_file)):
        if obj_data.startswith(b"\x7fELF"):
            obj_iter = parse_elf_obj(obj_data)
        else:
            obj_iter = parse_coff_obj(obj_data)
        try:
            for function in obj_iter:
                sym_name, code, relocs = function.name, function.code, function.relocations
                if not sym_name.strip():
                    # A .pat line's trailing field is the symbol name; a
                    # nameless line is malformed and poisons the whole file
                    # for signature parsers (symptom: "corrupt .pat").
                    skipped += 1
                    continue
                if len(code) >= 4:
                    line = bytes_to_pat_line(sym_name, code, relocs, labels=function.labels)
                    if line in seen:
                        continue
                    seen.add(line)
                    if is_weak_signature(line):
                        # Generic-prolog-only sigs would false-positive across
                        # the whole binary — drop them rather than emit noise.
                        weak_skipped += 1
                        continue
                    pat_lines.append(line)
        except OSError, KeyError, ValueError, struct.error:
            # The member contributed nothing and the .pat is written without
            # it, so name it: a signature that silently went missing reads as
            # a library that exports nothing.
            skipped += 1
            logger.warning("skipped unparsable archive member %s", member_name, exc_info=True)

    if pat_lines:
        atomic_write_text(
            out_path, "".join(line + "\n" for line in pat_lines) + "---\n", encoding="utf-8"
        )
    elif out_path.exists():
        out_path.unlink()
    return {
        "signatures": len(pat_lines),
        "skipped_members": skipped,
        "skipped_weak": weak_skipped,
        "written": bool(pat_lines),
    }


@app.callback(invoke_without_command=True)
def main(
    lib_path: str = typer.Argument(..., help="Path to .lib file"),
    output: str | None = typer.Option(
        None, "--output", "-o", help="Output .pat file path", metavar="<path>"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Generate FLIRT .pat files from COFF .lib and ELF .a archives."""
    lib_file = Path(lib_path)
    if not lib_file.exists():
        error_exit(f"{lib_file} not found", json_mode=json_output)

    lib_name = fold_ident(lib_file.stem)
    out_path = Path(output) if output else Path(f"flirt_sigs/{lib_name}.pat")

    stats = generate_pat(lib_file, out_path)
    skipped = stats["skipped_members"]
    weak_skipped = stats["skipped_weak"]
    if json_output:
        json_print(
            {
                "output": str(out_path),
                "signatures": stats["signatures"],
                "written": stats["written"],
                "source": str(lib_file),
                "skipped_members": skipped,
                "skipped_weak": weak_skipped,
            }
        )
        return

    if stats["signatures"] == 0:
        msg = f"{lib_file}: 0 signatures, no pattern file written"
    else:
        msg = f"Generated {out_path}: {stats['signatures']} signatures from {lib_file}"
    if skipped:
        msg += f" ({skipped} corrupt members skipped)"
    if weak_skipped:
        msg += f" ({weak_skipped} weak signatures skipped)"
    console.print(msg)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
