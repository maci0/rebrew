"""Shared binary-analysis primitives for recon and visualization tools.

Architecture notes:

- Every helper takes a ``BinaryInfo`` (from ``rebrew.binary_loader``) so the
  caller controls when the binary is parsed — the "lazy LIEF" pattern.  Parse
  once, reuse across tools.
- ``scan_references`` walks the code sections once with capstone and classifies
  every absolute reference: direct calls/jumps, IAT calls/jumps (``call
  [slot]`` / ``jmp [slot]``), ``push imm32``, ``mov reg, imm32``, ``lea`` /
  ``mov`` with an absolute memory operand, and a generic fallback for any
  absolute memory operand (no base/index register), e.g. ``and [abs], 0``.
- ``iter_strings`` extracts printable ASCII / UTF-16LE runs from data
  sections.  ``.text`` is skipped by default (embedded immediates are noise);
  pass ``section_names`` explicitly to scan it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rebrew.binary_loader import BinaryInfo

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class Xref:
    """A reference from one address to another inside the binary.

    ``kind`` is one of:
    - ``call`` / ``jmp``      — direct relative call/jump
    - ``iat_call`` / ``iat_jmp`` — ``call [slot]`` / ``jmp [slot]`` (IAT)
    - ``push``                — ``push imm32`` (string/address load)
    - ``mov``                 — ``mov reg, imm32`` (address load)
    - ``lea``                 — ``lea reg, [abs]``
    - ``mov_mem``             — ``mov reg, [abs]`` (data read)
    - ``mov_mem_store``       — ``mov [abs], reg`` (data write)
    - otherwise               — mnemonic + ``_mem`` (e.g. ``and_mem``)
    """

    kind: str
    from_va: int
    to_va: int


@dataclass
class Insn:
    """A decoded instruction, kept in a format-agnostic shape."""

    va: int
    size: int
    mnemonic: str
    op_str: str
    raw: bytes


@dataclass
class StringEntry:
    """A printable string run in a data section."""

    va: int
    size: int  # bytes on disk (includes terminator for ascii)
    text: str  # decoded text (without terminator)
    kind: str  # "ascii" | "utf16"
    section: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _capstone(skipdata: bool = False) -> Any:
    """Return a capstone ``Cs`` disassembler for the default x86-32 target.

    With *skipdata* set, undecodable bytes are emitted as ``.byte`` pseudo
    instructions instead of terminating the linear scan — required for real
    binaries whose ``.text`` contains embedded data (jump tables, alignment).
    """
    try:
        from capstone import CS_ARCH_X86, CS_MODE_32, Cs
    except ImportError as exc:
        raise RuntimeError("capstone not installed") from exc
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    if skipdata:
        md.skipdata = True
        md.skipdata_setup = ("db", None, None)
    return md


def _op_constants() -> tuple[Any, Any, Any]:
    """Return ``(CS_OP_REG, CS_OP_IMM, CS_OP_MEM)`` from capstone."""
    try:
        from capstone import CS_OP_IMM, CS_OP_MEM, CS_OP_REG
    except ImportError as exc:
        raise RuntimeError("capstone not installed") from exc
    return CS_OP_REG, CS_OP_IMM, CS_OP_MEM


def iter_instructions(
    info: BinaryInfo, va: int, size: int, section_names: list[str] | None = None
) -> list[Insn]:
    """Disassemble *size* bytes at *va*, returning ``Insn`` records.

    Disassembly stops at the first invalid byte (capstone ``stop`` callback
    semantics).  *section_names* is accepted for API symmetry but unused — the
    caller already restricts *va*/*size* to the section it wants.
    """
    raw = extract_bytes(info, va, size)
    md = _capstone(skipdata=True)
    out: list[Insn] = []
    for insn in md.disasm(raw, va):
        out.append(
            Insn(
                va=insn.address,
                size=insn.size,
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
                raw=raw[insn.address - va : insn.address - va + insn.size],
            )
        )
    return out


def extract_bytes(info: BinaryInfo, va: int, size: int) -> bytes:
    """Return *size* file bytes at virtual address *va* (clamped to the file)."""
    data = info.data
    offset = va_to_file_offset(info, va)
    return data[offset : offset + size]


def va_to_file_offset(info: BinaryInfo, va: int) -> int:
    """Translate *va* to a file offset using section bounds, else a raw guess."""
    for section in info.sections.values():
        if section.va <= va < section.va + section.size:
            return section.file_offset + (va - section.va)
    return va - info.image_base


def section_range(info: BinaryInfo, name: str) -> tuple[int, int] | None:
    """Return ``(start_va, size)`` for the named section, or None."""
    section = info.sections.get(name)
    if section is None:
        return None
    return section.va, section.size


def is_inside(info: BinaryInfo, va: int) -> bool:
    """Whether *va* falls inside any mapped section of the binary."""
    return any(section.va <= va < section.va + section.size for section in info.sections.values())


# ---------------------------------------------------------------------------
# Cross-references
# ---------------------------------------------------------------------------


def _mem_absolute(mem: Any) -> int | None:
    """Return the absolute address for a capstone memory operand, or None.

    Only mod=00/rm=101-style operands (base and index absent) are absolute
    addresses; register-relative offsets (``[esi+0xd]``) are not.
    """
    if mem is None:
        return None
    if mem.base != 0 or mem.index != 0:
        return None
    disp = mem.disp
    return int(disp) if disp is not None else None


def scan_references(
    info: BinaryInfo,
    target_va: int | None = None,
    section_names: list[str] | None = None,
) -> list[Xref]:
    """Scan code sections for absolute references.

    With *target_va* set, only references pointing at that address are kept.
    Without it, every absolute reference found is returned (in address order).
    The scan covers *section_names* (default ``[".text"]``).
    """
    names = section_names if section_names is not None else [".text"]
    md = _capstone(skipdata=True)
    xrefs: list[Xref] = []
    for name in names:
        rng = section_range(info, name)
        if rng is None:
            continue
        va, size = rng
        raw = extract_bytes(info, va, size)
        for insn in md.disasm(raw, va):
            if insn.mnemonic == "db":  # skipdata placeholder
                continue
            ref = _classify_insn(info, insn)
            if ref is None:
                continue
            kind, from_va, to_va = ref
            if target_va is not None and to_va != target_va:
                continue
            if not is_inside(info, to_va):
                continue
            xrefs.append(Xref(kind=kind, from_va=from_va, to_va=to_va))
    xrefs.sort(key=lambda x: (x.from_va, x.to_va))
    return xrefs


def _classify_insn(info: BinaryInfo, insn: Any) -> tuple[str, int, int] | None:
    """Classify one capstone instruction into ``(kind, from_va, to_va)``."""
    from_va = insn.address
    ops = insn.operands
    if not ops:
        return None
    mnemonic = insn.mnemonic
    op_reg, op_imm, op_mem = _op_constants()

    if mnemonic in ("call", "jmp"):
        op = ops[0]
        if op.type == op_imm:
            return mnemonic, from_va, op.imm
        if op.type == op_mem:
            addr = _mem_absolute(op.mem)
            if addr is not None:
                return f"iat_{mnemonic}", from_va, addr
        return None

    if mnemonic == "push":
        op = ops[0]
        if op.type == op_imm:
            return "push", from_va, op.imm
        if op.type == op_mem:  # push [abs] — reads a global
            addr = _mem_absolute(op.mem)
            if addr is not None:
                return "push_mem", from_va, addr
        return None

    if mnemonic == "lea":
        if len(ops) >= 2 and ops[1].type == op_mem:
            addr = _mem_absolute(ops[1].mem)
            if addr is not None:
                return "lea", from_va, addr
        return None

    if mnemonic == "mov":
        if len(ops) < 2:
            return None
        a, b = ops[0], ops[1]
        if a.type == op_reg and b.type == op_imm:  # mov reg, imm32
            return "mov", from_va, b.imm
        if a.type == op_reg and b.type == op_mem:  # mov reg, [abs] — data read
            addr = _mem_absolute(b.mem)
            if addr is not None:
                return "mov_mem", from_va, addr
        if a.type == op_mem and b.type == op_reg:  # mov [abs], reg — data write
            addr = _mem_absolute(a.mem)
            if addr is not None:
                return "mov_mem_store", from_va, addr
        return None

    # Generic absolute memory operand (and/or/cmp/test/inc/... [abs]).
    for op in ops:
        if op.type == op_mem:
            addr = _mem_absolute(op.mem)
            if addr is not None:
                return f"{mnemonic}_mem", from_va, addr
    return None


# ---------------------------------------------------------------------------
# Strings
# ---------------------------------------------------------------------------

_PRINTABLE = set(range(0x20, 0x7F))
_UTF16_PRINTABLE = set(range(0x20, 0x7F))


def iter_strings(
    info: BinaryInfo,
    min_len: int = 4,
    section_names: list[str] | None = None,
) -> list[StringEntry]:
    """Extract printable ASCII and UTF-16LE runs from data sections.

    *section_names* defaults to the data-ish sections (``.rdata``, ``.data``,
    ``.rodata``); pass an explicit list to include ``.text``.
    """
    default = [n for n in (".rdata", ".data", ".rodata") if n in info.sections]
    names = section_names if section_names is not None else default
    strings: list[StringEntry] = []
    for name in names:
        rng = section_range(info, name)
        if rng is None:
            continue
        va, size = rng
        raw = extract_bytes(info, va, size)
        strings.extend(_scan_ascii(raw, va, name, min_len))
        strings.extend(_scan_utf16(raw, va, name, min_len))
    strings.sort(key=lambda s: s.va)
    return strings


def _scan_ascii(raw: bytes, va: int, section: str, min_len: int) -> list[StringEntry]:
    out: list[StringEntry] = []
    start = -1
    for i, byte in enumerate(raw):
        if byte in _PRINTABLE:
            if start < 0:
                start = i
        else:
            if start >= 0 and i - start >= min_len:
                text = raw[start:i].decode("ascii")
                out.append(
                    StringEntry(
                        va=va + start,
                        size=i - start,
                        text=text,
                        kind="ascii",
                        section=section,
                    )
                )
            start = -1
    if start >= 0 and len(raw) - start >= min_len:
        text = raw[start:].decode("ascii")
        out.append(
            StringEntry(
                va=va + start, size=len(raw) - start, text=text, kind="ascii", section=section
            )
        )
    return out


def _scan_utf16(raw: bytes, va: int, section: str, min_len: int) -> list[StringEntry]:
    out: list[StringEntry] = []
    start = -1
    i = 0
    while i + 1 < len(raw):
        lo, hi = raw[i], raw[i + 1]
        if hi == 0 and lo in _UTF16_PRINTABLE:
            if start < 0:
                start = i
        else:
            if start >= 0 and (i - start) // 2 >= min_len:
                text = raw[start:i:2].decode("ascii")
                out.append(
                    StringEntry(
                        va=va + start,
                        size=i - start,
                        text=text,
                        kind="utf16",
                        section=section,
                    )
                )
            start = -1
        i += 2
    if start >= 0 and (len(raw) - start) // 2 >= min_len:
        text = raw[start::2].decode("ascii")
        out.append(
            StringEntry(
                va=va + start, size=len(raw) - start, text=text, kind="utf16", section=section
            )
        )
    return out


def string_refs(info: BinaryInfo, strings: list[StringEntry]) -> dict[int, list[Xref]]:
    """Map string VA -> references, using *strings* as the target set."""
    targets = {s.va for s in strings}
    refs: dict[int, list[Xref]] = {}
    for xref in scan_references(info):
        if xref.to_va in targets:
            refs.setdefault(xref.to_va, []).append(xref)
    for key in refs:
        refs[key].sort(key=lambda x: x.from_va)
    return refs
