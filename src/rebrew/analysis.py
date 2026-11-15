"""Shared binary-analysis primitives for recon and visualization tools.

Architecture notes:

- Every helper takes a ``BinaryInfo`` (from ``rebrew.formats.binary_model``) so the
  caller controls when the binary is parsed — the "lazy LIEF" pattern.  Parse
  once, reuse across tools.
- ``scan_references`` walks the code sections once with capstone and classifies
  every absolute reference: direct calls/jumps, IAT calls/jumps (``call
  [slot]`` / ``jmp [slot]``), ``push imm32``, ``mov reg, imm32``, ``cmp``
  against an address-valued immediate, ``lea`` /
  ``mov`` with an absolute memory operand, and a generic fallback for any
  absolute memory operand (no base/index register), e.g. ``and [abs], 0``.
  On an x86-32 PE it also reports ``call reg`` / ``jmp reg`` as an IAT
  call/jump when every path to it loads that register from one import slot
  (:class:`_RegisterImportCalls`).
- ``iter_strings`` extracts printable ASCII / UTF-16LE runs from data
  sections.  ``.text`` is skipped by default (embedded immediates are noise);
  pass ``section_names`` explicitly to scan it.
- ``disasm_insns`` / ``normalized_operands`` disassemble raw byte buffers
  (compiled objects, extracted target bytes) without a ``BinaryInfo``; the
  diff, clone, and climb tools share them.
"""

from __future__ import annotations

import re
import threading
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Protocol
lazy from array import array
lazy from collections.abc import Iterator

lazy import capstone

lazy from rebrew.errors import RebrewError
lazy from rebrew.formats.binary_loader import (
    capstone_config_for,
    iat_slot_vas,
    section_extent,
    va_to_file_offset,
)
lazy from rebrew.formats.binary_model import BinaryInfo


class CapstoneUnavailable(RebrewError, RuntimeError):
    """The optional ``capstone`` disassembler is not installed."""


DEFAULT_CS_ARCH = "CS_ARCH_X86"
DEFAULT_CS_MODE = "CS_MODE_32"

# x86 register names collapsed to ``R`` when comparing operands: GPRs,
# r8–r15, vector regs, MMX, and the x87 stack. ``st(i)`` ends on ``)``, so
# the bounds are "not a word char" rather than ``\b`` (there is no word
# boundary between ``)`` and a following comma).
_REGISTER_RE = re.compile(
    r"(?<!\w)(?:"
    r"r(?:ax|bx|cx|dx|si|di|bp|sp)|"
    r"r(?:8|9|1[0-5])(?:d|w|b)?|"
    r"[xyz]mm\d+|"
    r"mm\d+|"
    r"eax|ebx|ecx|edx|esi|edi|ebp|esp|"
    r"ax|bx|cx|dx|si|di|bp|sp|"
    r"al|bl|cl|dl|ah|bh|ch|dh|sil|dil|spl|bpl|"
    r"st\(\d+\)"
    r")(?!\w)",
)

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class Xref:
    """A reference from one address to another inside the binary.

    ``kind`` is one of:
    - ``call`` / ``jmp``      — direct relative call/jump
    - ``iat_call`` / ``iat_jmp`` — ``call [slot]`` / ``jmp [slot]`` (IAT), or
      ``call reg`` / ``jmp reg`` with the register loaded from import slot
      ``to_va`` on every path (:func:`scan_references` on an x86-32 PE)
    - ``push``                — ``push imm32`` (string/address load)
    - ``push_mem``            — ``push [abs]`` (global read)
    - ``mov``                 — ``mov reg/[mem], imm32`` (address load/store)
    - ``cmp``                 — ``cmp reg/[mem], imm`` (possible pointer comparison)
    - ``lea``                 — ``lea reg, [abs]``
    - ``mov_mem``             — ``mov reg, [abs]`` (data read)
    - ``mov_mem_store``       — ``mov [abs], reg/imm`` (data write)
    - ``indexed_mem``         — indexed memory displacement (opt-in base candidate,
      not a resolved effective address or IAT call)
    - otherwise               — mnemonic + ``_mem`` (e.g. ``and_mem``)

    :func:`is_xref_kind` tells whether a reference can have a given kind.
    """

    kind: str
    from_va: int
    to_va: int


#: The fixed :attr:`Xref.kind` values; every other kind is a mnemonic plus ``_mem``.
XREF_KINDS = frozenset(
    {
        "call",
        "jmp",
        "iat_call",
        "iat_jmp",
        "push",
        "push_mem",
        "mov",
        "cmp",
        "lea",
        "mov_mem",
        "mov_mem_store",
        "indexed_mem",
    }
)

#: A capstone mnemonic (lowercase, with a prefix such as ``rep`` after a space)
#: plus ``_mem``.
_MEM_XREF_KIND = re.compile(r"[a-z][a-z0-9. ]*_mem")


def is_xref_kind(kind: str) -> bool:
    """Whether some :class:`Xref` can have *kind*."""
    return kind in XREF_KINDS or _MEM_XREF_KIND.fullmatch(kind) is not None


@dataclass
class Insn:
    """A decoded instruction, kept in a format-agnostic shape."""

    va: int
    size: int
    mnemonic: str
    op_str: str
    raw: bytes


def instruction_text(insn: Insn) -> str:
    """One decoded instruction as ``"mnemonic operands"`` text."""
    return f"{insn.mnemonic} {insn.op_str}".strip()


@dataclass
class StringEntry:
    """A printable string run in a data section."""

    va: int
    size: int  # bytes on disk (no NUL terminator; pascal includes its length prefix)
    text: str  # decoded text (without terminator)
    kind: str  # "ascii" | "utf16" | "pascal" (16-bit NE length-prefixed)
    section: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# Capstone ``Cs`` objects wrap a libcapstone handle mutated on every
# ``disasm`` call, so one instance cannot be shared across threads.
# ``iter_instructions`` runs per function over whole code sections; a
# per-thread cache elides repeated constructor calls without handle races.
_capstone_tls = threading.local()


def capstone_for(info: BinaryInfo | None = None) -> Any:
    """Return a capstone ``Cs`` disassembler.

    Defaults to x86-32.  A ``BinaryInfo`` selects the arch, the x86 bitness
    (NE/MZ → 16-bit), and the image endianness through
    :func:`rebrew.formats.binary_loader.capstone_config_for`.  Undecodable bytes are
    emitted as ``.byte`` pseudo instructions instead of terminating the
    linear scan — required for real binaries whose code contains embedded data.

    Instances are cached per thread keyed on (arch, mode).
    """
    try:
        from capstone import CS_ARCH_X86, CS_MODE_32, Cs
    except ImportError as exc:
        raise CapstoneUnavailable("capstone not installed") from exc

    if info is None:
        cs_arch, mode = CS_ARCH_X86, CS_MODE_32
    else:
        cs_arch, mode = capstone_config_for(info)
    cache = getattr(_capstone_tls, "cache", None)
    if cache is None:
        cache = {}
        _capstone_tls.cache = cache
    key = (cs_arch, mode)
    md = cache.get(key)
    if md is None:
        md = Cs(cs_arch, mode)
        md.detail = True
        md.skipdata = True
        md.skipdata_setup = ("db", None, None)
        cache[key] = md
    return md


_cs_handle_tls = threading.local()


def capstone_handle(
    cs_arch: int, cs_mode: int, *, detail: bool = False, skipdata: bool = False
) -> Any:
    """A cached capstone handle for an explicit ``(cs_arch, cs_mode)``.

    ``detail`` off is the hot path: mnemonics, operands and bytes only, no
    operand/detail decoding.  ``skipdata`` keeps an undecodable byte as a
    ``.byte`` pseudo-instruction instead of ending the scan; it is part of
    the key because it is a property of the handle, not of one ``disasm``
    call, and a caller that flips it on a shared handle changes every other
    caller reusing that entry.  Cached per thread for the same reason
    :func:`capstone_for` is: a ``Cs`` mutates its libcapstone handle on every
    ``disasm``, so one instance cannot be shared across threads.
    """
    from capstone import Cs

    cache = getattr(_cs_handle_tls, "cache", None)
    if cache is None:
        cache = {}
        _cs_handle_tls.cache = cache
    key = (cs_arch, cs_mode, detail, skipdata)
    md = cache.get(key)
    if md is None:
        md = Cs(cs_arch, cs_mode)
        md.detail = detail
        md.skipdata = skipdata
        cache[key] = md
    return md


def resolve_capstone(value: str | int) -> int:
    """Resolve a capstone constant-name string ("CS_MODE_32") or int to an int."""
    if isinstance(value, int):
        return value
    try:
        return int(getattr(capstone, value))
    except AttributeError, TypeError:
        # A numeric string ("3" or "0x3") is a valid capstone constant.
        from rebrew.utils import parse_int_literal

        return parse_int_literal(value)


def disasm_insns(
    code: bytes,
    va: int,
    cs_arch: str | int = DEFAULT_CS_ARCH,
    cs_mode: str | int = DEFAULT_CS_MODE,
) -> list[Insn]:
    """Disassemble *code* into :class:`Insn` records.

    *cs_arch*/*cs_mode* accept capstone constant-name strings (the module
    defaults), the int constants that ``cfg.capstone_arch``/``cfg.capstone_mode``
    return, or a bare numeric string ("3") — both config styles must work.
    """
    md = capstone_handle(resolve_capstone(cs_arch), resolve_capstone(cs_mode))
    return [
        Insn(va=i.address, size=i.size, mnemonic=i.mnemonic, op_str=i.op_str, raw=bytes(i.bytes))
        for i in md.disasm(code, va)
    ]


class _OperandCarrier(Protocol):
    """Anything with an operand string: the diff path's ``Insn`` or a view over one."""

    op_str: str


def normalized_operands(insn: _OperandCarrier) -> str:
    """Operand string with register names stripped — detects register-alloc churn.

    ``mov eax, ebx`` vs ``mov ecx, edx`` both normalise to ``mov R, R``.

    Takes anything with an ``op_str`` (not just ``Insn``) because the codegen
    comparison surfaces share it: ``instruction_clones`` wraps a bare operand
    string in a namespace and masks immediates on top, and any future
    instruction-level matcher should normalise registers the same way rather
    than growing a second rule.
    """
    return _REGISTER_RE.sub("R", insn.op_str)


#: Direct calls whose target operand is an immediate address.  x86 uses
#: ``call``.  ARM, AArch64, and PPC use ``bl``/``blx``; MIPS uses ``jal``;
#: SH uses ``bsr``.  A register-indirect form (``jalr $t9``, ``blx lr``)
#: has no ``0x`` immediate, so :func:`direct_call_target` drops it.
DIRECT_CALL_MNEMONICS = frozenset(
    {"call", "jal", "jalrc", "bl", "blx", "bsr", "jsr", "bcl", "bctrl"}
)

#: Unconditional branches with an immediate address.  Conditional branches
#: (``je``, ``beq``) stay out: an x86 ``jmp`` is the only jump the reference
#: scan already recorded, and a conditional is not that edge.
DIRECT_JUMP_MNEMONICS = frozenset({"jmp", "b", "j", "bra"})


def _immediate_address(op_str: str) -> int | None:
    """Absolute address printed as ``0xNNNN`` or ``#0xNNNN``, or None."""
    op = op_str.strip()
    if op.startswith("#"):
        op = op[1:].strip()
    token = op.split(",", 1)[0].strip()
    if not token.startswith("0x"):
        return None
    try:
        return int(token, 16)
    except ValueError:
        return None


def direct_call_target(mnemonic: str, op_str: str) -> int | None:
    """Immediate target of a direct call, or None for anything else.

    ARM and AArch64 print the target as ``#0xNNNN``.  x86, MIPS, PPC, and
    SH print ``0xNNNN``.  A comma-separated operand is not an immediate
    address.
    """
    if mnemonic not in DIRECT_CALL_MNEMONICS:
        return None
    return _immediate_address(op_str)


def direct_jump_target(mnemonic: str, op_str: str) -> int | None:
    """Immediate target of an unconditional branch, or None."""
    if mnemonic not in DIRECT_JUMP_MNEMONICS:
        return None
    return _immediate_address(op_str)


_OP_CONSTANTS: tuple[Any, Any, Any] | None = None
_OP_CONSTANTS_LOCK = threading.Lock()


def _op_constants() -> tuple[Any, Any, Any]:
    """Return ``(CS_OP_REG, CS_OP_IMM, CS_OP_MEM)`` from capstone (cached).

    ``_classify_insn`` runs per disassembled instruction over whole code
    sections, so the import machinery must not run per call."""
    global _OP_CONSTANTS
    if _OP_CONSTANTS is not None:
        return _OP_CONSTANTS
    with _OP_CONSTANTS_LOCK:
        if _OP_CONSTANTS is None:
            try:
                from capstone import CS_OP_IMM, CS_OP_MEM, CS_OP_REG
            except ImportError as exc:
                raise CapstoneUnavailable("capstone not installed") from exc
            _OP_CONSTANTS = (CS_OP_REG, CS_OP_IMM, CS_OP_MEM)
        return _OP_CONSTANTS


def iter_instruction_stream(info: BinaryInfo, va: int, size: int) -> Iterator[Insn]:
    """Yield ``Insn`` records for *size* bytes at *va*, one at a time.

    Same scan as :func:`iter_instructions`, as a generator: a caller that only
    wants a few addresses out of a whole code section can stop early instead of
    paying for the full section's list.  Undecodable bytes are emitted as
    ``.byte`` rather than ending the scan.
    """
    if size <= 0:
        return
    raw = extract_bytes(info, va, size)
    md = capstone_for(info)
    for insn in md.disasm(raw, va):
        yield Insn(
            va=insn.address,
            size=insn.size,
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
            raw=raw[insn.address - va : insn.address - va + insn.size],
        )


def iter_instructions(info: BinaryInfo, va: int, size: int) -> list[Insn]:
    """Disassemble *size* bytes at *va*, returning ``Insn`` records.

    Undecodable bytes are emitted as ``.byte`` rather than ending the scan.
    """
    return list(iter_instruction_stream(info, va, size))


def extract_bytes(info: BinaryInfo, va: int, size: int) -> bytes:
    """Return *size* file bytes at virtual address *va*.

    Clamped to the containing section's file-backed span (``raw_size``) and to
    the file length: a section whose virtual size exceeds its raw size (an NE
    iterated segment with ``raw_size == 0``, a PE BSS-like tail) has no file
    bytes there, and returning the neighbouring data would fabricate content.
    """
    if size <= 0:
        return b""
    data = info.data
    offset = va_to_file_offset(info, va)
    if offset < 0 or offset >= len(data):
        return b""
    avail = len(data) - offset
    for section in info.sections.values():
        # Same containment rule as va_to_file_offset: a section with virtual
        # size 0 maps its raw size, and must still clamp to it.
        if section.va <= va < section.va + section_extent(section):
            avail = max(0, section.raw_size - (va - section.va))
            break
    return data[offset : offset + min(size, avail)]


def section_range(info: BinaryInfo, name: str) -> tuple[int, int] | None:
    """Return ``(start_va, size)`` for the named section, or None."""
    section = info.sections.get(name)
    if section is None:
        return None
    return section.va, section.size


def _merged_ranges(info: BinaryInfo) -> tuple[list[int], list[int]]:
    """Sorted, merged ``(starts, ends)`` for every mapped section.

    Built once per scan and shared by the hot loops below: the previous
    per-reference ``any(...)`` over ``sections.values()`` cost O(sections)
    per candidate, so a whole-.text scan paid O(instructions × sections).
    """
    spans = sorted(
        (section.va, section.va + section.size)
        for section in info.sections.values()
        if section.size > 0
    )
    starts: list[int] = []
    ends: list[int] = []
    for start, end in spans:
        if starts and start <= ends[-1]:
            ends[-1] = max(ends[-1], end)
        else:
            starts.append(start)
            ends.append(end)
    return starts, ends


def _inside_ranges(starts: list[int], ends: list[int], va: int) -> bool:
    """Whether *va* falls in the merged ranges (binary search)."""
    if va < 0:
        return False
    index = bisect_right(starts, va) - 1
    return index >= 0 and va < ends[index]


def is_inside(info: BinaryInfo, va: int) -> bool:
    """Whether *va* falls inside any mapped section of the binary."""
    if va < 0:
        return False
    return any(section.va <= va < section.va + section.size for section in info.sections.values())


# ---------------------------------------------------------------------------
# Cross-references
# ---------------------------------------------------------------------------


def _mem_absolute(mem: Any, insn: Any = None) -> int | None:
    """Return the absolute address for a capstone memory operand, or None.

    Only mod=00/rm=101-style operands (base and index absent) are absolute
    addresses; register-relative offsets (``[esi+0xd]``) are not.  On x86-64 a
    RIP-relative operand (``[rip+disp]``) is absolute too: its target is
    ``insn.address + insn.size + disp``, so *insn* is required for that form.
    """
    if mem is None or not hasattr(mem, "base"):
        # SH (and any non-x86 mem operand) has no ``base``/``index``.  Reading
        # them raised AttributeError and aborted the whole reference scan.
        return None
    if mem.base != 0 or mem.index != 0:
        if insn is not None and mem.index == 0:
            from capstone.x86 import X86_REG_RIP

            if mem.base == X86_REG_RIP:
                return int(insn.address) + int(insn.size) + int(mem.disp or 0)
        return None
    disp = mem.disp
    return int(disp) if disp is not None else None


def scan_references(
    info: BinaryInfo,
    target_va: int | None = None,
    section_names: list[str] | None = None,
    *,
    include_indexed: bool = False,
) -> list[Xref]:
    """Scan code sections for absolute references.

    With *target_va* set, only references pointing at that address are kept.
    Without it, every absolute reference found is returned (in address order).
    The scan covers *section_names* (default: the NE code segments for NE
    binaries, else ``[".text"]``).
    *include_indexed* also reports x86 no-base indexed displacements as
    ``indexed_mem`` candidates; their effective address remains unknown.
    On an x86-32 PE, a ``call reg`` / ``jmp reg`` whose register holds one
    import slot's pointer on every path is an ``iat_call`` / ``iat_jmp`` to
    that slot (:class:`_RegisterImportCalls` names the rule and its limits).
    """
    names = section_names if section_names is not None else _default_scan_sections(info)
    md = capstone_for(info)
    starts, ends = _merged_ranges(info)
    slots: frozenset[int] = frozenset()
    if info.format == "pe" and info.arch == "x86_32":
        slots = iat_slot_vas(info.path)
    xrefs: list[Xref] = []
    for name in names:
        rng = section_range(info, name)
        if rng is None:
            continue
        va, size = rng
        raw = extract_bytes(info, va, size)
        # NE code segments carry a 2-byte Borland index marker before the
        # instruction stream — skipping it keeps the disasm aligned.
        start = 2 if info.format == "ne" else 0
        held = _RegisterImportCalls(md, raw, va, slots, starts, ends) if slots else None
        for insn in md.disasm(raw[start:], va + start):
            mnemonic = insn.mnemonic
            refs = (
                ()
                if mnemonic == "db"  # skipdata placeholder
                else _classify_insn(info, insn, include_indexed=include_indexed)
            )
            if held is not None:
                held.observe(insn, mnemonic, refs)
            for kind, from_va, to_va in refs:
                if target_va is not None and to_va != target_va:
                    continue
                if _inside_ranges(starts, ends, to_va):
                    xrefs.append(Xref(kind=kind, from_va=from_va, to_va=to_va))
        if held is not None:
            xrefs.extend(
                Xref(kind=kind, from_va=from_va, to_va=to_va)
                for kind, from_va, to_va in held.references(info)
                if target_va is None or to_va == target_va
            )
    xrefs.sort(key=lambda x: (x.from_va, x.to_va))
    return xrefs


def data_references(
    info: BinaryInfo, va: int, size: int, *, include_indexed: bool = False
) -> list[Xref]:
    """Absolute references from the instructions at *va*, per function.

    :func:`scan_references` sweeps whole code sections linearly; this is its
    per-function counterpart.  Only the function's own bytes are decoded, so
    filler between functions (a jump table, a data blob) cannot desynchronize
    the stream and swallow the references of everything after it.  ``to_va``
    may land in any section; the caller filters by target.
    *include_indexed* adds displacement-base candidates, as in ``scan_references``.
    """
    if size <= 0:
        return []
    raw = extract_bytes(info, va, size)
    if not raw:
        return []
    md = capstone_for(info)
    # NE code segments carry a 2-byte Borland index marker before the
    # instruction stream, the same offset scan_references skips.
    start = 2 if info.format == "ne" and len(raw) > 2 else 0
    starts, ends = _merged_ranges(info)
    out: list[Xref] = []
    for insn in md.disasm(raw[start:], va + start):
        if insn.mnemonic == "db":  # skipdata placeholder
            continue
        for kind, from_va, to_va in _classify_insn(info, insn, include_indexed=include_indexed):
            if _inside_ranges(starts, ends, to_va):
                out.append(Xref(kind=kind, from_va=from_va, to_va=to_va))
    return out


def reachable_code(
    info: BinaryInfo, va: int, size: int, *, include_indexed: bool = False
) -> tuple[list[Insn], list[Xref]]:
    """Decode reachable x86 instructions inside an independently established body.

    Direct internal branches are followed; calls, external tail jumps and
    indirect dispatch targets are not. Tables and padding skipped by control
    flow are never decoded. This does not discover or extend a function body.
    *include_indexed* adds displacement-base candidates, as in ``scan_references``.
    """
    if info.arch not in {"x86_32", "x86_64"}:
        raise ValueError("reachable code decoding requires x86_32 or x86_64")
    raw = extract_bytes(info, va, size)
    end = va + len(raw)
    pending = [va]
    decoded: dict[int, Insn] = {}
    covered: set[int] = set()
    refs: list[Xref] = []
    md = capstone_for(info)
    starts, ends = _merged_ranges(info)
    _, op_imm, _ = _op_constants()
    while pending:
        pc = pending.pop()
        if pc in decoded or not va <= pc < end:
            continue
        if pc in covered:
            raise ValueError(f"branch target 0x{pc:x} overlaps an instruction")
        insn = next(md.disasm(raw[pc - va :], pc, count=1), None)
        if insn is None or insn.mnemonic == "db":
            raise ValueError(f"cannot decode reachable instruction at 0x{pc:x}")
        occupied = set(range(pc, pc + insn.size))
        if occupied & covered:
            raise ValueError(f"instruction at 0x{pc:x} overlaps another instruction")
        covered.update(occupied)
        decoded[pc] = Insn(pc, insn.size, insn.mnemonic, insn.op_str, bytes(insn.bytes))
        for ref in _classify_insn(info, insn, include_indexed=include_indexed):
            if _inside_ranges(starts, ends, ref[2]):
                refs.append(Xref(*ref))
        if insn.group(capstone.CS_GRP_RET) or insn.group(capstone.CS_GRP_IRET):
            continue
        if insn.mnemonic in {"int3", "ud2", "hlt"}:
            continue
        if insn.group(capstone.CS_GRP_JUMP):
            if len(insn.operands) == 1 and insn.operands[0].type == op_imm:
                pending.append(int(insn.operands[0].imm))
            if insn.mnemonic in {"jmp", "ljmp"}:
                continue
        pending.append(pc + insn.size)
    return [decoded[pc] for pc in sorted(decoded)], sorted(refs, key=lambda r: r.from_va)


def ne_code_segments(info: BinaryInfo) -> list[str]:
    """Section names of an NE binary's code segments (for scans)."""
    return [f"SEG{s.index}" for s in info.ne_segments if s.is_code]


def _default_scan_sections(info: BinaryInfo) -> list[str]:
    """Sections scanned for references: code segments for NE, else .text."""
    if info.format == "ne":
        return ne_code_segments(info)
    return [".text"]


def _ne_segment_of(info: BinaryInfo, va: int) -> int | None:
    """Segment index (1-based) containing a synthetic VA, or None."""
    for seg in info.ne_segments:
        if seg.base_va <= va < seg.base_va + seg.length:
            return int(seg.index)
    return None


def _classify_insn(
    info: BinaryInfo, insn: Any, *, include_indexed: bool = False
) -> tuple[tuple[str, int, int], ...]:
    """Classify static references and optional indexed displacement candidates."""
    from_va = insn.address
    ops = insn.operands
    if not ops:
        return ()
    mnemonic = insn.mnemonic
    op_reg, op_imm, op_mem = _op_constants()
    if include_indexed and info.arch in {"x86_32", "x86_64"}:
        indexed = tuple(
            ("indexed_mem", from_va, int(op.mem.disp))
            for op in ops
            if op.type == op_mem and op.mem.base == 0 and op.mem.index != 0
        )
        if indexed:
            # Keep immediate references without treating the indexed operand as exact.
            return (*_classify_insn(info, insn), *indexed)

    # 16-bit NE: near call/jmp targets are relative within the segment;
    # absolute data reads/writes (e.g. ``mov ax, [imm16]``) address the DS
    # segment (the NE autodata segment).
    if info.format == "ne":
        seg_index = _ne_segment_of(info, from_va)
        if seg_index is None:
            return ()
        if mnemonic in ("call", "jmp"):
            op = ops[0]
            if op.type == op_imm:
                # capstone resolves 16-bit relative branches to the absolute
                # target already.
                return ((mnemonic, from_va, int(op.imm)),)
            return ()
        if mnemonic in ("push", "mov"):
            # `push 0x0D000` / `mov reg, 0x0D000` push/load a 16-bit absolute
            # (usually a string/global address in the autodata segment) —
            # mirror the 32-bit path so NE string/global references are
            # found, not just [imm16] memory operands.
            op = ops[0] if mnemonic == "push" else (ops[1] if len(ops) >= 2 else None)
            if op is not None and op.type == op_imm:
                disp = int(op.imm)
                if 0 <= disp <= 0xFFFF:
                    autodata = getattr(info, "ne_header", None)
                    data_seg = autodata.autodata_segment if autodata is not None else 1
                    # autodata_segment is NE's one-based segment number; the
                    # flat VA space is zero-based
                    return ((mnemonic, from_va, (data_seg - 1) << 16 | disp),)
        # Absolute [imm16] operands: a1/a3 (mov), and generic [abs] memory ops
        for op in ops:
            if (
                op.type == op_mem
                and op.mem.base == 0
                and op.mem.index == 0
                and op.mem.disp is not None
            ):
                disp = int(op.mem.disp)
                if 0 <= disp <= 0xFFFF:
                    autodata = getattr(info, "ne_header", None)
                    data_seg = autodata.autodata_segment if autodata is not None else 1
                    # one-based segment number into the zero-based VA space
                    to_va = ((data_seg - 1) << 16) | disp
                    kind = "mov_mem" if mnemonic == "mov" else f"{mnemonic}_mem"
                    return ((kind, from_va, to_va),)
        return ()

    # Non-x86 direct calls and unconditional branches.  The address is in
    # the operand text: SH ``bsr`` is not an immediate operand (its ``imm``
    # is the displacement), and ARM prints ``#0x``.  Kind stays ``call`` /
    # ``jmp`` so call-graph consumers do not grow a per-arch set.
    call_target = direct_call_target(mnemonic, insn.op_str)
    if call_target is not None:
        return (("call", from_va, call_target),)
    jump_target = direct_jump_target(mnemonic, insn.op_str)
    if jump_target is not None:
        return (("jmp", from_va, jump_target),)

    if mnemonic in ("call", "jmp"):
        op = ops[0]
        if op.type == op_imm:
            return ((mnemonic, from_va, op.imm),)
        if op.type == op_mem:
            addr = _mem_absolute(op.mem, insn)
            if addr is not None:
                return ((f"iat_{mnemonic}", from_va, addr),)
        return ()

    if mnemonic == "push":
        op = ops[0]
        if op.type == op_imm:
            return (("push", from_va, op.imm),)
        if op.type == op_mem:  # push [abs] — reads a global
            addr = _mem_absolute(op.mem, insn)
            if addr is not None:
                return (("push_mem", from_va, addr),)
        return ()

    if mnemonic == "lea":
        if len(ops) >= 2 and ops[1].type == op_mem:
            addr = _mem_absolute(ops[1].mem, insn)
            if addr is not None:
                return (("lea", from_va, addr),)
        return ()

    if mnemonic == "mov":
        if len(ops) < 2:
            return ()
        a, b = ops[0], ops[1]
        if a.type in (op_reg, op_mem) and b.type == op_imm:
            immediate = ("mov", from_va, int(b.imm))
            if a.type == op_mem:
                addr = _mem_absolute(a.mem, insn)
                if addr is not None:
                    return (immediate, ("mov_mem_store", from_va, addr))
            return (immediate,)
        if a.type == op_reg and b.type == op_mem:  # mov reg, [abs] — data read
            addr = _mem_absolute(b.mem, insn)
            if addr is not None:
                return (("mov_mem", from_va, addr),)
        if a.type == op_mem and b.type == op_reg:  # mov [abs], reg — data write
            addr = _mem_absolute(a.mem, insn)
            if addr is not None:
                return (("mov_mem_store", from_va, addr),)
        return ()

    # Like mov immediates, a cmp immediate inside the image is a possible
    # address reference, not proof that the value is a pointer.
    immediate_refs: tuple[tuple[str, int, int], ...] = ()
    if (
        info.arch in {"x86_32", "x86_64"}
        and mnemonic == "cmp"
        and len(ops) == 2
        and ops[1].type == op_imm
    ):
        immediate_refs = (("cmp", from_va, int(ops[1].imm)),)

    # Generic absolute memory operand (and/or/cmp/test/inc/... [abs]).
    for op in ops:
        if op.type == op_mem:
            addr = _mem_absolute(op.mem, insn)
            if addr is not None:
                return (*immediate_refs, (f"{mnemonic}_mem", from_va, addr))
    return immediate_refs


# ---------------------------------------------------------------------------
# Calls through a register holding an import pointer
# ---------------------------------------------------------------------------

_EAX, _ECX, _EDX, _EBX, _ESP, _EBP, _ESI, _EDI = (1 << bit for bit in range(8))
_ALL_GPRS = 0xFF

#: One bit per x86-32 general-purpose register, under every name capstone
#: prints for it: a write to ``si`` or ``al`` changes ``esi`` or ``eax``.
_GPR_BITS = {
    **dict.fromkeys(("eax", "ax", "al", "ah"), _EAX),
    **dict.fromkeys(("ecx", "cx", "cl", "ch"), _ECX),
    **dict.fromkeys(("edx", "dx", "dl", "dh"), _EDX),
    **dict.fromkeys(("ebx", "bx", "bl", "bh"), _EBX),
    **dict.fromkeys(("esp", "sp"), _ESP),
    **dict.fromkeys(("ebp", "bp"), _EBP),
    **dict.fromkeys(("esi", "si"), _ESI),
    **dict.fromkeys(("edi", "di"), _EDI),
}

#: Registers a ``call reg`` / ``jmp reg`` target is followed in.
_TRACKED_REGISTERS = {
    name: _GPR_BITS[name] for name in ("eax", "ecx", "edx", "ebx", "ebp", "esi", "edi")
}

#: Registers a callee may change under the Win32 x86 conventions (cdecl,
#: stdcall, fastcall, thiscall); ``ebx``, ``esi``, ``edi`` and ``ebp`` survive.
_CALLER_SAVED = _EAX | _ECX | _EDX

#: Mnemonics after which control never reaches the next swept instruction;
#: ``db`` is the skipdata placeholder for bytes that did not decode.
_NO_FALLTHROUGH = frozenset({"jmp", "ljmp", "ret", "retf", "iret", "iretd", "hlt", "ud2", "db"})

_IAT_KINDS = frozenset({"iat_call", "iat_jmp"})

#: Instructions one site's backward walk visits before it gives up (no edge).
_REGISTER_WALK_LIMIT = 4096

#: Entries read from a possible pointer table; the first entry outside the
#: section ends the read sooner.
_POINTER_TABLE_MAX_ENTRIES = 256
_X86_32_POINTER_BYTES = 4

#: Longest x86 instruction encoding.
_X86_MAX_INSN_BYTES = 15


class _RegisterImportCalls:
    """Import slots behind ``call reg`` / ``jmp reg`` in one x86-32 code section.

    MSVC loads an import pointer into a register once (``mov esi,
    [__imp__lstrlenW]``) and calls it several times (``call esi``).  Fed the
    section's linear sweep through :meth:`observe`, :meth:`references` walks
    back from each such site over the swept control flow and reports an
    ``iat_call`` / ``iat_jmp`` to the slot only when every path reaching the
    site loads the register from that one slot and nothing after the load
    writes it.  Each limit below gives no edge rather than a wrong one:

    - A predecessor is the previous swept instruction when it falls through,
      the source of a direct ``jmp``, ``jcc`` or ``loop``, or, for each entry
      of its table, a ``jmp [index*4 + table]`` switch dispatch.  A table is
      read until an entry leaves the section or after
      ``_POINTER_TABLE_MAX_ENTRIES`` entries.  The walk stops with no edge at
      an instruction with no predecessor (a function entry), at a direct call
      target, at an in-section address an instruction carries as a value
      (immediate or memory operand), and at an entry of any other possible
      pointer table (a memory operand with a register and an in-image
      displacement): control may arrive there from code the walk does not
      follow.
    - Any write to the register or a part of it (explicit or implicit, from
      capstone's register access) stops the walk, as does a call when the
      register is ``eax``, ``ecx`` or ``edx``, an interrupt, or an undecodable
      byte.  Callees are taken to keep ``ebx``, ``esi``, ``edi`` and ``ebp``.
    - Two slots on two paths, or more than ``_REGISTER_WALK_LIMIT`` visited
      instructions, give no edge.
    - Not followed: register copies and stack spills (no edge), and
      predecessors the sweep cannot see, which are taken to be absent: an
      indirect jump through a table whose address is not a displacement, an
      exception continuation, a branch into the middle of a swept instruction.
    """

    def __init__(
        self,
        md: Any,
        raw: bytes,
        base_va: int,
        slots: frozenset[int],
        starts: list[int],
        ends: list[int],
    ) -> None:
        self._md = md
        self._raw = raw
        self._base = base_va
        self._end = base_va + len(raw)
        self._slots = slots
        self._starts = starts
        self._ends = ends
        self._vas = array("I")
        self._falls_through = bytearray()
        self._branch_sources: dict[int, list[int]] = {}
        self._entries: set[int] = set()
        self._tables: set[int] = set()
        self._dispatch_tables: dict[int, list[int]] = {}
        self._sites: list[tuple[int, str, int]] = []
        self._effects: dict[int, tuple[int, int, int]] = {}
        self._op_mem = _op_constants()[2]

    def observe(self, insn: Any, mnemonic: str, refs: tuple[tuple[str, int, int], ...]) -> None:
        """Record one swept capstone instruction, its mnemonic and its classified references."""
        va = int(insn.address)
        op_str = insn.op_str
        self._vas.append(va)
        self._falls_through.append(mnemonic not in _NO_FALLTHROUGH)
        for kind, _from_va, to_va in refs:
            if kind == "jmp":
                self._branch_sources.setdefault(to_va, []).append(va)
            elif kind not in _IAT_KINDS and self._base <= to_va < self._end:
                self._entries.add(to_va)
        if mnemonic in ("call", "jmp"):
            register = _TRACKED_REGISTERS.get(op_str)
            if register is not None:
                self._sites.append((va, mnemonic, register))
        elif mnemonic.startswith(("j", "loop")):
            target = _immediate_address(op_str)
            if target is not None:
                self._branch_sources.setdefault(target, []).append(va)
        if "[" in op_str:
            for op in insn.operands:
                mem = op.mem if op.type == self._op_mem else None
                if mem is None or not (mem.base or mem.index):
                    continue
                disp = int(mem.disp)
                if not _inside_ranges(self._starts, self._ends, disp):
                    continue
                if (
                    mnemonic == "jmp"
                    and not mem.base
                    and mem.index
                    and mem.scale == _X86_32_POINTER_BYTES
                ):
                    self._dispatch_tables.setdefault(disp, []).append(va)
                else:
                    self._tables.add(disp)

    def references(self, info: BinaryInfo) -> list[tuple[str, int, int]]:
        """``(kind, site VA, slot VA)`` for every site resolved to one import slot."""
        if not self._sites:
            return []
        self._read_tables(info)
        out: list[tuple[str, int, int]] = []
        for va, mnemonic, register in self._sites:
            slot = self._held_slot(va, register)
            if slot is not None:
                out.append((f"iat_{mnemonic}", va, slot))
        return out

    def _read_tables(self, info: BinaryInfo) -> None:
        """Enter each table entry as a dispatch's branch target or as an unknown entry."""
        for table, dispatches in self._dispatch_tables.items():
            for entry in self._table_entries(info, table):
                self._branch_sources.setdefault(entry, []).extend(dispatches)
        for table in self._tables:
            self._entries.update(self._table_entries(info, table))
        self._dispatch_tables.clear()
        self._tables.clear()

    def _table_entries(self, info: BinaryInfo, table: int) -> Iterator[int]:
        """The leading in-section pointers stored at *table*."""
        width = _X86_32_POINTER_BYTES
        raw = extract_bytes(info, table, _POINTER_TABLE_MAX_ENTRIES * width)
        for offset in range(0, len(raw) - width + 1, width):
            entry = int.from_bytes(raw[offset : offset + width], "little")
            if not self._base <= entry < self._end:
                return
            yield entry

    def _held_slot(self, site_va: int, register: int) -> int | None:
        """The one import slot *register* holds on every path into *site_va*, or None."""
        slot: int | None = None
        seen: set[int] = set()
        pending = [bisect_left(self._vas, site_va)]
        while pending:
            predecessors = self._predecessors(pending.pop())
            if predecessors is None:
                return None
            for index in predecessors:
                if index in seen:
                    continue
                seen.add(index)
                if len(seen) > _REGISTER_WALK_LIMIT:
                    return None
                loaded, loaded_slot, writes = self._effect(index)
                if loaded == register:
                    if slot is not None and slot != loaded_slot:
                        return None
                    slot = loaded_slot
                elif writes & register:
                    return None
                else:
                    pending.append(index)
        return slot

    def _predecessors(self, index: int) -> list[int] | None:
        """Swept instructions control enters instruction *index* from.

        None when control may also enter it from code the sweep does not show.
        """
        va = self._vas[index]
        if va in self._entries:
            return None
        found = [index - 1] if index > 0 and self._falls_through[index - 1] else []
        found.extend(bisect_left(self._vas, source) for source in self._branch_sources.get(va, ()))
        return found or None

    def _effect(self, index: int) -> tuple[int, int, int]:
        """``(register loaded from an import slot, the slot, registers written)``.

        The first two are 0 unless the instruction is ``mov reg32, [slot]``.
        """
        cached = self._effects.get(index)
        if cached is not None:
            return cached
        va = self._vas[index]
        offset = va - self._base
        code = self._raw[offset : offset + _X86_MAX_INSN_BYTES]
        insn = next(self._md.disasm(code, va, count=1), None)
        effect = (0, 0, _ALL_GPRS)
        if insn is not None and insn.mnemonic != "db" and not insn.group(capstone.CS_GRP_INT):
            writes = 0
            for reg in insn.regs_access()[1]:
                writes |= _GPR_BITS.get(insn.reg_name(reg), 0)
            if insn.group(capstone.CS_GRP_CALL):
                writes |= _CALLER_SAVED
            loaded, slot = self._import_load(insn)
            effect = (loaded, slot, writes)
        self._effects[index] = effect
        return effect

    def _import_load(self, insn: Any) -> tuple[int, int]:
        """``(register bit, slot)`` for ``mov reg32, [slot]``, else ``(0, 0)``."""
        if insn.mnemonic != "mov" or len(insn.operands) != 2:
            return 0, 0
        op_reg, _, op_mem = _op_constants()
        dst, src = insn.operands
        if dst.type != op_reg or src.type != op_mem:
            return 0, 0
        register = _TRACKED_REGISTERS.get(insn.reg_name(dst.reg), 0)
        slot = _mem_absolute(src.mem)
        if register and slot is not None and slot in self._slots:
            return register, slot
        return 0, 0


# ---------------------------------------------------------------------------
# Strings
# ---------------------------------------------------------------------------

_PRINTABLE = set(range(0x20, 0x7F))
_UTF16_PRINTABLE = set(range(0x20, 0x7F))

#: Whole-section strings scan: one compiled run per section instead of a
#: per-byte Python loop. Matched runs are exactly the printable stretches the
#: old loops collected, so results are identical; the regex engine does the
#: byte walk in C.
_ASCII_RUN = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]+")


@lru_cache(maxsize=64)
def _ascii_run(min_len: int) -> re.Pattern[bytes]:
    """Run matcher for ASCII strings."""
    return _ASCII_RUN if min_len == 4 else re.compile(rb"[\x20-\x7e]{%d,}" % min_len)


@lru_cache(maxsize=64)
def _utf16_run(min_len: int) -> re.Pattern[bytes]:
    """Run matcher for UTF-16LE strings."""
    return _UTF16_RUN if min_len == 4 else re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)


#: Borland/Delphi ``ShortString`` maximum length: the length prefix is one byte,
#: so a string runs to 255 bytes.  The old cap of 63 silently dropped every
#: 64..255-byte string, and a long printable run is *stronger* evidence of a
#: real string than a short one, not weaker.
_PASCAL_MAX_LEN = 255


def iter_strings(
    info: BinaryInfo,
    min_len: int = 4,
    section_names: list[str] | None = None,
) -> list[StringEntry]:
    """Extract printable ASCII and UTF-16LE runs from data sections.

    *section_names* defaults to the data-ish sections (``.rdata``, ``.data``,
    ``.rodata``); pass an explicit list to include ``.text``.  For 16-bit NE
    binaries the default is the non-code segments, and Pascal (length-
    prefixed) strings are recognized in addition to plain ASCII runs —
    Borland Delphi stores its UI strings as Pascal strings.
    """
    min_len = max(min_len, 1)
    names: list[str]
    if info.format == "ne":
        data_segs = [s for s in info.ne_segments if not s.is_code]
        names = section_names if section_names is not None else [f"SEG{s.index}" for s in data_segs]
    else:
        default: list[str] = [n for n in (".rdata", ".data", ".rodata") if n in info.sections]
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
        if info.format == "ne":
            strings.extend(_scan_pascal(raw, va, name, min_len))
    strings.sort(key=lambda s: s.va)
    return strings


def _scan_pascal(raw: bytes, va: int, section: str, min_len: int) -> list[StringEntry]:
    """Scan for Pascal (length-prefixed) strings: ``len`` then *len* printable
    ASCII bytes.  Borland Delphi's RTL stores strings this way."""
    out: list[StringEntry] = []
    # A body is printable iff it lies inside one maximal printable run, so
    # only positions whose body overlaps such a run can match.  Scanning
    # candidates run-by-run (regex finds the runs in C) avoids a per-byte
    # Python loop over the whole segment; results are identical because a
    # match is exactly a run-contained body with a sufficient length byte.
    for match in _PRINTABLE_RUN.finditer(raw):
        s, e = match.start(), match.end()
        if e - s < min_len:
            continue
        i = s - 1
        last = e - min_len
        while 0 <= i <= last:
            ln = raw[i]
            if min_len <= ln <= _PASCAL_MAX_LEN and i + 1 + ln <= e:
                out.append(
                    StringEntry(
                        va=va + i,
                        size=1 + ln,
                        text=raw[i + 1 : i + 1 + ln].decode("ascii", "replace"),
                        kind="pascal",
                        section=section,
                    )
                )
                i += 1 + ln
                continue
            i += 1
    out.sort(key=lambda entry: entry.va)
    return out


def _scan_ascii(raw: bytes, va: int, section: str, min_len: int) -> list[StringEntry]:
    pat = _ascii_run(min_len)
    return [
        StringEntry(
            va=va + m.start(),
            size=m.end() - m.start(),
            text=m.group().decode("ascii"),
            kind="ascii",
            section=section,
        )
        for m in pat.finditer(raw)
    ]


def _scan_utf16(raw: bytes, va: int, section: str, min_len: int) -> list[StringEntry]:
    pat = _utf16_run(min_len)
    return [
        StringEntry(
            va=va + m.start(),
            size=m.end() - m.start(),
            text=m.group()[::2].decode("ascii"),
            kind="utf16",
            section=section,
        )
        for m in pat.finditer(raw)
    ]


def string_refs(
    info: BinaryInfo, strings: list[StringEntry], all_refs: list[Xref] | None = None
) -> dict[int, list[Xref]]:
    """Map string VA -> references, using *strings* as the target set.

    *all_refs* is an already-computed unfiltered :func:`scan_references`
    result; passing it avoids a second full disassembly of every code
    section, which on a multi-megabyte ``.text`` costs seconds.
    """
    if not strings:
        return {}
    targets = {s.va for s in strings}
    refs: dict[int, list[Xref]] = {}
    for xref in all_refs if all_refs is not None else scan_references(info):
        if xref.to_va in targets:
            refs.setdefault(xref.to_va, []).append(xref)
    for xrefs_at_va in refs.values():
        xrefs_at_va.sort(key=lambda x: x.from_va)
    return refs
