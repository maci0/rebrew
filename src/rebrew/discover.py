"""rebrew discover-functions — robust function enumeration for a target binary.

Function discovery is the weak link in onboarding: rizin's ``aaa`` mis-merges
functions on some toolchains (the MinGW GCC family) and ``aap`` misses
frameless functions, and rizin sizes are frequently off by a few bytes.  This
command chains several strategies and merges the best result:

1. rizin ``aaa`` (full analysis)
2. rizin ``aa; aap`` (function-prelude analysis)
3. a capstone linear sweep over .text: function starts after padding runs,
   ``push ebp; mov ebp, esp`` prologues, and direct-call targets
4. unwind tables, which a stripped binary keeps: an ELF's ``.eh_frame``
   records (every function, on a default x86-64 or AArch64 build) and an x64
   PE's ``.pdata`` runtime functions (every non-leaf function), each an exact
   start and size

Candidates are merged by VA (dropping any that land inside a larger span) and
each size is refined by disassembling to the first ``ret`` — the size that
actually matches what a compiler emits (the "rizin said 34, real size 36"
problem).

Usage::

    rebrew discover-functions original/game.exe
    rebrew discover-functions game.exe --output src/game/function_structure.json
"""

from __future__ import annotations

import bisect
import logging
import re
import struct
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer

from rebrew.analysis import iter_instructions
from rebrew.binary_loader import load_binary
from rebrew.cli import console, error_exit, json_print
from rebrew.utils import atomic_write_text

app = typer.Typer(help="Enumerate functions: rizin aaa/aap + capstone sweep, sizes validated.")

#: setuptools entry-point group whose members register extra function
#: discoverers.  A member is a callable ``fn(binary: Path) ->
#: list[tuple[va, size, name]]`` keyed by its entry-point name — e.g. a
#: Ghidra/rizin-alternative backend emitting the same triple shape
#: ``discover --output`` writes.  An optional registry: a broken plugin is
#: skipped with a warning instead of bricking discovery.
DISCOVERER_ENTRY_POINT_GROUP = "rebrew.discoverers"

#: A function discoverer: binary path in, ``[(va, size, name)]`` out.
#: Empty list = nothing found (never None, never raises — providers that
#: fail return [] so one broken backend cannot abort the merge).
Discoverer = Callable[[Path], list[tuple[int, int, str]]]

logger = logging.getLogger(__name__)


@dataclass
class Discovery:
    """A merged function-discovery result."""

    functions: list[tuple[int, int, str]] = field(default_factory=list)
    sources: dict[str, int] = field(default_factory=dict)  # strategy -> count


def _rizin_functions(binary: Path, cmds: list[str]) -> list[tuple[int, int, str]]:
    """Run rizin with *cmds* and parse ``afl`` output (3- or 4-column)."""
    from rebrew.catalog import parse_rizin_afl

    try:
        r = subprocess.run(
            ["rizin", "-q", "-c", "; ".join(cmds) + "; afl", str(binary)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
        )
    except OSError as exc:
        logger.warning("rizin %s unavailable for %s: %s", cmds, binary, exc)
        return []
    except subprocess.TimeoutExpired:
        logger.warning("rizin %s timed out after 300s on %s", cmds, binary)
        return []
    if r.returncode != 0:
        logger.debug("rizin %s failed (rc=%d): %s", cmds, r.returncode, r.stderr[:500])
        return []
    return parse_rizin_afl(r.stdout)


def _discover_rizin_aaa(binary: Path) -> list[tuple[int, int, str]]:
    """Packaged discoverer: rizin full analysis."""
    return _rizin_functions(binary, ["aaa"])


def _discover_rizin_aap(binary: Path) -> list[tuple[int, int, str]]:
    """Packaged discoverer: rizin function-prelude analysis."""
    return _rizin_functions(binary, ["aa", "aap"])


def _discover_capstone_sweep(binary: Path) -> list[tuple[int, int, str]]:
    """Packaged discoverer: capstone linear sweep (sizes unvalidated)."""
    try:
        return _capstone_sweep(binary)
    except Exception as exc:
        # A fallback source's absence must not be silent — without it,
        # rizin-derived sizes go unvalidated.
        logger.warning("capstone linear sweep failed (sizes unvalidated): %s", exc)
        return []


#: DW_EH_PE value formats (the encoding's low nibble) with a fixed width;
#: ``absptr`` (0x00) is the target's pointer width and is added per call.
_EH_PE_FORMATS = {0x02: "H", 0x03: "I", 0x04: "Q", 0x0A: "h", 0x0B: "i", 0x0C: "q"}
_EH_PE_PCREL = 0x10
_EH_PE_APPLICATION_MASK = 0x70
_EH_PE_OMIT = 0xFF
#: A record length of this value means a 64-bit length follows.
_EH_EXTENDED_LENGTH = 0xFFFFFFFF


def _uleb128(data: bytes, pos: int) -> tuple[int, int]:
    """``(value, next position)`` of the ULEB128 at *pos*; IndexError when truncated."""
    value = shift = 0
    while True:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos


def _parse_eh_frame(
    data: bytes, section_va: int, *, pointer_size: int, big_endian: bool
) -> list[tuple[int, int]]:
    """``(start, size)`` of every FDE in the ``.eh_frame`` image *data* mapped at *section_va*.

    Reads CIEs for their FDE pointer encoding (the ``zR`` augmentation) and
    each FDE's initial location and address range.  Parsing stops at the zero
    terminator or at the first malformed record, keeping what was read before
    it; it never raises on bad input.  An FDE whose CIE was not seen, or whose
    range is zero, is skipped.
    """
    order = ">" if big_endian else "<"
    formats = {0x00: "Q" if pointer_size == 8 else "I", **_EH_PE_FORMATS}

    def pointer(pos: int, encoding: int, *, pc_relative: bool = True) -> tuple[int, int]:
        fmt = order + formats[encoding & 0x0F]
        (value,) = struct.unpack_from(fmt, data, pos)
        if pc_relative and encoding & _EH_PE_APPLICATION_MASK == _EH_PE_PCREL:
            value += section_va + pos
        return value, pos + struct.calcsize(fmt)

    def fde_encoding(pos: int, end: int) -> int:
        version = data[pos]
        terminator = data.index(b"\0", pos + 1, end)
        augmentation = data[pos + 1 : terminator]
        pos = terminator + 1
        if b"eh" in augmentation:  # pre-DWARF-2 GCC: an EH data pointer follows
            pos += pointer_size
        _code_align, pos = _uleb128(data, pos)
        _data_align, pos = _uleb128(data, pos)  # SLEB128, but only skipped
        pos = pos + 1 if version == 1 else _uleb128(data, pos)[1]
        encoding = 0x00
        if augmentation.startswith(b"z"):
            _length, pos = _uleb128(data, pos)
            for letter in augmentation[1:].decode("ascii"):
                if letter == "R":
                    encoding = data[pos]
                    pos += 1
                elif letter == "P":
                    _personality, pos = pointer(pos + 1, data[pos])
                elif letter == "L":
                    pos += 1
                elif letter not in "SB":
                    break  # unknown letter: the rest of the data is unknown
        return encoding

    encodings: dict[int, int] = {}
    extents: list[tuple[int, int]] = []
    pos = 0
    try:
        while pos + 4 <= len(data):
            (length,) = struct.unpack_from(order + "I", data, pos)
            if length == 0:
                break
            body, id_format = pos + 4, "I"
            if length == _EH_EXTENDED_LENGTH:
                (length,) = struct.unpack_from(order + "Q", data, body)
                body, id_format = body + 8, "Q"
            end = body + length
            if end > len(data):
                break
            (cie_id,) = struct.unpack_from(order + id_format, data, body)
            fields = body + struct.calcsize(id_format)
            if cie_id == 0:
                encodings[pos] = fde_encoding(fields, end)
            else:
                encoding = encodings.get(body - cie_id)
                if encoding is not None and encoding != _EH_PE_OMIT:
                    start, fields = pointer(fields, encoding)
                    size, _ = pointer(fields, encoding & 0x0F, pc_relative=False)
                    if size > 0:
                        extents.append((start, size))
            pos = end
    except (struct.error, KeyError, ValueError, IndexError, UnicodeDecodeError):
        logger.debug("malformed .eh_frame record at offset 0x%x; kept what came before", pos)
    return extents


def _discover_eh_frame(binary: Path) -> list[tuple[int, int, str]]:
    """Packaged discoverer: exact function extents from an ELF's ``.eh_frame``.

    Only extents that start inside a code section are kept.  Empty for a
    non-ELF binary or one without unwind records.
    """
    try:
        info = load_binary(binary)
    except (OSError, ValueError):
        return []
    if info.format != "elf":
        return []
    section = next((s for s in info.sections.values() if s.name == ".eh_frame"), None)
    if section is None or section.file_offset < 0 or section.raw_size <= 0:
        return []
    data = info.data[section.file_offset : section.file_offset + section.raw_size]
    code = [(s.va, s.va + s.size) for s in info.sections.values() if s.is_code]
    extents = _parse_eh_frame(
        data,
        section.va,
        pointer_size=8 if info.arch.endswith("64") else 4,
        big_endian=info.endian == "big",
    )
    return [
        (va, size, f"fcn.{va:08x}")
        for va, size in sorted(set(extents))
        if any(lo <= va < hi for lo, hi in code)
    ]


def _discover_pdata(binary: Path) -> list[tuple[int, int, str]]:
    """Packaged discoverer: exact function extents from an x64 PE's ``.pdata``.

    A runtime function whose unwind info chains to another describes a
    fragment of that function, not a start, and is skipped.  Empty for any
    other binary.
    """
    import lief

    config = lief.PE.ParserConfig()
    config.parse_exceptions = True
    try:
        pe = lief.PE.parse(str(binary), config) if lief.is_pe(str(binary)) else None
    except (OSError, ValueError):
        return []
    if pe is None:
        return []
    base = pe.optional_header.imagebase
    out: list[tuple[int, int, str]] = []
    for entry in pe.exceptions:
        if not isinstance(entry, lief.PE.RuntimeFunctionX64):
            continue
        info = entry.unwind_info
        if info is not None and info.chained is not None:
            continue
        size = entry.rva_end - entry.rva_start
        if size > 0:
            va = base + entry.rva_start
            out.append((va, size, f"fcn.{va:08x}"))
    return sorted(set(out))


def _inside_an_extent(extents: list[tuple[int, int]], va: int) -> bool:
    """True when *va* falls strictly inside one of the sorted ``(start, size)`` *extents*."""
    index = bisect.bisect_left(extents, (va, 0)) - 1
    if index < 0:
        return False
    start, size = extents[index]
    return start < va < start + size


def _discover_ne_loader(binary: Path) -> list[tuple[int, int, str]]:
    """Packaged discoverer: 16-bit NE native loader (None unless NE)."""
    from rebrew.binary_loader import is_ne, load_binary
    from rebrew.ne_loader import enumerate_ne_functions

    if not is_ne(binary):
        return []
    info = load_binary(binary)
    return [(f.va, f.size, f.name) for f in enumerate_ne_functions(info)]


def _discover_mz_sweep(binary: Path) -> list[tuple[int, int, str]]:
    """Packaged discoverer: 16-bit DOS MZ sweep (None unless MZ)."""
    from rebrew.binary_loader import is_mz

    if not is_mz(binary):
        return []
    return sorted(_mz_capstone_sweep(binary))


#: Packaged discoverers: name -> provider.  Plugins join via the
#: ``rebrew.discoverers`` entry-point group (see :func:`discoverer_map`).
_PACKAGED_DISCOVERERS: dict[str, Discoverer] = {
    "rizin aaa": _discover_rizin_aaa,
    "rizin aa;aap": _discover_rizin_aap,
    "capstone sweep": _discover_capstone_sweep,
    "eh_frame": _discover_eh_frame,
    "pdata": _discover_pdata,
    "ne loader": _discover_ne_loader,
    "mz sweep": _discover_mz_sweep,
}


def discoverer_map() -> dict[str, Discoverer]:
    """Packaged discoverers + ``rebrew.discoverers`` entry-point plugins.

    Merging order: packaged first, then plugins in discovery order.  A
    broken or conflicting plugin is skipped with a warning (discovery
    degrades to the packaged set) instead of bricking onboarding.
    """
    from rebrew.registry import (
        RegistryError,
        entry_point_registrations,
        load_registration_optional,
        merge_into,
    )

    merged: dict[str, Discoverer] = dict(_PACKAGED_DISCOVERERS)
    for reg in entry_point_registrations(DISCOVERER_ENTRY_POINT_GROUP):
        fn = load_registration_optional(reg, logger)
        if fn is None:
            continue
        if not callable(fn):
            logger.warning(
                "skipping %s registration %r: expected a callable discoverer, got %s",
                reg.group,
                reg.name,
                type(fn).__name__,
            )
            continue
        try:
            merge_into(merged, reg.name, fn, reg.origin, group=reg.group)
        except RegistryError as exc:
            logger.warning("skipping %s registration %r: %s", reg.group, reg.name, exc)
    return merged


def refresh_discoverers() -> dict[str, Discoverer]:
    """Re-run discovery and refresh the discoverer snapshot.

    Long-lived processes can pick up discoverers installed after startup
    without a restart."""
    global _DISCOVERER_MAP

    _DISCOVERER_MAP = discoverer_map()
    return _DISCOVERER_MAP


_DISCOVERER_MAP = discoverer_map()


def _capstone_sweep(binary: Path) -> list[tuple[int, int, str]]:
    """Linear-sweep candidates from .text: post-padding starts, frame prologues, call targets.

    x86-32/64 uses the full heuristic set (int3/nop padding runs, ``push
    ebp; mov ebp,esp`` prologues, ``e8 rel32`` call targets).  Other arches
    (multi-arch P0) use a minimal sweep — the .text base plus direct call
    targets via the arch-aware disassembler — until arch-specific padding
    and prologue patterns land with the first real target.
    """
    try:
        info = load_binary(binary)
    except (OSError, ValueError):
        return []
    text = next((s for s in info.sections.values() if s.name.lower() == ".text"), None)
    if text is None:
        return []
    if text.size <= 0 or text.file_offset < 0:
        return []
    if text.file_offset + text.size > len(info.data):
        return []
    data = info.data
    raw = data[text.file_offset : text.file_offset + text.size]
    va_base = text.va

    arch = getattr(info, "arch", "") or ""
    if arch and not arch.startswith("x86"):
        # Minimal non-x86 sweep: .text base + direct call targets.
        nstarts: set[int] = {va_base}
        for insn in iter_instructions(info, text.va, text.size):
            if insn.mnemonic in ("call", "jal", "bl") and insn.op_str.startswith("0x"):
                try:
                    tgt = int(insn.op_str, 16)
                except ValueError:
                    continue
                if text.va <= tgt < text.va + text.size:
                    nstarts.add(tgt)
        return [(va, 0, f"fcn.{va:08x}") for va in sorted(nstarts)]

    starts: set[int] = set()
    # 1. the .text base is always a candidate
    starts.add(va_base)
    # 2. bytes after padding runs (int3 / nop alignment, documented
    # multi-byte NOP forms only — never a bare 0x0F, which is a real opcode)
    i = 0
    n = len(raw)
    while i < n - 1:
        b = raw[i]
        if b in (0xCC, 0x90):
            j = i
            while j < n:
                if raw[j] in (0xCC, 0x90):
                    j += 1
                    continue
                nop_len = _multibyte_nop_len(raw, j) if raw[j] in (0x0F, 0x66) else 0
                if nop_len:
                    j += nop_len
                    continue
                break
            # a padding run of >= 3 bytes: the byte after it starts a function.
            if j - i >= 3 and j < n:
                starts.add(va_base + j)
            i = j
        else:
            i += 1
    # 3. `push ebp; mov ebp, esp` prologue
    for m in re.finditer(rb"\x55\x8b\xec", raw):
        starts.add(va_base + m.start())
    # 4. direct-call targets (e8 rel32) via capstone
    for insn in iter_instructions(info, text.va, text.size):
        if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
            try:
                tgt = int(insn.op_str, 16)
            except ValueError:
                continue
            if text.va <= tgt < text.va + text.size:
                starts.add(tgt)

    funcs: list[tuple[int, int, str]] = []
    for va in sorted(starts):
        funcs.append((va, 0, f"fcn.{va:08x}"))
    return funcs


_PAD = {0xCC, 0x90}

#: Documented multi-byte NOP body lengths by (first, second) opcode bytes.
#: Only these exact two-byte prefixes count as multi-byte NOP padding —
#: a bare 0x0F is a real opcode (e.g. part of ``0F 85 jnz``) and must
#: never be treated as padding.
_MULTIBYTE_NOP_LEN: dict[tuple[int, int], int] = {
    (0x0F, 0x1F): 3,  # 0F 1F /0 — 3-byte NOP (ModRM always follows)
    (0x0F, 0x0D): 3,  # 3DNow! prefetch — same ModRM shape
    (0x66, 0x90): 2,  # operand-size NOP (66 90)
    (0x66, 0x0F): 4,  # 66 0F 1F /0 — 4-byte NOP (ModRM always follows)
}


def _multibyte_nop_len(raw: bytes | bytearray, i: int) -> int:
    """Length of the multi-byte NOP at ``raw[i:]``, or 0 when it is not one.

    ``0F 1F`` / ``66 0F 1F`` require a valid ModRM byte: register-direct
    (``mod == 0b11``) forms are real instructions (e.g. ``0F 1F C0`` decodes
    as ``nop eax,eax`` only under 64-bit; under 32-bit it can be something
    else), and memory forms with SIB/disp bytes consume them.  A missing or
    out-of-range ModRM means "not a NOP".
    """
    n = len(raw)
    pair = (raw[i], raw[i + 1] if i + 1 < n else -1)
    base = _MULTIBYTE_NOP_LEN.get((pair[0], pair[1] if isinstance(pair[1], int) else -1))
    if base is None:
        return 0
    if pair in (
        (
            0x66,
            0x90,
        ),
    ):
        return base
    # A ModRM byte must exist after the two-byte prefix.
    if i + 2 >= n:
        return 0
    modrm = raw[i + 2]
    mod = modrm >> 6
    rm = modrm & 7
    if mod == 0b11:
        return 0  # register-direct — not documented padding
    length = base
    if rm == 0b100:  # SIB byte follows
        length += 1
        if i + 3 >= n:
            return 0
        sib = raw[i + 3]
        base_reg = sib & 7
        if mod == 0b00 and base_reg == 0b101:  # disp32, no base
            length += 4
        elif mod == 0b01:  # disp8
            length += 1
        elif mod == 0b10:  # disp32
            length += 4
    elif mod == 0b00 and rm == 0b101:  # disp32, no base
        length += 4
    elif mod == 0b01:  # disp8
        length += 1
    elif mod == 0b10:  # disp32
        length += 4
    return length if i + length <= n else 0


def _is_padding(info: Any, va: int, end: int) -> bool:
    """True when [va, end) disassembles to nothing but padding bytes."""
    from rebrew.analysis import extract_bytes

    try:
        raw = extract_bytes(info, va, end - va)
    except Exception:
        logger.debug("extract_bytes failed at 0x%x", va, exc_info=True)
        return False
    i = 0
    while i < len(raw):
        b = raw[i]
        if b in _PAD:
            i += 1
            continue
        if b in (0x0F, 0x66) and i + 1 < len(raw):
            nop_len = _multibyte_nop_len(raw, i)
            if nop_len:
                i += nop_len
                continue
        return False
    return True


def _validate_and_refine(
    info: Any, funcs: list[tuple[int, int, str]], *, vouched: frozenset[int] = frozenset()
) -> list[tuple[int, int, str]]:
    """Drop candidates that are inside another function's span; size = gap, trimmed of padding.

    A start in *vouched* (one an unwind record names) is never dropped: code
    that ends in a call to a noreturn function runs straight into the next
    function with no ``ret``.

    A candidate is a *real* function start when the previous function's code
    reaches a ``ret`` followed by padding before the candidate.  If the code
    runs straight into the candidate with no ret+padding boundary, the
    candidate is a false positive (a call target inside the previous
    function).  Sizes are the gap to the next validated start, minus trailing
    padding — the size a compiler actually emits.
    """
    funcs = sorted(funcs, key=lambda f: f[0])
    out: list[tuple[int, int, str]] = []
    i = 0
    while i < len(funcs):
        va, _s, name = funcs[i]
        nxt = funcs[i + 1][0] if i + 1 < len(funcs) else None
        gap = (nxt - va) if nxt else None

        # Find the first ret within the gap.
        ret_end = None
        last_mnemonic = ""
        decoded_end = va
        try:
            for insn in iter_instructions(info, va, gap or 0x400):
                last_mnemonic = insn.mnemonic
                decoded_end = insn.va + insn.size
                if insn.mnemonic.startswith("ret"):
                    ret_end = insn.va + insn.size - va
                    break
        except Exception:
            # Disassembly failure at this candidate: ret_end stays None, so the
            # size falls back to the raw gap. Log it — a mis-sized function in
            # the catalog is otherwise indistinguishable from a correct one.
            logger.debug(
                "instruction sweep failed at candidate 0x%x (size = raw gap)", va, exc_info=True
            )

        # The window IS the gap (`iter_instructions(info, va, gap)`), so the old
        # `insn.va >= nxt` test could never fire and the phantom candidate was
        # never dropped.  The real signal is "the predecessor decoded to the
        # candidate with no boundary": no ret, and nothing that legitimately ends
        # a function without one (a tail-call `jmp`, int3/hlt/ud2 padding).  An
        # empty decode stays conservative — nothing is dropped.
        # Only code that decodes all the way to the candidate runs into it: a
        # window cut short (the section's file bytes end first, as at the end of
        # an ELF `.plt`) proves nothing.  A prefixed jump (`bnd jmp`, `notrack
        # jmp`) is a tail jump, and `nop` is padding, like int3/hlt/ud2.
        hit_nxt = (
            ret_end is None
            and gap is not None
            and nxt is not None
            and nxt not in vouched
            and decoded_end >= nxt
            and last_mnemonic != ""
            and last_mnemonic.split()[-1] != "jmp"
            and last_mnemonic not in ("int3", "hlt", "ud2", "nop")
        )

        if hit_nxt:
            # code runs straight into the next candidate with no ret — that
            # candidate is a false positive inside this function: drop it.
            del funcs[i + 1]
            continue

        if ret_end is not None and gap is not None:
            tail = gap - ret_end
            size = (
                ret_end
                if tail > 0 and nxt is not None and _is_padding(info, va + ret_end, nxt)
                else gap
            )
        else:
            size = gap if gap is not None else (ret_end or 0)
        out.append((va, size, name))
        i += 1
    return out


def _mz_capstone_sweep(binary: Path) -> list[tuple[int, int, str]]:
    """Linear-sweep candidates for a plain DOS MZ executable.

    Rizin cannot analyze MZ; the code region (after the header + relocation
    table) is swept in 16-bit mode for the classic cdecl prologue
    ``push bp; mov bp,sp``, padding runs, the CS:IP entry point, and
    ``e8 rel16`` call targets inside the region.  VAs are linear
    ``segment*16+offset`` addresses (the DOS convention).
    """
    from rebrew.binary_loader import parse_mz_header

    h = parse_mz_header(binary)
    with open(binary, "rb") as f:
        f.seek(h["code_offset"])
        raw = f.read(h["code_size"])
    if not raw:
        return []
    # VAs are segment-relative linear addresses: the code region starts at
    # VA 0 and the header's code segment ``e_cs`` lands at ``e_cs*16``
    # (entry at ``e_cs*16 + e_ip``), consistent with load_binary's pseudo
    # .text section.  VA(F) = F - code_offset.
    va_base = h["va_base"]
    starts: set[int] = set()

    # 1. the code region base and the CS:IP entry are always candidates
    starts.add(va_base)
    entry = h["entry_va"]
    if va_base <= entry < va_base + len(raw):
        starts.add(entry)
    # 2. bytes after padding runs (nop alignment)
    i = 0
    n = len(raw)
    while i < n - 1:
        if raw[i] == 0x90:
            j = i
            while j < n and raw[j] in (0x90, 0xCC):
                j += 1
            if j - i >= 2 and j < n:
                starts.add(va_base + j)
            i = j
        else:
            i += 1
    # 3. `push bp; mov bp,sp` prologue (16-bit cdecl)
    for m in re.finditer(rb"\x55\x8b\xec", raw):
        starts.add(va_base + m.start())
    # 4. direct-call targets (e8 rel16) inside the region
    try:
        import capstone

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    except Exception:
        md = None
    if md is not None:
        for insn in md.disasm(raw, va_base):
            if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
                try:
                    tgt = int(insn.op_str, 16)
                except ValueError:
                    continue
                if va_base <= tgt < va_base + n:
                    starts.add(tgt)

    # Sizes: extent up to the next candidate (linear-sweep convention);
    # the last candidate runs to the end of the code region.
    ordered = sorted(starts)
    region_end = va_base + n
    out: list[tuple[int, int, str]] = []
    for i, va in enumerate(ordered):
        end = ordered[i + 1] if i + 1 < len(ordered) else region_end
        out.append((va, max(0, end - va), f"fcn.{va:04x}"))
    return out


def _is_discovery_result(found: Any) -> bool:
    """True when *found* is a list of ``(va >= 0, size >= 0, name: str)`` rows."""
    return isinstance(found, list) and all(
        isinstance(row, tuple)
        and len(row) == 3
        and isinstance(row[0], int)
        and isinstance(row[1], int)
        and isinstance(row[2], str)
        and row[0] >= 0
        and row[1] >= 0
        for row in found
    )


def _run_providers(
    names: list[str], binary: Path, d: Discovery
) -> dict[str, list[tuple[int, int, str]]]:
    """Run named providers, recording per-source counts on *d*.

    A provider that raises, or returns anything but a list of
    ``(va: int >= 0, size: int >= 0, name: str)`` rows, is recorded as empty
    (one broken backend cannot abort the merge).  Returns
    ``{name: [(va, size, name)]}``.
    """
    out: dict[str, list[tuple[int, int, str]]] = {}
    for name in names:
        fn = _DISCOVERER_MAP.get(name)
        if fn is None:
            continue
        try:
            found = fn(binary)
        except Exception as exc:
            logger.warning("discoverer %r failed (skipped): %s", name, exc)
            found = []
        if not _is_discovery_result(found):
            logger.warning(
                "discoverer %r returned %s (expected list[(va, size, name)]; skipped)",
                name,
                type(found).__name__,
            )
            found = []
        d.sources[name] = len(found)
        out[name] = found
    return out


def _merge_union(
    found: dict[str, list[tuple[int, int, str]]], *, min_size: int = 0
) -> dict[int, tuple[int, str]]:
    """Prefer-larger-size union over provider outputs."""
    merged: dict[int, tuple[int, str]] = {}
    for funcs in found.values():
        for va, size, name in funcs:
            if min_size and size < min_size:
                continue
            cur = merged.get(va)
            if cur is None or size > cur[0]:
                merged[va] = (size, name)
    return merged


def discover_functions(binary: Path, *, min_size: int = 8) -> Discovery:
    """Chain packaged + plugin discoverers and merge into validated functions.

    Format branches keep their size semantics: 16-bit NE binaries use the
    native NE loader only (rizin output is garbage file-offset
    "functions" \u2014 the 233-function false enumeration that once polluted
    the SkiFree intake); plain DOS MZ binaries use the 16-bit sweep with
    gap-to-next sizing (no symbol table); everything else merges the rizin
    strategies with the capstone sweep and refines sizes against the binary.
    Plugin discoverers (``rebrew.discoverers``) join every branch under
    their entry-point name.
    """
    from rebrew.binary_loader import is_mz, is_ne, load_binary

    d = Discovery()
    plugins = [n for n in _DISCOVERER_MAP if n not in _PACKAGED_DISCOVERERS]

    if is_ne(binary):
        merged = _merge_union(_run_providers(["ne loader", *plugins], binary, d), min_size=min_size)
        d.functions = sorted((va, size, name) for va, (size, name) in merged.items())
        return d

    if is_mz(binary):
        # Sizes are unknown in a bare MZ sweep (no symbol table) — estimate
        # each candidate's extent as the gap to the next candidate so
        # --min-size is honored (a size-0 filter would drop everything).
        merged = _merge_union(_run_providers(["mz sweep", *plugins], binary, d))
        pairs = sorted(merged.items())
        sized: list[tuple[int, int, str]] = []
        for idx, (va, (_size, name)) in enumerate(pairs):
            nxt = pairs[idx + 1][0] if idx + 1 < len(pairs) else va + 0x100
            sized.append((va, max(1, nxt - va), name))
        d.functions = [f for f in sized if f[1] >= min_size]
        return d

    found = _run_providers(["rizin aaa", "rizin aa;aap", "eh_frame", "pdata", *plugins], binary, d)
    # Merge: prefer-larger-size union over every provider (rizin strategies
    # and plugins alike); the merged-rizin count tracks the rizin pair only.
    merged = _merge_union(found)
    d.sources["merged-rizin"] = len(
        _merge_union({k: found[k] for k in ("rizin aaa", "rizin aa;aap") if k in found})
    )

    # Add capstone sweep candidates not already present.
    sweep = _run_providers(["capstone sweep"], binary, d)["capstone sweep"]
    sweep_names = {va: name for va, _, name in sweep}
    for va in sweep_names:
        if va not in merged:
            merged[va] = (0, sweep_names[va])
    d.sources["capstone sweep"] = len(sweep_names)

    # An unwind record is the compiler's own statement of a function's extent:
    # any other candidate inside one is a branch target, not a function.
    unwind = {
        va: size for source in ("eh_frame", "pdata") for va, size, _name in found.get(source, [])
    }
    extents = sorted(unwind.items())
    if extents:
        merged = {va: entry for va, entry in merged.items() if not _inside_an_extent(extents, va)}

    # Validate: drop candidates that fall inside a larger span.
    ordered = sorted(merged.items())
    kept: dict[int, tuple[int, str]] = {}
    for i, (va, (size, name)) in enumerate(ordered):
        nxt_va = ordered[i + 1][0] if i + 1 < len(ordered) else None
        if nxt_va is not None and nxt_va - va <= 2:
            continue  # duplicate/adjacent junk
        kept[va] = (size, name)

    funcs: list[tuple[int, int, str]] = [
        (va, size, name) for va, (size, name) in sorted(kept.items())
    ]

    # Refine sizes against the binary (first-ret).
    try:
        info = load_binary(binary)
        funcs = _validate_and_refine(info, funcs, vouched=frozenset(unwind))
    except Exception as exc:
        # Unvalidated gap-based sizes are still emitted, but the user must
        # know the refine pass was skipped.
        logger.warning("size refine step failed (emitting unvalidated sizes): %s", exc)

    funcs = [(va, unwind.get(va, size), name) for va, size, name in funcs]
    funcs = [f for f in funcs if f[1] >= min_size]
    d.functions = funcs
    return d


@app.callback(invoke_without_command=True)
def main(
    binary: str = typer.Argument(..., help="Path to the target binary."),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write function_structure.json to this path (default: stdout as text).",
    ),
    min_size: int = typer.Option(8, "--min-size", help="Drop functions smaller than this."),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Enumerate functions with chained strategies and validated sizes."""
    bin_path = Path(binary)
    if not bin_path.exists():
        msg = f"binary not found: {bin_path}"
        error_exit(msg, json_mode=json_output)

    d = discover_functions(bin_path, min_size=min_size)
    text = "".join(f"0x{va:08x} {name} {size}\n" for va, size, name in d.functions)

    if output:
        import json

        Path(output).parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(
            Path(output),
            json.dumps(
                [{"va": va, "size": size, "name": name} for va, size, name in d.functions],
                indent=2,
            )
            + "\n",
        )

    if json_output:
        json_print(
            {
                "binary": str(bin_path),
                "functions": len(d.functions),
                "sources": d.sources,
                "output": output,
                "sample": [
                    {"va": f"0x{va:08x}", "size": size, "name": name}
                    for va, size, name in d.functions[:10]
                ],
            }
        )
    else:
        console.print(f"[green]{len(d.functions)} functions[/green] from {d.sources}")
        if output:
            console.print(f"  wrote {output}")
        else:
            print(text, end="")


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
