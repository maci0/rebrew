"""omf16.py — minimal 16-bit OMF parser (MSVC 1.52 dialect).

MSVC 1.52 emits a 16-bit OMF dialect that objconv crashes on (buffer
overflow) and LIEF cannot parse.  Empirically mapped (docs/OMF_NOTES.md):

- **Unoptimized dialect** (no /O flags):
  - ``0xA0`` records carry the code: ``[seg:1][offset:2 LE][code...]``
  - ``0x90`` MODEND carries the public symbols: ``[len][name][offset:2 LE]``
    (verified: `_main` @ 0x1a lands exactly at the second function in the
    concatenated code stream of a real compile_c object).
- **Optimized dialect** (/O1 etc. — the GA flag sweep's default):
  - ``0xC2`` records carry the code: ``[header][code...][checksum:1]``
    (one record per function, trailing byte makes the record sum ≡ 0 mod 256).
    The header length depends on the **code model**: near-code models
    (/AS small, /AC compact) use a 9-byte header and name the code segment
    ``_TEXT``; far-code models (/AM medium, /AL large) use a **7-byte
    header** and name it ``SRC_TEXT``.  The GRPDEF code-segment name picks
    the length.
  - ``0x96`` = public name list ``[len][name]...`` (distinct from the
    unoptimized GRPDEF ``0x96`` which starts with a ``00`` byte).
  - ``0xCA`` = static (local) name list ``[len][name]...``.
  - Name records (0xCA then 0x96) appear in the same order as their
    0xC2 code records, so function ``i`` maps to code record ``i``.

This parser extracts function code bytes + public offsets — enough for
`parse_obj_symbol_and_relocs` to serve the 16-bit path.  Reloc slots are
the ``e8``/``e9`` rel16 displacement positions **plus** absolute ``disp16``
operands (global-variable access: ``a0-a3`` moffs forms and modrm
``mod=00 rm=110``), located via capstone (the 0x8C/0x9C fixup records are
documented follow-up).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


class Omf16Error(RuntimeError):
    """The object is not a decodable 16-bit MSVC OMF."""


@dataclass
class Omf16Module:
    """Decoded 16-bit OMF: concatenated code + public symbol offsets."""

    code: bytes = b""
    publics: dict[str, int] = field(default_factory=dict)  # name -> code offset
    # Optimized dialect: one code record per function, in name-record order.
    # ``names`` is the concatenation of the 0xCA (static) and 0x96 (public)
    # name lists in stream order; ``code_records[i]`` is function ``i``'s
    # code bytes.
    names: list[str] = field(default_factory=list)
    code_records: list[bytes] = field(default_factory=list)


def _record_len(data: bytes, pos: int) -> int:
    """Length (incl. checksum) of the record starting at *pos*, or 0."""
    if pos + 3 > len(data):
        return 0
    ln = (data[pos + 1] | (data[pos + 2] << 8)) & 0x7FFF
    if ln < 1 or pos + 3 + ln > len(data):
        return 0
    return ln


def _parse_name_list(body: bytes) -> list[str]:
    """Parse ``[len][name]...`` name lists (0x96 publics, 0xCA statics)."""
    names: list[str] = []
    i = 0
    while i < len(body):
        ln = body[i]
        if ln == 0 or i + 1 + ln > len(body):
            break
        raw = body[i + 1 : i + 1 + ln]
        if all(32 <= c < 127 for c in raw):
            names.append(raw.decode("ascii", "replace"))
        i += 1 + ln
    return names


def is_omf16(data: bytes) -> bool:
    """True when *data* looks like the MSVC 1.52 16-bit OMF dialect (an
    ``0xA0`` or ``0xC2`` code record present)."""
    pos = 0
    while pos + 3 <= len(data):
        t = data[pos]
        ln = _record_len(data, pos)
        if ln == 0:
            return False
        if t in (0xA0, 0xC2):
            return True
        pos += 3 + ln
    return False


def parse_omf16(data: bytes) -> Omf16Module:
    """Parse the 16-bit MSVC OMF dialect (see module docstring).

    Handles both the unoptimized (0xA0 code + 0x90 publics) and the
    optimized (0xC2 code + 0x96/0xCA name lists) dialects, and both code
    models within the optimized dialect (near-code 9-byte 0xC2 header vs
    far-code 7-byte — the GRPDEF code-segment name ``_TEXT``/``SRC_TEXT``
    picks the length).
    """
    mod = Omf16Module()
    pos = 0
    saw_code = False
    c2_bodies: list[bytes] = []
    grp_names: list[str] = []
    while pos + 3 <= len(data):
        t = data[pos]
        ln = _record_len(data, pos)
        if ln == 0:
            break
        body = data[pos + 3 : pos + 3 + ln]
        if t == 0xA0:
            saw_code = True
            off = int.from_bytes(body[1:3], "little")
            code_chunk = body[3:]
            # TCC/wcc16 end their LEDATA records with an OMF checksum byte
            # (whole record incl. type+length ≡ 0 mod 256); MSVC 1.52 does
            # not.  Detect by the record sum and drop it — otherwise the
            # code slice carries a spurious trailing byte that breaks
            # byte-matching.
            if code_chunk and ((sum(body) + t + (ln & 0xFF) + ((ln >> 8) & 0xFF)) % 256 == 0):
                code_chunk = code_chunk[:-1]
            if len(mod.code) < off + len(code_chunk):
                mod.code = mod.code.ljust(off + len(code_chunk), b"\x00")
            mod.code = mod.code[:off] + code_chunk + mod.code[off + len(code_chunk) :]
        elif t == 0xC2:  # optimized dialect: one code record per function
            saw_code = True
            c2_bodies.append(body)
        elif t == 0x90:  # MODEND — public name/offset pairs (unoptimized)
            i = 0
            while i + 3 <= len(body):
                ln2 = body[i]
                if ln2 == 0 or i + 1 + ln2 + 2 > len(body):
                    i += 1
                    continue
                name = body[i + 1 : i + 1 + ln2]
                if all(32 <= c < 127 for c in name):
                    mod.publics[name.decode("ascii", "replace")] = int.from_bytes(
                        body[i + 1 + ln2 : i + 3 + ln2], "little"
                    )
                    i += 1 + ln2 + 2
                else:
                    i += 1
        elif t == 0x96 and body and body[0] != 0x00:
            # optimized dialect: public name list (unoptimized GRPDEF
            # starts with a 00 group-index byte).
            mod.names.extend(_parse_name_list(body))
        elif t == 0x96 and body and body[0] == 0x00:
            # GRPDEF — capture the code-segment name to pick the 0xC2
            # header length (near "_TEXT" -> 9B, far "SRC_TEXT" -> 7B).
            grp_names.extend(_parse_name_list(body[1:]))
        elif t == 0xCA:  # optimized dialect: static (local) name list
            mod.names.extend(_parse_name_list(body))
        pos += 3 + ln
    if not saw_code:
        raise Omf16Error("no 0xA0/0xC2 code record — not a 16-bit MSVC OMF")
    # Slice the collected 0xC2 bodies now that the code model is known:
    # far-code models (SRC_TEXT segment) carry a 7-byte header.
    header_len = 7 if "SRC_TEXT" in grp_names else 9
    for body in c2_bodies:
        if len(body) > header_len:
            code_chunk = body[header_len:-1]  # trailing byte = checksum
            mod.code_records.append(code_chunk)
            mod.code += code_chunk
    return mod


_CS_PREFIXES = {0x66, 0x67, 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0xF0, 0xF2, 0xF3}
_CS_MOFFS = {0xA0, 0xA1, 0xA2, 0xA3}  # mov al/ax, moffs / mov moffs, al/ax


def _code_relocs(code: bytes, start: int, end: int) -> dict[int, str]:
    """Reloc slots within ``code[start:end]``, offsets relative to *start*.

    16-bit MSVC codegen never emits literal ``e8``/``e9`` opcodes (calls and
    jumps are always linker-patched rel16 slots), so every ``e8``/``e9``
    marks a 2-byte relocation at ``opcode+1``.  Global-variable access adds
    absolute ``disp16`` slots: the ``a0-a3`` moffs forms (``mov ax,[g]``)
    and any modrm with ``mod=00 rm=110`` (``add ax,[g]``, ``push [g]``...).
    Far-code models add ``lcall``/``ljmp`` (``9a``/``ea``) — a 4-byte
    ptr16:16 patch slot.  Capstone (already a matcher dependency) locates
    these operands exactly; the pure e8/e9 scan is the fallback when
    capstone is unavailable."""
    import capstone

    relocs: dict[int, str] = {}
    # e8/e9 rel16 slots — always apply (byte scan, cheap)
    for i in range(start, end):
        if code[i] in (0xE8, 0xE9) and i + 2 < end:
            relocs[i + 1 - start] = "rel16"
    # disp16 absolute-operand slots via capstone (locates them exactly)
    try:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
        md.detail = True
    except Exception:  # pragma: no cover — capstone is a core dep
        return relocs
    for insn in md.disasm(code[start:end], 0):
        raw = bytes(insn.bytes)
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
                i = 0
                while i < len(raw) and raw[i] in _CS_PREFIXES:
                    i += 1
                opcode = raw[i] if i < len(raw) else 0
                if opcode in _CS_MOFFS:
                    relocs[insn.address + i + 1] = "disp16"
                    continue
                if opcode == 0x0F:
                    i += 2
                else:
                    i += 1
                if i < len(raw) and raw[i] & 0xC7 == 0x06:
                    relocs[insn.address + i + 1] = "disp16"
            # far-call/jump: 9a/ea opcode + 4-byte ptr16:16 patch slot
            if op.type == capstone.x86.X86_OP_IMM and insn.mnemonic in ("lcall", "ljmp"):
                relocs[insn.address + 1] = "far16"
    return relocs


def _match_symbol(mod: Omf16Module, symbol: str) -> tuple[bytes | None, dict[int, str]]:
    """Return ``(code_bytes, reloc_offsets)`` for *symbol*, or ``(None, {})``.

    Tries both dialects: offset-based publics (unoptimized) and
    order-mapped name records (optimized)."""
    candidates = [symbol]
    if symbol.startswith("_"):
        candidates += [symbol[1:], symbol[1:] + "_"]
    else:
        candidates += ["_" + symbol, symbol + "_"]
    # Borland pascal convention: the symbol is emitted UPPERCASE without a
    # leading underscore (``void far *pascal f(...)`` → ``F``), while the
    # C-level name is lowercase — match that dialect too.
    candidates += [symbol.strip("_").upper()]
    for name in candidates:
        if name in mod.publics:  # unoptimized dialect
            off = mod.publics[name]
            end = len(mod.code)
            for other in mod.publics.values():
                if other > off and other < end:
                    end = other
            return mod.code[off:end], _code_relocs(mod.code, off, end)
        if name in mod.names:  # optimized dialect: order-mapped records
            idx = mod.names.index(name)
            if idx < len(mod.code_records):
                rec = mod.code_records[idx]
                return rec, _code_relocs(rec, 0, len(rec))
    return None, {}


def parse_obj_omf16(obj_path: str | Path, symbol: str) -> tuple[bytes | None, dict[int, str]]:
    """Extract ``(code_bytes, reloc_offsets)`` for *symbol* from a 16-bit OMF.

    The symbol is matched across compiler conventions (``_name``/``name_``/
    ``name``); reloc slots are the ``e8``/``e9`` displacement positions."""
    data = Path(obj_path).read_bytes()
    mod = parse_omf16(data)
    return _match_symbol(mod, symbol)


__all__ = ["Omf16Error", "Omf16Module", "is_omf16", "parse_omf16", "parse_obj_omf16"]
