"""omf16.py — minimal 16-bit OMF parser (MSVC 1.52 dialect).

MSVC 1.52 emits a 16-bit OMF dialect that objconv crashes on (buffer
overflow) and LIEF cannot parse.  Empirically mapped (docs/OMF_NOTES.md):

- ``0xA0`` records carry the code: ``[seg:1][offset:2 LE][code...]``
- ``0x90`` MODEND carries the public symbols: ``[len][name][offset:2 LE]``
  (verified: `_main` @ 0x1a lands exactly at the second function in the
  concatenated code stream of a real compile_c object).

This parser extracts function code bytes + public offsets — enough for
`parse_obj_symbol_and_relocs` to serve the 16-bit path (relocs are not yet
decoded; the 0x8C/0xB2 fixup records are documented follow-up).
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


def detect_omf16(data: bytes) -> bool:
    """True when *data* looks like the MSVC 1.52 16-bit OMF dialect (an
    ``0xA0`` code record present)."""
    pos = 0
    while pos + 3 <= len(data):
        t = data[pos]
        ln = (data[pos + 1] | (data[pos + 2] << 8)) & 0x7FFF
        if ln < 1 or pos + 3 + ln > len(data):
            return False
        if t == 0xA0:
            return True
        pos += 3 + ln
    return False


def parse_omf16(data: bytes) -> Omf16Module:
    """Parse the 16-bit MSVC OMF dialect (see module docstring)."""
    mod = Omf16Module()
    pos = 0
    saw_code = False
    while pos + 3 <= len(data):
        t = data[pos]
        ln = (data[pos + 1] | (data[pos + 2] << 8)) & 0x7FFF
        if ln < 1 or pos + 3 + ln > len(data):
            break
        body = data[pos + 3 : pos + 3 + ln]
        if t == 0xA0:
            saw_code = True
            off = int.from_bytes(body[1:3], "little")
            code_chunk = body[3:]
            if len(mod.code) < off + len(code_chunk):
                mod.code = mod.code.ljust(off + len(code_chunk), b"\x00")
            mod.code = mod.code[:off] + code_chunk + mod.code[off + len(code_chunk) :]
        elif t == 0x90:  # MODEND — public name/offset pairs
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
        pos += 3 + ln
    if not saw_code:
        raise Omf16Error("no 0xA0 code record — not a 16-bit MSVC OMF")
    return mod


def parse_obj_omf16(obj_path: str | Path, symbol: str) -> tuple[bytes | None, dict[int, str]]:
    """Extract ``(code_bytes, reloc_offsets)`` for *symbol* from a 16-bit OMF.

    The symbol is matched across compiler conventions (``_name``/``name_``/
    ``name``); relocs are not yet decoded (empty dict)."""
    data = Path(obj_path).read_bytes()
    mod = parse_omf16(data)
    candidates = [symbol]
    if symbol.startswith("_"):
        candidates += [symbol[1:], symbol[1:] + "_"]
    else:
        candidates += ["_" + symbol, symbol + "_"]
    for name in candidates:
        if name in mod.publics:
            off = mod.publics[name]
            end = len(mod.code)
            for other in mod.publics.values():
                if other > off and other < end:
                    end = other
            return mod.code[off:end], {}
    return None, {}


__all__ = ["Omf16Error", "Omf16Module", "detect_omf16", "parse_omf16", "parse_obj_omf16"]
