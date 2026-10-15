"""LIEF COFF parsing with canonical symbol names and retained object ownership."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import lief


def _coff_symbol_names(data: bytes) -> list[str]:
    """Resolve standard COFF names, including suffixes shared in the string table."""
    if len(data) < 20:
        return []
    offset, count = struct.unpack_from("<II", data, 8)
    end = offset + count * 18
    if offset < 20 or end + 4 > len(data):
        return []
    length = struct.unpack_from("<I", data, end)[0]
    strings = data[end : end + length]
    names = []
    index = 0
    while index < count:
        entry = offset + index * 18
        raw = data[entry : entry + 8]
        if raw[:4] == b"\0" * 4:
            start = struct.unpack_from("<I", raw, 4)[0]
            raw = strings[start:] if 4 <= start < len(strings) else b""
        names.append(raw.split(b"\0", 1)[0].decode("utf-8", errors="replace"))
        index += 1 + data[entry + 17]
    return names


def load_coff(
    obj_data: bytes,
) -> tuple[lief.COFF.Binary, list[lief.COFF.Symbol], list[str]] | None:
    """Parse a COFF object with LIEF; return the binary, its symbols, and their names.

    ``None`` when the bytes are too short or LIEF rejects them.  A name LIEF
    leaves empty (a suffix shared in the string table) is read from the raw
    symbol table.  Stock MSVC tcmap members have machine=0 and one empty
    ``.text`` section; LIEF rejects that machine, so only the in-memory parser
    input is normalized.  The library on disk and the linker's inputs remain
    untouched.  The symbols are views into the binary: keep the binary
    referenced while they are used, or LIEF frees them under the caller.
    """
    import lief

    if len(obj_data) < 20:
        return None
    parse_data = b"\x4c\x01" + obj_data[2:] if obj_data[:4] == b"\0\0\x01\0" else obj_data
    coff = lief.COFF.parse(list(parse_data))
    if coff is None:
        return None
    symbols = list(coff.symbols)
    raw_names = _coff_symbol_names(obj_data)
    names = [
        str(sym.name) or (raw_names[i] if len(raw_names) == len(symbols) else "")
        for i, sym in enumerate(symbols)
    ]
    return coff, symbols, names
