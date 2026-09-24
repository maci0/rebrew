"""vtordisp.py — find multiple-inheritance thunk (vtordisp) functions.

Adapted from reccmp (isledecomp/reccmp, MIT License) ``analysis/vtordisp.py``.

An MSVC vtordisp thunk adjusts ``this`` (``sub ecx, <disp>``) and jumps to
the base-class implementation.  Three shapes exist:

- ``vtordisp{disp, 0}``        — 8 bytes  (``2B 49 d8`` + ``E9 rel32``)
- ``vtordisp{disp, addend}``   — 14 bytes (``2B 49 d8`` + ``81 C1 imm32`` + ``E9 rel32``)
- ``vtordisp{disp, -addend}``  — 11 bytes (``2B 49 d8`` + ``83 E9 imm8`` + ``E9 rel32``)

Scanning the raw code bytes (no disassembly) is both faster and safer than
linear disassembly: thunks are data-like 8-14 byte islands the linker may
place between functions.
"""

from __future__ import annotations

import re
import struct
from collections.abc import Iterator
from dataclasses import dataclass

# Each vtordisp function begins with `sub ecx, <byte>`.
_VTOR_START_RE = re.compile(rb"\x2b\x49")

# n.b. These regexes use positive lookahead to support overlapping matches —
# checking only spots where `2B 49` occurs is faster than scanning the whole
# code section for each shape.

# vtordisp{byte, 0} -- 8 bytes
_VTOR_RE = re.compile(rb"(?=\x2b\x49(.)\xe9(.{4}))", flags=re.S)

# vtordisp{byte, dword} -- 14 bytes
_VTOR_ADD_RE = re.compile(rb"(?=\x2b\x49(.)\x81\xc1(.{4})\xe9(.{4}))", flags=re.S)

# vtordisp{byte, byte} - 11 bytes
_VTOR_SUB_RE = re.compile(rb"(?=\x2b\x49(.)\x83\xe9(.)\xe9(.{4}))", flags=re.S)


@dataclass(frozen=True)
class VtordispFunction:
    """One detected vtordisp thunk.

    ``disp`` is the ``this`` adjustment; ``addend`` an optional second
    adjustment (positive via ``add ecx``, negative via ``sub ecx``);
    ``func_addr`` the thunk target; ``size`` the thunk's byte length.
    """

    addr: int
    disp: int
    addend: int
    func_addr: int
    size: int


def find_vtordisps(code: bytes, base_addr: int = 0) -> Iterator[VtordispFunction]:
    """Yield every vtordisp thunk in *code* (``base_addr`` + offset = VA)."""
    for start_match in _VTOR_START_RE.finditer(code):
        start = start_match.start()
        view = memoryview(code)[start:]
        addr = base_addr + start

        # (disp, addend, size, regex) checked in the same order as reccmp:
        # the 14-byte shape must be tested before the 8-byte one or its
        # prefix would match first.
        for regex, unpackers, size, addend_of in (
            (_VTOR_ADD_RE, ("b", "<i", "<i"), 14, lambda g: g[1]),
            (_VTOR_SUB_RE, ("b", "b", "<i"), 11, lambda g: -g[1]),
            (_VTOR_RE, ("b", "<i"), 8, lambda g: 0),
        ):
            m = regex.match(view)
            if m is None:
                continue
            groups = [
                struct.unpack(fmt, bytes(m.group(i + 1)))[0] for i, fmt in enumerate(unpackers)
            ]
            jmp_rel = groups[-1]
            yield VtordispFunction(
                addr=addr,
                disp=groups[0],
                addend=addend_of(groups),
                func_addr=addr + size + jmp_rel,
                size=size,
            )
            break
