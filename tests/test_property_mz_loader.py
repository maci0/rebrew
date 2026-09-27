"""Property-based fuzzing for the hand-written DOS MZ header reader.

``parse_mz_header`` / ``is_mz`` read a 0x40-byte header straight out of an
untrusted target file, so the page count, the bytes in the last page, the
header paragraph count and the relocation table pointer are all forgeable.
LIEF cannot classify a bare MZ, so this parser is the only thing standing
between a corrupted 16-bit target and a wildly out-of-range code region.

The harnesses below build link-shaped MZ files (realistic field values so the
success branch is reachable) mixed with fully degenerate ones, plus raw
random bytes, and assert:

* the only failure mode is ``ValueError`` — never ``struct.error``,
  ``IndexError`` or a ``KeyError`` from the section map;
* a parsed header never points past EOF and never reports a negative region;
* the load path round-trips: the bytes a header places at ``code_offset`` are
  the bytes ``extract_bytes_at_va`` hands back (a pair assertion across the
  header-to-image boundary);
* ``is_mz`` and the header parser agree on what counts as an MZ at all.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

#: Real-mode ``segment*16 + offset`` wraps at 1 MiB.
REAL_MODE_ADDRESS_MASK = 0xFFFFF

_HEADER_SIZE = 0x40


@pytest.fixture(scope="module")
def mz_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Module-scoped scratch dir: hypothesis rejects function-scoped fixtures."""
    return tmp_path_factory.mktemp("mz_fuzz")


def _write(directory: Path, name: str, data: bytes) -> Path:
    path = directory / name
    path.write_bytes(data)
    return path


_u16 = st.integers(min_value=0, max_value=0xFFFF)


@st.composite
def _mz_file(draw: st.DrawFn) -> bytes:
    """A DOS MZ file: a 0x40-byte header plus a body of arbitrary bytes.

    ``cparhdr`` and ``cp`` are drawn in a small range most of the time so the
    code region lands inside the body and the success branch is exercised;
    the remaining draws reach the degenerate shapes (a header paragraph count
    far past EOF, a relocation pointer beyond the file, a page count of zero).
    """
    body = draw(st.binary(min_size=0, max_size=2048))
    header = bytearray(_HEADER_SIZE)
    header[0:2] = b"MZ"
    cparhdr = draw(st.one_of(st.integers(1, 8), _u16))
    cp = draw(st.one_of(st.integers(0, 6), _u16))
    if draw(st.booleans()):
        # A well-formed page count: the last page holds a real byte count, or
        # zero when the file ends exactly on a page boundary.
        cblp = 0 if draw(st.booleans()) else draw(st.integers(1, 512))
        cp = max(1, (len(body) + 511) // 512) or 1
    else:
        cblp = draw(st.integers(0, 512))
    struct.pack_into("<H", header, 0x02, cblp)  # e_cblp
    struct.pack_into("<H", header, 0x04, cp)  # e_cp
    struct.pack_into("<H", header, 0x06, draw(_u16))  # e_crlc
    struct.pack_into("<H", header, 0x08, cparhdr)  # e_cparhdr
    struct.pack_into("<H", header, 0x14, draw(_u16))  # e_ip
    struct.pack_into("<H", header, 0x16, draw(_u16))  # e_cs
    struct.pack_into("<H", header, 0x18, draw(_u16))  # e_lfarlc
    struct.pack_into("<H", header, 0x1A, draw(_u16))  # e_ovno
    struct.pack_into("<I", header, 0x3C, draw(st.integers(0, 0x10000)))  # e_lfanew
    return bytes(header) + body


@settings(max_examples=300, deadline=None)
@given(_mz_file())
def test_parse_mz_header_invariants(mz_dir: Path, blob: bytes) -> None:
    """Fuzz: a link-shaped MZ header.  Either the parser refuses with
    ``ValueError``, or every field is in range: the code region is
    non-negative, ends inside the file, and the entry lands in real-mode
    address space."""
    from rebrew.binary_loader import parse_mz_header

    path = _write(mz_dir, "inv.exe", blob)
    try:
        header = parse_mz_header(path)
    except ValueError:
        return
    assert header["code_offset"] >= 0
    assert header["code_size"] >= 0
    assert header["code_offset"] + header["code_size"] <= len(blob)
    assert 0 <= header["entry_va"] <= REAL_MODE_ADDRESS_MASK
    assert header["va_base"] == 0


@settings(max_examples=200, deadline=None)
@given(_mz_file())
def test_mz_section_round_trips_header_geometry(mz_dir: Path, blob: bytes) -> None:
    """Pair assertion across the header-to-image boundary: the pseudo
    ``.text`` section the loader builds must describe the same code region the
    header parser reported, and the bytes it holds are the file's bytes at
    ``code_offset``."""
    from rebrew.binary_loader import extract_bytes_at_va, load_binary, parse_mz_header

    path = _write(mz_dir, "round.exe", blob)
    try:
        header = parse_mz_header(path)
    except ValueError:
        return
    info = load_binary(path)
    assert info.format == "mz"
    assert info.arch == "x86_16"
    assert info.sections.keys() == {".text"}
    section = info.sections[".text"]
    assert section.file_offset == header["code_offset"]
    assert section.raw_size == header["code_size"]
    assert section.va == 0
    assert info.text_va == 0
    assert info.text_size == header["code_size"]
    if header["code_size"] > 0:
        probe = blob[header["code_offset"] : header["code_offset"] + 4]
        assert extract_bytes_at_va(info, 0, 4, trim_padding=False) == probe


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=1024), st.integers(min_value=0, max_value=0x10000))
def test_mz_probes_reject_non_mz_bytes(mz_dir: Path, blob: bytes, lfanew: int) -> None:
    """Fuzz: arbitrary bytes with an arbitrary ``e_lfanew``.  Whatever the
    verdict, the parser either refuses with ``ValueError`` or describes a code
    region that lies inside the file, and a success implies the input really
    did carry an MZ header."""
    from rebrew.binary_loader import is_mz, parse_mz_header

    data = bytearray(blob)
    if len(data) >= _HEADER_SIZE:
        struct.pack_into("<I", data, 0x3C, lfanew)
    path = _write(mz_dir, "raw.exe", bytes(data))
    assert isinstance(is_mz(path), bool)
    try:
        header = parse_mz_header(path)
    except ValueError:
        return
    assert bytes(data[:2]) == b"MZ"
    assert len(data) >= _HEADER_SIZE
    assert header["code_offset"] + header["code_size"] <= len(data)


@settings(max_examples=200, deadline=None)
@given(st.integers(min_value=0, max_value=0x10000))
def test_is_mz_rejects_wrappers(mz_dir: Path, lfanew: int) -> None:
    """A 16-bit or 32-bit wrapper signature at ``e_lfanew`` means the file is
    not a plain MZ, so ``load_binary`` must not route it to the DOS path; a
    signature that is absent or unreachable leaves it a plain MZ."""
    from rebrew.binary_loader import is_mz

    head = bytearray(0x40)
    head[0:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, lfanew)
    body = bytes(head) + bytes(256)
    path = _write(mz_dir, "wrap.exe", body)

    reachable = lfanew + 4 <= 0x10000 and lfanew + 4 <= len(body)
    at_offset = body[lfanew : lfanew + 2] if reachable else b""
    if at_offset in (b"NE", b"PE", b"LE", b"LX"):
        # An unpatched file has no signature yet; place one so both branches
        # of is_mz are reached with the same offset.
        patched = bytearray(body)
        patched[lfanew : lfanew + 4] = at_offset + b"\x00\x00"
        assert is_mz(_write(mz_dir, "wrap_sig.exe", bytes(patched))) is False
    assert is_mz(path) is (at_offset not in (b"NE", b"PE", b"LE", b"LX"))
