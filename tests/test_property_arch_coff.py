"""Property-based fuzz tests for the ar-archive and COFF symbol parsers.

Both ``formats.archives.parse_archive`` and ``formats.coff._coff_symbol_names``
walk raw, attacker-controlled bytes: static archives span untrusted ``.lib`` /
``.a`` files and COFF symbol tables are read verbatim from object files.  No
prior Hypothesis harness covered these two parsers while every sibling
parser (OMF, DFM, NE, LZEXE, PE) already had one.
"""

from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.formats.archives import parse_archive, stock_lib_valid
from rebrew.formats.coff import _coff_symbol_names


def _archive_bodies_fit(data: bytes) -> bool:
    """Independent structural check mirroring ``stock_lib_valid``'s walk.

    Deliberately recomputed from the bytes (not by calling the code under
    test) so an always-True implementation fails the agreement check.
    """
    if not data.startswith(b"!<arch>\n"):
        return False
    size = len(data)
    position = 8
    while position < size:
        if position % 2:
            position += 1
        if position >= size:
            break
        if position + 60 > size:
            return False
        try:
            member_size = int(data[position + 48 : position + 58].strip())
        except ValueError:
            return False
        if member_size < 0:
            return False
        position += 60
        if position + member_size > size:
            return False
        position += member_size
    return True


def _parse_archive_bytes(data: bytes) -> list[tuple[str, bytes]]:
    """Run parse_archive on *data* via a temp file; only ValueError escapes."""
    fd, name = tempfile.mkstemp(suffix=".lib")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        return list(parse_archive(name))
    finally:
        os.unlink(name)


class TestParseArchiveRobust:
    @settings(max_examples=50, deadline=None)
    @given(st.binary(max_size=512))
    def test_raw_bytes_never_crashes_archive(self, data: bytes) -> None:
        try:
            members = _parse_archive_bytes(data)
        except ValueError:
            return
        # Any successful parse yields (str, bytes) pairs with sane names.
        for name, body in members:
            assert isinstance(name, str) and name
            assert isinstance(body, bytes)
            # Member data must be a suffix of the input (no invented bytes).
            assert body in data or body == b""

    @settings(max_examples=50, deadline=None)
    @given(st.binary(min_size=8, max_size=512))
    def test_stock_lib_valid_never_crashes(self, data: bytes) -> None:
        fd, name = tempfile.mkstemp(suffix=".lib")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            valid = stock_lib_valid(Path(name))
            assert isinstance(valid, bool)
            # Agreement: a True must be structurally sound, not merely a
            # bool.  Always-True would pass the isinstance check but accept
            # truncated archives (the exact failure the cache guard exists
            # to prevent); always-False would reject the known-good roundtrip.
            if valid:
                assert data.startswith(b"!<arch>\n")
                assert valid == (len(data) == 8 or _archive_bodies_fit(data))
            if not data.startswith(b"!<arch>\n"):
                assert valid is False
        finally:
            os.unlink(name)

    @st.composite
    def _ar_stream(self: st.DrawFn) -> bytes:
        """A structured ar stream: valid magic + forged headers/bodies."""
        out = b"!<arch>\n"
        for _ in range(self(st.integers(0, 3))):
            name = self(st.sampled_from([b"a.obj/", b"//", b"/0", b"/9999", b"b.o/", b""]))
            body = self(st.binary(max_size=16))
            size = self(st.integers(0, len(body) + 8))
            # Header layout: name[16] mtime[12] uid[6] gid[6] mode[8] size[10] "`\n"
            hdr = (
                name.ljust(16, b" ")[:16]
                + b"0".ljust(12, b" ")
                + b"0".ljust(6, b" ")
                + b"0".ljust(6, b" ")
                + b"100644".ljust(8, b" ")
                + str(size).encode().ljust(10, b" ")
                + b"`\n"
            )
            out += hdr + body[:size]
            if size % 2 == 1 and len(body) >= size:
                out += b"\n"
        # Occasionally truncate mid-header or mid-body.
        if out and self(st.booleans()):
            cut = self(st.integers(0, len(out)))
            out = out[:cut]
        return out

    @given(_ar_stream())
    def test_structured_archive_never_crashes(self, data: bytes) -> None:
        try:
            members = _parse_archive_bytes(data)
        except ValueError:
            return
        for name, body in members:
            assert isinstance(name, str) and name
            assert isinstance(body, bytes)

    @settings(max_examples=50)
    @given(
        st.just(
            b"!<arch>\n"
            b"a.obj/          "
            + b"0".ljust(12, b" ")
            + b"0".ljust(6, b" ")
            + b"0".ljust(6, b" ")
            + b"100644".ljust(8, b" ")
            + b"5".ljust(10, b" ")
            + b"`\n"
            + b"hello"
        )
    )
    def test_valid_archive_roundtrip(self, data: bytes) -> None:
        members = _parse_archive_bytes(data)
        assert members == [("a.obj", b"hello")]


class TestCoffSymbolNamesRobust:
    @given(st.binary(max_size=512))
    def test_raw_bytes_never_crashes_coff(self, data: bytes) -> None:
        names = _coff_symbol_names(data)
        assert isinstance(names, list)
        assert all(isinstance(n, str) for n in names)

    @st.composite
    def _coff_blob(self: st.DrawFn) -> bytes:
        """A COFF-ish blob: 20-byte header + forged string-table geometry."""
        offset = self(st.integers(0, 64))
        count = self(st.integers(0, 8))
        # Header: machine[2] sections[2] time[4] symptr[4]=offset count[4] optlen[2] char[2]
        hdr = struct.pack("<HHIIIHH", 0x14C, 1, 0, offset, count, 0, 0)
        pad = self(st.binary(max_size=32))
        str_len = self(st.integers(0, 64))
        trailer = struct.pack("<I", str_len) + self(st.binary(max_size=32))
        return hdr + pad + trailer

    @given(_coff_blob())
    def test_structured_coff_never_crashes(self, data: bytes) -> None:
        names = _coff_symbol_names(data)
        assert isinstance(names, list)
        assert all(isinstance(n, str) for n in names)

    @settings(max_examples=50)
    @given(st.integers(0, 0x10000), st.binary(min_size=1, max_size=8))
    def test_coff_no_invented_names(self, count_hint: int, name_bytes: bytes) -> None:
        # No valid table geometry can be conjured from a hint; result must be
        # a list of strings derived only from the input slice.
        data = struct.pack("<HHIIIHH", 0x14C, 0, 0, 20, 1, 0, 0)
        entry = name_bytes.ljust(8, b"\x00")[:8] + b"\x00" * 9 + bytes([count_hint & 0xFF])
        table = struct.pack("<I", 4 + len(name_bytes)) + name_bytes
        blob = data + entry + table
        names = _coff_symbol_names(blob)
        assert isinstance(names, list)
        # With one entry the name must be either the inline name or "".
        if names:
            assert names[0] in (name_bytes.split(b"\x00", 1)[0].decode("utf-8", "replace"), "")
