"""Tests for the ``ar`` member walk in ``rebrew.formats.archives``."""

from __future__ import annotations

lazy from pathlib import Path

import pytest

from rebrew.formats.archives import parse_archive_bytes, stock_lib_valid


def _member(name: bytes, body: bytes, size: bytes | None = None) -> bytes:
    """One ar member: 60-byte header, body, and the odd-length pad byte."""
    field = size if size is not None else str(len(body)).encode()
    header = (
        name.ljust(16, b" ")
        + b"0".ljust(12, b" ")
        + b"0".ljust(6, b" ")
        + b"0".ljust(6, b" ")
        + b"100644".ljust(8, b" ")
        + field.ljust(10, b" ")
        + b"`\n"
    )
    return header + body + (b"\n" if len(body) % 2 else b"")


class TestParseArchiveBytes:
    @pytest.mark.parametrize("size", [b"4x", b"-4"])
    def test_bad_member_size_refuses_the_archive(self, size: bytes, tmp_path: Path) -> None:
        data = (
            b"!<arch>\n"
            + _member(b"a.obj/", b"aaaa")
            + _member(b"b.obj/", b"bbbb", size)
            + _member(b"c.obj/", b"cccc")
        )
        with pytest.raises(ValueError, match="member size"):
            list(parse_archive_bytes(data, "bad.lib"))
        lib = tmp_path / "bad.lib"
        lib.write_bytes(data)
        assert not stock_lib_valid(lib)

    def test_truncated_header_refuses_the_archive(self) -> None:
        data = b"!<arch>\n" + _member(b"a.obj/", b"aaaa") + _member(b"b.obj/", b"bb")[:30]
        with pytest.raises(ValueError, match="truncated archive member header"):
            list(parse_archive_bytes(data, "short.lib"))

    def test_special_members_are_skipped(self) -> None:
        data = (
            b"!<arch>\n"
            + _member(b"/", b"\0\0\0\0")
            + _member(b"/SYM64/", b"\0" * 8)
            + _member(b"//", b"long_object_name.obj/\n")
            + _member(b"a.obj/", b"aaaa")
            + _member(b"/0", b"bbbb")
        )
        assert list(parse_archive_bytes(data, "gnu.a")) == [
            ("a.obj", b"aaaa"),
            ("long_object_name.obj", b"bbbb"),
        ]

    def test_odd_final_member_pad_is_not_a_header(self) -> None:
        data = b"!<arch>\n" + _member(b"a.obj/", b"abc")
        assert list(parse_archive_bytes(data, "odd.lib")) == [("a.obj", b"abc")]
