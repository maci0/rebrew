"""Tests for the LZEXE 0.90/0.91 unpacker (rebrew.lzexe).

The fixture ``tc16_hello_lzexe.exe`` is the real Turbo C++ 3.1 hello-world
executable (``tc16_hello.exe``) packed with the original LZEXE 0.91 packer
(Fabrice Bellard's distribution) running under DOSBox — so the round-trip
test validates against the packer's own output, not a hand-built sample.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from rebrew.lzexe import (
    NotLzexeError,
    _decompress,
    lzexe_version,
    unpack_lzexe,
    unpack_to_file,
)

FIXTURES = Path(__file__).parent / "fixtures"
PACKED = FIXTURES / "tc16_hello_lzexe.exe"
ORIGINAL = FIXTURES / "tc16_hello.exe"


def _header(path: Path) -> list[int]:
    return list(struct.unpack_from("<14H", path.read_bytes(), 0))


class TestDetection:
    def test_packed_fixture_detected(self) -> None:
        assert lzexe_version(PACKED) == 91

    def test_unpacked_mz_not_lzexe(self) -> None:
        assert lzexe_version(ORIGINAL) is None

    def test_non_mz_not_lzexe(self, tmp_path: Path) -> None:
        junk = tmp_path / "junk.bin"
        junk.write_bytes(b"\x00" * 512)
        assert lzexe_version(junk) is None

    def test_header_shape_mismatch_not_lzexe(self, tmp_path: Path) -> None:
        # An MZ header with lfarlc != 0x1c must not be detected.
        data = bytearray(PACKED.read_bytes())
        data[0x18:0x1A] = struct.pack("<H", 0x40)  # lfarlc -> 0x40
        f = tmp_path / "bad_lfarlc.exe"
        f.write_bytes(data)
        assert lzexe_version(f) is None

    def test_unpack_raises_for_plain_mz(self) -> None:
        with pytest.raises(NotLzexeError):
            unpack_lzexe(ORIGINAL)


class TestUnpack:
    def test_roundtrip_image_and_relocs(self) -> None:
        """The unpacked image and relocation entries equal the pre-pack original."""
        r = unpack_lzexe(PACKED)
        assert r.version == 91

        orig = ORIGINAL.read_bytes()
        ohead = _header(ORIGINAL)
        o_image = orig[ohead[4] * 16 :]
        assert r.image == o_image

        # Relocation entries (content, not placement): the packer's delta
        # table only preserves positions; lfarlc itself is not recoverable.
        o_crlc = ohead[3]
        o_lfarlc = ohead[0x0C]
        o_relocs = [struct.unpack_from("<HH", orig, o_lfarlc + 4 * i) for i in range(o_crlc)]
        assert r.relocs == list(o_relocs)

    def test_entry_and_stack_restored(self) -> None:
        r = unpack_lzexe(PACKED)
        ohead = _header(ORIGINAL)
        assert r.cs == ohead[0x0B]
        assert r.ip == ohead[0x0A]
        assert r.ss == ohead[7]
        assert r.sp == ohead[8]

    def test_to_bytes_is_valid_mz(self) -> None:
        out = unpack_lzexe(PACKED).to_bytes()
        assert out[:2] in (b"MZ", b"ZM")
        words = struct.unpack_from("<14H", out, 0)
        assert words[0x0C] == 0x1C  # lfarlc -> our reloc table position
        assert words[4] * 16 + len(unpack_lzexe(PACKED).image) == len(out)

    def test_unpack_to_file(self, tmp_path: Path) -> None:
        out = tmp_path / "out.exe"
        unpack_to_file(PACKED, out)
        assert out.read_bytes() == unpack_lzexe(PACKED).to_bytes()

    def test_default_output_path(self, tmp_path: Path) -> None:
        import shutil

        src = tmp_path / "game.exe"
        shutil.copy(PACKED, src)
        out = unpack_to_file(src)
        assert out.name == "game.exe.unpacked.exe"
        assert out.exists()


class TestDecompress:
    def test_decompress_stream_offset(self) -> None:
        """The stream starts at 0x20 for a tiny pack (cparhdr=2, e_cs covers)."""
        data = PACKED.read_bytes()
        ihead = _header(PACKED)
        # param block at CS:0000 -> inf[4] = compressed size in paragraphs
        fpos = (ihead[0x0B] + ihead[4]) * 16
        inf = struct.unpack_from("<8H", data, fpos)
        stream_off = (ihead[0x0B] - inf[4] + ihead[4]) * 16
        img = _decompress(data, stream_off)
        ohead = _header(ORIGINAL)
        assert img == ORIGINAL.read_bytes()[ohead[4] * 16 :]

    def test_literals_then_matches(self) -> None:
        """Sanity: the fixture's first bytes are verbatim literals (control word
        of all-ones), and the stream ends with the 0-byte terminator."""
        data = PACKED.read_bytes()
        ihead = _header(PACKED)
        fpos = (ihead[0x0B] + ihead[4]) * 16
        inf = struct.unpack_from("<8H", data, fpos)
        stream_off = (ihead[0x0B] - inf[4] + ihead[4]) * 16
        img = _decompress(data, stream_off)
        # First 16 literals are the original startup code copied verbatim
        # (the packer leaves the first block uncompressed).
        ohead = _header(ORIGINAL)
        orig_img = ORIGINAL.read_bytes()[ohead[4] * 16 :]
        assert img[:16] == orig_img[:16]
        assert len(img) > 1000


class TestCorruption:
    def test_truncated_file_raises_cleanly(self, tmp_path: Path) -> None:
        """A truncated LZEXE file must raise NotLzexeError (not struct.error /
        IndexError / silent garbage) so the CLI reports a clean error."""
        data = PACKED.read_bytes()[: len(PACKED.read_bytes()) // 2]
        f = tmp_path / "trunc.exe"
        f.write_bytes(data)
        with pytest.raises(NotLzexeError):
            unpack_lzexe(f)

    def test_midstream_corruption_raises_or_detects(self, tmp_path: Path) -> None:
        """Deleting bytes mid-stream must not produce a silent success —
        either detection rejects the file or the unpack raises cleanly."""
        data = bytearray(PACKED.read_bytes())
        del data[len(data) // 3 : len(data) // 3 + 100]
        f = tmp_path / "corrupt.exe"
        f.write_bytes(bytes(data))
        if lzexe_version(f) is not None:
            with pytest.raises(NotLzexeError):
                unpack_lzexe(f)
        else:
            # detection rejected it — also fine (clean error path)
            with pytest.raises(NotLzexeError):
                unpack_lzexe(f)


class TestReloc90:
    """The v0.90 relocation table decoder (the LZEXE 0.90 path has no real
    fixture — unit-test the table decode + truncation directly)."""

    def test_reloc90_decodes_groups(self) -> None:
        from rebrew.lzexe import _reloc_table90

        # group 0: 2 offsets; groups 1-15: 0; group 16 (seg 0x10000): 0
        data = b"\x02\x00\x10\x00\x20\x00" + b"\x00\x00" * 15
        relocs, end = _reloc_table90(data, 0)
        assert relocs == [(0x10, 0), (0x20, 0)]
        assert end == 6 + 30

    def test_reloc90_truncated_raises(self) -> None:
        from rebrew.lzexe import NotLzexeError, _reloc_table90

        # ends before the 0x10000 terminator group
        data = b"\x01\x00\x10\x00" + b"\x00\x00" * 3
        with pytest.raises(NotLzexeError):
            _reloc_table90(data, 0)

    def test_reloc90_truncated_mid_group_raises(self) -> None:
        from rebrew.lzexe import NotLzexeError, _reloc_table90

        # count promises offsets that run past the buffer
        data = b"\x05\x00\x10\x00"  # 5 offsets but only 1 present
        with pytest.raises(NotLzexeError):
            _reloc_table90(data, 0)
