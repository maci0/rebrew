"""NE comparison distinctions and bounded relocation records."""

import struct
from pathlib import Path

import pytest
from bin_util import make_ne
from typer.testing import CliRunner

from rebrew.formats.ne_analysis import NeImage, block_set, covered_bytes, segment_refs
from rebrew.formats.ne_loader import NeParseError
from rebrew.ne_compare import compare_images


class TestNeComparison:
    def test_relocated_content_is_not_file_equality(self, tmp_path: Path) -> None:
        a, b = tmp_path / "a.exe", tmp_path / "b.exe"
        a.write_bytes(make_ne(segments=[(b"ABCDEFGHIJKLMNOP", 0)]))
        data = bytearray(a.read_bytes())
        data[0x10] = 1
        b.write_bytes(data)
        report = compare_images(a, b, 8)
        assert not report["identical"]
        assert report["segments"][0]["exact"]
        assert report["same_offset_bytes"] == len(data) - 1
        from rebrew.app.main import app

        result = CliRunner().invoke(
            app, ["binary", "ne-compare", str(b), "--original", str(a), "--json"]
        )
        assert result.exit_code == 1, result.output

    def test_matching_window_union_and_short_tail(self) -> None:
        assert covered_bytes(b"XabcabcZ", block_set(b"abcabc", 3), 3) == 6
        assert covered_bytes(b"ab", block_set(b"ab", 3), 3) == 0
        with pytest.raises(ValueError, match="positive"):
            block_set(b"abc", 0)

    def test_fixups_and_truncation(self, tmp_path: Path) -> None:
        path = tmp_path / "a.exe"
        data = bytearray(make_ne(segments=[(bytes(16), 0x100)]))
        data += struct.pack("<HBBHHH", 1, 3, 0, 2, 1, 4)
        path.write_bytes(data)
        image = NeImage(path)
        assert image.fixups(0)[0].addend == 4
        assert segment_refs(image) == ({0: {0}}, {0: 0})
        path.write_bytes(data[:-1])
        with pytest.raises(NeParseError, match="truncated fixup"):
            NeImage(path).fixups(0)

    def test_virtual_segment_has_no_file_bytes(self, tmp_path: Path) -> None:
        data = bytearray(make_ne(segments=[(bytes(16), 0)]))
        struct.pack_into("<H", data, 0x140, 0)
        path = tmp_path / "a.exe"
        path.write_bytes(data)
        assert NeImage(path).seg_bytes(0) == b""

    def test_truncated_segment_refused_and_iterated_bytes_stay_physical(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "a.exe"
        path.write_bytes(make_ne(segments=[(bytes(16), 0)])[:-1])
        with pytest.raises(NeParseError, match="beyond"):
            NeImage(path)
        path.write_bytes(make_ne(segments=[(bytes(16), 8)]))
        assert NeImage(path).seg_bytes(0) == bytes(16)


class TestPublishedMethods:
    def test_complete_same_segment_pointer_and_rejecting_controls(self) -> None:
        from rebrew.formats.ne_analysis import published_method_candidates

        raw = b"\x08TExample\x01\x00\xff\xff\x00\x00\x04Test"
        assert published_method_candidates(raw, "TExample", fixups={(0, 11): (0, 16)}) == [
            ("Test", 16)
        ]
        assert published_method_candidates(raw, "TExample", fixups={(0, 11): (1, 16)}) == []
        assert published_method_candidates(raw[:-1], "TExample", fixups={(0, 11): (0, 16)}) == []

    def test_invalid_marker_does_not_hide_later_complete_table(self) -> None:
        from rebrew.formats.ne_analysis import published_method_candidates

        marker = b"\x08TExample"
        raw = marker + b"\x00\x00" + marker + b"\x01\x00\x10\x00\x00\x00\x04Test"
        assert published_method_candidates(raw, "TExample") == [("Test", 16)]
