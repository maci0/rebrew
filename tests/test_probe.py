"""Tests for `rebrew.probe`, the no-side-effect per-function ruler."""

from __future__ import annotations

from rebrew.probe import matched_reloc_count


class TestMatchedRelocCount:
    """The historical "matched-reloc" byte count."""

    def test_counts_agreeing_bytes_and_reloc_sites(self) -> None:
        # Byte 1 differs but relocates on the candidate side, so it matches.
        assert matched_reloc_count(b"\x90\x01\x02", b"\x90\xff\x02", {1}, 3) == 3

    def test_stops_at_the_short_target_read(self) -> None:
        # SIZE (8) runs past the target section's raw bytes, so only 3 bytes
        # were read.  Indexing past them raised IndexError; the overlap that
        # does exist is 3, with byte 2 a real difference.
        assert matched_reloc_count(b"\x90\x01\x02", b"\x90\x01\xff" * 2, set(), 8) == 2

    def test_stops_at_the_short_candidate(self) -> None:
        assert matched_reloc_count(b"\x90\x01\x02\x03", b"\x90\x01", set(), 4) == 2

    def test_empty_side_counts_nothing(self) -> None:
        assert matched_reloc_count(b"", b"\x90", set(), 1) == 0
        assert matched_reloc_count(b"\x90", b"", set(), 1) == 0
