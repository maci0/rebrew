"""Tests for flirt.py — pure helpers (signature scanning needs real .sig files)."""

from pathlib import Path

import pytest

from rebrew.flirt import find_func_size, iter_match_offsets


class TestFindFuncSize:
    def test_ret_at_start(self) -> None:
        assert find_func_size(b"\xc3\xcc\xcc", 0) == 1

    def test_ret_after_code(self) -> None:
        assert find_func_size(b"\x55\x89\xe5\xc3", 0) == 4

    def test_ret_imm16(self) -> None:
        # C2 08 00 = ret 8 → 3 bytes; preceded by a 1-byte push → size 4.
        assert find_func_size(b"\x55\xc2\x08\x00\xcc", 0) == 4
        assert find_func_size(b"\xc2\x08\x00", 0) == 3

    def test_no_ret_uses_max_scan(self) -> None:
        data = b"\x90" * 200  # nops, no ret
        assert find_func_size(data, 0) == 200  # capped by _MAX_FUNC_SCAN

    def test_offset_respected(self) -> None:
        # ret at absolute index 2; from offset 2 → size 1.
        assert find_func_size(b"\x55\x89\xc3", 2) == 1


class TestIterMatchOffsets:
    def test_small_code_no_probes(self) -> None:
        assert list(iter_match_offsets(16)) == []  # < min_window (32)

    def test_stride_probing(self) -> None:
        offsets = list(iter_match_offsets(100, stride=16, min_window=32))
        assert offsets == [0, 16, 32, 48, 64]  # last_start = 100-32 = 68 → 0..68 step 16

    def test_custom_stride(self) -> None:
        offsets = list(iter_match_offsets(64, stride=8, min_window=32))
        assert offsets == [0, 8, 16, 24, 32]


class TestLoadSignaturesErrors:
    def test_bad_file_warns(self, tmp_path: Path) -> None:
        from rebrew.flirt import load_signatures

        (tmp_path / "bad.pat").write_text("not a pat file", encoding="utf-8")
        with pytest.warns(UserWarning, match="Error loading"):
            assert load_signatures(str(tmp_path)) == []

    def test_unreadable_file_warns(self, tmp_path: Path) -> None:
        from rebrew.flirt import load_signatures

        (tmp_path / "broken.sig").write_bytes(b"")
        with pytest.warns(UserWarning, match="Error loading"):
            assert load_signatures(str(tmp_path)) == []
