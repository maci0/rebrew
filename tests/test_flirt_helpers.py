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

    def test_c3_operand_does_not_end_function(self) -> None:
        # `mov eax, 0xC3` (B8 C3 00 00 00) embeds a C3 byte that is an
        # immediate, not a ret — the size must run past it to the real ret.
        assert find_func_size(bytes.fromhex("b8 c3 00 00 00 90 c3"), 0) == 7

    def test_modrm_c3_does_not_end_function(self) -> None:
        # `les eax, [ebx+0xC3]`-shaped bytes embed C3 as displacement.
        assert find_func_size(bytes.fromhex("c4 83 c3 00 00 00 c3"), 0) == 7


class TestIterMatchOffsets:
    def test_small_code_no_probes(self) -> None:
        assert list(iter_match_offsets(16)) == []  # < min_window (32)

    def test_stride_probing(self) -> None:
        offsets = list(iter_match_offsets(100, stride=16, min_window=32))
        assert offsets == [0, 16, 32, 48, 64]  # last_start = 100-32 = 68 → 0..68 step 16

    def test_custom_stride(self) -> None:
        offsets = list(iter_match_offsets(64, stride=8, min_window=32))
        assert offsets == [0, 8, 16, 24, 32]


class TestMatchTextDedup:
    def test_duplicate_vas_deduped(self) -> None:
        """Overlapping stride windows reporting the same VA yield one match."""

        class _M:
            def __init__(self, names) -> None:
                self.names = names

        class _Matcher:
            def match(self, data):
                return [_M([("printf", 0, 0)])]

        from rebrew.flirt import match_text

        code = b"\x55\x89\xe5\x5d\xc3" + b"\x90" * 64
        matches = match_text(_Matcher(), code, 0x1000, stride=1)
        vas = [m["va"] for m in matches]
        assert len(vas) == len(set(vas))
        assert vas[0] == 0x1000


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


class TestUndecodableByteEndsScan:
    def test_invalid_byte_ends_scan(self) -> None:
        """An undecodable byte ends the scan (the `.byte` pseudo-insn the
        docstring relies on).  With skipdata=False capstone silently STOPPED at
        it, so the function was reported as the full window (here 6 bytes)."""
        # nop; <invalid VEX2 prefix>; nop; ret
        assert find_func_size(b"\x90\xc4\xe2\x78\x90\xc3", 0) == 1
