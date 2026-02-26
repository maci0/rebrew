"""Tests for unmatchable detection, grouping, and multi-VA loading in rebrew-next."""

import json
from pathlib import Path
from types import SimpleNamespace

from rebrew.binary_loader import BinaryInfo, SectionInfo
from rebrew.naming import (
    detect_origin,
    detect_unmatchable,
    group_uncovered,
    ignored_symbols,
    load_data,
    parse_byte_delta,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_binary_info(text_bytes: bytes, text_va: int = 0x10001000) -> BinaryInfo:
    """Create a minimal BinaryInfo with a .text section containing given bytes."""
    text_size = len(text_bytes)
    info = BinaryInfo(
        path=Path("/fake/test.dll"),
        format="pe",
        image_base=0x10000000,
        text_va=text_va,
        text_size=text_size,
        text_raw_offset=0x400,
        sections={
            ".text": SectionInfo(
                name=".text",
                va=text_va,
                size=text_size,
                file_offset=0x400,
                raw_size=text_size,
            )
        },
        _data=b"\x00" * 0x400 + text_bytes,  # pad to file_offset then text bytes
    )
    return info


# ---------------------------------------------------------------------------
# detect_unmatchable
# ---------------------------------------------------------------------------


class TestDetectUnmatchable:
    def test_none_without_binary(self) -> None:
        """Without binary info, can't detect byte patterns."""
        result = detect_unmatchable(0x10001000, 100, None)
        assert result is None

    def test_iat_thunk_from_config(self) -> None:
        """IAT thunks in the config should be flagged."""
        result = detect_unmatchable(0x10001000, 6, None, iat_thunks={0x10001000})
        assert result is not None
        assert "IAT thunk" in result

    def test_ignored_symbol(self) -> None:
        """Ignored symbols should be flagged."""
        result = detect_unmatchable(
            0x10001000,
            50,
            None,
            ignored_symbols={"__allshl"},
            name="__allshl",
        )
        assert result is not None
        assert "ignored symbol" in result

    def test_single_byte_ret(self) -> None:
        """A single C3 byte = RET stub, unmatchable."""
        info = _make_binary_info(bytes([0xC3]))
        result = detect_unmatchable(0x10001000, 1, info)
        assert result is not None
        assert "RET" in result

    def test_int3_padding(self) -> None:
        """A single CC byte = INT3 padding, unmatchable."""
        info = _make_binary_info(bytes([0xCC]))
        result = detect_unmatchable(0x10001000, 1, info)
        assert result is not None
        assert "INT3" in result

    def test_nop_padding(self) -> None:
        """A single 90 byte = NOP padding, unmatchable."""
        info = _make_binary_info(bytes([0x90]))
        result = detect_unmatchable(0x10001000, 1, info)
        assert result is not None
        assert "NOP" in result

    def test_iat_jmp_thunk(self) -> None:
        """FF 25 xx xx xx xx = IAT jmp [addr], unmatchable."""
        # jmp [0x10025000]
        info = _make_binary_info(bytes([0xFF, 0x25, 0x00, 0x50, 0x02, 0x10]))
        result = detect_unmatchable(0x10001000, 6, info)
        assert result is not None
        assert "IAT jmp" in result

    def test_seh_handler(self) -> None:
        """64 A1 00 00 00 00 = mov eax, fs:[0], SEH handler."""
        info = _make_binary_info(bytes([0x64, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x50, 0x53]))
        result = detect_unmatchable(0x10001000, 20, info)
        assert result is not None
        assert "SEH" in result

    def test_normal_function(self) -> None:
        """A normal function prologue should not be flagged."""
        # push ebp; mov ebp, esp; sub esp, 0x10
        info = _make_binary_info(bytes([0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10] + [0x90] * 50))
        result = detect_unmatchable(0x10001000, 56, info)
        assert result is None

    def test_large_function_not_iat(self) -> None:
        """A large function starting with FF 25 should NOT be flagged as IAT (too big)."""
        # FF 25 at start but size > 8 → not an IAT thunk
        info = _make_binary_info(bytes([0xFF, 0x25, 0x00, 0x00, 0x00, 0x00] + [0x90] * 100))
        result = detect_unmatchable(0x10001000, 106, info)
        assert result is None  # too large to be an IAT thunk

    def test_priority_config_over_bytes(self) -> None:
        """Config IAT thunks take priority (checked first)."""
        info = _make_binary_info(bytes([0x55, 0x8B, 0xEC]))
        result = detect_unmatchable(0x10001000, 100, info, iat_thunks={0x10001000})
        assert result is not None
        assert "config" in result


# ---------------------------------------------------------------------------
# parse_byte_delta
# ---------------------------------------------------------------------------


class TestParseByteDelta:
    def test_xb_diff(self) -> None:
        assert parse_byte_delta("2B diff") == 2
        assert parse_byte_delta("24B diff:") == 24
        assert parse_byte_delta("(2B diff)") == 2
        assert parse_byte_delta("1B diff:") == 1

    def test_byte_diff(self) -> None:
        assert parse_byte_delta("3-byte size diff (154B vs 157B)") == 3

    def test_xb_vs_yb(self) -> None:
        assert parse_byte_delta("229B vs 205B") == 24
        assert parse_byte_delta("244B vs 242B (2B diff)") == 2  # diff pattern takes priority

    def test_no_delta(self) -> None:
        assert parse_byte_delta("register allocation differs") is None
        assert parse_byte_delta("") is None
        assert parse_byte_delta("FPU register allocation") is None

    def test_complex_blocker(self) -> None:
        blocker = "byte param zero-extend (xor edx+mov dl vs bare mov dl), 244B vs 242B (2B diff)"
        assert parse_byte_delta(blocker) == 2

    def test_large_diff(self) -> None:
        blocker = "22B diff from AND ECX,0xFF vs MOV CL,2 clamp pattern"
        assert parse_byte_delta(blocker) == 22


# ---------------------------------------------------------------------------
# ignored_symbols — getattr robustness
# ---------------------------------------------------------------------------


class TestIgnoredSymbols:
    def test_with_list(self) -> None:
        cfg = SimpleNamespace(ignored_symbols=["__allshl", "__aullshr"])
        result = ignored_symbols(cfg)
        assert result == {"__allshl", "__aullshr"}

    def test_with_none(self) -> None:
        cfg = SimpleNamespace(ignored_symbols=None)
        assert ignored_symbols(cfg) == set()

    def test_missing_attr(self) -> None:
        """Should not crash when cfg lacks ignored_symbols entirely."""
        cfg = SimpleNamespace()
        assert ignored_symbols(cfg) == set()

    def test_empty_list(self) -> None:
        cfg = SimpleNamespace(ignored_symbols=[])
        assert ignored_symbols(cfg) == set()


# ---------------------------------------------------------------------------
# detect_origin — getattr robustness
# ---------------------------------------------------------------------------


class TestDetectOriginRobust:
    def test_missing_game_range_end(self) -> None:
        """Should not crash when cfg lacks game_range_end."""
        cfg = SimpleNamespace(origins=["GAME"])
        assert detect_origin(0x1000C000, "my_func", cfg) == "GAME"

    def test_crt_prefix_without_game_range(self) -> None:
        """CRT prefix detection should work regardless of game_range_end."""
        cfg = SimpleNamespace(origins=["GAME", "MSVCRT"])
        assert detect_origin(0x10001000, "__security_init_cookie", cfg) == "MSVCRT"


# ---------------------------------------------------------------------------
# group_uncovered
# ---------------------------------------------------------------------------


def _make_item(
    va: int,
    size: int = 64,
    difficulty: int = 2,
    name: str = "func",
    origin: str = "GAME",
    reason: str = "test",
    neighbor: str | None = None,
) -> tuple[int, int, int, str, str, str, str | None]:
    """Helper to create a tuple matching the uncovered format."""
    return (difficulty, size, va, name, origin, reason, neighbor)


class TestGroupUncovered:
    def test_empty(self) -> None:
        assert group_uncovered([]) == []

    def test_single_item(self) -> None:
        items = [_make_item(0x10001000)]
        groups = group_uncovered(items)
        assert len(groups) == 1
        assert len(groups[0]) == 1

    def test_adjacent_grouped(self) -> None:
        """Functions within max_gap of each other should be grouped."""
        items = [
            _make_item(0x10001000, size=64),
            _make_item(0x10001100, size=64),
            _make_item(0x10001200, size=64),
        ]
        groups = group_uncovered(items, max_gap=0x1000)
        assert len(groups) == 1
        assert len(groups[0]) == 3

    def test_distant_split(self) -> None:
        """Functions far apart should be in separate groups."""
        items = [
            _make_item(0x10001000, size=64),
            _make_item(0x10005000, size=64),
        ]
        groups = group_uncovered(items, max_gap=0x1000)
        assert len(groups) == 2

    def test_sorted_by_total_size(self) -> None:
        """Groups should be sorted by total size (smallest first)."""
        items = [
            _make_item(0x10001000, size=200),  # group 1: 200B total
            _make_item(0x10005000, size=50),  # group 2: 50+50 = 100B total
            _make_item(0x10005100, size=50),
        ]
        groups = group_uncovered(items, max_gap=0x1000)
        assert len(groups) == 2
        # Smaller total size first
        assert sum(i[1] for i in groups[0]) < sum(i[1] for i in groups[1])

    def test_gap_accounts_for_function_size(self) -> None:
        """Gap is from end of previous function, not just VA distance."""
        # VA gap = 0x1100, but func at 0x10001000 is 0x200 bytes long,
        # so actual gap = 0x1100 - 0x200 = 0xF00 (within 0x1000)
        items = [
            _make_item(0x10001000, size=0x200),
            _make_item(0x10002100, size=64),
        ]
        groups = group_uncovered(items, max_gap=0x1000)
        assert len(groups) == 1

    def test_gap_too_large_with_function_size(self) -> None:
        """When gap exceeds max_gap even accounting for function body."""
        # VA gap = 0x2000, func size = 0x100 → actual gap = 0x1F00 > 0x1000
        items = [
            _make_item(0x10001000, size=0x100),
            _make_item(0x10003000, size=64),
        ]
        groups = group_uncovered(items, max_gap=0x1000)
        assert len(groups) == 2

    def test_unsorted_input(self) -> None:
        """Input order should not affect grouping (sorted internally by VA)."""
        items = [
            _make_item(0x10001200, size=64),
            _make_item(0x10001000, size=64),
            _make_item(0x10001100, size=64),
        ]
        groups = group_uncovered(items, max_gap=0x1000)
        assert len(groups) == 1
        assert len(groups[0]) == 3
        # Verify sorted by VA within the group
        vas = [item[2] for item in groups[0]]
        assert vas == sorted(vas)


# ---------------------------------------------------------------------------
# load_data — multi-VA coverage
# ---------------------------------------------------------------------------


class TestLoadDataMultiVA:
    """Verify load_data sees all VAs in multi-function .c files."""

    def test_multi_function_file_covers_all_vas(self, tmp_path) -> None:
        """Secondary VAs in a multi-function file must be recognized as covered."""
        src_dir = tmp_path / "src"
        src_dir.mkdir()

        # Write a multi-function .c file with two annotation blocks
        multi_file = src_dir / "game_funcs.c"
        multi_file.write_text(
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: RELOC\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _func_a\n"
            "int __cdecl func_a(void) { return 0; }\n"
            "\n"
            "// FUNCTION: SERVER 0x10001100\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 128\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _func_b\n"
            "int __cdecl func_b(void) { return 0; }\n",
            encoding="utf-8",
        )

        # Write ghidra_functions.json with 3 functions (2 covered, 1 not)
        ghidra_json = src_dir / "ghidra_functions.json"
        ghidra_json.write_text(
            json.dumps(
                [
                    {"va": 0x10001000, "ghidra_name": "func_a", "size": 64},
                    {"va": 0x10001100, "ghidra_name": "func_b", "size": 128},
                    {"va": 0x10002000, "ghidra_name": "func_c", "size": 96},
                ]
            ),
            encoding="utf-8",
        )

        cfg = SimpleNamespace(reversed_dir=src_dir)
        ghidra_funcs, existing, covered_vas = load_data(cfg)

        # Both VAs from the multi-function file should be in existing
        assert 0x10001000 in existing
        assert 0x10001100 in existing
        assert 0x10002000 not in existing

        # covered_vas should mirror existing
        assert 0x10001000 in covered_vas
        assert 0x10001100 in covered_vas
        assert covered_vas[0x10001000] == "game_funcs.c"
        assert covered_vas[0x10001100] == "game_funcs.c"

    def test_single_function_file_still_works(self, tmp_path) -> None:
        """Single-function files should work as before."""
        src_dir = tmp_path / "src"
        src_dir.mkdir()

        c_file = src_dir / "game_func.c"
        c_file.write_text(
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: EXACT\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _my_func\n"
            "int __cdecl my_func(void) { return 0; }\n",
            encoding="utf-8",
        )

        ghidra_json = src_dir / "ghidra_functions.json"
        ghidra_json.write_text(
            json.dumps(
                [
                    {"va": 0x10001000, "ghidra_name": "my_func", "size": 64},
                ]
            ),
            encoding="utf-8",
        )

        cfg = SimpleNamespace(reversed_dir=src_dir)
        ghidra_funcs, existing, covered_vas = load_data(cfg)

        assert 0x10001000 in existing
        assert existing[0x10001000]["status"] == "EXACT"

    def test_data_annotations_excluded(self, tmp_path) -> None:
        """DATA/GLOBAL marker types should not appear in coverage."""
        src_dir = tmp_path / "src"
        src_dir.mkdir()

        c_file = src_dir / "game_data.c"
        c_file.write_text(
            "// DATA: SERVER 0x10001000\n"
            "// STATUS: EXACT\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 4\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SECTION: .data\n",
            encoding="utf-8",
        )

        ghidra_json = src_dir / "ghidra_functions.json"
        ghidra_json.write_text(json.dumps([]), encoding="utf-8")

        cfg = SimpleNamespace(reversed_dir=src_dir)
        _, existing, covered_vas = load_data(cfg)

        assert 0x10001000 not in existing
        assert 0x10001000 not in covered_vas
