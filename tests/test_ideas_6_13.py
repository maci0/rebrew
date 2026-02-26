"""Tests for ga.py near-miss MATCHING mode and data.py dispatch table detection."""

import struct

from rebrew.data import DispatchEntry, DispatchTable, find_dispatch_tables
from rebrew.ga import find_near_miss, parse_matching_info

# ---------------------------------------------------------------------------
# Tests for ga.py near-miss mode (#6)
# ---------------------------------------------------------------------------


class TestParseMatchingInfo:
    def _make_c(self, d, name, va, status, blocker="", skip=False) -> None:
        lines = [
            f"// FUNCTION: SERVER 0x{va:08x}",
            f"// STATUS: {status}",
            "// ORIGIN: GAME",
            "// SIZE: 100",
            "// CFLAGS: /O2 /Gd",
            f"// SYMBOL: _{name}",
        ]
        if blocker:
            lines.append(f"// BLOCKER: {blocker}")
        if skip:
            lines.append("// SKIP: reason")
        lines.append(f"int __cdecl {name}(void) {{ return 0; }}")
        (d / f"{name}.c").write_text("\n".join(lines), encoding="utf-8")

    def test_matching_with_small_delta(self, tmp_path) -> None:
        self._make_c(tmp_path, "FuncA", 0x10001000, "MATCHING", "2B diff: off by 2 bytes")
        result = parse_matching_info(tmp_path / "FuncA.c", max_delta=10)
        assert result is not None
        assert result["delta"] == 2

    def test_matching_large_delta_excluded(self, tmp_path) -> None:
        self._make_c(tmp_path, "FuncB", 0x10002000, "MATCHING", "50B diff: too big")
        result = parse_matching_info(tmp_path / "FuncB.c", max_delta=10)
        assert result is None

    def test_stub_excluded(self, tmp_path) -> None:
        self._make_c(tmp_path, "FuncC", 0x10003000, "STUB", "2B diff")
        result = parse_matching_info(tmp_path / "FuncC.c", max_delta=10)
        assert result is None

    def test_no_blocker_excluded(self, tmp_path) -> None:
        self._make_c(tmp_path, "FuncD", 0x10004000, "MATCHING")
        result = parse_matching_info(tmp_path / "FuncD.c", max_delta=10)
        assert result is None

    def test_skip_excluded(self, tmp_path) -> None:
        self._make_c(tmp_path, "FuncE", 0x10005000, "MATCHING", "2B diff", skip=True)
        result = parse_matching_info(tmp_path / "FuncE.c", max_delta=10)
        assert result is None


class TestFindNearMiss:
    def _make_c(self, d, name, va, status, blocker="") -> None:
        lines = [
            f"// FUNCTION: SERVER 0x{va:08x}",
            f"// STATUS: {status}",
            "// ORIGIN: GAME",
            "// SIZE: 100",
            "// CFLAGS: /O2 /Gd",
            f"// SYMBOL: _{name}",
        ]
        if blocker:
            lines.append(f"// BLOCKER: {blocker}")
        lines.append(f"int __cdecl {name}(void) {{ return 0; }}")
        (d / f"{name}.c").write_text("\n".join(lines), encoding="utf-8")

    def test_finds_near_miss(self, tmp_path) -> None:
        self._make_c(tmp_path, "Near1", 0x10001000, "MATCHING", "2B diff")
        self._make_c(tmp_path, "Near2", 0x10002000, "MATCHING", "5B diff")
        self._make_c(tmp_path, "Far", 0x10003000, "MATCHING", "50B diff")
        self._make_c(tmp_path, "Stub", 0x10004000, "STUB", "2B diff")

        results = find_near_miss(tmp_path, max_delta=10)
        names = [r["filepath"].stem for r in results]
        assert "Near1" in names
        assert "Near2" in names
        assert "Far" not in names
        assert "Stub" not in names

    def test_sorted_by_delta(self, tmp_path) -> None:
        self._make_c(tmp_path, "Big", 0x10001000, "MATCHING", "8B diff")
        self._make_c(tmp_path, "Small", 0x10002000, "MATCHING", "1B diff")
        results = find_near_miss(tmp_path, max_delta=10)
        assert results[0]["delta"] <= results[1]["delta"]


# ---------------------------------------------------------------------------
# Tests for data.py dispatch table detection (#13)
# ---------------------------------------------------------------------------


class TestDispatchTable:
    def test_dataclass_properties(self) -> None:
        entries = [
            DispatchEntry(target_va=0x10001000, name="func_a", status="RELOC"),
            DispatchEntry(target_va=0x10002000, name="", status=""),
            DispatchEntry(target_va=0x10003000, name="func_c", status="EXACT"),
        ]
        table = DispatchTable(va=0x1002C000, section=".data", entries=entries)
        assert table.num_entries == 3
        assert table.resolved == 2
        assert abs(table.coverage - 2 / 3) < 0.01

    def test_to_dict(self) -> None:
        table = DispatchTable(
            va=0x1002C000,
            section=".rdata",
            entries=[DispatchEntry(target_va=0x10001000, name="f", status="RELOC")],
        )
        d = table.to_dict()
        assert d["va"] == "0x1002c000"
        assert d["num_entries"] == 1
        assert d["resolved"] == 1


class TestFindDispatchTables:
    def _make_binary(self, text_va, text_size, data_va, data_offset, pointers) -> bytes:
        """Build a minimal binary with .text and .data sections."""
        # Create binary data large enough
        binary = bytearray(data_offset + len(pointers) * 4 + 256)
        # Write function pointers into the data section
        for i, ptr in enumerate(pointers):
            struct.pack_into("<I", binary, data_offset + i * 4, ptr)
        return bytes(binary)

    def test_detects_table(self) -> None:
        text_va = 0x10001000
        text_size = 0x10000
        data_va = 0x10020000
        data_offset = 0x1000

        # 4 pointers into .text
        ptrs = [text_va + 0x100, text_va + 0x200, text_va + 0x300, text_va + 0x400]
        binary = self._make_binary(text_va, text_size, data_va, data_offset, ptrs)

        sections = {
            ".text": {"va": text_va, "size": text_size, "file_offset": 0, "raw_size": 0x1000},
            ".data": {
                "va": data_va,
                "size": len(ptrs) * 4 + 256,
                "file_offset": data_offset,
                "raw_size": len(ptrs) * 4 + 256,
            },
        }

        known = {text_va + 0x100: {"name": "func_a", "status": "RELOC"}}
        tables = find_dispatch_tables(binary, 0x10000000, sections, known, min_entries=3)

        assert len(tables) == 1
        tbl = tables[0]
        assert tbl.num_entries == 4
        assert tbl.resolved == 1
        assert tbl.entries[0].name == "func_a"

    def test_no_text_section(self) -> None:
        tables = find_dispatch_tables(b"\x00" * 100, 0, {}, {})
        assert tables == []

    def test_min_entries_filter(self) -> None:
        text_va = 0x10001000
        text_size = 0x10000
        data_va = 0x10020000
        data_offset = 0x1000

        # Only 2 pointers — below min_entries=3
        ptrs = [text_va + 0x100, text_va + 0x200]
        binary = self._make_binary(text_va, text_size, data_va, data_offset, ptrs)

        sections = {
            ".text": {"va": text_va, "size": text_size, "file_offset": 0, "raw_size": 0x1000},
            ".data": {"va": data_va, "size": 256, "file_offset": data_offset, "raw_size": 256},
        }

        tables = find_dispatch_tables(binary, 0x10000000, sections, {}, min_entries=3)
        assert len(tables) == 0
