"""Tests for rebrew.ga — STUB parsing and batch GA logic."""

from pathlib import Path

from rebrew.ga import find_all_stubs, parse_stub_info

# -------------------------------------------------------------------------
# parse_stub_info
# -------------------------------------------------------------------------


class TestParseStubInfo:
    def _make_stub_file(
        self, tmp_path, va=0x10001000, status="STUB", size=64, symbol="_my_func", origin="GAME"
    ) -> Path:
        f = tmp_path / f"func_{va:08x}.c"
        f.write_text(
            f"// FUNCTION: SERVER 0x{va:08X}\n"
            f"// STATUS: {status}\n"
            f"// ORIGIN: {origin}\n"
            f"// SIZE: {size}\n"
            f"// CFLAGS: /O2 /Gd\n"
            f"// SYMBOL: {symbol}\n"
            f"void __cdecl {symbol}(void) {{\n"
            f"    // stub\n"
            f"}}\n",
            encoding="utf-8",
        )
        return f

    def test_parses_stub(self, tmp_path) -> None:
        f = self._make_stub_file(tmp_path)
        result = parse_stub_info(f)
        assert result is not None
        assert result["va"] == "0x10001000"
        assert result["symbol"] == "_my_func"

    def test_skips_non_stub(self, tmp_path) -> None:
        f = self._make_stub_file(tmp_path, status="EXACT")
        result = parse_stub_info(f)
        assert result is None

    def test_skips_skip_status(self, tmp_path) -> None:
        f = self._make_stub_file(tmp_path, status="SKIP")
        result = parse_stub_info(f)
        assert result is None

    def test_skips_ignored_symbols(self, tmp_path) -> None:
        f = self._make_stub_file(tmp_path, symbol="_asm_func")
        result = parse_stub_info(f, ignored={"_asm_func"})
        assert result is None

    def test_skips_tiny_functions(self, tmp_path) -> None:
        f = self._make_stub_file(tmp_path, size=2)
        result = parse_stub_info(f)
        assert result is None

    def test_no_annotations(self, tmp_path) -> None:
        f = tmp_path / "bad.c"
        f.write_text("int main() { return 0; }\n", encoding="utf-8")
        result = parse_stub_info(f)
        assert result is None


# -------------------------------------------------------------------------
# find_all_stubs
# -------------------------------------------------------------------------


class TestFindAllStubs:
    def _make_stub(self, d, va, symbol, size=64) -> None:
        f = d / f"func_{va:08x}.c"
        f.write_text(
            f"// FUNCTION: SERVER 0x{va:08X}\n"
            f"// STATUS: STUB\n"
            f"// ORIGIN: GAME\n"
            f"// SIZE: {size}\n"
            f"// CFLAGS: /O2 /Gd\n"
            f"// SYMBOL: {symbol}\n"
            f"void __cdecl {symbol}(void) {{}}\n",
            encoding="utf-8",
        )

    def test_finds_stubs(self, tmp_path) -> None:
        self._make_stub(tmp_path, 0x10001000, "_func_a", size=64)
        self._make_stub(tmp_path, 0x10002000, "_func_b", size=128)
        stubs = find_all_stubs(tmp_path)
        assert len(stubs) == 2

    def test_sorted_by_size(self, tmp_path) -> None:
        self._make_stub(tmp_path, 0x10002000, "_big", size=200)
        self._make_stub(tmp_path, 0x10001000, "_small", size=32)
        stubs = find_all_stubs(tmp_path)
        assert stubs[0]["size"] <= stubs[1]["size"]

    def test_empty_dir(self, tmp_path) -> None:
        stubs = find_all_stubs(tmp_path)
        assert stubs == []

    def test_ignores_exact(self, tmp_path) -> None:
        f = tmp_path / "exact.c"
        f.write_text(
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: EXACT\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _exact\n"
            "void __cdecl _exact(void) {}\n",
            encoding="utf-8",
        )
        stubs = find_all_stubs(tmp_path)
        assert stubs == []

    def test_duplicate_va_warning(self, tmp_path) -> None:
        """Duplicate VAs should be detected — only first kept."""
        self._make_stub(tmp_path, 0x10001000, "_dup_a")
        # Create second file with same VA
        f2 = tmp_path / "dup_file.c"
        f2.write_text(
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _dup_b\n"
            "void __cdecl _dup_b(void) {}\n",
            encoding="utf-8",
        )
        stubs = find_all_stubs(tmp_path)
        assert len(stubs) == 1

    def test_filters_ignored(self, tmp_path) -> None:
        self._make_stub(tmp_path, 0x10001000, "_asm_builtin")
        stubs = find_all_stubs(tmp_path, ignored={"_asm_builtin"})
        assert stubs == []
