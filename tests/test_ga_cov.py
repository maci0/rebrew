"""Tests for rebrew.ga — STUB parsing, batch GA, and batch flag sweep logic."""

from pathlib import Path

from rebrew.ga import (
    find_all_matching,
    find_all_stubs,
    parse_matching_all,
    parse_stub_info,
    update_cflags_annotation,
)

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


# -------------------------------------------------------------------------
# parse_matching_all (batch flag sweep discovery)
# -------------------------------------------------------------------------


class TestParseMatchingAll:
    def _make_c(
        self,
        d: Path,
        name: str,
        va: int,
        status: str,
        blocker: str = "",
        skip: bool = False,
        cflags: str = "/O2 /Gd",
    ) -> Path:
        lines = [
            f"// FUNCTION: SERVER 0x{va:08x}",
            f"// STATUS: {status}",
            "// ORIGIN: GAME",
            "// SIZE: 100",
            f"// CFLAGS: {cflags}",
            f"// SYMBOL: _{name}",
        ]
        if blocker:
            lines.append(f"// BLOCKER: {blocker}")
        if skip:
            lines.append("// SKIP: reason")
        lines.append(f"int __cdecl {name}(void) {{ return 0; }}")
        path = d / f"{name}.c"
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def test_accepts_matching_without_blocker(self, tmp_path: Path) -> None:
        self._make_c(tmp_path, "FuncA", 0x10001000, "MATCHING")
        result = parse_matching_all(tmp_path / "FuncA.c")
        assert result is not None
        assert result["va"] == "0x10001000"
        assert "delta" not in result

    def test_accepts_matching_with_blocker(self, tmp_path: Path) -> None:
        self._make_c(tmp_path, "FuncB", 0x10002000, "MATCHING", "3B diff")
        result = parse_matching_all(tmp_path / "FuncB.c")
        assert result is not None
        assert result["delta"] == 3

    def test_rejects_stub(self, tmp_path: Path) -> None:
        self._make_c(tmp_path, "FuncC", 0x10003000, "STUB")
        result = parse_matching_all(tmp_path / "FuncC.c")
        assert result is None

    def test_rejects_exact(self, tmp_path: Path) -> None:
        self._make_c(tmp_path, "FuncD", 0x10004000, "EXACT")
        result = parse_matching_all(tmp_path / "FuncD.c")
        assert result is None

    def test_rejects_skip(self, tmp_path: Path) -> None:
        self._make_c(tmp_path, "FuncE", 0x10005000, "MATCHING", skip=True)
        result = parse_matching_all(tmp_path / "FuncE.c")
        assert result is None

    def test_rejects_ignored(self, tmp_path: Path) -> None:
        self._make_c(tmp_path, "FuncF", 0x10006000, "MATCHING")
        result = parse_matching_all(tmp_path / "FuncF.c", ignored={"_FuncF"})
        assert result is None

    def test_preserves_cflags(self, tmp_path: Path) -> None:
        self._make_c(tmp_path, "FuncG", 0x10007000, "MATCHING", cflags="/O1 /Gz")
        result = parse_matching_all(tmp_path / "FuncG.c")
        assert result is not None
        assert result["cflags"] == "/O1 /Gz"


# -------------------------------------------------------------------------
# find_all_matching
# -------------------------------------------------------------------------


class TestFindAllMatching:
    def _make_c(
        self,
        d: Path,
        name: str,
        va: int,
        status: str,
        blocker: str = "",
        size: int = 100,
    ) -> None:
        lines = [
            f"// FUNCTION: SERVER 0x{va:08x}",
            f"// STATUS: {status}",
            "// ORIGIN: GAME",
            f"// SIZE: {size}",
            "// CFLAGS: /O2 /Gd",
            f"// SYMBOL: _{name}",
        ]
        if blocker:
            lines.append(f"// BLOCKER: {blocker}")
        lines.append(f"int __cdecl {name}(void) {{ return 0; }}")
        (d / f"{name}.c").write_text("\n".join(lines), encoding="utf-8")

    def test_finds_all_matching(self, tmp_path: Path) -> None:
        self._make_c(tmp_path, "Match1", 0x10001000, "MATCHING", "2B diff")
        self._make_c(tmp_path, "Match2", 0x10002000, "MATCHING")
        self._make_c(tmp_path, "Stub1", 0x10003000, "STUB")
        self._make_c(tmp_path, "Exact1", 0x10004000, "EXACT")

        results = find_all_matching(tmp_path)
        names = [r["filepath"].stem for r in results]
        assert "Match1" in names
        assert "Match2" in names
        assert "Stub1" not in names
        assert "Exact1" not in names

    def test_sorted_by_delta_then_size(self, tmp_path: Path) -> None:
        self._make_c(tmp_path, "NoDelta", 0x10003000, "MATCHING", size=50)
        self._make_c(tmp_path, "BigDelta", 0x10001000, "MATCHING", "8B diff", size=100)
        self._make_c(tmp_path, "SmallDelta", 0x10002000, "MATCHING", "1B diff", size=200)

        results = find_all_matching(tmp_path)
        names = [r["filepath"].stem for r in results]
        assert names[0] == "SmallDelta"
        assert names[1] == "BigDelta"
        assert names[2] == "NoDelta"

    def test_empty_dir(self, tmp_path: Path) -> None:
        results = find_all_matching(tmp_path)
        assert results == []

    def test_nonexistent_dir(self, tmp_path: Path) -> None:
        results = find_all_matching(tmp_path / "nonexistent")
        assert results == []

    def test_duplicate_va_keeps_first(self, tmp_path: Path) -> None:
        self._make_c(tmp_path, "Dup1", 0x10001000, "MATCHING")
        f2 = tmp_path / "dup2.c"
        f2.write_text(
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: MATCHING\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 100\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _Dup2\n"
            "int __cdecl Dup2(void) { return 0; }\n",
            encoding="utf-8",
        )
        results = find_all_matching(tmp_path, warn_duplicates=False)
        assert len(results) == 1


# -------------------------------------------------------------------------
# update_cflags_annotation
# -------------------------------------------------------------------------


class TestUpdateCflagsAnnotation:
    def _make_source(self, tmp_path: Path, cflags: str = "/O2 /Gd") -> Path:
        f = tmp_path / "func.c"
        f.write_text(
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: MATCHING\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 100\n"
            f"// CFLAGS: {cflags}\n"
            "// SYMBOL: _func\n"
            "int __cdecl func(void) { return 0; }\n",
            encoding="utf-8",
        )
        return f

    def test_updates_cflags(self, tmp_path: Path) -> None:
        f = self._make_source(tmp_path, "/O2 /Gd")
        changed = update_cflags_annotation(f, "/O1 /Gz")
        assert changed is True
        content = f.read_text(encoding="utf-8")
        assert "// CFLAGS: /O1 /Gz" in content
        assert "// CFLAGS: /O2 /Gd" not in content

    def test_no_change_when_same(self, tmp_path: Path) -> None:
        f = self._make_source(tmp_path, "/O2 /Gd")
        changed = update_cflags_annotation(f, "/O2 /Gd")
        assert changed is False

    def test_no_change_when_no_annotation(self, tmp_path: Path) -> None:
        f = tmp_path / "no_cflags.c"
        f.write_text(
            "// FUNCTION: SERVER 0x10001000\n// STATUS: STUB\nint main() { return 0; }\n",
            encoding="utf-8",
        )
        changed = update_cflags_annotation(f, "/O1 /Gz")
        assert changed is False

    def test_preserves_other_annotations(self, tmp_path: Path) -> None:
        f = self._make_source(tmp_path, "/O2 /Gd")
        update_cflags_annotation(f, "/O1 /Gz")
        content = f.read_text(encoding="utf-8")
        assert "// STATUS: MATCHING" in content
        assert "// SYMBOL: _func" in content
        assert "// SIZE: 100" in content
