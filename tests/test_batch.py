"""Tests for rebrew.extract — byte extraction, detect_reversed_vas, cmd_list."""

from pathlib import Path

import pytest

from rebrew.binary_loader import BinaryInfo, SectionInfo, extract_bytes_at_va
from rebrew.extract import cmd_list, detect_reversed_vas

# ---------------------------------------------------------------------------
# extract_bytes_at_va (the production byte-extraction path used by extract)
# ---------------------------------------------------------------------------


class TestExtractBytes:
    """Tests for extract_bytes_at_va() behind the extract tooling."""

    def _make_binary_info(
        self, data: bytes, tmp_path: Path, va_start: int = 0x10001000
    ) -> BinaryInfo:
        """Create a BinaryInfo with a single .text section."""
        section = SectionInfo(
            name=".text",
            va=va_start,
            size=len(data),
            file_offset=0,
            raw_size=len(data),
        )
        tmp = tmp_path / "test_bin.tmp"
        tmp.write_bytes(data)
        bi = BinaryInfo(
            path=tmp,
            format="pe",
            image_base=0x10000000,
            sections={".text": section},
            _data=data,
        )
        return bi

    def test_basic_extraction(self, tmp_path: Path) -> None:
        """Extracts bytes at the given VA."""
        data = b"\x55\x8b\xec\x83\xec\x08\xc3"
        bi = self._make_binary_info(data, tmp_path)
        result = extract_bytes_at_va(bi, 0x10001000, 4)
        assert result == b"\x55\x8b\xec\x83"

    def test_full_size(self, tmp_path: Path) -> None:
        """Extracts full function bytes."""
        data = b"\x55\x8b\xec\xc3"
        bi = self._make_binary_info(data, tmp_path)
        result = extract_bytes_at_va(bi, 0x10001000, len(data))
        assert result == data

    def test_va_not_in_section_returns_none(self, tmp_path: Path) -> None:
        """VA outside any section returns None."""
        data = b"\x55\x8b\xec\xc3"
        bi = self._make_binary_info(data, tmp_path)
        result = extract_bytes_at_va(bi, 0x20000000, 4)
        assert result is None


# ---------------------------------------------------------------------------
# detect_reversed_vas
# ---------------------------------------------------------------------------


class TestDetectReversedVas:
    """Tests for detect_reversed_vas()."""

    def test_empty_dir(self, tmp_path: Path) -> None:
        """Empty directory returns empty set."""
        result = detect_reversed_vas(tmp_path)
        assert result == set()

    def test_nonexistent_dir(self, tmp_path: Path) -> None:
        """Nonexistent directory returns empty set."""
        result = detect_reversed_vas(tmp_path / "nope")
        assert result == set()

    def test_finds_annotated_vas(self, tmp_path: Path) -> None:
        """Detects VAs from annotated .c files."""
        src = tmp_path / "func.c"
        src.write_text(
            "// FUNCTION: test.dll 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 32\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _my_func\n"
            "void my_func(void) {}\n",
            encoding="utf-8",
        )
        result = detect_reversed_vas(tmp_path)
        assert 0x10001000 in result

    def test_skips_non_c_files(self, tmp_path: Path) -> None:
        """Non-.c files are ignored."""
        txt = tmp_path / "notes.txt"
        txt.write_text("// FUNCTION: test.dll 0x10001000\n", encoding="utf-8")
        result = detect_reversed_vas(tmp_path)
        assert result == set()

    def test_multiple_functions(self, tmp_path: Path) -> None:
        """Multiple functions in one file are all detected."""
        src = tmp_path / "multi.c"
        src.write_text(
            "// FUNCTION: test.dll 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 32\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _func_a\n"
            "void func_a(void) {}\n"
            "\n"
            "// FUNCTION: test.dll 0x10002000\n"
            "// STATUS: RELOC\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _func_b\n"
            "void func_b(void) {}\n",
            encoding="utf-8",
        )
        result = detect_reversed_vas(tmp_path)
        assert 0x10001000 in result
        assert 0x10002000 in result

    def test_skips_data_markers(self, tmp_path: Path) -> None:
        """DATA and GLOBAL markers are excluded from the result set."""
        src = tmp_path / "data.c"
        src.write_text(
            "// GLOBAL: test.dll 0x10005000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 4\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _g_var\n"
            "int g_var = 0;\n",
            encoding="utf-8",
        )
        result = detect_reversed_vas(tmp_path)
        assert 0x10005000 not in result

    def test_stub_marker_not_reversed(self, tmp_path: Path) -> None:
        """A bare `// STUB:` pre-skeleton placeholder is not a reversed
        function — it stays an extract candidate.  Regression: stub-heavy
        projects (win2k-*, test_*) reported zero extract candidates even
        though every function was an unreversed pre-skeleton."""
        src = tmp_path / "stub.c"
        src.write_text(
            "// STUB: test.dll 0x10001000\n"
            "void fcn_0x10001000(void)\n"
            "{\n"
            "    /* pending per-function decompilation */\n"
            "}\n",
            encoding="utf-8",
        )
        assert detect_reversed_vas(tmp_path) == set()

    def test_function_marker_stub_status_still_reversed(self, tmp_path: Path) -> None:
        """A `// FUNCTION:` file whose metadata STATUS is STUB is a real
        (incomplete) attempt and stays reversed — only the bare STUB marker
        form is a pre-skeleton."""
        src = tmp_path / "func.c"
        src.write_text(
            "// FUNCTION: test.dll 0x10001000\n"
            "// STATUS: STUB\n"
            "// SIZE: 32\n"
            "void my_func(void) {}\n",
            encoding="utf-8",
        )
        assert 0x10001000 in detect_reversed_vas(tmp_path)


# ---------------------------------------------------------------------------
# cmd_list
# ---------------------------------------------------------------------------


class TestCmdList:
    """Tests for cmd_list()."""

    def test_empty_list(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Empty candidate list shows 0 count."""
        cmd_list([])
        captured = capsys.readouterr()
        assert "Candidates (0" in captured.err

    def test_formats_candidates(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Candidates are printed with VA, size, and name."""
        candidates = [
            (0x10001000, 32, "func_a"),
            (0x10002000, 128, "func_b"),
        ]
        cmd_list(candidates)
        captured = capsys.readouterr()
        assert "Candidates (2" in captured.err
        assert "0x10001000" in captured.err
        assert "func_a" in captured.err
        assert "func_b" in captured.err

    def test_index_numbering(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Candidates have sequential index numbers."""
        candidates = [(0x10001000 + i * 0x100, 16 + i, f"f{i}") for i in range(3)]
        cmd_list(candidates)
        captured = capsys.readouterr()
        # Rich Table renders numbered rows — check all 3 items appear in stderr
        assert "f0" in captured.err
        assert "f1" in captured.err
        assert "f2" in captured.err


class TestBatchTypeSafety:
    """Verify that extract.load_functions returns dicts with correct types."""

    def test_load_from_txt(self, tmp_path: Path) -> None:
        """parse_function_list returns {va: int, size: int, name: str}."""
        from types import SimpleNamespace
        from typing import Any

        from rebrew.extract import load_functions

        func_list = tmp_path / "functions.txt"
        func_list.write_text(
            "0x10001000 64 _func_a\n0x10002000 128 _func_b\n",
            encoding="utf-8",
        )
        cfg: Any = SimpleNamespace(function_list=func_list)
        funcs = load_functions(cfg)
        assert len(funcs) == 2
        assert isinstance(funcs[0]["va"], int)
        assert isinstance(funcs[0]["size"], int)
        assert isinstance(funcs[0]["name"], str)
        assert funcs[0]["va"] == 0x10001000
        assert funcs[0]["size"] == 64
