"""Tests for rebrew.extract — extract_bytes, detect_reversed_vas, cmd_list."""

from pathlib import Path

import pytest

from rebrew.binary_loader import BinaryInfo, SectionInfo
from rebrew.extract import cmd_list, detect_reversed_vas, extract_bytes

# ---------------------------------------------------------------------------
# extract_bytes
# ---------------------------------------------------------------------------


class TestExtractBytes:
    """Tests for extract_bytes() wrapper."""

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
        result = extract_bytes(bi, 0x10001000, 4)
        assert result == b"\x55\x8b\xec\x83"

    def test_full_size(self, tmp_path: Path) -> None:
        """Extracts full function bytes."""
        data = b"\x55\x8b\xec\xc3"
        bi = self._make_binary_info(data, tmp_path)
        result = extract_bytes(bi, 0x10001000, len(data))
        assert result == data

    def test_va_not_in_section_returns_empty(self, tmp_path: Path) -> None:
        """VA outside any section returns empty bytes."""
        data = b"\x55\x8b\xec\xc3"
        bi = self._make_binary_info(data, tmp_path)
        result = extract_bytes(bi, 0x20000000, 4)
        assert result == b""


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


# ---------------------------------------------------------------------------
# cmd_list
# ---------------------------------------------------------------------------


class TestCmdList:
    """Tests for cmd_list()."""

    def test_empty_list(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Empty candidate list shows 0 count."""
        cmd_list([])
        captured = capsys.readouterr()
        assert "Candidates: 0" in captured.out

    def test_formats_candidates(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Candidates are printed with VA, size, and name."""
        candidates = [
            (0x10001000, 32, "func_a"),
            (0x10002000, 128, "func_b"),
        ]
        cmd_list(candidates)
        captured = capsys.readouterr()
        assert "Candidates: 2" in captured.out
        assert "0x10001000" in captured.out
        assert "func_a" in captured.out
        assert "func_b" in captured.out

    def test_index_numbering(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Candidates have sequential index numbers."""
        candidates = [(0x10001000 + i * 0x100, 16 + i, f"f{i}") for i in range(3)]
        cmd_list(candidates)
        captured = capsys.readouterr()
        lines = [
            line for line in captured.out.splitlines() if line.strip().startswith(("0", "1", "2"))
        ]
        assert len(lines) == 3
