"""Tests for rebrew.order_sources — VA-ordered source layout."""

from pathlib import Path

from rebrew.order_sources import _base_key, file_va, order_sources


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


class TestFileVa:
    def test_lowest_va_wins(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path / "a.c",
            "// FUNCTION: T 0x10002000\nint a(void){return 0;}\n"
            "// FUNCTION: T 0x10001000\nint b(void){return 1;}\n",
        )
        assert file_va(f) == 0x10001000

    def test_no_marker_returns_none(self, tmp_path: Path) -> None:
        assert file_va(_write(tmp_path / "b.c", "int x;\n")) is None

    def test_missing_file_returns_none(self, tmp_path: Path) -> None:
        assert file_va(tmp_path / "nope.c") is None


class TestBaseKey:
    def test_posix_and_windows_separators(self) -> None:
        assert _base_key("zlib/adler32.c") == "adler32.c"
        assert _base_key("zlib\\adler32.c") == "adler32.c"
        assert _base_key("adler32.c") == "adler32.c"


class TestOrderSources:
    def test_known_first_then_unknown(self, tmp_path: Path) -> None:
        hi = _write(tmp_path / "hi.c", "// FUNCTION: T 0x10002000\nint h(void){return 0;}\n")
        lo = _write(tmp_path / "lo.c", "// FUNCTION: T 0x10001000\nint l(void){return 0;}\n")
        unk = _write(tmp_path / "z.c", "int z;\n")
        ordered, excluded = order_sources([hi, unk, lo])
        assert ordered == [lo, hi, unk]
        assert excluded == []

    def test_first_va_table_and_exclude(self, tmp_path: Path) -> None:
        lib = _write(tmp_path / "adler32.c", "int a;\n")
        drop = _write(tmp_path / "gzio.c", "int g;\n")
        ordered, excluded = order_sources(
            [drop, lib], first_va={"zlib/adler32.c": 0x10000000}, exclude={"gzio.c"}
        )
        assert ordered == [lib]
        assert excluded == ["gzio.c"]

    def test_empty_input(self) -> None:
        assert order_sources([]) == ([], [])


class TestBlockMarkersAndZeroVa:
    def test_block_style_marker_is_read(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path / "tc.c",
            "/* FUNCTION: MAIN 0x00001000 */\nint a(void){return 0;}\n",
        )
        assert file_va(f) == 0x1000

    def test_explicit_zero_va_overrides_marker(self, tmp_path: Path) -> None:
        """`--first-va f=0x0` is a real override, not a missing value."""
        hi = _write(tmp_path / "a.c", "// FUNCTION: T 0x10003000\nint a(void){return 0;}\n")
        lo = _write(tmp_path / "b.c", "// FUNCTION: T 0x10001000\nint b(void){return 0;}\n")
        ordered, _ = order_sources([hi, lo], first_va={"a.c": 0x0})
        assert ordered == [hi, lo]
