"""Tests for rebrew.link_order VA-ordered source helpers (order-sources CLI)."""

from pathlib import Path

from rebrew.link_order import _base_key, file_va, order_sources
from rebrew.metadata import record_function_identity


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

    def test_cp1252_source_still_finds_ascii_marker(self, tmp_path: Path) -> None:
        """Legacy-encoded sources go through read_source_text, not UTF-8-replace."""
        f = tmp_path / "legacy.c"
        f.write_bytes(b"// FUNCTION: T 0x10001000\n// Caf\xe9\nint a(void){return 0;}\n")
        assert file_va(f) == 0x10001000


class TestBaseKey:
    def test_posix_and_windows_separators(self) -> None:
        assert _base_key("zlib/adler32.c") == "adler32.c"
        assert _base_key("zlib\\adler32.c") == "adler32.c"
        assert _base_key("adler32.c") == "adler32.c"


class TestOrderSources:
    def test_migrated_sources_keep_function_order(self, tmp_path: Path) -> None:
        sources = tmp_path / "nested"
        sources.mkdir()
        hi = _write(sources / "a.c", "int high(void){return 2;}\n")
        lo = _write(sources / "z.c", "int low(void){return 1;}\n")
        for path, module, va, marker in (
            (hi, "SERVER", 0x10003000, "FUNCTION"),
            (lo, "SERVER", 0x10001000, "LIBRARY"),
            (hi, "CLIENT", 0x401000, "FUNCTION"),
        ):
            record_function_identity(
                tmp_path,
                module=module,
                va=va,
                file=f"nested/{path.name}",
                marker_type=marker,
            )
        assert file_va(hi, "SERVER", metadata_dir=tmp_path) == 0x10003000
        assert order_sources([hi, lo], marker="SERVER", metadata_dir=tmp_path)[0] == [lo, hi]
        assert order_sources(
            [hi, lo],
            first_va={"a.c": 0},
            marker="SERVER",
            metadata_dir=tmp_path,
        )[0] == [hi, lo]

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


class TestFileVaMarker:
    """Stacked shared files order by the requesting target's own marker."""

    def _stacked(self, tmp_path: Path) -> Path:
        p = tmp_path / "s.c"
        p.write_text(
            "// FUNCTION: V2 0x501000\n// SIZE: 11\n"
            "// FUNCTION: V1 0x401000\n// SIZE: 11\n"
            "int common(void){return 1;}\n",
            encoding="utf-8",
        )
        return p

    def test_unfiltered_minimum_unchanged(self, tmp_path: Path) -> None:
        assert file_va(self._stacked(tmp_path)) == 0x401000

    def test_marker_scopes_to_own_va(self, tmp_path: Path) -> None:
        f = self._stacked(tmp_path)
        assert file_va(f, "V2") == 0x501000
        assert file_va(f, "V1") == 0x401000

    def test_unknown_marker_falls_back(self, tmp_path: Path) -> None:
        assert file_va(self._stacked(tmp_path), "V9") == 0x401000

    def test_library_and_stub_keep_target_link_positions(self, tmp_path: Path) -> None:
        lib = _write(
            tmp_path / "gzread.c",
            "// LIBRARY: SERVER 0x10003960\n// FUNCTION: GOLDTL 0x45f380\n"
            "int gzread(void){return 1;}\n",
        )
        stub = _write(
            tmp_path / "stub.c",
            "/* STUB: SERVER 0x10003d20 */\nint stub(void){return 0;}\n"
            "/* DATA: SERVER 0x10001000 */\nint data;\n",
        )
        game = _write(
            tmp_path / "game.c", "// FUNCTION: SERVER 0x10006c80\nint game(void){return 0;}\n"
        )
        assert file_va(lib, "SERVER") == 0x10003960
        assert file_va(stub, "SERVER") == 0x10003D20
        assert order_sources([game, stub, lib], marker="SERVER")[0] == [lib, stub, game]
