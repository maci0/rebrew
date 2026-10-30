"""Tests for rebrew.link_order VA-ordered source helpers (order-sources CLI)."""

from pathlib import Path

from source_util import SourceFixture, write_source

from rebrew.link_order import _base_key, file_va, order_sources
from rebrew.metadata.functions import record_function_identity


def _write(path: Path, text: str) -> Path:
    write_source(path, text, encoding="utf-8")
    return path


class TestFileVa:
    def test_lowest_va_wins(self, tmp_path: Path) -> None:
        f = _write(
            tmp_path / "a.c",
            SourceFixture(
                "/* ADDRESS: T 0x10002000 */\nint a(void){return 0;}\n/* ADDRESS: T 0x10001000 */\nint b(void){return 1;}\n",
                {"T.0x10002000": {"kind": "FUNCTION"}, "T.0x10001000": {"kind": "FUNCTION"}},
            ),
        )
        assert file_va(f) == 0x10001000

    def test_no_marker_returns_none(self, tmp_path: Path) -> None:
        assert file_va(_write(tmp_path / "b.c", "int x;\n")) is None

    def test_missing_file_returns_none(self, tmp_path: Path) -> None:
        assert file_va(tmp_path / "nope.c") is None

    def test_cp1252_source_still_finds_ascii_marker(self, tmp_path: Path) -> None:
        """Legacy-encoded sources go through read_source_text, not UTF-8-replace."""
        f = tmp_path / "legacy.c"
        f.write_bytes(b"/* ADDRESS: T 0x10001000 */\n// Caf\xe9\nint a(void){return 0;}\n")
        assert file_va(f) == 0x10001000


class TestBaseKey:
    def test_posix_and_windows_separators(self) -> None:
        assert _base_key("zlib/adler32.c") == "adler32.c"
        assert _base_key("zlib\\adler32.c") == "adler32.c"
        assert _base_key("adler32.c") == "adler32.c"


class TestFirstVaFile:
    def test_order_file_supplies_a_missing_va(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from rebrew.app.main import app

        hi = _write(tmp_path / "a.c", "int high(void){return 0;}\n")
        lo = _write(tmp_path / "z.c", "/* ADDRESS: T 0x10001000 */\nint low(void){return 1;}\n")
        order = tmp_path / "order.txt"
        order.write_text("# vendored\na.c=0x10002000\n", encoding="utf-8")
        result = CliRunner().invoke(
            app,
            ["build", "order-sources", str(hi), str(lo), "--first-va-file", str(order), "--json"],
        )
        assert result.exit_code == 0, result.output
        ordered = [Path(item).name for item in __import__("json").loads(result.stdout)["ordered"]]
        assert ordered == ["a.c", "z.c"]

    def test_conflicting_file_entry_is_refused(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from rebrew.app.main import app

        src = _write(tmp_path / "a.c", "int a(void){return 0;}\n")
        order = tmp_path / "order.txt"
        order.write_text("a.c=0x10000000\n", encoding="utf-8")
        result = CliRunner().invoke(
            app,
            [
                "build",
                "order-sources",
                str(src),
                "--first-va",
                "a.c=0x10001000",
                "--first-va-file",
                str(order),
            ],
        )
        assert result.exit_code != 0
        assert "already has" in result.output


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
                kind=marker,
            )
        assert file_va(hi, "SERVER", metadata_dir=tmp_path) == 0x10003000
        assert order_sources([hi, lo], target_module_name="SERVER", metadata_dir=tmp_path)[0] == [
            lo,
            hi,
        ]
        assert order_sources(
            [hi, lo],
            first_va={"a.c": 0},
            target_module_name="SERVER",
            metadata_dir=tmp_path,
        )[0] == [hi, lo]

    def test_known_first_then_unknown(self, tmp_path: Path) -> None:
        hi = _write(
            tmp_path / "hi.c",
            SourceFixture(
                "/* ADDRESS: T 0x10002000 */\nint h(void){return 0;}\n",
                {"T.0x10002000": {"kind": "FUNCTION"}},
            ),
        )
        lo = _write(
            tmp_path / "lo.c",
            SourceFixture(
                "/* ADDRESS: T 0x10001000 */\nint l(void){return 0;}\n",
                {"T.0x10001000": {"kind": "FUNCTION"}},
            ),
        )
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
            SourceFixture(
                "/* ADDRESS: MAIN 0x00001000 */\nint a(void){return 0;}\n",
                {"MAIN.0x00001000": {"kind": "FUNCTION"}},
            ),
        )
        assert file_va(f) == 0x1000

    def test_explicit_zero_va_overrides_marker(self, tmp_path: Path) -> None:
        """`--first-va f=0x0` is a real override, not a missing value."""
        hi = _write(
            tmp_path / "a.c",
            SourceFixture(
                "/* ADDRESS: T 0x10003000 */\nint a(void){return 0;}\n",
                {"T.0x10003000": {"kind": "FUNCTION"}},
            ),
        )
        lo = _write(
            tmp_path / "b.c",
            SourceFixture(
                "/* ADDRESS: T 0x10001000 */\nint b(void){return 0;}\n",
                {"T.0x10001000": {"kind": "FUNCTION"}},
            ),
        )
        ordered, _ = order_sources([hi, lo], first_va={"a.c": 0x0})
        assert ordered == [hi, lo]


class TestFileVaModule:
    """Stacked shared files order by the requesting target's own module."""

    def _stacked(self, tmp_path: Path) -> Path:
        p = tmp_path / "s.c"
        write_source(
            p,
            "/* ADDRESS: V2 0x501000 */\n\n/* ADDRESS: V1 0x401000 */\n\nint common(void){return 1;}\n",
            encoding="utf-8",
            metadata_fields={
                "V2.0x501000": {"kind": "FUNCTION", "size": 11},
                "V1.0x401000": {"kind": "FUNCTION", "size": 11},
            },
        )
        return p

    def test_unfiltered_minimum_unchanged(self, tmp_path: Path) -> None:
        assert file_va(self._stacked(tmp_path)) == 0x401000

    def test_module_scopes_to_own_va(self, tmp_path: Path) -> None:
        f = self._stacked(tmp_path)
        assert file_va(f, "V2") == 0x501000
        assert file_va(f, "V1") == 0x401000

    def test_foreign_module_has_no_order(self, tmp_path: Path) -> None:
        assert file_va(self._stacked(tmp_path), "V9") is None

    def test_library_and_stub_keep_target_link_positions(self, tmp_path: Path) -> None:
        lib = _write(
            tmp_path / "gzread.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x10003960 */\n/* ADDRESS: GOLDTL 0x45f380 */\nint gzread(void){return 1;}\n",
                {"SERVER.0x10003960": {"kind": "LIBRARY"}, "GOLDTL.0x45f380": {"kind": "FUNCTION"}},
            ),
        )
        stub = _write(
            tmp_path / "stub.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x10003d20 */\nint stub(void){return 0;}\n/* ADDRESS: SERVER 0x10001000 */\nint data;\n",
                {"SERVER.0x10003d20": {"kind": "STUB"}, "SERVER.0x10001000": {"kind": "DATA"}},
            ),
        )
        game = _write(
            tmp_path / "game.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x10006c80 */\nint game(void){return 0;}\n",
                {"SERVER.0x10006c80": {"kind": "FUNCTION"}},
            ),
        )
        assert file_va(lib, "SERVER") == 0x10003960
        assert file_va(stub, "SERVER") == 0x10003D20
        assert order_sources([game, stub, lib], target_module_name="SERVER")[0] == [lib, stub, game]
