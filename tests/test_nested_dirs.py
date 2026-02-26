"""Tests for nested directory support across rebrew tools.

Validates that all tools correctly discover, display, and deduplicate
source files in nested subdirectory layouts (e.g. src/server.dll/game/init.c
vs src/server.dll/network/init.c).
"""

from pathlib import Path
from types import SimpleNamespace

from rebrew.cli import iter_sources, rel_display_path
from rebrew.data import scan_data_annotations, scan_globals
from rebrew.ga import find_all_stubs, find_near_miss
from rebrew.lint import lint_file
from rebrew.naming import load_existing_vas

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

STUB_TEMPLATE = """\
// FUNCTION: SERVER 0x{va:08X}
// STATUS: {status}
// ORIGIN: {origin}
// SIZE: {size}
// CFLAGS: /O2 /Gd
// SYMBOL: {symbol}
{blocker}
void __cdecl {symbol_bare}(void)
{{
    return;
}}
"""

DATA_TEMPLATE = """\
// DATA: SERVER 0x{va:08X}
// STATUS: STUB
// ORIGIN: GAME
// SIZE: {size}

extern int {name};
"""

GLOBAL_TEMPLATE = """\
// FUNCTION: SERVER 0x{va:08X}
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 64
// CFLAGS: /O2 /Gd
// SYMBOL: _{func}

// GLOBAL: SERVER 0x{global_va:08X}
extern int {name};

int __cdecl {func}(void) {{ return 0; }}
"""


def _make_c(
    directory: Path,
    filename: str,
    va: int,
    *,
    status: str = "STUB",
    origin: str = "GAME",
    size: int = 64,
    symbol: str | None = None,
    blocker: str = "",
) -> Path:
    """Create a .c file with annotations in a (possibly nested) directory."""
    filepath = directory / filename
    filepath.parent.mkdir(parents=True, exist_ok=True)
    sym = symbol or f"_func_{va:08x}"
    sym_bare = sym.lstrip("_")
    filepath.write_text(
        STUB_TEMPLATE.format(
            va=va,
            status=status,
            origin=origin,
            size=size,
            symbol=sym,
            symbol_bare=sym_bare,
            blocker=f"// BLOCKER: {blocker}" if blocker else "",
        ),
        encoding="utf-8",
    )
    return filepath


# ---------------------------------------------------------------------------
# 1. rel_display_path
# ---------------------------------------------------------------------------


class TestRelDisplayPath:
    """Unit tests for the rel_display_path helper."""

    def test_flat_layout(self, tmp_path: Path) -> None:
        f = tmp_path / "my_func.c"
        f.touch()
        assert rel_display_path(f, tmp_path) == "my_func.c"

    def test_nested_layout(self, tmp_path: Path) -> None:
        f = tmp_path / "game" / "pool_free.c"
        f.parent.mkdir()
        f.touch()
        assert rel_display_path(f, tmp_path) == "game/pool_free.c"

    def test_deeply_nested(self, tmp_path: Path) -> None:
        f = tmp_path / "a" / "b" / "c" / "deep.c"
        f.parent.mkdir(parents=True)
        f.touch()
        assert rel_display_path(f, tmp_path) == "a/b/c/deep.c"

    def test_no_base_dir(self, tmp_path: Path) -> None:
        f = tmp_path / "game" / "init.c"
        f.parent.mkdir()
        f.touch()
        assert rel_display_path(f) == "init.c"

    def test_file_not_under_base(self, tmp_path: Path) -> None:
        f = tmp_path / "other" / "file.c"
        f.parent.mkdir()
        f.touch()
        base = tmp_path / "unrelated"
        base.mkdir()
        assert rel_display_path(f, base) == "file.c"


# ---------------------------------------------------------------------------
# 2. iter_sources
# ---------------------------------------------------------------------------


class TestIterSources:
    """iter_sources must find files in nested subdirectories."""

    def test_flat_files(self, tmp_path: Path) -> None:
        (tmp_path / "a.c").touch()
        (tmp_path / "b.c").touch()
        result = iter_sources(tmp_path)
        assert len(result) == 2

    def test_nested_files(self, tmp_path: Path) -> None:
        (tmp_path / "game").mkdir()
        (tmp_path / "network").mkdir()
        (tmp_path / "game" / "init.c").touch()
        (tmp_path / "network" / "init.c").touch()
        (tmp_path / "top.c").touch()
        result = iter_sources(tmp_path)
        assert len(result) == 3

    def test_deeply_nested(self, tmp_path: Path) -> None:
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)
        (nested / "deep.c").touch()
        result = iter_sources(tmp_path)
        assert len(result) == 1
        assert result[0].name == "deep.c"

    def test_sorted_by_path(self, tmp_path: Path) -> None:
        (tmp_path / "z").mkdir()
        (tmp_path / "a").mkdir()
        (tmp_path / "z" / "file.c").touch()
        (tmp_path / "a" / "file.c").touch()
        result = iter_sources(tmp_path)
        assert str(result[0]) < str(result[1])

    def test_respects_source_ext(self, tmp_path: Path) -> None:
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "file.cpp").touch()
        (tmp_path / "sub" / "file.c").touch()
        cfg = SimpleNamespace(source_ext=".cpp")
        result = iter_sources(tmp_path, cfg)
        assert len(result) == 1
        assert result[0].suffix == ".cpp"

    def test_empty_dir(self, tmp_path: Path) -> None:
        assert iter_sources(tmp_path) == []


# ---------------------------------------------------------------------------
# 3. load_existing_vas (skeleton.py) — stores relative paths
# ---------------------------------------------------------------------------


class TestLoadExistingVasNested:
    """load_existing_vas must store relative paths for nested files."""

    def test_flat_returns_filename(self, tmp_path: Path) -> None:
        _make_c(tmp_path, "func_a.c", 0x10001000)
        result = load_existing_vas(tmp_path)
        assert result[0x10001000] == "func_a.c"

    def test_nested_returns_relative_path(self, tmp_path: Path) -> None:
        _make_c(tmp_path, "game/pool_free.c", 0x10001000)
        result = load_existing_vas(tmp_path)
        assert result[0x10001000] == "game/pool_free.c"

    def test_multiple_nested_dirs(self, tmp_path: Path) -> None:
        _make_c(tmp_path, "game/init.c", 0x10001000)
        _make_c(tmp_path, "network/init.c", 0x10002000)
        result = load_existing_vas(tmp_path)
        assert result[0x10001000] == "game/init.c"
        assert result[0x10002000] == "network/init.c"

    def test_mixed_flat_and_nested(self, tmp_path: Path) -> None:
        _make_c(tmp_path, "top_func.c", 0x10001000)
        _make_c(tmp_path, "sub/nested_func.c", 0x10002000)
        result = load_existing_vas(tmp_path)
        assert result[0x10001000] == "top_func.c"
        assert result[0x10002000] == "sub/nested_func.c"


# ---------------------------------------------------------------------------
# 4. find_all_stubs (ga.py) — discovers nested stubs
# ---------------------------------------------------------------------------


class TestFindAllStubsNested:
    """find_all_stubs must discover STUB files in nested directories."""

    def test_finds_nested_stubs(self, tmp_path: Path) -> None:
        _make_c(tmp_path, "game/func_a.c", 0x10001000, size=64)
        _make_c(tmp_path, "network/func_b.c", 0x10002000, size=128)
        stubs = find_all_stubs(tmp_path)
        assert len(stubs) == 2

    def test_duplicate_va_across_nested_dirs(self, tmp_path: Path, capsys: object) -> None:
        """Duplicate VA across nested dirs — only the first (sorted) is kept."""
        _make_c(tmp_path, "aaa/func.c", 0x10001000, symbol="_dup_a")
        _make_c(tmp_path, "zzz/func.c", 0x10001000, symbol="_dup_b")
        stubs = find_all_stubs(tmp_path)
        assert len(stubs) == 1

    def test_nested_sorted_by_size(self, tmp_path: Path) -> None:
        _make_c(tmp_path, "big/func.c", 0x10002000, size=200)
        _make_c(tmp_path, "small/func.c", 0x10001000, size=32)
        stubs = find_all_stubs(tmp_path)
        assert stubs[0]["size"] <= stubs[1]["size"]


# ---------------------------------------------------------------------------
# 5. find_near_miss (ga.py) — discovers nested MATCHING files
# ---------------------------------------------------------------------------


class TestFindNearMissNested:
    """find_near_miss must discover MATCHING files in nested directories."""

    def test_finds_nested_matching(self, tmp_path: Path) -> None:
        _make_c(
            tmp_path,
            "game/near.c",
            0x10001000,
            status="MATCHING",
            blocker="5 byte diffs at [0, 1, 2, 3, 4]",
        )
        results = find_near_miss(tmp_path, max_delta=10)
        assert len(results) == 1


# ---------------------------------------------------------------------------
# 6. lint — duplicate VA tracking with nested paths
# ---------------------------------------------------------------------------


class TestLintNestedDuplicateVA:
    """Lint E013 duplicate VA should use relative paths in messages."""

    def test_duplicate_va_shows_relative_path(self, tmp_path: Path) -> None:
        f1 = _make_c(tmp_path, "game/func_10001000.c", 0x10001000, status="EXACT")
        f2 = _make_c(tmp_path, "network/func_10001000.c", 0x10001000, status="EXACT")

        seen_vas: dict[int, str] = {}
        r1 = lint_file(f1, seen_vas=seen_vas)
        assert r1.passed  # first file should pass

        r2 = lint_file(f2, seen_vas=seen_vas)
        # second file should have E013
        e013_errors = [msg for _, code, msg in r2.errors if code == "E013"]
        assert len(e013_errors) == 1
        # The error message should reference the first file's name
        assert "func_10001000.c" in e013_errors[0]


# ---------------------------------------------------------------------------
# 7. scan_globals (data.py) — nested directory support
# ---------------------------------------------------------------------------


class TestScanGlobalsNested:
    """scan_globals must discover globals in nested directories."""

    def test_finds_nested_globals(self, tmp_path: Path) -> None:
        (tmp_path / "game").mkdir()
        f = tmp_path / "game" / "func.c"
        f.write_text(
            GLOBAL_TEMPLATE.format(
                va=0x10001000,
                global_va=0x100A0000,
                name="g_counter",
                func="my_func",
            ),
            encoding="utf-8",
        )
        result = scan_globals(tmp_path)
        assert "g_counter" in result.globals
        assert result.globals["g_counter"].va == 0x100A0000


# ---------------------------------------------------------------------------
# 8. scan_data_annotations (data.py) — nested directory support
# ---------------------------------------------------------------------------


class TestScanDataAnnotationsNested:
    """scan_data_annotations must discover DATA annotations in nested dirs."""

    def test_finds_nested_data(self, tmp_path: Path) -> None:
        (tmp_path / "sub").mkdir()
        f = tmp_path / "sub" / "data.c"
        f.write_text(
            DATA_TEMPLATE.format(va=0x10050000, size=4, name="g_value"),
            encoding="utf-8",
        )
        entries = scan_data_annotations(tmp_path)
        assert len(entries) == 1
        # filepath should be relative, not just filename
        assert entries[0]["filepath"] == "sub/data.c" or "data.c" in entries[0]["filepath"]

    def test_mixed_flat_and_nested(self, tmp_path: Path) -> None:
        f1 = tmp_path / "top.c"
        f1.write_text(
            DATA_TEMPLATE.format(va=0x10050000, size=4, name="g_top"),
            encoding="utf-8",
        )
        (tmp_path / "sub").mkdir()
        f2 = tmp_path / "sub" / "nested.c"
        f2.write_text(
            DATA_TEMPLATE.format(va=0x10060000, size=8, name="g_nested"),
            encoding="utf-8",
        )
        entries = scan_data_annotations(tmp_path)
        assert len(entries) == 2


# ---------------------------------------------------------------------------
# 9. Integration: same-named files in different subdirs don't collide
# ---------------------------------------------------------------------------


class TestNestedPathUniqueness:
    """Files with the same name in different subdirs must remain distinct."""

    def test_load_existing_vas_distinguishes_same_name(self, tmp_path: Path) -> None:
        """game/init.c and network/init.c should map to different VAs."""
        _make_c(tmp_path, "game/init.c", 0x10001000)
        _make_c(tmp_path, "network/init.c", 0x10002000)
        result = load_existing_vas(tmp_path)
        assert len(result) == 2
        assert result[0x10001000] != result[0x10002000]
        assert "game/init.c" in result.values()
        assert "network/init.c" in result.values()

    def test_find_all_stubs_distinguishes_same_name(self, tmp_path: Path) -> None:
        """game/init.c and network/init.c with different VAs both found."""
        _make_c(tmp_path, "game/init.c", 0x10001000, size=32)
        _make_c(tmp_path, "network/init.c", 0x10002000, size=64)
        stubs = find_all_stubs(tmp_path)
        assert len(stubs) == 2
        paths = {str(s["filepath"]) for s in stubs}
        assert any("game" in p for p in paths)
        assert any("network" in p for p in paths)

    def test_iter_sources_returns_all_same_named(self, tmp_path: Path) -> None:
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        (tmp_path / "a" / "init.c").touch()
        (tmp_path / "b" / "init.c").touch()
        result = iter_sources(tmp_path)
        assert len(result) == 2
