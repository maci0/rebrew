"""Tests for match.py annotation parsing filters."""

from pathlib import Path

from rebrew.match import (
    find_all_stubs,
    find_near_miss,
    parse_matching_info,
    parse_stub_info,
)


def _write_stub(tmp_path: Path, name: str, content: str) -> Path:
    f = tmp_path / name
    f.write_text(content, encoding="utf-8")
    return f


def _stub_file(tmp_path: Path, va: int = 0x10001000, status: str = "STUB", size: int = 64) -> Path:
    return _write_stub(
        tmp_path,
        "func.c",
        f"// FUNCTION: SERVER 0x{va:x}\n"
        f"// STATUS: {status}\n"
        f"// SIZE: {size}\n"
        f"// SYMBOL: _func\n"
        f"int func(void) {{ return 1; }}\n",
    )


class TestParseStubInfo:
    def test_basic_stub(self, tmp_path: Path) -> None:
        f = _stub_file(tmp_path)
        stubs = parse_stub_info(f)
        assert len(stubs) == 1
        assert stubs[0].status == "STUB"
        assert stubs[0].va == "0x10001000"
        assert stubs[0].size == 64

    def test_non_stub_excluded(self, tmp_path: Path) -> None:
        f = _stub_file(tmp_path, status="EXACT")
        assert parse_stub_info(f) == []

    def test_ignored_symbol(self, tmp_path: Path) -> None:
        f = _stub_file(tmp_path)
        assert parse_stub_info(f, ignored={"func"}) == []
        assert parse_stub_info(f, ignored={"_func"}) == []

    def test_tiny_size_excluded(self, tmp_path: Path) -> None:
        f = _stub_file(tmp_path, size=4)  # < 10
        assert parse_stub_info(f) == []

    def test_low_va_excluded(self, tmp_path: Path) -> None:
        f = _stub_file(tmp_path, va=0x500)
        assert parse_stub_info(f) == []


class TestParseMatchingInfo:
    def test_near_matching_delta_filter(self, tmp_path: Path) -> None:
        f = _write_stub(
            tmp_path,
            "func.c",
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: NEAR_MATCHING\n"
            "// SIZE: 32\n"
            "// SYMBOL: _func\n"
            "// BLOCKER_DELTA: 4\n"
            "int func(void) { return 1; }\n",
        )
        stubs = parse_matching_info(f, max_delta=10)
        assert len(stubs) == 1
        assert stubs[0].delta == 4
        # max_delta below the blocker delta excludes it.
        assert parse_matching_info(f, max_delta=2) == []

    def test_exact_not_near(self, tmp_path: Path) -> None:
        f = _stub_file(tmp_path, status="EXACT")
        assert parse_matching_info(f) == []


class TestFindAllStubs:
    def test_finds_stub(self, tmp_path: Path) -> None:
        _stub_file(tmp_path)  # created inside tmp_path (the reversed dir)
        assert [s.symbol for s in find_all_stubs(tmp_path)] == ["_func"]


class TestFindNearMiss:
    def test_finds_near_matching(self, tmp_path: Path) -> None:
        _write_stub(
            tmp_path,
            "func.c",
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: NEAR_MATCHING\n"
            "// SIZE: 32\n"
            "// SYMBOL: _func\n"
            "// BLOCKER_DELTA: 3\n"
            "int func(void) { return 1; }\n",
        )
        stubs = find_near_miss(tmp_path)
        assert len(stubs) == 1
        assert stubs[0].status == "NEAR_MATCHING"


class TestUpdateCflagsAnnotation:
    def test_updates_cflags(self, tmp_path: Path) -> None:
        from rebrew.match import update_cflags_annotation

        f = _stub_file(tmp_path, status="STUB")
        assert update_cflags_annotation(f, "/O1") is True
        # Second identical update is a no-op.
        assert update_cflags_annotation(f, "/O1") is False

    def test_no_marker_returns_false(self, tmp_path: Path) -> None:
        from rebrew.match import update_cflags_annotation

        f = _write_stub(tmp_path, "plain.c", "int plain(void) { return 0; }\n")
        assert update_cflags_annotation(f, "/O1") is False

    def test_unreadable_returns_false(self, tmp_path: Path) -> None:
        from rebrew.match import update_cflags_annotation

        assert update_cflags_annotation(tmp_path / "missing.c", "/O1") is False
