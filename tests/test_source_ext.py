"""Tests for source language detection and configurable source_ext."""

from __future__ import annotations

import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from rebrew.binary_loader import detect_source_language
from rebrew.config import ProjectConfig
from rebrew.sources import (
    files_with_ext,
    iter_headers,
    iter_library_headers,
    iter_sources,
    scan_files,
    source_glob,
)


def test_sources_public_all() -> None:
    """Star-imports must not leak typing/stdlib names into consumer namespaces.

    ``files_with_ext`` belongs to the declared surface: the cross-module
    private-import refactor promoted it (``data_layout`` imports it, which an
    underscore name forbids) and listed it in ``sources.__all__``.  This
    literal mirrors that declaration so dropping it narrows the surface
    visibly.
    """
    import rebrew.sources as sources

    assert sources.__all__ == [
        "contained_path",
        "files_with_ext",
        "iter_headers",
        "iter_library_headers",
        "iter_sources",
        "iter_sources_and_headers",
        "scan_files",
        "source_exts",
        "source_glob",
        "source_roots",
        "target_marker",
    ]
    for name in sources.__all__:
        assert getattr(sources, name, None) is not None, name
    ns: dict[str, Any] = {}
    exec("from rebrew.sources import *", ns)  # noqa: S102
    exported = {k for k in ns if not k.startswith("_")}
    assert exported == set(sources.__all__)


class TestScanFiles:
    """``scan_files`` is the one traversal behind every source enumerator."""

    def _tree(self, root: Path) -> Path:
        src = root / "src"
        (src / "sub" / "deep").mkdir(parents=True)
        (src / "build").mkdir()
        (src / "a.c").write_text("x", encoding="utf-8")
        (src / "B.CPP").write_text("x", encoding="utf-8")
        (src / "sub" / "b.c").write_text("x", encoding="utf-8")
        (src / "sub" / "deep" / "c.cpp").write_text("x", encoding="utf-8")
        (src / "sub" / "library_zlib.h").write_text("x", encoding="utf-8")
        (src / "build" / "skip.c").write_text("x", encoding="utf-8")
        (src / "linkdir").symlink_to(src / "sub", target_is_directory=True)
        (src / "linkfile.c").symlink_to(src / "a.c")
        (src / "broken.c").symlink_to(src / "nowhere")
        return src

    def test_scan_matches_a_plain_walk(self, tmp_path: Path) -> None:
        """Sorted, symlink-free, exclusions applied, nested and case-insensitive."""
        src = self._tree(tmp_path)
        assert [p.name for p in scan_files(src)] == [
            "B.CPP",
            "a.c",
            "b.c",
            "c.cpp",
            "library_zlib.h",
        ]

    def test_filtered_views_agree_with_scanned_passthrough(self, tmp_path: Path) -> None:
        """Passing ``scanned=`` filters the same traversal instead of redoing it.

        This is what lets one command (``rebrew status``) walk the reversed
        tree once for its source pass, its library-header pass, and its file
        count; the results must not depend on whether the tree was walked
        once or three times.
        """
        src = self._tree(tmp_path)
        cfg = ProjectConfig(root=tmp_path, reversed_dir=src, target_name="t", marker="T")
        tree = scan_files(src)
        assert iter_sources(src, cfg, scanned=tree) == iter_sources(src, cfg)
        assert iter_library_headers(src, cfg, scanned=tree) == iter_library_headers(src, cfg)
        assert iter_headers(src, cfg) == files_with_ext(src, {".h"})


# ---------------------------------------------------------------------------
# detect_source_language() tests
# ---------------------------------------------------------------------------


def _make_pe_binary(tmp_path: Path, symbols: list[str] | None = None) -> Path:
    """Create a minimal PE binary with optional export names."""
    pe_path = tmp_path / "SERVER"
    # Minimal MZ + PE stub — enough for LIEF to parse
    # We rely on LIEF being forgiving about incomplete PE files
    pe_path.write_bytes(
        b"MZ" + b"\x00" * 58 + struct.pack("<I", 64) + b"PE\x00\x00" + b"\x00" * 200
    )
    return pe_path


def test_detect_c_default(tmp_path: Path) -> None:
    """No C++ symbols → returns C."""
    pe_path = _make_pe_binary(tmp_path)
    lang, ext = detect_source_language(pe_path)
    assert ext == ".c"
    assert lang == "C"


def test_detect_nonexistent_file() -> None:
    """Non-existent file → default C."""
    lang, ext = detect_source_language(Path("/nonexistent/binary.dll"))
    assert ext == ".c"
    assert lang == "C"


def _detect_with_mock(mock_binary: SimpleNamespace) -> tuple[str, str]:
    """Helper: run detect_source_language with a mocked binary and file existence."""
    with (
        patch("rebrew.binary_loader.lief.parse", return_value=mock_binary),
        patch.object(Path, "exists", return_value=True),
    ):
        return detect_source_language(Path("/fake/test.bin"))


def test_detect_cpp_msvc() -> None:
    """Symbols starting with ? → C++."""
    mock = SimpleNamespace(
        sections=[],
        symbols=[SimpleNamespace(name=f"?func{i}@@YAXXZ") for i in range(5)],
    )
    lang, ext = _detect_with_mock(mock)
    assert ext == ".cpp"
    assert lang == "C++"


def test_detect_cpp_itanium() -> None:
    """Symbols starting with _Z → C++."""
    mock = SimpleNamespace(
        sections=[],
        symbols=[SimpleNamespace(name=f"_Z{i}funcv") for i in range(5)],
    )
    lang, ext = _detect_with_mock(mock)
    assert ext == ".cpp"
    assert lang == "C++"


def test_detect_rust() -> None:
    """Symbols starting with _R + alpha → Rust."""
    mock = SimpleNamespace(
        sections=[],
        symbols=[SimpleNamespace(name=f"_RNvC{i}_4core") for i in range(5)],
    )
    lang, ext = _detect_with_mock(mock)
    assert ext == ".rs"
    assert lang == "Rust"


def test_detect_go_section() -> None:
    """Section named .gopclntab → Go."""
    mock = SimpleNamespace(
        sections=[SimpleNamespace(name=".gopclntab")],
        symbols=[],
    )
    lang, ext = _detect_with_mock(mock)
    assert ext == ".go"
    assert lang == "Go"


def test_detect_objc_section() -> None:
    """Section named __objc_methnames → Objective-C."""
    mock = SimpleNamespace(
        sections=[SimpleNamespace(name="__objc_methnames")],
        symbols=[],
    )
    lang, ext = _detect_with_mock(mock)
    assert ext == ".m"
    assert lang == "Objective-C"


def test_detect_d() -> None:
    """Symbols starting with _D + digit → D."""
    mock = SimpleNamespace(
        sections=[],
        symbols=[SimpleNamespace(name=f"_D3std{i}") for i in range(5)],
    )
    lang, ext = _detect_with_mock(mock)
    assert ext == ".d"
    assert lang == "D"


def test_detect_threshold_not_met() -> None:
    """Below threshold (< 3 symbols) → default C."""
    mock = SimpleNamespace(
        sections=[],
        symbols=[SimpleNamespace(name="?func1@@YAXXZ"), SimpleNamespace(name="?func2@@YAXXZ")],
    )
    lang, ext = _detect_with_mock(mock)
    assert ext == ".c"
    assert lang == "C"


# ---------------------------------------------------------------------------
# source_glob() tests
# ---------------------------------------------------------------------------


def test_source_glob_default() -> None:
    """No cfg → default *.c."""
    assert source_glob(None) == "*.c"


def test_source_glob_c() -> None:
    """source_ext=.c → *.c."""
    cfg = ProjectConfig(root=Path("/tmp"), source_ext=".c")
    assert source_glob(cfg) == "*.c"


def test_source_glob_cpp() -> None:
    """source_ext=.cpp → *.cpp."""
    cfg = ProjectConfig(root=Path("/tmp"), source_ext=".cpp")
    assert source_glob(cfg) == "*.cpp"


def test_source_glob_rs() -> None:
    """source_ext=.rs → *.rs."""
    cfg = ProjectConfig(root=Path("/tmp"), source_ext=".rs")
    assert source_glob(cfg) == "*.rs"


def test_source_glob_no_attr() -> None:
    """cfg without source_ext attribute → *.c."""
    cfg = ProjectConfig(
        root=Path("/tmp"),
    )
    assert source_glob(cfg) == "*.c"


# ---------------------------------------------------------------------------
# ProjectConfig.source_ext tests
# ---------------------------------------------------------------------------


def test_config_source_ext_default() -> None:
    """ProjectConfig defaults to .c."""
    cfg = ProjectConfig(root=Path("/tmp"))
    assert cfg.source_ext == ".c"


# ---------------------------------------------------------------------------
# skeleton make_filename() tests
# ---------------------------------------------------------------------------


def test_make_filename_c() -> None:
    """Default cfg → .c extension."""
    from rebrew.naming import make_filename

    cfg = ProjectConfig(root=Path("/tmp"), source_ext=".c")
    result = make_filename("my_func", "GAME", cfg=cfg)
    assert result.endswith(".c")


def test_make_filename_cpp() -> None:
    """source_ext=.cpp → .cpp extension."""
    from rebrew.naming import make_filename

    cfg = ProjectConfig(root=Path("/tmp"), source_ext=".cpp")
    result = make_filename("my_func", "GAME", cfg=cfg)
    assert result.endswith(".cpp")


def test_make_filename_no_cfg() -> None:
    """No cfg → .c extension (backward compat)."""
    from rebrew.naming import make_filename

    result = make_filename("my_func", "GAME")
    assert result.endswith(".c")


# ---------------------------------------------------------------------------
# load_existing_vas() tests
# ---------------------------------------------------------------------------


def test_load_existing_vas_with_cfg(tmp_path: Path) -> None:
    """load_existing_vas uses source_glob(cfg) pattern."""
    from rebrew.naming import load_existing_vas

    # Create a .cpp file with annotation
    cpp_file = tmp_path / "my_func.cpp"
    cpp_file.write_text(
        "// FUNCTION: SERVER 0x10001000\n"
        "// STATUS: STUB\n"
        "// ORIGIN: GAME\n"
        "// SIZE: 100\n"
        "// CFLAGS: /O2\n"
        "// SYMBOL: _my_func\n"
        "int my_func(void) { return 0; }\n",
        encoding="utf-8",
    )
    # Also create a .c file that should NOT be found with .cpp config
    c_file = tmp_path / "other.c"
    c_file.write_text(
        "// FUNCTION: SERVER 0x10002000\n"
        "// STATUS: STUB\n"
        "// ORIGIN: GAME\n"
        "// SIZE: 50\n"
        "// CFLAGS: /O2\n"
        "// SYMBOL: _other\n"
        "int other(void) { return 0; }\n",
        encoding="utf-8",
    )

    cfg_cpp = ProjectConfig(root=Path("/tmp"), source_ext=".cpp")
    result_cpp = load_existing_vas(tmp_path, cfg=cfg_cpp)
    assert 0x10001000 in result_cpp
    assert 0x10002000 not in result_cpp

    cfg_c = ProjectConfig(root=Path("/tmp"), source_ext=".c")
    result_c = load_existing_vas(tmp_path, cfg=cfg_c)
    assert 0x10002000 in result_c
    assert 0x10001000 not in result_c


class TestContainedPath:
    """``file`` is a path, not a label: it must not reach outside the trees."""

    def test_relative_inside_root_resolves(self, tmp_path: Path) -> None:
        from rebrew.sources import contained_path

        rev = tmp_path / "src_SERVER"
        rev.mkdir()
        assert contained_path(rev, "pool/f.c") == (rev / "pool/f.c").resolve()

    def test_parent_escape_refused(self, tmp_path: Path) -> None:
        from rebrew.sources import contained_path

        rev = tmp_path / "src_SERVER"
        rev.mkdir()
        assert contained_path(rev, "../../.bashrc") is None

    def test_absolute_refused(self, tmp_path: Path) -> None:
        from rebrew.sources import contained_path

        rev = tmp_path / "src_SERVER"
        rev.mkdir()
        assert contained_path(rev, tmp_path / "other.c") is None

    def test_empty_refused(self, tmp_path: Path) -> None:
        from rebrew.sources import contained_path

        assert contained_path(tmp_path, "") is None

    def test_symlink_out_of_root_refused(self, tmp_path: Path) -> None:
        from rebrew.sources import contained_path

        rev = tmp_path / "src_SERVER"
        rev.mkdir()
        outside = tmp_path / "secret.c"
        outside.write_text("int x;\n", encoding="utf-8")
        (rev / "f.c").symlink_to(outside)
        assert contained_path(rev, "f.c") is None

    def test_shared_relative_path_accepted(self, tmp_path: Path) -> None:
        """A shared source is recorded with ``..`` from reversed_dir; that is not an escape."""
        from rebrew.sources import contained_path, source_roots

        rev = tmp_path / "src_SERVER"
        shared = tmp_path / "src" / "shared"
        rev.mkdir()
        shared.mkdir(parents=True)
        cfg = ProjectConfig(root=tmp_path, reversed_dir=rev, shared_dir=shared)
        resolved = contained_path(source_roots(cfg), "../src/shared/f.c")
        assert resolved == (shared / "f.c").resolve()

    def test_source_roots_order(self, tmp_path: Path) -> None:
        from rebrew.sources import source_roots

        cfg = ProjectConfig(
            root=tmp_path,
            reversed_dir=tmp_path / "src_SERVER",
            shared_dir=tmp_path / "src" / "shared",
        )
        assert source_roots(cfg) == (
            tmp_path / "src_SERVER",
            tmp_path / "src" / "shared",
            tmp_path,
        )

    def test_source_roots_without_shared(self, tmp_path: Path) -> None:
        from rebrew.sources import source_roots

        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path / "src_SERVER")
        assert source_roots(cfg) == (tmp_path / "src_SERVER", tmp_path)
