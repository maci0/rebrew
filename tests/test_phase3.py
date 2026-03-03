"""Phase 3 tests — coverage for new/changed code from Phase 1 & Phase 2 audit."""

import struct
from pathlib import Path

from rebrew.annotation import split_annotation_sections
from rebrew.binary_loader import (
    _LOAD_BINARY_CACHE_MAX,
    _load_binary_cache,
    load_binary,
)
from rebrew.compile import _safe_shlex_split
from rebrew.matcher.compiler import _filter_wine_stderr

# ---------------------------------------------------------------------------
# split_annotation_sections (annotation.py)
# ---------------------------------------------------------------------------


class TestSplitAnnotationSections:
    def test_empty_text(self) -> None:
        preamble, blocks = split_annotation_sections("")
        assert preamble == ""
        assert blocks == []

    def test_no_markers(self) -> None:
        text = "#include <stdio.h>\nint main() { return 0; }\n"
        preamble, blocks = split_annotation_sections(text)
        assert preamble == text
        assert blocks == []

    def test_single_function_block(self) -> None:
        text = "#include <stdio.h>\n// FUNCTION: GAME 0x10001000\nint foo() { return 1; }\n"
        preamble, blocks = split_annotation_sections(text)
        assert preamble == "#include <stdio.h>\n"
        assert len(blocks) == 1
        assert "// FUNCTION: GAME 0x10001000" in blocks[0]
        assert "int foo()" in blocks[0]

    def test_multiple_function_blocks(self) -> None:
        text = (
            "#include <stdlib.h>\n"
            "// FUNCTION: GAME 0x10001000\n"
            "int foo() { return 1; }\n"
            "// FUNCTION: GAME 0x10002000\n"
            "int bar() { return 2; }\n"
            "// LIBRARY: MSVCRT 0x10003000\n"
            "int baz() { return 3; }\n"
        )
        preamble, blocks = split_annotation_sections(text)
        assert preamble == "#include <stdlib.h>\n"
        assert len(blocks) == 3
        assert "0x10001000" in blocks[0]
        assert "0x10002000" in blocks[1]
        assert "0x10003000" in blocks[2]
        assert "int foo()" in blocks[0]
        assert "int bar()" in blocks[1]
        assert "int baz()" in blocks[2]

    def test_no_preamble(self) -> None:
        text = "// FUNCTION: GAME 0x10001000\nint foo() {}\n"
        preamble, blocks = split_annotation_sections(text)
        assert preamble == ""
        assert len(blocks) == 1

    def test_all_marker_types(self) -> None:
        """STUB, GLOBAL, DATA markers also split correctly."""
        text = (
            "// STUB: GAME 0x10001000\nvoid stub() {}\n"
            "// GLOBAL: GAME 0x10002000\nint g_val;\n"
            "// DATA: GAME 0x10003000\nchar data[];\n"
        )
        preamble, blocks = split_annotation_sections(text)
        assert preamble == ""
        assert len(blocks) == 3


# ---------------------------------------------------------------------------
# _safe_shlex_split fallback (compile.py)
# ---------------------------------------------------------------------------


class TestSafeShexSplit:
    def test_normal_string(self) -> None:
        result = _safe_shlex_split("wine /path/to/CL.EXE")
        assert result == ["wine", "/path/to/CL.EXE"]

    def test_quoted_path(self) -> None:
        result = _safe_shlex_split('wine "/path with spaces/CL.EXE"')
        assert result == ["wine", "/path with spaces/CL.EXE"]

    def test_malformed_quotes_fallback(self) -> None:
        """Unclosed quotes should fall back to str.split()."""
        bad = '/FI"unclosed /c /MT'
        result = _safe_shlex_split(bad)
        assert result == ['/FI"unclosed', "/c", "/MT"]

    def test_empty_string(self) -> None:
        result = _safe_shlex_split("")
        assert result == []


# ---------------------------------------------------------------------------
# load_binary bounded cache (binary_loader.py)
# ---------------------------------------------------------------------------


def _make_pe_stub(path: Path, machine: int = 0x14C) -> Path:
    """Build a minimal PE file that LIEF recognises."""
    buf = bytearray(256)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 60, 128)
    buf[128:132] = b"PE\x00\x00"
    struct.pack_into("<H", buf, 132, machine)
    struct.pack_into("<H", buf, 148, 96)
    struct.pack_into("<H", buf, 152, 0x10B)
    path.write_bytes(bytes(buf))
    return path


class TestLoadBinaryCache:
    def setup_method(self) -> None:
        _load_binary_cache.clear()

    def teardown_method(self) -> None:
        _load_binary_cache.clear()

    def test_cache_hit(self, tmp_path: Path) -> None:
        f = _make_pe_stub(tmp_path / "test.exe")
        info1 = load_binary(f)
        info2 = load_binary(f)
        assert info1 is info2  # Same object from cache

    def test_cache_stores_entry(self, tmp_path: Path) -> None:
        f = _make_pe_stub(tmp_path / "test.exe")
        load_binary(f)
        assert len(_load_binary_cache) == 1

    def test_cache_eviction(self, tmp_path: Path) -> None:
        """When cache is full, oldest entry is evicted."""
        paths = []
        for i in range(_LOAD_BINARY_CACHE_MAX):
            p = _make_pe_stub(tmp_path / f"test_{i}.exe")
            paths.append(p)
            load_binary(p)

        assert len(_load_binary_cache) == _LOAD_BINARY_CACHE_MAX

        overflow = _make_pe_stub(tmp_path / "overflow.exe")
        load_binary(overflow)
        assert len(_load_binary_cache) == _LOAD_BINARY_CACHE_MAX

        first_key = (str(paths[0].resolve()), "auto")
        assert first_key not in _load_binary_cache

        overflow_key = (str(overflow.resolve()), "auto")
        assert overflow_key in _load_binary_cache


# ---------------------------------------------------------------------------
# _filter_wine_stderr lazy wrapper (matcher/compiler.py)
# ---------------------------------------------------------------------------


class TestFilterWineStderrWrapper:
    def test_delegates_to_compile(self) -> None:
        """The wrapper should produce the same result as the real function."""
        from rebrew.compile import filter_wine_stderr

        noisy = "0042:err:ntdll:something broken\nreal error: missing ;\n"
        assert _filter_wine_stderr(noisy) == filter_wine_stderr(noisy)

    def test_strips_wine_noise(self) -> None:
        result = _filter_wine_stderr("0042:fixme:winediag:test\nactual output")
        assert "fixme" not in result
        assert "actual output" in result

    def test_empty_string(self) -> None:
        assert _filter_wine_stderr("") == ""
