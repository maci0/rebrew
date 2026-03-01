"""Tests for the rebrew crt-match command helpers."""

from pathlib import Path

from rebrew.config import ProjectConfig, load_config
from rebrew.crt_match import (
    CrtSourceEntry,
    _source_ref,
    build_crt_index,
    is_asm_only,
    match_function,
    normalize_name,
)


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


class TestCrtIndexBuilding:
    def test_build_index_c_files(self, tmp_path: Path) -> None:
        _write(
            tmp_path / "MALLOC.C",
            "int malloc(int n)\n{\n    return n;\n}\n\nvoid free(void* p)\n{\n}\n",
        )

        entries = build_crt_index(tmp_path, "MSVCRT")
        names = {entry.name.lower() for entry in entries if entry.line > 0}

        assert "malloc" in names
        assert "free" in names

    def test_build_index_asm_files(self, tmp_path: Path) -> None:
        _write(
            tmp_path / "MEM.ASM",
            "_memcpy PROC\nmov eax, eax\nret\n_memcpy ENDP\n",
        )

        entries = build_crt_index(tmp_path, "MSVCRT")
        asm_names = {entry.name.lower() for entry in entries if entry.is_asm}

        assert "memcpy" in asm_names

    def test_build_index_empty_dir(self, tmp_path: Path) -> None:
        entries = build_crt_index(tmp_path, "MSVCRT")
        assert entries == []

    def test_build_index_nested(self, tmp_path: Path) -> None:
        _write(
            tmp_path / "nested" / "deep" / "STRLEN.C", "int strlen(char* s)\n{\n    return 0;\n}\n"
        )

        entries = build_crt_index(tmp_path, "MSVCRT")
        files = {entry.file for entry in entries}

        assert "nested/deep/STRLEN.C" in files

    def test_build_index_filename_entry(self, tmp_path: Path) -> None:
        _write(tmp_path / "QSORT.C", "int not_qsort(void)\n{\n    return 0;\n}\n")

        entries = build_crt_index(tmp_path, "MSVCRT")
        filename_entries = [
            entry for entry in entries if entry.file == "QSORT.C" and entry.line == 0
        ]

        assert any(entry.name == "qsort" for entry in filename_entries)


class TestNameNormalization:
    def test_normalize_strips_underscore(self) -> None:
        assert normalize_name("_malloc") == "malloc"

    def test_normalize_preserves_double_underscore(self) -> None:
        assert normalize_name("__allmul") == "__allmul"

    def test_normalize_strips_imp(self) -> None:
        assert normalize_name("__imp__malloc") == "malloc"

    def test_normalize_lowercase(self) -> None:
        assert normalize_name("MALLOC") == "malloc"

    def test_normalize_imp_chkstk(self) -> None:
        assert normalize_name("__imp___chkstk") == "__chkstk"

    def test_normalize_imp_memcpy(self) -> None:
        assert normalize_name("__imp__memcpy") == "memcpy"

    def test_normalize_imp_no_underscore(self) -> None:
        assert normalize_name("__imp_memcpy") == "memcpy"

    def test_normalize_stdcall_suffix(self) -> None:
        assert normalize_name("_malloc@4") == "malloc"

    def test_normalize_stdcall_preserves_non_numeric(self) -> None:
        assert normalize_name("foo@bar") == "foo@bar"

    def test_normalize_empty(self) -> None:
        assert normalize_name("") == ""

    def test_normalize_whitespace(self) -> None:
        assert normalize_name("  _malloc  ") == "malloc"


class TestAsmOnlyDetection:
    def test_is_asm_only_memcpy(self) -> None:
        assert is_asm_only("memcpy") is True

    def test_is_asm_only_malloc(self) -> None:
        assert is_asm_only("malloc") is False

    def test_is_asm_only_chkstk(self) -> None:
        assert is_asm_only("_chkstk") is True

    def test_is_asm_only_underscored_memcpy(self) -> None:
        assert is_asm_only("_memcpy") is True

    def test_is_asm_only_imp_strlen(self) -> None:
        assert is_asm_only("__imp__strlen") is True

    def test_is_asm_only_double_underscore_allmul(self) -> None:
        assert is_asm_only("__allmul") is True


class TestFunctionMatching:
    def test_match_exact_name(self) -> None:
        index = [
            CrtSourceEntry(name="malloc", file="MALLOC.C", line=42, is_asm=False, origin="MSVCRT"),
        ]

        matches = match_function("_malloc", 64, "MSVCRT", index)

        assert matches
        assert matches[0].source.file == "MALLOC.C"

    def test_match_filename_based(self) -> None:
        index = [
            CrtSourceEntry(name="qsort", file="QSORT.C", line=0, is_asm=False, origin="MSVCRT"),
        ]

        matches = match_function("_qsort", 80, "MSVCRT", index)

        assert matches
        assert matches[0].confidence == 0.85

    def test_match_asm_function(self) -> None:
        index = [
            CrtSourceEntry(name="strlen", file="STRLEN.ASM", line=12, is_asm=True, origin="MSVCRT"),
        ]

        matches = match_function("strlen", 25, "MSVCRT", index)

        assert matches
        assert matches[0].is_asm_only is True

    def test_match_no_match(self) -> None:
        index = [
            CrtSourceEntry(name="malloc", file="MALLOC.C", line=42, is_asm=False, origin="MSVCRT"),
        ]

        matches = match_function("totally_unknown", 40, "MSVCRT", index)

        assert matches == []

    def test_match_confidence_ordering(self) -> None:
        index = [
            CrtSourceEntry(name="_malloc", file="EXACT.C", line=8, is_asm=False, origin="MSVCRT"),
            CrtSourceEntry(
                name="malloc", file="NORMALIZED.C", line=12, is_asm=False, origin="MSVCRT"
            ),
            CrtSourceEntry(name="malloc", file="FILENAME.C", line=0, is_asm=False, origin="MSVCRT"),
        ]

        matches = match_function("_malloc", 64, "MSVCRT", index)
        confidences = [match.confidence for match in matches]

        assert confidences[0] == 0.95
        assert 0.90 in confidences
        assert 0.85 in confidences

    def test_match_filename_does_not_shadow_exact(self) -> None:
        index = [
            CrtSourceEntry(name="malloc", file="MALLOC.C", line=0, is_asm=False, origin="MSVCRT"),
            CrtSourceEntry(name="malloc", file="MALLOC.C", line=42, is_asm=False, origin="MSVCRT"),
        ]

        matches = match_function("malloc", 64, "MSVCRT", index)

        assert matches[0].confidence == 0.95
        assert matches[0].source.line == 42

    def test_match_filters_by_origin(self) -> None:
        index = [
            CrtSourceEntry(name="inflate", file="INF.C", line=10, is_asm=False, origin="ZLIB"),
            CrtSourceEntry(name="inflate", file="CRT.C", line=20, is_asm=False, origin="MSVCRT"),
        ]

        matches = match_function("inflate", 200, "ZLIB", index)

        assert len(matches) == 1
        assert matches[0].source.origin == "ZLIB"

    def test_match_va_passthrough(self) -> None:
        index = [
            CrtSourceEntry(name="malloc", file="MALLOC.C", line=42, is_asm=False, origin="MSVCRT"),
        ]

        matches = match_function("malloc", 64, "MSVCRT", index, va=0x10006C00)

        assert matches[0].va == 0x10006C00

    def test_match_stdcall_decorated(self) -> None:
        index = [
            CrtSourceEntry(name="foo", file="FOO.C", line=5, is_asm=False, origin="MSVCRT"),
        ]

        matches = match_function("_foo@8", 32, "MSVCRT", index)

        assert matches
        assert matches[0].confidence == 0.90


class TestSourceRef:
    def test_c_source_with_line(self) -> None:
        entry = CrtSourceEntry(name="malloc", file="MALLOC.C", line=42, is_asm=False, origin="X")
        assert _source_ref(entry) == "MALLOC.C:42"

    def test_asm_source_omits_line(self) -> None:
        entry = CrtSourceEntry(name="memcpy", file="MEMCPY.ASM", line=12, is_asm=True, origin="X")
        assert _source_ref(entry) == "MEMCPY.ASM"

    def test_filename_entry_omits_line(self) -> None:
        entry = CrtSourceEntry(name="qsort", file="QSORT.C", line=0, is_asm=False, origin="X")
        assert _source_ref(entry) == "QSORT.C"


class TestIndexEdgeCases:
    def test_build_index_cpp_files(self, tmp_path: Path) -> None:
        _write(
            tmp_path / "helper.cpp",
            "void helper(int x)\n{\n    return;\n}\n",
        )

        entries = build_crt_index(tmp_path, "MSVCRT")
        names = {entry.name for entry in entries if entry.line > 0}

        assert "helper" in names

    def test_build_index_ignores_header_files(self, tmp_path: Path) -> None:
        _write(tmp_path / "stdlib.h", "int malloc(int n);\n")

        entries = build_crt_index(tmp_path, "MSVCRT")
        func_entries = [e for e in entries if e.line > 0]

        assert func_entries == []

    def test_build_index_nonexistent_dir(self) -> None:
        entries = build_crt_index(Path("/nonexistent/path"), "MSVCRT")
        assert entries == []


class TestConfigIntegration:
    def test_crt_sources_config_field(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[targets.main.crt_sources]
MSVCRT = "tools/MSVC600/VC98/CRT/SRC"
"""
        (tmp_path / "rebrew-project.toml").write_text(toml, encoding="utf-8")

        cfg = load_config(tmp_path)

        assert hasattr(cfg, "crt_sources")
        assert cfg.crt_sources == {"MSVCRT": "tools/MSVC600/VC98/CRT/SRC"}

    def test_crt_sources_default_empty(self) -> None:
        cfg = ProjectConfig(root=Path("."))
        assert cfg.crt_sources == {}
