"""Tests for the rebrew crt-match command helpers."""

from pathlib import Path
from types import SimpleNamespace

import pytest

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
            CrtSourceEntry(name="malloc", file="MALLOC.C", line=42, is_asm=False, module="MSVCRT"),
        ]

        matches = match_function("_malloc", 64, "MSVCRT", index)

        assert matches
        assert matches[0].source.file == "MALLOC.C"

    def test_match_filename_based(self) -> None:
        index = [
            CrtSourceEntry(name="qsort", file="QSORT.C", line=0, is_asm=False, module="MSVCRT"),
        ]

        matches = match_function("_qsort", 80, "MSVCRT", index)

        assert matches
        assert matches[0].confidence == 0.85

    def test_match_asm_function(self) -> None:
        index = [
            CrtSourceEntry(name="strlen", file="STRLEN.ASM", line=12, is_asm=True, module="MSVCRT"),
        ]

        matches = match_function("strlen", 25, "MSVCRT", index)

        assert matches
        assert matches[0].is_asm_only is True

    def test_match_no_match(self) -> None:
        index = [
            CrtSourceEntry(name="malloc", file="MALLOC.C", line=42, is_asm=False, module="MSVCRT"),
        ]

        matches = match_function("totally_unknown", 40, "MSVCRT", index)

        assert matches == []

    def test_match_confidence_ordering(self) -> None:
        index = [
            CrtSourceEntry(name="_malloc", file="EXACT.C", line=8, is_asm=False, module="MSVCRT"),
            CrtSourceEntry(
                name="malloc", file="NORMALIZED.C", line=12, is_asm=False, module="MSVCRT"
            ),
            CrtSourceEntry(name="malloc", file="FILENAME.C", line=0, is_asm=False, module="MSVCRT"),
        ]

        matches = match_function("_malloc", 64, "MSVCRT", index)
        confidences = [match.confidence for match in matches]

        assert confidences[0] == 0.95
        assert 0.90 in confidences
        assert 0.85 in confidences

    def test_match_filename_does_not_shadow_exact(self) -> None:
        index = [
            CrtSourceEntry(name="malloc", file="MALLOC.C", line=0, is_asm=False, module="MSVCRT"),
            CrtSourceEntry(name="malloc", file="MALLOC.C", line=42, is_asm=False, module="MSVCRT"),
        ]

        matches = match_function("malloc", 64, "MSVCRT", index)

        assert matches[0].confidence == 0.95
        assert matches[0].source.line == 42

    def test_match_filters_by_origin(self) -> None:
        index = [
            CrtSourceEntry(name="inflate", file="INF.C", line=10, is_asm=False, module="ZLIB"),
            CrtSourceEntry(name="inflate", file="CRT.C", line=20, is_asm=False, module="MSVCRT"),
        ]

        matches = match_function("inflate", 200, "ZLIB", index)

        assert len(matches) == 1
        assert matches[0].source.module == "ZLIB"

    def test_match_va_passthrough(self) -> None:
        index = [
            CrtSourceEntry(name="malloc", file="MALLOC.C", line=42, is_asm=False, module="MSVCRT"),
        ]

        matches = match_function("malloc", 64, "MSVCRT", index, va=0x10006C00)

        assert matches[0].va == 0x10006C00

    def test_match_stdcall_decorated(self) -> None:
        index = [
            CrtSourceEntry(name="foo", file="FOO.C", line=5, is_asm=False, module="MSVCRT"),
        ]

        matches = match_function("_foo@8", 32, "MSVCRT", index)

        assert matches
        assert matches[0].confidence == 0.90


class TestSourceRef:
    def test_c_source_with_line(self) -> None:
        entry = CrtSourceEntry(name="malloc", file="MALLOC.C", line=42, is_asm=False, module="X")
        assert _source_ref(entry) == "MALLOC.C:42"

    def test_asm_source_omits_line(self) -> None:
        entry = CrtSourceEntry(name="memcpy", file="MEMCPY.ASM", line=12, is_asm=True, module="X")
        assert _source_ref(entry) == "MEMCPY.ASM"

    def test_filename_entry_omits_line(self) -> None:
        entry = CrtSourceEntry(name="qsort", file="QSORT.C", line=0, is_asm=False, module="X")
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
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[targets.main.crt_sources]
MSVCRT = "toolchain/msvc/6.0-win32/VC98/CRT/SRC"
"""
        (tmp_path / "rebrew-project.toml").write_text(toml, encoding="utf-8")

        cfg = load_config(tmp_path)

        assert hasattr(cfg, "crt_sources")
        assert cfg.crt_sources == {"MSVCRT": "toolchain/msvc/6.0-win32/VC98/CRT/SRC"}

    def test_crt_sources_default_empty(self) -> None:
        cfg = ProjectConfig(root=Path("."))
        assert cfg.crt_sources == {}


class TestMatchHelpers:
    def test_asm_only_known_function(self) -> None:
        from rebrew.crt_match import is_asm_only

        assert is_asm_only("_chkstk") is True
        assert is_asm_only("chkstk") is True
        assert is_asm_only("not_a_crt_function") is False

    def test_match_reason_asm_only(self) -> None:
        from rebrew.crt_match import _match_reason

        assert "ASM-only" in _match_reason("exact name match", asm_only=True)
        assert _match_reason("exact name match", asm_only=False) == "exact name match"

    def test_match_to_dict_shape(self) -> None:
        from rebrew.crt_match import CrtMatch, CrtSourceEntry, _match_to_dict

        entry = CrtSourceEntry(
            name="_printf", file=str(Path("crt/printf.c")), line=42, is_asm=False, module="MSVCRT"
        )
        m = CrtMatch(
            va=0x1000,
            binary_name="_printf",
            binary_size=64,
            source=entry,
            confidence=0.95,
            reason="exact name match",
            is_asm_only=False,
        )
        d = _match_to_dict(m)
        assert d["va"] == "0x00001000"
        assert d["binary_name"] == "_printf"
        assert d["confidence"] == 0.95
        assert d["source_file"] == str(Path("crt/printf.c"))


class TestCollectLibraryAnnotations:
    """Tests for crt_match._collect_library_annotations (source scanning + module filter)."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        return SimpleNamespace(
            reversed_dir=src,
            metadata_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
            root=tmp_path,
            library_modules=[],
            function_list="",
            target_binary=None,
            dll_exports={},
            iat_thunks=set(),
        )

    def test_library_marker_target_module_collected(self, tmp_path: Path) -> None:
        from rebrew.crt_match import _collect_library_annotations

        cfg = self._cfg(tmp_path)
        (cfg.reversed_dir / "lib.c").write_text(
            "// LIBRARY: SERVER 0x10001000\n// SYMBOL: _malloc\nint malloc(int n) { return n; }\n",
            encoding="utf-8",
        )
        pairs = _collect_library_annotations(cfg)
        assert len(pairs) == 1
        _, ann = pairs[0]
        assert ann.marker_type == "LIBRARY"
        assert ann.va == 0x10001000

    def test_library_marker_cross_module_collected(self, tmp_path: Path) -> None:
        """LIBRARY markers of non-target modules (documented library_modules
        convention) must NOT be dropped by the parser's target filter."""
        from rebrew.crt_match import _collect_library_annotations

        cfg = self._cfg(tmp_path)
        (cfg.reversed_dir / "lib.c").write_text(
            "// LIBRARY: MSVCRT 0x10002000\n// SYMBOL: _fflush\nint fflush(void) { return 0; }\n",
            encoding="utf-8",
        )
        pairs = _collect_library_annotations(cfg)
        assert len(pairs) == 1
        assert pairs[0][1].module == "MSVCRT"

    def test_function_marker_in_library_module_collected(self, tmp_path: Path) -> None:
        from rebrew.crt_match import _collect_library_annotations

        cfg = self._cfg(tmp_path)
        cfg.library_modules = ["ZLIB"]
        (cfg.reversed_dir / "zlib.c").write_text(
            "// FUNCTION: ZLIB 0x10003000\n// SYMBOL: _inflate\nint inflate(void) { return 0; }\n",
            encoding="utf-8",
        )
        pairs = _collect_library_annotations(cfg)
        assert len(pairs) == 1
        assert pairs[0][1].va == 0x10003000

    def test_target_function_marker_excluded(self, tmp_path: Path) -> None:
        """Plain FUNCTION markers of the target module are not library code."""
        from rebrew.crt_match import _collect_library_annotations

        cfg = self._cfg(tmp_path)
        (cfg.reversed_dir / "own.c").write_text(
            "// FUNCTION: SERVER 0x10004000\nint own(void) { return 0; }\n",
            encoding="utf-8",
        )
        assert _collect_library_annotations(cfg) == []

    def test_global_and_data_markers_excluded(self, tmp_path: Path) -> None:
        """GLOBAL/DATA markers must never match against the CRT function index."""
        from rebrew.crt_match import _collect_library_annotations

        cfg = self._cfg(tmp_path)
        cfg.library_modules = ["MSVCRT"]
        (cfg.reversed_dir / "data.c").write_text(
            "// GLOBAL: MSVCRT 0x10005000\n// SYMBOL: g_buf\nchar g_buf[16];\n",
            encoding="utf-8",
        )
        (cfg.reversed_dir / "data2.c").write_text(
            "// DATA: MSVCRT 0x10005100\n// SYMBOL: g_tbl\nint g_tbl[4];\n",
            encoding="utf-8",
        )
        assert _collect_library_annotations(cfg) == []


class TestBuildIndexes:
    def test_relative_path_resolved_against_root(self, tmp_path: Path) -> None:
        from rebrew.crt_match import _build_indexes

        crt = tmp_path / "crt"
        crt.mkdir()
        (crt / "QSORT.C").write_text("int qsort(void) { return 0; }\n", encoding="utf-8")
        cfg = SimpleNamespace(root=tmp_path, crt_sources={"MSVCRT": "crt"})
        indexes = _build_indexes(cfg)
        assert set(indexes) == {"MSVCRT"}
        assert any(e.name == "qsort" and e.module == "MSVCRT" for e in indexes["MSVCRT"])

    def test_absolute_path_used_as_is(self, tmp_path: Path) -> None:
        from rebrew.crt_match import _build_indexes

        abs_dir = tmp_path / "elsewhere"
        abs_dir.mkdir()
        (abs_dir / "STRLEN.C").write_text("int strlen(void) { return 0; }\n", encoding="utf-8")
        cfg = SimpleNamespace(root=tmp_path, crt_sources={"ZLIB": str(abs_dir)})
        indexes = _build_indexes(cfg)
        assert any(e.name == "strlen" and e.module == "ZLIB" for e in indexes["ZLIB"])

    def test_missing_dir_yields_empty_index(self, tmp_path: Path) -> None:
        from rebrew.crt_match import _build_indexes

        cfg = SimpleNamespace(root=tmp_path, crt_sources={"MSVCRT": "does-not-exist"})
        assert _build_indexes(cfg) == {"MSVCRT": []}


class TestMatchAll:
    def test_match_all_end_to_end(self, tmp_path: Path) -> None:
        """A LIBRARY: MSVCRT marker matches a function in the MSVCRT CRT index."""
        from rebrew.crt_match import match_all

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        (src / "lib.c").write_text(
            "// LIBRARY: MSVCRT 0x10001000\n// SYMBOL: _malloc\nint malloc(int n) { return n; }\n",
            encoding="utf-8",
        )
        crt = tmp_path / "crt"
        crt.mkdir()
        (crt / "MALLOC.C").write_text("int malloc(int n) { return n; }\n", encoding="utf-8")
        cfg = SimpleNamespace(
            reversed_dir=src,
            metadata_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
            root=tmp_path,
            library_modules=["MSVCRT"],
            crt_sources={"MSVCRT": "crt"},
        )
        matches = match_all(cfg)
        # "malloc" hits the function entry (exact, 0.95) and the filename
        # entry (filename-based, 0.85) — sorted by confidence.
        assert len(matches) == 2
        best = matches[0]
        assert best.va == 0x10001000
        assert best.binary_name == "malloc"
        assert best.confidence == 0.95
        assert best.source.module == "MSVCRT"
        assert best.source.file == "MALLOC.C"
        assert best.reason == "exact name match"
        assert matches[1].confidence == 0.85
        assert matches[1].reason == "filename-based source match"

    def test_match_all_skips_missing_index(self, tmp_path: Path) -> None:
        """No CRT index for the marker's module → no matches, no crash."""
        from rebrew.crt_match import match_all

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        (src / "lib.c").write_text(
            "// LIBRARY: ZLIB 0x10001000\n// SYMBOL: _inflate\nint inflate(void) { return 0; }\n",
            encoding="utf-8",
        )
        cfg = SimpleNamespace(
            reversed_dir=src,
            metadata_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
            root=tmp_path,
            library_modules=["ZLIB"],
            crt_sources={"MSVCRT": "does-not-exist"},
        )
        assert match_all(cfg) == []


class TestCrtMatchCli:
    """CLI-level tests via CliRunner with a stubbed config."""

    def _cfg(self, tmp_path: Path, *, crt_sources: dict[str, str]) -> SimpleNamespace:
        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        return SimpleNamespace(
            reversed_dir=src,
            metadata_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
            root=tmp_path,
            library_modules=["MSVCRT"],
            crt_sources=crt_sources,
        )

    def test_no_crt_sources_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from typer.testing import CliRunner

        from rebrew.crt_match import app

        cfg = self._cfg(tmp_path, crt_sources={})
        monkeypatch.setattr("rebrew.crt_match.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code != 0
        assert "crt_sources" in result.output

    def test_index_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        from typer.testing import CliRunner

        from rebrew.crt_match import app

        crt = tmp_path / "crt"
        crt.mkdir()
        (crt / "MALLOC.C").write_text("int malloc(void) { return 0; }\n", encoding="utf-8")
        cfg = self._cfg(tmp_path, crt_sources={"MSVCRT": "crt"})
        monkeypatch.setattr("rebrew.crt_match.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["--index", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["count"] >= 2  # function entry + filename entry
        assert all(e["module"] == "MSVCRT" for e in data["entries"])

    def test_missing_va_and_all_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.crt_match import app

        cfg = self._cfg(tmp_path, crt_sources={"MSVCRT": "crt"})
        monkeypatch.setattr("rebrew.crt_match.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code != 0
        assert "Provide a VA or use --all" in result.output

    def test_va_no_library_marker_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.crt_match import app

        cfg = self._cfg(tmp_path, crt_sources={"MSVCRT": "crt"})
        monkeypatch.setattr("rebrew.crt_match.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["--json", "0x10001000"])
        assert result.exit_code != 0
        assert "No library marker found" in result.output

    def test_single_va_match_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        from typer.testing import CliRunner

        from rebrew.crt_match import app

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        (src / "lib.c").write_text(
            "// LIBRARY: MSVCRT 0x10001000\n// SYMBOL: _malloc\nint malloc(int n) { return n; }\n",
            encoding="utf-8",
        )
        crt = tmp_path / "crt"
        crt.mkdir()
        (crt / "MALLOC.C").write_text("int malloc(int n) { return n; }\n", encoding="utf-8")
        cfg = self._cfg(tmp_path, crt_sources={"MSVCRT": "crt"})
        monkeypatch.setattr("rebrew.crt_match.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["--json", "0x10001000"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["match_count"] == 2
        best = data["matches"][0]
        assert best["binary_name"] == "malloc"
        assert best["source_file"] == "MALLOC.C"
        assert best["confidence"] == 0.95

    def test_all_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        from typer.testing import CliRunner

        from rebrew.crt_match import app

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        (src / "lib.c").write_text(
            "// LIBRARY: MSVCRT 0x10001000\n// SYMBOL: _malloc\nint malloc(int n) { return n; }\n",
            encoding="utf-8",
        )
        crt = tmp_path / "crt"
        crt.mkdir()
        (crt / "MALLOC.C").write_text("int malloc(int n) { return n; }\n", encoding="utf-8")
        cfg = self._cfg(tmp_path, crt_sources={"MSVCRT": "crt"})
        monkeypatch.setattr("rebrew.crt_match.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["--all", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["match_count"] == 2

    def test_fix_source_writes_metadata(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.crt_match import app
        from rebrew.metadata import get_entry

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        lib_c = src / "lib.c"
        lib_c.write_text(
            "// LIBRARY: MSVCRT 0x10001000\n// SYMBOL: _malloc\nint malloc(int n) { return n; }\n",
            encoding="utf-8",
        )
        crt = tmp_path / "crt"
        crt.mkdir()
        (crt / "MALLOC.C").write_text("int malloc(int n) { return n; }\n", encoding="utf-8")
        cfg = self._cfg(tmp_path, crt_sources={"MSVCRT": "crt"})
        monkeypatch.setattr("rebrew.crt_match.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["--fix-source", "--all", "--json"])
        assert result.exit_code == 0
        # SOURCE is metadata-routed: it must land in cfg.metadata_dir (the
        # reversed_dir parent), not in a stray toml next to the .c file.
        entry = get_entry(tmp_path, 0x10001000, "MSVCRT")
        assert entry.get("source") == "MALLOC.C:1"
        assert not (src / "rebrew-function.toml").exists()

    def test_no_matches_message(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from typer.testing import CliRunner

        from rebrew.crt_match import app

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        (src / "lib.c").write_text(
            "// LIBRARY: MSVCRT 0x10001000\n// SYMBOL: _nope\nint nope(void) { return 0; }\n",
            encoding="utf-8",
        )
        crt = tmp_path / "crt"
        crt.mkdir()
        (crt / "MALLOC.C").write_text("int malloc(int n) { return n; }\n", encoding="utf-8")
        cfg = self._cfg(tmp_path, crt_sources={"MSVCRT": "crt"})
        monkeypatch.setattr("rebrew.crt_match.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["--all"])
        assert result.exit_code == 0
        assert "No matches found." in result.output


class TestCrtMatchCliBranches:
    """Remaining CLI branch coverage: render fns, error exits, dedup, console output."""

    def test_render_functions_content(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from io import StringIO

        from rich.console import Console

        import rebrew.crt_match as crt_mod
        from rebrew.crt_match import (
            CrtMatch,
            CrtSourceEntry,
            _render_index_table,
            _render_match_table,
        )

        buf = StringIO()
        monkeypatch.setattr(
            crt_mod,
            "console",
            Console(file=buf, force_terminal=True, width=120, no_color=True, highlight=False),
        )
        entry = CrtSourceEntry(
            name="malloc", file="MALLOC.C", line=1, is_asm=False, module="MSVCRT"
        )
        match = CrtMatch(
            va=0x10001000,
            binary_name="_malloc",
            binary_size=16,
            source=entry,
            confidence=0.9,
            reason="normalized name match",
            is_asm_only=False,
        )
        _render_index_table([entry])
        _render_match_table([match])
        out = buf.getvalue()
        assert "malloc" in out
        assert "MALLOC.C" in out
        assert "MSVCRT" in out
        assert "_malloc" in out
        assert "0x10001000" in out
        assert "0.90" in out
        # Rich wraps the Reason cell when the table is narrow (each wrapped
        # line becomes a table row), so assert the reason's words appear.
        flat = out.replace("\n", " ")
        assert "normalized name" in flat
        assert "match" in flat

    def test_va_entry_without_symbol_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.crt_match import app

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        (src / "anon.c").write_text("// LIBRARY: MSVCRT 0x10001000\n", encoding="utf-8")
        crt = tmp_path / "crt"
        crt.mkdir()
        cfg = SimpleNamespace(
            reversed_dir=src,
            metadata_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
            root=tmp_path,
            library_modules=["MSVCRT"],
            crt_sources={"MSVCRT": "crt"},
        )
        monkeypatch.setattr("rebrew.crt_match.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["--json", "0x10001000"])
        assert result.exit_code != 0
        assert "has no symbol/name" in result.output

    def test_va_module_without_index_falls_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A marker module with no index falls back to every configured index
        (same rule as match_all) — 0 matches, not a spurious module error."""
        import json

        from typer.testing import CliRunner

        from rebrew.crt_match import app

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        (src / "zlib.c").write_text(
            "// LIBRARY: ZLIB 0x10001000\n// SYMBOL: _inflate\nint inflate(void) { return 0; }\n",
            encoding="utf-8",
        )
        cfg = SimpleNamespace(
            reversed_dir=src,
            metadata_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
            root=tmp_path,
            library_modules=["ZLIB"],
            crt_sources={"MSVCRT": "crt"},
        )
        monkeypatch.setattr("rebrew.crt_match.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["--json", "0x10001000"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["match_count"] == 0  # MSVCRT index can't name inflate

    def test_both_va_and_all_dedup(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        from typer.testing import CliRunner

        from rebrew.crt_match import app

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        (src / "lib.c").write_text(
            "// LIBRARY: MSVCRT 0x10001000\n// SYMBOL: _malloc\nint malloc(int n) { return n; }\n",
            encoding="utf-8",
        )
        crt = tmp_path / "crt"
        crt.mkdir()
        (crt / "MALLOC.C").write_text("int malloc(int n) { return n; }\n", encoding="utf-8")
        cfg = SimpleNamespace(
            reversed_dir=src,
            metadata_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
            root=tmp_path,
            library_modules=["MSVCRT"],
            crt_sources={"MSVCRT": "crt"},
        )
        monkeypatch.setattr("rebrew.crt_match.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["--all", "--json", "0x10001000"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        # --all would produce the same 2 matches; dedup keeps them at 2.
        assert data["match_count"] == 2

    def test_fix_source_console_message(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.crt_match import app

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        (src / "lib.c").write_text(
            "// LIBRARY: MSVCRT 0x10001000\n// SYMBOL: _malloc\nint malloc(int n) { return n; }\n",
            encoding="utf-8",
        )
        crt = tmp_path / "crt"
        crt.mkdir()
        (crt / "MALLOC.C").write_text("int malloc(int n) { return n; }\n", encoding="utf-8")
        cfg = SimpleNamespace(
            reversed_dir=src,
            metadata_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
            root=tmp_path,
            library_modules=["MSVCRT"],
            crt_sources={"MSVCRT": "crt"},
        )
        monkeypatch.setattr("rebrew.crt_match.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["--fix-source", "--all"])
        assert result.exit_code == 0
        assert "Updated SOURCE annotations: 1" in result.output

    def test_match_all_falls_back_to_all_indexes(self, tmp_path: Path) -> None:
        """LIBRARY markers using the TARGET's module (e.g. SERVER) still match
        against every configured library index — the library identity comes
        from the name match, not the marker module."""
        from rebrew.crt_match import match_all

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        (src / "lib.c").write_text(
            "// LIBRARY: SERVER 0x10001000\n// SYMBOL: _free\nint free(void *p) { return 0; }\n",
            encoding="utf-8",
        )
        crt = tmp_path / "crt"
        crt.mkdir()
        (crt / "FREE.C").write_text("void free(void *p) {}\n", encoding="utf-8")
        cfg = SimpleNamespace(
            reversed_dir=src,
            metadata_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
            root=tmp_path,
            library_modules=[],
            crt_sources={"MSVCRT": "crt"},
        )
        matches = match_all(cfg)
        assert len(matches) >= 1
        assert matches[0].binary_name == "free"
        assert matches[0].source.module == "MSVCRT"
        assert matches[0].source.file == "FREE.C"


class TestFixSourceDryRun:
    def test_dry_run_previews_without_writing(self, tmp_path: Path) -> None:
        from types import SimpleNamespace

        from typer.testing import CliRunner

        import rebrew.crt_match as cm

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        header = src / "library_msvc.h"
        header.write_text("// LIBRARY: MSVCRT 0x1000\n// _malloc\n", encoding="utf-8")
        (tmp_path / "md").mkdir(exist_ok=True)
        crt = tmp_path / "crt"
        crt.mkdir()
        (crt / "MALLOC.C").write_text("int malloc(int n) { return n; }\n", encoding="utf-8")
        cfg = SimpleNamespace(
            reversed_dir=src,
            metadata_dir=tmp_path / "md",
            marker="SERVER",
            source_ext=".c",
            root=tmp_path,
            library_modules=["MSVCRT"],
            crt_sources={"MSVCRT": str(crt)},
            dll_exports={},
            iat_thunks=set(),
            function_list="",
            target_binary=None,
        )
        monkeypatch_patch = None
        import pytest

        monkeypatch_patch = pytest.MonkeyPatch()
        monkeypatch_patch.setattr(cm, "require_config", lambda target=None, json_mode=False: cfg)
        result = CliRunner().invoke(cm.app, ["--all", "--fix-source", "--dry-run"])
        monkeypatch_patch.undo()
        assert "Would update SOURCE annotations: 1" in result.output
        from rebrew.metadata import get_entry

        assert get_entry(cfg.metadata_dir, 0x1000, "MSVCRT") == {}  # nothing written


class TestSingleVaModuleFallback:
    """Single-VA matching must fall back to every configured index when the
    marker module (e.g. "SERVER") owns no crt_sources entry — same rule
    match_all already uses.  Was: "No CRT index configured for module"."""

    def _cfg(self, tmp_path: Path, *, crt_sources: dict[str, str]) -> SimpleNamespace:
        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        return SimpleNamespace(
            reversed_dir=src,
            metadata_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
            root=tmp_path,
            library_modules=["MSVCRT"],
            crt_sources=crt_sources,
        )

    def test_marker_module_without_index_falls_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import json

        from typer.testing import CliRunner

        from rebrew.crt_match import app

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        (src / "lib.c").write_text(
            "// LIBRARY: SERVER 0x10001000\n// SYMBOL: _malloc\nint malloc(int n) { return n; }\n",
            encoding="utf-8",
        )
        crt = tmp_path / "crt"
        crt.mkdir()
        (crt / "MALLOC.C").write_text("int malloc(int n) { return n; }\n", encoding="utf-8")
        cfg = self._cfg(tmp_path, crt_sources={"MSVCRT": "crt"})
        monkeypatch.setattr("rebrew.crt_match.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["--json", "0x10001000"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["match_count"] >= 1
        assert data["matches"][0]["source_file"] == "MALLOC.C"

    def test_no_indexes_at_all_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.crt_match import app

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        (src / "lib.c").write_text(
            "// LIBRARY: SERVER 0x10001000\n// SYMBOL: _malloc\nint malloc(int n) { return n; }\n",
            encoding="utf-8",
        )
        cfg = self._cfg(tmp_path, crt_sources={})
        monkeypatch.setattr("rebrew.crt_match.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["--json", "0x10001000"])
        assert result.exit_code != 0
        assert "No crt_sources configured" in result.output
