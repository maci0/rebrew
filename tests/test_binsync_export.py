"""Tests for binsync_export.py."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
import tomlkit
from typer.testing import CliRunner

from rebrew.main import app

runner = CliRunner()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TOML_CFG = """
[project]
default_target = "server"

[targets.server]
binary = "server.dll"
reversed_dir = "src"
"""


def _make_project(tmp_path: Path, files: dict[str, str]) -> Path:
    """Create a minimal rebrew project with caller-supplied source files."""
    (tmp_path / "rebrew-project.toml").write_text(_TOML_CFG, encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    for name, content in files.items():
        (src / name).write_text(content, encoding="utf-8")
    return tmp_path


def _invoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *extra_args: str) -> Any:
    """Run `rebrew binsync-export <outdir> [extra_args]` from tmp_path."""
    outdir = tmp_path / "binsync_out"
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["binsync-export", str(outdir), *extra_args])
    return result, outdir


# ---------------------------------------------------------------------------
# Basic export (name, addr, size)
# ---------------------------------------------------------------------------


class TestBinsyncExportBasic:
    def test_name_and_addr(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 31\nint foo() { return 1; }\n",
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        toml_file = outdir / "functions" / "10001000.toml"
        assert toml_file.exists()
        doc = tomlkit.loads(toml_file.read_text())
        info = cast(dict[str, Any], doc["info"])
        assert info["addr"] == 0x10001000
        assert info["name"] == "_foo"
        assert info["size"] == 31

    def test_size_omitted_when_zero(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path,
            {
                "bar.c": "// FUNCTION: SERVER 0x20002000\n// STATUS: NEAR_MATCHING\ndouble bar() { return 2.0; }\n",
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0
        doc = tomlkit.loads((outdir / "functions" / "20002000.toml").read_text())
        assert "size" not in cast(dict[str, Any], doc["info"])

    def test_fallback_name_when_no_symbol(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            {
                "stub.c": "// FUNCTION: SERVER 0x30003000\n// STATUS: STUB\nvoid stub(void);\n",
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0
        doc = tomlkit.loads((outdir / "functions" / "30003000.toml").read_text())
        name = cast(dict[str, Any], doc["info"])["name"]
        # Stub with no body: falls back to symbol from declaration or func_ prefix
        assert isinstance(name, str) and len(name) > 0


# ---------------------------------------------------------------------------
# Prototype → [header].type
# ---------------------------------------------------------------------------


class TestBinsyncExportPrototype:
    def test_prototype_written_to_header(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            {
                "calc.c": (
                    "// FUNCTION: SERVER 0x10001000\n"
                    "// STATUS: EXACT\n"
                    "// SIZE: 20\n"
                    "// PROTOTYPE: int __cdecl Calc(int x, int y)\n"
                    "int __cdecl Calc(int x, int y) { return x + y; }\n"
                ),
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0
        doc = tomlkit.loads((outdir / "functions" / "10001000.toml").read_text())
        assert "header" in doc
        # Body should be stripped from [header].type — only the signature
        header_type = cast(dict[str, Any], doc["header"])["type"]
        assert header_type == "int __cdecl Calc(int x, int y)"
        assert "{" not in header_type

    def test_header_strips_body_for_inline_definitions(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Inline function definitions (no // PROTOTYPE: annotation) still get a
        stripped [header].type with no function body."""
        _make_project(
            tmp_path,
            {
                "f.c": "// FUNCTION: SERVER 0x10002000\n// STATUS: EXACT\n// SIZE: 5\nvoid f(void) {}\n"
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0
        doc = tomlkit.loads((outdir / "functions" / "10002000.toml").read_text())
        # prototype is always derived from the C source; body must be stripped
        assert "header" in doc
        htype = cast(dict[str, Any], doc["header"])["type"]
        assert "{" not in htype
        assert "void f(void)" in htype


# ---------------------------------------------------------------------------
# Metadata comments → [comments]
# ---------------------------------------------------------------------------


class TestBinsyncExportComments:
    def test_status_and_cflags_in_comment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            {
                "f.c": (
                    "// FUNCTION: SERVER 0x10010000\n"
                    "// STATUS: RELOC\n"
                    "// SIZE: 12\n"
                    "// CFLAGS: /O1 /Gd\n"
                    "int f(void) { return 0; }\n"
                ),
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0
        doc = tomlkit.loads((outdir / "functions" / "10010000.toml").read_text())
        assert "comments" in doc
        comments = cast(dict[str, Any], doc["comments"])
        assert str(0x10010000) in comments
        assert "STATUS=RELOC" in comments[str(0x10010000)]
        assert "CFLAGS=/O1 /Gd" in comments[str(0x10010000)]

    def test_note_written_at_va_plus_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            {
                "g.c": (
                    "// FUNCTION: SERVER 0x10020000\n"
                    "// STATUS: EXACT\n"
                    "// SIZE: 8\n"
                    "// NOTE: worth double-checking\n"
                    "void g(void) {}\n"
                ),
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0
        doc = tomlkit.loads((outdir / "functions" / "10020000.toml").read_text())
        comments = cast(dict[str, Any], doc["comments"])
        note_key = str(0x10020000 + 1)
        assert note_key in comments
        assert "worth double-checking" in comments[note_key]
        assert comments[note_key].startswith("[rebrew:note]")

    def test_rebrew_comment_helper_empty_when_no_status(self) -> None:
        """_rebrew_comment returns empty string when both status and cflags are empty."""
        from rebrew.binsync_export import _rebrew_comment

        assert _rebrew_comment("", "") == ""
        assert _rebrew_comment("EXACT", "") == "[rebrew] STATUS=EXACT"
        assert _rebrew_comment("", "/O1") == "[rebrew] CFLAGS=/O1"
        assert _rebrew_comment("RELOC", "/O2") == "[rebrew] STATUS=RELOC CFLAGS=/O2"


# ---------------------------------------------------------------------------
# Global variables → global_vars.toml
# ---------------------------------------------------------------------------


class TestBinsyncExportGlobals:
    def test_global_vars_toml_written(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            {
                "func.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nvoid func(void) {}\n",
                "data.c": ("// GLOBAL: SERVER 0x01008000\n// SIZE: 64\nchar g_szBuffer[64];\n"),
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0
        gv_path = outdir / "global_vars.toml"
        assert gv_path.exists()
        doc = tomlkit.loads(gv_path.read_text())
        assert str(0x01008000) in doc
        entry = cast(dict[str, Any], doc[str(0x01008000)])
        assert entry["addr"] == 0x01008000

    def test_data_marker_above_include_not_misparsed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A `// DATA:` marker placed above `#include <windows.h>` (synthetic
        link-stub VAs like notepad's 0xDEADBEEF) must not fabricate
        name='<windows.h>' / type='#include' in global_vars.toml — it falls
        back to the g_<hex> name instead."""
        _make_project(
            tmp_path,
            {
                "stub.c": "// DATA: SERVER 0xDEADBEEF\n#include <windows.h>\n\nvoid f(void) {}\n",
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0
        gv_path = outdir / "global_vars.toml"
        assert gv_path.exists()
        doc = tomlkit.loads(gv_path.read_text())
        entry = cast(dict[str, Any], doc["3735928559"])  # 0xDEADBEEF
        assert entry["name"] == "g_deadbeef"
        assert entry["type"] != "#include"
        assert "<windows.h>" not in entry["name"]

    def test_no_global_vars_toml_when_no_globals(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            {
                "func.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nvoid func(void) {}\n"
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0
        assert not (outdir / "global_vars.toml").exists()


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------


class TestBinsyncExportDryRun:
    def test_dry_run_writes_nothing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path,
            {
                "f.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nvoid f(void) {}\n"
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch, "--dry-run")
        assert result.exit_code == 0
        # Nothing should exist on disk
        assert not outdir.exists()

    def test_dry_run_json_reports_counts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            {
                "f.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nvoid f(void) {}\n"
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch, "--dry-run", "--json")
        assert result.exit_code == 0
        import json

        data = json.loads(result.stdout)
        assert data["dry_run"] is True
        assert data["functions"] == 1
        assert not outdir.exists()


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


class TestBinsyncExportJson:
    def test_json_output_structure(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path,
            {
                "f.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nvoid f(void) {}\n"
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch, "--json")
        assert result.exit_code == 0
        import json

        data = json.loads(result.stdout)
        assert "functions" in data
        assert "globals" in data
        assert "structs" in data
        assert "function_files" in data
        assert data["functions"] == 1
        assert data["globals"] == 0


class TestBinsyncWriters:
    def test_global_vars_toml_sorted_and_size_skipped(self, tmp_path: Path) -> None:
        from rebrew.binsync_export import _write_global_vars_toml

        out = tmp_path / "global_vars.toml"
        _write_global_vars_toml(out, [(0x2000, "g_b", 0), (0x1000, "g_a", 4)])
        text = out.read_text()
        # Sorted by VA → g_a (0x1000) first.
        assert text.index("g_a") < text.index("g_b")
        # size omitted when 0, present when > 0.
        assert "size = 4" in text
        assert text.count("size =") == 1

    def test_struct_toml_placeholder(self, tmp_path: Path) -> None:
        from rebrew.binsync_export import _write_struct_toml

        out = tmp_path / "structs" / "NPSTATE.toml"
        out.parent.mkdir()
        _write_struct_toml(out, "NPSTATE")
        assert "NPSTATE" in out.read_text()


class TestBinsyncGhidraComment:
    def test_ghidra_name_differing_from_symbol(self, tmp_path: Path) -> None:
        from rebrew.binsync_export import _write_function_toml

        out = tmp_path / "f.toml"
        _write_function_toml(
            out,
            name="local_name",
            va=0x1000,
            size=10,
            prototype="",
            status="EXACT",
            cflags="",
            note="",
            ghidra="ghidra_name",
        )
        content = out.read_text(encoding="utf-8")
        assert "[rebrew:ghidra] ghidra_name" in content

    def test_export_toml_left_readonly(self, tmp_path: Path) -> None:
        """binsync exports (functions/*.toml, global_vars.toml, structs/*.toml)
        are write-locked 0444 — direct edits fail, tools chmod+update+re-lock."""
        from rebrew.binsync_export import (
            _write_function_toml,
            _write_global_vars_toml,
            _write_struct_toml,
        )

        fn = tmp_path / "functions" / "1000.toml"
        fn.parent.mkdir(parents=True)
        _write_function_toml(
            fn,
            name="f",
            va=0x1000,
            size=4,
            prototype="",
            status="EXACT",
            cflags="",
            note="",
            ghidra="",
        )
        gv = tmp_path / "global_vars.toml"
        _write_global_vars_toml(gv, [(0x2000, "g_var", 4)])
        st = tmp_path / "structs" / "S.toml"
        st.parent.mkdir(parents=True)
        _write_struct_toml(st, "S", fields=[{"name": "x", "type": "int"}])
        for path in (fn, gv, st):
            assert (path.stat().st_mode & 0o777) == 0o444, path

    def test_ghidra_name_matching_symbol_omitted(self, tmp_path: Path) -> None:
        from rebrew.binsync_export import _write_function_toml

        out = tmp_path / "f.toml"
        _write_function_toml(
            out,
            name="same_name",
            va=0x1000,
            size=10,
            prototype="",
            status="EXACT",
            cflags="",
            note="",
            ghidra="same_name",
        )
        assert "[rebrew:ghidra]" not in out.read_text(encoding="utf-8")


class TestBinsyncExportModuleFilter:
    def test_module_filter(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path,
            {
                "a.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nint a(void){return 1;}\n",
                "b.c": "// FUNCTION: OTHER 0x10002000\n// STATUS: EXACT\n// SIZE: 4\nint b(void){return 2;}\n",
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch, "--module", "SERVER")
        assert result.exit_code == 0
        assert (outdir / "functions" / "10001000.toml").exists()
        assert not (outdir / "functions" / "10002000.toml").exists()

    def test_module_filter_unknown_exits_nonzero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            {
                "a.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nint a(void){return 1;}\n"
            },
        )
        result, _ = _invoke(tmp_path, monkeypatch, "--module", "UNKNOWN", "--json")
        assert result.exit_code != 0

    def test_module_filter_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json as _json

        _make_project(
            tmp_path,
            {
                "a.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nint a(void){return 1;}\n"
            },
        )
        result, _ = _invoke(tmp_path, monkeypatch, "--module", "SERVER", "--json")
        assert result.exit_code == 0
        data = _json.loads(result.stdout)
        assert data["module"] == "SERVER"


class TestBinsyncStructFields:
    def test_parse_struct_fields(self) -> None:
        from rebrew.binsync_export import _parse_struct_fields

        fields = _parse_struct_fields("typedef struct { int x; int y; char name[32]; } Foo;")
        names = [f["name"] for f in fields]
        assert "x" in names and "y" in names and "name" in names

    def test_struct_with_fields_written(self, tmp_path: Path) -> None:
        from rebrew.binsync_export import _write_struct_toml

        out = tmp_path / "MyStruct.toml"
        _write_struct_toml(
            out, "MyStruct", fields=[{"name": "x", "type": "int"}, {"name": "y", "type": "float"}]
        )
        doc = tomlkit.loads(out.read_text())
        assert "fields" in doc
        fields = cast(dict[str, Any], doc["fields"])
        assert fields["x"]["type"] == "int"
        assert fields["y"]["type"] == "float"

    def test_struct_fields_from_header(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Real struct definitions via headers should produce fields, not placeholders
        _make_project(
            tmp_path,
            {
                "a.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nint a(void){return 1;}\n",
            },
        )
        # Add a header with a real typedef struct
        (tmp_path / "src" / "types.h").write_text(
            "typedef struct {\n    int x;\n    float y;\n} Point;\n", encoding="utf-8"
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0
        p = outdir / "structs" / "Point.toml"
        assert p.exists()
        doc = tomlkit.loads(p.read_text())
        assert "fields" in doc


class TestBinsyncCatalogSync:
    def test_catalog_only_functions_exported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _TOML_WITH_SERVER = """
[project]
default_target = "server"

[targets.server]
binary = "server.dll"
reversed_dir = "src/server"
"""
        (tmp_path / "rebrew-project.toml").write_text(_TOML_WITH_SERVER, encoding="utf-8")
        (tmp_path / "src" / "server").mkdir(parents=True)
        (tmp_path / "src" / "server" / "foo.c").write_text(
            "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 10\nint foo(void){return 1;}\n",
            encoding="utf-8",
        )
        (tmp_path / "src" / "server" / "functions.txt").write_text(
            "0x10001000 10 foo\n0x10002000 16 bar_func\n", encoding="utf-8"
        )
        outdir = tmp_path / "binsync_out"
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["binsync-export", str(outdir), "--json"])
        assert result.exit_code == 0, result.output
        assert (outdir / "functions" / "10001000.toml").exists()
        assert (outdir / "functions" / "10002000.toml").exists()
        # Catalog-only gets no rebrew comment; name is raw (no _ prefix for catalog entries)
        doc = tomlkit.loads((outdir / "functions" / "10002000.toml").read_text())
        assert "comments" not in doc
        assert cast(dict[str, Any], doc["info"])["name"] in ("bar_func", "_bar_func")

    def test_catalog_clean_removes_orphans(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _TOML_WITH_SERVER = """
[project]
default_target = "server"

[targets.server]
binary = "server.dll"
reversed_dir = "src/server"
"""

        (tmp_path / "rebrew-project.toml").write_text(_TOML_WITH_SERVER, encoding="utf-8")
        (tmp_path / "src" / "server").mkdir(parents=True)
        (tmp_path / "src" / "server" / "foo.c").write_text(
            "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 10\nint foo(void){return 1;}\n",
            encoding="utf-8",
        )
        (tmp_path / "src" / "server" / "functions.txt").write_text(
            "0x10001000 10 foo\n0x10002000 16 bar_func\n", encoding="utf-8"
        )
        outdir = tmp_path / "binsync_out_clean"
        monkeypatch.chdir(tmp_path)
        r = runner.invoke(app, ["binsync-export", str(outdir), "--json"])
        assert r.exit_code == 0, r.output
        # Orphan a file
        (outdir / "functions" / "99999999.toml").write_text('[info]\nname = "orphan"\naddr = 1\n')
        # Remove bar from catalog, then --clean should delete both 10002000 and orphan
        (tmp_path / "src" / "server" / "functions.txt").write_text(
            "0x10001000 10 foo\n", encoding="utf-8"
        )
        r2 = runner.invoke(app, ["binsync-export", str(outdir), "--clean", "--json"])
        assert r2.exit_code == 0, r2.output
        import json as _j

        assert not (outdir / "functions" / "10002000.toml").exists()
        assert not (outdir / "functions" / "99999999.toml").exists()
        assert len(_j.loads(r2.stdout).get("cleaned", [])) == 2

    def test_module_filter_still_works_with_catalog(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Catalog VAs have module="" so --module SERVER should filter them out?  Export
        # module filter applies to annotation entries; catalog entries are module-less
        # and should still export when no filter is set.
        _TOML_WITH_SERVER = """
[project]
default_target = "server"

[targets.server]
binary = "server.dll"
reversed_dir = "src/server"
"""
        (tmp_path / "rebrew-project.toml").write_text(_TOML_WITH_SERVER, encoding="utf-8")
        (tmp_path / "src" / "server").mkdir(parents=True)
        (tmp_path / "src" / "server" / "functions.txt").write_text(
            "0x10002000 16 bar_func\n", encoding="utf-8"
        )
        outdir = tmp_path / "binsync_out2"
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["binsync-export", str(outdir), "--json"])
        # No annotations, but catalog has a function — should still export (not "No annotations found")
        assert result.exit_code == 0, result.output
        assert (outdir / "functions" / "10002000.toml").exists()


class TestBinsyncStructNames:
    def test_struct_annotation_creates_struct_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.binsync_export import app

        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=tmp_path / "src" / "SERVER",
            metadata_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
        )
        cfg.reversed_dir.mkdir(parents=True, exist_ok=True)
        (cfg.reversed_dir / "f.c").write_text(
            "// FUNCTION: SERVER 0x1000\n// STRUCT: MyStruct\nint f(void) { return 0; }\n",
            encoding="utf-8",
        )
        monkeypatch.setattr("rebrew.binsync_export.require_config", lambda **kw: cfg)
        outdir = tmp_path / "binsync"
        result = CliRunner().invoke(app, ["--json", str(outdir)])
        assert result.exit_code == 0
        assert (outdir / "structs" / "MyStruct.toml").exists()
