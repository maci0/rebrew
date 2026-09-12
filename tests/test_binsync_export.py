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

pytest.importorskip("declib")


def _load_func(path: Path) -> Any:
    from rebrew.binsync_serial import load_artifact

    return load_artifact(path, "function")


def _load_artifacts(path: Path, kind: str) -> list[Any]:
    from rebrew.binsync_serial import load_many

    return load_many(path, kind)


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
        func = _load_func(toml_file)
        assert func.addr == 0x10001000
        assert func.name == "_foo"
        assert func.size == 31

    def test_size_zero_written(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path,
            {
                "bar.c": "// FUNCTION: SERVER 0x20002000\n// STATUS: NEAR_MATCHING\ndouble bar() { return 2.0; }\n",
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0
        func = _load_func(outdir / "functions" / "20002000.toml")
        assert func.addr == 0x20002000
        assert func.size == 0

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
        name = _load_func(outdir / "functions" / "30003000.toml").name
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
    def test_status_and_cflags_not_exported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """STATUS/CFLAGS have no BinSync counterpart — the old write-only
        ``[rebrew] STATUS=… CFLAGS=…`` comment was removed (metadata-review
        R2): the function TOML carries only BinSync-native fields."""
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
        comments = doc.get("comments")
        assert comments is None or not any("[rebrew] STATUS=" in str(v) for v in comments.values())

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
        comments = _load_artifacts(outdir / "comments.toml", "comment")
        note = next(c for c in comments if c.addr == 0x10020000 + 1)
        assert note.func_addr == 0x10020000
        assert "worth double-checking" in note.comment
        assert note.comment.startswith("[rebrew:note]")


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
        globals_list = _load_artifacts(gv_path, "global_variable")
        assert [g.addr for g in globals_list] == [0x01008000]
        assert globals_list[0].name and globals_list[0].type
        assert globals_list[0].size == 64

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
        globals_list = _load_artifacts(gv_path, "global_variable")
        entry = next(g for g in globals_list if g.addr == 0xDEADBEEF)
        assert entry.name == "g_deadbeef"
        assert entry.type != "#include"
        assert "<windows.h>" not in entry.name

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
    def test_global_vars_sizes(self, tmp_path: Path) -> None:
        from rebrew.binsync_export import _write_global_vars_toml

        out = tmp_path / "global_vars.toml"
        _write_global_vars_toml(
            out,
            [(0x2000, "g_b", 0, "char", None), (0x1000, "g_a", 4, "char", None)],
        )
        arts = {g.addr: g for g in _load_artifacts(out, "global_variable")}
        assert arts[0x1000].size == 4
        # size 0 is omitted (None), not written as 0x0.
        assert arts[0x2000].size is None

    def test_struct_toml_placeholder(self, tmp_path: Path) -> None:
        from rebrew.binsync_export import _write_struct_toml
        from rebrew.binsync_serial import load_artifact

        out = tmp_path / "structs" / "NPSTATE.toml"
        out.parent.mkdir()
        _write_struct_toml(out, "NPSTATE")
        struct = load_artifact(out, "struct")
        assert struct is not None
        assert struct.name == "NPSTATE"


class TestBinsyncGhidraComment:
    def test_ghidra_comment_written(self, tmp_path: Path) -> None:
        from rebrew.binsync_export import _write_comments_toml

        out = tmp_path / "comments.toml"
        _write_comments_toml(out, [(0x1002, 0x1000, "[rebrew:ghidra] ghidra_name")])
        comments = _load_artifacts(out, "comment")
        assert [c.addr for c in comments] == [0x1002]
        assert comments[0].func_addr == 0x1000
        assert comments[0].comment == "[rebrew:ghidra] ghidra_name"

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
        _write_function_toml(fn, name="f", va=0x1000, size=4, prototype="")
        gv = tmp_path / "global_vars.toml"
        _write_global_vars_toml(gv, [(0x2000, "g_var", 4, "char", None)])
        st = tmp_path / "structs" / "S.toml"
        st.parent.mkdir(parents=True)
        _write_struct_toml(st, "S", fields=[{"name": "x", "type": "int"}])
        for path in (fn, gv, st):
            assert (path.stat().st_mode & 0o777) == 0o444, path

    def test_ghidra_name_matching_symbol_omitted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A GHIDRA name equal to the exported symbol produces no comment."""
        _make_project(
            tmp_path,
            {
                "f.c": (
                    "// FUNCTION: SERVER 0x10001000\n"
                    "// STATUS: EXACT\n"
                    "// SIZE: 4\n"
                    "// GHIDRA: _foo\n"
                    "int foo(void) { return 1; }\n"
                )
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        comments_path = outdir / "comments.toml"
        comments = _load_artifacts(comments_path, "comment") if comments_path.exists() else []
        assert not any("[rebrew:ghidra]" in (c.comment or "") for c in comments)


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
        from rebrew.binsync_serial import load_artifact

        out = tmp_path / "MyStruct.toml"
        _write_struct_toml(
            out, "MyStruct", fields=[{"name": "x", "type": "int"}, {"name": "y", "type": "float"}]
        )
        struct = load_artifact(out, "struct")
        assert struct is not None
        assert struct.name == "MyStruct"
        assert struct.members[0].name == "x"
        assert struct.members[0].type == "int"
        assert struct.members[4].name == "y"
        assert struct.members[4].type == "float"

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
        from rebrew.binsync_serial import load_artifact

        struct = load_artifact(p, "struct")
        assert struct is not None
        assert struct.members[0].name == "x"
        assert struct.members[4].name == "y"


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
        # Catalog-only gets no rebrew provenance comment; name is raw.
        func = _load_func(outdir / "functions" / "10002000.toml")
        assert func.name in ("bar_func", "_bar_func")
        comments_path = outdir / "comments.toml"
        comments = _load_artifacts(comments_path, "comment") if comments_path.exists() else []
        assert not any(c.func_addr == 0x10002000 for c in comments)

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


class TestManifest:
    def test_manifest_written(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 31\nint foo() { return 1; }\n",
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        manifest = outdir / "manifest.toml"
        assert manifest.exists()
        doc = tomlkit.parse(manifest.read_text(encoding="utf-8"))
        assert doc["content_hash"]
        assert doc["exported_at"]

    def test_manifest_loads(self, tmp_path: Path) -> None:
        from rebrew.binsync_state import load_manifest

        assert load_manifest(tmp_path) == {}
        manifest = tmp_path / "manifest.toml"
        manifest.write_text(
            'exported_at = "2026-09-10T00:00:00+00:00"\ncontent_hash = "abc"\n', encoding="utf-8"
        )
        assert load_manifest(tmp_path) == {
            "exported_at": "2026-09-10T00:00:00+00:00",
            "content_hash": "abc",
        }


class TestBinaryHashAndSharedTypes:
    _FOO = (
        "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 31\nint foo() { return 1; }\n"
    )

    def test_binary_hash_written(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import hashlib

        payload = b"pe-server-binary"
        (tmp_path / "server.dll").write_bytes(payload)
        _make_project(tmp_path, {"foo.c": self._FOO})
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        digest = hashlib.md5(payload).hexdigest()
        assert (outdir / "binary_hash").read_text(encoding="utf-8") == digest
        doc = tomlkit.parse((outdir / "manifest.toml").read_text(encoding="utf-8"))
        assert doc["target"] == "server"
        assert doc["binary_hash"] == digest

    def test_binary_hash_omitted_without_binary(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(tmp_path, {"foo.c": self._FOO})
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        assert not (outdir / "binary_hash").exists()

    def test_shared_header_struct_exported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(tmp_path, {"foo.c": self._FOO})
        shared = tmp_path / "src" / "shared"
        shared.mkdir()
        (shared / "point.h").write_text(
            "typedef struct {\n    int x;\n    int y;\n} Point;\n", encoding="utf-8"
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        assert (outdir / "structs" / "Point.toml").exists()


class TestBinsyncEnumsAndTypedefs:
    _FOO = "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nint foo() { return 1; }\n"

    def test_enum_and_typedef_exported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import json

        _make_project(tmp_path, {"foo.c": self._FOO})
        (tmp_path / "src" / "types.h").write_text(
            "typedef enum { A, B = 5, C } E;\ntypedef unsigned int uint32_t;\n",
            encoding="utf-8",
        )
        result, outdir = _invoke(tmp_path, monkeypatch, "--json")
        assert result.exit_code == 0, result.output

        enums = _load_artifacts(outdir / "enums.toml", "enum")
        enum = next(e for e in enums if e.name == "E")
        assert {str(k): int(v) for k, v in enum.members.items()} == {"A": 0, "B": 5, "C": 6}

        typedefs = _load_artifacts(outdir / "typedefs.toml", "typedef")
        typedef = next(t for t in typedefs if t.name == "uint32_t")
        assert typedef.type == "unsigned int"

        payload = json.loads(result.stdout)
        assert payload["enums"] == 1
        assert payload["typedefs"] == 1
        assert str(payload["enums_file"]).endswith("enums.toml")
        assert str(payload["typedefs_file"]).endswith("typedefs.toml")

    def test_shared_dir_enum_exported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(tmp_path, {"foo.c": self._FOO})
        shared = tmp_path / "src" / "shared"
        shared.mkdir()
        (shared / "colors.h").write_text("typedef enum { RED, GREEN } Color;\n", encoding="utf-8")
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        enums = tomlkit.loads((outdir / "enums.toml").read_text())
        assert "Color" in enums

    def test_empty_collections_write_no_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(tmp_path, {"foo.c": self._FOO})
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        assert not (outdir / "enums.toml").exists()
        assert not (outdir / "typedefs.toml").exists()


class TestDeclibParse:
    """The written state dir must parse with declib (not just with rebrew)."""

    def test_exported_dir_parses_with_declib(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from declib.artifacts import Comment, Enum, Function, GlobalVariable, Struct, Typedef

        _make_project(
            tmp_path,
            {
                "foo.c": (
                    "// FUNCTION: SERVER 0x10001000\n"
                    "// STATUS: EXACT\n"
                    "// SIZE: 16\n"
                    "// NOTE: a note\n"
                    "int foo(void) { return 1; }\n"
                ),
                "data.c": "// GLOBAL: SERVER 0x01008000\n// SIZE: 4\nchar g_x;\n",
                "types.h": (
                    "typedef struct { int x; } Point;\n"
                    "typedef enum { A, B } E;\n"
                    "typedef unsigned int uint32_t;\n"
                ),
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output

        func = Function.loads((outdir / "functions" / "10001000.toml").read_text())
        assert func.addr == 0x10001000
        assert func.name == "_foo"
        comments = Comment.loads_many((outdir / "comments.toml").read_text())
        assert any((c.comment or "").startswith("[rebrew:note]") for c in comments)
        gvars = GlobalVariable.loads_many((outdir / "global_vars.toml").read_text())
        assert gvars[0].addr == 0x01008000
        enums = Enum.loads_many((outdir / "enums.toml").read_text())
        assert enums[0].name == "E"
        typedefs = Typedef.loads_many((outdir / "typedefs.toml").read_text())
        assert typedefs[0].name == "uint32_t"
        struct = Struct.loads((outdir / "structs" / "Point.toml").read_text())
        assert struct.name == "Point"
        assert struct.members[0].name == "x"
        metadata = tomlkit.parse((outdir / "metadata.toml").read_text())
        assert metadata["user"]
        assert metadata["version"]

    def test_locals_and_comments_round_trip(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata import get_entry, update_field

        foo = "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 16\nint foo(void){return 1;}\n"
        proj_a = tmp_path / "a"
        proj_a.mkdir()
        _make_project(proj_a, {"foo.c": foo})
        update_field(
            proj_a,
            0x10001000,
            "locals",
            {"-4": {"name": "ret", "type": "int", "size": 4}},
            "SERVER",
        )
        update_field(
            proj_a,
            0x10001000,
            "comments",
            {"0x10001004": {"comment": "hi", "func_addr": 0x10001000}},
            "SERVER",
        )
        state_a = tmp_path / "state_a"
        monkeypatch.chdir(proj_a)
        result = runner.invoke(app, ["binsync-export", str(state_a), "--json"])
        assert result.exit_code == 0, result.output
        func = _load_func(state_a / "functions" / "10001000.toml")
        assert func.stack_vars[-4].name == "ret"
        assert func.stack_vars[-4].type == "int"
        comments = _load_artifacts(state_a / "comments.toml", "comment")
        assert any(c.addr == 0x10001004 and c.comment == "hi" for c in comments)

        proj_b = tmp_path / "b"
        proj_b.mkdir()
        _make_project(proj_b, {"foo.c": foo})
        monkeypatch.chdir(proj_b)
        result = runner.invoke(app, ["binsync-import", str(state_a), "--json"])
        assert result.exit_code == 0, result.output
        entry = get_entry(proj_b, 0x10001000, "SERVER")
        assert entry.get("locals") == {"-4": {"name": "ret", "type": "int", "size": 4}}
        assert entry.get("comments")

        state_b = tmp_path / "state_b"
        result = runner.invoke(app, ["binsync-export", str(state_b), "--json"])
        assert result.exit_code == 0, result.output
        func_b = _load_func(state_b / "functions" / "10001000.toml")
        assert func_b.stack_vars[-4].name == "ret"
