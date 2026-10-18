"""Tests for binsync_export.py."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
import tomlkit
from cli_json import cli_payload
from source_util import SourceFixture, write_source, write_store_fixture
from typer.testing import CliRunner

from rebrew.app.main import app

runner = CliRunner()

pytest.importorskip("declib")


def _load_func(path: Path) -> Any:
    from rebrew.binsync.serial import load_artifact

    return load_artifact(path, "function")


def _load_artifacts(path: Path, kind: str) -> list[Any]:
    from rebrew.binsync.serial import load_many

    return load_many(path, kind)


class TestSerialBom:
    def test_load_artifact_strips_utf8_bom(self, tmp_path: Path) -> None:
        """Notepad-style EF BB BF must not make a valid artifact unreadable."""
        from declib.artifacts import Function

        from rebrew.binsync.serial import load_artifact

        path = tmp_path / "fn.toml"
        # Write unlocked: dump_artifact locks 0444; we need to prefix a BOM.
        body = Function(addr=0x1000, name="foo").dumps()
        path.write_bytes(b"\xef\xbb\xbf" + body.encode("utf-8"))
        loaded = load_artifact(path, "function")
        assert loaded is not None
        assert loaded.name == "foo"

    def test_load_many_strips_utf8_bom(self, tmp_path: Path) -> None:
        from declib.artifacts import Comment

        from rebrew.binsync.serial import load_many

        path = tmp_path / "comments.toml"
        body = Comment.dumps_many(
            [Comment(addr=0x1001, func_addr=0x1000, comment="hi")], key_attr="addr"
        )
        path.write_bytes(b"\xef\xbb\xbf" + body.encode("utf-8"))
        loaded = load_many(path, "comment")
        assert len(loaded) == 1
        assert loaded[0].comment == "hi"


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
    write_source(tmp_path / "rebrew-project.toml", _TOML_CFG, encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    for name, content in files.items():
        write_source(src / name, content, encoding="utf-8")
    return tmp_path


def _invoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *extra_args: str) -> Any:
    """Run `rebrew binsync export <outdir> [extra_args]` from tmp_path."""
    outdir = tmp_path / "binsync_out"
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["binsync", "export", str(outdir), *extra_args])
    return result, outdir


# ---------------------------------------------------------------------------
# Basic export (name, addr, size)
# ---------------------------------------------------------------------------


class TestBinsyncExportBasic:
    def test_name_and_addr(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n\n\nint foo() { return 1; }\n",
                    {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 31}},
                ),
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        toml_file = outdir / "functions" / "10001000.toml"
        assert toml_file.exists()
        func = _load_func(toml_file)
        assert func.addr == 0x10001000
        assert func.name == "foo"  # the C name; the decorated symbol stays local
        assert func.size == 31

    def test_size_zero_written(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path,
            {
                "bar.c": SourceFixture(
                    "/* ADDRESS: SERVER 0x20002000 */\n\ndouble bar() { return 2.0; }\n",
                    {"SERVER.0x20002000": {"kind": "FUNCTION"}},
                ),
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
                "stub.c": SourceFixture(
                    "void stub(void);\n", {"SERVER.0x30003000": {"kind": "FUNCTION"}}
                ),
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0
        name = _load_func(outdir / "functions" / "30003000.toml").name
        # A prototype-only stub carries no symbol: the name falls back to func_<va>
        assert name == "func_30003000"


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
                    SourceFixture(
                        "/* ADDRESS: SERVER 0x10001000 */\n\n\nint __cdecl Calc(int x, int y) { return x + y; }\n",
                        {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 20}},
                    )
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
                "f.c": SourceFixture(
                    "/* ADDRESS: SERVER 0x10002000 */\n\n\nvoid f(void) {}\n",
                    {"SERVER.0x10002000": {"kind": "FUNCTION", "size": 5}},
                )
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
                    SourceFixture(
                        "/* ADDRESS: SERVER 0x10010000 */\n\n\n\nint f(void) { return 0; }\n",
                        {
                            "SERVER.0x10010000": {
                                "kind": "FUNCTION",
                                "size": 12,
                                "cflags": "/O1 /Gd",
                            }
                        },
                    )
                ),
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0
        doc = tomlkit.loads((outdir / "functions" / "10010000.toml").read_text())
        # The marker is spelled `[rebrew:…]`; a rewrite under any other prefix
        # or into a different field is the same regression, so scan the text.
        exported = "\n".join(
            p.read_text(encoding="utf-8")
            for p in sorted(outdir.rglob("*.toml"))
            if p.name != "manifest.toml"
        )
        assert "[rebrew" not in exported
        assert "STATUS=" not in exported
        assert "CFLAGS=" not in exported
        comments = doc.get("comments")
        assert comments is None or not any("[rebrew" in str(v) for v in comments.values())

    def test_note_written_at_va_plus_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata.functions import update_field

        _make_project(
            tmp_path,
            {
                "g.c": (
                    SourceFixture(
                        "/* ADDRESS: SERVER 0x10020000 */\n\nvoid g(void) {}\n",
                        {"SERVER.0x10020000": {"kind": "FUNCTION", "size": 8}},
                    )
                ),
            },
        )
        update_field(tmp_path, 0x10020000, "note", "worth double-checking", "SERVER")
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
        from rebrew.data_scan import scan_globals

        scans = 0

        def scan_once(*args: Any, **kwargs: Any) -> Any:
            nonlocal scans
            scans += 1
            return scan_globals(*args, **kwargs)

        monkeypatch.setattr("rebrew.data_scan.scan_globals", scan_once)
        _make_project(
            tmp_path,
            {
                "func.c": SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n\n\nvoid func(void) {}\n",
                    {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 4}},
                ),
                "data.c": (
                    SourceFixture(
                        "/* ADDRESS: SERVER 0x01008000 */\n\nchar g_szBuffer[64];\n",
                        {"SERVER.0x01008000": {"kind": "GLOBAL", "size": 64}},
                    )
                ),
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0
        gv_path = outdir / "global_vars.toml"
        assert gv_path.exists()
        globals_list = _load_artifacts(gv_path, "global_variable")
        assert [g.addr for g in globals_list] == [0x01008000]
        assert globals_list[0].name == "g_szBuffer"
        assert globals_list[0].type == "char[64]"
        assert globals_list[0].size == 64
        assert scans == 1

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
                "stub.c": SourceFixture(
                    "#include <windows.h>\n\nvoid f(void) {}\n",
                    {"SERVER.0xDEADBEEF": {"kind": "DATA"}},
                ),
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
                "func.c": SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n\n\nvoid func(void) {}\n",
                    {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 4}},
                )
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
                "f.c": SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n\n\nvoid f(void) {}\n",
                    {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 4}},
                )
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
                "f.c": SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n\n\nvoid f(void) {}\n",
                    {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 4}},
                )
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch, "--dry-run", "--json")
        assert result.exit_code == 0

        data = cli_payload(result)
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
                "f.c": SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n\n\nvoid f(void) {}\n",
                    {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 4}},
                )
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch, "--json")
        assert result.exit_code == 0

        data = cli_payload(result)
        assert "functions" in data
        assert "globals" in data
        assert "structs" in data
        assert "function_files" in data
        assert data["functions"] == 1
        assert data["globals"] == 0


class TestBinsyncWriters:
    def test_struct_size_cannot_truncate_a_member(self, tmp_path: Path) -> None:
        from rebrew.binsync.export import _write_struct_toml

        path = tmp_path / "Point.toml"
        path.write_text("preserved")
        with pytest.raises(ValueError, match="smaller than member extent"):
            _write_struct_toml(
                path,
                "Point",
                [{"name": "x", "type": "int", "offset": 0, "size": 4}],
                total_size=1,
            )
        assert path.read_text() == "preserved"

    def test_global_vars_sizes(self, tmp_path: Path) -> None:
        from rebrew.binsync.export import _write_global_vars_toml

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
        from rebrew.binsync.export import _write_struct_toml
        from rebrew.binsync.serial import load_artifact

        out = tmp_path / "structs" / "NPSTATE.toml"
        out.parent.mkdir()
        _write_struct_toml(out, "NPSTATE")
        struct = load_artifact(out, "struct")
        assert struct is not None
        assert struct.name == "NPSTATE"


class TestBinsyncGhidraComment:
    def test_ghidra_comment_written(self, tmp_path: Path) -> None:
        from rebrew.binsync.export import _write_comments_toml

        out = tmp_path / "comments.toml"
        _write_comments_toml(out, [(0x1002, 0x1000, "[rebrew:ghidra] ghidra_name")])
        comments = _load_artifacts(out, "comment")
        assert [c.addr for c in comments] == [0x1002]
        assert comments[0].func_addr == 0x1000
        assert comments[0].comment == "[rebrew:ghidra] ghidra_name"

    def test_export_leaves_state_files_writable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """BinSync's own State.dump rewrites these files on the same tree, so
        an export leaves every state file writable, and an identical re-export
        unlocks a file an older rebrew left 0444."""
        _make_project(
            tmp_path,
            {
                "foo.c": SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n\n\nint foo(void) { return 1; }\n/* ADDRESS: SERVER 0x10003000 */\nint g_count;\n",
                    {
                        "SERVER.0x10001000": {"kind": "FUNCTION", "size": 11, "note": "n"},
                        "SERVER.0x10003000": {"kind": "GLOBAL"},
                    },
                ),
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        written = [p for p in outdir.rglob("*") if p.is_file()]
        assert any(p.name == "metadata.toml" for p in written)
        assert any(p.name == "manifest.toml" for p in written)
        for path in written:
            assert path.stat().st_mode & 0o200, path

        legacy = outdir / "metadata.toml"
        legacy.chmod(0o444)
        result, _ = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        assert legacy.stat().st_mode & 0o200

    def test_ghidra_name_matching_symbol_omitted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A GHIDRA name equal to the exported symbol produces no comment."""
        _make_project(
            tmp_path,
            {
                "f.c": (
                    SourceFixture(
                        "/* ADDRESS: SERVER 0x10001000 */\n\n\n\nint foo(void) { return 1; }\n",
                        {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 4, "ghidra": "_foo"}},
                    )
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
                "a.c": SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n\n\nint a(void){return 1;}\n",
                    {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 4}},
                ),
                "b.c": SourceFixture(
                    "/* ADDRESS: OTHER 0x10002000 */\n\n\nint b(void){return 2;}\n",
                    {"OTHER.0x10002000": {"kind": "FUNCTION", "size": 4}},
                ),
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
                "a.c": SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n\n\nint a(void){return 1;}\n",
                    {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 4}},
                )
            },
        )
        result, _ = _invoke(tmp_path, monkeypatch, "--module", "UNKNOWN", "--json")
        assert result.exit_code == 2
        assert cli_payload(result) == {"error": "No annotations found.", "code": 2}

    def test_module_filter_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:

        _make_project(
            tmp_path,
            {
                "a.c": SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n\n\nint a(void){return 1;}\n",
                    {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 4}},
                )
            },
        )
        result, _ = _invoke(tmp_path, monkeypatch, "--module", "SERVER", "--json")
        assert result.exit_code == 0
        data = cli_payload(result)
        assert data["module"] == "SERVER"


class TestBinsyncStructFields:
    def testparse_struct_fields(self) -> None:
        from rebrew.binsync.state import parse_struct_fields

        fields = parse_struct_fields("typedef struct { int x; int y; char name[32]; } Foo;")
        names = [f["name"] for f in fields]
        assert "x" in names and "y" in names and "name" in names

    def test_struct_with_fields_written(self, tmp_path: Path) -> None:
        from rebrew.binsync.export import _write_struct_toml
        from rebrew.binsync.serial import load_artifact

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
                "a.c": SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n\n\nint a(void){return 1;}\n",
                    {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 4}},
                ),
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
        from rebrew.binsync.serial import load_artifact

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
        write_source(tmp_path / "rebrew-project.toml", _TOML_WITH_SERVER, encoding="utf-8")
        (tmp_path / "src" / "server").mkdir(parents=True)
        write_source(
            tmp_path / "src" / "server" / "foo.c",
            "/* ADDRESS: SERVER 0x10001000 */\n\n\nint foo(void){return 1;}\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x10001000": {"kind": "FUNCTION", "size": 10}},
        )
        import json as _json

        (tmp_path / "src" / "server" / "function_structure.json").write_text(
            _json.dumps(
                [
                    {"va": 0x10001000, "size": 10, "name": "foo"},
                    {"va": 0x10002000, "size": 16, "name": "bar_func"},
                ]
            ),
            encoding="utf-8",
        )
        outdir = tmp_path / "binsync_out"
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["binsync", "export", str(outdir), "--json"])
        assert result.exit_code == 0, result.output
        assert (outdir / "functions" / "10001000.toml").exists()
        assert (outdir / "functions" / "10002000.toml").exists()
        # Catalog-only gets no rebrew provenance comment; name is raw.
        func = _load_func(outdir / "functions" / "10002000.toml")
        assert func.name in ("bar_func", "_bar_func")
        comments_path = outdir / "comments.toml"
        comments = _load_artifacts(comments_path, "comment") if comments_path.exists() else []
        assert not any(c.func_addr == 0x10002000 for c in comments)

    def test_catalog_vas_inside_an_annotated_function_are_not_exported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A catalog VA inside an annotated span is not a separate function.

        Regression: the skip test was `va in reversed_vas`, an exact START
        match, so a catalog entry falling *inside* an annotated function was
        exported as its own function.  Heuristic discovery emits switch arms as
        pseudo-functions (`case.0x...`), so guild-rebrew's state dir gained 18
        of them -- and because import reads the same state back,
        `rebrew sync --pull` then proposed creating them as real functions
        inside code that was already EXACT/RELOC.
        """
        toml = """
[project]
default_target = "server"

[targets.server]
binary = "server.dll"
reversed_dir = "src/server"
"""
        write_source(tmp_path / "rebrew-project.toml", toml, encoding="utf-8")
        (tmp_path / "src" / "server").mkdir(parents=True)
        write_source(
            tmp_path / "src" / "server" / "foo.c",
            "/* ADDRESS: SERVER 0x10001000 */\n\n\nint foo(void){return 1;}\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x10001000": {"kind": "FUNCTION", "size": 256}},
        )
        import json as _json

        (tmp_path / "src" / "server" / "function_structure.json").write_text(
            _json.dumps(
                [
                    {"va": 0x10001000, "size": 256, "name": "foo"},
                    # A switch arm 0x50 into foo: must NOT be exported.
                    {"va": 0x10001050, "size": 32, "name": "case.0x10001000.1"},
                    # Immediately after foo ends: a real neighbour.
                    {"va": 0x10001100, "size": 16, "name": "after_func"},
                ]
            ),
            encoding="utf-8",
        )
        outdir = tmp_path / "binsync_out"
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["binsync", "export", str(outdir), "--json"])
        assert result.exit_code == 0, result.output
        assert (outdir / "functions" / "10001000.toml").exists()
        assert (outdir / "functions" / "10001100.toml").exists()
        assert not (outdir / "functions" / "10001050.toml").exists(), (
            "a VA inside an annotated function must not be exported"
        )

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

        write_source(tmp_path / "rebrew-project.toml", _TOML_WITH_SERVER, encoding="utf-8")
        (tmp_path / "src" / "server").mkdir(parents=True)
        write_source(
            tmp_path / "src" / "server" / "foo.c",
            "/* ADDRESS: SERVER 0x10001000 */\n\n\nint foo(void){return 1;}\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x10001000": {"kind": "FUNCTION", "size": 10}},
        )
        import json as _json

        (tmp_path / "src" / "server" / "function_structure.json").write_text(
            _json.dumps(
                [
                    {"va": 0x10001000, "size": 10, "name": "foo"},
                    {"va": 0x10002000, "size": 16, "name": "bar_func"},
                ]
            ),
            encoding="utf-8",
        )
        outdir = tmp_path / "binsync_out_clean"
        monkeypatch.chdir(tmp_path)
        r = runner.invoke(app, ["binsync", "export", str(outdir), "--json"])
        assert r.exit_code == 0, r.output
        # Orphan a file
        (outdir / "functions" / "99999999.toml").write_text('[info]\nname = "orphan"\naddr = 1\n')
        # Remove bar from catalog, then --clean should delete both 10002000 and orphan
        (tmp_path / "src" / "server" / "function_structure.json").write_text(
            _json.dumps([{"va": 0x10001000, "size": 10, "name": "foo"}]),
            encoding="utf-8",
        )
        r2 = runner.invoke(app, ["binsync", "export", str(outdir), "--clean", "--json"])
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
        write_source(tmp_path / "rebrew-project.toml", _TOML_WITH_SERVER, encoding="utf-8")
        (tmp_path / "src" / "server").mkdir(parents=True)
        import json as _json

        (tmp_path / "src" / "server" / "function_structure.json").write_text(
            _json.dumps([{"va": 0x10002000, "size": 16, "name": "bar_func"}]),
            encoding="utf-8",
        )
        outdir = tmp_path / "binsync_out2"
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["binsync", "export", str(outdir), "--json"])
        # No annotations, but catalog has a function — should still export (not "No annotations found")
        assert result.exit_code == 0, result.output
        assert (outdir / "functions" / "10002000.toml").exists()


class TestBinsyncStructNames:
    def test_struct_annotation_does_not_invent_a_layout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.binsync.export import app

        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=tmp_path / "src" / "SERVER",
            metadata_dir=tmp_path,
            module="SERVER",
            source_ext=".c",
        )
        cfg.reversed_dir.mkdir(parents=True, exist_ok=True)
        write_source(
            cfg.reversed_dir / "f.c",
            "/* ADDRESS: SERVER 0x1000 */\n\nint f(void) { return 0; }\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION", "struct": "MyStruct"}},
            metadata_dir=tmp_path,
        )
        monkeypatch.setattr("rebrew.binsync.export.require_config", lambda **kw: cfg)
        outdir = tmp_path / "binsync"
        result = CliRunner().invoke(app, ["--json", str(outdir)])
        assert result.exit_code == 0
        assert not (outdir / "structs" / "MyStruct.toml").exists()


class TestManifest:
    def test_manifest_written(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n\n\nint foo() { return 1; }\n",
                    {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 31}},
                ),
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
        from rebrew.binsync.state import load_manifest

        assert load_manifest(tmp_path) == {}
        manifest = tmp_path / "manifest.toml"
        manifest.write_text(
            'exported_at = "2026-09-10T00:00:00+00:00"\ncontent_hash = "abc"\n', encoding="utf-8"
        )
        assert load_manifest(tmp_path) == {
            "exported_at": "2026-09-10T00:00:00+00:00",
            "content_hash": "abc",
        }

    def test_manifest_rerun_preserves_exported_at(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Identical content must not bump exported_at (no timestamp-only churn)."""
        _make_project(
            tmp_path,
            {
                "foo.c": SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n\n\nint foo() { return 1; }\n",
                    {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 31}},
                ),
            },
        )
        result1, outdir = _invoke(tmp_path, monkeypatch)
        assert result1.exit_code == 0, result1.output
        manifest = outdir / "manifest.toml"
        first = manifest.read_text(encoding="utf-8")
        doc1 = tomlkit.parse(first)
        result2, _ = _invoke(tmp_path, monkeypatch)
        assert result2.exit_code == 0, result2.output
        second = manifest.read_text(encoding="utf-8")
        doc2 = tomlkit.parse(second)
        assert doc1["exported_at"] == doc2["exported_at"]
        assert doc1["content_hash"] == doc2["content_hash"]
        assert first == second

    def test_manifest_bom_prefixed_still_idempotent(self, tmp_path: Path) -> None:
        """Notepad EF BB BF must not force a rewrite (content_hash still matches)."""
        import os

        from rebrew.binsync.export import _write_manifest

        outdir = tmp_path / "state"
        outdir.mkdir()
        (outdir / "functions").mkdir()
        # Seed a non-manifest toml so content_hash is non-empty and stable.
        (outdir / "functions" / "1000.toml").write_text('name = "foo"\n', encoding="utf-8")
        first_hash = _write_manifest(outdir, None, target="server")
        manifest = outdir / "manifest.toml"
        body = manifest.read_bytes()
        os.chmod(manifest, 0o644)
        manifest.write_bytes(b"\xef\xbb\xbf" + body)
        second_hash = _write_manifest(outdir, None, target="server")
        assert first_hash == second_hash
        # Idempotent path left the on-disk bytes alone (still BOM-prefixed).
        assert manifest.read_bytes().startswith(b"\xef\xbb\xbf")

    def test_unreadable_artifact_does_not_publish_hash(self, tmp_path: Path) -> None:
        """A file that cannot be hashed must not look like an unchanged export."""
        from rebrew.binsync.export import _write_manifest

        outdir = tmp_path / "state"
        (outdir / "functions").mkdir(parents=True)
        (outdir / "functions" / "1000.toml").write_text('name = "foo"\n', encoding="utf-8")
        first = _write_manifest(outdir, None, target="server")
        manifest = outdir / "manifest.toml"
        before = manifest.read_bytes()
        (outdir / "functions" / "2000.toml").write_text('name = "bar"\n', encoding="utf-8")
        real = Path.read_bytes

        def _boom(self: Path) -> bytes:
            if self.name == "2000.toml":
                raise OSError("permission denied")
            return real(self)

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(Path, "read_bytes", _boom)
        try:
            with pytest.raises(OSError, match="2000.toml"):
                _write_manifest(outdir, None, target="server")
        finally:
            monkeypatch.undo()
        assert manifest.read_bytes() == before
        assert tomlkit.parse(before.decode("utf-8"))["content_hash"] == first


class TestBinaryHashAndSharedTypes:
    _FOO = SourceFixture(
        "/* ADDRESS: SERVER 0x10001000 */\n\n\nint foo() { return 1; }\n",
        {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 31}},
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

    def test_failing_header_does_not_drop_later_structs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.types as types_mod

        _make_project(tmp_path, {"foo.c": self._FOO})
        src = tmp_path / "src"
        (src / "a_bad.h").write_text("typedef struct {\n    int b;\n} Bad;\n", encoding="utf-8")
        (src / "point.h").write_text(
            "typedef struct {\n    int x;\n    int y;\n} Point;\n", encoding="utf-8"
        )
        real_parse = types_mod.parse_structs

        def _parse(text: str) -> dict[str, types_mod.StructDef]:
            if "Bad" in text:
                raise ValueError("boom")
            return real_parse(text)

        monkeypatch.setattr("rebrew.types.parse_structs", _parse)
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        assert (outdir / "structs" / "Point.toml").exists()
        assert not (outdir / "structs" / "Bad.toml").exists()


class TestBinsyncEnumsAndTypedefs:
    _FOO = SourceFixture(
        "/* ADDRESS: SERVER 0x10001000 */\n\n\nint foo() { return 1; }\n",
        {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 4}},
    )

    def test_enum_and_typedef_exported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:

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

        payload = cli_payload(result)
        assert payload["enums"] == 1
        assert payload["typedefs"] == 1
        assert str(payload["enums_file"]).endswith("enums.toml")
        assert str(payload["typedefs_file"]).endswith("typedefs.toml")

    def test_ambiguous_scoped_and_unknown_enums_are_omitted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": self._FOO,
                "a.h": "typedef enum { A = 1 } Conflicting;\n",
                "b.c": (
                    "typedef enum { B = 2 } Conflicting;\n"
                    "#ifdef OTHER_TARGET\nenum Conditional { C };\n#endif\n"
                    "void private(void) { enum Local { D }; }\n"
                    "typedef enum { KNOWN = 4, UNKNOWN = SOME_MACRO, NEXT } Unresolved;\n"
                ),
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        assert not (outdir / "enums.toml").exists()

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

        from rebrew.metadata.functions import update_field

        _make_project(
            tmp_path,
            {
                "foo.c": (
                    SourceFixture(
                        "/* ADDRESS: SERVER 0x10001000 */\n\nint foo(void) { return 1; }\n",
                        {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 16}},
                    )
                ),
                "data.c": SourceFixture(
                    "/* ADDRESS: SERVER 0x01008000 */\n\nchar g_x;\n",
                    {"SERVER.0x01008000": {"kind": "GLOBAL", "size": 4}},
                ),
                "types.h": (
                    "typedef struct { int x; } Point;\n"
                    "typedef enum { A, B } E;\n"
                    "typedef unsigned int uint32_t;\n"
                ),
            },
        )
        update_field(tmp_path, 0x10001000, "note", "a note", "SERVER")
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output

        func = Function.loads((outdir / "functions" / "10001000.toml").read_text())
        assert func.addr == 0x10001000
        assert func.name == "foo"
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
        from rebrew.metadata.functions import get_entry, update_field

        foo = SourceFixture(
            "/* ADDRESS: SERVER 0x10001000 */\n\n\nint foo(void){return 1;}\n",
            {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 16}},
        )
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
        result = runner.invoke(app, ["binsync", "export", str(state_a), "--json"])
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
        result = runner.invoke(app, ["binsync", "import", str(state_a), "--json"])
        assert result.exit_code == 0, result.output
        entry = get_entry(proj_b, 0x10001000, "SERVER")
        assert entry.get("locals") == {"-4": {"name": "ret", "type": "int", "size": 4}}
        assert entry.get("comments")

        state_b = tmp_path / "state_b"
        result = runner.invoke(app, ["binsync", "export", str(state_b), "--json"])
        assert result.exit_code == 0, result.output
        func_b = _load_func(state_b / "functions" / "10001000.toml")
        assert func_b.stack_vars[-4].name == "ret"


class TestMigratedPrototypes:
    """A marker-free source exports the prototype of its C definition."""

    def test_migrated_function_exports_its_signature(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            {
                "server.c": SourceFixture(
                    "typedef void *LPVOID;\n/* ADDRESS: SERVER 0x10001000 */\n\nint __cdecl Init(LPVOID param)\n{\n    return 0;\n}\n/* ADDRESS: SERVER 0x10001010 */\n\nstatic void __stdcall Pump(int a, int b)\n{\n}\n",
                    {
                        "SERVER.0x10001000": {"kind": "FUNCTION", "size": 16},
                        "SERVER.0x10001010": {"kind": "FUNCTION", "size": 16},
                    },
                ),
            },
        )
        monkeypatch.chdir(tmp_path)
        migrated = runner.invoke(app, ["source", "register"], catch_exceptions=False)
        assert migrated.exit_code == 0, migrated.output
        source = tmp_path / "src" / "server.c"
        text = source.read_text(encoding="utf-8")
        assert "// FUNCTION" not in text
        # Reformatted after migration: the signature now spans two lines.
        source.write_text(
            text.replace("Pump(int a, int b)", "Pump(int a,\n                           int b)"),
            encoding="utf-8",
        )

        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        init = _load_func(outdir / "functions" / "10001000.toml")
        assert init.header.type == "int __cdecl Init(LPVOID param)"
        pump = _load_func(outdir / "functions" / "10001010.toml")
        assert pump.header.type == "static void __stdcall Pump(int a, int b)"


class TestStructLayouts:
    """Exported struct members carry real names, types and offsets, never parser debris."""

    _FOO = SourceFixture(
        "/* ADDRESS: SERVER 0x10001000 */\n\nint foo() { return 1; }\n",
        {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 4}},
    )

    def test_tail_padding_is_exported_and_acknowledged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.binsync.serial import load_artifact
        from rebrew.binsync.state import incoming_type_records, type_sync_records
        from rebrew.config import load_config

        _make_project(tmp_path, {"foo.c": self._FOO})
        (tmp_path / "src" / "types.h").write_text(
            "typedef struct { int id; char tag; } Padded;\n"
            "#pragma pack(push, 1)\n"
            "typedef struct { int id; char tag; } Packed;\n#pragma pack(pop)\n",
            encoding="utf-8",
        )
        result, outdir = _invoke(tmp_path, monkeypatch, "--json")
        assert result.exit_code == 0, result.output
        padded = load_artifact(outdir / "structs" / "Padded.toml", "struct")
        packed = load_artifact(outdir / "structs" / "Packed.toml", "struct")
        assert padded is not None and padded.size == 8
        assert packed is not None and packed.size == 5
        cfg = load_config(tmp_path)
        local = type_sync_records(cfg)
        remote = incoming_type_records(outdir)
        assert local["struct.Padded"] == remote["struct.Padded"]
        assert local["struct.Packed"] == remote["struct.Packed"]

    def test_struct_name_survives_alias_expansion(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(tmp_path, {"foo.c": self._FOO})
        (tmp_path / "src" / "aliases.h").write_text(
            "typedef struct { int x; int y; } Canonical;\ntypedef Canonical Point;\n",
            encoding="utf-8",
        )
        (tmp_path / "src" / "point.h").write_text(
            "#pragma pack(push, 1)\n"
            "typedef struct { char tag; int value; } Point;\n"
            "typedef struct { Point point; char tail; } Holder;\n#pragma pack(pop)\n",
            encoding="utf-8",
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        assert self._members(outdir, "Point") == {0: ("tag", "char"), 1: ("value", "int")}
        assert self._members(outdir, "Holder") == {0: ("point", "Point"), 5: ("tail", "char")}

    def _members(self, outdir: Path, name: str) -> dict[int, tuple[str, str]]:
        from rebrew.binsync.serial import load_artifact

        struct = load_artifact(outdir / "structs" / f"{name}.toml", "struct")
        assert struct is not None, name
        return {off: (m.name, m.type) for off, m in struct.members.items()}

    def test_packing_context_survives_definition_extraction(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(tmp_path, {"foo.c": self._FOO})
        (tmp_path / "src" / "types.h").write_text(
            "#pragma pack(push, 1)\n"
            "typedef struct EntityQueryRecord {\n"
            "char type; int entity_id; char pad_05[0x20];\n"
            "unsigned short filter_25; unsigned short slot_index; char pad_29[0x80];\n"
            "} EntityQueryRecord;\n"
            "typedef struct { char kind; unsigned short ids[10]; } BuildingDefaults;\n"
            "typedef struct { char tag; int value; } Inner;\n"
            "#pragma pack(pop)\n"
            "typedef struct { char tag; Inner rows[2]; int tail; } Outer;\n"
            "typedef struct { char c; int x; } Natural;\n",
            encoding="utf-8",
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        assert self._members(outdir, "EntityQueryRecord") == {
            0: ("type", "char"),
            1: ("entity_id", "int"),
            5: ("pad_05", "char[0x20]"),
            0x25: ("filter_25", "unsigned short"),
            0x27: ("slot_index", "unsigned short"),
            0x29: ("pad_29", "char[0x80]"),
        }
        from rebrew.binsync.serial import load_artifact

        entity = load_artifact(outdir / "structs" / "EntityQueryRecord.toml", "struct")
        defaults = load_artifact(outdir / "structs" / "BuildingDefaults.toml", "struct")
        assert entity is not None and entity.size == 0xA9
        assert defaults is not None and defaults.size == 0x15
        outer = load_artifact(outdir / "structs" / "Outer.toml", "struct")
        assert outer is not None
        assert outer.members[1].size == 10
        assert self._members(outdir, "Outer") == {
            0: ("tag", "char"),
            1: ("rows", "Inner[2]"),
            12: ("tail", "int"),
        }
        assert self._members(outdir, "Natural") == {0: ("c", "char"), 4: ("x", "int")}

    def test_comments_typedefs_and_nested_members(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        _make_project(tmp_path, {"foo.c": self._FOO})
        (tmp_path / "src" / "types.h").write_text(
            "typedef unsigned long DWORD;\n"
            "typedef struct gz {\n"
            "    int  z_err;   /* error code for last stream operation */\n"
            "    DWORD crc;    /* crc32 of 'w' or 'r' data */\n"
            "    char  mode;   /* 'w' or 'r' */\n"
            "    struct { int adler; } check;\n"
            "    int  after;\n"
            "} gz;\n"
            "typedef struct VT {\n"
            "    int count;\n"
            "    long (__stdcall *Release)(struct VT *self, int flags);\n"
            "} VT;\n",
            encoding="utf-8",
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        assert not (outdir / "structs" / "gz.toml").exists()
        assert not (outdir / "structs" / "VT.toml").exists()
        assert not (outdir / "structs" / "check.toml").exists()
        assert "struct gz: layout stops after member mode" in caplog.text
        assert "struct VT: layout stops after member count" in caplog.text

    def test_differing_duplicate_definitions_are_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": self._FOO,
                "a.c": "typedef struct Ent { int id; } Ent;\n",
                "b.c": "typedef struct Ent { short id; short kind; } Ent;\n",
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        assert not (outdir / "structs" / "Ent.toml").exists()
        assert "1 struct name(s) have more than one differing definition" in caplog.text
        assert ": Ent" in caplog.text

    def test_same_definition_with_different_packing_is_ambiguous(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        definition = "typedef struct { char tag; int id; } Record;\n"
        _make_project(
            tmp_path,
            {
                "foo.c": self._FOO,
                "a.h": definition,
                "b.c": "#pragma pack(push, 1)\n" + definition,
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        assert not (outdir / "structs" / "Record.toml").exists()

    def test_private_typedef_context_does_not_change_another_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": self._FOO,
                "a.c": "typedef short Local; typedef struct { Local id; } Small;\n",
                "b.c": "typedef int Local; typedef struct { Local id; } Large;\n",
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        assert self._members(outdir, "Small") == {0: ("id", "short")}
        assert self._members(outdir, "Large") == {0: ("id", "int")}
        assert not any(
            t.name == "Local" for t in _load_artifacts(outdir / "typedefs.toml", "typedef")
        )

    def test_incomplete_local_preserves_remote_layout_and_baseline(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.binsync.state import load_sync_baseline
        from rebrew.config import load_config

        _make_project(
            tmp_path,
            {
                "foo.c": self._FOO,
                "types.h": "typedef struct { int id; int flags; } Record;\n",
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        cfg = load_config(tmp_path)
        before = load_sync_baseline(cfg, outdir)["struct.Record"]
        remote = outdir / "structs" / "Record.toml"
        original = remote.read_bytes()
        (tmp_path / "src" / "types.h").write_text(
            "typedef struct { int id; unsigned flags:1; } Record;\n"
        )
        result, _ = _invoke(tmp_path, monkeypatch, "--json")
        assert result.exit_code == 0, result.output
        assert any(
            "struct.Record" in warning and "preserving existing remote state" in warning
            for warning in cli_payload(result)["warnings"]
        )
        assert remote.read_bytes() == original
        assert load_sync_baseline(cfg, outdir)["struct.Record"] == before

    def test_conditional_and_block_types_are_not_global_types(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": self._FOO,
                "types.h": (
                    "#ifndef TYPES_H\n#define TYPES_H\n"
                    "typedef struct { int id; } Public;\n"
                    "#ifdef OTHER_TARGET\n"
                    "typedef struct { int id; } Conditional;\n"
                    "#endif\n#endif\n"
                ),
                "private.c": "void f(void) { typedef struct { int id; } Private; }\n",
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        assert self._members(outdir, "Public") == {0: ("id", "int")}
        assert not (outdir / "structs" / "Conditional.toml").exists()
        assert not (outdir / "structs" / "Private.toml").exists()

    def test_unknown_included_alias_is_not_borrowed_from_an_unrelated_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": self._FOO,
                "a.c": "typedef short Local;\n",
                "b.c": "typedef struct { Local id; } Record;\n",
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        assert not (outdir / "structs" / "Record.toml").exists()

    def test_multiple_field_declarators_are_not_exported_as_a_complete_prefix(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": self._FOO,
                "types.h": "typedef struct { int a, b; int tail; } Record;\n",
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        assert not (outdir / "structs" / "Record.toml").exists()

    def test_embedded_ambiguous_type_does_not_leave_an_unresolved_layout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": self._FOO,
                "a.h": (
                    "typedef struct { int id; } Private;\n"
                    "typedef struct { Private record; } Holder;\n"
                ),
                "b.c": "typedef struct { short id; } Private;\n",
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        assert not (outdir / "structs" / "Private.toml").exists()
        assert not (outdir / "structs" / "Holder.toml").exists()

    def test_alias_expansion_preserves_member_identifiers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.binsync.serial import load_artifact
        from rebrew.binsync.state import parse_struct_fields

        definition = "typedef struct DWORD { DWORD DWORD; char tag; } Record;\n"
        _make_project(
            tmp_path,
            {
                "foo.c": self._FOO,
                "types.h": "typedef unsigned long DWORD;\n" + definition,
            },
        )
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        assert self._members(outdir, "Record") == {
            0: ("DWORD", "unsigned long"),
            4: ("tag", "char"),
        }
        struct = load_artifact(outdir / "structs" / "Record.toml", "struct")
        assert struct is not None and struct.size == 8
        assert parse_struct_fields(definition, {"DWORD": "unsigned long"}) == [
            {"name": "DWORD", "type": "unsigned long", "offset": 0, "size": 4},
            {"name": "tag", "type": "char", "offset": 4, "size": 1},
        ]


class TestExportIdentityWarnings:
    def test_prose_name_and_duplicate_identity_are_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        _make_project(
            tmp_path,
            {
                "a.c": SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n\nint foo(void) { return 1; }\n",
                    {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 4}},
                ),
                "b.c": SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n\nint foo2(void) { return 2; }\n",
                    {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 4}},
                ),
                "lib.c": "/* identified by its archive bytes */\n",
            },
        )
        # A library row whose name is the header's prose, as an identification
        # tool recorded it.
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 3\n["SERVER.0x10002000"]\nfile = "lib.c"\nkind = "LIBRARY"\nname = "(static, no archive symbol)"\nsize = 4\n',
            encoding="utf-8",
        )
        result, outdir = _invoke(tmp_path, monkeypatch, "--json")
        assert result.exit_code == 0, result.output
        warnings = cli_payload(result)["warnings"]
        assert any("0x10001000 has two identities (a.c, b.c)" in w for w in warnings), warnings
        assert any("is not a C identifier; exported as func_10002000" in w for w in warnings)
        assert _load_func(outdir / "functions" / "10002000.toml").name == "func_10002000"


class TestMigratedPrototypeFallback:
    def test_definition_the_ast_misses_reads_from_its_line(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A definition tree-sitter buries in an error node (seen with some
        inline-asm bodies) still exports the signature its first line spells."""
        _make_project(
            tmp_path,
            {
                "server.c": SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n\nint __cdecl Init(void *param)\n{\n    return 0;\n}\n",
                    {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 16}},
                ),
            },
        )
        monkeypatch.chdir(tmp_path)
        migrated = runner.invoke(app, ["source", "register"], catch_exceptions=False)
        assert migrated.exit_code == 0, migrated.output
        monkeypatch.setattr("rebrew.c_parser.function_signatures", lambda _source: {})
        result, outdir = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        init = _load_func(outdir / "functions" / "10001000.toml")
        assert init.header.type == "int __cdecl Init(void *param)"
