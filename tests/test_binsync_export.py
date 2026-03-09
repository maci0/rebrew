"""Tests for binsync_export.py."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, cast

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


def _invoke(tmp_path: Path, *extra_args: str) -> Any:
    """Run `rebrew binsync-export <outdir> [extra_args]` from tmp_path."""
    outdir = tmp_path / "binsync_out"
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        result = runner.invoke(app, ["binsync-export", str(outdir), *extra_args])
    finally:
        os.chdir(cwd)
    return result, outdir


# ---------------------------------------------------------------------------
# Basic export (name, addr, size)
# ---------------------------------------------------------------------------


class TestBinsyncExportBasic:
    def test_name_and_addr(self, tmp_path: Path) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 31\nint foo() { return 1; }\n",
            },
        )
        result, outdir = _invoke(tmp_path)
        assert result.exit_code == 0, result.output
        toml_file = outdir / "functions" / "10001000.toml"
        assert toml_file.exists()
        doc = tomlkit.loads(toml_file.read_text())
        info = cast(dict[str, Any], doc["info"])
        assert info["addr"] == 0x10001000
        assert info["name"] == "_foo"
        assert info["size"] == 31

    def test_size_omitted_when_zero(self, tmp_path: Path) -> None:
        _make_project(
            tmp_path,
            {
                "bar.c": "// FUNCTION: SERVER 0x20002000\n// STATUS: MATCHING\ndouble bar() { return 2.0; }\n",
            },
        )
        result, outdir = _invoke(tmp_path)
        assert result.exit_code == 0
        doc = tomlkit.loads((outdir / "functions" / "20002000.toml").read_text())
        assert "size" not in cast(dict[str, Any], doc["info"])

    def test_fallback_name_when_no_symbol(self, tmp_path: Path) -> None:
        _make_project(
            tmp_path,
            {
                "stub.c": "// FUNCTION: SERVER 0x30003000\n// STATUS: STUB\nvoid stub(void);\n",
            },
        )
        result, outdir = _invoke(tmp_path)
        assert result.exit_code == 0
        doc = tomlkit.loads((outdir / "functions" / "30003000.toml").read_text())
        name = cast(dict[str, Any], doc["info"])["name"]
        # Stub with no body: falls back to symbol from declaration or func_ prefix
        assert name  # just ensure something is written


# ---------------------------------------------------------------------------
# Prototype → [header].type
# ---------------------------------------------------------------------------


class TestBinsyncExportPrototype:
    def test_prototype_written_to_header(self, tmp_path: Path) -> None:
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
        result, outdir = _invoke(tmp_path)
        assert result.exit_code == 0
        doc = tomlkit.loads((outdir / "functions" / "10001000.toml").read_text())
        assert "header" in doc
        # Body should be stripped from [header].type — only the signature
        header_type = cast(dict[str, Any], doc["header"])["type"]
        assert header_type == "int __cdecl Calc(int x, int y)"
        assert "{" not in header_type

    def test_header_strips_body_for_inline_definitions(self, tmp_path: Path) -> None:
        """Inline function definitions (no // PROTOTYPE: annotation) still get a
        stripped [header].type with no function body."""
        _make_project(
            tmp_path,
            {
                "f.c": "// FUNCTION: SERVER 0x10002000\n// STATUS: EXACT\n// SIZE: 5\nvoid f(void) {}\n"
            },
        )
        result, outdir = _invoke(tmp_path)
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
    def test_status_and_cflags_in_comment(self, tmp_path: Path) -> None:
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
        result, outdir = _invoke(tmp_path)
        assert result.exit_code == 0
        doc = tomlkit.loads((outdir / "functions" / "10010000.toml").read_text())
        assert "comments" in doc
        comments = cast(dict[str, Any], doc["comments"])
        assert str(0x10010000) in comments
        assert "STATUS=RELOC" in comments[str(0x10010000)]
        assert "CFLAGS=/O1 /Gd" in comments[str(0x10010000)]

    def test_note_written_at_va_plus_one(self, tmp_path: Path) -> None:
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
        result, outdir = _invoke(tmp_path)
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
    def test_global_vars_toml_written(self, tmp_path: Path) -> None:
        _make_project(
            tmp_path,
            {
                "func.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nvoid func(void) {}\n",
                "data.c": ("// GLOBAL: SERVER 0x01008000\n// SIZE: 64\nchar g_szBuffer[64];\n"),
            },
        )
        result, outdir = _invoke(tmp_path)
        assert result.exit_code == 0
        gv_path = outdir / "global_vars.toml"
        assert gv_path.exists()
        doc = tomlkit.loads(gv_path.read_text())
        assert str(0x01008000) in doc
        entry = cast(dict[str, Any], doc[str(0x01008000)])
        assert entry["addr"] == 0x01008000

    def test_no_global_vars_toml_when_no_globals(self, tmp_path: Path) -> None:
        _make_project(
            tmp_path,
            {
                "func.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nvoid func(void) {}\n"
            },
        )
        result, outdir = _invoke(tmp_path)
        assert result.exit_code == 0
        assert not (outdir / "global_vars.toml").exists()


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------


class TestBinsyncExportDryRun:
    def test_dry_run_writes_nothing(self, tmp_path: Path) -> None:
        _make_project(
            tmp_path,
            {
                "f.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nvoid f(void) {}\n"
            },
        )
        result, outdir = _invoke(tmp_path, "--dry-run")
        assert result.exit_code == 0
        # Nothing should exist on disk
        assert not outdir.exists()

    def test_dry_run_json_reports_counts(self, tmp_path: Path) -> None:
        _make_project(
            tmp_path,
            {
                "f.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nvoid f(void) {}\n"
            },
        )
        result, outdir = _invoke(tmp_path, "--dry-run", "--json")
        assert result.exit_code == 0
        import json

        data = json.loads(result.output)
        assert data["dry_run"] is True
        assert data["functions"] == 1
        assert not outdir.exists()


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


class TestBinsyncExportJson:
    def test_json_output_structure(self, tmp_path: Path) -> None:
        _make_project(
            tmp_path,
            {
                "f.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nvoid f(void) {}\n"
            },
        )
        result, outdir = _invoke(tmp_path, "--json")
        assert result.exit_code == 0
        import json

        data = json.loads(result.output)
        assert "functions" in data
        assert "globals" in data
        assert "structs" in data
        assert "function_files" in data
        assert data["functions"] == 1
        assert data["globals"] == 0
