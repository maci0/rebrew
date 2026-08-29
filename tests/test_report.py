"""Tests for rebrew report — static HTML documentation site generation."""

import json
import struct
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent))  # tests/ on path for bin_util
from bin_util import make_pe

from rebrew.imports import parse_import_table
from rebrew.report import app

runner = CliRunner()

_TOML = """\
[project]
default_target = "server"
output_dir = "output"

[targets.server]
binary = "game.exe"
reversed_dir = "src"
marker = "SERVER"
"""

_FUNC_A = (
    "// FUNCTION: SERVER 0x10001000\n"
    "// STATUS: EXACT\n"
    "// SIZE: 100\n"
    "// CFLAGS: /O2 /Gd\n"
    "int func_a(void) { return 0; }\n"
)

_FUNC_B = (
    "// FUNCTION: SERVER 0x10002000\n"
    "// STATUS: NEAR_MATCHING\n"
    "// SIZE: 200\n"
    "int func_b(void) { return 1; }\n"
)


def _write_project(tmp_path: Path, pe_bytes: bytes | None = None) -> None:
    """Create a minimal rebrew project (toml + optional binary + annotated sources)."""
    (tmp_path / "rebrew-project.toml").write_text(_TOML, encoding="utf-8")
    if pe_bytes is not None:
        (tmp_path / "game.exe").write_bytes(pe_bytes)
    src = tmp_path / "src"
    src.mkdir()
    (src / "func_a.c").write_text(_FUNC_A, encoding="utf-8")
    (src / "func_b.c").write_text(_FUNC_B, encoding="utf-8")


class TestReportCli:
    def test_generates_all_four_pages(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """All four pages exist and index.html carries the project's functions."""
        _write_project(tmp_path, pe_bytes=make_pe(b"\x90" * 32))
        monkeypatch.chdir(tmp_path)
        site = tmp_path / "site"
        result = runner.invoke(app, ["--out", str(site)])
        assert result.exit_code == 0, result.output

        # The out directory is created and contains all four pages.
        assert site.is_dir()
        for page in ("index.html", "strings.html", "imports.html", "graph.html"):
            assert (site / page).is_file()

        index = (site / "index.html").read_text(encoding="utf-8")
        assert "server" in index  # target name in the header
        assert "func_a" in index
        assert "func_b" in index
        assert "EXACT" in index
        assert "NEAR_MATCHING" in index
        assert "0x10001000" in index
        assert "CFLAGS" in index
        assert "/O2 /Gd" in index

    def test_index_shows_blockers(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The function table's Blocker column surfaces near-diag blockers."""
        _write_project(tmp_path, pe_bytes=make_pe(b"\x90" * 32))
        # Metadata at the project root (the default metadata_dir).
        (tmp_path / "rebrew-functions.toml").write_text(
            '["SERVER.0x10002000"]\n'
            'blocker = "NEAR_MATCHING — REGISTER (57% of delta) — try: mut_swap_register_keywords"\n',
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)
        site = tmp_path / "site"
        result = runner.invoke(app, ["--out", str(site)])
        assert result.exit_code == 0, result.output
        index = (site / "index.html").read_text(encoding="utf-8")
        assert "Blocker" in index
        assert "NEAR_MATCHING — REGISTER" in index
        assert "mut_swap_register_keywords" in index

        graph = (site / "graph.html").read_text(encoding="utf-8")
        assert "graph LR" in graph  # mermaid block
        assert "2 nodes" in graph  # plain-text adjacency fallback

    def test_default_out_dir_under_output_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without --out the site lands in <output_dir>/report."""
        _write_project(tmp_path, pe_bytes=make_pe(b"\x90" * 32))
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, [])
        assert result.exit_code == 0, result.output
        assert (tmp_path / "output" / "report" / "index.html").is_file()

    def test_cli_invocation_with_temp_cwd(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CliRunner invocation from a temp cwd prints the out dir and page list."""
        _write_project(tmp_path, pe_bytes=make_pe(b"\x90" * 32))
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, [])
        assert result.exit_code == 0, result.output
        assert "Report written to" in result.output
        assert "index.html" in result.output
        assert "graph.html" in result.output

    def test_json_output_shape(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """--json prints {out, pages, summary} with totals from the status report."""
        _write_project(tmp_path, pe_bytes=make_pe(b"\x90" * 32))
        monkeypatch.chdir(tmp_path)
        site = tmp_path / "site"
        result = runner.invoke(app, ["--json", "--out", str(site)])
        assert result.exit_code == 0, result.output

        payload = json.loads(result.stdout)
        assert payload["out"] == str(site)
        assert payload["pages"] == ["index.html", "strings.html", "imports.html", "graph.html"]
        summary = payload["summary"]
        assert summary["total_functions"] == 2
        assert summary["covered_functions"] == 2
        assert summary["coverage_pct"] == 100.0
        assert summary["matched_pct"] == 50.0
        assert summary["status_counts"] == {"EXACT": 1, "NEAR_MATCHING": 1}

    def test_no_data_sections_degrades_gracefully(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A binary with only .text yields empty strings/imports pages, not a crash."""
        _write_project(tmp_path, pe_bytes=make_pe(b"\x90" * 32))  # .text only, no data sections
        monkeypatch.chdir(tmp_path)
        site = tmp_path / "site"
        result = runner.invoke(app, ["--out", str(site)])
        assert result.exit_code == 0, result.output

        strings_html = (site / "strings.html").read_text(encoding="utf-8")
        assert "no data sections" in strings_html.lower()
        imports_html = (site / "imports.html").read_text(encoding="utf-8")
        assert "No import table" in imports_html
        # The other pages are still written.
        assert (site / "index.html").is_file()
        assert (site / "graph.html").is_file()

    def test_imports_page_lists_apis(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A PE with an import table and jmp [IAT] stub shows both on imports.html."""
        imports = [("KERNEL32.dll", ["MessageBoxA"])]
        # LIEF's iat_address is not byte-exact with the hand-rolled layout, so
        # the IAT slot VA is learned from a probe build with identical length.
        probe = tmp_path / "probe.exe"
        probe.write_bytes(make_pe(b"\x90" * 8, imports=imports))
        table = parse_import_table(probe)
        iat_va = min(table)
        stub = b"\xff\x25" + struct.pack("<I", iat_va) + b"\x90\x90"
        _write_project(tmp_path, pe_bytes=make_pe(stub, imports=imports))
        monkeypatch.chdir(tmp_path)
        site = tmp_path / "site"
        result = runner.invoke(app, ["--out", str(site)])
        assert result.exit_code == 0, result.output

        imports_html = (site / "imports.html").read_text(encoding="utf-8")
        assert "MessageBoxA" in imports_html
        assert "KERNEL32.dll" in imports_html
        assert "Import stubs" in imports_html
