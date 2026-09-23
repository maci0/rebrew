"""Tests for rebrew report — static HTML documentation site generation."""

import json
import struct
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent))  # tests/ on path for bin_util
from bin_util import make_pe

from rebrew.import_table import parse_import_table
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
    "// SIZE: 100\n"
    "// CFLAGS: /O2 /Gd\n"
    "int func_a(void) { return 0; }\n"
)

_FUNC_B = "// FUNCTION: SERVER 0x10002000\n// SIZE: 200\nint func_b(void) { return 1; }\n"

# STATUS lives in rebrew-functions.toml, not inline.
_METADATA_TOML = (
    '["SERVER.0x10001000"]\nstatus = "EXACT"\n["SERVER.0x10002000"]\nstatus = "NEAR_MATCHING"\n'
)


def _write_project(tmp_path: Path, pe_bytes: bytes | None = None) -> None:
    """Create a minimal rebrew project (toml + optional binary + annotated sources)."""
    (tmp_path / "rebrew-project.toml").write_text(_TOML, encoding="utf-8")
    if pe_bytes is not None:
        (tmp_path / "game.exe").write_bytes(pe_bytes)
    (tmp_path / "rebrew-functions.toml").write_text(_METADATA_TOML, encoding="utf-8")
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
        result = runner.invoke(app, ["--output", str(site)])
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
        assert "table-scroll" in index
        assert "flex-wrap" in index
        assert "aria-current='page'" in index
        assert "scope='col'" in index
        assert "Skip to content" in index
        assert "aria-label='Report pages'" in index
        assert "tabindex='-1'" in index  # skip-link focus target (WCAG 2.4.1)
        assert "#475569" in index  # STUB text meets WCAG AA contrast on white
        assert "#94a3b8" not in index
        assert "min-height: 2.75rem" in index  # nav link touch target (WCAG 2.5.8)
        assert "border: 1px solid #767676" in index  # WCAG 1.4.11 non-text contrast
        assert "#e2e8f0" not in index
        assert "#64748b" not in index  # no raw Tailwind slate chrome
        assert "text-transform: uppercase" not in index
        assert "prefers-reduced-motion" in index
        assert "forced-colors" in index
        assert "text-decoration: underline" in index  # nav links not color-only (1.4.1)
        assert "max-width: 40rem" in index  # narrow-viewport reflow (1.4.10)
        # Dark-header link colors must not reach the pager nav on the light
        # body: white hover text and a pale focus ring fail 1.4.3 / 1.4.11.
        assert "\nnav a" not in index
        assert "header nav a:hover { color: #fff; }" in index
        assert "header nav a:focus-visible { outline-color: #9dc4f5; }" in index
        graph = (site / "graph.html").read_text(encoding="utf-8")
        assert "<h2>Call graph</h2>" in graph
        assert "<h3>" not in graph
        imports_html = (site / "imports.html").read_text(encoding="utf-8")
        assert "<h2>Imports</h2>" in imports_html
        assert "<h3>" not in imports_html
        strings_html = (site / "strings.html").read_text(encoding="utf-8")
        assert "<h2>Strings</h2>" in strings_html

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
        result = runner.invoke(app, ["--output", str(site)])
        assert result.exit_code == 0, result.output
        index = (site / "index.html").read_text(encoding="utf-8")
        assert "Blocker" in index
        assert "NEAR_MATCHING — REGISTER" in index
        assert "mut_swap_register_keywords" in index

        graph = (site / "graph.html").read_text(encoding="utf-8")
        assert "graph LR" in graph  # mermaid block
        # Wide source must be keyboard-scrollable and named by its heading.
        assert "tabindex='0' role='region' aria-labelledby='mermaid-heading'" in graph
        assert "adjacency.txt" in graph  # sidecar link, not inlined
        adjacency = (site / "adjacency.txt").read_text(encoding="utf-8")
        assert "2 nodes" in adjacency  # plain-text adjacency fallback

    def test_default_out_dir_under_output_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without --output the site lands in <output_dir>/report."""
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
        result = runner.invoke(app, ["--json", "--output", str(site)])
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
        result = runner.invoke(app, ["--output", str(site)])
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
        result = runner.invoke(app, ["--output", str(site)])
        assert result.exit_code == 0, result.output

        imports_html = (site / "imports.html").read_text(encoding="utf-8")
        assert "MessageBoxA" in imports_html
        assert "KERNEL32.dll" in imports_html
        assert "Import stubs" in imports_html


class TestAdjacencyListLabels:
    def test_truncated_string_cells_expose_full_text(self) -> None:
        """Long strings and xref lists truncate into a keyboard-operable <details>,
        not a title tooltip that keyboard and touch users cannot open."""
        from types import SimpleNamespace

        from rebrew.report import _string_row

        long_text = "A" * 100
        xrefs = [SimpleNamespace(from_va=0x1000 + i) for i in range(7)]
        row = _string_row(
            SimpleNamespace(va=0x2000, section=".rdata", kind="ascii", text=long_text),
            xrefs,
        )
        assert "title=" not in row
        assert f"<details><summary>{'A' * 80}…</summary>{long_text}</details>" in row
        assert (
            "<details><summary>0x00001000, 0x00001001, 0x00001002, 0x00001003, 0x00001004"
            " (+2 more)</summary>0x00001000, 0x00001001, 0x00001002, 0x00001003, 0x00001004,"
            " 0x00001005, 0x00001006</details>" in row
        )

    def test_short_string_cells_stay_plain(self) -> None:
        from types import SimpleNamespace

        from rebrew.report import _string_row

        row = _string_row(
            SimpleNamespace(va=0x2000, section=".rdata", kind="ascii", text="a<b"),
            [],
        )
        assert "<details>" not in row
        assert "<td class='mono'>a&lt;b</td>" in row
        assert "<td class='mono'>&mdash;</td>" in row

    def test_failed_ref_scan_reads_na_not_zero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A failed xref scan must not render as '0 refs' (a faked healthy zero)."""
        from types import SimpleNamespace

        import rebrew.report as report_mod

        (tmp_path / "game.exe").write_bytes(b"MZ")
        monkeypatch.setattr(report_mod, "load_binary", lambda path: SimpleNamespace())
        monkeypatch.setattr(
            report_mod,
            "iter_strings",
            lambda info, min_len: [
                SimpleNamespace(va=0x2000, section=".rdata", kind="ascii", text="hello")
            ],
        )

        def _boom(info: object, strings: object) -> None:
            raise ValueError("bad section")

        monkeypatch.setattr(report_mod, "string_refs", _boom)
        cfg = SimpleNamespace(target_name="T", target_binary=tmp_path / "game.exe")
        ((_, page),) = report_mod._render_strings(cfg)
        assert "could not be scanned" in page
        assert "<td>n/a</td><td class='mono'>n/a</td>" in page
        assert "<td>0</td>" not in page

    def test_prints_symbols_not_internal_keys(self) -> None:
        """Node keys are `va:0x…`/`sym:…` internal identifiers; the adjacency
        fallback must print the symbol (mermaid/dot already do)."""
        from rebrew.report import _adjacency_list

        nodes = {
            "va:0x00001000": {"symbol": "func_a", "status": "EXACT", "va": 0x1000},
            "va:0x00002000": {"symbol": "func_b", "status": "STUB", "va": 0x2000},
        }
        edges = [("va:0x00001000", "va:0x00002000")]
        out = _adjacency_list(nodes, edges, [])
        assert "func_a [EXACT] 0x00001000 -> func_b" in out
        assert "va:0x00001000" not in out

    def test_ne_ranges_use_node_keys(self, monkeypatch) -> None:
        """The NE call-graph augmentation must key ranges like build_graph's
        nodes (`va:0x…`), not `fcn_…` (phantom nodes)."""
        from types import SimpleNamespace

        import rebrew.report as report_mod

        monkeypatch.setattr(
            "rebrew.ne_loader.enumerate_ne_functions",
            lambda info: [SimpleNamespace(va=0x1000, size=0x20)],
        )
        assert report_mod._ne_ranges(None) == [(0x1000, 0x1020, "va:0x00001000")]


class TestDecompDevUnitNames:
    def test_same_basename_files_get_distinct_unit_names(self, tmp_path: Path) -> None:
        """`rel_display_path(path)` with no base gave bare basenames, so two
        `pool.c` under different directories collided in report.json."""
        from types import SimpleNamespace

        from rebrew.report import generate_decomp_dev_report

        src = tmp_path / "src"
        (src / "engine").mkdir(parents=True)
        (src / "ui").mkdir()
        (src / "engine" / "pool.c").write_text(
            "// FUNCTION: SERVER 0x1000\n// SIZE: 8\nint pool_init(void) { return 0; }\n",
            encoding="utf-8",
        )
        (src / "ui" / "pool.c").write_text(
            "// FUNCTION: SERVER 0x2000\n// SIZE: 8\nint pool_draw(void) { return 0; }\n",
            encoding="utf-8",
        )
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            metadata_dir=tmp_path,
            marker="SERVER",
            target_name="T",
            target_binary=tmp_path / "x.dll",
            source_ext=".c",
            arch="x86_32",
        )
        out = tmp_path / "report.json"
        generate_decomp_dev_report(cfg, out)
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert sorted(u["name"] for u in doc["units"]) == ["engine/pool.c", "ui/pool.c"]


class TestLibraryHeaderRows:
    def test_library_header_entries_appear_in_the_table(self, tmp_path: Path) -> None:
        """`identify-library` writes library_*.h entries that the summary cards
        count (collect_status scans the headers), but the function table only
        scanned iter_sources, so they were missing from it."""
        from types import SimpleNamespace

        from rebrew.report import _collect_functions

        src = tmp_path / "src"
        src.mkdir()
        (src / "game.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint a(void) { return 0; }\n", encoding="utf-8"
        )
        (src / "library_msvcrt.h").write_text(
            "// LIBRARY: SERVER 0x2000\n// _malloc\n// SIZE: 64\n", encoding="utf-8"
        )
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            metadata_dir=tmp_path,
            marker="SERVER",
            target_name="T",
            source_ext=".c",
            arch="x86_32",
        )
        rows = _collect_functions(cfg)
        lib_rows = [r for r in rows if r["va"] == 0x2000]
        assert len(lib_rows) == 1
        assert "malloc" in lib_rows[0]["name"]
        assert lib_rows[0]["file"] == "library_msvcrt.h"

    def test_library_header_entries_are_graph_nodes(self, tmp_path: Path) -> None:
        """The call graph must show library-header functions too (the summary
        and the table do); graph.html previously omitted them entirely."""
        from types import SimpleNamespace

        from rebrew.depgraph import build_graph

        src = tmp_path / "src"
        src.mkdir()
        (src / "game.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint a(void) { return 0; }\n", encoding="utf-8"
        )
        (src / "library_msvcrt.h").write_text(
            "// LIBRARY: SERVER 0x2000\n// _malloc\n// SIZE: 64\n", encoding="utf-8"
        )
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            metadata_dir=tmp_path,
            marker="SERVER",
            target_name="T",
            source_ext=".c",
            arch="x86_32",
        )
        nodes, _edges, _dispatch = build_graph(src, cfg=cfg)
        assert "va:0x00002000" in nodes
        assert nodes["va:0x00002000"]["file"] == "library_msvcrt.h"


class TestReportPayloadShape:
    def test_writes_precompressed_gzip_sidecars(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Static pages ship .gz/.zst sidecars so servers can skip per-request compression."""
        import gzip

        import zstandard

        _write_project(tmp_path, pe_bytes=make_pe(b"\x90" * 32))
        monkeypatch.chdir(tmp_path)
        site = tmp_path / "site"
        result = runner.invoke(app, ["--output", str(site)])
        assert result.exit_code == 0, result.output
        for name in ("index.html", "strings.html", "imports.html", "graph.html"):
            plain = site / name
            gz_path = Path(str(plain) + ".gz")
            zst_path = Path(str(plain) + ".zst")
            assert gz_path.is_file(), name
            assert zst_path.is_file(), name
            raw = plain.read_bytes()
            gzipped = gz_path.read_bytes()
            zstd = zst_path.read_bytes()
            assert len(gzipped) < len(raw)
            assert len(zstd) < len(raw)
            assert gzip.decompress(gzipped) == raw
            assert zstandard.ZstdDecompressor().decompress(zstd) == raw

    def test_large_function_table_paginates(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Index pages beyond _TABLE_PAGE_SIZE spill to index-pN.html for first paint."""
        from rebrew.config import load_config
        from rebrew.report import _TABLE_PAGE_SIZE, generate_report

        _write_project(tmp_path, pe_bytes=make_pe(b"\x90" * 32))
        src = tmp_path / "src"
        meta_lines = [
            '["SERVER.0x10001000"]\nstatus = "EXACT"\n',
            '["SERVER.0x10002000"]\nstatus = "NEAR_MATCHING"\n',
        ]
        # Enough extras that page 1 is full and page 2 exists.
        for i in range(_TABLE_PAGE_SIZE):
            va = 0x10003000 + i * 0x10
            (src / f"extra_{i:04d}.c").write_text(
                f"// FUNCTION: SERVER 0x{va:08x}\n// SIZE: 16\nint extra_{i}(void) {{ return 0; }}\n",
                encoding="utf-8",
            )
            meta_lines.append(f'["SERVER.0x{va:08x}"]\nstatus = "STUB"\n')
        (tmp_path / "rebrew-functions.toml").write_text("".join(meta_lines), encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        site = tmp_path / "site"
        cfg = load_config(tmp_path)
        result = generate_report(cfg, site)
        assert (site / "index.html").is_file()
        assert (site / "index-p2.html").is_file()
        index = (site / "index.html").read_text(encoding="utf-8")
        page2 = (site / "index-p2.html").read_text(encoding="utf-8")
        assert "Showing 1–" in index or "Showing 1\u2013" in index
        assert "Next" in index
        assert "Previous" in page2
        assert "<nav class='pager' aria-label='Table pages'>" in index
        assert "aria-label='Next page of functions'" in index
        assert "aria-label='Previous page of functions'" in page2
        assert "index-p2.html" in result["pages"]
        # Page 1 must not embed every row (first-paint budget).
        assert index.count("<tr>") < _TABLE_PAGE_SIZE + 5
        assert "extra_0" in index
        assert "extra_249" in page2
        # The pager repeats below the table so a reader at the bottom can move on.
        assert index.count("aria-label='Next page of functions'") == 2
        assert "aria-label='Table pages, bottom'" in index

    def test_pager_offers_first_and_last_on_middle_pages(self) -> None:
        from rebrew.report import _TABLE_PAGE_SIZE, _pager_nav

        total = _TABLE_PAGE_SIZE * 5
        middle = _pager_nav("index", 3, 5, total, "functions")
        assert "<a href='index.html' aria-label='First page of functions'>First</a>" in middle
        assert "<a href='index-p5.html' aria-label='Last page of functions'>Last</a>" in middle
        # Adjacent to an end, First/Last would duplicate Previous/Next.
        second = _pager_nav("index", 2, 5, total, "functions")
        assert "First</a>" not in second
        assert "Last</a>" in second
        last = _pager_nav("index", 5, 5, total, "functions")
        assert "Last</a>" not in last
        assert "Next</a>" not in last
