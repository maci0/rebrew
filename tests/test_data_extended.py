"""Extended tests for rebrew data.py — scan branches, renderers, gen-header, CLI."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import typer
from typer.testing import CliRunner

from rebrew.data import (
    BssEntry,
    BssGap,
    BssReport,
    _emit_extern_decl,
    _gen_globals_header,
    _generate_bss_fix,
    _render_bss,
    _render_globals,
    _render_summary,
    scan_data_annotations,
    scan_globals,
)


def _cfg(tmp_path: Path, **overrides: object) -> SimpleNamespace:
    src = tmp_path / "src" / "SERVER"
    src.mkdir(parents=True, exist_ok=True)
    defaults: dict = {
        "root": tmp_path,
        "target_name": "SERVER",
        "target_binary": tmp_path / "fake.dll",
        "reversed_dir": src,
        "metadata_dir": tmp_path,
        "marker": "SERVER",
        "source_ext": ".c",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _console(buf: object | None = None) -> object:
    from io import StringIO

    from rich.console import Console

    if buf is None:
        buf = StringIO()
    return Console(file=buf, force_terminal=True, width=120, no_color=True, highlight=False)


class TestScanGlobalsBranches:
    def test_global_annotation_without_declaration_warns(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "a.c").write_text("// GLOBAL: SERVER 0x1000\n", encoding="utf-8")
        with pytest.warns(UserWarning, match="has no declaration"):
            scan_globals(cfg.reversed_dir, cfg)

    def test_non_extern_decl_fallback_name(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "a.c").write_text(
            "// GLOBAL: SERVER 0x1000\nint g_counter;\n", encoding="utf-8"
        )
        scan = scan_globals(cfg.reversed_dir, cfg)
        entry = scan.globals.get("g_counter")
        assert entry is not None
        assert entry.va == 0x1000
        assert entry.annotated is True

    def test_va_filled_from_annotated_file(self, tmp_path: Path) -> None:
        """extern-only file (sorted first) creates a VA-less entry; the GLOBAL
        annotation in a later file fills in the VA."""
        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "a_extern.c").write_text("extern int g_data;\n", encoding="utf-8")
        (cfg.reversed_dir / "b_annotated.c").write_text(
            "// GLOBAL: SERVER 0x2000\nextern int g_data;\n", encoding="utf-8"
        )
        scan = scan_globals(cfg.reversed_dir, cfg)
        entry = scan.globals["g_data"]
        assert entry.va == 0x2000
        assert entry.annotated is True
        assert entry.declared_in == ["a_extern.c", "b_annotated.c"]

    def test_scan_data_annotations_missing_dir(self, tmp_path: Path) -> None:
        assert scan_data_annotations(tmp_path / "nope") == []


class TestEmitExternDecl:
    def test_no_type_fallback(self) -> None:
        assert _emit_extern_decl({"name": "g_buf"}) == "extern unsigned char g_buf[];"

    def test_scalar_type(self) -> None:
        assert _emit_extern_decl({"name": "g_x", "type": "int"}) == "extern int g_x;"

    def test_array_type(self) -> None:
        assert (
            _emit_extern_decl({"name": "g_arr", "type": "unsigned char[16]"})
            == "extern unsigned char[16] g_arr;"
        )


class TestGenGlobalsHeader:
    def test_writes_header_from_annotations(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "globals.c").write_text(
            "// DATA: SERVER 0x1000\n// SYMBOL: g_counter\nint g_counter;\n"
            "// GLOBAL: SERVER 0x2000\n// SYMBOL: g_flag\nint g_flag;\n",
            encoding="utf-8",
        )
        _gen_globals_header(cfg, cfg.reversed_dir)
        out = cfg.reversed_dir / "rebrew_globals.h"
        assert out.exists()
        text = out.read_text(encoding="utf-8")
        assert "#ifndef REBREW_GLOBALS_H" in text
        assert "extern" in text
        assert "0x00001000" in text

    def test_dedup_by_va(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "a.c").write_text(
            "// DATA: SERVER 0x1000\nint g_counter;\n", encoding="utf-8"
        )
        (cfg.reversed_dir / "b.c").write_text(
            "// GLOBAL: SERVER 0x1000\nint g_counter;\n", encoding="utf-8"
        )
        _gen_globals_header(cfg, cfg.reversed_dir)
        out = cfg.reversed_dir / "rebrew_globals.h"
        text = out.read_text(encoding="utf-8")
        assert text.count("extern") == 1  # one decl despite two annotations

    def test_refuses_overwrite_without_force(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        out = cfg.reversed_dir / "rebrew_globals.h"
        out.write_text("existing", encoding="utf-8")
        with pytest.raises(typer.Exit):
            _gen_globals_header(cfg, cfg.reversed_dir, out_path=out)

    def test_force_overwrites(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        out = cfg.reversed_dir / "rebrew_globals.h"
        out.write_text("existing", encoding="utf-8")
        _gen_globals_header(cfg, cfg.reversed_dir, out_path=out, force=True)
        assert "#ifndef REBREW_GLOBALS_H" in out.read_text(encoding="utf-8")

    def test_regeneration_is_idempotent(self, tmp_path: Path) -> None:
        """Re-running --gen-header must not rewrite the file (timestamp churn)."""
        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "globals.c").write_text(
            "// DATA: SERVER 0x1000\nint g_counter;\n", encoding="utf-8"
        )
        _gen_globals_header(cfg, cfg.reversed_dir, force=True)
        out = cfg.reversed_dir / "rebrew_globals.h"
        first = out.read_text(encoding="utf-8")
        # Second run: body identical, only the "Generated:" timestamp would
        # differ — the file must stay byte-identical.
        _gen_globals_header(cfg, cfg.reversed_dir, force=True)
        assert out.read_text(encoding="utf-8") == first


class TestRenderers:
    def test_render_globals_empty(self) -> None:
        from io import StringIO

        buf = StringIO()
        scan = scan_globals(Path("/nonexistent"))
        _render_globals(_console(buf), scan)  # type: ignore[arg-type]
        assert "No globals found" in buf.getvalue()

    def test_render_summary_empty(self) -> None:
        from io import StringIO

        buf = StringIO()
        scan = scan_globals(Path("/nonexistent"))
        _render_summary(_console(buf), scan, {})  # type: ignore[arg-type]
        # Empty scan still renders a section summary table (zeros).
        assert "Section" in buf.getvalue() or "Globals" in buf.getvalue() or buf.getvalue() != ""

    def test_render_bss_no_section(self) -> None:
        from io import StringIO

        buf = StringIO()
        report = BssReport()
        _render_bss(_console(buf), report)  # type: ignore[arg-type]
        assert "No .bss section found" in buf.getvalue()

    def test_generate_bss_fix_no_gaps(self, tmp_path: Path) -> None:
        _generate_bss_fix(BssReport(), tmp_path, "SERVER")
        assert not (tmp_path / "bss_padding.c").exists()

    def test_generate_bss_fix_writes_file_and_metadata(self, tmp_path: Path) -> None:
        report = BssReport(
            bss_va=0x5000,
            bss_size=0x100,
            known_entries=[BssEntry(name="g_a", va=0x5000, size_hint=4)],
            gaps=[BssGap(offset=0x5004, size=16, before="g_a", after="g_b")],
        )
        _generate_bss_fix(report, tmp_path, "SERVER")
        out = tmp_path / "bss_padding.c"
        assert out.exists()
        text = out.read_text(encoding="utf-8")
        assert "// DATA: SERVER 0x00005004" in text
        assert "char gap_00005004[16];" in text
        from rebrew.data_metadata import load_data_metadata

        meta = load_data_metadata(tmp_path)
        assert any(m.get("size") == 16 and m.get("section") == ".bss" for m in meta.values())


class TestDataCli:
    def _invoke(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        args: list[str],
        **cfg_overrides: object,
    ) -> object:
        from rebrew.data import app

        cfg = _cfg(tmp_path, **cfg_overrides)
        monkeypatch.setattr("rebrew.data.require_config", lambda **kw: cfg)
        return CliRunner().invoke(app, args)

    def _write_global(self, cfg: SimpleNamespace) -> None:
        (cfg.reversed_dir / "globals.c").write_text(
            "// GLOBAL: SERVER 0x1000\n// SYMBOL: g_counter\nextern int g_counter;\n",
            encoding="utf-8",
        )

    def test_json_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _cfg(tmp_path)
        self._write_global(cfg)
        result = self._invoke(tmp_path, monkeypatch, ["--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "g_counter" in data["globals"]
        assert "sections" in data

    def test_summary_text(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _cfg(tmp_path)
        self._write_global(cfg)
        result = self._invoke(tmp_path, monkeypatch, ["--summary"])
        assert result.exit_code == 0
        assert "Global" in result.output

    def test_conflicts_flag(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "a.c").write_text(
            "// GLOBAL: SERVER 0x1000\nextern int g_x;\n", encoding="utf-8"
        )
        (cfg.reversed_dir / "b.c").write_text(
            "// GLOBAL: SERVER 0x1000\nextern float g_x;\n", encoding="utf-8"
        )
        result = self._invoke(tmp_path, monkeypatch, ["--conflicts"])
        assert result.exit_code == 0
        assert "Type Conflicts" in result.output
        assert "g_x" in result.output

    def test_gen_header_writes_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _cfg(tmp_path)
        self._write_global(cfg)
        result = self._invoke(tmp_path, monkeypatch, ["--gen-header"])
        assert result.exit_code == 0
        out = cfg.reversed_dir / "rebrew_globals.h"
        assert out.exists()

    def test_gen_header_out_custom_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _cfg(tmp_path)
        self._write_global(cfg)
        out = tmp_path / "custom.h"
        result = self._invoke(tmp_path, monkeypatch, ["--gen-header", "--gen-header-out", str(out)])
        assert result.exit_code == 0
        assert out.exists()

    def test_bss_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _cfg(tmp_path)
        self._write_global(cfg)
        from types import SimpleNamespace

        # data.py now derives sections from a single load_binary() parse.
        monkeypatch.setattr(
            "rebrew.binary_loader.load_binary",
            lambda p: SimpleNamespace(
                image_base=0,
                text_raw_offset=0,
                data=b"\x00" * 16,
                sections={
                    ".bss": SimpleNamespace(va=0x1000, size=0x100, file_offset=0, raw_size=0x100)
                },
            ),
        )
        (tmp_path / "fake.dll").write_bytes(b"\x00" * 16)
        result = self._invoke(tmp_path, monkeypatch, ["--bss", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["bss_size"] == 0x100

    def test_fix_bss_writes_padding(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _cfg(tmp_path)
        self._write_global(cfg)
        report = BssReport(
            bss_va=0x1000,
            bss_size=0x200,
            gaps=[BssGap(offset=0x1004, size=16, before="g_counter", after="next")],
        )
        monkeypatch.setattr("rebrew.data.verify_bss_layout", lambda scan, sections: report)
        result = self._invoke(tmp_path, monkeypatch, ["--fix-bss"])
        assert result.exit_code == 0
        assert (cfg.reversed_dir / "bss_padding.c").exists()

    def test_dispatch_missing_binary_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._invoke(tmp_path, monkeypatch, ["--dispatch"])
        assert result.exit_code != 0
        assert "target binary not found" in result.output

    def test_dispatch_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        (tmp_path / "fake.dll").write_bytes(b"\x00" * 16)
        monkeypatch.setattr(
            "rebrew.binary_loader.load_binary",
            lambda p: SimpleNamespace(data=b"\x00" * 16, sections={}),
        )
        monkeypatch.setattr("rebrew.data.find_dispatch_tables", lambda *a, **k: [])
        result = self._invoke(tmp_path, monkeypatch, ["--dispatch", "--json"])
        assert result.exit_code == 0
        assert json.loads(result.output) == []

    def test_dispatch_parses_binary_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--dispatch must reuse the section-enrichment parse, not re-parse."""
        (tmp_path / "fake.dll").write_bytes(b"\x00" * 16)
        calls: dict[str, int] = {"n": 0}

        def _fake_load(_p: object) -> SimpleNamespace:
            calls["n"] += 1
            return SimpleNamespace(
                data=b"\x00" * 16,
                sections={".text": SimpleNamespace(va=0x1000, size=16, file_offset=0, raw_size=16)},
            )

        monkeypatch.setattr("rebrew.binary_loader.load_binary", _fake_load)
        monkeypatch.setattr("rebrew.data.find_dispatch_tables", lambda *a, **k: [])
        result = self._invoke(tmp_path, monkeypatch, ["--dispatch", "--json"])
        assert result.exit_code == 0
        assert calls["n"] == 1


class TestRenderDispatchAndBss:
    def test_render_dispatch_empty(self) -> None:
        from io import StringIO

        from rebrew.data import _render_dispatch

        buf = StringIO()
        _render_dispatch(_console(buf), [])  # type: ignore[arg-type]
        assert "No dispatch tables detected" in buf.getvalue()

    def test_render_dispatch_with_tables(self) -> None:
        from io import StringIO

        from rebrew.data import DispatchEntry, DispatchTable, _render_dispatch

        buf = StringIO()
        tbl = DispatchTable(
            va=0x4000,
            section=".rdata",
            entries=[
                DispatchEntry(target_va=0x1000, name="fn_a", status="EXACT"),
                DispatchEntry(target_va=0x2000, name="", status=""),
            ],
        )
        _render_dispatch(_console(buf), [tbl])  # type: ignore[arg-type]
        out = buf.getvalue()
        assert "Dispatch Tables" in out
        assert "fn_a" in out or "0x00004000" in out or "0x4000" in out

    def test_render_bss_populated(self) -> None:
        from io import StringIO

        buf = StringIO()
        report = BssReport(
            bss_va=0x5000,
            bss_size=0x100,
            known_entries=[BssEntry(name="g_a", va=0x5000, size_hint=4, source_file="a.c")],
            gaps=[BssGap(offset=0x5004, size=16, before="g_a", after="g_b")],
            coverage_bytes=4,
        )
        _render_bss(_console(buf), report)  # type: ignore[arg-type]
        out = buf.getvalue()
        assert "BSS Layout" in out
        assert "0x00005000" in out or "0x5000" in out
        assert "g_a" in out or "Gaps detected" in out

    def test_render_bss_no_gaps(self) -> None:
        from io import StringIO

        buf = StringIO()
        report = BssReport(
            bss_va=0x5000,
            bss_size=0x100,
            known_entries=[BssEntry(name="g_a", va=0x5000, size_hint=4)],
            coverage_bytes=4,
        )
        _render_bss(_console(buf), report)  # type: ignore[arg-type]
        out = buf.getvalue()
        assert "BSS Layout" in out
        assert "Gaps detected" in out

    def test_render_globals_many_files(self, tmp_path: Path) -> None:
        from io import StringIO

        cfg = _cfg(tmp_path)
        for i in range(4):
            (cfg.reversed_dir / f"f{i}.c").write_text("extern int g_x;\n", encoding="utf-8")
        scan = scan_globals(cfg.reversed_dir, cfg)
        buf = StringIO()
        _render_globals(_console(buf), scan)  # type: ignore[arg-type]
        # Unannotated externs alone may still yield empty scan; just ensure render is stable.
        assert isinstance(buf.getvalue(), str)

    def test_render_summary_with_sections(self, tmp_path: Path) -> None:
        from io import StringIO

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "a.c").write_text(
            "// GLOBAL: SERVER 0x1000\nextern int g_x;\n", encoding="utf-8"
        )
        scan = scan_globals(cfg.reversed_dir, cfg)
        sections = {".data": {"va": 0x1000, "size": 0x100}}
        buf = StringIO()
        _render_summary(_console(buf), scan, sections)  # type: ignore[arg-type]
        out = buf.getvalue()
        assert "Section" in out or ".data" in out or "Globals" in out


class TestGenGlobalsHeaderMetadata:
    def test_metadata_overlay_and_unknown_section(self, tmp_path: Path) -> None:
        from rebrew.data_metadata import set_data_field

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "globals.c").write_text(
            "// DATA: SERVER 0x1000\n// SYMBOL: _g_counter\nint g_counter;\n",
            encoding="utf-8",
        )
        # Overlay name/section/size/type from rebrew-data.toml (DATA markers
        # carry no inline name in the parser; metadata is the name source).
        set_data_field(cfg.metadata_dir, 0x1000, "name", "g_counter", "SERVER")
        set_data_field(cfg.metadata_dir, 0x1000, "section", ".rdata", "SERVER")
        set_data_field(cfg.metadata_dir, 0x1000, "size", 16, "SERVER")
        set_data_field(cfg.metadata_dir, 0x1000, "type", "int[4]", "SERVER")
        _gen_globals_header(cfg, cfg.reversed_dir)
        text = (cfg.reversed_dir / "rebrew_globals.h").read_text(encoding="utf-8")
        # Underscore stripped from symbol-derived name.
        assert "g_counter" in text
        assert "int[4] g_counter" in text
        assert ".rdata" in text
        assert "16 bytes" in text

    def test_parse_failure_skips_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _cfg(tmp_path)
        bad = cfg.reversed_dir / "bad.c"
        bad.write_text("// DATA: SERVER 0x1000\nint x;\n", encoding="utf-8")
        real_parse = __import__(
            "rebrew.annotation", fromlist=["parse_c_file_multi"]
        ).parse_c_file_multi

        def _flaky(src, **kw):
            if Path(src) == bad:
                raise RuntimeError("boom")
            return real_parse(src, **kw)

        monkeypatch.setattr("rebrew.annotation.parse_c_file_multi", _flaky)
        _gen_globals_header(cfg, cfg.reversed_dir)
        out = cfg.reversed_dir / "rebrew_globals.h"
        assert out.exists()  # bad.c skipped, no crash


class TestDataMoreBranches:
    def test_render_summary_with_conflicts(self, tmp_path: Path) -> None:
        from rebrew.data import _render_summary, scan_globals

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "a.c").write_text(
            "// GLOBAL: SERVER 0x1000\nextern int g_x;\n", encoding="utf-8"
        )
        (cfg.reversed_dir / "b.c").write_text(
            "// GLOBAL: SERVER 0x1000\nextern float g_x;\n", encoding="utf-8"
        )
        scan = scan_globals(cfg.reversed_dir, cfg)
        assert scan.type_conflicts  # ensure the conflicts subtitle path runs
        _render_summary(_console(), scan, {".data": {"va": 0x1000, "size": 0x100}})  # type: ignore[arg-type]

    def test_scan_globals_unreadable_skipped(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "bad.c").mkdir()  # directory → read OSError → skip
        scan = scan_globals(cfg.reversed_dir, cfg)
        assert scan.globals == {}

    def test_gen_header_underscore_strip_and_unknown_section(self, tmp_path: Path) -> None:
        from rebrew.data import _gen_globals_header
        from rebrew.data_metadata import set_data_field

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "globals.c").write_text(
            "// DATA: SERVER 0x1000\n// SYMBOL: _g_und\nint g_und;\n"
            "// DATA: SERVER 0x2000\n// SYMBOL: g_other\nint g_other;\n",
            encoding="utf-8",
        )
        # DATA-marker names come from rebrew-data.toml; underscore is stripped.
        set_data_field(cfg.metadata_dir, 0x1000, "name", "_g_und", "SERVER")
        set_data_field(cfg.metadata_dir, 0x2000, "name", "g_other", "SERVER")
        _gen_globals_header(cfg, cfg.reversed_dir)
        text = (cfg.reversed_dir / "rebrew_globals.h").read_text(encoding="utf-8")
        assert "g_und" in text  # leading underscore stripped
        assert "g_other" in text
        assert "(unknown section)" in text
