"""Tests for symbol_addrs.py: splat-style symbol export (rich, CSV, references)."""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import rebrew.symbol_addrs as symbol_addrs
from rebrew.pe_symbols import PeSymbol, PeSymbolTable
from rebrew.symbol_addrs import (
    SymbolRow,
    format_csv,
    format_symbol,
    merge_pe_symbols,
    parse_symbol_addrs,
)

sys.path.insert(0, str(Path(__file__).parent))  # tests/ on path for bin_util
from bin_util import make_pe

runner = CliRunner()

FIXTURES = Path(__file__).parent / "fixtures"
MINI_PE = FIXTURES / "mini_pe.exe"

IMAGE_BASE = 0x400000
TEXT_VA = 0x1000


def _fake_ann(
    va: int, name: str, marker: str = "FUNCTION", symbol: str = "", size: int = 0
) -> SimpleNamespace:
    return SimpleNamespace(va=va, name=name, symbol=symbol, marker_type=marker, size=size)


def _patch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    annos: list[SimpleNamespace],
    *,
    binary: Path | None = None,
) -> SimpleNamespace:
    cfg = SimpleNamespace(
        target_binary=binary or (tmp_path / "x.dll"),
        reversed_dir=tmp_path / "src",
        root=tmp_path,
        target_name="T",
        metadata_dir=tmp_path,
        marker="T",
        source_ext=".c",
    )
    cfg.reversed_dir.mkdir(exist_ok=True)
    monkeypatch.setattr(
        symbol_addrs, "require_config", lambda target=None, json_mode=False, root=None: cfg
    )
    monkeypatch.setattr(
        symbol_addrs,
        "iter_annotations",
        lambda sources, target=None, metadata_dir=None: [(Path("a.c"), annos)],
    )
    return cfg


class TestSymbolAddrs:
    def test_writes_sorted_rich_symbols(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch(
            monkeypatch,
            tmp_path,
            [_fake_ann(0x2000, "later"), _fake_ann(0x1000, "earlier")],
        )
        out = tmp_path / "symbol_addrs.csv"
        r = runner.invoke(symbol_addrs.app, ["--output", str(out)])
        assert r.exit_code == 0
        lines = out.read_text(encoding="utf-8").splitlines()
        assert lines == [
            "earlier = 0x00001000; // type:func",
            "later = 0x00002000; // type:func",
        ]

    def test_annotation_size_reaches_the_comment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch(monkeypatch, tmp_path, [_fake_ann(0x1000, "sized", size=0x2A)])
        out = tmp_path / "symbol_addrs.csv"
        runner.invoke(symbol_addrs.app, ["--output", str(out)])
        assert (
            out.read_text(encoding="utf-8").strip() == "sized = 0x00001000; // type:func size:0x2A"
        )

    def test_csv_flag_keeps_the_bare_format(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch(
            monkeypatch,
            tmp_path,
            [_fake_ann(0x2000, "later"), _fake_ann(0x1000, "earlier")],
        )
        out = tmp_path / "symbol_addrs.csv"
        r = runner.invoke(symbol_addrs.app, ["--output", str(out), "--csv"])
        assert r.exit_code == 0
        assert out.read_text(encoding="utf-8").splitlines() == [
            "0x00001000,earlier",
            "0x00002000,later",
        ]

    def test_excludes_globals_and_unnamed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch(
            monkeypatch,
            tmp_path,
            [
                _fake_ann(0x1000, "func_a"),
                _fake_ann(0x2000, "", marker="GLOBAL"),  # excluded (marker)
                _fake_ann(0x3000, "", marker="FUNCTION"),  # excluded (unnamed)
            ],
        )
        out = tmp_path / "symbol_addrs.csv"
        r = runner.invoke(symbol_addrs.app, ["--output", str(out), "--json"])
        assert r.exit_code == 0
        payload = json.loads(r.stdout)
        assert payload["symbols"] == 1
        assert payload["skipped_unnamed"] == 1
        assert payload["format"] == "rich"
        lines = out.read_text(encoding="utf-8").splitlines()
        assert lines == ["func_a = 0x00001000; // type:func"]

    def test_prefers_symbol_over_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch(monkeypatch, tmp_path, [_fake_ann(0x1000, "func_a", symbol="_func_a@8")])
        out = tmp_path / "symbol_addrs.csv"
        r = runner.invoke(symbol_addrs.app, ["--output", str(out)])
        assert r.exit_code == 0
        assert out.read_text(encoding="utf-8").strip() == "_func_a@8 = 0x00001000; // type:func"

    def test_zero_va_rows_skipped_with_warning_count(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Annotations below the VA floor (0x0 placeholder rows) are skipped
        with a warning count instead of exported as 0x00000000 lines."""
        _patch(
            monkeypatch,
            tmp_path,
            [
                _fake_ann(0x1000, "good"),
                _fake_ann(0x0, "zero_va"),
            ],
        )
        out = tmp_path / "symbol_addrs.csv"
        r = runner.invoke(symbol_addrs.app, ["--output", str(out), "--json"])
        assert r.exit_code == 0
        payload = json.loads(r.stdout)
        assert payload["symbols"] == 1
        assert payload["skipped_invalid_va"] == 1
        lines = out.read_text(encoding="utf-8").splitlines()
        assert lines == ["good = 0x00001000; // type:func"]

    def test_csv_and_references_conflict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch(monkeypatch, tmp_path, [_fake_ann(0x1000, "good")])
        out = tmp_path / "symbol_addrs.csv"
        r = runner.invoke(symbol_addrs.app, ["--output", str(out), "--csv", "--references"])
        assert r.exit_code != 0


class TestPeSymbolsFlag:
    def test_pe_symbols_are_appended(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(
            monkeypatch,
            tmp_path,
            [_fake_ann(0x10001000, "GameMain", size=0x40)],
            binary=MINI_PE,
        )
        out = tmp_path / "symbol_addrs.csv"
        r = runner.invoke(symbol_addrs.app, ["--output", str(out), "--pe-symbols", "--json"])
        assert r.exit_code == 0
        payload = json.loads(r.stdout)
        assert payload["pe_symbols"] >= 2
        assert payload["pe_collisions"] == []
        text = out.read_text(encoding="utf-8")
        assert "entrypoint = 0x00401000; // type:func" in text
        assert "__imp_kernel32_GetTickCount = 0x" in text
        assert "// type:u32 size:0x4 -- import from KERNEL32.dll" in text

    def test_default_output_has_no_pe_symbols(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch(monkeypatch, tmp_path, [_fake_ann(0x10001000, "GameMain")], binary=MINI_PE)
        out = tmp_path / "symbol_addrs.csv"
        runner.invoke(symbol_addrs.app, ["--output", str(out)])
        text = out.read_text(encoding="utf-8")
        assert "__imp_" not in text
        assert "entrypoint" not in text

    def test_annotation_wins_a_collision_and_it_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Same VA as the fixture's entry point, under a different name.
        _patch(monkeypatch, tmp_path, [_fake_ann(IMAGE_BASE + TEXT_VA, "MyEntry")], binary=MINI_PE)
        out = tmp_path / "symbol_addrs.csv"
        r = runner.invoke(symbol_addrs.app, ["--output", str(out), "--pe-symbols", "--json"])
        assert r.exit_code == 0
        payload = json.loads(r.stdout)
        assert len(payload["pe_collisions"]) == 1
        assert "same VA" in payload["pe_collisions"][0]
        text = out.read_text(encoding="utf-8")
        assert "MyEntry = 0x00401000" in text
        assert "entrypoint = 0x00401000" not in text

    def test_missing_binary_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, tmp_path, [_fake_ann(0x10001000, "GameMain")])
        out = tmp_path / "symbol_addrs.csv"
        r = runner.invoke(symbol_addrs.app, ["--output", str(out), "--pe-symbols"])
        assert r.exit_code != 0


class TestReferences:
    def _reference_pe(self, tmp_path: Path) -> Path:
        """A PE whose first function loads the address of a later one."""
        target_va = IMAGE_BASE + TEXT_VA + 0x40
        code = b"\xb8" + struct.pack("<I", target_va) + b"\xc3" + b"\x90" * 0x40 + b"\xc3"
        path = tmp_path / "refs.exe"
        path.write_bytes(make_pe(code, image_base=IMAGE_BASE, text_va=TEXT_VA))
        return path

    def test_referenced_by_lists_the_enclosing_symbol(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary = self._reference_pe(tmp_path)
        _patch(
            monkeypatch,
            tmp_path,
            [
                _fake_ann(IMAGE_BASE + TEXT_VA, "caller", size=6),
                _fake_ann(IMAGE_BASE + TEXT_VA + 0x40, "target", size=8),
            ],
            binary=binary,
        )
        out = tmp_path / "symbols.csv"
        r = runner.invoke(symbol_addrs.app, ["--output", str(out), "--references", "--json"])
        assert r.exit_code == 0
        assert json.loads(r.stdout)["format"] == "references"
        lines = out.read_text(encoding="utf-8").splitlines()
        assert lines[0] == "va,name,type,size,referenced_by"
        by_name = {line.split(",")[1]: line for line in lines[1:]}
        assert by_name["target"].endswith(",caller")
        assert by_name["caller"].endswith(",")

    def test_unresolved_site_is_named_by_its_address(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary = self._reference_pe(tmp_path)
        # Only the target is known; the referring site has no enclosing symbol.
        _patch(
            monkeypatch,
            tmp_path,
            [_fake_ann(IMAGE_BASE + TEXT_VA + 0x40, "target", size=8)],
            binary=binary,
        )
        out = tmp_path / "symbols.csv"
        runner.invoke(symbol_addrs.app, ["--output", str(out), "--references"])
        lines = out.read_text(encoding="utf-8").splitlines()
        assert f"fcn_{IMAGE_BASE + TEXT_VA:08x}" in lines[1]

    def test_missing_binary_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, tmp_path, [_fake_ann(0x10001000, "GameMain")])
        r = runner.invoke(symbol_addrs.app, ["--output", str(tmp_path / "s.csv"), "--references"])
        assert r.exit_code != 0


class TestRichFormat:
    def test_format_and_parse_round_trip(self) -> None:
        row = SymbolRow(va=0x401004, name="__imp_kernel32_Foo", kind="u32", size=4, detail="x")
        line = format_symbol(row)
        assert line == "__imp_kernel32_Foo = 0x00401004; // type:u32 size:0x4 -- x"
        parsed = parse_symbol_addrs(line + "\n")
        assert parsed == [
            SymbolRow(va=0x401004, name="__imp_kernel32_Foo", kind="u32", size=4, detail="x")
        ]

    def test_forwarded_export_is_a_note_line(self) -> None:
        row = SymbolRow(va=None, name="Fwd", kind="forwarder", forwarder="KERNEL32.Sleep")
        line = format_symbol(row)
        assert line == "// Fwd -> KERNEL32.Sleep (forwarded export)"
        assert parse_symbol_addrs(line) == []

    def test_parser_accepts_bare_csv(self) -> None:
        assert parse_symbol_addrs("0x00001000,func_a\n") == [SymbolRow(va=0x1000, name="func_a")]

    def test_parser_skips_comments_and_blanks(self) -> None:
        text = "// note\n\n0x1000,plain\na = 0x2000; // type:func\n"
        assert parse_symbol_addrs(text) == [
            SymbolRow(va=0x1000, name="plain"),
            SymbolRow(va=0x2000, name="a"),
        ]

    def test_parser_reads_back_written_output(self) -> None:
        rows = [
            SymbolRow(va=0x1000, name="a", size=0x10),
            SymbolRow(va=0x2000, name="b", kind="u32", size=4, detail="import from X.dll"),
        ]
        parsed = parse_symbol_addrs("\n".join(format_symbol(row) for row in rows) + "\n")
        assert parsed == rows

    def test_csv_dump_columns(self) -> None:
        rows = [SymbolRow(va=0x1000, name="a", size=0x10)]
        text = format_csv(rows, {0x1000: ["caller", "other"]})
        assert text.splitlines() == [
            "va,name,type,size,referenced_by",
            "0x00001000,a,func,0x10,caller|other",
        ]


class TestMergePeSymbols:
    def test_annotation_wins_same_va(self) -> None:
        rows = [SymbolRow(va=0x1000, name="mine")]
        table = PeSymbolTable(
            symbols=(PeSymbol(va=0x1000, name="theirs", kind="func", origin="entrypoint"),)
        )
        merged, collisions = merge_pe_symbols(rows, table)
        assert merged == rows
        assert len(collisions) == 1
        assert "same VA" in collisions[0]

    def test_annotation_wins_same_name(self) -> None:
        rows = [SymbolRow(va=0x1000, name="shared")]
        table = PeSymbolTable(
            symbols=(PeSymbol(va=0x2000, name="shared", kind="func", origin="export"),)
        )
        merged, collisions = merge_pe_symbols(rows, table)
        assert merged == rows
        assert "same name" in collisions[0]

    def test_non_colliding_symbol_is_kept(self) -> None:
        rows = [SymbolRow(va=0x1000, name="mine")]
        table = PeSymbolTable(
            symbols=(PeSymbol(va=0x2000, name="theirs", kind="u32", origin="import", size=4),)
        )
        merged, collisions = merge_pe_symbols(rows, table)
        assert collisions == []
        assert [row.name for row in merged] == ["mine", "theirs"]
        assert merged[1].size == 4

    def test_pe_symbols_colliding_with_each_other_are_reported(self) -> None:
        # Two export names for one address: the second would make the file
        # ambiguous, so it is dropped with its own message.
        table = PeSymbolTable(
            symbols=(
                PeSymbol(va=0x2000, name="alias_a", kind="func", origin="export"),
                PeSymbol(va=0x2000, name="alias_b", kind="func", origin="export"),
            )
        )
        merged, collisions = merge_pe_symbols([], table)
        assert [row.name for row in merged] == ["alias_a"]
        assert "another PE symbol" in collisions[0]
