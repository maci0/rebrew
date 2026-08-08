"""Tests for rebrew imports — import-table symbol recovery."""

import json
import struct
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent))  # tests/ on path for bin_util
from bin_util import make_pe  # noqa: E402

from rebrew.imports import find_import_stubs, parse_import_table  # noqa: E402

IMAGE_BASE = 0x400000
TEXT_VA = 0x1000


def _pe_with_stub() -> tuple[bytes, int, int]:
    """A PE whose .text starts with ``jmp dword ptr [iat]`` at TEXT_VA.

    Returns (pe_bytes, stub_len, iat_va).  LIEF's ``iat_address`` is not
    byte-exact with the hand-rolled layout, so the IAT slot VA is learned
    from a probe build with identical code length.
    """
    stub_len = 8
    tail = b"\x55\x8b\xec\x5d\xc3"  # a normal function after the stub
    imports = [("KERNEL32.dll", ["MessageBoxA", "GetProcAddress"])]
    probe = make_pe(
        b"\x90" * stub_len + tail,
        image_base=IMAGE_BASE,
        text_va=TEXT_VA,
        imports=imports,
    )
    probe_path = Path(tempfile.mkdtemp()) / "probe.exe"
    probe_path.write_bytes(probe)
    table = parse_import_table(probe_path)
    iat_va = min(table)
    stub = b"\xff\x25" + struct.pack("<I", iat_va) + b"\x90\x90"
    return (
        make_pe(
            stub + tail,
            image_base=IMAGE_BASE,
            text_va=TEXT_VA,
            imports=imports,
        ),
        stub_len,
        iat_va,
    )


@pytest.fixture()
def pe_path(tmp_path: Path) -> Path:
    pe_bytes, _, _ = _pe_with_stub()
    path = tmp_path / "game.exe"
    path.write_bytes(pe_bytes)
    return path


class TestParseImportTable:
    def test_imports_parsed(self, pe_path: Path) -> None:
        table = parse_import_table(pe_path)
        # IAT slots land right after the stub code inside .text.
        assert "MessageBoxA" in table.values()
        assert "GetProcAddress" in table.values()
        for va in table:
            assert va >= IMAGE_BASE

    def test_non_pe_returns_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "not_a_pe.bin"
        path.write_bytes(b"\x00" * 64)
        assert parse_import_table(path) == {}

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        assert parse_import_table(tmp_path / "nope.exe") == {}


class TestFindImportStubs:
    def test_detects_jmp_stub(self, pe_path: Path) -> None:
        stubs = find_import_stubs(pe_path)
        # The stub lives at .text start (full VA = imagebase + RVA).
        stub_va = IMAGE_BASE + TEXT_VA
        assert stub_va in stubs
        assert stubs[stub_va] in ("MessageBoxA", "GetProcAddress")

    def test_no_imports_no_stubs(self, tmp_path: Path) -> None:
        plain = tmp_path / "plain.exe"
        plain.write_bytes(make_pe(b"\x90" * 16))
        assert find_import_stubs(plain) == {}


class TestImportsCli:
    def test_terminal_output(self, pe_path: Path) -> None:
        from rebrew.imports import app

        result = CliRunner().invoke(app, [str(pe_path)])
        assert result.exit_code == 0
        assert "MessageBoxA" in result.output
        assert "KERNEL32.dll" in result.output

    def test_json_output(self, pe_path: Path) -> None:
        from rebrew.imports import app

        result = CliRunner().invoke(app, ["--json", str(pe_path)])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert any(i["name"] == "MessageBoxA" for i in payload["imports"])
        assert payload["stubs"]  # stub VA → name present

    def test_missing_binary_errors(self, tmp_path: Path) -> None:
        from rebrew.imports import app

        result = CliRunner().invoke(app, [str(tmp_path / "nope.exe")])
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_registered_in_umbrella(self) -> None:
        from rebrew.main import app as umbrella

        result = CliRunner().invoke(umbrella, ["--help"])
        assert result.exit_code == 0
        assert "imports" in result.output


class TestImportsMark:
    """imports --mark writes LIBRARY annotations for detected stubs."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(
            marker="SERVER",
            target_name="server.dll",
            reversed_dir=tmp_path / "src" / "SERVER",
            metadata_dir=tmp_path / "src",
        )

    def test_mark_writes_library_header(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.imports import mark_import_stubs

        cfg = self._cfg(tmp_path)
        cfg.reversed_dir.mkdir(parents=True)
        added = mark_import_stubs(cfg, {0x401000: "MessageBoxA"}, dry_run=False)
        assert added == 1
        out = cfg.reversed_dir / "library_imports.h"
        assert out.is_file()
        text = out.read_text(encoding="utf-8")
        assert "// LIBRARY: SERVER 0x00401000" in text
        assert "// MessageBoxA" in text

    def test_mark_dry_run_writes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.imports import mark_import_stubs

        cfg = self._cfg(tmp_path)
        cfg.reversed_dir.mkdir(parents=True)
        added = mark_import_stubs(cfg, {0x401000: "MessageBoxA"}, dry_run=True)
        assert added == 1
        assert not (cfg.reversed_dir / "library_imports.h").exists()

    def test_mark_skips_existing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.imports import mark_import_stubs

        cfg = self._cfg(tmp_path)
        cfg.reversed_dir.mkdir(parents=True)
        mark_import_stubs(cfg, {0x401000: "MessageBoxA"}, dry_run=False)
        added = mark_import_stubs(cfg, {0x401000: "MessageBoxA"}, dry_run=False)
        assert added == 0  # already annotated
