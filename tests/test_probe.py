"""Tests for `rebrew.probe`, the no-side-effect per-function ruler."""

from __future__ import annotations

import json
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import capstone
import pytest
import typer
from typer.testing import CliRunner, Result

from rebrew.coff_reloc import CatalogScanError, CoffRelocRecord
from rebrew.probe import matched_reloc_count


class TestMatchedRelocCount:
    """The historical "matched-reloc" byte count."""

    def test_counts_agreeing_bytes_and_reloc_sites(self) -> None:
        # Byte 1 differs but relocates on the candidate side, so it matches.
        assert matched_reloc_count(b"\x90\x01\x02", b"\x90\xff\x02", {1}, 3) == 3

    def test_stops_at_the_short_target_read(self) -> None:
        # SIZE (8) runs past the target section's raw bytes, so only 3 bytes
        # were read.  Indexing past them raised IndexError; the overlap that
        # does exist is 3, with byte 2 a real difference.
        assert matched_reloc_count(b"\x90\x01\x02", b"\x90\x01\xff" * 2, set(), 8) == 2

    def test_stops_at_the_short_candidate(self) -> None:
        assert matched_reloc_count(b"\x90\x01\x02\x03", b"\x90\x01", set(), 4) == 2

    def test_empty_side_counts_nothing(self) -> None:
        assert matched_reloc_count(b"", b"\x90", set(), 1) == 0
        assert matched_reloc_count(b"\x90", b"", set(), 1) == 0


class TestProbeRelocationContext:
    """Probe validates real target bindings with the same context as test."""

    def _invoke(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        kind: int = 6,
        actual: int = 0x12345678,
        iat: bool = False,
        catalog_error: bool = False,
    ) -> Result:
        import rebrew.coff_reloc as relocs
        import rebrew.compile_overrides as overrides
        import rebrew.matcher.parsers as parsers
        import rebrew.probe as probe

        cfg = SimpleNamespace(
            root=tmp_path,
            target_binary=tmp_path / "original.dll",
            capstone_arch=capstone.CS_ARCH_X86,
            capstone_mode=capstone.CS_MODE_32,
        )
        source = tmp_path / "func.c"
        source.write_text("void func(void) {}\n")
        ann = SimpleNamespace(size=6, symbol="_func", toolchain=None, cflags="", module="TEST")
        candidate = (b"\xa1" if kind == 6 else b"\xe8") + bytes(4) + b"\xc3"
        target_value = actual if kind == 6 else actual - 0x1000 - 5
        target = candidate[:1] + struct.pack("<I", target_value) + candidate[-1:]
        monkeypatch.setattr(probe, "require_config", lambda **kw: cfg)
        monkeypatch.setattr(probe, "select_annotation", lambda *a, **kw: (source, ann, 0x1000))
        monkeypatch.setattr(probe, "load_binary", lambda p: None)
        monkeypatch.setattr(probe, "extract_raw_bytes", lambda *a: target)
        monkeypatch.setattr(
            probe, "compile_to_obj", lambda *a, **kw: (str(tmp_path / "func.obj"), None)
        )
        monkeypatch.setattr(overrides, "resolve_compile_overrides", lambda *a: ("msvc-6.0", "/O2"))
        monkeypatch.setattr(
            parsers,
            "parse_obj_symbol_and_relocs",
            lambda *a: (candidate, {1: "_value"}, [CoffRelocRecord(1, kind, "_value")]),
        )

        def lookup(cfg: Any) -> dict[str, int]:
            if catalog_error:
                raise CatalogScanError("catalog unavailable")
            return {"_value": 0x12345678, "_other": 0x87654321}

        monkeypatch.setattr(relocs, "build_name_to_va", lookup)
        monkeypatch.setattr(
            relocs, "build_iat_region", lambda cfg: frozenset({actual}) if iat else frozenset()
        )
        app = typer.Typer()
        app.command()(probe.main)
        return CliRunner().invoke(app, [str(source), "--json"])

    @pytest.mark.parametrize(
        ("kind", "actual", "iat", "matched"),
        [
            (6, 0x12345678, False, True),
            (20, 0x12345678, False, True),
            (6, 0x87654321, False, False),
            (20, 0x87654321, False, False),
            (6, 0x87654321, True, True),
        ],
    )
    def test_target_bindings(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        kind: int,
        actual: int,
        iat: bool,
        matched: bool,
    ) -> None:
        result = self._invoke(tmp_path, monkeypatch, kind, actual, iat)
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert (payload["matched"] == payload["total"]) is matched
        assert (payload["matched_reloc"] == payload["total"]) is matched

    def test_catalog_failure_is_an_infrastructure_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = self._invoke(tmp_path, monkeypatch, catalog_error=True)
        assert result.exit_code == 2, result.output
        assert "catalog unavailable" in result.stdout
