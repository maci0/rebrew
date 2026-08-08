"""Tests for rebrew.resource — .rsrc section compare/extract."""

from __future__ import annotations

import json
from pathlib import Path

from bin_util import append_pe_section, make_pe
from typer.testing import CliRunner

runner = CliRunner()


def _rsrc_pe(path: Path, rsrc: bytes) -> Path:
    pe = append_pe_section(make_pe(b"\x55\x8b\xec\xc3", text_va=0x1000), ".rsrc", rsrc)
    path.write_bytes(pe)
    return path


def test_compare_identical_rsrc(tmp_path: Path) -> None:
    from rebrew.resource import app

    rsrc = b"\x00" * 64 + b"RESDATA"
    a = _rsrc_pe(tmp_path / "a.exe", rsrc)
    b = _rsrc_pe(tmp_path / "b.exe", rsrc)
    result = runner.invoke(app, ["compare", str(a), str(b), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["match"] is True


def test_compare_differing_rsrc_exits_mismatch(tmp_path: Path) -> None:
    from rebrew.resource import app

    a = _rsrc_pe(tmp_path / "a.exe", b"\x00" * 64 + b"AAAA")
    b = _rsrc_pe(tmp_path / "b.exe", b"\x00" * 64 + b"BBBB")
    result = runner.invoke(app, ["compare", str(a), str(b), "--json"])
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["match"] is False
    assert data["diff_bytes"] == 4
    assert data["first_diff_offset"] == 64
    assert data["size_delta"] == 0


def test_compare_missing_rsrc(tmp_path: Path) -> None:
    from rebrew.resource import app

    a = tmp_path / "a.exe"
    a.write_bytes(make_pe(b"\xc3"))
    b = _rsrc_pe(tmp_path / "b.exe", b"R")
    result = runner.invoke(app, ["compare", str(a), str(b), "--json"])
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["match"] is False
    assert data["recompiled_rsrc"]["present"] is False


def test_extract_writes_rsrc(tmp_path: Path) -> None:
    from rebrew.resource import app

    rsrc = b"\xde\xad\xbe\xef" * 16
    a = _rsrc_pe(tmp_path / "a.exe", rsrc)
    out = tmp_path / "out.rsrc"
    result = runner.invoke(app, ["extract", str(a), "--output", str(out)])
    assert result.exit_code == 0
    assert out.read_bytes() == rsrc


def test_extract_missing_rsrc_fails(tmp_path: Path) -> None:
    from rebrew.resource import app

    a = tmp_path / "a.exe"
    a.write_bytes(make_pe(b"\xc3"))
    result = runner.invoke(app, ["extract", str(a)])
    assert result.exit_code == 1
