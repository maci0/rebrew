"""Tests for rebrew.resource — .rsrc section compare/extract."""

from __future__ import annotations

lazy from pathlib import Path

from bin_util import append_pe_section, make_pe
from cli_json import cli_payload
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
    data = cli_payload(result)
    assert data["match"] is True


def test_compare_differing_rsrc_exits_mismatch(tmp_path: Path) -> None:
    from rebrew.resource import app

    a = _rsrc_pe(tmp_path / "a.exe", b"\x00" * 64 + b"AAAA")
    b = _rsrc_pe(tmp_path / "b.exe", b"\x00" * 64 + b"BBBB")
    result = runner.invoke(app, ["compare", str(a), str(b), "--json"])
    assert result.exit_code == 1
    data = cli_payload(result)
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
    data = cli_payload(result)
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
    from rebrew.cli import EXIT_ERROR
    from rebrew.resource import app

    a = tmp_path / "a.exe"
    a.write_bytes(make_pe(b"\xc3"))
    result = runner.invoke(app, ["extract", str(a)])
    assert result.exit_code == EXIT_ERROR


def test_extract_json(tmp_path: Path) -> None:
    from rebrew.resource import app

    rsrc = b"\xde\xad\xbe\xef" * 16
    a = _rsrc_pe(tmp_path / "a.exe", rsrc)
    out = tmp_path / "out.rsrc"
    result = runner.invoke(app, ["extract", str(a), "--output", str(out), "--json"])
    assert result.exit_code == 0
    data = cli_payload(result)
    assert data["present"] is True
    assert data["output"] == str(out)
    assert data["bytes"] == len(rsrc)
    assert out.read_bytes() == rsrc


def test_extract_missing_rsrc_json(tmp_path: Path) -> None:
    from rebrew.cli import EXIT_ERROR
    from rebrew.resource import app

    a = tmp_path / "a.exe"
    a.write_bytes(make_pe(b"\xc3"))
    result = runner.invoke(app, ["extract", str(a), "--json"])
    assert result.exit_code == EXIT_ERROR
    data = cli_payload(result)
    assert data["present"] is False


def test_compare_rejects_truncated_resource_sections(tmp_path: Path) -> None:
    from rebrew.resource import app

    a = _rsrc_pe(tmp_path / "a.exe", b"RESOURCE")
    b = _rsrc_pe(tmp_path / "b.exe", b"RESOURCE")
    for path in (a, b):
        path.write_bytes(path.read_bytes()[:-1])
    result = runner.invoke(app, ["compare", str(a), str(b), "--json"])
    assert result.exit_code == 2
    assert "truncated .rsrc" in result.stderr


def test_extract_keeps_output_when_resource_is_truncated(tmp_path: Path) -> None:
    from rebrew.resource import app

    source = _rsrc_pe(tmp_path / "source.exe", b"RESOURCE")
    source.write_bytes(source.read_bytes()[:-1])
    output = tmp_path / "out.rsrc"
    output.write_bytes(b"keep")
    result = runner.invoke(app, ["extract", str(source), "-o", str(output), "--json"])
    assert result.exit_code == 2
    assert "truncated .rsrc" in result.stderr
    assert output.read_bytes() == b"keep"


def test_resource_payload_without_alignment_padding_is_accepted(tmp_path: Path) -> None:
    from rebrew.formats.binary_loader import load_binary
    from rebrew.resource import app

    payload = b"RESOURCE"
    source = _rsrc_pe(tmp_path / "source.exe", payload)
    section = load_binary(source).sections[".rsrc"]
    assert len(source.read_bytes()) == section.file_offset + len(payload)
    assert section.raw_size > len(payload)
    compared = runner.invoke(app, ["compare", str(source), str(source), "--json"])
    assert compared.exit_code == 0
    assert cli_payload(compared)["match"] is True
    output = tmp_path / "out.rsrc"
    extracted = runner.invoke(app, ["extract", str(source), "-o", str(output), "--json"])
    assert extracted.exit_code == 0
    assert output.read_bytes() == payload
