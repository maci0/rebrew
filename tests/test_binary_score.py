"""Tests for the same-offset binary score command."""

from __future__ import annotations

from pathlib import Path

import pytest
from bin_util import make_pe
from cli_json import cli_payload
from typer.testing import CliRunner


def _project(tmp_path: Path, reference: bytes) -> None:
    (tmp_path / "rebrew-project.toml").write_text(
        '[project]\ndefault_target = "game"\n\n'
        '[targets.game]\nbinary = "original.exe"\nmodule = "GAME"\nreversed_dir = "src"\n'
        '[compiler]\nprofile = "msvc-6.0"\ncommand = "cl"\ncflags = "/O2"\n'
    )
    (tmp_path / "original.exe").write_bytes(reference)


def test_identical_images_score_every_compared_byte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rebrew.binary_score import app

    image = make_pe(b"\x90" * 64)
    _project(tmp_path, image)
    built = tmp_path / "built.exe"
    built.write_bytes(image)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["--built", str(built), "--json"])
    assert result.exit_code == 0, result.output
    payload = cli_payload(result)
    assert payload["same"] == payload["compared"] > 0
    assert payload["ratio"] == 1.0
    assert payload["file"]["same"] == payload["file"]["compared"] > payload["same"]


def test_changed_byte_costs_one_match(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from rebrew.binary_score import app

    reference = make_pe(b"\x90" * 64)
    built_bytes = bytearray(reference)
    built_bytes[0x210] ^= 0xFF
    _project(tmp_path, reference)
    built = tmp_path / "built.exe"
    built.write_bytes(bytes(built_bytes))
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["--built", str(built), "--json"])
    assert result.exit_code == 0, result.output
    payload = cli_payload(result)
    assert payload["compared"] - payload["same"] == 1
    assert payload["file"]["compared"] - payload["file"]["same"] == 1
    assert 0 < payload["ratio"] < 1


def test_missing_built_image_fails_loudly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from rebrew.binary_score import app

    _project(tmp_path, make_pe(b"\x90" * 32))
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["--built", "nope.exe", "--json"])
    assert result.exit_code != 0
