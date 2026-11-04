"""Tests for the same-offset binary score command."""

from __future__ import annotations

lazy from pathlib import Path

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
    assert 0 < payload["informative"]["same"] <= payload["same"]
    assert payload["informative"]["compared"] <= payload["compared"]


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


def test_count_window_mixed_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Equal zero pairs count as matches; informative counts track nonzero reference bytes."""
    import rebrew.binary_score as bs

    monkeypatch.setattr(bs, "_VECTOR_COMPARE_MIN_BYTES", 1 << 30)
    reference = b"\x00\x00\x01\x02"
    built = b"\x00\x01\x01\x03"
    assert bs._count_window(reference, built, 0, 4) == (2, 1, 2)
    assert bs._count_window(reference, built, 2, 4) == (1, 1, 2)
    assert bs._count_window(reference, built, 3, 2) == (0, 0, 0)


def test_count_window_vector_path_matches_scalar(monkeypatch: pytest.MonkeyPatch) -> None:
    """The NumPy and plain-loop paths return identical counts on the same bytes."""
    import rebrew.binary_score as bs

    reference = bytes((i * 37 + 11) & 0xFF for i in range(4096))
    built = bytearray(reference)
    for i in range(0, len(built), 3):
        built[i] ^= 0x5A
    scalar = bs._count_window(reference, bytes(built), 0, len(built))
    monkeypatch.setattr(bs, "_VECTOR_COMPARE_MIN_BYTES", 1)
    assert bs._count_window(reference, bytes(built), 0, len(built)) == scalar


def test_count_window_clips_a_window_past_the_images(monkeypatch: pytest.MonkeyPatch) -> None:
    """A section window reaching past either buffer stops at the common end."""
    import rebrew.binary_score as bs

    monkeypatch.setattr(bs, "_VECTOR_COMPARE_MIN_BYTES", 1 << 30)
    assert bs._count_window(b"\x01\x02", b"\x01\x02", 0, 0x100) == (2, 2, 2)


@pytest.mark.parametrize("vector_threshold", [1 << 30, 1])
def test_count_window_clips_a_negative_start(
    monkeypatch: pytest.MonkeyPatch, vector_threshold: int
) -> None:
    """A window starting before the image counts only bytes both sides hold."""
    import rebrew.binary_score as bs

    monkeypatch.setattr(bs, "_VECTOR_COMPARE_MIN_BYTES", vector_threshold)
    assert bs._count_window(b"abcd", b"abce", -3, 2) == (2, 2, 2)
    assert bs._count_window(b"abcd", b"abce", -10, 2) == (2, 2, 2)
