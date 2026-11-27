"""Tests for library presence: locate a COFF object's bodies in an image."""

from __future__ import annotations

lazy from pathlib import Path

import pytest
from bin_util import make_coff_obj, make_pe
from cli_json import cli_payload
from typer.testing import CliRunner

_BODY = b"\x55\x8b\xec\x83\xec\x10\x8b\x45\x08\x85\xc0\x74\x0d\x8b\x4d\x0c\x89\x08" + b"\xc3" * 40


def _project(tmp_path: Path, code: bytes) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text(
        "/* ADDRESS: GAME 0x1000 */\nint alpha(void) { return 1; }\n"
    )
    (tmp_path / "rebrew-project.toml").write_text(
        '[project]\ndefault_target = "game"\n\n'
        '[targets.game]\nbinary = "game.exe"\nmodule = "GAME"\nreversed_dir = "src"\n'
        '[compiler]\nprofile = "msvc-6.0"\ncommand = "cl"\ncflags = "/O2"\n'
    )
    (tmp_path / "game.exe").write_bytes(make_pe(code))
    return tmp_path


def _object(tmp_path: Path, body: bytes) -> Path:
    obj = tmp_path / "member.obj"
    obj.write_bytes(make_coff_obj(body, func_symbol="_alpha"))
    return obj


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, object_path: Path, *args: str):
    from rebrew.library.presence import app

    monkeypatch.chdir(tmp_path)
    return CliRunner().invoke(app, ["--object", str(object_path), *args])


class TestPresence:
    def test_present_body_reports_its_va(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project = _project(tmp_path, b"\x90" * 16 + _BODY + b"\x90" * 16)
        obj = _object(project, _BODY)
        result = _run(project, monkeypatch, obj, "--json")
        assert result.exit_code == 0, result.output
        payload = cli_payload(result)
        assert payload["counts"] == {"present": 1, "absent": 0, "unknown": 0}
        row = payload["symbols"][0]
        assert row["verdict"] == "present"
        assert row["va"] == "0x401010"
        assert row["object_offset"] == 0
        assert row["object_text_size"] > 0
        assert row["ratio"] >= 0.9

    def test_each_symbol_reports_its_own_body_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        second = bytes(range(0x20, 0x20 + 54))  # 58 + 54: no section padding
        project = _project(tmp_path, b"\x90" * 16 + _BODY + second + b"\x90" * 16)
        obj = tmp_path / "pair.obj"
        obj.write_bytes(
            make_coff_obj(_BODY + second, func_symbol="_alpha", extra_funcs=[("_beta", len(_BODY))])
        )
        result = _run(project, monkeypatch, obj, "--json")
        assert result.exit_code == 0, result.output
        rows = {row["symbol"]: row for row in cli_payload(result)["symbols"]}
        assert rows["_alpha"]["size"] == len(_BODY)
        assert rows["_beta"]["size"] == len(second)
        assert rows["_beta"]["object_offset"] == len(_BODY)
        assert rows["_beta"]["va"] == f"0x{0x401010 + len(_BODY):x}"

    def test_absent_body_is_reported_absent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project = _project(tmp_path, b"\xcc" * 128)
        obj = _object(project, _BODY)
        result = _run(project, monkeypatch, obj, "--json")
        assert result.exit_code == 0, result.output
        payload = cli_payload(result)
        assert payload["counts"]["absent"] == 1
        assert payload["symbols"][0]["va"] is None

    def test_short_body_stays_unknown(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project = _project(tmp_path, b"\x90" * 16 + b"\xc3" + b"\x90" * 16)
        obj = _object(project, b"\xc3")
        result = _run(project, monkeypatch, obj, "--json")
        assert result.exit_code == 0, result.output
        assert cli_payload(result)["counts"]["unknown"] == 1


def test_lowered_thresholds_locate_a_short_body() -> None:
    from rebrew.library.presence import classify, locate_body

    body = b"\x55\x8b\xec\x83\xec\x10\x8b\x45\x08\x85\xc0\x74\x05\x8b\x4d\x0c\x89\x08\x5d\xc3"
    text = b"\xcc" * 32 + body + b"\xcc" * 32
    best = locate_body(text, body, set(), min_fixed=16)
    assert best is not None
    assert best["offset"] == 32
    assert classify(best, True, min_ratio=0.9, min_fixed=16) == "present"
    assert classify(best, True) == "unknown"
