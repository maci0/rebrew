"""The Delphi CLI produces consistent artifacts without changing reference bytes or stores."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from rebrew.app.main import app
from rebrew.compiler.delphi16 import Delphi16Error, Delphi16Result


def _project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    source = tmp_path / "HELLO.DPR"
    source.write_text("program Hello; begin end.")
    reference = tmp_path / "original.exe"
    reference.write_bytes(b"reference")
    cfg = SimpleNamespace(
        compiler_profile="delphi-1.0",
        compile_timeout=180,
        base_cflags="",
        cflags="-$S-",
        bin_dir=tmp_path / "bin",
        target_binary=reference,
    )
    monkeypatch.setattr("rebrew.delphi_build.require_config", lambda **_kw: cfg)
    return cfg


class TestDelphiBuild:
    def test_copies_same_invocation_artifacts_and_uses_configured_flags(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path, monkeypatch)
        made = tmp_path / "made.exe"
        made.write_bytes(b"compiled")
        mapping = tmp_path / "made.map"
        mapping.write_text("segment map")

        def build(source: Path, workdir: Path | None, **kwargs: object) -> Delphi16Result:
            assert source.name == "HELLO.DPR"
            assert kwargs["extra_args"] == ["-$S-", "-$R+"]
            assert kwargs["map_file"] is True
            return Delphi16Result(made, log="compiled", map_path=mapping)

        monkeypatch.setattr("rebrew.delphi_build.compile_ne", build)
        output, map_output = tmp_path / "out.exe", tmp_path / "out.map"
        result = CliRunner().invoke(
            app,
            [
                "build",
                "delphi",
                str(tmp_path / "HELLO.DPR"),
                "--output",
                str(output),
                "--map",
                str(map_output),
                "--dcc-args=-$R+",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        assert output.read_bytes() == b"compiled"
        assert map_output.read_text() == "segment map"
        assert json.loads(result.stdout)["toolchain"] == "delphi-1.0"
        assert (tmp_path / "original.exe").read_bytes() == b"reference"

    def test_failure_cannot_publish_stale_artifacts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path, monkeypatch)
        output = tmp_path / "out.exe"
        output.write_bytes(b"last good build")

        def fail(*_a: object, **_kw: object) -> Delphi16Result:
            raise Delphi16Error("compile failed")

        monkeypatch.setattr("rebrew.delphi_build.compile_ne", fail)
        result = CliRunner().invoke(
            app, ["build", "delphi", str(tmp_path / "HELLO.DPR"), "--output", str(output), "--json"]
        )
        assert result.exit_code == 2
        assert output.read_bytes() == b"last good build"

    def test_reference_cannot_be_overwritten(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _project(tmp_path, monkeypatch)
        result = CliRunner().invoke(
            app,
            [
                "build",
                "delphi",
                str(tmp_path / "HELLO.DPR"),
                "--output",
                str(cfg.target_binary),
                "--json",
            ],
        )
        assert result.exit_code == 2
        assert cfg.target_binary.read_bytes() == b"reference"
