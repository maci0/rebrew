"""Tests for rebrew.toolchain — standardized toolchain invocation."""

from __future__ import annotations

from pathlib import Path

import pytest

from rebrew.toolchain import (
    TOOLCHAINS,
    ToolchainError,
    ToolchainSpec,
    get_toolchain,
    run_toolchain,
)


class _FakeProc:
    def __init__(self, rc: int = 0, out: str = "", err: str = "") -> None:
        self.returncode = rc
        self.stdout = out
        self.stderr = err


def _monkey_docker(monkeypatch, *, available: bool = True, image: bool = True) -> list[list[str]]:
    """Fake docker availability + image presence + capture invocations."""
    calls: list[list[str]] = []

    def _run(cmd, **kwargs):
        calls.append(cmd)
        return _FakeProc(0, "compiled ok", "")

    monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: available)
    monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: available and image)
    monkeypatch.setattr("rebrew.toolchain.subprocess.run", _run)
    return calls


class TestRegistry:
    def test_known_toolchains(self) -> None:
        assert {"msvc6", "delphi16", "gcc-pe"} <= set(TOOLCHAINS)

    def test_get_unknown_raises(self) -> None:
        with pytest.raises(ToolchainError, match="unknown toolchain"):
            get_toolchain("nope")

    def test_delphi16_host_binary_name(self) -> None:
        # The host executable is DCC.EXE (uppercase on disk); the docker
        # image's ENTRYPOINT is the dcc wrapper, so no command is passed.
        spec = TOOLCHAINS["delphi16"]
        assert spec.binary == "DCC.EXE"
        assert spec.image_binary is None


class TestRunToolchain:
    def test_docker_backend_uses_image_and_mount(self, tmp_path: Path, monkeypatch) -> None:
        spec = ToolchainSpec(name="t", image="rebrew/t:latest", binary="cl", image_binary="cl")
        calls = _monkey_docker(monkeypatch)
        r = run_toolchain(spec, ["/c", "f.c"], workdir=tmp_path)
        assert r.backend == "docker"
        assert r.ok
        assert calls[0][:5] == ["docker", "run", "--rm", "-v", f"{tmp_path.resolve()}:/work"]
        assert calls[0][5:9] == ["-w", "/work", "rebrew/t:latest", "cl"]
        assert calls[0][9:] == ["/c", "f.c"]

    def test_docker_entrypoint_image_passes_no_command(self, tmp_path: Path, monkeypatch) -> None:
        """image_binary=None means the image ENTRYPOINT is the compiler —
        no command is appended after the image tag (Godbolt convention)."""
        spec = ToolchainSpec(name="t", image="rebrew/t:latest", binary="wcc386")
        calls = _monkey_docker(monkeypatch)
        run_toolchain(spec, ["-zq", "f.c"], workdir=tmp_path)
        assert calls[0][8:] == ["-zq", "f.c"]

    def test_docker_uses_image_binary_shim(self, tmp_path: Path, monkeypatch) -> None:
        spec = ToolchainSpec(
            name="t", image="rebrew/t:latest", binary="DCC.EXE", image_binary="dcc"
        )
        calls = _monkey_docker(monkeypatch)
        run_toolchain(spec, ["hello.dpr"], workdir=tmp_path)
        assert calls[0][8] == "dcc"

    def test_host_fallback_uses_vendored_path(self, tmp_path: Path, monkeypatch) -> None:
        dcc = tmp_path / "DELPHI10" / "DCC.EXE"
        dcc.parent.mkdir(parents=True)
        dcc.write_bytes(b"MZ")
        spec = ToolchainSpec(
            name="t", image=None, binary="DCC.EXE", host_path=tmp_path / "DELPHI10"
        )
        calls: list[list[str]] = []

        def _run(cmd, **kwargs):
            calls.append(cmd)
            return _FakeProc(1, "", "err")

        monkeypatch.setattr("rebrew.toolchain.subprocess.run", _run)
        r = run_toolchain(spec, ["x.dpr"], workdir=tmp_path)
        assert r.backend == "host"
        assert not r.ok
        assert calls[0][0] == str(dcc)

    def test_no_backend_raises(self, tmp_path: Path, monkeypatch) -> None:
        _monkey_docker(monkeypatch, available=False, image=False)
        monkeypatch.setattr("rebrew.toolchain.shutil.which", lambda *a, **k: None)
        spec = ToolchainSpec(name="t", image="rebrew/t:latest", binary="nope")
        with pytest.raises(ToolchainError, match="no host binary"):
            run_toolchain(spec, [], workdir=tmp_path)


class TestCli:
    def test_list_registered_in_umbrella(self) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        result = CliRunner().invoke(umbrella, ["toolchain", "list", "--json"])
        assert result.exit_code == 0, result.output
        import json

        data = json.loads(result.stdout)
        assert {t["name"] for t in data["toolchains"]} >= {"msvc6", "delphi16"}

    def test_unknown_status_errors(self) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        result = CliRunner().invoke(umbrella, ["toolchain", "status", "nope"])
        assert result.exit_code != 0

    def test_pull_host_only_errors(self, monkeypatch) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: False)
        result = CliRunner().invoke(umbrella, ["toolchain", "pull", "gcc-pe"])
        assert result.exit_code == 2
        assert "host-only" in result.output

    def test_pull_unknown_errors(self) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        result = CliRunner().invoke(umbrella, ["toolchain", "pull", "nope"])
        assert result.exit_code == 2
        assert "unknown toolchain" in result.output

    def test_build_host_only_errors(self, monkeypatch) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        result = CliRunner().invoke(umbrella, ["toolchain", "build", "gcc-pe"])
        assert result.exit_code == 2
        assert "host-only" in result.output

    def test_build_missing_dockerfile_errors(self, monkeypatch) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        monkeypatch.setattr("rebrew.toolchain_cli.Path.exists", lambda self: False)
        result = CliRunner().invoke(umbrella, ["toolchain", "build", "watcom"])
        assert result.exit_code == 2
        assert "Dockerfile" in result.output
