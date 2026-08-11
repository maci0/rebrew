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

    def test_family_derived_from_image_tag(self) -> None:
        """The toolchain-images/ top-level dir is the unversioned family
        (Godbolt-style), derived from the image repository — never the
        version-encoded profile id (msvc1.52 -> msvc/, delphi16 ->
        delphi/)."""
        assert TOOLCHAINS["msvc6"].family == "msvc"
        assert TOOLCHAINS["msvc1.52"].family == "msvc"
        assert TOOLCHAINS["delphi16"].family == "delphi"
        assert TOOLCHAINS["watcom"].family == "watcom"
        # host-only spec: falls back to its name
        assert TOOLCHAINS["gcc-pe"].family == "gcc-pe"


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


class TestPullToolchain:
    """pull_toolchain treats locally-present images as a successful no-op
    (they are built via `toolchain build`, not pulled from a registry)."""

    def test_already_present_skips_docker_pull(self, monkeypatch) -> None:
        from rebrew.toolchain import pull_toolchain

        monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: True)
        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: True)
        called: list[str] = []
        monkeypatch.setattr(
            "rebrew.toolchain.subprocess.run",
            lambda *a, **k: called.append(a) or type("R", (), {"returncode": 0})(),
        )
        tag, was_present = pull_toolchain("msvc6")
        assert tag == "rebrew/msvc:6.0-linux-x64"
        assert was_present is True
        assert not called  # no docker pull subprocess for a local image

    def test_absent_image_does_pull(self, monkeypatch) -> None:
        from rebrew.toolchain import pull_toolchain

        monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: True)
        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: False)
        monkeypatch.setattr(
            "rebrew.toolchain.subprocess.run",
            lambda *a, **k: type("R", (), {"returncode": 0})(),
        )
        tag, was_present = pull_toolchain("msvc6")
        assert tag == "rebrew/msvc:6.0-linux-x64"
        assert was_present is False

    def test_cli_reports_already_present(self, monkeypatch) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: True)
        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: True)
        result = CliRunner().invoke(umbrella, ["toolchain", "pull", "msvc6", "--json"])
        assert result.exit_code == 0
        assert '"already_present": true' in result.output
        assert '"pulled": "rebrew/msvc:6.0-linux-x64"' in result.output
