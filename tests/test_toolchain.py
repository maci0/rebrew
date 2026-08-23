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
        assert calls[0][:4] == ["docker", "run", "--rm", "--network=none"]
        # Named container: the timeout path must be able to kill it (a killed
        # docker CLI alone leaves the container running under dockerd).
        assert calls[0][4] == "--name"
        assert calls[0][5].startswith("rebrew-")
        assert calls[0][6:10] == ["-v", f"{tmp_path.resolve()}:/work", "-w", "/work"]
        assert calls[0][10:12] == ["rebrew/t:latest", "cl"]
        assert calls[0][12:] == ["/c", "f.c"]

    def test_docker_entrypoint_image_passes_no_command(self, tmp_path: Path, monkeypatch) -> None:
        """image_binary=None means the image ENTRYPOINT is the compiler —
        no command is appended after the image tag (Godbolt convention)."""
        spec = ToolchainSpec(name="t", image="rebrew/t:latest", binary="wcc386")
        calls = _monkey_docker(monkeypatch)
        run_toolchain(spec, ["-zq", "f.c"], workdir=tmp_path)
        assert calls[0][11:] == ["-zq", "f.c"]

    def test_docker_uses_image_binary_shim(self, tmp_path: Path, monkeypatch) -> None:
        spec = ToolchainSpec(
            name="t", image="rebrew/t:latest", binary="DCC.EXE", image_binary="dcc"
        )
        calls = _monkey_docker(monkeypatch)
        run_toolchain(spec, ["hello.dpr"], workdir=tmp_path)
        assert calls[0][11] == "dcc"

    def test_wine_runtime_without_image_raises(self, tmp_path: Path, monkeypatch) -> None:
        """A wine-runtime spec without an image is not runnable — execution
        is docker-only for every Windows toolchain (no host wine path)."""
        spec = ToolchainSpec(
            name="t",
            image=None,
            binary="cl",
            runtime="wine",
            host_path=tmp_path / "vc",
            host_bin="Bin",
        )
        calls: list[list[str]] = []

        def _run(cmd, **kwargs):
            calls.append(cmd)
            return _FakeProc(0, "", "")

        monkeypatch.setattr("rebrew.toolchain.subprocess.run", _run)
        with pytest.raises(ToolchainError, match="no docker image"):
            run_toolchain(spec, ["/c", "t.c"], workdir=tmp_path)
        assert calls == [], "no subprocess may run for a wine spec without an image"

    def test_docker_timeout_kills_named_container(self, tmp_path: Path, monkeypatch) -> None:
        """A timed-out compile must kill its container by name: killing the
        docker CLI leaves the container running under dockerd, so a GA sweep
        would otherwise accumulate one hung wine process per timeout."""
        import subprocess as sp

        spec = ToolchainSpec(name="t", image="rebrew/t:latest", binary="cl", image_binary="cl")
        calls: list[list[str]] = []

        def _run(cmd, **kwargs):
            calls.append(list(cmd))
            if cmd[1] == "run":
                raise sp.TimeoutExpired(cmd, 300)
            return _FakeProc(0, "", "")

        monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: True)
        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: True)
        monkeypatch.setattr("rebrew.toolchain.subprocess.run", _run)

        with pytest.raises(ToolchainError, match="docker invocation failed"):
            run_toolchain(spec, ["/c", "f.c"], workdir=tmp_path, timeout=1)

        assert len(calls) == 2
        assert calls[0][4:6] == ["--name", calls[1][2]], "kill must target the run's container"
        assert calls[1][:2] == ["docker", "kill"]

    def test_docker_os_error_skips_kill(self, tmp_path: Path, monkeypatch) -> None:
        """No container exists when docker itself cannot be exec'd — the
        error path must not fire a kill."""
        spec = ToolchainSpec(name="t", image="rebrew/t:latest", binary="cl", image_binary="cl")
        calls: list[list[str]] = []

        def _run(cmd, **kwargs):
            calls.append(list(cmd))
            raise OSError("docker not found")

        monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: True)
        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: True)
        monkeypatch.setattr("rebrew.toolchain.subprocess.run", _run)

        with pytest.raises(ToolchainError, match="docker invocation failed"):
            run_toolchain(spec, ["/c", "f.c"], workdir=tmp_path)

        assert len(calls) == 1

    def test_native_runtime_without_image_uses_vendored_path(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """Native-Linux toolchains without an image (gcc-pe, watcom16 wcc)
        exec their vendored/PATH binary directly — they are not Windows
        binaries, so no wine glue is involved."""
        cl = tmp_path / "vc" / "bin" / "cl.exe"
        cl.parent.mkdir(parents=True)
        cl.write_bytes(b"MZ")
        spec = ToolchainSpec(
            name="t",
            image=None,
            binary="cl",
            runtime="native",
            host_path=tmp_path / "vc",
            host_bin="Bin",
        )
        calls: list[list[str]] = []

        def _run(cmd, **kwargs):
            calls.append(cmd)
            return _FakeProc(0, "", "")

        monkeypatch.setattr("rebrew.toolchain.subprocess.run", _run)
        r = run_toolchain(spec, ["/c", "t.c"], workdir=tmp_path)
        assert r.backend == "native"
        assert calls[0] == [str(cl), "/c", "t.c"]

    def test_missing_image_raises_with_build_hint(self, tmp_path: Path, monkeypatch) -> None:
        """A docker toolchain whose image is not built is a hard error that
        tells the user to build it — there is no host fallback anymore."""
        spec = ToolchainSpec(name="t", image="rebrew/t:latest", binary="cl")
        monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: True)
        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: False)
        with pytest.raises(ToolchainError, match="not built"):
            run_toolchain(spec, ["/c", "t.c"], workdir=tmp_path)

    def test_docker_unavailable_raises(self, tmp_path: Path, monkeypatch) -> None:
        """No docker daemon -> clear error before any invocation attempt."""
        spec = ToolchainSpec(name="t", image="rebrew/t:latest", binary="cl")
        monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: False)
        with pytest.raises(ToolchainError, match="docker is not available"):
            run_toolchain(spec, ["/c", "t.c"], workdir=tmp_path)


class TestCli:
    def test_list_registered_in_umbrella(self) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        result = CliRunner().invoke(umbrella, ["toolchain", "list", "--json"])
        assert result.exit_code == 0, result.output
        import json

        data = json.loads(result.stdout)
        assert {t["name"] for t in data["toolchains"]} >= {
            "msvc5",
            "msvc420",
            "msvc6",
            "delphi16",
        }

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

    def test_detect_json_standalone(self, tmp_path: Path, monkeypatch) -> None:
        """`toolchain detect` works without a project; no profile keys in JSON."""
        import json

        from typer.testing import CliRunner

        from rebrew.main import app as umbrella
        from rebrew.toolchain_detect import ToolchainInfo

        bin_path = tmp_path / "x.exe"
        bin_path.write_bytes(b"MZ\x90\x00")
        monkeypatch.chdir(tmp_path)  # no rebrew-project.toml here — standalone mode
        info = ToolchainInfo(
            family="msvc",
            version_hint="MSVC 6.0",
            confidence="high",
            detected_by="die",
            evidence=["Compiler: Microsoft Visual C/C++"],
        )
        monkeypatch.setattr("rebrew.toolchain_detect.detect_toolchain", lambda p: info)
        result = CliRunner().invoke(umbrella, ["toolchain", "detect", str(bin_path), "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert data["family"] == "msvc"
        assert data["version_hint"] == "MSVC 6.0"
        assert data["confidence"] == "high"
        assert "msvc6" in data["compatible_profiles"]
        assert "profile" not in data and "aligned" not in data

    def test_detect_alignment_mismatch(self, tmp_path: Path, monkeypatch) -> None:
        """A project profile that cannot byte-match the detection is flagged."""
        import json

        from typer.testing import CliRunner

        from rebrew.main import app as umbrella
        from rebrew.toolchain_detect import ToolchainInfo

        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\nname = "t"\ndefault_target = "main"\n'
            '[targets."main"]\nbinary = "original/x.exe"\n'
            '[compiler]\nprofile = "msvc6"\n'
        )
        bin_path = tmp_path / "x.exe"
        bin_path.write_bytes(b"MZ\x90\x00")
        monkeypatch.chdir(tmp_path)
        info = ToolchainInfo(
            family="msvc",
            version_hint="16-bit MSVC-style NE",
            confidence="medium",
            detected_by="heuristics",
            arch="x86_16",
        )
        monkeypatch.setattr("rebrew.toolchain_detect.detect_toolchain", lambda p: info)
        result = CliRunner().invoke(umbrella, ["toolchain", "detect", "x.exe", "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert data["profile"] == "msvc6"
        assert data["aligned"] is False
        assert "msvc1.52" in data["explanation"]

    def test_detect_missing_binary_errors(self, tmp_path: Path, monkeypatch) -> None:
        import json

        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(umbrella, ["toolchain", "detect", "nope.exe", "--json"])
        assert result.exit_code == 2
        data = json.loads(result.stdout)
        assert data["error"] and data["code"] == 2

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
        assert tag == "rebrew/msvc:6.0-win32"
        assert was_present is True
        assert not called  # no docker pull subprocess for a local image

    def test_absent_image_does_pull(self, monkeypatch) -> None:
        from rebrew.toolchain import pull_toolchain

        monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: True)
        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: False)
        # Model the swap's inspect calls: backup inspect fails (absent),
        # then the pull succeeds and the verify inspect resolves a new id.
        calls = {"n": 0}

        def _run(cmd, **kwargs):
            if cmd[:2] == ["docker", "image"]:
                calls["n"] += 1
                if calls["n"] == 1:
                    return type("R", (), {"returncode": 1, "stdout": "", "stderr": ""})()
                return type("R", (), {"returncode": 0, "stdout": "sha256:NEW\n", "stderr": ""})()
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

        monkeypatch.setattr("rebrew.toolchain.subprocess.run", _run)
        tag, was_present = pull_toolchain("msvc6")
        assert tag == "rebrew/msvc:6.0-win32"
        assert was_present is False

    def test_cli_reports_already_present(self, monkeypatch) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: True)
        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: True)
        result = CliRunner().invoke(umbrella, ["toolchain", "pull", "msvc6", "--json"])
        assert result.exit_code == 0
        assert '"already_present": true' in result.output
        assert '"pulled": "rebrew/msvc:6.0-win32"' in result.output


class TestSwapToolchainImage:
    """swap_toolchain_image: backup→swap→rollback for toolchain images.

    A failed build/pull must leave the previously registered image under the
    tag (or restore it if the tag was left dangling) — never a half-registered
    state.
    """

    TAG = "rebrew/msvc:6.0-win32"

    def _fake_docker(self, monkeypatch, initial_id: str | None):
        """Fake docker with a mutable tag→id mapping; returns (state, calls)."""
        from types import SimpleNamespace

        state: dict[str, str | None] = {"id": initial_id}
        calls: list[list[str]] = []

        def _run(cmd, **kwargs):
            calls.append(cmd)
            if cmd[:2] == ["docker", "image"]:
                if state["id"] is None:
                    return SimpleNamespace(returncode=1, stdout="", stderr="")
                return SimpleNamespace(returncode=0, stdout=state["id"] + "\n", stderr="")
            if cmd[:2] == ["docker", "tag"]:
                state["id"] = cmd[2]
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: True)
        monkeypatch.setattr("rebrew.toolchain.subprocess.run", _run)
        return state, calls

    def test_failed_op_leaves_previous_image(self, monkeypatch) -> None:
        """A normal failure (docker keeps the old tag) needs no restore."""
        from rebrew.toolchain import ToolchainError, swap_toolchain_image

        state, calls = self._fake_docker(monkeypatch, "sha256:OLD")

        def _failing_op() -> None:
            raise ToolchainError("build exploded")

        with pytest.raises(ToolchainError, match="build exploded"):
            swap_toolchain_image(self.TAG, _failing_op)
        assert state["id"] == "sha256:OLD"
        assert not any(c[:2] == ["docker", "tag"] for c in calls)

    def test_failed_op_rolls_back_dangling_tag(self, monkeypatch) -> None:
        """A failure that left the tag dangling restores the backup image."""
        from rebrew.toolchain import ToolchainError, swap_toolchain_image

        state, calls = self._fake_docker(monkeypatch, "sha256:OLD")

        def _bad_pull() -> None:
            state["id"] = None  # the failed pull left the tag dangling
            raise ToolchainError("pull died mid-way")

        with pytest.raises(ToolchainError, match="pull died mid-way"):
            swap_toolchain_image(self.TAG, _bad_pull)
        assert state["id"] == "sha256:OLD"  # rollback re-tagged the backup
        assert any(c[:2] == ["docker", "tag"] for c in calls)

    def test_success_returns_new_id(self, monkeypatch) -> None:
        from rebrew.toolchain import swap_toolchain_image

        state, calls = self._fake_docker(monkeypatch, "sha256:OLD")

        def _ok_op() -> None:
            state["id"] = "sha256:NEW"  # docker's tag-on-success is the swap

        new_id = swap_toolchain_image(self.TAG, _ok_op)
        assert new_id == "sha256:NEW"
        assert not any(c[:2] == ["docker", "tag"] for c in calls)

    def test_success_but_tag_unresolvable_raises_and_restores(self, monkeypatch) -> None:
        from rebrew.toolchain import ToolchainError, swap_toolchain_image

        state, calls = self._fake_docker(monkeypatch, "sha256:OLD")

        def _ok_but_dangling() -> None:
            state["id"] = None

        with pytest.raises(ToolchainError, match="does not resolve"):
            swap_toolchain_image(self.TAG, _ok_but_dangling)
        assert state["id"] == "sha256:OLD"
        assert any(c[:2] == ["docker", "tag"] for c in calls)

    def test_no_backup_failure_propagates_without_retag(self, monkeypatch) -> None:
        from rebrew.toolchain import ToolchainError, swap_toolchain_image

        state, calls = self._fake_docker(monkeypatch, None)

        def _failing_op() -> None:
            raise ToolchainError("nope")

        with pytest.raises(ToolchainError, match="nope"):
            swap_toolchain_image(self.TAG, _failing_op)
        assert state["id"] is None
        assert not any(c[:2] == ["docker", "tag"] for c in calls)

    def test_no_backup_success_returns_id(self, monkeypatch) -> None:
        from rebrew.toolchain import swap_toolchain_image

        state, _calls = self._fake_docker(monkeypatch, None)

        def _ok_op() -> None:
            state["id"] = "sha256:FRESH"

        assert swap_toolchain_image(self.TAG, _ok_op) == "sha256:FRESH"


class TestResolveBinaryCaseInsensitive:
    """DOS-era vendored trees use uppercase subdirs (BIN) — the resolver
    must match host_bin case-insensitively (MSVC 1.52 regression)."""

    def test_uppercase_bin_resolves(self, tmp_path: Path) -> None:
        from rebrew.toolchain import ToolchainSpec, _resolve_binary

        (tmp_path / "BIN").mkdir()
        (tmp_path / "BIN" / "CL.EXE").write_bytes(b"")
        spec = ToolchainSpec(
            name="msvc1.52",
            image=None,
            binary="CL.EXE",
            host_bin="Bin",  # spec says Bin, disk says BIN
            host_path=str(tmp_path),
        )
        resolved = _resolve_binary(spec)
        assert resolved == str(tmp_path / "BIN" / "CL.EXE")

    def test_exact_case_still_works(self, tmp_path: Path) -> None:
        from rebrew.toolchain import ToolchainSpec, _resolve_binary

        (tmp_path / "Bin").mkdir()
        (tmp_path / "Bin" / "cl").write_bytes(b"")
        spec = ToolchainSpec(
            name="watcom",
            image=None,
            binary="cl",
            host_bin="Bin",
            host_path=str(tmp_path),
        )
        assert _resolve_binary(spec) == str(tmp_path / "Bin" / "cl")

    def test_exe_suffix_tolerated_in_subdir(self, tmp_path: Path) -> None:
        """binary="cl" must resolve CL.EXE in the host_bin subdir (vendored
        Windows trees store the .exe; specs name the bare binary)."""
        from rebrew.toolchain import ToolchainSpec, _resolve_binary

        (tmp_path / "Bin").mkdir()
        (tmp_path / "Bin" / "CL.EXE").write_bytes(b"")
        spec = ToolchainSpec(
            name="msvc5",
            image=None,
            binary="cl",
            host_bin="Bin",
            host_path=str(tmp_path),
        )
        assert _resolve_binary(spec) == str(tmp_path / "Bin" / "CL.EXE")

    def test_exe_suffix_tolerated_at_root(self, tmp_path: Path) -> None:
        """binary="cl" must also resolve cl.exe directly in host_path."""
        from rebrew.toolchain import ToolchainSpec, _resolve_binary

        (tmp_path / "cl.exe").write_bytes(b"")
        spec = ToolchainSpec(
            name="msvc5",
            image=None,
            binary="cl",
            host_path=str(tmp_path),
        )
        assert _resolve_binary(spec) == str(tmp_path / "cl.exe")

    def test_status_uses_shared_resolver(self, monkeypatch, tmp_path: Path) -> None:
        """toolchain status must agree with _resolve_binary (case-insensitive
        host_bin) instead of its own case-sensitive path check."""
        import json

        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        (tmp_path / "BIN").mkdir()
        (tmp_path / "BIN" / "CL.EXE").write_bytes(b"")
        monkeypatch.setattr(
            "rebrew.toolchain.TOOLCHAINS",
            {
                "msvc1.52": __import__(
                    "rebrew.toolchain", fromlist=["ToolchainSpec"]
                ).ToolchainSpec(
                    name="msvc1.52",
                    image=None,
                    binary="CL.EXE",
                    host_bin="Bin",
                    host_path=str(tmp_path),
                )
            },
        )
        result = CliRunner().invoke(umbrella, ["toolchain", "status", "msvc1.52", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["host_binary_present"] is True


class TestDockerOnlyGuard:
    """run_toolchain is docker-only: every Windows/DOS toolchain (wine- and
    dosbox-runtime) must fail with a clear build hint when its image is
    absent — never exec the vendored binary directly (EACCES / Exec format
    error).  Native-Linux specs without an image (gcc-pe, watcom16 wcc)
    keep the direct vendored-host path: they are not Windows binaries."""

    def test_msvc152_image_missing_raises(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.toolchain import TOOLCHAINS, ToolchainError, run_toolchain

        monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: True)
        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: False)
        with pytest.raises(ToolchainError, match="not built"):
            run_toolchain(TOOLCHAINS["msvc1.52"], ["t.c", "/O1"], workdir=tmp_path)

    def test_delphi16_image_missing_raises(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.toolchain import TOOLCHAINS, ToolchainError, run_toolchain

        monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: True)
        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: False)
        with pytest.raises(ToolchainError, match="not built"):
            run_toolchain(TOOLCHAINS["delphi16"], ["hello.dpr"], workdir=tmp_path)

    def test_watcom16_native_path_unaffected(self, tmp_path: Path, monkeypatch) -> None:
        """watcom16 has no image (native Linux wcc) — the direct vendored
        binary path still applies; only image-less wine/dosbox specs are
        blocked by the docker-only guard."""
        from rebrew.toolchain import TOOLCHAINS, run_toolchain

        spec = TOOLCHAINS["watcom16"]
        monkeypatch.setattr(
            "rebrew.toolchain._resolve_binary",
            lambda spec: (_ for _ in ()).throw(ToolchainError("no native binary")),
        )
        with pytest.raises(ToolchainError, match="no native binary"):
            run_toolchain(spec, ["-zq", "f.c"], workdir=tmp_path)


class TestVc98Wrap:
    """MSVC 6.0's classic master layout is the VC98/ tree (every legacy
    tools/MSVC600/VC98/... reference expects it).  The old decomp.me
    tarball was flat, so vendor wrapped it via vc98_wrap; the current
    archaic-msvc source (msvc600) already carries VC98/ at the top."""

    def test_msvc6_source_needs_no_wrap(self) -> None:
        from rebrew.toolchain import _SOURCES

        # archaic-msvc/msvc600 ships VC98/ at the top level already, so no
        # wrap step is needed (the old decomp.me tarball was flat).
        assert _SOURCES["msvc6"].vc98_wrap is False

    def test_other_sources_do_not_wrap(self) -> None:
        from rebrew.toolchain import _SOURCES

        for name, src in _SOURCES.items():
            if name != "msvc6":
                assert src.vc98_wrap is False, name

    def test_old_msvc_sources_pinned(self) -> None:
        """msvc400/msvc420/msvc5 must have pinned, sha256-verified sources:
        their host trees are smoke-gated for byte-reproducibility, so a fresh
        clone must be able to reproduce them via `rebrew toolchain vendor`
        (they were vendored but unpinnable before)."""
        from rebrew.toolchain import _SOURCES

        for name, expected_dir in (
            ("msvc400", "msvc/4.0-win32"),
            ("msvc420", "msvc/4.2-win32"),
            ("msvc5", "msvc/5.0-win32"),
        ):
            src = _SOURCES[name]
            assert src.host_dir == expected_dir, name
            assert src.url.startswith("https://") and src.sha256, name
            assert len(src.sha256) == 64, name
            assert src.layout == "tar-strip1", name


class TestCompatLinksRemoved:
    """The legacy `tools/<name> → toolchain/<dir>` compat symlinks are gone:
    the vendored trees now live in the rebrew-toolchains checkout, so there
    is nothing to alias and vendor must not recreate them."""

    def test_ensure_compat_links_no_longer_exists(self) -> None:
        import rebrew.toolchain_cli as cli

        assert not hasattr(cli, "ensure_compat_links")
        assert not hasattr(cli, "_COMPAT_LINK_ALIASES")

    def test_toolchain_dir_is_gitignored(self) -> None:
        """A stray/accidentally-recreated repo `toolchain/` must never stage
        (the build source lives in the rebrew-toolchains checkout).  Docker
        bind-mount tests may recreate the empty dir as a side effect — the
        guarantee is that git ignores it."""
        import subprocess

        repo = Path(__file__).resolve().parents[1]
        r = subprocess.run(
            ["git", "check-ignore", "toolchain/"],
            capture_output=True,
            text=True,
            cwd=repo,
        )
        assert r.returncode == 0, (
            "toolchain/ must be gitignored — rebrew no longer vendors "
            "toolchain build source in-repo"
        )


class TestToolchainsRepoResolver:
    """_toolchains_repo() resolves the rebrew-toolchains build source: the
    sibling checkout by default, REBREW_TOOLCHAINS_DIR otherwise."""

    def test_default_is_sibling(self) -> None:
        from rebrew.toolchain import _toolchains_repo

        repo = Path(__file__).resolve().parents[1]
        assert _toolchains_repo() == repo.parent / "rebrew-toolchains"

    def test_env_override(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.toolchain import _toolchains_repo

        override = tmp_path / "my-toolchains"
        monkeypatch.setenv("REBREW_TOOLCHAINS_DIR", str(override))
        assert _toolchains_repo() == override

    def test_require_missing_raises_actionable(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.toolchain import ToolchainError, _require_toolchains_repo

        monkeypatch.setenv("REBREW_TOOLCHAINS_DIR", str(tmp_path / "nope"))
        with pytest.raises(ToolchainError, match="rebrew-toolchains"):
            _require_toolchains_repo()

    def test_in_repo_tarballs_rebased_to_checkout(self) -> None:
        """The 16-bit _SOURCES in_repo paths are now relative to the
        rebrew-toolchains checkout root (no toolchain/ prefix), sitting in
        the same <family>/<ver>-<arch> dir as the Dockerfile they feed."""
        from rebrew.toolchain import _SOURCES, _toolchains_repo

        repo = _toolchains_repo()
        for name in ("msvc15", "msvc10", "msvc1.52", "delphi16", "tc20", "tc16"):
            src = _SOURCES[name]
            assert src.in_repo, name
            assert not src.in_repo.startswith("toolchain/"), name
            assert (repo / src.in_repo).parent == repo / src.host_dir, name


class TestDockerfileSanity:
    """The toolchain Dockerfiles must stay parseable — a prior commit that
    added OCI labels to toolchain/base/Dockerfile accidentally deleted the
    leading `RUN dpkg --add-architecture i386` line, leaving a lone
    `&& apt-get update` that broke `rebrew toolchain build` for EVERY
    image (build_cmd rebuilds base first).  Static, CI-safe checks (no
    docker required) pin the structure.  The Dockerfiles live in the
    sibling rebrew-toolchains checkout now."""

    _REPO: Path | None = None

    @classmethod
    def _repo(cls) -> Path:
        if cls._REPO is None:
            from rebrew.toolchain import _toolchains_repo

            cls._REPO = _toolchains_repo()
        return cls._REPO

    def _read(self, rel: str) -> str:
        return (self._repo() / rel).read_text(encoding="utf-8")

    def test_base_apt_block_has_run(self) -> None:
        text = self._read("base/Dockerfile")
        # The apt block must be a single RUN continuation — a lone
        # `&& apt-get` (missing RUN) is a parse error.
        idx = text.index("&& apt-get update")
        prefix = text[:idx]
        assert "RUN dpkg --add-architecture i386" in prefix, (
            "base Dockerfile apt block lost its RUN prefix"
        )

    def test_no_lone_continuation_after_label_blocks(self) -> None:
        """Every tracked Dockerfile: any `&& ` line must be preceded (within
        the same block) by a `RUN ` line — the OCI-label insertion pattern
        dropped RUN prefixes in some files."""
        dockerfiles = sorted((self._repo()).rglob("Dockerfile"))
        assert dockerfiles, "no Dockerfiles found in the rebrew-toolchains checkout"
        for f in dockerfiles:
            if "linux-x64" in str(f):
                continue
            lines = f.read_text(encoding="utf-8").splitlines()
            in_run = False
            for ln in lines:
                if ln.startswith("RUN "):
                    in_run = True
                    continue
                if ln.strip().startswith("&& ") and not in_run:
                    raise AssertionError(f"{f.relative_to(self._repo())}: '&&' without RUN: {ln!r}")
                if ln.strip() and not ln.startswith((" ", "\t")) and not ln.startswith("#"):
                    in_run = False  # new instruction (RUN/LABEL/ENV/COPY/...)

    def test_every_image_spec_has_dockerfile_in_checkout(self) -> None:
        """Every image-backed toolchain must have its Dockerfile in the
        rebrew-toolchains checkout — a fresh clone must be able to rebuild
        the image (tc16/tc20 images were built from UNTRACKED Dockerfiles,
        silently unreproducible)."""
        from rebrew.toolchain import TOOLCHAINS

        repo = self._repo()
        missing = []
        for name, spec in TOOLCHAINS.items():
            if spec.image is None:
                continue
            tag, verarch = spec.image.rsplit(":", 1)
            df = repo / spec.family / verarch / "Dockerfile"
            if not df.is_file():
                missing.append(f"{name} ({df.relative_to(repo)})")
        assert not missing, (
            "image-backed toolchains without a Dockerfile in the "
            "rebrew-toolchains checkout (a fresh clone cannot rebuild "
            "them): " + ", ".join(missing)
        )


class TestSmokePrintGoldens:
    """`toolchain smoke --print-goldens` recomputes the masked hashes
    without comparing (the regeneration path for _SMOKE_GOLDEN after a
    toolchain source change)."""

    def test_print_goldens_emits_masked_hash(self, tmp_path: Path, monkeypatch, capsys) -> None:
        import hashlib
        import json
        import subprocess
        from types import SimpleNamespace

        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        obj = b"OBJ" + b"\x01\x02\x03\x04" + b"TAIL"

        def _fake_run(cmd, **kwargs):
            # docker run ... -v <host>:/work ... image /c t.c → writes the
            # object into /work (the mounted host workdir).
            from pathlib import Path

            v = cmd[cmd.index("-v") + 1]
            (Path(v.split(":")[0]) / "t.obj").write_bytes(obj)
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        monkeypatch.setattr(subprocess, "run", _fake_run)
        result = CliRunner().invoke(
            umbrella, ["toolchain", "smoke", "msvc6", "--print-goldens", "--json"]
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert set(payload) == {"goldens"}
        # msvc6 mask is (4,8): the TimeDateStamp is zeroed before hashing.
        masked = bytearray(obj)
        masked[4:8] = b"\x00" * 4
        assert payload["goldens"]["msvc6"] == hashlib.sha256(bytes(masked)).hexdigest()


class TestPullToolchainHint:
    """pull on an absent locally-built image must point at `toolchain
    build` — rebrew images are built from pinned sources, not on a
    registry, so a raw docker-pull failure is a dead end."""

    def test_pull_failure_suggests_build(self, monkeypatch) -> None:
        from types import SimpleNamespace

        from rebrew.toolchain import ToolchainError, pull_toolchain

        def _fake_run(cmd, **kwargs):
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"pull access denied")

        monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: True)
        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: False)
        monkeypatch.setattr("rebrew.toolchain.subprocess.run", _fake_run)
        with pytest.raises(ToolchainError, match="toolchain build msvc420"):
            pull_toolchain("msvc420")
