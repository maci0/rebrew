"""Tests for rebrew.cmake_tc — the docker CMake toolchain bridge.

Covers the argv translation (ported from the project's wine wrapper), the
project-root discovery, the toolchain-file generator, and the docker
command construction (mocked runner — no docker is executed here).
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.cmake_tc import (
    _TOOL_MODES,
    _docker_run,
    _docker_user_args,
    _ensure_wineprefix,
    _exclusive_lock,
    _is_host_path,
    _rewrite_args,
    _to_w,
    generate_toolchain_file,
)
from rebrew.config import walk_up_to_root
from rebrew.toolchain import TOOLCHAINS


def test_to_w() -> None:
    assert _to_w("/home/maci/x.c") == r"Z:\home\maci\x.c"
    assert _to_w("x.c") == "x.c"
    assert _to_w("") == ""


class TestRewriteArgsCl:
    def test_absolute_include_and_source(self) -> None:
        out = _rewrite_args(
            "cl",
            ["/nologo", "/I/home/maci/inc", "/Fo/tmp/out.obj", "/home/maci/src.c"],
        )
        assert "/I" + r"Z:\home\maci\inc" in out
        assert "/Fo" + r"Z:\tmp\out.obj" in out
        assert r"Z:\home\maci\src.c" in out

    def test_relative_fo_becomes_absolute(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir("/tmp")
        out = _rewrite_args("cl", ["/Fodir/out.obj"])
        assert out[0] == "/Fo" + r"Z:\tmp\dir\out.obj"

    def test_flags_pass_through(self) -> None:
        out = _rewrite_args("cl", ["/O2", "/Gd", "/DREBREW_ALLOW_NAKED", "/c"])
        assert out == ["/O2", "/Gd", "/DREBREW_ALLOW_NAKED", "/c"]

    def test_absolute_path_outside_legacy_prefixes(self) -> None:
        """Any absolute host path converts — not just /home, /tmp, /gamatcher."""
        out = _rewrite_args("cl", ["/nologo", "/c", "/srv/decomp/src.c"])
        assert out == ["/nologo", "/c", r"Z:\srv\decomp\src.c"]


class TestIsHostPath:
    def test_multi_segment_paths_always_convert(self) -> None:
        assert _is_host_path("/srv/build/x.obj")
        assert _is_host_path("/mnt/data/inc/header.h")

    def test_single_segment_flag_is_not_a_path(self) -> None:
        assert not _is_host_path("/O2")
        assert not _is_host_path("/c")
        assert not _is_host_path("/INCREMENTAL:NO")

    def test_root_level_needs_existence(self, tmp_path: Path) -> None:
        assert not _is_host_path("/definitely-not-a-real-file")
        existing = tmp_path / "marker"
        existing.write_text("", encoding="utf-8")
        assert _is_host_path(str(existing))

    def test_relative_and_empty_pass_through(self) -> None:
        assert not _is_host_path("x.c")
        assert not _is_host_path("")
        assert not _is_host_path("/")


class TestRewriteArgsLink:
    def test_output_and_libpaths(self) -> None:
        out = _rewrite_args(
            "link",
            ["/OUT:/home/maci/server.dll", "/LIBPATH:/opt/lib", "/home/maci/a.obj"],
        )
        assert "/OUT:" + r"Z:\home\maci\server.dll" in out
        assert "/LIBPATH:" + r"Z:\opt\lib" in out
        assert r"Z:\home\maci\a.obj" in out

    def test_absolute_path_outside_legacy_prefixes(self) -> None:
        """Inputs outside /home,/tmp,/gamatcher still convert (any project root)."""
        out = _rewrite_args("link", ["/MACHINE:X86", "/srv/decomp/b.obj"])
        assert out == ["/MACHINE:X86", r"Z:\srv\decomp\b.obj"]

    def test_case_insensitive_flags(self) -> None:
        out = _rewrite_args("link", ["/out:/home/x.dll", "/pdb:/home/x.pdb"])
        assert "/OUT:" + r"Z:\home\x.dll" in out
        assert "/PDB:" + r"Z:\home\x.pdb" in out


class TestRewriteArgsLib:
    def test_out_and_members(self) -> None:
        out = _rewrite_args("lib", ["/OUT:/home/x.lib", "/home/maci/a.obj"])
        assert "/OUT:" + r"Z:\home\x.lib" in out
        assert r"Z:\home\maci\a.obj" in out


def test_find_project_root(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    (proj / "build").mkdir(parents=True)
    (proj / "rebrew-project.toml").write_text("", encoding="utf-8")
    assert walk_up_to_root(proj / "build") == proj
    assert walk_up_to_root(proj) == proj
    assert walk_up_to_root(tmp_path / "elsewhere") is None


def test_find_project_root_rejects_directory_marker(tmp_path: Path) -> None:
    """A directory named like the marker file must not satisfy the search —
    the marker has to be a regular file."""
    (tmp_path / "rebrew-project.toml").mkdir()
    assert walk_up_to_root(tmp_path) is None


def test_tool_modes_dispatch() -> None:
    assert _TOOL_MODES == {
        "rebrew-cmake-cl": "cl",
        "rebrew-cmake-link": "link",
        "rebrew-cmake-lib": "lib",
    }


class TestDockerUserArgs:
    def test_posix_hosts_pass_uid_gid(self) -> None:
        """Capability probe: --user only where the host exposes unix ids."""
        args = _docker_user_args()
        if hasattr(os, "getuid") and hasattr(os, "getgid"):
            assert args == ["--user", f"{os.getuid()}:{os.getgid()}"]
        else:
            assert args == []


class TestExclusiveLock:
    def test_released_after_exit(self, tmp_path: Path) -> None:
        lock_path = tmp_path / ".lock"
        with _exclusive_lock(lock_path):
            pass
        with _exclusive_lock(lock_path):
            pass  # second acquisition must succeed (no leaked handle)

    def test_excludes_concurrent_holder(self, tmp_path: Path) -> None:
        import fcntl

        lock_path = tmp_path / ".lock"
        with (
            _exclusive_lock(lock_path),
            open(lock_path) as other,
            pytest.raises(OSError),
        ):
            fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_docker_run_builds_command(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """_docker_run serializes on the prefix lock and builds the docker argv."""
    proj = tmp_path / "proj"
    (proj / "build").mkdir(parents=True)
    (proj / "rebrew-project.toml").write_text("", encoding="utf-8")
    monkeypatch.chdir(proj / "build")

    prefix = tmp_path / "prefix"
    monkeypatch.setenv("REBREW_WINEPREFIX", str(prefix))

    calls: list[list[str]] = []
    returncodes = [0, 3]

    def fake_run(cmd: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append(cmd)
        return SimpleNamespace(returncode=returncodes[len(calls) - 1], stdout="", stderr="")

    monkeypatch.setattr("rebrew.cmake_tc.subprocess.run", fake_run)

    spec = TOOLCHAINS["msvc6"]
    rc = _docker_run(spec, "cl", ["/c", "x.c"])
    assert rc == 3

    # First invocation initializes the shared wineprefix exactly once.
    init_cmd, run_cmd = calls
    assert init_cmd[init_cmd.index("--entrypoint") + 1] == "/usr/bin/wine"
    assert init_cmd[-2:] == ["wineboot", "-u"]
    if hasattr(os, "getuid"):
        user = f"{os.getuid()}:{os.getgid()}"
        assert init_cmd[init_cmd.index("--user") + 1] == user
        assert run_cmd[run_cmd.index("--user") + 1] == user

    # Second invocation runs CL.EXE from the image's tool tree with the
    # INCLUDE/LIB env pointing at that same tree.
    assert run_cmd[run_cmd.index("--entrypoint") + 1] == "/usr/bin/wine"
    assert run_cmd[run_cmd.index("--entrypoint") + 2] == spec.image
    tool = run_cmd[run_cmd.index("--entrypoint") + 3]
    assert tool == "/opt/msvc6.0/VC98/Bin/CL.EXE"
    env_args = [run_cmd[i + 1] for i in range(len(run_cmd) - 1) if run_cmd[i] == "-e"]
    env_pairs = dict(arg.split("=", 1) for arg in env_args)
    assert env_pairs["WINEPREFIX"] == str(prefix)
    assert env_pairs["XDG_CACHE_HOME"] == f"{prefix}/xdg-cache"
    assert env_pairs["INCLUDE"] == r"Z:\opt\msvc6.0\VC98\Include"
    assert env_pairs["LIB"] == r"Z:\opt\msvc6.0\VC98\Lib"
    # Both critical sections take their sidecar lock under the prefix.
    assert (prefix / ".init.lock").exists()
    assert (prefix / ".run.lock").exists()


def _chdir_project(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    (proj / "build").mkdir(parents=True)
    (proj / "rebrew-project.toml").write_text("", encoding="utf-8")
    monkeypatch.chdir(proj / "build")
    prefix = tmp_path / "prefix"
    monkeypatch.setenv("REBREW_WINEPREFIX", str(prefix))
    return prefix


def test_docker_run_timeout_kills_container(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A timed-out wine compile is killed by container name: killing the
    docker CLI alone leaves the container running under dockerd, leaking one
    hung wine process per timeout."""
    import subprocess as sp

    _chdir_project(monkeypatch, tmp_path)
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        if "wineboot" not in cmd:
            raise sp.TimeoutExpired(cmd, 3600)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("rebrew.cmake_tc.subprocess.run", fake_run)

    spec = TOOLCHAINS["msvc6"]
    with pytest.raises(sp.TimeoutExpired):
        _docker_run(spec, "cl", ["/c", "x.c"])

    init_cmd, run_cmd, kill_cmd = calls
    assert init_cmd[-2:] == ["wineboot", "-u"]
    assert kill_cmd[:2] == ["docker", "kill"]
    assert kill_cmd[2] == run_cmd[run_cmd.index("--name") + 1]


def test_wineprefix_init_timeout_kills_container(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A hung wineboot is killed by container name before the error exit."""
    import subprocess as sp

    import typer

    _chdir_project(monkeypatch, tmp_path)
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        if "wineboot" in cmd:
            raise sp.TimeoutExpired(cmd, 300)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("rebrew.cmake_tc.subprocess.run", fake_run)

    with pytest.raises(typer.Exit):
        _ensure_wineprefix(Path(os.environ["REBREW_WINEPREFIX"]), TOOLCHAINS["msvc6"])

    assert len(calls) == 2
    assert calls[1][:2] == ["docker", "kill"]


def test_generate_toolchain_file(tmp_path: Path) -> None:
    spec = TOOLCHAINS["msvc6"]
    out = generate_toolchain_file(spec, tmp_path)
    assert out.name == "toolchain-msvc6-docker.cmake"
    text = out.read_text(encoding="utf-8")
    assert 'set(CMAKE_C_COMPILER "rebrew-cmake-cl")' in text
    assert 'set(CMAKE_LINKER "rebrew-cmake-link")' in text
    assert 'set(CMAKE_AR "rebrew-cmake-lib")' in text
    assert spec.image in text  # type: ignore[arg-type]
    assert 'CMAKE_C_COMPILER_ID "MSVC"' in text
    assert 'CMAKE_C_OUTPUT_EXTENSION ".obj"' in text


def test_tc_main_dispatch_and_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """tc_main resolves the toolchain from the project toml and runs docker."""
    proj = tmp_path / "proj"
    (proj / "build").mkdir(parents=True)
    (proj / "rebrew-project.toml").write_text('[compiler]\nprofile = "msvc6"\n', encoding="utf-8")

    calls: list[tuple[str, list[str]]] = []

    def fake_docker_run(spec, mode: str, args: list[str]) -> int:
        calls.append((mode, args))
        return 7

    monkeypatch.setattr("rebrew.cmake_tc._docker_run", fake_docker_run)
    monkeypatch.setattr("rebrew.cmake_tc.sys.argv", ["rebrew-cmake-cl", "/c", "x.c"])
    monkeypatch.setattr("rebrew.cmake_tc.Path.cwd", lambda: proj / "build")
    with pytest.raises(SystemExit) as exc:
        import rebrew.cmake_tc as tc

        tc.tc_main()
    assert exc.value.code == 7
    assert calls == [("cl", ["/c", "x.c"])]
