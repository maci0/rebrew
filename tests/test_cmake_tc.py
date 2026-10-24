"""Tests for rebrew.cmake_tc — the docker CMake toolchain bridge.

Covers the argv translation (ported from the project's wine wrapper), the
project-root discovery, the toolchain-file generator, and the docker
command construction (mocked runner — no docker is executed here).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew import cmake_tc
from rebrew.cmake_tc import (
    ToolMode,
    _docker_run,
    _docker_user_args,
    _ensure_wineprefix,
    _is_host_path,
    _rewrite_args,
    _to_w,
    generate_toolchain_file,
)
from rebrew.compiler.toolchain import TOOLCHAINS
from rebrew.utils import file_lock
from rebrew.workspace import walk_up_to_root


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

    def test_relative_fo_becomes_absolute(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        out = _rewrite_args("cl", ["/Fodir/out.obj"])
        assert out[0] == "/Fo" + _to_w(str(tmp_path / "dir/out.obj"))

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

    @pytest.mark.parametrize(
        ("argument", "expected"),
        [
            ("/STUB:stub.exe", "/STUB:stub.exe"),
            ("/stub:build/stub.exe", "/STUB:build/stub.exe"),
            ("/Stub:/home/build dir/stub.exe", r"/STUB:Z:\home\build dir\stub.exe"),
        ],
    )
    def test_stub_path_keeps_linker_option(self, argument: str, expected: str) -> None:
        assert _rewrite_args("link", [argument]) == [expected]


class TestRewriteArgsLib:
    @pytest.mark.parametrize("flag", ["/OUT:", "/DEF:", "/LIST:", "/LIBPATH:"])
    def test_path_options(self, flag: str) -> None:
        assert _rewrite_args("lib", [flag + "build/input.def"]) == [flag + "build/input.def"]
        assert _rewrite_args("lib", [flag.lower() + "/tmp/input.def"]) == [
            flag + r"Z:\tmp\input.def"
        ]

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
    assert {mode.value for mode in ToolMode} == {"cl", "link", "lib"}


class TestDockerUserArgs:
    def test_posix_hosts_pass_uid_gid(self) -> None:
        """Capability probe: --user only where the host exposes unix ids."""
        args = _docker_user_args()
        if hasattr(os, "getuid") and hasattr(os, "getgid"):
            assert args == ["--user", f"{os.getuid()}:{os.getgid()}"]
        else:
            assert args == []


class TestFileLock:
    def test_released_after_exit(self, tmp_path: Path) -> None:
        fcntl = pytest.importorskip("fcntl")

        lock_path = tmp_path / ".lock"
        with file_lock(lock_path):
            assert lock_path.exists()
        # After the context exits the handle must be gone: a non-blocking
        # flock on a fresh fd must succeed (no leaked exclusive holder).
        with open(lock_path) as probe:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(probe, fcntl.LOCK_UN)
        with file_lock(lock_path):
            assert lock_path.exists()

    def test_excludes_concurrent_holder(self, tmp_path: Path) -> None:
        fcntl = pytest.importorskip("fcntl")

        lock_path = tmp_path / ".lock"
        with (
            file_lock(lock_path),
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

    spec = TOOLCHAINS["msvc-6.0"]
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


@pytest.mark.parametrize("mode", ["cl", "link", "lib"])
def test_source_date_epoch_freezes_tool_after_real_wineboot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str
) -> None:
    """Each driver uses the native clock helper; prefix initialization stays real."""
    _chdir_project(monkeypatch, tmp_path)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1071482016")
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("rebrew.cmake_tc.subprocess.run", fake_run)
    spec = TOOLCHAINS["msvc-6.0"]
    assert _docker_run(spec, mode, ["/nologo"]) == 0
    init, tool = calls
    assert not any(a.startswith("SOURCE_DATE_EPOCH=") for a in init)
    entry = tool.index("--entrypoint")
    assert tool[entry + 1 : entry + 4] == [
        "/usr/local/bin/rebrew-clock",
        spec.image,
        "/usr/bin/wine",
    ]
    assert tool[entry + 4 :] == [f"{spec.tool_root}/{mode.upper()}.EXE", "/nologo"]
    assert "SOURCE_DATE_EPOCH=1071482016" in tool[:entry]


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

    spec = TOOLCHAINS["msvc-6.0"]
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
        _ensure_wineprefix(Path(os.environ["REBREW_WINEPREFIX"]), TOOLCHAINS["msvc-6.0"])

    assert len(calls) == 2
    assert calls[1][:2] == ["docker", "kill"]


@pytest.mark.parametrize("failure", ["response", "lock", "spawn"])
def test_docker_run_does_not_kill_before_launch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    """Preparation/spawn failures cannot leave a container running."""
    prefix = _chdir_project(monkeypatch, tmp_path)
    prefix.mkdir()
    (prefix / ".update-timestamp").touch()
    killed: list[str] = []
    launched: list[list[str]] = []

    def fail(*args: object, **kwargs: object) -> None:
        raise PermissionError("denied")

    def fail_spawn(cmd: list[str], **kwargs: object) -> None:
        launched.append(cmd)
        fail()

    monkeypatch.setattr("rebrew.cmake_tc.kill_container", killed.append)
    monkeypatch.setattr("rebrew.cmake_tc.subprocess.run", fail_spawn)
    if failure == "response":
        monkeypatch.setattr("rebrew.cmake_tc._rewrite_response_files", fail)
    elif failure == "lock":
        monkeypatch.setattr("rebrew.cmake_tc.file_lock", fail)
    with pytest.raises(PermissionError, match="denied"):
        _docker_run(TOOLCHAINS["msvc-6.0"], "cl", ["/c", "x.c"])
    assert killed == []
    assert len(launched) == (1 if failure == "spawn" else 0)


def test_generate_toolchain_file(tmp_path: Path) -> None:
    spec = TOOLCHAINS["msvc-6.0"]
    out = generate_toolchain_file(spec, tmp_path)
    assert out.name == "toolchain-msvc-6.0-docker.cmake"
    text = out.read_text(encoding="utf-8")
    assert spec.image in text
    assert 'CMAKE_C_COMPILER_ID "MSVC"' in text
    assert 'CMAKE_C_OUTPUT_EXTENSION ".obj"' in text


def test_generated_toolchain_binds_one_installation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """CMake retains absolute sibling drivers when PATH changes later."""
    cmake = shutil.which("cmake")
    if cmake is None:
        pytest.skip("CMake unavailable")
    drivers = tmp_path / "drivers"
    drivers.mkdir()
    modes = ["cl", "link", "lib"]
    driver = drivers / "rebrew"
    driver.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    driver.chmod(0o755)
    monkeypatch.setenv("PATH", str(drivers))
    toolchain = generate_toolchain_file(TOOLCHAINS["msvc-6.0"], tmp_path)
    paths = tmp_path / "paths.txt"
    script = tmp_path / "check.cmake"
    script.write_text(
        f'include("{toolchain}")\n'
        'set(ENV{PATH} "")\n'
        f'file(WRITE "{paths}" '
        '"${CMAKE_C_COMPILER}\n${CMAKE_LINKER}\n${CMAKE_AR}\n")\n',
        encoding="utf-8",
    )
    subprocess.run([cmake, "-P", str(script)], check=True, capture_output=True)
    assert paths.read_text(encoding="utf-8").splitlines() == [
        str(drivers / "rebrew") for _ in modes
    ]
    script.write_text(
        "set(CMAKE_FIND_USE_CMAKE_SYSTEM_PATH FALSE)\n"
        "set(CMAKE_FIND_USE_SYSTEM_ENVIRONMENT_PATH FALSE)\n"
        f'include("{toolchain}")\n',
        encoding="utf-8",
    )
    missing = subprocess.run([cmake, "-P", str(script)], capture_output=True, text=True)
    assert missing.returncode != 0
    assert "rebrew not found on PATH" in missing.stderr


@pytest.mark.parametrize("use_override", [False, True])
def test_generated_toolchain_replaces_a_dead_cached_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, use_override: bool
) -> None:
    cmake = shutil.which("cmake")
    if cmake is None:
        pytest.skip("CMake unavailable")
    driver = tmp_path / "rebrew"
    driver.write_text("#!/bin/sh\nexit 0\n")
    driver.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.delenv("REBREW_EXECUTABLE", raising=False)
    if use_override:
        monkeypatch.setenv("REBREW_EXECUTABLE", str(driver))
        monkeypatch.setenv("PATH", "")
    toolchain = generate_toolchain_file(TOOLCHAINS["msvc-6.0"], tmp_path)
    output = tmp_path / "chosen.txt"
    script = tmp_path / "review.cmake"
    script.write_text(
        'set(_REBREW_EXECUTABLE "/vanished/environment/rebrew" CACHE FILEPATH "")\n'
        f'include("{toolchain}")\n'
        f'file(WRITE "{output}" "${{CMAKE_C_COMPILER}}")\n'
    )
    result = subprocess.run([cmake, "-P", str(script)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert output.read_text() == str(driver)
    monkeypatch.setenv("REBREW_EXECUTABLE", str(tmp_path / "missing"))
    result = subprocess.run([cmake, "-P", str(script)], capture_output=True, text=True)
    assert result.returncode != 0
    assert "REBREW_EXECUTABLE must name an existing absolute executable path" in result.stderr


@pytest.mark.parametrize("generator,tool", [("Unix Makefiles", "make"), ("Ninja", "ninja")])
def test_generated_toolchain_builds_with_only_umbrella_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, generator: str, tool: str
) -> None:
    """Actual CMake builds route compile, archive, and both link rules through rebrew."""
    cmake = shutil.which("cmake")
    if os.name != "posix" or cmake is None or shutil.which(tool) is None:
        pytest.skip("POSIX CMake and build tool required for the fake driver")
    drivers = tmp_path / "driver with spaces"
    drivers.mkdir()
    driver = drivers / "rebrew"
    driver.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "assert sys.argv[1:3] == ['build', 'driver'] and sys.argv[4] == '--', sys.argv\n"
        "assert sys.argv[5] == '/REBREW_TOOLCHAIN:msvc-6.0', sys.argv\n"
        "with open(os.environ['REBREW_FAKE_DRIVER_LOG'], 'a') as log:\n"
        "    log.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "for arg in sys.argv[5:]:\n"
        "    if arg.startswith('/Fo') or arg.lower().startswith('/out:'):\n"
        "        out = Path(arg[3:] if arg.startswith('/Fo') else arg[5:])\n"
        "        out.parent.mkdir(parents=True, exist_ok=True)\n"
        "        out.write_bytes(b'fake compiler output')\n",
        encoding="utf-8",
    )
    driver.chmod(0o755)
    monkeypatch.setenv("PATH", str(drivers) + os.pathsep + os.environ.get("PATH", ""))
    log = tmp_path / "commands.jsonl"
    monkeypatch.setenv("REBREW_FAKE_DRIVER_LOG", str(log))
    (tmp_path / "unit.c").write_text("int main(void) { return 0; }\n")
    (tmp_path / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.15)\n"
        "project(bridge C)\n"
        "add_library(arch STATIC unit.c)\n"
        "add_library(shared SHARED unit.c)\n"
        "add_executable(exe unit.c)\n"
    )
    toolchain = generate_toolchain_file(TOOLCHAINS["msvc-6.0"], tmp_path / "cmake")
    build = tmp_path / "build"
    configured = subprocess.run(
        [
            cmake,
            "-G",
            generator,
            "-S",
            str(tmp_path),
            "-B",
            str(build),
            "--toolchain",
            str(toolchain),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert configured.returncode == 0, configured.stdout + configured.stderr
    built = subprocess.run(
        [cmake, "--build", str(build)], capture_output=True, text=True, check=False
    )
    assert built.returncode == 0, built.stdout + built.stderr
    commands = [json.loads(line) for line in log.read_text().splitlines()]
    assert {args[2] for args in commands} == {"cl", "link", "lib"}
    assert sum(args[2] == "link" for args in commands) == 2
    for artifact in ("arch.lib", "shared.dll", "exe.exe"):
        assert (build / artifact).is_file(), artifact


def test_per_toolchain_version_stamping(tmp_path: Path) -> None:
    """Each MSVC profile stamps its own compiler version (linker era +
    Rich-header build), not msvc-6.0's 12.00.8168."""
    assert 'CMAKE_C_COMPILER_VERSION "12.00.8168"' in generate_toolchain_file(
        TOOLCHAINS["msvc-6.0"], tmp_path
    ).read_text(encoding="utf-8")
    assert 'CMAKE_C_COMPILER_VERSION "12.00.8447"' in generate_toolchain_file(
        TOOLCHAINS["msvc-6.0-sp3"], tmp_path
    ).read_text(encoding="utf-8")
    assert 'CMAKE_C_COMPILER_VERSION "13.10.3077"' in generate_toolchain_file(
        TOOLCHAINS["msvc-7.1"], tmp_path
    ).read_text(encoding="utf-8")


def test_resolve_spec_rejects_dosbox_image() -> None:
    """Non-wine image toolchains (dosbox entrypoint wrappers) degrade with
    an actionable error instead of a missing-tool_root dead end."""
    import typer

    from rebrew.cmake_tc import _resolve_spec
    from rebrew.compiler.toolchain import TOOLCHAINS

    with pytest.raises(typer.Exit):
        _resolve_spec("borland-3.1")

    # mingw-16.2.0 is a wine-driven image too (its driver is a PE32 binary), but it
    # is one gcc with no separate link/lib tools — refused, like any other
    # wine image without a tool_root.
    with pytest.raises(typer.Exit):
        _resolve_spec("mingw-16.2.0")

    # every wine image spec that declares a tool_root resolves.
    for name, spec in TOOLCHAINS.items():
        if spec.image is not None and spec.runtime == "wine" and spec.tool_root:
            assert _resolve_spec(name) is spec, name


@pytest.mark.parametrize("mode", ["cl", "link", "lib"])
def test_driver_dispatch_and_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str
) -> None:
    """Umbrella driver preserves compiler flags and propagates the tool exit."""
    proj = tmp_path / "proj"
    (proj / "build").mkdir(parents=True)
    (proj / "rebrew-project.toml").write_text(
        '[compiler]\nprofile = "msvc-6.0"\n', encoding="utf-8"
    )

    calls: list[tuple[str, list[str]]] = []

    def fake_docker_run(spec, mode: str, args: list[str]) -> int:
        calls.append((mode, args))
        return 7

    monkeypatch.setattr("rebrew.cmake_tc._docker_run", fake_docker_run)
    monkeypatch.setattr("rebrew.cmake_tc.Path.cwd", lambda: proj / "build")
    from typer.testing import CliRunner

    from rebrew.app.main import app

    args = ["/c", "x.c", "--help", "--version", "-v", "/Ipath with spaces"]
    result = CliRunner().invoke(app, ["build", "driver", mode, "--", *args])
    assert result.exit_code == 7, result.output
    assert calls == [(mode, args)]


@pytest.mark.parametrize("mode", ["cl", "link", "lib"])
@pytest.mark.parametrize("override", [False, True])
def test_generated_profile_pin_precedes_environment_and_allows_file_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str, override: bool
) -> None:
    """The generated default wins over the environment; a later file pin wins over it."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "rebrew-project.toml").write_text('[compiler]\nprofile = "msvc-6.0"\n')
    monkeypatch.chdir(proj)
    monkeypatch.setenv("REBREW_TOOLCHAIN", "msvc-7.1")
    calls: list[tuple[str, list[str]]] = []

    def fake_docker_run(spec, selected_mode: str, args: list[str]) -> int:
        calls.append((spec.name, args))
        assert selected_mode == mode
        return 0

    monkeypatch.setattr("rebrew.cmake_tc._docker_run", fake_docker_run)
    from typer.testing import CliRunner

    from rebrew.app.main import app

    arguments = ["/REBREW_TOOLCHAIN:msvc-6.0-sp5", "/O2"]
    if override:
        arguments.append("-REBREW_TOOLCHAIN:msvc-6.0-sp5-pp")
    arguments.extend(["/c", "unit.c"])
    result = CliRunner().invoke(app, ["build", "driver", mode, "--", *arguments])
    assert result.exit_code == 0, result.output
    expected = "msvc-6.0-sp5-pp" if override else "msvc-6.0-sp5"
    assert calls == [(expected, ["/O2", "/c", "unit.c"])]


def test_docker_run_rejects_relative_wineprefix(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A relative REBREW_WINEPREFIX exits before any docker call."""
    import typer

    (tmp_path / "rebrew-project.toml").write_text("", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("REBREW_WINEPREFIX", "prefix")
    calls: list[list[str]] = []
    monkeypatch.setattr("rebrew.cmake_tc.subprocess.run", lambda cmd, **_: calls.append(cmd))

    with pytest.raises(typer.Exit):
        _docker_run(TOOLCHAINS["msvc-6.0"], "cl", ["/c", "x.c"])
    assert calls == []
    assert not (tmp_path / "prefix").exists()
    assert "must be an absolute path" in capsys.readouterr().err


def test_response_paths_are_rewritten_without_changing_original(tmp_path: Path) -> None:
    from rebrew.cmake_tc import _rewrite_response_files

    response = tmp_path / "input.rsp"
    original = (
        '"/home/build dir/a.obj" /home/build/b.lib /STUB:/home/build/stub.exe /MACHINE:I386\n'
    )
    response.write_text(original)
    output = tmp_path / "copies"
    output.mkdir()
    args = _rewrite_response_files("link", ["@" + str(response)], output)
    assert args[0].startswith("@Z:")
    rewritten = next(output.glob("*.rsp")).read_text()
    assert '"Z:\\home\\build dir\\a.obj"' in rewritten
    assert "Z:\\home\\build\\b.lib" in rewritten
    assert "/STUB:Z:\\home\\build\\stub.exe" in rewritten
    assert "/MACHINE:I386" in rewritten
    assert response.read_text() == original


def test_absolute_link_order_file() -> None:
    assert _rewrite_args("link", ["/ORDER:@/home/build/order.txt"]) == [
        r"/ORDER:@Z:\home\build\order.txt"
    ]


def test_response_file_bytes_survive_the_rewrite(tmp_path: Path) -> None:
    """A non-UTF-8 path byte is copied through, not decoded with the locale."""
    from rebrew.cmake_tc import _rewrite_response_files

    response = tmp_path / "input.rsp"
    response.write_bytes(b'"/home/caf\xe9 dir/a.obj" /MACHINE:I386\n')
    output = tmp_path / "copies"
    output.mkdir()
    _rewrite_response_files("link", ["@" + str(response)], output)
    rewritten = next(output.glob("*.rsp")).read_bytes()
    assert b'"Z:\\home\\caf\xe9 dir\\a.obj"' in rewritten


@pytest.mark.parametrize("mode", ["cl", "link", "lib"])
def test_driver_uses_configured_unshare(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str
) -> None:
    from typer.testing import CliRunner

    from rebrew import cmake_tc
    from rebrew.app.main import app

    (tmp_path / "rebrew-project.toml").write_text(
        '[compiler]\nprofile="msvc-6.0-sp5"\nexecution_backend="unshare"\n'
    )
    monkeypatch.chdir(tmp_path)
    calls = []
    monkeypatch.setattr(
        cmake_tc,
        "_unshare_run",
        lambda spec, mode, args: calls.append((spec.name, mode, args)) or 9,
        raising=False,
    )
    monkeypatch.setattr(cmake_tc, "_docker_run", lambda *_: pytest.fail("Docker must not run"))
    result = CliRunner().invoke(
        app, ["build", "driver", mode, "--", "/REBREW_TOOLCHAIN:msvc-6.0-sp5-pp", "/ML"]
    )
    assert result.exit_code == 9, result.output
    assert calls == [("msvc-6.0-sp5-pp", mode, ["/ML"])]


@pytest.mark.parametrize("mode", ["cl", "link", "lib"])
@pytest.mark.parametrize("epoch", [None, "0", "1234567890"])
def test_unshare_bridge_keeps_paths_and_tool(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str, epoch: str | None
) -> None:
    from rebrew import cmake_tc
    from rebrew.compiler import toolchain

    (tmp_path / "rebrew-project.toml").write_text('[compiler]\nprofile="msvc-6.0-sp5-pp"\n')
    build = tmp_path / "build space"
    build.mkdir()
    monkeypatch.chdir(build)
    if epoch is None:
        monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    else:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", epoch)
    (build / "inputs.rsp").write_text(f'"{tmp_path}/source file.c"')
    monkeypatch.setattr(toolchain, "cached_image_digest", lambda *_: "sha256:" + "a" * 64)
    calls = []

    def run(spec, args, **kwargs):
        calls.append((spec, args, kwargs))
        rewritten = Path(args[-1][3:].replace("\\", "/"))
        assert cmake_tc._to_w(str(tmp_path / "source file.c")) in rewritten.read_text()
        return SimpleNamespace(returncode=3, stdout="ok\r\n", stderr="")

    monkeypatch.setattr(toolchain, "run_toolchain", run)
    assert cmake_tc._unshare_run(TOOLCHAINS["msvc-6.0-sp5-pp"], mode, ["@inputs.rsp"]) == 3
    spec, args, kwargs = calls[0]
    assert spec.image_entrypoint == (
        "/usr/local/bin/rebrew-clock" if epoch is not None else "/usr/bin/wine"
    )
    assert args[: 1 if epoch is not None else 0] == (["/usr/bin/wine"] if epoch is not None else [])
    assert (
        str(Path(spec.tool_root) / {"cl": "CL.EXE", "link": "LINK.EXE", "lib": "LIB.EXE"}[mode])
        in args
    )
    assert kwargs == {
        "workdir": tmp_path,
        "project_cwd": build,
        "image_id": "sha256:" + "a" * 64,
        "execution_backend": "unshare",
        "timeout": 3600,
    }


@pytest.mark.parametrize("backend", ["docker", "podman"])
def test_driver_explicit_container_backend(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, backend: str
) -> None:
    from typer.testing import CliRunner

    from rebrew import cmake_tc
    from rebrew.app.main import app

    (tmp_path / "rebrew-project.toml").write_text(
        f'[compiler]\nprofile="msvc-6.0-sp5"\nexecution_backend="{backend}"\n'
    )
    monkeypatch.chdir(tmp_path)
    calls = []
    monkeypatch.setattr(
        cmake_tc, "_docker_run", lambda spec, mode, args, **kwargs: calls.append(kwargs) or 0
    )
    result = CliRunner().invoke(app, ["build", "driver", "cl", "--", "/c", "x.c"])
    assert result.exit_code == 0, result.output
    assert calls == [{"runtime": backend}]


def test_driver_unshare_failure_has_no_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from typer.testing import CliRunner

    from rebrew import cmake_tc
    from rebrew.app.main import app
    from rebrew.compiler.toolchain import ToolchainError

    (tmp_path / "rebrew-project.toml").write_text(
        '[compiler]\nprofile="msvc-6.0-sp5"\nexecution_backend="unshare"\n'
    )
    monkeypatch.chdir(tmp_path)

    def fail(*_):
        raise ToolchainError("user namespaces blocked", kind="invocation", name="msvc-6.0-sp5")

    monkeypatch.setattr(cmake_tc, "_unshare_run", fail)
    monkeypatch.setattr(cmake_tc, "_docker_run", lambda *_: pytest.fail("must not fall back"))
    result = CliRunner().invoke(app, ["build", "driver", "cl", "--", "/c", "x.c"])
    assert result.exit_code != 0
    assert "user namespaces blocked" in result.output
    assert result.exception is not None and isinstance(result.exception, SystemExit)


def test_driver_reuses_object_and_exact_diagnostics(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An unchanged argv/source compile must survive flags.make invalidation."""
    from typer.testing import CliRunner

    from rebrew import cmake_tc
    from rebrew.app.main import app
    from rebrew.compiler import toolchain

    (tmp_path / "rebrew-project.toml").write_text(
        '[project]\ndefault_target="game"\n'
        '[targets.game]\nbinary="original.exe"\nreversed_dir="src"\nmodule="GAME"\n'
        '[compiler]\nprofile="msvc-6.0-sp5-pp"\nexecution_backend="unshare"\n'
    )
    (tmp_path / "src").mkdir()
    source = tmp_path / "src" / "source.c"
    source.write_text("int f(void) { return 1; }\n")
    output = tmp_path / "output.obj"
    (tmp_path / "original.exe").write_bytes(b"fixture")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1071482016")
    monkeypatch.setattr(toolchain, "cached_image_digest", lambda *_: "sha256:" + "a" * 64)
    monkeypatch.setattr(toolchain, "image_environment", lambda *_: {})
    calls = []

    def run(spec, mode, args, **kwargs):
        calls.append((spec, mode, args, kwargs))
        output.write_bytes(b"object fixture")
        print("source.c\nwarning C4101: fixture")
        print("stderr fixture", file=sys.stderr)
        return 0

    monkeypatch.setattr(cmake_tc, "_unshare_run", run)
    args = [
        "build",
        "driver",
        "cl",
        "--",
        "/c",
        "/O2",
        "/ML",
        "/Fdunused/",
        "/Fooutput.obj",
        str(source),
    ]
    first = CliRunner().invoke(app, args)
    assert first.exit_code == 0, first.output
    output.unlink()
    (tmp_path / "flags.make").write_text("unrelated source flags changed\n")
    second = CliRunner().invoke(app, args)
    assert second.exit_code == 0, second.output
    assert output.read_bytes() == b"object fixture"
    assert second.stdout == first.stdout
    assert second.stderr == first.stderr
    assert len(calls) == 1
    assert calls[0][3] == {"image_id": "sha256:" + "a" * 64}


def test_unshare_bridge_uses_the_cache_admitted_image_without_readmission(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from rebrew import cmake_tc
    from rebrew.compiler import toolchain

    (tmp_path / "rebrew-project.toml").write_text('[compiler]\nprofile="msvc-6.0-sp5-pp"\n')
    monkeypatch.chdir(tmp_path)
    image = "sha256:" + "a" * 64
    monkeypatch.setattr(
        toolchain, "cached_image_digest", lambda *_: pytest.fail("must retain admitted identity")
    )
    calls = []

    def run(spec, args, **kwargs):
        calls.append(kwargs)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(toolchain, "run_toolchain", run)
    assert (
        cmake_tc._unshare_run(TOOLCHAINS["msvc-6.0-sp5-pp"], "cl", ["/c", "f.c"], image_id=image)
        == 0
    )
    assert calls[0]["image_id"] == image


def test_load_profile_prefers_default_target_override(tmp_path: Path) -> None:
    """A target profile override must win over the project-level profile.

    CMake has no Rebrew target identity, so `build driver` resolves the
    project default target's compiler.  With the project-level profile only, a
    target on a different code generator (msvc-6.0-sp5-pp) compiled as plain
    SP5 and produced the non-PP x87 compare idiom for every manual probe.
    """
    (tmp_path / "rebrew-project.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "p"',
                'default_target = "TL"',
                "",
                '[targets."TL"]',
                'binary = "original/TL.exe"',
                'reversed_dir = "src"',
                'module = "TL"',
                'compiler = { profile = "msvc-6.0-sp5-pp" }',
                "",
                '[targets."Other"]',
                'binary = "original/Other.exe"',
                'reversed_dir = "src"',
                'module = "OTHER"',
                "",
                "[compiler]",
                'profile = "msvc-6.0-sp5"',
            ]
        )
    )
    assert cmake_tc._load_profile(tmp_path) == "msvc-6.0-sp5-pp"


def test_load_profile_falls_back_to_project_when_target_has_no_override(tmp_path: Path) -> None:
    (tmp_path / "rebrew-project.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "p"',
                'default_target = "TL"',
                "",
                '[targets."TL"]',
                'binary = "original/TL.exe"',
                'reversed_dir = "src"',
                'module = "TL"',
                "",
                "[compiler]",
                'profile = "msvc-6.0-sp5"',
            ]
        )
    )
    assert cmake_tc._load_profile(tmp_path) == "msvc-6.0-sp5"
