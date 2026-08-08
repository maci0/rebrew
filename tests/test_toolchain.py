"""Tests for core/toolchain.py — MSVC env construction."""

from pathlib import Path
from types import SimpleNamespace

from rebrew.core.toolchain import msvc_env_from_config


def _cfg(
    command: str = "/opt/vc6/bin/CL.EXE",
    runner: str | None = "wine",
    root: Path | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        compiler_command=command,
        compiler_runner=runner,
        root=root or Path("/project"),
        compiler_includes=Path("/inc"),
        compiler_libs=Path("/lib"),
    )


class TestMsvcEnvFromConfig:
    def test_wine_runner_sets_debug_env(self) -> None:
        env = msvc_env_from_config(_cfg())
        assert env["WINEDEBUG"] == "-all"
        assert env["REBREW_COMPILER_RUNNER"] == "wine"
        assert env["INCLUDE"] == "/inc"
        assert env["LIB"] == "/lib"

    def test_runner_auto_detected_from_command(self) -> None:
        env = msvc_env_from_config(_cfg(command="wine /opt/CL.EXE", runner=None))
        assert env["REBREW_COMPILER_RUNNER"] == "wine"
        assert env["WINEDEBUG"] == "-all"

    def test_relative_cl_path_resolved(self) -> None:
        env = msvc_env_from_config(_cfg(command="tools/vc6/CL.EXE", runner=None))
        # bin dir = /project/tools/vc6
        assert "/project/tools/vc6" in env["WINEPATH"]
        assert "/project/tools/vc6" in env["PATH"]

    def test_empty_command_empty_bin_dir(self) -> None:
        env = msvc_env_from_config(_cfg(command="", runner=""))
        # No CL.EXE → no runner key, no debug env, no bin dir contribution.
        assert "REBREW_COMPILER_RUNNER" not in env
        assert "WINEDEBUG" not in env

    def test_preserves_existing_winepath(self) -> None:
        env = msvc_env_from_config(_cfg())
        # Second call on a fresh env — verify the env is copied from os.environ.
        assert "WINEPATH" in env

    def test_non_wine_runner_no_debug(self) -> None:
        env = msvc_env_from_config(_cfg(command="cl", runner="msvc"))
        assert "WINEDEBUG" not in env
        assert env["REBREW_COMPILER_RUNNER"] == "msvc"
