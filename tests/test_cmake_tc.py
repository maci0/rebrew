"""Tests for rebrew.cmake_tc — the docker CMake toolchain bridge.

Covers the argv translation (ported from the project's wine wrapper), the
project-root discovery, and the toolchain-file generator.  The docker runs
themselves are not executed here — ``tc_main`` is exercised with a mocked
runner.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rebrew.cmake_tc import (
    _TOOL_MODES,
    _find_project_root,
    _rewrite_args,
    _to_w,
    generate_toolchain_file,
)
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


class TestRewriteArgsLink:
    def test_output_and_libpaths(self) -> None:
        out = _rewrite_args(
            "link",
            ["/OUT:/home/maci/server.dll", "/LIBPATH:/opt/lib", "/home/maci/a.obj"],
        )
        assert "/OUT:" + r"Z:\home\maci\server.dll" in out
        assert "/LIBPATH:" + r"Z:\opt\lib" in out
        assert r"Z:\home\maci\a.obj" in out

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
    assert _find_project_root(proj / "build") == proj
    assert _find_project_root(proj) == proj
    assert _find_project_root(tmp_path / "elsewhere") is None


def test_tool_modes_dispatch() -> None:
    assert _TOOL_MODES == {
        "rebrew-cmake-cl": "cl",
        "rebrew-cmake-link": "link",
        "rebrew-cmake-lib": "lib",
    }


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
