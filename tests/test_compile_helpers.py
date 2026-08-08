"""Tests for compile.py pure helpers — CL command resolution and include flags."""

from pathlib import Path
from types import SimpleNamespace

from rebrew.compile import _resolve_include_flags, resolve_cl_command


def _cfg(root: Path, **overrides: object) -> SimpleNamespace:
    defaults: dict = {
        "root": root,
        "compiler_command": "wine tools/CL.EXE",
        "compiler_runner": "",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class TestResolveClCommand:
    def test_wine_detected_and_stripped(self, tmp_path: Path) -> None:
        cmd = resolve_cl_command(_cfg(tmp_path))
        # The runner is stripped from the CL path and re-prepended.
        assert cmd == ["wine", str(tmp_path / "tools" / "CL.EXE")]

    def test_explicit_runner_stripped(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path, compiler_command="wibo /vc/CL.EXE", compiler_runner="wibo")
        cmd = resolve_cl_command(cfg)
        assert cmd == ["wibo", "/vc/CL.EXE"]

    def test_absolute_cl_path(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path, compiler_command="wine /abs/CL.EXE")
        cmd = resolve_cl_command(cfg)
        assert cmd == ["wine", "/abs/CL.EXE"]

    def test_no_runner_flags_preserved(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path, compiler_command="wine tools/CL.EXE /nologo /c")
        cmd = resolve_cl_command(cfg)
        assert cmd == ["wine", str(tmp_path / "tools" / "CL.EXE"), "/nologo", "/c"]


class TestResolveIncludeFlags:
    def test_relative_from_src(self, tmp_path: Path) -> None:
        src_parent = tmp_path / "src"
        inc = src_parent / "inc"
        inc.mkdir(parents=True)
        out = _resolve_include_flags(["/Iinc"], src_parent, tmp_path)
        assert out == [f"/I{inc.resolve()}"]

    def test_relative_from_root(self, tmp_path: Path) -> None:
        src_parent = tmp_path / "src"
        src_parent.mkdir()
        inc = tmp_path / "inc"
        inc.mkdir()
        out = _resolve_include_flags(["/Iinc"], src_parent, tmp_path)
        assert out == [f"/I{inc.resolve()}"]

    def test_missing_dir_keeps_flag(self, tmp_path: Path) -> None:
        out = _resolve_include_flags(["/Imissing"], tmp_path, tmp_path)
        assert out == ["/Imissing"]

    def test_absolute_and_non_include_passthrough(self, tmp_path: Path) -> None:
        out = _resolve_include_flags(["/I/abs/inc", "/O2", "/c"], tmp_path, tmp_path)
        assert out == ["/I/abs/inc", "/O2", "/c"]

    def test_dash_i_form(self, tmp_path: Path) -> None:
        src_parent = tmp_path / "src"
        inc = src_parent / "inc"
        inc.mkdir(parents=True)
        out = _resolve_include_flags(["-Iinc"], src_parent, tmp_path)
        assert out == [f"-I{inc.resolve()}"]


class TestResolveCompilerEnv:
    def test_resolves_paths(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import resolve_compiler_env

        tools = tmp_path / "tools"
        tools.mkdir()
        cl = tools / "CL.EXE"
        cl.touch()
        cfg = SimpleNamespace(
            root=tmp_path,
            compiler_command="wine tools/CL.EXE",
            compiler_runner="",
            compiler_includes="inc",
            metadata_dir=tmp_path,
        )
        (tmp_path / "inc").mkdir()
        monkeypatch.setattr("rebrew.compile.msvc_env_from_config", lambda cfg: {"X": "1"})
        monkeypatch.setattr("rebrew.compile.get_compile_cache", lambda root: None)
        cl_cmd, inc_dir, env, cc = resolve_compiler_env(cfg)
        assert str(cl) in cl_cmd  # existing relative path root-prefixed
        assert "wine" in cl_cmd
        assert inc_dir == str(tmp_path / "inc")  # existing include dir resolved
        assert env == {"X": "1"}
        assert cc is None

    def test_missing_paths_fallback(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import resolve_compiler_env

        cfg = SimpleNamespace(
            root=tmp_path,
            compiler_command="",
            compiler_runner="",
            compiler_includes="missing_inc",
            metadata_dir=tmp_path,
        )
        monkeypatch.setattr("rebrew.compile.resolve_cl_command", lambda cfg: ["cl"])
        monkeypatch.setattr("rebrew.compile.msvc_env_from_config", lambda cfg: {})
        monkeypatch.setattr("rebrew.compile.get_compile_cache", lambda root: None)
        cl_cmd, inc_dir, env, cc = resolve_compiler_env(cfg)
        assert cl_cmd == "cl"  # empty command falls back to resolve_cl_command
        assert inc_dir == "missing_inc"  # non-existent include stays as-is
        assert cc is None
