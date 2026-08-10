"""Tests for rebrew.compile — resolve_cl_command and compile_and_compare helpers."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from rebrew.compile import compile_to_obj, filter_wine_stderr, resolve_cl_command
from rebrew.config import ProjectConfig

# ---------------------------------------------------------------------------
# resolve_cl_command
# ---------------------------------------------------------------------------


class TestResolveClCommand:
    """Tests for resolve_cl_command()."""

    def test_wine_relative_path(self, tmp_path: Path) -> None:
        """wine + relative CL.EXE path is resolved against cfg.root."""
        cfg = ProjectConfig(
            root=tmp_path,
            compiler_command="wine tools/MSVC600/VC98/Bin/CL.EXE",
        )
        result = resolve_cl_command(cfg)
        assert result[0] == "wine"
        assert result[1] == str(tmp_path / "tools/MSVC600/VC98/Bin/CL.EXE")

    def test_wine_absolute_path(self, tmp_path: Path) -> None:
        """wine + absolute CL.EXE path is preserved as-is."""
        cfg = ProjectConfig(
            root=tmp_path,
            compiler_command="wine /opt/msvc/CL.EXE",
        )
        result = resolve_cl_command(cfg)
        assert result == ["wine", "/opt/msvc/CL.EXE"]

    def test_bare_relative_path(self, tmp_path: Path) -> None:
        """Bare relative path is resolved against cfg.root."""
        cfg = ProjectConfig(
            root=tmp_path,
            compiler_command="tools/CL.EXE",
        )
        result = resolve_cl_command(cfg)
        assert result == [str(tmp_path / "tools/CL.EXE")]

    def test_bare_absolute_path(self, tmp_path: Path) -> None:
        """Bare absolute path is preserved."""
        cfg = ProjectConfig(
            root=tmp_path,
            compiler_command="/usr/bin/cl",
        )
        result = resolve_cl_command(cfg)
        assert result == ["/usr/bin/cl"]

    def test_empty_command_fallback(self, tmp_path: Path) -> None:
        """Empty compiler_command falls back to CL.EXE."""
        cfg = ProjectConfig(
            root=tmp_path,
            compiler_command="",
        )
        result = resolve_cl_command(cfg)
        assert result == [str(tmp_path / "CL.EXE")]

    def test_quoted_wine_path(self, tmp_path: Path) -> None:
        """Quoted path with spaces is handled by shlex.split."""
        cfg = ProjectConfig(
            root=tmp_path,
            compiler_command='wine "tools/MS VC/CL.EXE"',
        )
        result = resolve_cl_command(cfg)
        assert result[0] == "wine"
        assert "MS VC" in result[1]

    def test_keeps_extra_tokens_after_compiler(self, tmp_path: Path) -> None:
        cfg = ProjectConfig(
            root=tmp_path,
            compiler_command="wine tools/CL.EXE --wrapper-arg",
        )
        result = resolve_cl_command(cfg)
        assert result == ["wine", str(tmp_path / "tools/CL.EXE"), "--wrapper-arg"]


# ---------------------------------------------------------------------------
# compile_and_compare — unit-level logic tests (no real compiler)
# ---------------------------------------------------------------------------


class TestSafeShlex:
    """Tests for internal cflags shlex-splitting helper."""

    def test_simple_flags_split(self) -> None:
        """Space-separated cflags are split into individual tokens."""
        from rebrew.utils import safe_shlex_split as _safe_shlex_split

        assert _safe_shlex_split("/O2 /Gd /MT") == ["/O2", "/Gd", "/MT"]

    def test_two_flags_split(self) -> None:
        """Two-flag string is split correctly."""
        from rebrew.utils import safe_shlex_split as _safe_shlex_split

        assert _safe_shlex_split("/O2 /Gd") == ["/O2", "/Gd"]

    def test_quoted_forced_include_path(self) -> None:
        """Quoted /FI paths with spaces are handled without crashing."""
        from rebrew.utils import safe_shlex_split as _safe_shlex_split

        result = _safe_shlex_split('/FI"forced.h" /nologo')
        assert result == ["/FIforced.h", "/nologo"]


class TestCompileToObj:
    def test_returns_copy_error_when_source_copy_fails(self, tmp_path: Path, monkeypatch) -> None:
        def _boom(*_args: object, **_kwargs: object) -> None:
            raise PermissionError("no write access")

        monkeypatch.setattr("rebrew.compile.shutil.copy2", _boom)
        cfg: Any = SimpleNamespace(
            compiler_includes=tmp_path,
            base_cflags="/nologo",
            compile_timeout=3,
            msvc_env=lambda: {},
            compiler_command="CL.EXE",
            compiler_runner="",
            root=tmp_path,
        )
        source = tmp_path / "f.c"
        source.write_text("int f(void){return 1;}\n", encoding="utf-8")

        obj_path, err = compile_to_obj(cast(ProjectConfig, cfg), source, ["/O2"], tmp_path)
        assert obj_path is None
        assert "Failed to copy source into workdir" in err

    def test_base_cflags_uses_shlex_split(self, tmp_path: Path, monkeypatch) -> None:
        captured: dict[str, list[str]] = {}

        def _fake_run(cmd: list[str], **_kwargs: object) -> SimpleNamespace:
            captured["cmd"] = cmd
            (tmp_path / "work" / "f.obj").write_bytes(b"\x00")
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        monkeypatch.setattr("rebrew.compile.subprocess.run", _fake_run)
        monkeypatch.setattr("rebrew.compile.resolve_cl_command", lambda _cfg: ["CL.EXE"])

        cfg: Any = SimpleNamespace(
            root=tmp_path,
            compiler_includes=tmp_path,
            base_cflags='/FI"my forced.h" /nologo',
            compile_timeout=3,
            compiler_command="CL.EXE",
            compiler_runner="",
            compiler_libs=tmp_path,
            msvc_env=lambda: {},
        )
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        source = src_dir / "f.c"
        source.write_text("int f(void){return 1;}\n", encoding="utf-8")
        workdir = tmp_path / "work"
        workdir.mkdir()

        obj_path, err = compile_to_obj(cast(ProjectConfig, cfg), source, ["/O2"], workdir)
        assert err == ""
        assert obj_path is not None
        assert "/FImy forced.h" in captured["cmd"]


class TestCompileToObjPosix:
    """gcc-pe / mingw (POSIX-style) compiler routing."""

    def _run_compile(
        self, tmp_path: Path, monkeypatch, *, profile: str, cflags: list[str]
    ) -> list[str]:
        captured: dict[str, list[str]] = {}

        def _fake_run(cmd: list[str], **_kwargs: object) -> SimpleNamespace:
            captured["cmd"] = cmd
            # GCC-style output flag: -o objname
            out = cmd[cmd.index("-o") + 1]
            (tmp_path / "work" / out).write_bytes(b"\x00")
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        monkeypatch.setattr("rebrew.compile.subprocess.run", _fake_run)
        monkeypatch.setattr(
            "rebrew.compile.resolve_cl_command", lambda _cfg: ["i686-w64-mingw32-gcc"]
        )

        cfg: Any = SimpleNamespace(
            root=tmp_path,
            compiler_includes=tmp_path / "nonexistent-inc",  # must be omitted for gcc
            base_cflags="-O2",
            compile_timeout=3,
            compiler_command="i686-w64-mingw32-gcc",
            compiler_runner="",
            compiler_libs=tmp_path,
            compiler_profile=profile,
            msvc_env=lambda: {},
        )
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        source = src_dir / "f.c"
        source.write_text("int f(void){return 1;}\n", encoding="utf-8")
        workdir = tmp_path / "work"
        workdir.mkdir()

        obj_path, err = compile_to_obj(cast(ProjectConfig, cfg), source, cflags, workdir)
        assert err == ""
        assert obj_path is not None
        return captured["cmd"]

    def test_gcc_pe_uses_posix_flags(self, tmp_path: Path, monkeypatch) -> None:
        cmd = self._run_compile(
            tmp_path, monkeypatch, profile="gcc-pe", cflags=["-O2", "-fno-builtin"]
        )
        # GCC-style: -I/-c/-o, no MSVC /Fo, no /I with empty include path
        assert "-c" in cmd
        assert "-o" in cmd
        assert any(a.startswith("-I") for a in cmd)
        assert not any(a.startswith("/Fo") for a in cmd)
        assert not any(a == "-I" for a in cmd)  # no dangling empty include
        # cflags passed through unchanged
        assert "-fno-builtin" in cmd

    def test_msvc_profile_unaffected(self, tmp_path: Path, monkeypatch) -> None:
        captured: dict[str, list[str]] = {}

        def _fake_run(cmd: list[str], **_kwargs: object) -> SimpleNamespace:
            captured["cmd"] = cmd
            (tmp_path / "work" / "f.obj").write_bytes(b"\x00")
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        monkeypatch.setattr("rebrew.compile.subprocess.run", _fake_run)
        monkeypatch.setattr("rebrew.compile.resolve_cl_command", lambda _cfg: ["wine", "CL.EXE"])

        cfg: Any = SimpleNamespace(
            root=tmp_path,
            compiler_includes=tmp_path,
            base_cflags="/nologo /c /MT",
            compile_timeout=3,
            compiler_command="wine CL.EXE",
            compiler_runner="wine",
            compiler_libs=tmp_path,
            compiler_profile="msvc6",
            msvc_env=lambda: {},
        )
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        source = src_dir / "f.c"
        source.write_text("int f(void){return 1;}\n", encoding="utf-8")
        workdir = tmp_path / "work"
        workdir.mkdir()

        obj_path, err = compile_to_obj(cast(ProjectConfig, cfg), source, ["/O2"], workdir)
        assert err == ""
        assert obj_path is not None
        assert any(a.startswith("/Fo") for a in captured["cmd"])
        assert "-o" not in captured["cmd"]


class TestFilterWineStderr:
    def test_filter_strips_wine_err(self) -> None:
        text = "wine: created the configuration directory\n1234:err:module:foo boom\n"
        assert filter_wine_stderr(text) == ""

    def test_filter_strips_fontconfig(self) -> None:
        text = "Fontconfig warning: line 5\n"
        assert filter_wine_stderr(text) == ""

    def test_filter_keeps_compiler_errors(self) -> None:
        text = "foo.c(7) : error C2143: syntax error : missing ';' before '}'\n"
        assert "C2143" in filter_wine_stderr(text)

    def test_filter_empty_input(self) -> None:
        assert filter_wine_stderr("") == ""

    def test_filter_no_noise(self) -> None:
        text = "CL : Command line warning D9002 : ignoring unknown option '/bad'"
        assert filter_wine_stderr(text) == text
