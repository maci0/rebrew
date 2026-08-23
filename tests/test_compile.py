"""Tests for rebrew.compile — resolve_cl_command and compile_and_compare helpers."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from rebrew.compile import (
    compile_to_obj,
    filter_wine_stderr,
    maybe_headless_wine,
    resolve_cl_command,
)
from rebrew.config import ProjectConfig

# ---------------------------------------------------------------------------
# resolve_cl_command
# ---------------------------------------------------------------------------


class TestResolveClCommand:
    """Tests for resolve_cl_command()."""

    def test_wine_relative_path(self, tmp_path: Path) -> None:
        """wine + relative CL.EXE path is resolved against cfg.root (the
        project-local file wins over the rebrew install's vendored tree)."""
        fake = tmp_path / "toolchain" / "msvc" / "6.0-win32" / "VC98" / "Bin" / "CL.EXE"
        fake.parent.mkdir(parents=True)
        fake.write_bytes(b"MZ")
        cfg = ProjectConfig(
            root=tmp_path,
            compiler_command="wine toolchain/msvc/6.0-win32/VC98/Bin/CL.EXE",
        )
        result = resolve_cl_command(cfg)
        assert result[0] == "wine"
        assert result[1] == str(fake)

    def test_missing_relative_path_falls_back_to_install(self, tmp_path: Path, monkeypatch) -> None:
        """A project-relative CL path absent under the project root resolves
        against the rebrew install's vendored tools/ (fresh projects without
        a tools/ symlink still compile)."""
        from rebrew import utils as rebrew_utils

        fake = tmp_path / "toolchain" / "msvc" / "6.0-win32" / "VC98" / "Bin" / "CL.EXE"
        fake.parent.mkdir(parents=True)
        fake.write_bytes(b"MZ")
        monkeypatch.setattr(rebrew_utils, "_REPO_ROOT", tmp_path)
        cfg = ProjectConfig(
            root=tmp_path / "project",
            compiler_command="wine toolchain/msvc/6.0-win32/VC98/Bin/CL.EXE",
        )
        result = resolve_cl_command(cfg)
        assert result[0] == "wine"
        assert result[1] == str(fake)

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

    def test_empty_command_returns_empty(self, tmp_path: Path) -> None:
        """Docker-only configs have an empty compiler_command (the image is
        the compiler) — nothing to resolve, no phantom CL.EXE path."""
        cfg = ProjectConfig(
            root=tmp_path,
            compiler_command="",
        )
        assert resolve_cl_command(cfg) == []

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
        # Source OUTSIDE the workdir so the copy actually runs (a source
        # already inside the workdir is served in place, not copied).
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        source = src_dir / "f.c"
        source.write_text("int f(void){return 1;}\n", encoding="utf-8")

        obj_path, err = compile_to_obj(cast(ProjectConfig, cfg), source, ["/O2"], tmp_path)
        assert obj_path is None
        assert "Failed to copy source into workdir" in err

    def test_base_cflags_uses_shlex_split(self, tmp_path: Path, monkeypatch) -> None:
        """base_cflags like '/FI"my forced.h" /nologo' are shlex-split so the
        quoted include reaches the docker invocation as one flag."""
        captured: dict[str, list[str]] = {}

        def _fake_run(spec, args, *, workdir, timeout, mounts=None):
            captured["args"] = args
            (workdir / "f.obj").write_bytes(b"\x00")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr("rebrew.compile.run_toolchain", _fake_run)
        monkeypatch.setattr("rebrew.compile.get_compile_cache", lambda *a, **k: None)

        cfg: Any = SimpleNamespace(
            root=tmp_path,
            compiler_includes=tmp_path,
            base_cflags='/FI"my forced.h" /nologo',
            compile_timeout=3,
            compiler_command="CL.EXE",
            compiler_runner="",
            compiler_libs=tmp_path,
            compiler_profile="msvc6",
            posix_style=False,
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
        assert any("/FImy forced.h" in a for a in captured["args"])

    def test_cache_key_includes_extra_include_dirs(self, tmp_path: Path, monkeypatch) -> None:
        """extra_include_dirs are compile inputs (they add /I flags and bind
        mounts); two compiles differing only in them must not share a cache
        entry."""
        seen: list[str] = []

        class _FakeCache:
            def get(self, key: str):
                seen.append(key)
                return None

            def put(self, key: str, data: bytes) -> None:
                pass

        def _fake_run(spec, args, *, workdir, timeout, mounts=None):
            (workdir / "f.obj").write_bytes(b"\x00")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr("rebrew.compile.run_toolchain", _fake_run)
        monkeypatch.setattr("rebrew.compile.get_compile_cache", lambda *a, **k: _FakeCache())

        cfg: Any = SimpleNamespace(
            root=tmp_path,
            compiler_includes=tmp_path,
            base_cflags="/nologo",
            compile_timeout=3,
            compiler_command="CL.EXE",
            compiler_runner="",
            compiler_libs=tmp_path,
            compiler_profile="msvc6",
            posix_style=False,
            msvc_env=lambda: {},
        )
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        source = src_dir / "f.c"
        source.write_text("int f(void){return 1;}\n", encoding="utf-8")
        workdir = tmp_path / "work"
        workdir.mkdir()

        compile_to_obj(cast(ProjectConfig, cfg), source, ["/O2"], workdir, cache=_FakeCache())
        compile_to_obj(
            cast(ProjectConfig, cfg),
            source,
            ["/O2"],
            workdir,
            cache=_FakeCache(),
            extra_include_dirs=["/proj/other/inc"],
        )
        assert len(seen) == 2
        assert seen[0] != seen[1], "cache key must differ with extra_include_dirs"


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
            posix_style=profile in ("gcc", "gcc-pe", "clang", "watcom"),
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

    def test_msvc_profile_routes_through_docker(self, tmp_path: Path, monkeypatch) -> None:
        """msvc6 is docker-backed: compile_to_obj routes through run_toolchain
        with MSVC-style flags (/Fo), not a host wine subprocess."""
        captured: dict[str, list[str]] = {}

        def _fake_run(spec, args, *, workdir, timeout, mounts=None):
            captured["args"] = args
            (workdir / "f.obj").write_bytes(b"\x00")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr("rebrew.compile.run_toolchain", _fake_run)
        monkeypatch.setattr("rebrew.compile.get_compile_cache", lambda *a, **k: None)

        cfg: Any = SimpleNamespace(
            root=tmp_path,
            compiler_includes=tmp_path,
            base_cflags="/nologo /c /MT",
            compile_timeout=3,
            compiler_command="wine CL.EXE",
            compiler_runner="wine",
            compiler_libs=tmp_path,
            compiler_profile="msvc6",
            posix_style=False,
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
        assert any(a.startswith("/Fo") for a in captured["args"])
        assert "-o" not in captured["args"]


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


class TestCompileToObjToolchainProfiles:
    """watcom / msvc1.52 profiles route through rebrew.toolchain's runner."""

    def _cfg(self, tmp_path: Path, profile: str) -> SimpleNamespace:
        return SimpleNamespace(
            root=tmp_path,
            compiler_profile=profile,
            compiler_command="wcc386",
            base_cflags="",
            compiler_includes=tmp_path / "h",
            compiler_runner="",
            compile_timeout=30,
        )

    def test_watcom_uses_toolchain_runner(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import compile_to_obj
        from rebrew.toolchain import RunResult

        captured: dict = {}

        def _fake_run(spec, args, *, workdir, timeout, mounts=None):
            captured["args"] = args
            obj = workdir / "t.obj"
            obj.write_bytes(b"OMF")
            return RunResult(0, "", "", backend="docker")

        monkeypatch.setattr("rebrew.compile.run_toolchain", _fake_run)
        monkeypatch.setattr("rebrew.compile.compile_cache_key", lambda **k: "k")
        monkeypatch.setattr("rebrew.compile.get_compile_cache", lambda *a, **k: None)

        src = tmp_path / "t.c"
        src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
        workdir = tmp_path / "work"
        workdir.mkdir()
        obj, err = compile_to_obj(self._cfg(tmp_path, "watcom"), src, [], workdir, use_cache=False)
        assert obj is not None and err == ""
        # wcc386 flag shape: -fo= output, -I includes, -zq quiet
        assert "-fo=t.obj" in captured["args"]
        assert "-zq" in captured["args"]

    def test_watcom16_uses_toolchain_runner(self, tmp_path: Path, monkeypatch) -> None:
        """watcom16 (wcc 16-bit) routes through rebrew.toolchain's runner with
        the same posix flag shape as wcc386 — but without -c (wcc16 rejects
        it: E1073)."""
        from rebrew.compile import compile_to_obj
        from rebrew.toolchain import RunResult

        captured: dict = {}

        def _fake_run(spec, args, *, workdir, timeout, mounts=None):
            captured["args"] = args
            obj = workdir / "t.obj"
            obj.write_bytes(b"OMF")
            return RunResult(0, "", "", backend="host")

        monkeypatch.setattr("rebrew.compile.run_toolchain", _fake_run)
        monkeypatch.setattr("rebrew.compile.compile_cache_key", lambda **k: "k")
        monkeypatch.setattr("rebrew.compile.get_compile_cache", lambda *a, **k: None)

        src = tmp_path / "t.c"
        src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
        workdir = tmp_path / "work"
        workdir.mkdir()
        obj, err = compile_to_obj(
            self._cfg(tmp_path, "watcom16"), src, [], workdir, use_cache=False
        )
        assert obj is not None and err == ""
        # wcc flag shape: -fo= output, -I includes, -zq quiet; no -c
        assert "-fo=t.obj" in captured["args"]
        assert "-zq" in captured["args"]
        assert "-c" not in captured["args"]

    def test_watcom_runner_failure_surfaces(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import compile_to_obj
        from rebrew.toolchain import RunResult

        def _fake_run(spec, args, *, workdir, timeout, mounts=None):
            return RunResult(1, "", "Error! E1139", backend="host")

        monkeypatch.setattr("rebrew.compile.run_toolchain", _fake_run)
        monkeypatch.setattr("rebrew.compile.get_compile_cache", lambda *a, **k: None)

        src = tmp_path / "t.c"
        src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
        workdir = tmp_path / "work"
        workdir.mkdir()
        obj, err = compile_to_obj(self._cfg(tmp_path, "watcom"), src, [], workdir, use_cache=False)
        assert obj is None
        assert "E1139" in err


class TestCompileToObjMsvc152Image:
    """msvc1.52 prefers the docker image (cl16 wrapper) when pulled."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(
            root=tmp_path,
            compiler_profile="msvc1.52",
            compiler_command="CL.EXE",
            base_cflags="",
            compiler_includes=tmp_path,
            compiler_runner="",
            compile_timeout=30,
        )

    def test_image_preferred_when_pulled(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import compile_to_obj
        from rebrew.toolchain import RunResult

        captured: dict = {}
        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: True)

        def _fake_run(spec, args, *, workdir, timeout, mounts=None):
            captured["args"] = args
            # DOSBox FAT-uppercases the object
            (workdir / "T.OBJ").write_bytes(b"OMF")
            return RunResult(0, "", "", backend="docker")

        monkeypatch.setattr("rebrew.compile.run_toolchain", _fake_run)
        monkeypatch.setattr("rebrew.compile.get_compile_cache", lambda *a, **k: None)

        src = tmp_path / "t.c"
        src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
        workdir = tmp_path / "work"
        workdir.mkdir()
        obj, err = compile_to_obj(self._cfg(tmp_path), src, [], workdir, use_cache=False)
        assert obj is not None and obj.endswith("T.OBJ")
        assert err == ""
        # image path passes source first, then CL flags (wrapper adds /nologo /c)
        assert captured["args"] == ["t.c"]

    def test_image_path_forwards_cflags(self, tmp_path: Path, monkeypatch) -> None:
        """The GA flag sweep relies on per-function cflags reaching CL — the
        cl16 wrapper must receive them after the source."""
        from rebrew.compile import compile_to_obj
        from rebrew.toolchain import RunResult

        captured: dict = {}
        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: True)

        def _fake_run(spec, args, *, workdir, timeout, mounts=None):
            captured["args"] = args
            (workdir / "T.OBJ").write_bytes(b"OMF")
            return RunResult(0, "", "", backend="docker")

        monkeypatch.setattr("rebrew.compile.run_toolchain", _fake_run)
        monkeypatch.setattr("rebrew.compile.get_compile_cache", lambda *a, **k: None)

        src = tmp_path / "t.c"
        src.write_text("int f(void) { return 1; }\n", encoding="utf-8")
        workdir = tmp_path / "work"
        workdir.mkdir()
        obj, err = compile_to_obj(
            self._cfg(tmp_path), src, ["/O1", "/Gs"], workdir, use_cache=False
        )
        assert obj is not None and err == ""
        # source first (wrapper convention), then the cflags verbatim
        assert captured["args"] == ["t.c", "/O1", "/Gs"]

    def test_no_image_raises_clear_error(self, tmp_path: Path, monkeypatch) -> None:
        """Docker-only: a missing image is a hard error — there is no host
        DOSBox fallback anymore."""
        from rebrew.compile import compile_to_obj

        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: False)
        monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: True)
        monkeypatch.setattr("rebrew.compile.get_compile_cache", lambda *a, **k: None)

        src = tmp_path / "t.c"
        src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
        workdir = tmp_path / "work"
        workdir.mkdir()
        obj, err = compile_to_obj(self._cfg(tmp_path), src, [], workdir, use_cache=False)
        assert obj is None
        assert "not built" in err


class TestMaybeHeadlessWine:
    """Tests for maybe_headless_wine() — wine runs headless via a persistent Xvfb."""

    def test_wine_gets_display_env(self, monkeypatch) -> None:
        """wine → command unchanged, env gains DISPLAY pointing at an Xvfb."""
        monkeypatch.setattr("rebrew.compile.ensure_xvfb", lambda: ":99")
        cmd, env = maybe_headless_wine(["wine", "/opt/CL.EXE"], {"WINEDEBUG": "-all"})
        assert cmd == ["wine", "/opt/CL.EXE"]
        assert env == {"WINEDEBUG": "-all", "DISPLAY": ":99"}

    def test_absolute_wine_path_gets_display(self, monkeypatch) -> None:
        """A path to wine (e.g. /usr/bin/wine) is matched by basename."""
        monkeypatch.setattr("rebrew.compile.ensure_xvfb", lambda: ":99")
        cmd, env = maybe_headless_wine(["/usr/bin/wine", "/opt/CL.EXE"], None)
        assert cmd == ["/usr/bin/wine", "/opt/CL.EXE"]
        assert env["DISPLAY"] == ":99"

    def test_wibo_not_touched(self, monkeypatch) -> None:
        """wibo is already headless — left untouched."""
        monkeypatch.setattr("rebrew.compile.ensure_xvfb", lambda: ":99")
        cmd, env = maybe_headless_wine(["wibo", "/opt/CL.EXE"], None)
        assert cmd == ["wibo", "/opt/CL.EXE"]
        assert env is None

    def test_gcc_not_touched(self, monkeypatch) -> None:
        """Non-wine commands are never touched."""
        monkeypatch.setattr("rebrew.compile.ensure_xvfb", lambda: ":99")
        cmd, env = maybe_headless_wine(["gcc", "-c", "t.c"], None)
        assert cmd == ["gcc", "-c", "t.c"]
        assert env is None

    def test_no_xvfb_falls_back_to_xvfb_run(self, monkeypatch) -> None:
        """No Xvfb binary but xvfb-run present → slow wrapper fallback."""
        monkeypatch.setattr("rebrew.compile.ensure_xvfb", lambda: None)
        monkeypatch.setattr(
            "rebrew.compile.shutil.which",
            lambda name: "/usr/bin/xvfb-run" if name == "xvfb-run" else None,
        )
        cmd, env = maybe_headless_wine(["wine", "/opt/CL.EXE"], {"WINEDEBUG": "-all"})
        assert cmd[0] == "xvfb-run"
        assert cmd[4:] == ["wine", "/opt/CL.EXE"]
        assert env == {"WINEDEBUG": "-all"}

    def test_no_xvfb_no_wrapper_bare_wine(self, monkeypatch) -> None:
        """Neither Xvfb nor xvfb-run → bare wine as-is."""
        monkeypatch.setattr("rebrew.compile.ensure_xvfb", lambda: None)
        monkeypatch.setattr("rebrew.compile.shutil.which", lambda name: None)
        cmd, env = maybe_headless_wine(["wine", "/opt/CL.EXE"], None)
        assert cmd == ["wine", "/opt/CL.EXE"]
        assert env is None

    def test_headless_opt_out_env(self, monkeypatch) -> None:
        """REBREW_WINE_HEADLESS=0 forces bare wine even with Xvfb available."""
        monkeypatch.setattr("rebrew.compile.ensure_xvfb", lambda: ":99")
        cmd, _env = maybe_headless_wine(["wine", "/opt/CL.EXE"], {"REBREW_WINE_HEADLESS": "0"})
        assert cmd == ["wine", "/opt/CL.EXE"]

    def test_empty_command_untouched(self, monkeypatch) -> None:
        monkeypatch.setattr("rebrew.compile.ensure_xvfb", lambda: ":99")
        cmd, env = maybe_headless_wine([], {"WINEDEBUG": "-all"})
        assert cmd == []
        assert env == {"WINEDEBUG": "-all"}


# ---------------------------------------------------------------------------
# Relative runner path resolution (--install-wibo config shape)
# ---------------------------------------------------------------------------


class TestRelativeRunnerResolution:
    """A relative runner like ``tools/wibo`` must anchor to the project root,
    not the (temp) compile workdir."""

    def test_resolve_cl_command_anchors_relative_runner(self, tmp_path: Path) -> None:
        """runner='tools/wibo' + command without prefix → root-anchored runner."""
        cfg = ProjectConfig(
            root=tmp_path,
            compiler_command="toolchain/msvc/5.0-win32/bin/cl.exe",
            compiler_runner="tools/wibo",
        )
        result = resolve_cl_command(cfg)
        assert result[0] == str(tmp_path / "tools/wibo")
        assert result[1].endswith("toolchain/msvc/5.0-win32/bin/cl.exe")

    def test_resolve_cl_command_bare_runner_untouched(self, tmp_path: Path) -> None:
        """Bare runner names (wine/wibo on PATH) pass through unchanged."""
        cfg = ProjectConfig(
            root=tmp_path,
            compiler_command="toolchain/msvc/5.0-win32/bin/cl.exe",
            compiler_runner="wine",
        )
        result = resolve_cl_command(cfg)
        assert result[0] == "wine"

    def test_msvc_env_runner_resolved_and_winedebug(self, tmp_path: Path) -> None:
        """msvc_env_from_config resolves the relative runner for the GA path
        and sets WINEDEBUG by basename (tools/wibo is still wibo)."""
        from rebrew.core.toolchain import msvc_env_from_config

        cfg = ProjectConfig(
            root=tmp_path,
            compiler_command="toolchain/msvc/5.0-win32/bin/cl.exe",
            compiler_runner="tools/wibo",
            compiler_includes="toolchain/msvc/5.0-win32/include",
            compiler_libs="toolchain/msvc/5.0-win32/lib",
        )
        env = msvc_env_from_config(cfg)
        assert env["REBREW_COMPILER_RUNNER"] == str(tmp_path / "tools/wibo")
        assert env["WINEDEBUG"] == "-all"


class TestCompileToObjBorlandc55:
    """borlandc55 routes through the toolchain runner with bcc32 flags
    (`-c` compile-only; the object follows the source stem — `-o obj` would
    misparse obj as an input file in Borland's flag dialect)."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(
            root=tmp_path,
            compiler_profile="borlandc55",
            compiler_command="bcc32.exe",
            base_cflags="",
            compiler_includes=tmp_path / "h",
            compiler_runner="",
            compile_timeout=30,
        )

    def test_borlandc55_uses_toolchain_runner(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import compile_to_obj
        from rebrew.toolchain import RunResult

        captured: dict = {}

        def _fake_run(spec, args, *, workdir, timeout, mounts=None):
            captured["args"] = args
            obj = workdir / "t.obj"
            obj.write_bytes(b"OMF")
            return RunResult(0, "", "", backend="host")

        monkeypatch.setattr("rebrew.compile.run_toolchain", _fake_run)
        monkeypatch.setattr("rebrew.compile.compile_cache_key", lambda **k: "k")
        monkeypatch.setattr("rebrew.compile.get_compile_cache", lambda *a, **k: None)

        src = tmp_path / "t.c"
        src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
        workdir = tmp_path / "work"
        workdir.mkdir()
        obj, err = compile_to_obj(self._cfg(tmp_path), src, [], workdir, use_cache=False)
        assert obj is not None and err == ""
        assert "-c" in captured["args"]
        assert "t.c" in captured["args"]
        assert "-o" not in captured["args"]


class TestPerFunctionOverrideArgShape:
    def test_16bit_override_gets_wrapper_args(self, tmp_path: Path, monkeypatch) -> None:
        """A per-function TOOLCHAIN override to a 16-bit toolchain must use
        the 16-bit DOSBox wrapper arg shape (source first), not the config
        profile's 32-bit /Fo shape (spec.name drives the branch)."""
        from rebrew.compile import compile_to_obj
        from rebrew.toolchain import RunResult

        captured: dict = {}

        def _fake_run(spec, args, *, workdir, timeout, mounts=None):
            captured["args"] = args
            (workdir / "F.OBJ").write_bytes(b"OMF")
            return RunResult(0, "", "", backend="docker")

        monkeypatch.setattr("rebrew.compile.run_toolchain", _fake_run)
        monkeypatch.setattr("rebrew.compile.get_compile_cache", lambda *a, **k: None)

        cfg: Any = SimpleNamespace(
            root=tmp_path,
            compiler_profile="msvc6",  # 32-bit config profile
            compiler_command="",
            compiler_runner="",
            compiler_includes="toolchain/msvc/6.0-win32/VC98/Include",
            base_cflags="",
            compile_timeout=30,
            posix_style=False,
            cflags_presets={},
            cflags="",
            cflags_explicit=False,
        )
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        source = src_dir / "f.c"
        source.write_text("int f(void){return 1;}\n", encoding="utf-8")
        work = tmp_path / "work"
        work.mkdir()
        obj, err = compile_to_obj(cfg, source, [], work, use_cache=False, toolchain="msvc1.52")
        assert obj is not None and err == ""
        assert captured["args"][0] == "f.c"  # source first (wrapper convention)
        assert not any(a.startswith("/Fo") for a in captured["args"])


class TestCompileEdgeCases:
    def test_obj_name_with_separator_rejected(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import compile_to_obj

        monkeypatch.setattr("rebrew.compile.get_compile_cache", lambda *a, **k: None)
        cfg: Any = SimpleNamespace(
            root=tmp_path,
            compiler_profile="msvc6",
            compiler_command="",
            compiler_runner="",
            compiler_includes="",
            base_cflags="",
            compile_timeout=10,
            posix_style=False,
            cflags_presets={},
            cflags="",
            cflags_explicit=False,
        )
        src = tmp_path / "f.c"
        src.write_text("int f(void){return 1;}", encoding="utf-8")
        work = tmp_path / "w"
        work.mkdir()
        obj, err = compile_to_obj(cfg, src, [], work, use_cache=False, obj_name="../evil.obj")
        assert obj is None
        assert "plain filename" in err

    def test_success_without_object_reports_error(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import compile_to_obj
        from rebrew.toolchain import RunResult

        def _fake_run(spec, args, *, workdir, timeout, mounts=None):
            return RunResult(0, "", "", backend="docker")  # no object written

        monkeypatch.setattr("rebrew.compile.run_toolchain", _fake_run)
        monkeypatch.setattr("rebrew.compile.get_compile_cache", lambda *a, **k: None)
        cfg: Any = SimpleNamespace(
            root=tmp_path,
            compiler_profile="msvc6",
            compiler_command="",
            compiler_runner="",
            compiler_includes="",
            base_cflags="",
            compile_timeout=10,
            posix_style=False,
            cflags_presets={},
            cflags="",
            cflags_explicit=False,
        )
        src = tmp_path / "f.c"
        src.write_text("int f(void){return 1;}", encoding="utf-8")
        work = tmp_path / "w"
        work.mkdir()
        obj, err = compile_to_obj(cfg, src, [], work, use_cache=False)
        assert obj is None
        assert "produced no object" in err
