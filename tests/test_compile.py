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
        """wine + relative CL.EXE path is resolved against cfg.root."""
        cfg = ProjectConfig(
            root=tmp_path,
            compiler_command="wine toolchain/msvc/6.0-win32/VC98/Bin/CL.EXE",
        )
        result = resolve_cl_command(cfg)
        assert result[0] == "wine"
        assert result[1] == str(tmp_path / "toolchain/msvc/6.0-win32/VC98/Bin/CL.EXE")

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

        def _fake_run(spec, args, *, workdir, timeout):  # noqa: ARG001
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

    def test_watcom_runner_failure_surfaces(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import compile_to_obj
        from rebrew.toolchain import RunResult

        def _fake_run(spec, args, *, workdir, timeout):  # noqa: ARG001
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

        def _fake_run(spec, args, *, workdir, timeout):  # noqa: ARG001
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

        def _fake_run(spec, args, *, workdir, timeout):  # noqa: ARG001
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

    def test_host_fallback_when_no_image(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import compile_to_obj

        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: False)
        captured: dict = {}

        def _fake_msvc16_compile(local_src, workdir, cflags, timeout):  # noqa: ARG001
            captured["host"] = True
            (workdir / "T.OBJ").write_bytes(b"OMF")
            return type("R", (), {"obj_path": workdir / "T.OBJ"})()

        monkeypatch.setattr("rebrew.msvc16.compile_c", _fake_msvc16_compile)
        monkeypatch.setattr("rebrew.compile.get_compile_cache", lambda *a, **k: None)

        src = tmp_path / "t.c"
        src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
        workdir = tmp_path / "work"
        workdir.mkdir()
        obj, err = compile_to_obj(self._cfg(tmp_path), src, [], workdir, use_cache=False)
        assert obj is not None
        assert captured.get("host") is True


def test_resolve_compiler_env_falls_back_to_install(tmp_path: Path, monkeypatch) -> None:
    """resolve_compiler_env (the GA/flag-sweep path) must resolve the CL path
    with the install-tools fallback — previously it kept the relative path,
    and `rebrew match` failed with wine rc 53 on projects without a local
    tools/ symlink while `rebrew test` worked."""
    from rebrew import utils as rebrew_utils
    from rebrew.compile import resolve_compiler_env
    from rebrew.config import ProjectConfig

    fake = tmp_path / "toolchain" / "msvc" / "5.0-win32" / "bin" / "cl.exe"
    fake.parent.mkdir(parents=True)
    fake.write_bytes(b"MZ")
    (tmp_path / "toolchain" / "msvc" / "5.0-win32" / "include").mkdir(parents=True)
    monkeypatch.setattr(rebrew_utils, "_REPO_ROOT", tmp_path)

    cfg = ProjectConfig(
        root=tmp_path / "project",
        compiler_command="wine toolchain/msvc/5.0-win32/bin/cl.exe",
        compiler_includes="toolchain/msvc/5.0-win32/include",
    )
    cl_cmd, _inc_dir, _env, _cc = resolve_compiler_env(cfg)
    assert cl_cmd == f"wine {fake}"  # inc_dir fallback is a load_config concern


# ---------------------------------------------------------------------------
# maybe_headless_wine
# ---------------------------------------------------------------------------


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
