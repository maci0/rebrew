"""Tests for rebrew.compile — backend selection and compile_and_compare helpers."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from rebrew.compile import compile_to_obj, filter_wine_stderr
from rebrew.config import ProjectConfig

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
    """gcc-pe / mingw (POSIX-style) compiler routing goes through run_toolchain."""

    def _run_compile(
        self, tmp_path: Path, monkeypatch, *, profile: str, cflags: list[str]
    ) -> list[str]:
        captured: dict[str, list[str]] = {}

        def _fake_run(spec, args, *, workdir, timeout, mounts=None):
            captured["args"] = args
            out = args[args.index("-o") + 1]
            (workdir / out).write_bytes(b"\x00")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr("rebrew.compile.run_toolchain", _fake_run)
        monkeypatch.setattr("rebrew.compile.get_compile_cache", lambda *a, **k: None)

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
        return captured["args"]

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
        monkeypatch.setattr("rebrew.toolchain.image_present", lambda tag: True)

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
        monkeypatch.setattr("rebrew.toolchain.image_present", lambda tag: True)

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

        monkeypatch.setattr("rebrew.toolchain.image_present", lambda tag: False)
        monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: True)
        monkeypatch.setattr("rebrew.compile.get_compile_cache", lambda *a, **k: None)

        src = tmp_path / "t.c"
        src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
        workdir = tmp_path / "work"
        workdir.mkdir()
        obj, err = compile_to_obj(self._cfg(tmp_path), src, [], workdir, use_cache=False)
        assert obj is None
        assert "not built" in err


# ---------------------------------------------------------------------------
# Linked single-function compare (padded shell + LINK.EXE oracle)
# ---------------------------------------------------------------------------


class TestLinkedShell:
    """Pure helpers of compile_and_compare_linked."""

    SRC = "int f(void){\n    return 1;\n}\n"

    def test_shell_source_with_pad(self) -> None:
        from rebrew.compile import linked_shell_source

        shell = linked_shell_source(self.SRC, 0x8320)
        assert '#pragma data_seg(".text$A")' in shell
        assert "__rebrew_linked_pad[33568]" in shell  # 0x8320 as a decimal array size
        assert "#pragma data_seg()" in shell
        assert '#pragma code_seg(".text$B")' in shell
        assert "int f(void)" in shell
        # The pad block precedes the function block.
        assert shell.index(".text$A") < shell.index(".text$B")

    def test_shell_source_no_pad(self) -> None:
        from rebrew.compile import linked_shell_source

        shell = linked_shell_source(self.SRC, 0)
        assert "data_seg" not in shell  # MSVC rejects zero-length arrays
        assert '#pragma code_seg(".text$B")' in shell
        assert "int f(void)" in shell

    def test_linked_pad_size(self) -> None:
        from rebrew.compile import linked_pad_size

        assert linked_pad_size(0x9320, 0x1000) == 0x8320
        assert linked_pad_size(0x1000, 0x1000) == 0
        assert linked_pad_size(0x900, 0x1000) == -1  # function precedes section

    def test_extract_linked_slice(self) -> None:
        from rebrew.compile import extract_linked_slice

        dll = b"\x00" * 0x1000 + b"ABCDEF"  # .text raw offset 0x1000
        assert extract_linked_slice(dll, 0x1000, 0, 3) == b"ABC"
        assert extract_linked_slice(dll, 0x1000, 1, 3) == b"BCD"
        # Window beyond the DLL end → truncated slice (SIZE_MISMATCH path).
        assert extract_linked_slice(dll, 0x1000, 0, 99) == b"ABCDEF"
        assert extract_linked_slice(dll, 0x1000, 99, 3) == b""

    def test_section_for_va(self) -> None:
        from rebrew.binary_loader import BinaryInfo, SectionInfo
        from rebrew.compile import _section_for_va

        info = BinaryInfo(
            path=Path("/nonexistent.dll"),
            format="pe",
            image_base=0x10000000,
            sections={
                "text": SectionInfo(
                    name="text",
                    va=0x10001000,
                    size=0x23000,
                    file_offset=0x1000,
                    raw_size=0x23000,
                ),
                "data": SectionInfo(
                    name="data", va=0x10050000, size=0x1000, file_offset=0x24000, raw_size=0x1000
                ),
            },
        )
        assert _section_for_va(info, 0x10009320) is info.sections["text"]
        assert _section_for_va(info, 0x10050FFF) is info.sections["data"]
        assert _section_for_va(info, 0x10090000) is None


class TestLinkedLinkCmd:
    """build_linked_link_cmd docker argv construction (no docker required)."""

    def _spec(self) -> Any:
        from rebrew.toolchain import ToolchainSpec

        return ToolchainSpec(
            name="msvc6",
            image="rebrew/msvc:6.0-win32",
            binary="cl",
            runtime="wine",
            flags_style="msvc",
            obj_ext=".obj",
            tool_root="/opt/msvc6.0/VC98/Bin",
            description="MSVC 6.0 (32-bit PE, C89) — docker image (wine inside)",
        )

    def test_cmd_shape_and_flags(self) -> None:
        from rebrew.compile import build_linked_link_cmd

        cmd, _script = build_linked_link_cmd(
            self._spec(), base=0x10000000, obj_name="f.obj", out_name="out.dll", workdir="/tmp/w"
        )
        assert cmd[:4] == ["docker", "run", "--rm", "--network=none"]
        # Named so a timed-out run can be killed instead of leaking under dockerd.
        assert cmd[4] == "--name"
        assert cmd[5].startswith("rebrew-link-")
        assert cmd[6:12] == ["-v", "/tmp/w:/work", "-w", "/work", "--entrypoint", "sh"]
        assert cmd[12] == "rebrew/msvc:6.0-win32"
        # LINK flags: DLL / NOENTRY at the target base, /OPT:NOREF + /OPT:NOICF.
        args = cmd[16:]
        assert "/DLL" in args and "/NOENTRY" in args
        assert "/BASE:0x10000000" in args
        assert "/ALIGN:4096" in args and "/FILEALIGN:4096" in args
        assert "/OPT:NOREF" in args and "/OPT:NOICF" in args
        assert "/NODEFAULTLIB" in args
        assert "/OUT:out.dll" in args and "f.obj" in args
        assert args.index("/OUT:out.dll") < args.index("f.obj")

    def test_script_exports_msvc_env_and_runs_link(self) -> None:
        from rebrew.compile import build_linked_link_cmd

        _cmd, script = build_linked_link_cmd(
            self._spec(), base=0x10000000, obj_name="f.obj", out_name="out.dll", workdir="/tmp/w"
        )
        assert "wrapper-common.sh" in script
        # Windows paths with escaped backslashes (wine Z: drive): the shell
        # turns each \\ into one \, yielding Z:\opt\msvc6.0\VC98\Include.
        assert 'INCLUDE="Z:\\\\opt\\\\msvc6.0\\\\VC98\\Include"' in script
        assert 'LIB="Z:\\\\opt\\\\msvc6.0\\\\VC98\\Lib"' in script
        assert 'rebrew_run /opt/msvc6.0/VC98/Bin/LINK.EXE "$@"' in script

    def test_no_image_raises(self) -> None:
        from rebrew.compile import build_linked_link_cmd
        from rebrew.toolchain import ToolchainError, ToolchainSpec

        native = ToolchainSpec(name="gcc-pe", image=None, binary="i686-w64-mingw32-gcc")
        try:
            build_linked_link_cmd(
                native, base=0x10000000, obj_name="f.o", out_name="o.dll", workdir="/tmp/w"
            )
        except ToolchainError as exc:
            assert "docker image" in str(exc)
        else:
            raise AssertionError("expected ToolchainError for image-less spec")


class TestLinkedSpec:
    def test_msvc_profile_resolves(self) -> None:
        from rebrew.compile import _linked_spec

        cfg: Any = SimpleNamespace(compiler_profile="msvc6")
        spec, err = _linked_spec(cfg, None)
        assert spec is not None and spec.name == "msvc6"
        assert err == ""

    def test_native_profile_rejected(self) -> None:
        from rebrew.compile import _linked_spec

        cfg: Any = SimpleNamespace(compiler_profile="gcc-pe")
        spec, err = _linked_spec(cfg, None)
        assert spec is None
        assert "MSVC" in err

    def test_non_msvc_image_rejected(self) -> None:
        from rebrew.compile import _linked_spec

        cfg: Any = SimpleNamespace(compiler_profile="borlandc55")
        spec, err = _linked_spec(cfg, None)
        assert spec is None
        assert "MSVC" in err
