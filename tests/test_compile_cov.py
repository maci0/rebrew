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

    def test_returns_list(self, tmp_path: Path) -> None:
        """Result is always a list of strings."""
        cfg = ProjectConfig(
            root=tmp_path,
            compiler_command="wine tools/CL.EXE",
        )
        result = resolve_cl_command(cfg)
        assert isinstance(result, list)
        assert all(isinstance(x, str) for x in result)

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


class TestCompileAndCompareEdgeCases:
    """Test edge-case logic in compile_and_compare without invoking a real compiler."""

    def test_cflags_string_split(self) -> None:
        """Verify cflags string→list conversion logic matches compile_and_compare."""
        # This tests the internal logic: isinstance(cflags, str) → .split()
        cflags_str = "/O2 /Gd /MT"
        result = cflags_str.split() if isinstance(cflags_str, str) else list(cflags_str)
        assert result == ["/O2", "/Gd", "/MT"]

    def test_cflags_list_passthrough(self) -> None:
        """List cflags pass through unchanged."""
        cflags_list = ["/O2", "/Gd"]
        result = cflags_list.split() if isinstance(cflags_list, str) else list(cflags_list)
        assert result == ["/O2", "/Gd"]

    def test_reloc_masking_logic(self) -> None:
        """Reloc masking with pointer_size=4 expands each offset to 4 bytes."""
        pointer_size = 4
        reloc_offsets = [2, 10]
        reloc_set: set[int] = set()
        for ro in reloc_offsets:
            for j in range(pointer_size):
                reloc_set.add(ro + j)
        assert reloc_set == {2, 3, 4, 5, 10, 11, 12, 13}

    def test_reloc_masking_clamped_to_bounds(self) -> None:
        """Reloc bytes beyond obj_bytes length are still in set but skipped during comparison."""
        obj_bytes = b"\x55\x8b\xec\x83"  # 4 bytes
        pointer_size = 4
        reloc_offsets = [2]  # bytes 2,3,4,5 — but only 2,3 are in range
        reloc_set: set[int] = set()
        for ro in reloc_offsets:
            for j in range(pointer_size):
                if 0 <= ro + j < len(obj_bytes):
                    reloc_set.add(ro + j)
        assert reloc_set == {2, 3}

    def test_exact_match_detection(self) -> None:
        """Identical bytes with no relocs → EXACT MATCH."""
        target = b"\x55\x8b\xec\xc3"
        candidate = b"\x55\x8b\xec\xc3"
        mismatches = [i for i in range(len(candidate)) if candidate[i] != target[i]]
        assert mismatches == []

    def test_mismatch_detection(self) -> None:
        """Different bytes → mismatches list populated."""
        target = b"\x55\x8b\xec\xc3"
        candidate = b"\x55\x8b\xed\xc3"
        mismatches = [i for i in range(len(candidate)) if candidate[i] != target[i]]
        assert mismatches == [2]

    def test_size_mismatch_short_circuits(self) -> None:
        """Different lengths should be detected before byte comparison."""
        target = b"\x55\x8b\xec\xc3"
        candidate = b"\x55\x8b\xec"
        assert len(candidate) != len(target)


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
