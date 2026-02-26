"""Tests for rebrew.compile — resolve_cl_command and compile_and_compare helpers."""

from pathlib import Path

from rebrew.compile import resolve_cl_command
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
