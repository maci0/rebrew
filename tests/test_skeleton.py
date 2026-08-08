"""Tests for rebrew.skeleton — utility functions for skeleton generation."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from rebrew.catalog import FunctionEntry
from rebrew.config import ProjectConfig
from rebrew.naming import (
    find_neighbor_file,
    load_existing_vas,
    make_filename,
    sanitize_name,
)
from rebrew.skeleton import (
    generate_annotation_block,
    generate_diff_command,
    generate_skeleton,
    generate_test_command,
    list_uncovered,
)

# -------------------------------------------------------------------------
# sanitize_name
# -------------------------------------------------------------------------


class TestSanitizeName:
    def test_fun_prefix(self) -> None:
        assert sanitize_name("FUN_10001000") == "func_10001000"

    def test_special_chars(self) -> None:
        assert sanitize_name("my.func!@#$") == "my_func"

    def test_leading_digit(self) -> None:
        assert sanitize_name("123abc") == "_123abc"

    def test_consecutive_underscores(self) -> None:
        assert sanitize_name("my___func") == "my_func"

    def test_empty(self) -> None:
        assert sanitize_name("") == "unnamed"

    def test_max_length(self) -> None:
        long_name = "a" * 100
        result = sanitize_name(long_name)
        assert len(result) <= 64

    def test_strip_underscores(self) -> None:
        assert sanitize_name("__my_func__") == "my_func"


# -------------------------------------------------------------------------
# make_filename
# -------------------------------------------------------------------------


class TestMakeFilename:
    def test_fun_prefix(self) -> None:
        assert make_filename(0x10001000, "FUN_10001000") == "func_10001000.c"

    def test_custom_name(self) -> None:
        result = make_filename(0x10001000, "whatever", "my_func")
        assert result.endswith(".c")
        assert "my_func" in result

    def test_no_origin_prefix(self) -> None:
        assert make_filename(0x10001000, "ParsePacket") == "ParsePacket.c"

    def test_no_origin_prefix_msvcrt(self) -> None:
        assert make_filename(0x10001000, "memset") == "memset.c"

    def test_name_with_prefix_unchanged(self) -> None:
        assert make_filename(0x10001000, "game_something") == "game_something.c"


# -------------------------------------------------------------------------
# generate_test_command
# -------------------------------------------------------------------------


class TestGenerateTestCommand:
    def test_basic(self) -> None:
        cmd = generate_test_command("src/game_func.c", "_my_func", 0x10001000, 64, "/O2 /Gd")
        assert "rebrew test" in cmd
        assert "src/game_func.c" in cmd


# -------------------------------------------------------------------------
# generate_diff_command
# -------------------------------------------------------------------------


class TestGenerateDiffCommand:
    def test_basic(self) -> None:
        cmd = generate_diff_command("src/game_func.c", "_my_func", "/O2")
        assert "rebrew diff" in cmd
        assert "src/game_func.c" in cmd


# -------------------------------------------------------------------------
# load_existing_vas
# -------------------------------------------------------------------------


class TestLoadExistingVas:
    def test_scans_files(self, tmp_path: Path) -> None:
        c_file = tmp_path / "game_func.c"
        c_file.write_text(
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _my_func\n"
            "void __cdecl _my_func(void) {}\n",
            encoding="utf-8",
        )
        result = load_existing_vas(str(tmp_path))
        assert 0x10001000 in result

    def test_empty_dir(self, tmp_path: Path) -> None:
        result = load_existing_vas(str(tmp_path))
        assert result == {}


# -------------------------------------------------------------------------
# list_uncovered
# -------------------------------------------------------------------------


class TestListUncovered:
    def setup_method(self) -> None:
        self.cfg = ProjectConfig(
            root=Path("/tmp"),
            ignored_symbols=[],
        )

    def test_filters_existing(self) -> None:
        ghidra = [
            FunctionEntry(va=0x10001000, tool_name="func_a", size=64),
            FunctionEntry(va=0x10002000, tool_name="func_b", size=128),
        ]
        existing = {0x10001000: "func_a.c"}
        result = list_uncovered(ghidra, existing, self.cfg)
        result_vas = {va for va, _, _ in result}
        assert 0x10001000 not in result_vas
        assert 0x10002000 in result_vas
        assert len(result) == 1

    def test_size_filter(self) -> None:
        ghidra = [
            FunctionEntry(va=0x10001000, tool_name="tiny", size=2),
            FunctionEntry(va=0x10002000, tool_name="big", size=5000),
            FunctionEntry(va=0x10003000, tool_name="normal", size=64),
        ]
        result = list_uncovered(ghidra, {}, self.cfg, min_size=10, max_size=1000)
        vas = [va for va, _, _ in result]
        assert 0x10001000 not in vas
        assert 0x10002000 not in vas
        assert 0x10003000 in vas

    def test_merges_function_list_only_entries(self, tmp_path: Path) -> None:
        """Functions known only to the function list (not the Ghidra cache) appear."""
        from rebrew.skeleton import list_uncovered

        cfg = ProjectConfig(
            root=tmp_path,
            ignored_symbols=[],
            function_list=str(tmp_path / "functions.txt"),
        )
        (tmp_path / "functions.txt").write_text(
            "  0x10005000     32  fcn.10005000\n", encoding="utf-8"
        )
        ghidra = [FunctionEntry(va=0x10001000, tool_name="func_a", size=64)]
        result = list_uncovered(ghidra, {}, cfg)
        vas = {va for va, _, _ in result}
        assert 0x10001000 in vas  # ghidra entry
        assert 0x10005000 in vas  # list-only entry


# -------------------------------------------------------------------------
# generate_skeleton — library_modules flow
# -------------------------------------------------------------------------


class TestGenerateSkeletonModules:
    """Verify generate_skeleton and generate_annotation_block use library_modules."""

    def _make_cfg(self, **overrides: Any) -> ProjectConfig:
        defaults: dict[str, Any] = dict(
            marker="SERVER",
            library_modules={"DIRECTX"},
        )
        defaults.update(overrides)
        return ProjectConfig(root=Path("/tmp"), **defaults)

    def test_library_module_uses_library_marker(self) -> None:
        cfg = self._make_cfg()
        content = generate_skeleton(cfg, 0x10001000, "dx_init", "DIRECTX")
        assert content.startswith("// LIBRARY: SERVER")

    def test_non_library_module_uses_function_marker(self) -> None:
        cfg = self._make_cfg()
        content = generate_skeleton(cfg, 0x10001000, "game_func", "SERVER")
        assert content.startswith("// FUNCTION: SERVER")

    def test_annotation_block_library_module(self) -> None:
        cfg = self._make_cfg()
        block = generate_annotation_block(cfg, 0x10001000, "dx_init", "DIRECTX")
        assert block.startswith("// LIBRARY: SERVER")

    def test_default_comment_in_skeleton(self) -> None:
        cfg = self._make_cfg()
        content = generate_skeleton(cfg, 0x10001000, "my_func", "SERVER")
        assert "TODO: Implement" in content


# -------------------------------------------------------------------------
# find_neighbor_file
# -------------------------------------------------------------------------


class TestFindNeighborFile:
    def test_empty_dict(self) -> None:
        assert find_neighbor_file(0x10001000, {}) is None

    def test_left_neighbor_within_gap(self) -> None:
        existing = {0x10001000: "func_a.c"}
        # 0x100 bytes away — well within default 0x1000 gap
        assert find_neighbor_file(0x10001100, existing) == "func_a.c"

    def test_right_neighbor_within_gap(self) -> None:
        existing = {0x10002000: "func_b.c"}
        assert find_neighbor_file(0x10001F00, existing) == "func_b.c"

    def test_no_neighbor_beyond_gap(self) -> None:
        existing = {0x10001000: "func_a.c"}
        # 0x2000 bytes away — beyond default 0x1000 gap
        assert find_neighbor_file(0x10003000, existing) is None

    def test_closest_neighbor_wins(self) -> None:
        existing = {
            0x10001000: "func_a.c",
            0x10001200: "func_b.c",
        }
        # 0x10001180 is closer to 0x10001200 (right, 0x80 gap)
        # than to 0x10001000 (left, 0x180 gap)
        assert find_neighbor_file(0x10001180, existing) == "func_b.c"

    def test_exact_gap_boundary(self) -> None:
        existing = {0x10001000: "func_a.c"}
        # Exactly at max_gap distance
        assert find_neighbor_file(0x10002000, existing, max_gap=0x1000) == "func_a.c"

    def test_one_past_gap_boundary(self) -> None:
        existing = {0x10001000: "func_a.c"}
        assert find_neighbor_file(0x10002001, existing, max_gap=0x1000) is None

    def test_custom_max_gap(self) -> None:
        existing = {0x10001000: "func_a.c"}
        assert find_neighbor_file(0x10001080, existing, max_gap=0x80) == "func_a.c"
        assert find_neighbor_file(0x10001090, existing, max_gap=0x80) is None

    def test_exact_va_match(self) -> None:
        """If the VA is already covered, it should still return the file."""
        existing = {0x10001000: "func_a.c"}
        assert find_neighbor_file(0x10001000, existing) == "func_a.c"

    def test_pre_sorted_keys(self) -> None:
        """Pre-sorted keys should produce the same result as auto-sorting."""
        existing = {0x10001000: "func_a.c", 0x10001200: "func_b.c"}
        sorted_keys = sorted(existing)
        result_auto = find_neighbor_file(0x10001180, existing)
        result_pre = find_neighbor_file(0x10001180, existing, _sorted_keys=sorted_keys)
        assert result_auto == result_pre == "func_b.c"

    def test_left_closer_than_right(self) -> None:
        """When left neighbor is closer, it should be preferred."""
        existing = {0x10001000: "left.c", 0x10001500: "right.c"}
        # 0x10001080 is 0x80 from left, 0x480 from right
        assert find_neighbor_file(0x10001080, existing) == "left.c"


class TestGenerateAnnotationBlock:
    def _cfg(self) -> object:
        from types import SimpleNamespace

        return SimpleNamespace(library_modules=set(), marker="SERVER")

    def test_basic_block(self) -> None:
        from rebrew.skeleton import generate_annotation_block

        block = generate_annotation_block(self._cfg(), 0x1000, "FUN_10001000")
        assert "FUNCTION: SERVER 0x00001000" in block
        assert "func_10001000" in block

    def test_custom_name_wins(self) -> None:
        from rebrew.skeleton import generate_annotation_block

        block = generate_annotation_block(
            self._cfg(), 0x1000, "FUN_10001000", custom_name="my_func"
        )
        assert "my_func" in block
        assert "func_10001000" not in block

    def test_library_module_marker(self) -> None:
        from types import SimpleNamespace

        from rebrew.skeleton import generate_annotation_block

        cfg = SimpleNamespace(library_modules={"MSVCRT"}, marker="SERVER")
        block = generate_annotation_block(cfg, 0x1000, "FUN_10001000", module="MSVCRT")
        assert "LIBRARY" in block


class TestSkeletonListFallback:
    """single-VA mode falls back to the function list when Ghidra lacks the VA."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        (tmp_path / "md").mkdir(exist_ok=True)
        (tmp_path / "functions.txt").write_text(
            "  0x10001000     42  fcn.10001000\n", encoding="utf-8"
        )
        (tmp_path / "game.dll").write_bytes(b"\x00" * 256)
        return SimpleNamespace(
            root=tmp_path,
            reversed_dir=src_dir,
            metadata_dir=tmp_path / "md",
            marker="GAME",
            source_ext=".c",
            function_list=tmp_path / "functions.txt",
            target_binary=tmp_path / "game.dll",
            iat_thunks=set(),
            dll_exports={},
            library_modules=set(),
        )

    def test_single_va_generates_from_list_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        import rebrew.skeleton as sk

        cfg = self._cfg(tmp_path)
        monkeypatch.setattr(sk, "require_config", lambda target=None, json_mode=False: cfg)
        # No function_structure.json exists — the fallback must kick in.
        result = CliRunner().invoke(sk.app, ["0x10001000"])
        assert result.exit_code == 0
        # Without the fallback this exits 1 with "not found in function_structure.json".
        created = list((tmp_path / "src").glob("*.c"))
        assert len(created) == 1
        text = created[0].read_text(encoding="utf-8")
        assert "0x10001000" in text  # marker from the list-derived entry

    def test_unresolved_va_errors_cleanly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        import rebrew.skeleton as sk

        cfg = self._cfg(tmp_path)
        monkeypatch.setattr(sk, "require_config", lambda target=None, json_mode=False: cfg)
        result = CliRunner().invoke(sk.app, ["0x10009999"])
        assert result.exit_code != 0
        assert "not found" in result.output


class TestSkeletonMetadataSize:
    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        src = tmp_path / "src"
        src.mkdir(exist_ok=True)
        (tmp_path / "md").mkdir(exist_ok=True)
        (tmp_path / "functions.txt").write_text(
            "  0x10001000     42  fcn.10001000\n", encoding="utf-8"
        )
        (tmp_path / "game.dll").write_bytes(b"\x00" * 256)
        return SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            metadata_dir=tmp_path / "md",
            marker="GAME",
            source_ext=".c",
            function_list=tmp_path / "functions.txt",
            target_binary=tmp_path / "game.dll",
            iat_thunks=set(),
            dll_exports={},
            library_modules=set(),
        )

    def test_single_va_writes_size_metadata(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        import rebrew.skeleton as sk

        cfg = self._cfg(tmp_path)
        monkeypatch.setattr(sk, "require_config", lambda target=None, json_mode=False: cfg)
        result = CliRunner().invoke(sk.app, ["0x10001000"])
        assert result.exit_code == 0
        from rebrew.metadata import get_entry

        entry = get_entry(cfg.metadata_dir, 0x10001000, "GAME")
        assert entry.get("size") == 42  # from the function list, now verifiable

    def test_existing_size_not_overwritten(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata import update_field
        from rebrew.skeleton import _write_skeleton_metadata

        cfg = self._cfg(tmp_path)
        update_field(cfg.metadata_dir, 0x10001000, "size", 99, module="GAME")
        _write_skeleton_metadata(cfg, 0x10001000, 42, "GAME")
        from rebrew.metadata import get_entry

        assert get_entry(cfg.metadata_dir, 0x10001000, "GAME").get("size") == 99


class TestSkeletonDryRun:
    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        src = tmp_path / "src"
        src.mkdir(exist_ok=True)
        (tmp_path / "md").mkdir(exist_ok=True)
        (tmp_path / "functions.txt").write_text(
            "  0x10001000     42  fcn.10001000\n  0x10002000     10  fcn.10002000\n",
            encoding="utf-8",
        )
        (tmp_path / "game.dll").write_bytes(b"\x00" * 256)
        return SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            metadata_dir=tmp_path / "md",
            marker="GAME",
            source_ext=".c",
            function_list=tmp_path / "functions.txt",
            target_binary=tmp_path / "game.dll",
            iat_thunks=set(),
            dll_exports={},
            library_modules=set(),
            ignored_symbols=[],
        )

    def test_single_dry_run_creates_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        import rebrew.skeleton as sk

        cfg = self._cfg(tmp_path)
        monkeypatch.setattr(sk, "require_config", lambda target=None, json_mode=False: cfg)
        result = CliRunner().invoke(sk.app, ["--dry-run", "0x10001000"])
        assert result.exit_code == 0
        assert "Would create" in result.output
        assert not list((tmp_path / "src").glob("*.c"))

    def test_batch_dry_run_creates_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        import rebrew.skeleton as sk

        cfg = self._cfg(tmp_path)
        monkeypatch.setattr(sk, "require_config", lambda target=None, json_mode=False: cfg)
        result = CliRunner().invoke(sk.app, ["--batch", "5", "--dry-run"])
        assert result.exit_code == 0
        assert result.output.count("Would create") == 2
        assert "CREATED" not in result.output
        assert not list((tmp_path / "src").glob("*.c"))
