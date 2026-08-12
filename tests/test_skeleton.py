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
# _stale_size_note
# -------------------------------------------------------------------------


class TestStaleSizeNote:
    """skeleton warns when the resolved size is stale (disassembly extent
    runs past it) so the first `rebrew test --size N` does not fail with
    SIZE_MISMATCH on a truncated functions.txt entry."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(
            arch="x86_32",
            target_binary=tmp_path / "x.exe",
        )

    def test_extent_larger_warns(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.skeleton import _stale_size_note

        (tmp_path / "x.exe").write_bytes(b"MZ")
        monkeypatch.setattr("rebrew.binary_loader.function_extent_from_disasm", lambda p, va: 121)
        note = _stale_size_note(self._cfg(tmp_path), 0x1000, 44)
        assert note is not None
        assert "44B is stale" in note
        assert "121B" in note
        assert "--fix-size" in note

    def test_accurate_size_no_warning(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.skeleton import _stale_size_note

        (tmp_path / "x.exe").write_bytes(b"MZ")
        monkeypatch.setattr("rebrew.binary_loader.function_extent_from_disasm", lambda p, va: 42)
        assert _stale_size_note(self._cfg(tmp_path), 0x1000, 50) is None

    def test_missing_binary_no_warning(self, tmp_path: Path) -> None:
        from rebrew.skeleton import _stale_size_note

        assert _stale_size_note(self._cfg(tmp_path), 0x1000, 44) is None

    def test_non_x86_arch_no_warning(self, tmp_path: Path) -> None:
        from types import SimpleNamespace as NS

        from rebrew.skeleton import _stale_size_note

        (tmp_path / "x.exe").write_bytes(b"MZ")
        cfg = NS(arch="x86_16", target_binary=tmp_path / "x.exe")
        assert _stale_size_note(cfg, 0x1000, 44) is None


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
    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        return SimpleNamespace(
            root=tmp_path,
            reversed_dir=src_dir,
            metadata_dir=tmp_path,
            marker="SERVER",
            target_name="SERVER",
            source_ext=".c",
        )

    def test_scans_files(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        c_file = src_dir / "game_func.c"
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
        result = load_existing_vas(src_dir, cfg=self._cfg(tmp_path))
        assert 0x10001000 in result

    def test_empty_dir(self, tmp_path: Path) -> None:
        result = load_existing_vas(tmp_path / "src", cfg=self._cfg(tmp_path))
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


class TestDecompBody:
    """K2: skeleton --decomp-body writes decompiled C as the function body."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(
            reversed_dir=tmp_path,
            marker="SERVER",
            metadata_dir=tmp_path,
            library_modules=set(),
            target_name="SERVER",
        )

    def test_decomp_body_writes_implementation(self, tmp_path: Path) -> None:
        cfg = self._cfg(tmp_path)
        content = generate_skeleton(
            cfg,
            0x1000,
            "my_func",
            decomp_code="int my_func(int a) { return a + 1; }",
            decomp_backend="r2ghidra",
            decomp_body=True,
        )
        # No comment wrapper; the decompiled body is the implementation.
        assert "=== Decompilation" not in content
        assert "int my_func(int a) { return a + 1; }" in content

    def test_decomp_body_renames_to_marker_function(self, tmp_path: Path) -> None:
        cfg = self._cfg(tmp_path)
        content = generate_skeleton(
            cfg,
            0x1000,
            "my_func",
            decomp_code="int orig_name(int a) { return a * 2; }",
            decomp_backend="r2ghidra",
            decomp_body=True,
        )
        assert "int my_func(int a) { return a * 2; }" in content  # renamed
        assert "orig_name" not in content

    def test_decomp_body_without_decomp_falls_back(self, tmp_path: Path) -> None:
        cfg = self._cfg(tmp_path)
        content = generate_skeleton(
            cfg, 0x1000, "my_func", decomp_code=None, decomp_backend="x", decomp_body=True
        )
        assert "return 0;" in content  # plain stub fallback

    def test_decomp_comment_mode_unchanged(self, tmp_path: Path) -> None:
        cfg = self._cfg(tmp_path)
        content = generate_skeleton(
            cfg,
            0x1000,
            "my_func",
            decomp_code="int my_func(void) { return 1; }",
            decomp_backend="r2ghidra",
            decomp_body=False,
        )
        assert "=== Decompilation (r2ghidra) ===" in content  # comment mode intact

    def test_cli_rejects_decomp_body_without_decomp(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--decomp-body alone was an accepted-but-inert flag: it silently
        produced a plain stub (functionality-review F7).  The CLI must fail
        loudly instead of pretending the option applied."""
        from typer.testing import CliRunner

        import rebrew.skeleton as sk
        from rebrew.main import app as umbrella

        cfg = self._cfg(tmp_path)
        monkeypatch.setattr(sk, "require_config", lambda target=None, json_mode=False: cfg)
        result = CliRunner().invoke(umbrella, ["skeleton", "0x10001000", "--decomp-body"])
        assert result.exit_code != 0
        assert "requires --decomp" in result.output
        # Nothing written.
        assert not list((tmp_path / "src").glob("*.c"))


class TestThunkFilter:
    """list_uncovered skips import/jump/call thunks — they have no
    decompilable body and waste batch skeleton slots."""

    def _cfg(self, tmp_path: Path) -> ProjectConfig:
        return ProjectConfig(
            root=tmp_path,
            ignored_symbols=[],
            arch="x86_32",
            target_binary=tmp_path / "x.exe",
        )

    def test_skips_import_thunk(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.skeleton import list_uncovered

        cfg = self._cfg(tmp_path)
        ghidra = [
            FunctionEntry(va=0x10001000, tool_name="import_thunk", size=16),
            FunctionEntry(va=0x10002000, tool_name="real_func", size=64),
        ]
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_raw_bytes",
            lambda p, va, n: b"\xff\x25\x00\x00\x00\x00" if va == 0x10001000 else b"\x55\x8b\xec",
        )
        result = list_uncovered(ghidra, {}, cfg)
        vas = {va for va, _, _ in result}
        assert 0x10001000 not in vas
        assert 0x10002000 in vas

    def test_skips_call_thunk(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.skeleton import list_uncovered

        cfg = self._cfg(tmp_path)
        ghidra = [
            FunctionEntry(va=0x10001000, tool_name="call_thunk", size=32),
            FunctionEntry(va=0x10002000, tool_name="real_func", size=64),
        ]
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_raw_bytes",
            lambda p, va, n: (
                b"\xe8\x00\x00\x00\x00\xe9\x00\x00\x00\x00" if va == 0x10001000 else b"\x55\x8b\xec"
            ),
        )
        result = list_uncovered(ghidra, {}, cfg)
        vas = {va for va, _, _ in result}
        assert 0x10001000 not in vas
        assert 0x10002000 in vas

    def test_keeps_real_function(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.skeleton import list_uncovered

        cfg = self._cfg(tmp_path)
        ghidra = [FunctionEntry(va=0x10001000, tool_name="real_func", size=64)]
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_raw_bytes",
            lambda p, va, n: b"\x55\x8b\xec\x83\xec\x10",
        )
        result = list_uncovered(ghidra, {}, cfg)
        assert [va for va, _, _ in result] == [0x10001000]

    def test_skips_non_x86_32(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.skeleton import list_uncovered

        cfg = self._cfg(tmp_path)
        cfg.arch = "x86_16"  # thunk detection is 32-bit-only
        ghidra = [FunctionEntry(va=0x10001000, tool_name="maybe_thunk", size=16)]
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_raw_bytes",
            lambda p, va, n: b"\xff\x25\x00\x00\x00\x00",
        )
        result = list_uncovered(ghidra, {}, cfg)
        assert [va for va, _, _ in result] == [0x10001000]


class TestConventionStub:
    """rebrew skeleton emits a calling-convention-aware signature instead of
    the generic `int __cdecl f(void)` — thiscall/stdcall shapes from rebrew
    asm's inference."""

    def _cfg(self, tmp_path: Path) -> Any:
        from types import SimpleNamespace as NS

        return NS(arch="x86_32", target_binary=str(tmp_path / "x.exe"))

    def test_thiscall_no_args(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.skeleton import _convention_stub

        # push esi; mov esi,ecx; mov eax,[esi+0x6c]; test; ret
        code = bytes.fromhex("56 8b f1 8b 46 6c 85 c0 5e c3")
        monkeypatch.setattr("rebrew.binary_loader.extract_raw_bytes", lambda p, va, n: code)
        sig, note = _convention_stub(self._cfg(tmp_path), 0x1000, "f")
        assert sig == "int __fastcall f(void *self)"
        assert note is None

    def test_thiscall_with_stack_args_naked(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.skeleton import _convention_stub

        # mov esi,ecx; mov eax,[esi]; call [eax+0x40]; ret 8
        code = bytes.fromhex("8b f1 8b 06 ff 50 40 c2 08 00")
        monkeypatch.setattr("rebrew.binary_loader.extract_raw_bytes", lambda p, va, n: code)
        sig, note = _convention_stub(self._cfg(tmp_path), 0x1000, "f")
        assert sig == "__declspec(naked) int f(void *self, int a1, int a2)"
        assert note is not None and "ret 8" in note

    def test_stdcall_args(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.skeleton import _convention_stub

        # mov eax,[esp+4]; mov ecx,[esp+8]; ret 8
        code = bytes.fromhex("8b 44 24 04 8b 4c 24 08 c2 08 00")
        monkeypatch.setattr("rebrew.binary_loader.extract_raw_bytes", lambda p, va, n: code)
        sig, note = _convention_stub(self._cfg(tmp_path), 0x1000, "f")
        assert sig == "int __stdcall f(int a1, int a2)"
        assert note is None

    def test_cdecl_default(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.skeleton import _convention_stub

        # mov eax,[esp+4]; ret
        code = bytes.fromhex("8b 44 24 04 c3")
        monkeypatch.setattr("rebrew.binary_loader.extract_raw_bytes", lambda p, va, n: code)
        sig, note = _convention_stub(self._cfg(tmp_path), 0x1000, "f")
        assert sig is None
        assert note is None

    def test_non_x86_arch_default(self, tmp_path: Path) -> None:
        from types import SimpleNamespace as NS

        from rebrew.skeleton import _convention_stub

        cfg = NS(arch="x86_16", target_binary=str(tmp_path / "x.exe"))
        sig, note = _convention_stub(cfg, 0x1000, "f")
        assert sig is None and note is None

    def test_long_function_with_branch_merge_jmp(self, tmp_path: Path, monkeypatch: Any) -> None:
        """A function whose real body extends past the old 48-byte flat window
        (extent walk terminated on a mid-function branch-merge jmp) must still
        get the correct thiscall stub — the window is padded past the jmp."""
        from rebrew.skeleton import _convention_stub

        # mov esi,ecx; (NOPs); ...; ret 0x10  — 60 bytes total, real thiscall
        code = bytes.fromhex("8b f1") + b"\x90" * 56 + bytes.fromhex("c2 10 00")
        assert len(code) > 48  # the old window would have truncated before ret
        monkeypatch.setattr(
            "rebrew.binary_loader.function_extent_from_disasm",
            lambda p, va, with_kind=True: (20, "jmp"),  # branch-merge jmp, not a thunk
        )
        monkeypatch.setattr("rebrew.binary_loader.extract_raw_bytes", lambda p, va, n: code[:n])
        sig, note = _convention_stub(self._cfg(tmp_path), 0x1000, "f")
        assert sig == "__declspec(naked) int f(void *self, int a1, int a2, int a3, int a4)"
        assert note is not None and "ret 16" in note

    def test_tail_call_arg_count_resolves_decorated_callee(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """A forwarding tail call resolves the callee's @N decoration to the
        caller's stack-arg count (stdcall forwarding pattern)."""
        from types import SimpleNamespace as NS

        from rebrew.skeleton import _tail_call_arg_count

        cfg = NS(arch="x86_32", target_binary=str(tmp_path / "x.exe"))
        monkeypatch.setattr(
            "rebrew.asm.build_function_lookup",
            lambda c: {0x1009C76: ("@fcn_01009c76@8", "RELOC")},
        )
        insns = [
            type("I", (), {"mnemonic": "call", "op_str": "dword ptr [0x1001d0c]"})(),
            type("I", (), {"mnemonic": "jmp", "op_str": "0x1009c76"})(),
        ]
        n, callee = _tail_call_arg_count(insns, cfg)  # type: ignore[arg-type]
        assert n == 2
        assert "fcn_01009c76@8" in callee

    def test_tail_call_with_unresolved_callee_generic_note(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """No decorated name for the target → plain signature + note."""
        from rebrew.skeleton import _convention_stub

        monkeypatch.setattr("rebrew.asm.build_function_lookup", lambda c: {})
        monkeypatch.setattr(
            "rebrew.binary_loader.function_extent_from_disasm",
            lambda p, va, with_kind=True: (42, "jmp"),
        )
        # mov esi,ecx; ...; jmp 0x1009c76  (real body, tail call)
        code = bytes.fromhex("8b f1 8b 01 ff 50 04 e9 00 00 00 00")
        monkeypatch.setattr("rebrew.binary_loader.extract_raw_bytes", lambda p, va, n: code)
        sig, note = _convention_stub(self._cfg(tmp_path), 0x1000, "f")
        assert sig is None
        assert note is not None and "tail call" in note

    def test_tail_call_thunk_stays_exact(self, tmp_path: Path, monkeypatch: Any) -> None:
        """A small jmp-terminated region (≤16 B) is a real tail-call thunk —
        the window must NOT be padded past it (would misread the next
        function's epilogue as ours)."""
        from rebrew.skeleton import _convention_stub

        # jmp [0x4130c8]  → 6-byte import thunk
        code = bytes.fromhex("ff 25 c8 30 41 00")
        monkeypatch.setattr(
            "rebrew.binary_loader.function_extent_from_disasm",
            lambda p, va, with_kind=True: (6, "jmp"),
        )
        monkeypatch.setattr("rebrew.binary_loader.extract_raw_bytes", lambda p, va, n: code[:n])
        sig, note = _convention_stub(self._cfg(tmp_path), 0x1000, "f")
        assert sig is None
        assert note is not None and "tail-call thunk" in note


class TestLooksLikeFragment:
    """Data regions / misaligned discovery entries start with non-code
    bytes — the opt-in --skip-fragments filter flags them so batch skeleton
    slots are not wasted on non-code."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        from types import SimpleNamespace as NS

        return NS(arch="x86_32", target_binary=tmp_path / "x.exe")

    def test_data_start_flagged(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.skeleton import _looks_like_fragment

        (tmp_path / "x.exe").write_bytes(b"MZ")
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_raw_bytes", lambda p, va, n: bytes.fromhex("13 24")
        )
        assert _looks_like_fragment(self._cfg(tmp_path), 0x1000) is True

    def test_prologue_start_not_flagged(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.skeleton import _looks_like_fragment

        (tmp_path / "x.exe").write_bytes(b"MZ")
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_raw_bytes", lambda p, va, n: bytes.fromhex("55 8b")
        )
        assert _looks_like_fragment(self._cfg(tmp_path), 0x1000) is False

    def test_non_x86_not_flagged(self, tmp_path: Path) -> None:
        from types import SimpleNamespace as NS

        from rebrew.skeleton import _looks_like_fragment

        cfg = NS(arch="x86_16", target_binary=tmp_path / "x.exe")
        assert _looks_like_fragment(cfg, 0x1000) is False


class TestMergedRegionNote:
    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(arch="x86_32", target_binary=tmp_path / "x.exe")

    def test_multiple_epilogues_warns(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.skeleton import _stale_size_note

        (tmp_path / "x.exe").write_bytes(b"MZ")
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_raw_bytes",
            lambda p, va, n: bytes.fromhex("b8 01 00 00 00 c3 b8 02 00 00 00 c3"),
        )
        monkeypatch.setattr("rebrew.binary_loader.function_extent_from_disasm", lambda p, va: None)
        note = _stale_size_note(self._cfg(tmp_path), 0x1000, 12)
        assert note is not None
        assert "multiple functions" in note
        assert "3" not in note  # 2 epilogues
        assert "2 ret-terminated" in note

    def test_single_epilogue_no_merged_warning(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.skeleton import _stale_size_note

        (tmp_path / "x.exe").write_bytes(b"MZ")
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_raw_bytes",
            lambda p, va, n: bytes.fromhex("55 8b ec 83 ec 08 b8 01 00 00 00 c9 c3"),
        )
        monkeypatch.setattr("rebrew.binary_loader.function_extent_from_disasm", lambda p, va: 12)
        assert _stale_size_note(self._cfg(tmp_path), 0x1000, 12) is None
