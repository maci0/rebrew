"""Tests for the config loader and multi-target support."""

import os
from pathlib import Path

import pytest

# Import from the rebrew package
from rebrew.config import (
    _ARCH_PRESETS,
    ProjectConfig,
    _detect_binary_layout,
    _find_root,
    _resolve,
    load_config,
)

# ---------------------------------------------------------------------------
# Helper: create a temp rebrew-project.toml and return the root dir
# ---------------------------------------------------------------------------


def _make_project(tmp_path: Path, toml_content: str) -> Path:
    """Write a rebrew-project.toml and return the directory."""
    (tmp_path / "rebrew-project.toml").write_text(toml_content, encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------------------
# _resolve()
# ---------------------------------------------------------------------------


class TestResolve:
    def test_relative_path(self, tmp_path: Path) -> None:
        result = _resolve(tmp_path, "foo/bar.dll")
        assert result == tmp_path / "foo" / "bar.dll"

    def test_absolute_path(self, tmp_path: Path) -> None:
        result = _resolve(tmp_path, "/absolute/path.dll")
        assert result == Path("/absolute/path.dll")

    def test_dot_path(self, tmp_path: Path) -> None:
        result = _resolve(tmp_path, ".")
        assert result == tmp_path / "."

    def test_none_returns_none(self, tmp_path: Path) -> None:
        result = _resolve(tmp_path, None)
        assert result is None


# ---------------------------------------------------------------------------
# _find_root()
# ---------------------------------------------------------------------------


class TestFindRoot:
    def test_explicit_root(self, tmp_path: Path) -> None:
        assert _find_root(tmp_path) == tmp_path

    def test_auto_detect_from_cwd(self, tmp_path: Path) -> None:
        """Test that _find_root can find rebrew-project.toml from cwd."""
        (tmp_path / "rebrew-project.toml").write_text(
            "[targets.main]\nbinary = 'test.exe'\n", encoding="utf-8"
        )
        old_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            root = _find_root()
            assert (root / "rebrew-project.toml").exists()
        finally:
            os.chdir(old_cwd)


# ---------------------------------------------------------------------------
# Architecture presets
# ---------------------------------------------------------------------------


class TestArchPresets:
    def test_x86_32_exists(self) -> None:
        assert "x86_32" in _ARCH_PRESETS

    def test_x86_64_exists(self) -> None:
        assert "x86_64" in _ARCH_PRESETS

    def test_arm32_exists(self) -> None:
        assert "arm32" in _ARCH_PRESETS

    def test_arm64_exists(self) -> None:
        assert "arm64" in _ARCH_PRESETS

    def test_x86_32_pointer_size(self) -> None:
        assert _ARCH_PRESETS["x86_32"]["pointer_size"] == 4

    def test_x86_64_pointer_size(self) -> None:
        assert _ARCH_PRESETS["x86_64"]["pointer_size"] == 8

    def test_x86_padding_bytes(self) -> None:
        assert _ARCH_PRESETS["x86_32"]["padding_bytes"] == [0xCC, 0x90]

    def test_arm_padding_bytes(self) -> None:
        assert _ARCH_PRESETS["arm32"]["padding_bytes"] == [0x00]

    def test_x86_32_symbol_prefix(self) -> None:
        assert _ARCH_PRESETS["x86_32"]["symbol_prefix"] == "_"

    def test_x86_64_no_prefix(self) -> None:
        assert _ARCH_PRESETS["x86_64"]["symbol_prefix"] == ""


# ---------------------------------------------------------------------------
# load_config() — multi-target format
# ---------------------------------------------------------------------------


class TestLoadConfigMultiTarget:
    MULTI_TOML = """\
[targets.server_dll]
binary = "original/Server/server.dll"
format = "pe"
arch = "x86_32"
reversed_dir = "src/server_dll"
 function_list = "src/server_dll/functions.txt"
bin_dir = "bin/server_dll"

[targets.client_exe]
binary = "original/Client/client.exe"
format = "pe"
arch = "x86_64"
reversed_dir = "src/client_exe"
function_list = "src/client_exe/funcs.txt"

[compiler]
profile = "gcc"
command = "gcc"
includes = "/usr/include"
libs = "/usr/lib"
"""

    def test_default_first_target(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, self.MULTI_TOML)
        cfg = load_config(root)
        assert cfg.target_name == "server_dll"

    def test_explicit_target_selection(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, self.MULTI_TOML)
        cfg = load_config(root, target="client_exe")
        assert cfg.target_name == "client_exe"
        assert cfg.arch == "x86_64"

    def test_all_targets_listed(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, self.MULTI_TOML)
        cfg = load_config(root)
        assert cfg.all_targets == ["server_dll", "client_exe"]

    def test_missing_target_raises(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, self.MULTI_TOML)
        with pytest.raises(KeyError, match="nonexistent"):
            load_config(root, target="nonexistent")

    def test_binary_path_resolved(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, self.MULTI_TOML)
        cfg = load_config(root)
        assert cfg.target_binary == root / "original" / "Server" / "server.dll"

    def test_reversed_dir_resolved(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, self.MULTI_TOML)
        cfg = load_config(root)
        assert cfg.reversed_dir == root / "src" / "server_dll"

    def test_compiler_profile(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, self.MULTI_TOML)
        cfg = load_config(root)
        assert cfg.compiler_profile == "gcc"

    def test_arch_derived_values(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, self.MULTI_TOML)
        cfg = load_config(root, target="client_exe")
        assert cfg.pointer_size == 8
        assert cfg.symbol_prefix == ""

    def test_per_target_sources(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, self.MULTI_TOML)
        cfg1 = load_config(root, target="server_dll")
        cfg2 = load_config(root, target="client_exe")
        assert cfg1.reversed_dir != cfg2.reversed_dir
        assert "server_dll" in str(cfg1.reversed_dir)
        assert "client_exe" in str(cfg2.reversed_dir)


# ---------------------------------------------------------------------------
# load_config() — edge cases
# ---------------------------------------------------------------------------


class TestLoadConfigEdgeCases:
    def test_missing_toml_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path)

    def test_empty_targets_raises(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, "[compiler]\nprofile = 'msvc6'\n")
        with pytest.raises(KeyError):
            load_config(root)

    def test_minimal_toml(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.target_name == "main"
        assert cfg.binary_format == "pe"  # default
        assert cfg.arch == "x86_32"  # default
        assert cfg.reversed_dir == root / "src" / "main"
        assert cfg.function_list == root / "src" / "main" / "functions.txt"
        assert cfg.bin_dir == root / "bin" / "main"

    def test_unknown_arch_falls_back(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"
arch = "mips32"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match="unknown arch"):
            cfg = load_config(root)
        assert cfg.pointer_size == 4

    def test_wrong_list_types_fall_back(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"
origins = "GAME"
iat_thunks = "0x1000"
ignored_symbols = "_bad"
library_origins = "MSVCRT"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning):
            cfg = load_config(root)
        assert cfg.origins == []
        assert cfg.iat_thunks == []
        assert cfg.ignored_symbols == []
        assert cfg.library_origins == set()

    def test_wrong_mapping_type_falls_back(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"
dll_exports = "not-a-dict"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match="Expected mapping"):
            cfg = load_config(root)
        assert cfg.dll_exports == {}


# ---------------------------------------------------------------------------
# Origin config fields
# ---------------------------------------------------------------------------


class TestOriginConfig:
    def test_library_origins_from_toml(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"
origins = ["GAME", "MSVCRT", "ZLIB"]
library_origins = ["MSVCRT", "ZLIB"]
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.library_origins == {"MSVCRT", "ZLIB"}

    def test_library_origins_default_from_origins(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"
origins = ["GAME", "MSVCRT", "ZLIB"]
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        # Default: all except first origin
        assert cfg.library_origins == {"MSVCRT", "ZLIB"}

    def test_library_origins_empty_when_single_origin(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"
origins = ["GAME"]
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.library_origins == set()

    def test_origin_comments_from_toml(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[targets.main.origin_comments]
GAME = "Custom game comment"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.origin_comments == {"GAME": "Custom game comment"}

    def test_origin_todos_from_toml(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[targets.main.origin_todos]
GAME = "Implement from decompiler output"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.origin_todos == {"GAME": "Implement from decompiler output"}

    def test_defaults_when_not_set(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.library_origins == set()
        assert cfg.origin_comments == {}
        assert cfg.origin_todos == {}


# ---------------------------------------------------------------------------
# Per-origin compiler overrides
# ---------------------------------------------------------------------------


class TestOriginCompiler:
    def test_global_origins_parsed(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler]
profile = "msvc6"

[compiler.origins.ZLIB]
cflags = "/O3"
command = "wine MSVC7/CL.EXE"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert "ZLIB" in cfg.origin_compiler
        assert cfg.origin_compiler["ZLIB"]["cflags"] == "/O3"
        assert cfg.origin_compiler["ZLIB"]["command"] == "wine MSVC7/CL.EXE"

    def test_per_target_origins_parsed(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[targets.main.compiler.origins.ZLIB]
cflags = "/O2"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.origin_compiler["ZLIB"]["cflags"] == "/O2"

    def test_per_target_origins_override_global(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler.origins.ZLIB]
cflags = "/O3"
command = "wine MSVC7/CL.EXE"

[targets.main.compiler.origins.ZLIB]
cflags = "/O2"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.origin_compiler["ZLIB"]["cflags"] == "/O2"
        assert cfg.origin_compiler["ZLIB"]["command"] == "wine MSVC7/CL.EXE"

    def test_multiple_origins(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler.origins.ZLIB]
cflags = "/O3"

[compiler.origins.MSVCRT]
cflags = "/O1"
profile = "msvc7"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.origin_compiler["ZLIB"]["cflags"] == "/O3"
        assert cfg.origin_compiler["MSVCRT"]["cflags"] == "/O1"
        assert cfg.origin_compiler["MSVCRT"]["profile"] == "msvc7"

    def test_empty_origins(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.origin_compiler == {}

    def test_unknown_origin_compiler_key_warns(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler.origins.ZLIB]
cflags = "/O3"
bogus_key = "oops"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"unrecognized keys.*bogus_key"):
            load_config(root)

    def test_for_origin_returns_self_when_no_overrides(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.for_origin("GAME") is cfg

    def test_for_origin_overrides_command(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler]
command = "wine CL.EXE"

[compiler.origins.ZLIB]
command = "wine MSVC7/CL.EXE"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        zcfg = cfg.for_origin("ZLIB")
        assert zcfg.compiler_command == "wine MSVC7/CL.EXE"
        assert cfg.compiler_command == "wine CL.EXE"

    def test_for_origin_overrides_profile(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler]
profile = "msvc6"

[compiler.origins.MSVCRT]
profile = "msvc7"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.for_origin("MSVCRT").compiler_profile == "msvc7"
        assert cfg.compiler_profile == "msvc6"

    def test_for_origin_overrides_cflags(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler]
cflags = "/O2 /Gd"

[compiler.origins.ZLIB]
cflags = "/O3"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.for_origin("ZLIB").cflags == "/O3"
        assert cfg.cflags == "/O2 /Gd"

    def test_for_origin_overrides_base_cflags(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler.origins.ZLIB]
base_cflags = "/nologo /c /MD"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.for_origin("ZLIB").base_cflags == "/nologo /c /MD"
        assert cfg.base_cflags == "/nologo /c /MT"

    def test_for_origin_resolves_includes_path(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler.origins.ZLIB]
includes = "references/zlib"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.for_origin("ZLIB").compiler_includes == root / "references" / "zlib"

    def test_for_origin_does_not_mutate_original(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler]
cflags = "/O2 /Gd"
profile = "msvc6"

[compiler.origins.ZLIB]
cflags = "/O3"
profile = "msvc7"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        zcfg = cfg.for_origin("ZLIB")
        assert zcfg.cflags == "/O3"
        assert zcfg.compiler_profile == "msvc7"
        assert cfg.cflags == "/O2 /Gd"
        assert cfg.compiler_profile == "msvc6"

    def test_resolve_origin_cflags_from_origin_compiler(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler.cflags_presets]
ZLIB = "/O2"

[compiler.origins.ZLIB]
cflags = "/O3"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.resolve_origin_cflags("ZLIB") == "/O3"

    def test_resolve_origin_cflags_falls_back_to_presets(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler.cflags_presets]
GAME = "/O2 /Gd"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.resolve_origin_cflags("GAME") == "/O2 /Gd"

    def test_resolve_origin_cflags_falls_back_to_default(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.resolve_origin_cflags("UNKNOWN") == "/O2 /Gd"

    def test_full_merge_hierarchy(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler]
profile = "msvc6"
command = "wine CL.EXE"
cflags = "/O2 /Gd"

[targets.main.compiler]
cflags = "/O1"

[compiler.origins.ZLIB]
cflags = "/O3"
command = "wine MSVC7/CL.EXE"

[targets.main.compiler.origins.ZLIB]
cflags = "/Ox"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.cflags == "/O1"
        assert cfg.compiler_command == "wine CL.EXE"
        zcfg = cfg.for_origin("ZLIB")
        assert zcfg.cflags == "/Ox"
        assert zcfg.compiler_command == "wine MSVC7/CL.EXE"
        assert zcfg.compiler_profile == "msvc6"


class TestRunnerField:
    def test_runner_from_toml(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler]
runner = "wibo"
command = "tools/MSVC600/VC98/Bin/CL.EXE"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.compiler_runner == "wibo"
        assert cfg.compiler_command == "tools/MSVC600/VC98/Bin/CL.EXE"

    def test_runner_auto_detect_wine(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler]
command = "wine CL.EXE"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.compiler_runner == "wine"
        assert cfg.compiler_command == "wine CL.EXE"

    def test_runner_auto_detect_wibo(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler]
command = "wibo CL.EXE"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.compiler_runner == "wibo"
        assert cfg.compiler_command == "wibo CL.EXE"

    def test_runner_empty_for_native(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler]
runner = ""
command = "cl"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.compiler_runner == ""
        assert cfg.compiler_command == "cl"

    def test_runner_default_no_runner_no_wine(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler]
command = "CL.EXE"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.compiler_runner == ""
        assert cfg.compiler_command == "CL.EXE"

    def test_runner_origin_override(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler]
runner = "wine"
command = "CL.EXE"

[compiler.origins.ZLIB]
runner = "wibo"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.origin_compiler["ZLIB"]["runner"] == "wibo"

    def test_for_origin_overrides_runner(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler]
runner = "wine"
command = "CL.EXE"

[compiler.origins.ZLIB]
runner = "wibo"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.for_origin("ZLIB").compiler_runner == "wibo"


# ---------------------------------------------------------------------------
# ProjectConfig methods
# ---------------------------------------------------------------------------


class TestProjectConfig:
    def test_va_to_file_offset(self) -> None:
        cfg = ProjectConfig(root=Path("."))
        cfg.text_va = 0x10001000
        cfg.text_raw_offset = 0x400
        assert cfg.va_to_file_offset(0x10001000) == 0x400
        assert cfg.va_to_file_offset(0x10001100) == 0x500

    def test_default_values(self) -> None:
        cfg = ProjectConfig(root=Path("."))
        assert cfg.binary_format == "pe"
        assert cfg.arch == "x86_32"
        assert cfg.pointer_size == 4
        assert cfg.padding_bytes == [0xCC, 0x90]
        assert cfg.image_base == 0
        assert cfg.text_va == 0
        assert cfg.text_raw_offset == 0


# ---------------------------------------------------------------------------
# PE layout detection
# ---------------------------------------------------------------------------


class TestPEDetection:
    def test_nonexistent_file_returns_zeros(self) -> None:
        with pytest.warns(UserWarning, match="Could not detect binary layout"):
            result = _detect_binary_layout(Path("/nonexistent/file.dll"))
        assert result["image_base"] == 0
        assert result["text_va"] == 0
        assert result["text_raw_offset"] == 0

    def test_non_pe_file_returns_zeros(self, tmp_path: Path) -> None:
        fake = tmp_path / "not_a_pe.dll"
        fake.write_bytes(b"this is not a PE file")
        with pytest.warns(UserWarning, match="Could not detect binary layout"):
            result = _detect_binary_layout(fake)
        assert result["image_base"] == 0


# ---------------------------------------------------------------------------
# Tool smoke tests (import + help)
# ---------------------------------------------------------------------------


class TestToolImports:
    """Verify all tools can be imported and have correct signatures."""

    def test_import_config(self) -> None:
        from rebrew.config import load_config

        assert callable(load_config)
        import inspect

        sig = inspect.signature(load_config)
        assert "root" in sig.parameters or "target" in sig.parameters

    def test_import_cli(self) -> None:
        from rebrew.cli import get_config

        assert callable(get_config)

    def test_import_matcher_scoring(self) -> None:
        from rebrew.matcher.scoring import score_candidate

        assert callable(score_candidate)
        import inspect

        sig = inspect.signature(score_candidate)
        assert "target_bytes" in sig.parameters
        assert "candidate_bytes" in sig.parameters

    def test_import_matcher_parsers(self) -> None:
        from rebrew.matcher.parsers import parse_obj_symbol_bytes

        assert callable(parse_obj_symbol_bytes)

    def test_import_matcher_compiler(self) -> None:
        from rebrew.matcher.compiler import build_candidate_obj_only

        assert callable(build_candidate_obj_only)

    def test_import_matcher_core(self) -> None:
        from rebrew.matcher.core import BuildResult, Score

        s = Score(
            length_diff=0,
            byte_score=1.0,
            reloc_score=0.5,
            mnemonic_score=0.3,
            prologue_bonus=0.0,
            total=42.0,
        )
        assert s.total == 42.0
        br = BuildResult(ok=True, obj_bytes=b"\x55")
        assert br.ok is True
        assert br.obj_bytes == b"\x55"

    def test_import_matcher_mutator(self) -> None:
        from rebrew.matcher.mutator import mutate_code

        assert callable(mutate_code)

    def test_import_binary_loader(self) -> None:
        from rebrew.binary_loader import BinaryInfo, extract_bytes_at_va, load_binary

        assert callable(load_binary)
        assert callable(extract_bytes_at_va)
        info = BinaryInfo(
            path=Path("/tmp/test.dll"),
            format="pe",
            image_base=0x10000000,
            text_va=0x1000,
            text_size=0x1000,
        )
        assert info.format == "pe"
        assert info.image_base == 0x10000000
        assert info.text_size == 0x1000

    def test_import_detect_binary_layout(self) -> None:
        from rebrew.config import _detect_binary_layout

        assert callable(_detect_binary_layout)


# ---------------------------------------------------------------------------
# Config validation layer (Idea 18)
# ---------------------------------------------------------------------------


class TestConfigValidation:
    """Tests for unknown-key warnings and value-type validation."""

    def test_unknown_top_level_key_warns(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[bogus_section]
foo = "bar"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match="unrecognized top-level keys.*bogus_section"):
            load_config(root)

    def test_unknown_target_key_warns(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"
typo_field = "oops"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"unrecognized keys.*typo_field"):
            load_config(root)

    def test_unknown_compiler_key_warns(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler]
profile = "msvc6"
misspelled_option = "bad"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"unrecognized keys.*misspelled_option"):
            load_config(root)

    def test_unknown_project_key_warns(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[project]
name = "test"
bogus = "oops"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"unrecognized keys.*bogus"):
            load_config(root)

    def test_unknown_arch_warns(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"
arch = "sparc64"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"unknown arch 'sparc64'"):
            cfg = load_config(root)
        assert cfg.pointer_size == 4  # falls back to x86_32

    def test_unknown_format_warns(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"
format = "coff"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"unknown format 'coff'"):
            load_config(root)

    def test_unknown_profile_warns(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"

[compiler]
profile = "turbo_c"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"unknown profile 'turbo_c'"):
            load_config(root)

    def test_valid_config_no_warnings(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"
format = "pe"
arch = "x86_32"
marker = "MAIN"
origins = ["GAME"]

[compiler]
profile = "msvc6"
command = "wine CL.EXE"
"""
        root = _make_project(tmp_path, toml)
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            cfg = load_config(root)
        assert cfg.target_name == "main"

    def test_multiple_typos_warn_separately(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"
binaryx = "typo"
formatx = "typo"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"unrecognized keys"):
            load_config(root)
