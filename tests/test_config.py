"""Tests for the config loader and multi-target support."""

import os
from pathlib import Path

import pytest

# Import from the rebrew package
from rebrew.config import (
    _ARCH_PRESETS,
    ProjectConfig,
    _detect_binary_layout,
    _detect_pe_layout,
    _find_root,
    _resolve,
    load_config,
)

# ---------------------------------------------------------------------------
# Helper: create a temp rebrew.toml and return the root dir
# ---------------------------------------------------------------------------

def _make_project(tmp_path: Path, toml_content: str) -> Path:
    """Write a rebrew.toml and return the directory."""
    (tmp_path / "rebrew.toml").write_text(toml_content)
    return tmp_path


# ---------------------------------------------------------------------------
# _resolve()
# ---------------------------------------------------------------------------

class TestResolve:
    def test_relative_path(self, tmp_path: Path):
        result = _resolve(tmp_path, "foo/bar.dll")
        assert result == tmp_path / "foo" / "bar.dll"

    def test_absolute_path(self, tmp_path: Path):
        result = _resolve(tmp_path, "/absolute/path.dll")
        assert result == Path("/absolute/path.dll")

    def test_dot_path(self, tmp_path: Path):
        result = _resolve(tmp_path, ".")
        assert result == tmp_path / "."

    def test_none_returns_none(self, tmp_path: Path):
        result = _resolve(tmp_path, None)
        assert result is None


# ---------------------------------------------------------------------------
# _find_root()
# ---------------------------------------------------------------------------

class TestFindRoot:
    def test_explicit_root(self, tmp_path: Path):
        assert _find_root(tmp_path) == tmp_path

    def test_auto_detect_from_cwd(self, tmp_path: Path):
        """Test that _find_root can find rebrew.toml from cwd."""
        (tmp_path / "rebrew.toml").write_text("[targets.main]\nbinary = 'test.exe'\n")
        old_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            root = _find_root()
            assert (root / "rebrew.toml").exists()
        finally:
            os.chdir(old_cwd)


# ---------------------------------------------------------------------------
# Architecture presets
# ---------------------------------------------------------------------------

class TestArchPresets:
    def test_x86_32_exists(self):
        assert "x86_32" in _ARCH_PRESETS

    def test_x86_64_exists(self):
        assert "x86_64" in _ARCH_PRESETS

    def test_arm32_exists(self):
        assert "arm32" in _ARCH_PRESETS

    def test_arm64_exists(self):
        assert "arm64" in _ARCH_PRESETS

    def test_x86_32_pointer_size(self):
        assert _ARCH_PRESETS["x86_32"]["pointer_size"] == 4

    def test_x86_64_pointer_size(self):
        assert _ARCH_PRESETS["x86_64"]["pointer_size"] == 8

    def test_x86_padding_bytes(self):
        assert _ARCH_PRESETS["x86_32"]["padding_bytes"] == [0xCC, 0x90]

    def test_arm_padding_bytes(self):
        assert _ARCH_PRESETS["arm32"]["padding_bytes"] == [0x00]

    def test_x86_32_symbol_prefix(self):
        assert _ARCH_PRESETS["x86_32"]["symbol_prefix"] == "_"

    def test_x86_64_no_prefix(self):
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
function_list = "src/server_dll/r2_functions.txt"
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

    def test_default_first_target(self, tmp_path: Path):
        root = _make_project(tmp_path, self.MULTI_TOML)
        cfg = load_config(root)
        assert cfg.target_name == "server_dll"

    def test_explicit_target_selection(self, tmp_path: Path):
        root = _make_project(tmp_path, self.MULTI_TOML)
        cfg = load_config(root, target="client_exe")
        assert cfg.target_name == "client_exe"
        assert cfg.arch == "x86_64"

    def test_all_targets_listed(self, tmp_path: Path):
        root = _make_project(tmp_path, self.MULTI_TOML)
        cfg = load_config(root)
        assert cfg.all_targets == ["server_dll", "client_exe"]

    def test_missing_target_raises(self, tmp_path: Path):
        root = _make_project(tmp_path, self.MULTI_TOML)
        with pytest.raises(KeyError, match="nonexistent"):
            load_config(root, target="nonexistent")

    def test_binary_path_resolved(self, tmp_path: Path):
        root = _make_project(tmp_path, self.MULTI_TOML)
        cfg = load_config(root)
        assert cfg.target_binary == root / "original" / "Server" / "server.dll"

    def test_reversed_dir_resolved(self, tmp_path: Path):
        root = _make_project(tmp_path, self.MULTI_TOML)
        cfg = load_config(root)
        assert cfg.reversed_dir == root / "src" / "server_dll"

    def test_compiler_profile(self, tmp_path: Path):
        root = _make_project(tmp_path, self.MULTI_TOML)
        cfg = load_config(root)
        assert cfg.compiler_profile == "gcc"

    def test_arch_derived_values(self, tmp_path: Path):
        root = _make_project(tmp_path, self.MULTI_TOML)
        cfg = load_config(root, target="client_exe")
        assert cfg.pointer_size == 8
        assert cfg.symbol_prefix == ""

    def test_per_target_sources(self, tmp_path: Path):
        root = _make_project(tmp_path, self.MULTI_TOML)
        cfg1 = load_config(root, target="server_dll")
        cfg2 = load_config(root, target="client_exe")
        assert cfg1.reversed_dir != cfg2.reversed_dir
        assert "server_dll" in str(cfg1.reversed_dir)
        assert "client_exe" in str(cfg2.reversed_dir)


# ---------------------------------------------------------------------------
# load_config() — legacy single-target format
# ---------------------------------------------------------------------------

class TestLoadConfigLegacy:
    LEGACY_TOML = """\
[target]
binary = "original/Server/server.dll"
format = "pe"
arch = "x86_32"

[sources]
reversed_dir = "src/server_dll"
function_list = "src/server_dll/r2_functions.txt"

[compiler]
profile = "msvc6"
command = "wine CL.EXE"
includes = "tools/MSVC600/VC98/Include"
"""

    def test_legacy_loads(self, tmp_path: Path):
        root = _make_project(tmp_path, self.LEGACY_TOML)
        cfg = load_config(root)
        assert cfg.binary_format == "pe"
        assert cfg.arch == "x86_32"

    def test_legacy_target_name_derived(self, tmp_path: Path):
        root = _make_project(tmp_path, self.LEGACY_TOML)
        cfg = load_config(root)
        # target_name derived from binary path
        assert cfg.target_name is not None
        assert len(cfg.target_name) > 0

    def test_legacy_sources_section(self, tmp_path: Path):
        root = _make_project(tmp_path, self.LEGACY_TOML)
        cfg = load_config(root)
        assert "server_dll" in str(cfg.reversed_dir)


# ---------------------------------------------------------------------------
# load_config() — edge cases
# ---------------------------------------------------------------------------

class TestLoadConfigEdgeCases:
    def test_missing_toml_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path)

    def test_empty_targets_raises(self, tmp_path: Path):
        root = _make_project(tmp_path, "[compiler]\nprofile = 'msvc6'\n")
        with pytest.raises(KeyError):
            load_config(root)

    def test_minimal_toml(self, tmp_path: Path):
        toml = """\
[targets.main]
binary = "test.exe"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.target_name == "main"
        assert cfg.binary_format == "pe"  # default
        assert cfg.arch == "x86_32"  # default

    def test_unknown_arch_falls_back(self, tmp_path: Path):
        toml = """\
[targets.main]
binary = "test.exe"
arch = "mips32"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        # Should fall back to x86_32 preset
        assert cfg.pointer_size == 4


# ---------------------------------------------------------------------------
# ProjectConfig methods
# ---------------------------------------------------------------------------

class TestProjectConfig:
    def test_va_to_file_offset(self):
        cfg = ProjectConfig(root=Path("."))
        cfg.text_va = 0x10001000
        cfg.text_raw_offset = 0x400
        assert cfg.va_to_file_offset(0x10001000) == 0x400
        assert cfg.va_to_file_offset(0x10001100) == 0x500

    def test_default_values(self):
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
    def test_nonexistent_file_returns_zeros(self):
        result = _detect_pe_layout(Path("/nonexistent/file.dll"))
        assert result["image_base"] == 0
        assert result["text_va"] == 0
        assert result["text_raw_offset"] == 0

    def test_non_pe_file_returns_zeros(self, tmp_path: Path):
        fake = tmp_path / "not_a_pe.dll"
        fake.write_bytes(b"this is not a PE file")
        result = _detect_pe_layout(fake)
        assert result["image_base"] == 0

    def test_binary_layout_alias(self):
        """_detect_pe_layout is an alias for _detect_binary_layout."""
        assert _detect_pe_layout is _detect_binary_layout


# ---------------------------------------------------------------------------
# Tool smoke tests (import + help)
# ---------------------------------------------------------------------------

class TestToolImports:
    """Verify all tools can be imported from rebrew package."""

    def test_import_config(self):
        from rebrew.config import load_config
        assert load_config is not None

    def test_import_cli(self):
        from rebrew.cli import get_config
        assert get_config is not None

    def test_import_matcher_scoring(self):
        from rebrew.matcher.scoring import score_candidate
        assert score_candidate is not None

    def test_import_matcher_parsers(self):
        from rebrew.matcher.parsers import parse_coff_obj_symbol_bytes
        assert parse_coff_obj_symbol_bytes is not None

    def test_import_matcher_compiler(self):
        from rebrew.matcher.compiler import build_candidate_obj_only
        assert build_candidate_obj_only is not None

    def test_import_matcher_core(self):
        from rebrew.matcher.core import BuildResult, Score
        assert Score is not None
        assert BuildResult is not None

    def test_import_matcher_mutator(self):
        from rebrew.matcher.mutator import mutate_code
        assert mutate_code is not None

    def test_import_binary_loader(self):
        from rebrew.binary_loader import BinaryInfo, extract_bytes_at_va, load_binary
        assert load_binary is not None
        assert BinaryInfo is not None
        assert extract_bytes_at_va is not None

    def test_import_detect_binary_layout(self):
        from rebrew.config import _detect_binary_layout
        assert _detect_binary_layout is not None
