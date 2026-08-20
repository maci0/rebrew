"""Tests for the config loader and multi-target support."""

from pathlib import Path

import pytest

# Import from the rebrew package
from rebrew.config import (
    _ARCH_PRESETS,
    ProjectConfig,
    _detect_binary_layout,
    _resolve,
    find_root,
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
# find_root()
# ---------------------------------------------------------------------------


class TestFindRoot:
    def test_explicit_root(self, tmp_path: Path) -> None:
        assert find_root(tmp_path) == tmp_path

    def test_auto_detect_from_cwd(self, tmp_path: Path, monkeypatch) -> None:
        """Test that find_root can find rebrew-project.toml from cwd."""
        (tmp_path / "rebrew-project.toml").write_text(
            "[targets.main]\nbinary = 'test.exe'\n", encoding="utf-8"
        )
        monkeypatch.chdir(tmp_path)
        root = find_root()
        assert (root / "rebrew-project.toml").exists()


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
[project]
default_target = "server_dll"

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

    def test_missing_default_target_raises(self, tmp_path: Path) -> None:
        """Missing default_target in [project] should raise KeyError."""
        toml = """\
[targets.server_dll]
binary = "test.exe"
"""
        root = _make_project(tmp_path, toml)
        with pytest.raises(KeyError, match="default_target"):
            load_config(root)

    def test_default_target_from_project(self, tmp_path: Path) -> None:
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
[project]
default_target = "main"

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
[project]
default_target = "main"

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
[project]
default_target = "main"

[targets.main]
binary = "test.exe"
iat_thunks = "0x1000"
ignored_symbols = "_bad"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning):
            cfg = load_config(root)
        assert cfg.iat_thunks == []
        assert cfg.ignored_symbols == []

    def test_wrong_mapping_type_falls_back(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"
dll_exports = "not-a-dict"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match="Expected mapping"):
            cfg = load_config(root)
        assert cfg.dll_exports == {}

    def test_wrong_crt_sources_type_falls_back(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"
crt_sources = "toolchain/msvc/6.0-win32/VC98/CRT/SRC"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match="Expected mapping for crt_sources"):
            cfg = load_config(root)
        assert cfg.crt_sources == {}

    def test_game_range_end_hex_string(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"
game_range_end = "0x1000ABCD"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.game_range_end == 0x1000ABCD

    def test_source_ext_without_dot_is_normalized(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"
source_ext = "cpp"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match="missing a leading dot"):
            cfg = load_config(root)
        assert cfg.source_ext == ".cpp"

    def test_invalid_source_ext_defaults(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"
source_ext = "src/*.c"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match="source_ext must be a file extension"):
            cfg = load_config(root)
        assert cfg.source_ext == ".c"

    def test_source_ext_multi_list(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"
source_ext = ".c,.cpp"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.source_ext == ".c,.cpp"

    def test_source_ext_multi_normalized(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"
source_ext = "c, cpp"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.source_ext == ".c,.cpp"


class TestRunnerField:
    def test_runner_from_toml(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[compiler]
runner = "wibo"
command = "toolchain/msvc/6.0-win32/VC98/Bin/CL.EXE"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.compiler_runner == "wibo"
        assert cfg.compiler_command == "toolchain/msvc/6.0-win32/VC98/Bin/CL.EXE"

    def test_runner_auto_detect_wine(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

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
[project]
default_target = "main"

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
[project]
default_target = "main"

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
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[compiler]
command = "CL.EXE"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.compiler_runner == ""
        assert cfg.compiler_command == "CL.EXE"


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


# ---------------------------------------------------------------------------
# Config validation layer (Idea 18)
# ---------------------------------------------------------------------------


class TestConfigValidation:
    """Tests for unknown-key warnings and value-type validation."""

    def test_unknown_top_level_key_warns(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[bogus_section]
foo = "bar"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match="unrecognized top-level keys.*bogus_section"):
            load_config(root)

    def test_llm_section_parsed(self, tmp_path: Path) -> None:
        """The documented `[llm]` table must reach cfg.llm_endpoint/api_key —
        it was previously not in the known top-level keys, so the table
        warned "unrecognized" and the fields were always "" (config-review
        F2: match --llm-seed's error message points users at `[llm]`)."""
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[llm]
endpoint = "http://localhost:9000/v1"
api_key = "secret-key"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.llm_endpoint == "http://localhost:9000/v1"
        assert cfg.llm_api_key == "secret-key"

    def test_dead_config_keys_warn(self, tmp_path: Path) -> None:
        """Reserved/no-op keys ([compiler.profiles], game_range_end) must warn
        at load — a user configuring them gets zero effect, so the no-op must
        be visible, not silent (config-review F5)."""
        toml = """\
[project]
default_target = "main"

[compiler.profiles.clang]
command = "clang"

[targets.main]
binary = "test.exe"
game_range_end = 0x20000000
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match="RESERVED and currently has no effect"):
            load_config(root)
        with pytest.warns(UserWarning, match="legacy no-op key"):
            load_config(root)

    def test_unknown_target_key_warns(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"
typo_field = "oops"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"unrecognized keys.*typo_field"):
            load_config(root)

    def test_unknown_compiler_key_warns(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

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
[project]
name = "test"
default_target = "main"
bogus = "oops"

[targets.main]
binary = "test.exe"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"unrecognized keys.*bogus"):
            load_config(root)

    def test_unknown_arch_warns(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"
arch = "sparc64"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"unknown arch 'sparc64'"):
            cfg = load_config(root)
        assert cfg.pointer_size == 4  # falls back to x86_32

    def test_unknown_format_falls_back_to_pe(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"
format = "coff"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"unknown format 'coff'"):
            cfg = load_config(root)
        assert cfg.binary_format == "pe"

    def test_ne_format_accepted(self, tmp_path: Path) -> None:
        """format = "ne" (written by intake for 16-bit NE targets) must load
        without the unknown-format fallback warning."""
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"
format = "ne"
arch = "x86_16"
"""
        root = _make_project(tmp_path, toml)
        # A real (minimal) NE binary so is_ne() routes to the native loader.
        ne = bytearray(0x300)
        ne[0:2] = b"MZ"
        ne[0x3C:0x40] = (0x100).to_bytes(4, "little")
        ne[0x100:0x102] = b"NE"
        (root / "test.exe").write_bytes(bytes(ne))
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("error", UserWarning)  # no unknown-format warn
            cfg = load_config(root)
        assert cfg.binary_format == "ne"

    def test_unknown_profile_falls_back_to_msvc6(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[compiler]
profile = "turbo_c"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"unknown profile 'turbo_c'"):
            cfg = load_config(root)
        assert cfg.compiler_profile == "msvc6"

    def test_empty_binary_raises(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = ""
"""
        root = _make_project(tmp_path, toml)
        with pytest.raises(KeyError, match="empty 'binary'"):
            load_config(root)

    def test_non_string_default_target_raises(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = true

[targets.main]
binary = "test.exe"
"""
        root = _make_project(tmp_path, toml)
        with pytest.raises(ValueError, match="default_target must be a string"):
            load_config(root)

    def test_empty_default_target_raises(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = ""

[targets.main]
binary = "test.exe"
"""
        root = _make_project(tmp_path, toml)
        with pytest.raises(ValueError, match="default_target must not be empty"):
            load_config(root)

    def test_non_string_cflags_falls_back(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[compiler]
cflags = 42
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"Expected string for compiler.cflags"):
            cfg = load_config(root)
        assert cfg.cflags == ""

    def test_msvc400_profile_is_known(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[compiler]
profile = "msvc400"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.compiler_profile == "msvc400"

    def test_non_positive_jobs_and_timeout_default(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"
jobs = 0

[targets.main]
binary = "test.exe"

[compiler]
timeout = -1
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning):
            cfg = load_config(root)
        assert cfg.default_jobs == 4
        assert cfg.compile_timeout == 60

    def test_valid_config_no_warnings(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"
format = "pe"
arch = "x86_32"
marker = "MAIN"

[compiler]
profile = "msvc6"
command = "wine CL.EXE"
"""
        root = _make_project(tmp_path, toml)
        # A valid project has its target binary present; a missing binary now
        # warns at load time (image_base auto-detection is skipped).
        from bin_util import make_pe

        (root / "test.exe").write_bytes(make_pe(b"\xc3"))
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            cfg = load_config(root)
        assert cfg.target_name == "main"

    def test_multiple_typos_warn_separately(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"
binaryx = "typo"
formatx = "typo"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"unrecognized keys"):
            load_config(root)


# ---------------------------------------------------------------------------
# Fail-fast validation regressions


class TestFailFastValidation:
    def test_empty_source_directory_raises(self, tmp_path: Path) -> None:
        root = _make_project(
            tmp_path,
            """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"
reversed_dir = ""
""",
        )
        with pytest.raises(ValueError, match=r"reversed_dir must not be empty"):
            load_config(root)

    def test_empty_compiler_command_raises(self, tmp_path: Path) -> None:
        root = _make_project(
            tmp_path,
            """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[compiler]
command = ""
""",
        )
        with pytest.raises(ValueError, match=r"compiler.command must not be empty"):
            load_config(root)

    def test_target_compiler_typo_warns(self, tmp_path: Path) -> None:
        root = _make_project(
            tmp_path,
            """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[targets.main.compiler]
commmand = "clang"
""",
        )
        with pytest.warns(UserWarning, match=r"targets.main.compiler.*commmand"):
            load_config(root)


# ---------------------------------------------------------------------------
# Regression tests


class TestParseIntList:
    def test_valid(self) -> None:
        from rebrew.config import _parse_int_list

        assert _parse_int_list([1, "0x10", "20"], "x") == [1, 16, 20]

    def test_invalid_entries_skipped_with_warning(self) -> None:
        from rebrew.config import _parse_int_list

        with pytest.warns(UserWarning, match="Invalid integer"):
            assert _parse_int_list(["oops", 5], "x") == [5]

    def test_non_list_ignored(self) -> None:
        from rebrew.config import _parse_int_list

        with pytest.warns(UserWarning):
            assert _parse_int_list(42, "x") == []
        assert _parse_int_list(None, "x") == []


class TestParseHexDict:
    def test_valid(self) -> None:
        from rebrew.config import _parse_hex_dict

        assert _parse_hex_dict({"0x1000": "a"}) == {0x1000: "a"}
        assert _parse_hex_dict({"4096": "b"}) == {4096: "b"}

    def test_invalid_key_skipped(self) -> None:
        from rebrew.config import _parse_hex_dict

        with pytest.warns(UserWarning, match="Invalid hex key"):
            assert _parse_hex_dict({"zzz": "x", "0x2000": "y"}) == {0x2000: "y"}

    def test_non_dict_ignored(self) -> None:
        from rebrew.config import _parse_hex_dict

        with pytest.warns(UserWarning):
            assert _parse_hex_dict("nope") == {}
        assert _parse_hex_dict(None) == {}


class TestParseStrList:
    def test_valid(self) -> None:
        from rebrew.config import _parse_str_list

        assert _parse_str_list(["a", "b"], "x") == ["a", "b"]

    def test_non_string_skipped(self) -> None:
        from rebrew.config import _parse_str_list

        with pytest.warns(UserWarning):
            assert _parse_str_list(["a", 3], "x") == ["a"]

    def test_none_and_non_list(self) -> None:
        from rebrew.config import _parse_str_list

        assert _parse_str_list(None, "x") == []
        with pytest.warns(UserWarning):
            assert _parse_str_list("str", "x") == []


class TestSafeInt:
    def test_valid(self) -> None:
        from rebrew.config import _safe_int

        assert _safe_int("42", 0, "x") == 42

    def test_invalid_uses_default(self) -> None:
        from rebrew.config import _safe_int

        with pytest.warns(UserWarning, match="Expected integer"):
            assert _safe_int("abc", 7, "x") == 7


class TestPositiveInt:
    def test_valid(self) -> None:
        from rebrew.config import _positive_int

        assert _positive_int(4, 1, "x") == 4

    def test_zero_uses_default(self) -> None:
        from rebrew.config import _positive_int

        with pytest.warns(UserWarning, match="positive"):
            assert _positive_int(0, 1, "x") == 1


class TestParseOptionalInt:
    def test_none_int_hex_string(self) -> None:
        from rebrew.config import _parse_optional_int

        assert _parse_optional_int(None, "x") is None
        assert _parse_optional_int(5, "x") == 5
        assert _parse_optional_int("0x10", "x") == 16

    def test_invalid_returns_none(self) -> None:
        from rebrew.config import _parse_optional_int

        with pytest.warns(UserWarning):
            assert _parse_optional_int("zzz", "x") is None
        with pytest.warns(UserWarning):
            assert _parse_optional_int(3.5, "x") is None


class TestParseStrDict:
    def test_valid(self) -> None:
        from rebrew.config import _parse_str_dict

        assert _parse_str_dict({"a": "b"}, "x") == {"a": "b"}

    def test_none_and_non_mapping(self) -> None:
        from rebrew.config import _parse_str_dict

        assert _parse_str_dict(None, "x") == {}
        with pytest.warns(UserWarning):
            assert _parse_str_dict("str", "x") == {}

    def test_non_string_pair_skipped(self) -> None:
        from rebrew.config import _parse_str_dict

        with pytest.warns(UserWarning):
            assert _parse_str_dict({"a": 1}, "x") == {}


class TestPosixStyleProfiles:
    """config.posix_style is the single source of truth for flag routing —
    watcom (wcc386, -I/-fo=/-zq) must be POSIX-style, not MSVC."""

    def test_posix_profiles(self) -> None:
        for prof in ("gcc", "gcc-pe", "clang", "watcom", "watcom16"):
            cfg = ProjectConfig(root=Path("."), compiler_profile=prof)
            assert cfg.posix_style is True, prof

    def test_msvc_profiles_not_posix(self) -> None:
        for prof in ("msvc6", "msvc1.52", "msvc7"):
            cfg = ProjectConfig(root=Path("."), compiler_profile=prof)
            assert cfg.posix_style is False, prof

    def test_watcom_default_profile(self) -> None:
        cfg = ProjectConfig(root=Path("."), compiler_profile="watcom")
        assert cfg.posix_style is True  # regression: was False -> /nologo /c glue -> E1139


class TestInstallToolsFallback:
    """config resolves missing project-relative tools/ paths against the
    rebrew install's vendored tree (fresh projects without a tools/ symlink
    compile out of the box)."""

    TOML = """\
[project]
default_target = "main"

[targets.main]
binary = "original/main.exe"

[compiler]
profile = "msvc6"
command = "wine toolchain/msvc/6.0-win32/VC98/Bin/CL.EXE"
"""

    def test_missing_includes_falls_back(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew import utils as rebrew_utils

        fake = tmp_path / "toolchain" / "msvc" / "6.0-win32" / "source" / "VC98" / "Include"
        fake.mkdir(parents=True)
        (fake / "stdio.h").write_text("")
        monkeypatch.setattr(rebrew_utils, "_REPO_ROOT", tmp_path)
        root = _make_project(tmp_path, self.TOML)
        cfg = load_config(root)
        assert cfg.compiler_includes == fake

    def test_missing_includes_falls_back_to_vendored_mirror(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """A machine with only the compile-only mirrors (no msvc-6.0-win32 master)
        must resolve includes against toolchain/msvc/6.0-sp6-win32 (SP6) instead of a broken
        toolchain/msvc/6.0-win32 path."""
        from rebrew import utils as rebrew_utils

        mirror = tmp_path / "toolchain" / "msvc" / "6.0-sp6-win32" / "source"
        (mirror / "Bin").mkdir(parents=True)
        (mirror / "Bin" / "CL.EXE").write_bytes(b"MZ")
        (mirror / "Include").mkdir()
        (mirror / "Include" / "stdio.h").write_text("")
        monkeypatch.setattr(rebrew_utils, "_REPO_ROOT", tmp_path)
        root = _make_project(tmp_path, self.TOML)
        cfg = load_config(root)
        assert (
            cfg.compiler_includes == tmp_path / "toolchain" / "msvc" / "6.0-sp6-win32" / "source" / "Include"
        )

    def test_existing_project_path_wins(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew import utils as rebrew_utils

        # Project-local toolchain/ present -> used, install copy ignored.
        (tmp_path / "toolchain" / "msvc" / "6.0-win32" / "source" / "VC98" / "Include").mkdir(parents=True)
        (tmp_path / "toolchain" / "msvc" / "6.0-win32" / "source" / "VC98" / "Include" / "stdio.h").write_text(
            ""
        )
        monkeypatch.setattr(rebrew_utils, "_REPO_ROOT", tmp_path)
        root = _make_project(tmp_path, self.TOML)
        cfg = load_config(root)
        assert (
            cfg.compiler_includes
            == tmp_path / "toolchain" / "msvc" / "6.0-win32" / "source" / "VC98" / "Include"
        )
