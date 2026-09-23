"""Tests for the config loader and multi-target support."""

from pathlib import Path

import pytest

# Import from the rebrew package
from rebrew.config import (
    _ARCH_PRESETS,
    ConfigError,
    ConfigKeyError,
    ConfigNotFoundError,
    ProjectConfig,
    _detect_binary_layout,
    _resolve,
    find_root,
    inventory_path_for,
    load_config,
)
from rebrew.errors import RebrewError

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

    def test_windows_separators_normalize(self, tmp_path: Path) -> None:
        """Config paths copied from Windows must resolve as POSIX components."""
        result = _resolve(tmp_path, r"foo\bar.dll")
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
bin_dir = "bin/server_dll"

[targets.client_exe]
binary = "original/Client/client.exe"
format = "pe"
arch = "x86_64"
reversed_dir = "src/client_exe"

[compiler]
profile = "gcc-14.2.0"
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

    def test_metadata_dir_prefers_parent(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, self.MULTI_TOML)
        cfg = load_config(root)
        assert cfg.metadata_dir == (root / "src").resolve()

    def test_metadata_dir_falls_back_to_source_root(self, tmp_path: Path) -> None:
        """Whole-tree projects may keep TOMLs inside reversed_dir itself."""
        toml = """\
[project]
default_target = "game"

[targets.game]
binary = "game.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src"

[compiler]
profile = "gcc-14.2.0"
"""
        root = _make_project(tmp_path, toml)
        (root / "src").mkdir()
        (root / "src" / "rebrew-functions.toml").write_text("", encoding="utf-8")
        cfg = load_config(root)
        assert cfg.metadata_dir == (root / "src").resolve()

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
        assert cfg.compiler_profile == "gcc-14.2.0"

    def test_arch_derived_values(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, self.MULTI_TOML)
        cfg = load_config(root, target="client_exe")
        assert cfg.pointer_size == 8

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
    def test_errors_share_rebrew_base_and_keep_builtin_bases(self, tmp_path: Path) -> None:
        """One ``except RebrewError`` catches every load failure; old bases still match."""
        with pytest.raises(ConfigNotFoundError) as missing:
            load_config(tmp_path)
        assert isinstance(missing.value, FileNotFoundError)
        assert isinstance(missing.value, RebrewError)

        root = _make_project(tmp_path, "[project]\n[targets.main]\nbinary = 'a.exe'\n")
        with pytest.raises(ConfigKeyError) as no_default:
            load_config(root)
        assert isinstance(no_default.value, KeyError)
        assert isinstance(no_default.value, RebrewError)
        assert str(no_default.value).startswith("rebrew-project.toml [project]")

        _make_project(tmp_path, "[[[\n")
        with pytest.raises(ConfigError, match="rebrew-project.toml") as bad_toml:
            load_config(root)
        assert isinstance(bad_toml.value, ValueError)

    def test_missing_toml_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path)

    def test_empty_targets_raises(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, "[compiler]\nprofile = 'msvc-6.0'\n")
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
        assert not hasattr(cfg, "function_list")
        assert cfg.bin_dir == root / "bin" / "main"

    def test_utf8_bom_prefixed_toml_loads(self, tmp_path: Path) -> None:
        """Notepad-style UTF-8 BOM must not make load_config raise.

        Concrete input: ``EF BB BF`` before ``[project]``.  Plain ``utf-8`` /
        ``tomllib.load`` on bytes leaves U+FEFF as the first character and
        both tomllib and tomlkit reject the file.
        """
        body = '[project]\ndefault_target = "main"\n\n[targets.main]\nbinary = "test.exe"\n'
        root = tmp_path
        (root / "rebrew-project.toml").write_bytes(b"\xef\xbb\xbf" + body.encode("utf-8"))
        cfg = load_config(root)
        assert cfg.target_name == "main"

    def test_link_file_align_warns_informational(self, tmp_path: Path) -> None:
        """link.file_align is parsed but no patch path applies it (FileAlignment
        needs a relink); the loader must warn instead of accepting a silent
        no-op."""
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[link]
file_align = 512
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match="file_align is informational"):
            cfg = load_config(root)
        assert cfg.link.file_align == 512

    def test_link_tsaware_non_bool_warns(self, tmp_path: Path) -> None:
        """Stringy link.tsaware must not be silently ignored (bool("false") is True)."""
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[link]
tsaware = "false"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match="link.tsaware"):
            cfg = load_config(root)
        assert cfg.link.tsaware is None

    def test_unknown_arch_raises(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"
arch = "riscv32"
"""
        root = _make_project(tmp_path, toml)
        with pytest.raises(ValueError, match=r"unknown arch 'riscv32'"):
            load_config(root)

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
    def test_default_values(self) -> None:
        cfg = ProjectConfig(root=Path("."))
        assert cfg.binary_format == "pe"
        assert cfg.arch == "x86_32"
        assert cfg.pointer_size == 4
        assert cfg.padding_bytes == [0xCC, 0x90]
        assert cfg.image_base == 0
        assert cfg.text_va == 0


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
        """The documented `[llm]` table must reach cfg.llm_endpoint/api_key/model."""
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[llm]
endpoint = "http://localhost:9000/v1"
api_key = "secret-key"
model = "local-qwen-7b"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"\[llm\]\.api_key is set in rebrew-project\.toml"):
            cfg = load_config(root)
        assert cfg.llm_endpoint == "http://localhost:9000/v1"
        assert cfg.llm_api_key == "secret-key"
        assert cfg.llm_model == "local-qwen-7b"

    def test_llm_unknown_key_warns(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[llm]
endpoint = "http://localhost:9000/v1"
temperature = 0.2
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"\[llm\].*unrecognized keys.*temperature"):
            load_config(root)

    def test_lint_unknown_key_warns(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"
[project.lint]
indent_size = 4

[targets.main]
binary = "test.exe"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"\[project\.lint\].*unrecognized keys.*indent_size"):
            load_config(root)

    def test_lint_typo_enum_falls_back(self, tmp_path: Path) -> None:
        """A typo'd naming_convention must not silently disable the style rule."""
        toml = """\
[project]
default_target = "main"
[project.lint]
naming_convention = "snake-case"
brace_style = "same-line"
indent_style = "space"

[targets.main]
binary = "test.exe"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"project\.lint\.naming_convention"):
            cfg = load_config(root)
        assert cfg.lint_naming_convention == "none"
        assert cfg.lint_brace_style == "none"
        assert cfg.lint_indent_style == "none"

    def test_lint_valid_enums(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"
[project.lint]
naming_convention = "snake_case"
brace_style = "new_line"
indent_style = "tabs"
max_line_length = 120

[targets.main]
binary = "test.exe"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.lint_naming_convention == "snake_case"
        assert cfg.lint_brace_style == "new_line"
        assert cfg.lint_indent_style == "tabs"
        assert cfg.lint_max_line_length == 120

    def test_llm_invalid_endpoint_raises(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[llm]
endpoint = "not-a-url"
"""
        root = _make_project(tmp_path, toml)
        with pytest.raises(ValueError, match=r"llm\.endpoint must be an http\(s\) URL"):
            load_config(root)

    def test_recompile_url_invalid_raises(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[compiler]
recompile_url = "ftp://example.com"
"""
        root = _make_project(tmp_path, toml)
        with pytest.raises(ValueError, match=r"compiler\.recompile_url must be an http\(s\) URL"):
            load_config(root)

    @pytest.mark.parametrize("section, key", [("compiler", "recompile_url"), ("llm", "endpoint")])
    @pytest.mark.parametrize(
        "url",
        [
            "http://:8000",
            "http://localhost:0",
            "http://localhost:99999",
            "http://localhost:bad",
            "http://[::1",
            "http://bad host",
            "http://local\\thost",
        ],
    )
    def test_invalid_http_authority_raises(
        self, tmp_path: Path, section: str, key: str, url: str
    ) -> None:
        root = _make_project(
            tmp_path,
            '[project]\ndefault_target = "main"\n[targets.main]\nbinary = "test.exe"\n'
            f'[{section}]\n{key} = "{url}"\n',
        )
        with pytest.raises(ValueError, match=rf"{section}\.{key} must be an http\(s\) URL"):
            load_config(root)

    @pytest.mark.parametrize(
        "url", ["http://localhost", "https://127.0.0.1:65535/v1", "http://[::1]:8000/v1", ""]
    )
    def test_valid_http_urls_preserved(self, tmp_path: Path, url: str) -> None:
        root = _make_project(
            tmp_path,
            '[project]\ndefault_target = "main"\n[targets.main]\nbinary = "test.exe"\n'
            f'[compiler]\nrecompile_url = "  {url}  "\n[llm]\nendpoint = "  {url}  "\n',
        )
        cfg = load_config(root)
        assert cfg.recompile_url == url
        assert cfg.llm_endpoint == url

    def test_llm_api_key_without_endpoint_warns(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[llm]
api_key = "secret-key"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"api_key is set but .*endpoint is empty"):
            cfg = load_config(root)
        assert cfg.llm_api_key == "secret-key"
        assert cfg.llm_endpoint == ""

    def test_defines_and_shared_dir_are_known_keys(self, tmp_path: Path) -> None:
        """Documented multi-version keys must not warn as unrecognized —
        same class of bug as the missing `layout` key (rewriters drop
        "unknown" tables)."""
        import warnings

        toml = """\
[project]
default_target = "main"
shared_dir = "src/shared"

[targets.main]
binary = "test.exe"
defines = ["V1"]
"""
        root = _make_project(tmp_path, toml)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            cfg = load_config(root)
        messages = [str(w.message) for w in caught]
        assert not [m for m in messages if "unrecognized" in m and "defines" in m], messages
        assert not [m for m in messages if "unrecognized" in m and "shared_dir" in m], messages
        assert cfg.defines == ["V1"]
        assert cfg.shared_dir == root / "src" / "shared"

    def test_legacy_target_cflags_presets_honoured_with_warning(self, tmp_path: Path) -> None:
        """Misplaced [targets.X.cflags_presets] used to be a silent no-op."""
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[targets.main.cflags_presets]
GAME = "/O1"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"cflags_presets is misplaced"):
            cfg = load_config(root)
        assert cfg.cflags_presets.get("GAME") == "/O1"

    @pytest.mark.parametrize("section", ["compiler", "targets.main.compiler", "targets.main"])
    @pytest.mark.parametrize("value", ['"/O2"', '""', "false", "0", "[]", '["/O2"]'])
    def test_cflags_presets_requires_table(self, tmp_path: Path, section: str, value: str) -> None:
        toml = f"""\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[{section}]
cflags_presets = {value}
"""
        if section == "targets.main":
            toml = toml.replace("\n[targets.main]\ncflags_presets", "\ncflags_presets")
        root = _make_project(tmp_path, toml)
        with pytest.raises(ValueError, match=rf"\[{section}\.cflags_presets\].*TOML table"):
            load_config(root)

    @pytest.mark.parametrize("section", ["compiler", "targets.main.compiler", "targets.main"])
    @pytest.mark.parametrize("value", ["false", "42", "[]", "{}"])
    def test_cflags_preset_requires_string(self, tmp_path: Path, section: str, value: str) -> None:
        toml = f"""\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[{section}.cflags_presets]
GAME = {value}
"""
        root = _make_project(tmp_path, toml)
        with pytest.raises(ValueError, match=rf"{section}\.cflags_presets\.GAME must be a string"):
            load_config(root)

    def test_cflags_presets_merge_preserves_empty_override(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[compiler.cflags_presets]
game = "/O2"
ZLIB = "/O1"

[targets.main.compiler.cflags_presets]
GAME = ""
"""
        cfg = load_config(_make_project(tmp_path, toml))
        assert cfg.cflags_presets == {"GAME": "", "ZLIB": "/O1"}

    def test_recompile_emit_assembly_rejects_stringy_bool(self, tmp_path: Path) -> None:
        """``bool("false")`` is True — a string must not enable the training tap."""
        toml = """\
[project]
default_target = "main"

[compiler]
recompile_emit_assembly = "false"

[targets.main]
binary = "test.exe"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(
            UserWarning, match=r"Expected boolean for compiler\.recompile_emit_assembly"
        ):
            cfg = load_config(root)
        assert cfg.recompile_emit_assembly is False

    def test_dead_config_keys_warn(self, tmp_path: Path) -> None:
        """Reserved/no-op keys ([compiler.profiles]) must warn at load — a user
        configuring them gets zero effect, so the no-op must be visible, not
        silent."""
        toml = """\
[project]
default_target = "main"

[compiler.profiles.clang]
command = "clang"

[targets.main]
binary = "test.exe"
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match=r"unrecognized keys.*profiles"):
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

    def test_layout_key_is_recognised(self, tmp_path: Path) -> None:
        """`rebrew layout capture` writes it, so the loader must know it.

        Regression: `layout` was missing from the known-target keys, so a
        project carrying the position-alignment package warned "unrecognized
        keys: {'layout'}" on EVERY rebrew invocation -- and an unrecognised key
        is one a config rewriter drops.  guild-rebrew lost its whole layout
        block that way during a `discover-functions` run.
        """
        import warnings

        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"
layout = {target = "test.exe", image_base = 268435456}
"""
        root = _make_project(tmp_path, toml)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            load_config(root)
        # Other warnings (e.g. the absent test binary) are fine; the point is
        # that `layout` itself must not be called unrecognised.
        messages = [str(w.message) for w in caught]
        assert not [m for m in messages if "unrecognized" in m and "layout" in m], messages

    def test_unknown_compiler_key_warns(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[compiler]
profile = "msvc-6.0"
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

    def test_non_string_arch_raises(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"
arch = 64
"""
        root = _make_project(tmp_path, toml)
        with pytest.raises(ValueError, match=r"unknown arch 64"):
            load_config(root)

    def test_unknown_format_raises(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"
format = "coff"
"""
        root = _make_project(tmp_path, toml)
        with pytest.raises(ValueError, match=r"unknown format 'coff'"):
            load_config(root)

    def test_unknown_cache_backend_raises(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[cache]
backend = "disk-cache"
"""
        root = _make_project(tmp_path, toml)
        with pytest.raises(ValueError, match=r"\[cache\]\.backend = 'disk-cache'"):
            load_config(root)

    def test_empty_cache_backend_raises(self, tmp_path: Path) -> None:
        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[cache]
backend = ""
"""
        root = _make_project(tmp_path, toml)
        with pytest.raises(ValueError, match=r"\[cache\]\.backend must not be empty"):
            load_config(root)

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

    def test_unknown_profile_falls_back_to_msvc_6_0(self, tmp_path: Path) -> None:
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
        assert cfg.compiler_profile == "msvc-6.0"

    def test_registered_toolchain_profile_accepted(self, tmp_path: Path) -> None:
        """A registered profile (delphi-1.0) must not be rejected and silently
        fall back to msvc-6.0."""

        toml = """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"
format = "ne"
arch = "x86_16"

[compiler]
profile = "delphi-1.0"
"""
        root = _make_project(tmp_path, toml)
        # A real (minimal) NE binary so layout detection succeeds silently
        # (a missing/unparseable binary emits a load-time UserWarning).
        ne = bytearray(0x300)
        ne[0:2] = b"MZ"
        ne[0x3C:0x40] = (0x100).to_bytes(4, "little")
        ne[0x100:0x102] = b"NE"
        (root / "test.exe").write_bytes(bytes(ne))
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("error", UserWarning)  # no unknown-profile warn
            cfg = load_config(root)
        assert cfg.compiler_profile == "delphi-1.0"
        assert cfg.binary_format == "ne"
        assert cfg.arch == "x86_16"

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
profile = "msvc-4.0"
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        assert cfg.compiler_profile == "msvc-4.0"

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

    @pytest.mark.parametrize("value", ["inf", "-inf", "nan"])
    def test_non_finite_jobs_and_timeout_default(self, tmp_path: Path, value: str) -> None:
        toml = f"""\
[project]
default_target = "main"
jobs = {value}

[targets.main]
binary = "test.exe"

[compiler]
timeout = {value}
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning) as warnings:
            cfg = load_config(root)
        assert cfg.default_jobs == 4
        assert cfg.compile_timeout == 60
        messages = [str(warning.message) for warning in warnings]
        assert any("Expected integer for project.jobs" in message for message in messages)
        assert any("Expected integer for compiler.timeout" in message for message in messages)

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
profile = "msvc-6.0"
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
        with pytest.warns(UserWarning, match=r"unrecognized keys") as caught:
            load_config(root)
        messages = " ".join(str(w.message) for w in caught)
        assert "binaryx" in messages
        assert "formatx" in messages


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

    def test_registry_error_propagates(self, tmp_path: Path, monkeypatch) -> None:
        """A toolchain RegistryError (plugin conflict) must propagate from
        config load, not be swallowed by the best-effort import guard."""
        import rebrew.config as config_mod
        from rebrew.registry import RegistryError

        root = _make_project(
            tmp_path,
            """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[compiler]
profile = "msvc-6.0"
command = ""
""",
        )
        real_import = __import__

        def _boom(name, *args, **kwargs):
            if name == "rebrew.toolchain":
                raise RegistryError("duplicate toolchain registration 'msvc-6.0'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr("builtins.__import__", _boom)
        with pytest.raises(RegistryError, match="duplicate toolchain"):
            config_mod.load_config(root)

    def test_target_compiler_typo_warns(self, tmp_path: Path) -> None:
        root = _make_project(
            tmp_path,
            """\
[project]
default_target = "main"

[targets.main]
binary = "test.exe"

[targets.main.compiler]
commmand = "clang-18.1.8"
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


class TestParseVaRanges:
    """``targets.<name>.external_ranges`` bands validate at load: a malformed
    band warns and is dropped before any tool reads ``cfg.external_ranges``
    (config checklist: invalid values fail at load, not later)."""

    def test_hex_and_decimal_bands_parse(self) -> None:
        from rebrew.config import _parse_va_ranges

        assert _parse_va_ranges(
            ["0x5e0000-0x64ffff", "1000-2000"], "targets.g.external_ranges"
        ) == [(0x5E0000, 0x64FFFF), (1000, 2000)]

    def test_missing_dash_warns_and_drops(self) -> None:
        from rebrew.config import _parse_va_ranges

        with pytest.warns(UserWarning, match="expected '0xLO-0xHI'"):
            assert _parse_va_ranges(["0x5e0000"], "targets.g.external_ranges") == []

    def test_non_numeric_warns_and_drops(self) -> None:
        from rebrew.config import _parse_va_ranges

        with pytest.warns(UserWarning, match="Invalid range"):
            assert _parse_va_ranges(["nope-0x20"], "targets.g.external_ranges") == []

    def test_end_before_start_warns_and_drops(self) -> None:
        from rebrew.config import _parse_va_ranges

        with pytest.warns(UserWarning, match="end before start"):
            assert _parse_va_ranges(["0x200-0x100"], "targets.g.external_ranges") == []

    def test_non_list_warns_and_returns_empty(self) -> None:
        from rebrew.config import _parse_va_ranges

        with pytest.warns(UserWarning, match="Expected list"):
            assert _parse_va_ranges("0x1-0x2", "targets.g.external_ranges") == []  # type: ignore[arg-type]
        assert _parse_va_ranges(None, "targets.g.external_ranges") == []

    def test_mixed_list_keeps_valid_bands(self) -> None:
        from rebrew.config import _parse_va_ranges

        with pytest.warns(UserWarning, match="Invalid range"):
            assert _parse_va_ranges(
                ["0x10-0x20", "garbage", "0x30-0x40"], "targets.g.external_ranges"
            ) == [(0x10, 0x20), (0x30, 0x40)]

    def test_load_config_binds_bands_and_warns_on_bad_ones(self, tmp_path: Path) -> None:
        """End-to-end: the band list lands on the config at load_config and a
        malformed entry is warned about there — never half-parsed later."""
        toml = """\
[project]
default_target = "game"

[targets.game]
binary = "game.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src"
external_ranges = ["0x5e0000-0x64ffff", "not-a-band"]
"""
        root = _make_project(tmp_path, toml)
        with pytest.warns(UserWarning, match="Invalid range"):
            cfg = load_config(root)
        assert cfg.external_ranges == [(0x5E0000, 0x64FFFF)]


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

    def test_non_integral_float_uses_default(self) -> None:
        from rebrew.config import _safe_int

        with pytest.warns(UserWarning, match="Expected integer"):
            assert _safe_int(3.9, 7, "x") == 7

    def test_integral_float_accepted(self) -> None:
        from rebrew.config import _safe_int

        assert _safe_int(4.0, 0, "x") == 4

    def test_bool_uses_default(self) -> None:
        from rebrew.config import _safe_int

        with pytest.warns(UserWarning, match="Expected integer"):
            assert _safe_int(True, 7, "x") == 7


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
        for prof in (
            "gcc-14.2.0",
            "mingw-16.2.0",
            "clang-18.1.8",
            "watcom-2.0-win32",
            "watcom-2.0-win16",
        ):
            cfg = ProjectConfig(root=Path("."), compiler_profile=prof)
            assert cfg.posix_style is True, prof

    def test_msvc_profiles_not_posix(self) -> None:
        for prof in ("msvc-6.0", "msvc-1.52", "msvc-7.0"):
            cfg = ProjectConfig(root=Path("."), compiler_profile=prof)
            assert cfg.posix_style is False, prof

    def test_watcom_default_profile(self) -> None:
        cfg = ProjectConfig(root=Path("."), compiler_profile="watcom-2.0-win32")
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
profile = "msvc-6.0"
command = "wine toolchain/msvc/6.0-win32/VC98/Bin/CL.EXE"
"""

    @pytest.mark.parametrize("key", ["includes", "libs"])
    @pytest.mark.parametrize("value", ["false", "0", "0.0", "[]", "{}"])
    def test_invalid_compiler_paths_raise(self, tmp_path: Path, key: str, value: str) -> None:
        root = _make_project(tmp_path, self.TOML + f"{key} = {value}\n")
        with pytest.raises(ValueError, match=rf"compiler\.{key} must be a path string"):
            load_config(root)

    @pytest.mark.parametrize("includes", ['""', '"   "'])
    @pytest.mark.parametrize("libs", [None, '"custom/lib"', '""'])
    @pytest.mark.parametrize("detected", [False, True])
    def test_empty_includes_with_independent_libs(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        includes: str,
        libs: str | None,
        detected: bool,
    ) -> None:
        from rebrew import utils as rebrew_utils

        layout = ("compiler", "detected/include", "detected/lib") if detected else None
        monkeypatch.setattr(rebrew_utils, "resolve_msvc_toolchain", lambda *_: layout)
        monkeypatch.setattr(rebrew_utils, "find_install_tool", lambda _: None)
        toml = self.TOML + f"includes = {includes}\n"
        if libs is not None:
            toml += f"libs = {libs}\n"
        cfg = load_config(_make_project(tmp_path, toml))

        assert cfg.compiler_includes == Path("")
        if libs == '""':
            assert cfg.compiler_libs == Path("")
        elif libs is not None:
            assert cfg.compiler_libs == tmp_path / "custom/lib"
        else:
            expected = "detected/lib" if detected else "toolchain/msvc/6.0-win32/source/VC98/Lib"
            assert cfg.compiler_libs == tmp_path / expected

    def test_missing_includes_falls_back(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew import utils as rebrew_utils

        fake = tmp_path / "toolchain" / "msvc" / "6.0-win32" / "source" / "VC98" / "Include"
        fake.mkdir(parents=True)
        (fake / "stdio.h").write_text("")
        monkeypatch.setattr(rebrew_utils, "SOURCE_CHECKOUT", tmp_path)
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
        monkeypatch.setattr(rebrew_utils, "SOURCE_CHECKOUT", tmp_path)
        root = _make_project(tmp_path, self.TOML)
        cfg = load_config(root)
        assert (
            cfg.compiler_includes
            == tmp_path / "toolchain" / "msvc" / "6.0-sp6-win32" / "source" / "Include"
        )

    def test_existing_project_path_wins(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew import utils as rebrew_utils

        # Project-local toolchain/ present -> used, install copy ignored.
        (tmp_path / "toolchain" / "msvc" / "6.0-win32" / "source" / "VC98" / "Include").mkdir(
            parents=True
        )
        (
            tmp_path
            / "toolchain"
            / "msvc"
            / "6.0-win32"
            / "source"
            / "VC98"
            / "Include"
            / "stdio.h"
        ).write_text("")
        monkeypatch.setattr(rebrew_utils, "SOURCE_CHECKOUT", tmp_path)
        root = _make_project(tmp_path, self.TOML)
        cfg = load_config(root)
        assert (
            cfg.compiler_includes
            == tmp_path / "toolchain" / "msvc" / "6.0-win32" / "source" / "VC98" / "Include"
        )


class TestConfigPublicExports:
    """Documented ``from rebrew.config import load_config`` stays star-import safe."""

    def test_all_lists_documented_entry_points(self) -> None:
        import rebrew.config as config

        required = {"ProjectConfig", "find_root", "load_config", "validate_http_url"}
        assert required <= set(config.__all__)
        for name in config.__all__:
            assert getattr(config, name, None) is not None, name

    def test_star_import_excludes_stdlib(self) -> None:
        ns: dict[str, object] = {}
        exec("from rebrew.config import *", ns)  # noqa: S102
        exported = {k for k in ns if not k.startswith("_")}
        assert "load_config" in exported
        assert not {"os", "re", "sys", "Path", "Any"} & exported


class TestInventoryFile:
    """Per-target ``inventory_file`` lets targets share one source tree."""

    INV_TOML = """\
[project]
default_target = "V1"

[targets.V1]
binary = "v1.exe"
reversed_dir = "src/shared"
inventory_file = "db/inventory-V1.json"

[targets.V2]
binary = "v2.exe"
reversed_dir = "src/shared"

[compiler]
profile = "gcc-14.2.0"
command = "gcc"
includes = "/usr/include"
libs = "/usr/lib"
"""

    def test_default_is_reversed_dir_join(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, self.INV_TOML)
        cfg = load_config(root, target="V2")
        assert cfg.inventory_file == ""
        assert (
            inventory_path_for(cfg.reversed_dir, cfg)
            == root / "src" / "shared" / "function_structure.json"
        )

    def test_override_resolves_against_root(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, self.INV_TOML)
        cfg = load_config(root, target="V1")
        assert inventory_path_for(cfg.reversed_dir, cfg) == root / "db" / "inventory-V1.json"

    def test_helper_prefers_override_for_own_dir(self, tmp_path: Path) -> None:
        from rebrew.config import inventory_path_for

        root = _make_project(tmp_path, self.INV_TOML)
        cfg = load_config(root, target="V1")
        assert inventory_path_for(root / "src" / "shared", cfg) == root / "db" / "inventory-V1.json"

    def test_helper_falls_back_for_other_dirs(self, tmp_path: Path) -> None:
        from rebrew.config import inventory_path_for

        root = _make_project(tmp_path, self.INV_TOML)
        cfg = load_config(root, target="V1")
        other = root / "elsewhere"
        assert inventory_path_for(other, cfg) == other / "function_structure.json"
        assert inventory_path_for(other) == other / "function_structure.json"
