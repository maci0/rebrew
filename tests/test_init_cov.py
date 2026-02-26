"""Tests for the rebrew init command."""

import pytest
from click.exceptions import Exit

from rebrew.init import (
    COMPILER_DEFAULTS,
    DEFAULT_AGENTS_MD,
    DEFAULT_REBREW_TOML,
    GCC_CONSTRAINTS,
    MSVC7_CONSTRAINTS,
    MSVC_CONSTRAINTS,
    init,
)

# ---------------------------------------------------------------------------
# COMPILER_DEFAULTS
# ---------------------------------------------------------------------------


class TestCompilerDefaults:
    """Tests for the COMPILER_DEFAULTS constant."""

    def test_has_four_profiles(self) -> None:
        assert len(COMPILER_DEFAULTS) == 4

    def test_known_profiles(self) -> None:
        assert set(COMPILER_DEFAULTS.keys()) == {"msvc6", "msvc7", "clang", "gcc"}

    @pytest.mark.parametrize("profile", ["msvc6", "msvc7", "clang", "gcc"])
    def test_required_keys(self, profile: str) -> None:
        """Every profile has command, includes, libs, cflags."""
        data = COMPILER_DEFAULTS[profile]
        for key in ("command", "includes", "libs", "cflags"):
            assert key in data, f"{profile} missing '{key}'"

    @pytest.mark.parametrize("profile", ["msvc6", "msvc7", "clang", "gcc"])
    def test_format_and_arch(self, profile: str) -> None:
        """Every profile has format and arch."""
        data = COMPILER_DEFAULTS[profile]
        assert "format" in data
        assert "arch" in data

    def test_msvc6_uses_wine(self) -> None:
        assert "wine" in COMPILER_DEFAULTS["msvc6"]["command"].lower()

    def test_msvc7_uses_wine(self) -> None:
        assert "wine" in COMPILER_DEFAULTS["msvc7"]["command"].lower()

    def test_gcc_no_wine(self) -> None:
        assert "wine" not in COMPILER_DEFAULTS["gcc"]["command"].lower()

    def test_clang_no_wine(self) -> None:
        assert "wine" not in COMPILER_DEFAULTS["clang"]["command"].lower()

    def test_pe_profiles(self) -> None:
        """MSVC profiles produce PE format."""
        assert COMPILER_DEFAULTS["msvc6"]["format"] == "pe"
        assert COMPILER_DEFAULTS["msvc7"]["format"] == "pe"

    def test_elf_profiles(self) -> None:
        """GCC and Clang produce ELF format."""
        assert COMPILER_DEFAULTS["gcc"]["format"] == "elf"
        assert COMPILER_DEFAULTS["clang"]["format"] == "elf"

    def test_lang_field(self) -> None:
        """MSVC6 is C89, others are C99."""
        assert COMPILER_DEFAULTS["msvc6"]["lang"] == "C89"
        assert COMPILER_DEFAULTS["msvc7"]["lang"] == "C99"
        assert COMPILER_DEFAULTS["gcc"]["lang"] == "C99"
        assert COMPILER_DEFAULTS["clang"]["lang"] == "C99"


# ---------------------------------------------------------------------------
# Template rendering
# ---------------------------------------------------------------------------


class TestTemplateRendering:
    """Tests for DEFAULT_REBREW_TOML template string."""

    def test_toml_template_renders(self) -> None:
        """Template renders without KeyError."""
        result = DEFAULT_REBREW_TOML.format(
            project_name="myproject",
            target_name="game.exe",
            binary_name="game.exe",
            compiler_profile="msvc6",
            compiler_command="wine CL.EXE",
            compiler_includes="tools/include",
            compiler_libs="tools/lib",
            cflags="/O2 /Gd",
        )
        assert "myproject" in result
        assert "game.exe" in result

    def test_toml_template_has_project_section(self) -> None:
        result = DEFAULT_REBREW_TOML.format(
            project_name="test",
            target_name="t",
            binary_name="t.exe",
            compiler_profile="msvc6",
            compiler_command="cl",
            compiler_includes="inc",
            compiler_libs="lib",
            cflags="/O2",
        )
        assert "[project]" in result
        assert "[compiler]" in result

    def test_agents_template_renders(self) -> None:
        """AGENTS.md template renders without KeyError."""
        result = DEFAULT_AGENTS_MD.format(
            project_name="myproject",
            target_name="game.exe",
            binary_name="game.exe",
            binary_format="pe",
            arch="x86_32",
            compiler_profile="msvc6",
            compiler_command="wine CL.EXE",
            compiler_constraints=MSVC_CONSTRAINTS,
            cflags="/O2 /Gd",
            lang="C89",
        )
        assert "myproject" in result
        assert "C89" in result


# ---------------------------------------------------------------------------
# Constraint strings
# ---------------------------------------------------------------------------


class TestConstraints:
    """Tests for compiler constraint strings."""

    def test_msvc_mentions_c89(self) -> None:
        assert "C89" in MSVC_CONSTRAINTS

    def test_msvc7_mentions_c99(self) -> None:
        assert "C99" in MSVC7_CONSTRAINTS

    def test_gcc_mentions_elf(self) -> None:
        assert "ELF" in GCC_CONSTRAINTS

    def test_msvc_mentions_wine(self) -> None:
        assert "Wine" in MSVC_CONSTRAINTS

    def test_msvc7_mentions_wine(self) -> None:
        assert "Wine" in MSVC7_CONSTRAINTS


# ---------------------------------------------------------------------------
# init() -- filesystem tests
# ---------------------------------------------------------------------------


class TestInit:
    """Tests for the init() function using tmp_path."""

    def test_creates_rebrew_toml(self, tmp_path, monkeypatch) -> None:
        """init() creates rebrew.toml in cwd."""
        monkeypatch.chdir(tmp_path)
        init(target_name="server", binary_name="server.dll", compiler_profile="msvc6")
        toml_path = tmp_path / "rebrew.toml"
        assert toml_path.exists()
        content = toml_path.read_text()
        assert "server" in content
        assert "server.dll" in content

    def test_creates_agents_md(self, tmp_path, monkeypatch) -> None:
        """init() creates AGENTS.md."""
        monkeypatch.chdir(tmp_path)
        init(target_name="main", binary_name="prog.exe", compiler_profile="msvc6")
        agents_path = tmp_path / "AGENTS.md"
        assert agents_path.exists()
        content = agents_path.read_text()
        assert "prog.exe" in content

    def test_creates_directories(self, tmp_path, monkeypatch) -> None:
        """init() creates original/, src/<target>/, bin/<target>/."""
        monkeypatch.chdir(tmp_path)
        init(target_name="game", binary_name="game.exe", compiler_profile="gcc")
        assert (tmp_path / "original").is_dir()
        assert (tmp_path / "src" / "game").is_dir()
        assert (tmp_path / "bin" / "game").is_dir()

    def test_creates_function_list(self, tmp_path, monkeypatch) -> None:
        """init() creates an empty functions.txt."""
        monkeypatch.chdir(tmp_path)
        init(target_name="t", binary_name="t.exe", compiler_profile="clang")
        func_list = tmp_path / "src" / "t" / "functions.txt"
        assert func_list.exists()

    def test_idempotency_guard(self, tmp_path, monkeypatch) -> None:
        """init() exits with code 1 if rebrew.toml already exists."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "rebrew.toml").write_text("existing", encoding="utf-8")
        with pytest.raises(Exit):
            init(target_name="t", binary_name="t.exe", compiler_profile="msvc6")

    def test_unknown_compiler_profile(self, tmp_path, monkeypatch) -> None:
        """init() exits with code 1 for unknown compiler profile."""
        monkeypatch.chdir(tmp_path)
        with pytest.raises(Exit):
            init(target_name="t", binary_name="t.exe", compiler_profile="borland")

    def test_msvc7_uses_msvc7_constraints(self, tmp_path, monkeypatch) -> None:
        """msvc7 profile generates AGENTS.md with C99 constraints."""
        monkeypatch.chdir(tmp_path)
        init(target_name="t", binary_name="t.exe", compiler_profile="msvc7")
        agents = (tmp_path / "AGENTS.md").read_text()
        assert "C99" in agents

    def test_gcc_uses_gcc_constraints(self, tmp_path, monkeypatch) -> None:
        """gcc profile generates AGENTS.md with ELF constraints."""
        monkeypatch.chdir(tmp_path)
        init(target_name="t", binary_name="t.exe", compiler_profile="gcc")
        agents = (tmp_path / "AGENTS.md").read_text()
        assert "ELF" in agents
