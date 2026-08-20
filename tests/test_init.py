"""Tests for the rebrew init command."""

from pathlib import Path
from types import SimpleNamespace

import pytest
import typer
from click.exceptions import Exit

from rebrew.init import (
    _AGENTS_MD_TEMPLATE,
    COMPILER_DEFAULTS,
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

    def test_has_expected_profiles(self) -> None:
        assert len(COMPILER_DEFAULTS) == 35  # 16 legacy + 19 MSVC 1.0-10.0 matrix profiles

    def test_known_profiles(self) -> None:
        assert set(COMPILER_DEFAULTS.keys()) == {
            "msvc400",
            "msvc420",
            "msvc410",
            "msvc200",
            "msvc5",
            "msvc500sp1",
            "msvc500sp2",
            "msvc500sp3",
            "msvc6",
            "msvc6.3",
            "msvc6.6",
            "msvc600sp3",
            "msvc600sp5",
            "msvc600sp6",
            "msvc7",
            "msvc700",
            "msvc700sp1",
            "msvc710",
            "msvc710sp1",
            "msvc800",
            "msvc800sp1",
            "msvc900",
            "msvc1000",
            "msvc1000sp1",
            "msvc1.52",
            "msvc15",
            "msvc10",
            "clang",
            "gcc",
            "gcc-pe",
            "watcom",
            "borlandc55",
            "watcom16",
            "tc20",
            "tc16",
        }

    @pytest.mark.parametrize(
        "profile",
        [
            "msvc400",
            "msvc420",
            "msvc5",
            "msvc6",
            "msvc6.3",
            "msvc6.6",
            "msvc7",
            "clang",
            "gcc",
            "gcc-pe",
        ],
    )
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
        """Template renders without KeyError and produces valid TOML."""
        import tomllib

        result = DEFAULT_REBREW_TOML.format(
            project_name="myproject",
            target_name="game.exe",
            binary_name="game.exe",
            marker="GAME",
            compiler_profile="msvc6",
            compiler_command="wine CL.EXE",
            compiler_includes="tools/include",
            compiler_libs="tools/lib",
            cflags="/O2 /Gd",
            base_cflags="/nologo /c /MT",
        )
        parsed = tomllib.loads(result)
        assert parsed["project"]["name"] == "myproject"
        assert "game.exe" in result

    def test_toml_template_has_project_section(self) -> None:
        result = DEFAULT_REBREW_TOML.format(
            project_name="test",
            target_name="t",
            binary_name="t.exe",
            marker="T",
            compiler_profile="msvc6",
            compiler_command="cl",
            compiler_includes="inc",
            compiler_libs="lib",
            cflags="/O2",
            base_cflags="",
        )
        assert "[project]" in result
        assert "[compiler]" in result

    def test_agents_template_renders(self) -> None:
        """AGENTS.md template renders without KeyError."""
        template = _AGENTS_MD_TEMPLATE.read_text(encoding="utf-8")
        result = template.format(
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


@pytest.fixture(autouse=True)
def mock_download_wibo(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent tests from hitting GitHub API rate limits."""
    monkeypatch.setattr("rebrew.wibo.download_wibo", lambda *args, **kwargs: "v1.2.3")


class TestInit:
    """Tests for the init() function using tmp_path."""

    def test_creates_rebrew_toml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """init() creates rebrew-project.toml in cwd."""
        monkeypatch.chdir(tmp_path)
        init(
            target_name="server",
            binary_name="server.dll",
            compiler_profile="msvc6",
            install_wibo=False,
            json_output=False,
            install_completions=False,
        )
        toml_path = tmp_path / "rebrew-project.toml"
        assert toml_path.exists()
        content = toml_path.read_text()
        assert "server" in content
        assert "server.dll" in content

    def test_msvc6_resolves_available_toolchain(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """msvc6 init must not write a broken toolchain/msvc/6.0-win32 path when the
        machine only has the vendored mirrors (or no layout at all)."""
        monkeypatch.chdir(tmp_path)
        init(
            target_name="server",
            binary_name="server.dll",
            compiler_profile="msvc6",
            install_wibo=False,
            json_output=False,
            install_completions=False,
        )
        content = (tmp_path / "rebrew-project.toml").read_text()

        from rebrew.utils import resolve_msvc_toolchain

        layout = resolve_msvc_toolchain(tmp_path, "msvc6")
        if layout is not None:
            # A layout exists (project tools/ or the rebrew install's own
            # vendored tree) — the generated command must point at it.
            assert layout[0] in content, f"expected {layout[0]!r} in generated config"
        else:
            # No layout anywhere (CI: tools/ is gitignored) — the documented
            # master default is kept, and the config-layer fallback reports
            # the missing toolchain via doctor.
            assert "toolchain/msvc/6.0-win32/VC98/Bin/CL.EXE" in content

    def test_msvc7_resolves_available_toolchain(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """msvc7 is docker-backed — init writes a docker-native config (empty
        host command; the image is the compiler), no stale wine path."""
        monkeypatch.chdir(tmp_path)
        init(
            target_name="server",
            binary_name="server.dll",
            compiler_profile="msvc7",
            install_wibo=False,
            json_output=False,
            install_completions=False,
        )
        content = (tmp_path / "rebrew-project.toml").read_text()
        assert 'profile = "msvc7"' in content
        assert 'command = ""' in content
        assert 'runner = ""' in content
        # no host wine invocation in the active [compiler] block
        assert not any(
            line.strip().startswith(("command", "runner")) and "wine" in line
            for line in content.splitlines()
        )

    def test_creates_agents_md(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """init() creates AGENTS.md."""
        monkeypatch.chdir(tmp_path)
        init(
            target_name="main",
            binary_name="prog.exe",
            compiler_profile="msvc6",
            install_wibo=False,
            json_output=False,
            install_completions=False,
        )
        agents_path = tmp_path / "AGENTS.md"
        assert agents_path.exists()
        content = agents_path.read_text()
        assert "prog.exe" in content

    def test_creates_directories(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """init() creates original/, src/<target>/, bin/<target>/."""
        monkeypatch.chdir(tmp_path)
        init(
            target_name="game",
            binary_name="game.exe",
            compiler_profile="gcc",
            install_wibo=False,
            json_output=False,
            install_completions=False,
        )
        assert (tmp_path / "original").is_dir()
        assert (tmp_path / "src" / "game").is_dir()
        assert (tmp_path / "bin" / "game").is_dir()

    def test_creates_function_list(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """init() creates an empty functions.txt."""
        monkeypatch.chdir(tmp_path)
        init(
            target_name="t",
            binary_name="t.exe",
            compiler_profile="clang",
            install_wibo=False,
            json_output=False,
            install_completions=False,
        )
        func_list = tmp_path / "src" / "t" / "functions.txt"
        assert func_list.exists()

    def test_binary_original_prefix_stripped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--binary original/bench.exe must not produce original/original/bench.exe."""
        monkeypatch.chdir(tmp_path)
        init(
            target_name="server",
            binary_name="original/bench.exe",
            compiler_profile="msvc6",
            install_wibo=False,
            json_output=False,
            install_completions=False,
        )
        content = (tmp_path / "rebrew-project.toml").read_text()
        assert 'binary = "original/bench.exe"' in content
        assert "original/original/" not in content

    def test_binary_original_prefix_backslash_stripped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        init(
            target_name="server",
            binary_name="original\\bench.exe",
            compiler_profile="msvc6",
            install_wibo=False,
            json_output=False,
            install_completions=False,
        )
        content = (tmp_path / "rebrew-project.toml").read_text()
        assert 'binary = "original/bench.exe"' in content

    def test_link_tools_from_creates_symlink(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--link-tools-from symlinks toolchain/msvc/6.0-win32 to the master directory."""
        master = tmp_path / "master"
        (master / "msvc" / "6.0-win32").mkdir(parents=True)
        monkeypatch.chdir(tmp_path)
        init(
            target_name="t",
            binary_name="t.exe",
            compiler_profile="msvc6",
            install_wibo=False,
            json_output=False,
            install_completions=False,
            toolchain_dir=master,
        )
        link = tmp_path / "toolchain" / "msvc" / "6.0-win32"
        assert link.is_symlink()
        assert link.resolve() == (master / "msvc" / "6.0-win32").resolve()

    def test_link_tools_from_mirror_only_master(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--link-tools-from must accept a master dir that only has the
        compile-only mirror (no msvc-6.0-win32 master) — link toolchain/msvc/6.0-sp6-win32."""
        master = tmp_path / "master"
        (master / "msvc" / "6.0-sp6-win32").mkdir(parents=True)
        monkeypatch.chdir(tmp_path)
        init(
            target_name="t",
            binary_name="t.exe",
            compiler_profile="msvc6",
            install_wibo=False,
            json_output=False,
            install_completions=False,
            toolchain_dir=master,
        )
        link = tmp_path / "toolchain" / "msvc" / "6.0-sp6-win32"
        assert link.is_symlink()
        assert link.resolve() == (master / "msvc" / "6.0-sp6-win32").resolve()
        # The generated command must reference the linked mirror.
        content = (tmp_path / "rebrew-project.toml").read_text()
        assert "wine toolchain/msvc/6.0-sp6-win32/Bin/CL.EXE" in content

    def test_link_tools_from_missing_toolchain_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A master dir without the profile's toolchain is a hard error."""
        master = tmp_path / "master"
        master.mkdir()
        monkeypatch.chdir(tmp_path)
        with pytest.raises(Exit):
            init(
                target_name="t",
                binary_name="t.exe",
                compiler_profile="msvc6",
                install_wibo=False,
                json_output=False,
                install_completions=False,
                toolchain_dir=master,
            )

    def test_link_tools_from_path_profiles_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PATH-based profiles (gcc-pe) have nothing to link — no error."""
        master = tmp_path / "master"
        master.mkdir()
        monkeypatch.chdir(tmp_path)
        init(
            target_name="t",
            binary_name="t.exe",
            compiler_profile="gcc-pe",
            install_wibo=False,
            json_output=False,
            install_completions=False,
            toolchain_dir=master,
        )
        assert not (tmp_path / "tools").exists()

    def test_idempotency_guard(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """init() exits with code 1 if rebrew-project.toml already exists."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "rebrew-project.toml").write_text("existing", encoding="utf-8")
        with pytest.raises(Exit):
            init(
                target_name="t",
                binary_name="t.exe",
                compiler_profile="msvc6",
                install_wibo=False,
                json_output=False,
                install_completions=False,
            )

    def test_unknown_compiler_profile(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """init() exits with code 1 for unknown compiler profile."""
        monkeypatch.chdir(tmp_path)
        with pytest.raises(Exit):
            init(
                target_name="t",
                binary_name="t.exe",
                compiler_profile="borland",
                install_wibo=False,
                json_output=False,
                install_completions=False,
            )

    def test_msvc7_uses_msvc7_constraints(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """msvc7 profile generates AGENTS.md with C99 constraints."""
        monkeypatch.chdir(tmp_path)
        init(
            target_name="t",
            binary_name="t.exe",
            compiler_profile="msvc7",
            install_wibo=False,
            json_output=False,
            install_completions=False,
        )
        agents = (tmp_path / "AGENTS.md").read_text()
        assert "C99" in agents

    def test_gcc_uses_gcc_constraints(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """gcc profile generates AGENTS.md with ELF constraints."""
        monkeypatch.chdir(tmp_path)
        init(
            target_name="t",
            binary_name="t.exe",
            compiler_profile="gcc",
            install_wibo=False,
            json_output=False,
            install_completions=False,
        )
        agents = (tmp_path / "AGENTS.md").read_text()
        assert "ELF" in agents


# ---------------------------------------------------------------------------
# init template checks
# ---------------------------------------------------------------------------
# init template checks
# ---------------------------------------------------------------------------


class TestFamilyMismatchWarning:
    """init warns when a high-confidence compiler-family detection
    contradicts the chosen profile (Zig/MinGW binary + msvc6)."""

    def _tc(self, family: str, confidence: str = "high", hint: str = "") -> SimpleNamespace:
        return SimpleNamespace(family=family, confidence=confidence, version_hint=hint)

    def test_mismatch_warns(self, capsys: pytest.CaptureFixture[str]) -> None:
        from rebrew.init import _warn_profile_family_mismatch

        _warn_profile_family_mismatch("msvc6", self._tc("zig", hint="Zig/LLVM 20.1"))
        out = capsys.readouterr()
        assert "looks like zig" in out.err
        assert "gcc-pe" in out.err  # suggests the counterpart profile

    def test_matching_family_silent(self, capsys: pytest.CaptureFixture[str]) -> None:
        from rebrew.init import _warn_profile_family_mismatch

        _warn_profile_family_mismatch("gcc-pe", self._tc("mingw"))
        _warn_profile_family_mismatch("msvc6", self._tc("msvc"))
        assert "looks like" not in capsys.readouterr().err

    def test_low_confidence_silent(self, capsys: pytest.CaptureFixture[str]) -> None:
        from rebrew.init import _warn_profile_family_mismatch

        _warn_profile_family_mismatch("msvc6", self._tc("zig", confidence="low"))
        assert "looks like" not in capsys.readouterr().err

    def test_unknown_family_silent(self, capsys: pytest.CaptureFixture[str]) -> None:
        from rebrew.init import _warn_profile_family_mismatch

        _warn_profile_family_mismatch("msvc6", self._tc("unknown"))
        assert "looks like" not in capsys.readouterr().err


class TestInitTemplate:
    def test_has_project_section(self) -> None:
        from rebrew.init import DEFAULT_REBREW_TOML

        assert "[project]" in DEFAULT_REBREW_TOML

    def test_has_base_cflags(self) -> None:
        from rebrew.init import DEFAULT_REBREW_TOML

        assert "base_cflags" in DEFAULT_REBREW_TOML

    def test_has_timeout(self) -> None:
        from rebrew.init import DEFAULT_REBREW_TOML

        assert "timeout" in DEFAULT_REBREW_TOML

    def test_has_ignored_symbols(self) -> None:
        from rebrew.init import DEFAULT_REBREW_TOML

        assert "ignored_symbols" in DEFAULT_REBREW_TOML

    def test_has_jobs(self) -> None:
        from rebrew.init import DEFAULT_REBREW_TOML

        assert "jobs" in DEFAULT_REBREW_TOML


class TestInitAgentSkills:
    def test_agents_md_has_skills_section(self) -> None:
        from rebrew.init import _AGENTS_MD_TEMPLATE

        template = _AGENTS_MD_TEMPLATE.read_text(encoding="utf-8")
        assert "## Agent Skills" in template

    def test_agent_skills_source_exists(self) -> None:
        from rebrew.init import _AGENT_SKILLS_SRC

        assert _AGENT_SKILLS_SRC.is_dir()
        subdirs = sorted(d.name for d in _AGENT_SKILLS_SRC.iterdir() if d.is_dir())
        assert "rebrew-intake" in subdirs

    def test_copies_agent_skills(self, tmp_path: Path) -> None:
        from rebrew.init import _copy_agent_skills

        _copy_agent_skills(tmp_path, "server.dll")
        skills_dir = tmp_path / ".agents" / "skills"
        assert skills_dir.is_dir()
        subdirs = sorted(d.name for d in skills_dir.iterdir() if d.is_dir())
        assert len(subdirs) >= 5
        for subdir in skills_dir.iterdir():
            if subdir.is_dir():
                assert (subdir / "SKILL.md").exists()
        for md_file in skills_dir.rglob("*.md"):
            content = md_file.read_text(encoding="utf-8")
            assert "<target>" not in content

    def test_copies_idempotent(self, tmp_path: Path) -> None:
        from rebrew.init import _copy_agent_skills

        _copy_agent_skills(tmp_path, "test")
        _copy_agent_skills(tmp_path, "test")
        assert (tmp_path / ".agents" / "skills").is_dir()


class TestInitCompletions:
    """rebrew init --install-completions writes bash/zsh/fish scripts."""

    def test_writes_all_three_scripts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        init(
            target_name="t",
            binary_name="t.exe",
            compiler_profile="msvc6",
            install_wibo=False,
            json_output=False,
            install_completions=True,
        )
        bash = tmp_path / "completions" / "rebrew.bash"
        zsh = tmp_path / "completions" / "rebrew.zsh"
        fish = tmp_path / "completions" / "rebrew.fish"
        assert bash.is_file()
        assert zsh.is_file()
        assert fish.is_file()
        bash_text = bash.read_text(encoding="utf-8")
        assert "_rebrew_completion" in bash_text
        assert "_REBREW_COMPLETE" in bash_text
        assert "complete_bash" in bash_text or "bash_complete" in bash_text
        assert "#compdef rebrew" in zsh.read_text(encoding="utf-8")
        assert "--command rebrew" in fish.read_text(encoding="utf-8")

    def test_no_completions_without_flag(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        init(
            target_name="t",
            binary_name="t.exe",
            compiler_profile="msvc6",
            install_wibo=False,
            json_output=False,
            install_completions=False,
        )
        assert not (tmp_path / "completions").exists()

    def test_scripts_deterministic(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        init(
            target_name="t",
            binary_name="t.exe",
            compiler_profile="msvc6",
            install_wibo=False,
            json_output=False,
            install_completions=True,
        )
        first = (tmp_path / "completions" / "rebrew.bash").read_bytes()
        other = tmp_path / "other"
        other.mkdir()
        from rebrew.init import _write_completion_scripts

        _write_completion_scripts(other)
        assert (other / "completions" / "rebrew.bash").read_bytes() == first
        assert (other / "completions" / "rebrew.zsh").read_bytes() == (
            tmp_path / "completions" / "rebrew.zsh"
        ).read_bytes()

    def test_json_reports_completions(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        import json

        monkeypatch.chdir(tmp_path)
        init(
            target_name="t",
            binary_name="t.exe",
            compiler_profile="msvc6",
            install_wibo=False,
            json_output=True,
            install_completions=True,
        )
        payload = json.loads(capsys.readouterr().out)
        assert len(payload["completions"]) == 3
        assert all("completions" in p for p in payload["completions"])

    def test_cli_flag_wires_install_completions(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--install-completions through the typer app writes the scripts."""
        from typer.testing import CliRunner

        from rebrew.init import app

        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["--install-completions"])
        assert result.exit_code == 0
        assert (tmp_path / "completions" / "rebrew.bash").is_file()
        assert (tmp_path / "completions" / "rebrew.zsh").is_file()
        assert (tmp_path / "completions" / "rebrew.fish").is_file()


class TestBinaryFormatDetection:
    """rebrew init auto-detects format/arch from a binary already in
    original/ instead of hardcoding the profile's pe/x86_32 defaults."""

    def test_detects_pe(self) -> None:
        from rebrew.init import _detect_binary_format

        pe = Path(__file__).resolve().parent / "fixtures" / "mini_pe.exe"
        assert _detect_binary_format(pe) == ("pe", "x86_32")

    def test_detects_ne(self) -> None:
        from rebrew.init import _detect_binary_format

        ne = Path(__file__).resolve().parent / "fixtures" / "mini_ne.exe"
        if not ne.exists():
            # build a minimal NE fixture on the fly (MZ stub + NE header)
            data = bytearray(0x140)
            data[0:2] = b"MZ"
            data[0x3C:0x40] = (0x100).to_bytes(4, "little")
            data[0x100:0x102] = b"NE"
            ne.write_bytes(bytes(data))
        assert _detect_binary_format(ne) == ("ne", "x86_16")

    def test_missing_binary_returns_none(self, tmp_path: Path) -> None:
        from rebrew.init import _detect_binary_format

        assert _detect_binary_format(tmp_path / "nope.exe") is None

    def test_init_writes_detected_ne_format(self, tmp_path: Path, monkeypatch) -> None:
        """End-to-end: init on a project with an NE binary writes
        format = "ne" / arch = "x86_16" (skifree16 got pe/x86_32 before)."""

        from typer.testing import CliRunner

        from rebrew.init import app

        original = tmp_path / "original"
        original.mkdir()
        ne = original / "game.exe"
        data = bytearray(0x140)
        data[0:2] = b"MZ"
        data[0x3C:0x40] = (0x100).to_bytes(4, "little")
        data[0x100:0x102] = b"NE"
        ne.write_bytes(bytes(data))

        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(
            app, ["--target", "game", "--binary", "original/game.exe", "--json"]
        )
        assert result.exit_code == 0, result.output
        toml = (tmp_path / "rebrew-project.toml").read_text(encoding="utf-8")
        assert 'format = "ne"' in toml
        assert 'arch = "x86_16"' in toml
        agents = (tmp_path / "AGENTS.md").read_text(encoding="utf-8")
        assert "(ne, x86_16)" in agents


class TestProfileMismatchWarning:
    """init warns when the detected binary contradicts the chosen profile
    (a 16-bit NE binary with a 32-bit msvc6 profile would fail doctor)."""

    def test_ne_binary_warns_on_msvc6(self, capsys) -> None:
        from rebrew.init import _warn_profile_mismatch

        _warn_profile_mismatch("msvc6", "ne", "x86_16")
        out = capsys.readouterr().err
        assert "16-bit binary (ne/x86_16)" in out
        # the suggestion lists the 16-bit-capable profiles (derived from
        # COMPILER_DEFAULTS, so tc16/watcom16 are included too)
        assert "msvc1.52" in out
        assert "tc16" in out

    def test_ne_binary_silent_on_msvc152(self, capsys) -> None:
        from rebrew.init import _warn_profile_mismatch

        _warn_profile_mismatch("msvc1.52", "ne", "x86_16")
        assert "warning" not in capsys.readouterr().err

    def test_32bit_pe_warns_on_msvc152(self, capsys) -> None:
        from rebrew.init import _warn_profile_mismatch

        _warn_profile_mismatch("msvc1.52", "pe", "x86_32")
        out = capsys.readouterr().err
        assert "16-bit compiler" in out

    def test_32bit_pe_silent_on_msvc6(self, capsys) -> None:
        from rebrew.init import _warn_profile_mismatch

        _warn_profile_mismatch("msvc6", "pe", "x86_32")
        assert "warning" not in capsys.readouterr().err

    def test_init_emits_warning_stderr_not_stdout(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        """--json mode: the mismatch warning goes to stderr so stdout stays
        pure JSON (the main init payload remains machine-parseable)."""
        import json

        from rebrew.init import init

        original = tmp_path / "original"
        original.mkdir()
        ne = original / "game.exe"
        data = bytearray(0x140)
        data[0:2] = b"MZ"
        data[0x3C:0x40] = (0x100).to_bytes(4, "little")
        data[0x100:0x102] = b"NE"
        ne.write_bytes(bytes(data))

        monkeypatch.chdir(tmp_path)
        init(
            target_name="game",
            binary_name="game.exe",
            compiler_profile="msvc6",
            json_output=True,
        )
        out = capsys.readouterr()
        # stdout parses as pure JSON (no warning interleaved)
        payload = json.loads(out.out)
        assert isinstance(payload, dict)
        # stderr carries the mismatch warning
        assert "16-bit binary" in out.err


class TestInitTc16:
    """rebrew init --compiler tc16 must generate a config that loads
    without an unknown-profile fallback (COMPILER_DEFAULTS + _KNOWN_PROFILES
    cover the new profile)."""

    def test_init_tc16_project(self, tmp_path: Path, monkeypatch) -> None:
        import warnings

        from rebrew.config import load_config
        from rebrew.init import init

        monkeypatch.chdir(tmp_path)
        init(
            target_name="main",
            binary_name="main.exe",
            compiler_profile="tc16",
            install_wibo=False,
            json_output=False,
            install_completions=False,
        )
        content = (tmp_path / "rebrew-project.toml").read_text()
        assert 'profile = "tc16"' in content
        # docker-backed: no host TCC.EXE command, empty docker-native command
        assert 'command = ""' in content
        assert "TCC.EXE" not in content
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            cfg = load_config(tmp_path, "main")
        assert cfg.compiler_profile == "tc16"
        assert not any("unknown profile" in str(x.message) for x in w)


class TestInitGuessCompiler:
    """rebrew init --guess-compiler auto-selects the profile from the
    target binary (diec → PDB → heuristics), preferring the 16-bit profile
    for DOS/NE binaries."""

    def test_guess_borlandc_from_real_exe(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.init import init

        fixture = Path(__file__).parent / "fixtures" / "tc16_hello.exe"
        if not fixture.exists():
            pytest.skip("tc16_hello.exe fixture not present")
        (tmp_path / "original").mkdir()
        import shutil

        shutil.copy(fixture, tmp_path / "original" / "game.exe")
        monkeypatch.chdir(tmp_path)
        init(
            target_name="main",
            binary_name="game.exe",
            guess_compiler=True,
            install_wibo=False,
            json_output=False,
            install_completions=False,
        )
        content = (tmp_path / "rebrew-project.toml").read_text()
        assert 'profile = "tc16"' in content

    def test_guess_msvc16_ne_binary(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.init import init
        from rebrew.toolchain_detect import ToolchainInfo

        def _fake_detect(path):  # noqa: ARG001
            return ToolchainInfo(
                family="msvc",
                version_hint="16-bit MSVC-style NE",
                confidence="high",
                arch="x86_16",
                detected_by="ne",
            )

        monkeypatch.setattr("rebrew.toolchain_detect.detect_toolchain", _fake_detect)
        (tmp_path / "original").mkdir()
        (tmp_path / "original" / "prog.exe").write_bytes(b"MZ")
        monkeypatch.chdir(tmp_path)
        init(
            target_name="main",
            binary_name="prog.exe",
            guess_compiler=True,
            install_wibo=False,
            json_output=False,
            install_completions=False,
        )
        content = (tmp_path / "rebrew-project.toml").read_text()
        assert 'profile = "msvc1.52"' in content

    def test_guess_missing_binary_errors(self, tmp_path: Path, monkeypatch, capsys) -> None:
        from rebrew.init import init

        monkeypatch.chdir(tmp_path)
        with pytest.raises(typer.Exit):
            init(
                target_name="main",
                binary_name="ghost.exe",
                guess_compiler=True,
                install_wibo=False,
                json_output=False,
                install_completions=False,
            )


class TestGuessCompilerFailure:
    """init --guess-compiler on an unrecognizable binary must fail with a
    hint to pass --compiler explicitly (perf of the onboarding UX)."""

    def test_unknown_family_suggests_explicit_compiler(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        from rebrew.init import init
        from rebrew.toolchain_detect import ToolchainInfo

        def _fake_detect(path):  # noqa: ARG001
            return ToolchainInfo(
                family="unknown",
                version_hint="",
                confidence="low",
                arch="",
                detected_by="heuristics",
            )

        monkeypatch.setattr("rebrew.toolchain_detect.detect_toolchain", _fake_detect)
        (tmp_path / "original").mkdir()
        (tmp_path / "original" / "weird.bin").write_bytes(b"\x00" * 64)
        monkeypatch.chdir(tmp_path)
        with pytest.raises(typer.Exit):
            init(
                target_name="main",
                binary_name="weird.bin",
                guess_compiler=True,
                install_wibo=False,
                json_output=False,
                install_completions=False,
            )
        captured = capsys.readouterr()
        assert "cannot guess" in captured.err
        assert "--compiler" in captured.err  # the actionable hint
