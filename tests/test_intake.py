"""Tests for rebrew.intake — one-shot binary onboarding."""

from __future__ import annotations

import json
from pathlib import Path

from rebrew.intake import _suggest_profile, blocker_reason

FAKE_FUNCS = [(0x401000, 32, "fcn.00401000"), (0x401020, 8, "fcn.00401020")]


def _run_main(tmp_path: Path, monkeypatch, *, argv: list[str]) -> str:
    """Invoke the intake CLI (via the real `rebrew intake` command), capturing stdout."""
    from typer.testing import CliRunner

    import rebrew.main as main_mod

    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    def _fake_rizin(binary: Path) -> list[tuple[int, int, str]]:
        return FAKE_FUNCS

    monkeypatch.setattr("rebrew.intake._run_rizin_functions", _fake_rizin)
    monkeypatch.setattr(
        "rebrew.intake._suggest_profile",
        lambda b: ("msvc6", "msvc", "MSVC 6.0", []),
    )
    result = runner.invoke(main_mod.app, ["intake", *argv])
    assert result.exit_code == 0, result.output
    return result.output


class TestIntake:
    def test_dry_run_no_writes(self, tmp_path: Path, monkeypatch) -> None:
        binary = tmp_path / "game.exe"
        binary.write_bytes(b"MZ")
        out = _run_main(tmp_path, monkeypatch, argv=["game.exe", "--dry-run", "--json"])
        data = json.loads(out)
        assert data["dry_run"] is True
        assert data["profile"] == "msvc6"
        assert data["family"] == "msvc"
        # The preview now runs rizin (read-only) so the user sees the real
        # function count before committing to the onboarding.
        assert data["function_count"] == 2
        assert not (tmp_path / "rebrew-project.toml").exists()

    def test_full_intake_writes_project(self, tmp_path: Path, monkeypatch) -> None:
        binary = tmp_path / "game.exe"
        binary.write_bytes(b"MZ")
        out = _run_main(tmp_path, monkeypatch, argv=["game.exe", "--json"])
        data = json.loads(out)
        assert data["functions"] == 2
        assert data["documented"] == 2
        assert data["target"] == "game"
        # functions.txt written
        funcs = (tmp_path / "src" / "game" / "functions.txt").read_text()
        assert "0x00401000" in funcs
        # STUB .c written
        stub = (tmp_path / "src" / "game" / "fcn_00401000.c").read_text()
        assert "// STUB: GAME 0x00401000" in stub
        # metadata has blocker + STUB
        meta = (tmp_path / "src" / "rebrew-function.toml").read_text()
        assert "blocker" in meta
        assert 'status = "STUB"' in meta
        # documented stubs carry the disassembly-derived SIZE so rebrew test
        # can run on them (a size-less stub is untestable + reports MISSING_SIZE)
        assert "size = 32" in meta
        assert "size = 8" in meta
        # binary copied
        assert (tmp_path / "original" / "game.exe").exists()

    def test_binary_missing_fails(self, tmp_path: Path, monkeypatch) -> None:
        from typer.testing import CliRunner

        import rebrew.main as main_mod

        runner = CliRunner()
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(main_mod.app, ["intake", "nope.exe", "--json"])
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_rizin_empty_functions_fails(self, tmp_path: Path, monkeypatch) -> None:
        """Regression (error-review F2): rizin failing/timing out must not be
        reported as a successful 'Intake complete: functions: 0' — onboarding
        with an empty function list is useless and misleading."""
        from typer.testing import CliRunner

        import rebrew.main as main_mod

        binary = tmp_path / "game.exe"
        binary.write_bytes(b"MZ")
        monkeypatch.setattr("rebrew.intake._run_rizin_functions", lambda b: [])
        monkeypatch.setattr(
            "rebrew.intake._suggest_profile",
            lambda b: ("msvc6", "msvc", "MSVC 6.0", []),
        )
        runner = CliRunner()
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(main_mod.app, ["intake", "game.exe", "--json"])
        assert result.exit_code != 0
        assert "no functions" in result.output
        # scaffold may exist, but no success payload
        assert '"functions"' not in result.output

    def test_rediscovery_prunes_stale_stubs(self, tmp_path: Path, monkeypatch) -> None:
        """Regression: re-running intake after the function list changes must
        remove auto-generated stubs (and their metadata) for functions that no
        longer exist — otherwise status totals inflate (observed on the 16-bit
        SkiFree NE re-onboarding: 233 orphaned stubs from a broken first run)."""
        from typer.testing import CliRunner

        import rebrew.main as main_mod

        binary = tmp_path / "game.exe"
        binary.write_bytes(b"MZ")

        def _fake_rizin_v1(binary: Path) -> list[tuple[int, int, str]]:
            return [(0x401000, 32, "fcn.00401000"), (0x402000, 64, "fcn.00402000")]

        monkeypatch.setattr("rebrew.intake._run_rizin_functions", _fake_rizin_v1)
        monkeypatch.setattr(
            "rebrew.intake._suggest_profile",
            lambda b: ("msvc6", "msvc", "MSVC 6.0", []),
        )
        runner = CliRunner()
        monkeypatch.chdir(tmp_path)
        out1 = runner.invoke(main_mod.app, ["intake", "game.exe", "--json"])
        assert out1.exit_code == 0, out1.output
        assert (tmp_path / "src" / "game" / "fcn_00402000.c").exists()

        # Re-discovery: one function vanishes, one new one appears.
        monkeypatch.setattr(
            "rebrew.intake._run_rizin_functions",
            lambda b: [(0x401000, 32, "fcn.00401000"), (0x403000, 16, "fcn.00403000")],
        )
        out2 = runner.invoke(main_mod.app, ["intake", "game.exe", "--json"])
        assert out2.exit_code == 0, out2.output
        # The vanished function's auto-stub is gone; the new one exists.
        assert not (tmp_path / "src" / "game" / "fcn_00402000.c").exists()
        assert (tmp_path / "src" / "game" / "fcn_00403000.c").exists()
        # Metadata entry for the vanished function is gone too.
        meta = (tmp_path / "src" / "rebrew-function.toml").read_text()
        assert "0x00402000" not in meta
        assert "0x00403000" in meta

    def test_rediscovery_keeps_edited_stubs(self, tmp_path: Path, monkeypatch) -> None:
        """A stub the user has edited (no longer matching the auto-stub
        pattern) must survive re-discovery even if its VA vanishes."""
        from typer.testing import CliRunner

        import rebrew.main as main_mod

        binary = tmp_path / "game.exe"
        binary.write_bytes(b"MZ")
        monkeypatch.setattr(
            "rebrew.intake._run_rizin_functions",
            lambda b: [(0x401000, 32, "fcn.00401000"), (0x402000, 64, "fcn.00402000")],
        )
        monkeypatch.setattr(
            "rebrew.intake._suggest_profile",
            lambda b: ("msvc6", "msvc", "MSVC 6.0", []),
        )
        runner = CliRunner()
        monkeypatch.chdir(tmp_path)
        out1 = runner.invoke(main_mod.app, ["intake", "game.exe", "--json"])
        assert out1.exit_code == 0, out1.output

        # User replaces the stub with real source (no STUB header).
        stub = tmp_path / "src" / "game" / "fcn_00402000.c"
        stub.write_text("// my decompilation work\nint real_fn(void) { return 0; }\n")

        monkeypatch.setattr(
            "rebrew.intake._run_rizin_functions",
            lambda b: [(0x401000, 32, "fcn.00401000")],
        )
        out2 = runner.invoke(main_mod.app, ["intake", "game.exe", "--json"])
        assert out2.exit_code == 0, out2.output
        assert stub.exists()  # edited file survives the prune


class TestBlockers:
    def test_thunk_reason(self) -> None:
        assert "thunk" in blocker_reason("msvc", 6, "")

    def test_delphi_reason(self) -> None:
        assert "Delphi" in blocker_reason("delphi", 64, "")

    def test_mingw_reason(self) -> None:
        assert "MinGW" in blocker_reason("mingw", 64, "pre-8 GCC style")

    def test_default_reason(self) -> None:
        assert "pending" in blocker_reason("msvc", 64, "")


class TestSuggestProfile:
    def test_watcom_routes_to_watcom_profile(self, monkeypatch) -> None:
        from rebrew.toolchain_detect import ToolchainInfo

        def _fake_detect(path) -> ToolchainInfo:
            return ToolchainInfo(family="watcom", confidence="high", version_hint="Watcom C/C++")

        monkeypatch.setattr("rebrew.toolchain_detect.detect_toolchain", _fake_detect)
        profile, family, hint, notes = _suggest_profile(Path("x.exe"))
        assert profile == "watcom"
        assert family == "watcom"
        assert any("watcom" in n for n in notes)

    def test_auto_detection_routing(self, monkeypatch) -> None:
        from rebrew.toolchain_detect import ToolchainInfo

        def _fake_detect(path) -> ToolchainInfo:
            return ToolchainInfo(family="mingw", confidence="high", version_hint="pre-8 GCC style")

        monkeypatch.setattr("rebrew.toolchain_detect.detect_toolchain", _fake_detect)
        profile, family, hint, notes = _suggest_profile(Path("x.exe"))
        assert profile == "gcc-pe"
        assert family == "mingw"


class TestSuggestProfile16Bit:
    """intake must pick the msvc1.52 (DOSBox) profile for 16-bit NE targets —
    a 32-bit msvc6 profile would produce a project that fails doctor."""

    def test_ne_routes_to_msvc152(self, monkeypatch) -> None:
        from rebrew.toolchain_detect import ToolchainInfo

        def _fake_detect(path) -> ToolchainInfo:
            return ToolchainInfo(
                family="msvc",
                arch="x86_16",
                confidence="medium",
                version_hint="16-bit MSVC-style NE (no Borland segment markers)",
            )

        monkeypatch.setattr("rebrew.toolchain_detect.detect_toolchain", _fake_detect)
        profile, family, hint, notes = _suggest_profile(Path("x.exe"))
        assert profile == "msvc1.52"
        assert family == "msvc"
        assert any("16-bit NE" in n for n in notes)

    def test_32bit_msvc_still_routes_to_msvc6(self, monkeypatch) -> None:
        from rebrew.toolchain_detect import ToolchainInfo

        def _fake_detect(path) -> ToolchainInfo:
            return ToolchainInfo(family="msvc", confidence="high", version_hint="MSVC 6.0")

        monkeypatch.setattr("rebrew.toolchain_detect.detect_toolchain", _fake_detect)
        profile, family, hint, notes = _suggest_profile(Path("x.exe"))
        assert profile == "msvc6"
        assert family == "msvc"


class TestToolchainLinks:
    """intake's profile -> vendored-toolchain link map must cover every
    matchable profile, including msvc1.52 (16-bit NE onboarding)."""

    def test_msvc152_has_link_entry(self) -> None:
        from rebrew.intake import _TOOLCHAIN_LINKS

        assert "msvc1.52" in _TOOLCHAIN_LINKS
        link_name, src_name = _TOOLCHAIN_LINKS["msvc1.52"]
        assert link_name == "MSVC152"
        assert src_name == "MSVC152"

    def test_every_matchable_profile_has_entry(self) -> None:
        from rebrew.intake import _TOOLCHAIN_LINKS

        # profiles that have a vendored tools/ dir in the repo should be
        # linkable (msvc400 lacks a vendored dir and is fine to skip)
        for profile in ("msvc6", "msvc1.52", "msvc5", "msvc420", "msvc6.3", "msvc6.6", "msvc7"):
            assert profile in _TOOLCHAIN_LINKS, profile
