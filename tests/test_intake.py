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
    def test_auto_detection_routing(self, monkeypatch) -> None:
        from rebrew.toolchain_detect import ToolchainInfo

        def _fake_detect(path) -> ToolchainInfo:
            return ToolchainInfo(family="mingw", confidence="high", version_hint="pre-8 GCC style")

        monkeypatch.setattr("rebrew.toolchain_detect.detect_toolchain", _fake_detect)
        profile, family, hint, notes = _suggest_profile(Path("x.exe"))
        assert profile == "gcc-pe"
        assert family == "mingw"
