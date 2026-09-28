"""Tests for ``rebrew test --watch`` (single-file watch mode)."""

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import typer

import rebrew.test as test_mod
from rebrew.cli import EXIT_ERROR

#: ``main`` leaves omitted parameters as typer ``OptionInfo`` sentinels, which
#: are truthy, so a partial direct call trips an unrelated guard (the
#: ``--linked``/``--fix-sizes`` check) before reaching the one under test. Every
#: parameter is therefore passed explicitly.
_CLI_DEFAULTS: dict[str, Any] = {
    "va": None,
    "symbol": None,
    "target_bin": None,
    "size": None,
    "cflags": None,
    "toolchain": None,
    "all_sources": False,
    "batch_dir": None,
    "origin": None,
    "dry_run": False,
    "jobs": None,
    "no_promote": False,
    "force_status": False,
    "fix_sizes": False,
    "linked": False,
    "context": None,
    "json_output": False,
    "target": None,
}


class TestWatchLoop:
    def test_retests_on_change(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A detected file change triggers retest(); KeyboardInterrupt stops the loop."""
        src = tmp_path / "func.c"
        src.write_text("v1", encoding="utf-8")
        calls: list[str] = []

        def fake_sleep(_seconds: float) -> None:
            if not calls:
                os.utime(src, ns=(1_800_000_000_000_000_000, 1_800_000_001_000_000_000))
            else:
                raise KeyboardInterrupt

        import rebrew.utils as utils_mod

        monkeypatch.setattr(utils_mod.time, "sleep", fake_sleep)
        test_mod._watch_loop(src, lambda: calls.append("retest"))
        assert calls == ["retest"]

    def test_no_change_no_retest(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """No file change means retest is never called."""
        src = tmp_path / "func.c"
        src.write_text("v1", encoding="utf-8")
        calls: list[str] = []

        def fake_sleep(_seconds: float) -> None:
            raise KeyboardInterrupt

        import rebrew.utils as utils_mod

        monkeypatch.setattr(utils_mod.time, "sleep", fake_sleep)
        test_mod._watch_loop(src, lambda: calls.append("retest"))
        assert calls == []

    def test_missing_file_tolerated(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A file that does not exist yet is tolerated; retest fires once it appears."""
        src = tmp_path / "func.c"  # does not exist
        calls: list[str] = []
        created = False

        def fake_sleep(_seconds: float) -> None:
            nonlocal created
            if not created:
                src.write_text("v1", encoding="utf-8")
                created = True
            elif not calls:
                os.utime(src, ns=(1_800_000_000_000_000_000, 1_800_000_001_000_000_000))
            else:
                raise KeyboardInterrupt

        import rebrew.utils as utils_mod

        monkeypatch.setattr(utils_mod.time, "sleep", fake_sleep)
        test_mod._watch_loop(src, lambda: calls.append("retest"))
        assert calls == ["retest"]

    def test_failed_run_does_not_stop_loop(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A typer.Exit from retest (e.g. compile error) is swallowed; next change retests."""
        src = tmp_path / "func.c"
        src.write_text("v1", encoding="utf-8")
        calls: list[str] = []

        def fake_sleep(_seconds: float) -> None:
            if not calls:
                os.utime(src, ns=(1_800_000_000_000_000_000, 1_800_000_001_000_000_000))
            elif calls == ["fail"]:
                os.utime(src, ns=(1_800_000_000_000_000_000, 1_800_000_002_000_000_000))
            else:
                raise KeyboardInterrupt

        def retest() -> None:
            if not calls:
                calls.append("fail")
                raise typer.Exit(code=1)
            calls.append("retest")

        import rebrew.utils as utils_mod

        monkeypatch.setattr(utils_mod.time, "sleep", fake_sleep)
        test_mod._watch_loop(src, retest)
        assert calls == ["fail", "retest"]


class TestWatchCli:
    def test_watch_rejects_all(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """--watch combined with --all is an error."""
        monkeypatch.setattr(
            test_mod,
            "require_config",
            lambda target=None, json_mode=False: SimpleNamespace(metadata_dir=Path("/tmp")),
        )
        with pytest.raises(typer.Exit) as exc_info:
            test_mod.main(**{**_CLI_DEFAULTS, "all_sources": True}, source=None, watch=True)
        assert exc_info.value.exit_code == EXIT_ERROR
        assert "--watch cannot be combined with --all" in capsys.readouterr().err

    def test_watch_requires_source(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """--watch without a source file is an error."""
        monkeypatch.setattr(
            test_mod,
            "require_config",
            lambda target=None, json_mode=False: SimpleNamespace(metadata_dir=Path("/tmp")),
        )
        with pytest.raises(typer.Exit) as exc_info:
            test_mod.main(**_CLI_DEFAULTS, source=None, watch=True)
        assert exc_info.value.exit_code == EXIT_ERROR
        assert "Provide a source file" in capsys.readouterr().err

    def test_watch_dispatches_to_loop(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--watch with a source file dispatches to _watch_loop with a retest closure."""
        src = tmp_path / "func.c"
        src.write_text("int f(void) { return 1; }\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        seen: dict[str, object] = {}
        monkeypatch.setattr(
            test_mod,
            "require_config",
            lambda target=None, json_mode=False: SimpleNamespace(metadata_dir=tmp_path),
        )

        def fake_loop(path: Path, retest: object) -> None:
            seen["path"] = path
            seen["retest"] = retest

        monkeypatch.setattr(test_mod, "_watch_loop", fake_loop)
        # Note: typer's callback wrapper misbinds partial keyword sets on direct
        # calls, so every parameter must be passed explicitly.
        test_mod.main(
            source="func.c",
            va="0x10001000",
            symbol="_f",
            target_bin="/tmp/target.bin",
            size=16,
            cflags=None,
            all_sources=False,
            batch_dir=None,
            origin=None,
            dry_run=False,
            jobs=None,
            no_promote=False,
            force_status=False,
            fix_sizes=False,
            linked=False,
            watch=True,
            context=None,
            json_output=False,
            target=None,
        )
        assert seen["path"].name == "func.c"
        assert callable(seen["retest"])
