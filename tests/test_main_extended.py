"""Tests for rebrew main.py — umbrella CLI registration, logging levels, error paths."""

import pytest
import typer
from typer.testing import CliRunner

import rebrew.main as main_mod


class TestVerbosity:
    def _invoke(self, args: list[str]) -> object:
        levels: list[int] = []

        def _basicConfig(format="", level=0, **kw):
            levels.append(level)

        main_mod.logging.basicConfig = _basicConfig
        try:
            result = CliRunner().invoke(main_mod.app, args)
            return result, levels
        finally:
            # restore
            import logging

            main_mod.logging.basicConfig = logging.basicConfig

    def test_default_warning(self) -> None:
        result, levels = self._invoke(["skills", "list"])
        assert levels == [main_mod.logging.WARNING]

    def test_quiet(self) -> None:
        result, levels = self._invoke(["-q", "skills", "list"])
        assert levels == [main_mod.logging.WARNING]

    def test_verbose_once(self) -> None:
        result, levels = self._invoke(["-v", "skills", "list"])
        assert levels == [main_mod.logging.INFO]

    def test_verbose_twice(self) -> None:
        result, levels = self._invoke(["-vv", "skills", "list"])
        assert levels == [main_mod.logging.DEBUG]


class TestStubRegistration:
    def test_stub_cmd_reports_error(self) -> None:
        stub = main_mod._make_stub_cmd("rebrew.nope", ImportError("no module"))
        with pytest.raises(typer.Exit) as exc:
            stub()
        assert exc.value.exit_code == main_mod.EXIT_ERROR

    def test_stub_app_reports_error(self) -> None:
        stub = main_mod._make_stub_app("rebrew.nope", ImportError("no module"))
        result = CliRunner().invoke(stub, [])
        assert result.exit_code == main_mod.EXIT_ERROR
        assert "could not load" in result.output


class TestMainEntry:
    def test_value_error_handled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _BoomApp:
            def __call__(self, *a: object, **k: object) -> None:
                raise ValueError("bad target")

        monkeypatch.setattr(main_mod, "app", _BoomApp())
        # main() must exit cleanly (SystemExit, not an uncaught typer.Exit
        # that would print a traceback and exit 1).
        with pytest.raises(SystemExit) as exc:
            main_mod.main()
        assert exc.value.code == main_mod.EXIT_ERROR

    def test_keyboard_interrupt_exit_130(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _InterruptApp:
            def __call__(self, *a: object, **k: object) -> None:
                raise KeyboardInterrupt()

        monkeypatch.setattr(main_mod, "app", _InterruptApp())
        with pytest.raises(SystemExit) as exc:
            main_mod.main()
        assert exc.value.code == 130


class TestMainEntryExitPaths:
    def test_typer_exit_from_subcommand_converted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The catch-all exists because error_exit() raises typer.Exit OUTSIDE
        click's handler — it must become SystemExit(EXIT_ERROR), not a
        traceback with exit 1."""
        import typer

        from rebrew.cli import EXIT_ERROR, EXIT_MISMATCH

        class _ExitApp:
            def __call__(self, *a: object, **k: object) -> None:
                raise typer.Exit(code=EXIT_MISMATCH)

        monkeypatch.setattr(main_mod, "app", _ExitApp())
        with pytest.raises(SystemExit) as exc:
            main_mod.main()
        assert exc.value.code == EXIT_ERROR


class TestJsonRequested:
    """_json_requested must match the EXACT --json token — the old argv
    substring scan matched any argument containing the literal (cli-review
    F11: a file named x--json.c or --cflags "--json" wrongly switched the
    error envelope to JSON mode)."""

    def test_exact_json_matches(self) -> None:
        from rebrew.main import _json_requested

        assert _json_requested(["rebrew", "test", "f.c", "--json"])
        assert _json_requested(["rebrew", "test", "--json=true"])

    def test_substring_does_not_match(self) -> None:
        from rebrew.main import _json_requested

        assert not _json_requested(["rebrew", "test", "x--json.c"])
        # A VALUE containing "--json" (e.g. --cflags "--json") is one token
        # and must not match; the old substring scan matched it.
        assert not _json_requested(["rebrew", "match", "--cflags=--json"])
        assert not _json_requested([])
