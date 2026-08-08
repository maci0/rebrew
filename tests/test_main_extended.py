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
        with pytest.raises(typer.Exit) as exc:
            main_mod.main()
        assert exc.value.exit_code == main_mod.EXIT_ERROR

    def test_keyboard_interrupt_exit_130(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _InterruptApp:
            def __call__(self, *a: object, **k: object) -> None:
                raise KeyboardInterrupt()

        monkeypatch.setattr(main_mod, "app", _InterruptApp())
        with pytest.raises(typer.Exit) as exc:
            main_mod.main()
        assert exc.value.exit_code == 130
