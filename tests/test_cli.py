"""Tests for the shared CLI helpers in rebrew.cli."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import typer

from rebrew.cli import (
    EXIT_ERROR,
    error_exit,
    json_print,
    parse_va,
    require_config,
    resolve_source_arg,
)

# ---------------------------------------------------------------------------
# error_exit()
# ---------------------------------------------------------------------------


class TestErrorExit:
    def test_plain_stderr_and_exit(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(typer.Exit) as exc_info:
            error_exit("something broke")
        assert exc_info.value.exit_code == 1
        captured = capsys.readouterr()
        assert "something broke" in captured.err
        assert captured.out == ""

    def test_custom_exit_code(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(typer.Exit) as exc_info:
            error_exit("fatal", code=2)
        assert exc_info.value.exit_code == 2

    def test_json_mode_stdout(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(typer.Exit):
            error_exit("bad input", json_mode=True)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data == {"error": "bad input", "code": 1}
        assert captured.err == ""

    def test_json_mode_exit_code(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(typer.Exit) as exc_info:
            error_exit("nope", json_mode=True, code=3)
        assert exc_info.value.exit_code == 3
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data == {"error": "nope", "code": 3}


# ---------------------------------------------------------------------------
# require_config()
# ---------------------------------------------------------------------------


class TestRequireConfig:
    def test_missing_config_exits_as_infrastructure_error(self, tmp_path: Path) -> None:
        with pytest.raises(typer.Exit) as exc_info:
            require_config(root=tmp_path)
        assert exc_info.value.exit_code == EXIT_ERROR

    def test_explicit_root_loads_project(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-project.toml").write_text(
            "\n".join(
                [
                    "[project]",
                    'default_target = "main"',
                    "",
                    "[targets.main]",
                    'binary = "test.exe"',
                    'format = "pe"',
                    'arch = "x86_32"',
                    'reversed_dir = "src"',
                ]
            ),
            encoding="utf-8",
        )

        cfg = require_config(root=tmp_path)

        assert cfg.target_name == "main"


# ---------------------------------------------------------------------------
# json_print()
# ---------------------------------------------------------------------------


class TestJsonPrint:
    def test_dict_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        json_print({"status": "ok", "count": 42})
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data == {"status": "ok", "count": 42}
        assert captured.err == ""

    def test_list_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        json_print([{"va": "0x1000"}, {"va": "0x2000"}])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 2
        assert data[0]["va"] == "0x1000"

    def test_pretty_printed(self, capsys: pytest.CaptureFixture[str]) -> None:
        json_print({"a": 1})
        captured = capsys.readouterr()
        assert "\n" in captured.out

    def test_empty_dict(self, capsys: pytest.CaptureFixture[str]) -> None:
        json_print({})
        captured = capsys.readouterr()
        assert json.loads(captured.out) == {}


# ---------------------------------------------------------------------------
# parse_va()
# ---------------------------------------------------------------------------


class TestParseVa:
    def test_bare_hex(self) -> None:
        assert parse_va("10003da0") == 0x10003DA0

    def test_prefixed_hex(self) -> None:
        assert parse_va("0x10003da0") == 0x10003DA0

    def test_uppercase(self) -> None:
        assert parse_va("0X10003DA0") == 0x10003DA0

    def test_whitespace_stripped(self) -> None:
        assert parse_va("  0x1000  ") == 0x1000

    def test_invalid_exits(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(typer.Exit) as exc_info:
            parse_va("not_hex")
        assert exc_info.value.exit_code == 1
        captured = capsys.readouterr()
        assert "not_hex" in captured.err

    def test_invalid_json_mode(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(typer.Exit):
            parse_va("zzz", json_mode=True)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "error" in data
        assert "zzz" in data["error"]

    def test_empty_string_exits(self) -> None:
        with pytest.raises(typer.Exit):
            parse_va("")

    def test_zero(self) -> None:
        assert parse_va("0") == 0

    def test_small_value(self) -> None:
        assert parse_va("ff") == 255


class TestRequireConfigErrors:
    def test_config_error_exits(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.cli as cli_mod

        def bad_load(root=None, target=None) -> object:
            raise ValueError("broken TOML")

        monkeypatch.setattr(cli_mod, "load_config", bad_load)
        with pytest.raises(typer.Exit) as exc_info:
            require_config(root=tmp_path)
        assert exc_info.value.exit_code == EXIT_ERROR


class TestIterAnnotations:
    def test_parse_error_skipped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.cli as cli_mod

        def boom(src, target_name=None, metadata_dir=None) -> object:
            raise ValueError("bad annotation")

        monkeypatch.setattr("rebrew.annotation.parse_c_file_multi", boom)
        src = tmp_path / "a.c"
        src.write_text("x", encoding="utf-8")
        assert cli_mod.iter_annotations([src], target="SERVER") == []


# ---------------------------------------------------------------------------
# resolve_source_arg()
# ---------------------------------------------------------------------------


class TestResolveSourceArg:
    """resolve_source_arg: path / symbol name / hex VA → source file Path."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(
            reversed_dir=tmp_path, metadata_dir=tmp_path.parent, source_ext=".c", marker="GAME"
        )

    def test_direct_path_that_exists(self, tmp_path: Path) -> None:
        src = tmp_path / "foo.c"
        src.write_text("// FUNCTION: GAME 0x1000\nint foo(void) { return 0; }\n", encoding="utf-8")
        assert resolve_source_arg(self._cfg(tmp_path), str(src)) == src

    def test_symbol_search_finds_stem_match(self, tmp_path: Path) -> None:
        src = tmp_path / "my_func.c"
        src.write_text(
            "// FUNCTION: GAME 0x1000\nint my_func(void) { return 0; }\n", encoding="utf-8"
        )
        assert resolve_source_arg(self._cfg(tmp_path), "my_func") == src

    def test_symbol_search_strips_leading_underscore(self, tmp_path: Path) -> None:
        src = tmp_path / "my_func.c"
        src.write_text(
            "// FUNCTION: GAME 0x1000\nint my_func(void) { return 0; }\n", encoding="utf-8"
        )
        assert resolve_source_arg(self._cfg(tmp_path), "_my_func") == src

    def test_va_lookup_finds_annotation(self, tmp_path: Path) -> None:
        src = tmp_path / "target_func.c"
        src.write_text("// FUNCTION: GAME 0x1000\nint f(void) { return 0; }\n", encoding="utf-8")
        assert resolve_source_arg(self._cfg(tmp_path), "0x1000") == src

    def test_va_lookup_with_no_match_returns_argument(self, tmp_path: Path) -> None:
        src = tmp_path / "target_func.c"
        src.write_text("// FUNCTION: GAME 0x1000\nint f(void) { return 0; }\n", encoding="utf-8")
        # No function at this VA — argument passes through unchanged.
        assert resolve_source_arg(self._cfg(tmp_path), "0x2000") == Path("0x2000")

    def test_nonexistent_returns_path_as_is(self, tmp_path: Path) -> None:
        result = resolve_source_arg(self._cfg(tmp_path), "no_such_func")
        # Returns Path("no_such_func") which doesn't exist — caller handles it
        assert result == Path("no_such_func")
