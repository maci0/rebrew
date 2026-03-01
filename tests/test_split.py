"""Tests for the rebrew split command."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from typer.testing import CliRunner

from rebrew.split import app

runner = CliRunner()


def _make_cfg(tmp_path: Path, marker: str = "SERVER") -> Any:
    return SimpleNamespace(marker=marker, source_ext=".c", reversed_dir=tmp_path)


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _multi_two() -> str:
    return (
        "#include <stdio.h>\n"
        "\n"
        "// FUNCTION: SERVER 0x10001000\n"
        "// STATUS: EXACT\n"
        "// ORIGIN: GAME\n"
        "// SIZE: 42\n"
        "// CFLAGS: /O2\n"
        "// SYMBOL: _func_a\n"
        "\n"
        "int func_a(void) { return 0; }\n"
        "\n"
        "// FUNCTION: SERVER 0x10002000\n"
        "// STATUS: MATCHING\n"
        "// ORIGIN: GAME\n"
        "// SIZE: 84\n"
        "// CFLAGS: /O2\n"
        "// SYMBOL: _func_b\n"
        "\n"
        "int func_b(void) { return 1; }\n"
    )


class TestSplitBasic:
    def test_splits_two_functions(self, tmp_path: Path, monkeypatch: Any) -> None:
        src = _write(tmp_path / "multi.c", _multi_two())
        monkeypatch.setattr("rebrew.split.get_config", lambda target=None: _make_cfg(tmp_path))

        result = runner.invoke(app, [str(src)])
        assert result.exit_code == 0
        assert (tmp_path / "func_a.c").exists()
        assert (tmp_path / "func_b.c").exists()

    def test_includes_shared_preamble_in_each_output(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        content = (
            "#include <stdio.h>\n"
            "#define MAGIC 7\n"
            "\n"
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: EXACT\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 1\n"
            "// CFLAGS: /O2\n"
            "// SYMBOL: _a\n"
            "\n"
            "int a(void) { return MAGIC; }\n"
            "\n"
            "// FUNCTION: SERVER 0x10002000\n"
            "// STATUS: EXACT\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 1\n"
            "// CFLAGS: /O2\n"
            "// SYMBOL: _b\n"
            "\n"
            "int b(void) { return MAGIC; }\n"
        )
        src = _write(tmp_path / "multi.c", content)
        monkeypatch.setattr("rebrew.split.get_config", lambda target=None: _make_cfg(tmp_path))

        result = runner.invoke(app, [str(src)])
        assert result.exit_code == 0
        assert "#include <stdio.h>" in (tmp_path / "a.c").read_text(encoding="utf-8")
        assert "#define MAGIC 7" in (tmp_path / "b.c").read_text(encoding="utf-8")

    def test_uses_symbol_for_filename(self, tmp_path: Path, monkeypatch: Any) -> None:
        src = _write(tmp_path / "multi.c", _multi_two())
        monkeypatch.setattr("rebrew.split.get_config", lambda target=None: _make_cfg(tmp_path))

        result = runner.invoke(app, [str(src)])
        assert result.exit_code == 0
        assert (tmp_path / "func_a.c").exists()
        assert (tmp_path / "func_b.c").exists()

    def test_falls_back_to_va_filename_without_symbol(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        content = (
            "// FUNCTION: SERVER 0x1000ABCD\n"
            "// STATUS: EXACT\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 1\n"
            "// CFLAGS: /O2\n"
            "\n"
            "int first(void) { return 0; }\n"
            "\n"
            "// FUNCTION: SERVER 0x10002000\n"
            "// STATUS: EXACT\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 1\n"
            "// CFLAGS: /O2\n"
            "// SYMBOL: _named\n"
            "\n"
            "int named(void) { return 0; }\n"
        )
        src = _write(tmp_path / "multi.c", content)
        monkeypatch.setattr("rebrew.split.get_config", lambda target=None: _make_cfg(tmp_path))

        result = runner.invoke(app, [str(src)])
        assert result.exit_code == 0
        assert (tmp_path / "func_1000abcd.c").exists()
        assert (tmp_path / "named.c").exists()

    def test_dry_run_does_not_create_files(self, tmp_path: Path, monkeypatch: Any) -> None:
        src = _write(tmp_path / "multi.c", _multi_two())
        monkeypatch.setattr("rebrew.split.get_config", lambda target=None: _make_cfg(tmp_path))

        result = runner.invoke(app, ["--dry-run", str(src)])
        assert result.exit_code == 0
        assert not (tmp_path / "func_a.c").exists()
        assert not (tmp_path / "func_b.c").exists()

    def test_errors_when_input_has_only_one_function(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        content = (
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: EXACT\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 1\n"
            "// CFLAGS: /O2\n"
            "// SYMBOL: _only\n"
            "\n"
            "int only(void) { return 0; }\n"
        )
        src = _write(tmp_path / "single.c", content)
        monkeypatch.setattr("rebrew.split.get_config", lambda target=None: _make_cfg(tmp_path))

        result = runner.invoke(app, [str(src)])
        assert result.exit_code != 0
        assert "at least two function blocks" in result.output

    def test_errors_when_output_exists_without_force(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        src = _write(tmp_path / "multi.c", _multi_two())
        _write(tmp_path / "func_a.c", "stale\n")
        monkeypatch.setattr("rebrew.split.get_config", lambda target=None: _make_cfg(tmp_path))

        result = runner.invoke(app, [str(src)])
        assert result.exit_code != 0
        assert "Output file already exists" in result.output

    def test_force_overwrites_existing_files(self, tmp_path: Path, monkeypatch: Any) -> None:
        src = _write(tmp_path / "multi.c", _multi_two())
        existing = _write(tmp_path / "func_a.c", "stale\n")
        monkeypatch.setattr("rebrew.split.get_config", lambda target=None: _make_cfg(tmp_path))

        result = runner.invoke(app, ["--force", str(src)])
        assert result.exit_code == 0
        assert "// FUNCTION: SERVER 0x10001000" in existing.read_text(encoding="utf-8")

    def test_json_output_structure(self, tmp_path: Path, monkeypatch: Any) -> None:
        src = _write(tmp_path / "multi.c", _multi_two())
        payloads: list[dict[str, Any]] = []
        monkeypatch.setattr("rebrew.split.get_config", lambda target=None: _make_cfg(tmp_path))
        monkeypatch.setattr("rebrew.split.json_print", lambda data: payloads.append(data))

        result = runner.invoke(app, ["--json", str(src)])
        assert result.exit_code == 0
        assert len(payloads) == 1
        payload = payloads[0]
        assert payload["count"] == 2
        assert payload["dry_run"] is False
        assert "files" in payload
        assert len(payload["files"]) == 2

    def test_filters_blocks_to_selected_target(self, tmp_path: Path, monkeypatch: Any) -> None:
        content = (
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: EXACT\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 1\n"
            "// CFLAGS: /O2\n"
            "// SYMBOL: _server_a\n"
            "\n"
            "int server_a(void) { return 0; }\n"
            "\n"
            "// FUNCTION: CLIENT 0x20001000\n"
            "// STATUS: EXACT\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 1\n"
            "// CFLAGS: /O2\n"
            "// SYMBOL: _client_a\n"
            "\n"
            "int client_a(void) { return 0; }\n"
            "\n"
            "// FUNCTION: SERVER 0x10002000\n"
            "// STATUS: EXACT\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 1\n"
            "// CFLAGS: /O2\n"
            "// SYMBOL: _server_b\n"
            "\n"
            "int server_b(void) { return 0; }\n"
        )
        src = _write(tmp_path / "multi.c", content)
        monkeypatch.setattr(
            "rebrew.split.get_config",
            lambda target=None: _make_cfg(tmp_path, marker="SERVER"),
        )

        result = runner.invoke(app, [str(src)])
        assert result.exit_code == 0
        assert (tmp_path / "server_a.c").exists()
        assert (tmp_path / "server_b.c").exists()
        assert not (tmp_path / "client_a.c").exists()
