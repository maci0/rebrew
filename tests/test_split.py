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
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )

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
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )

        result = runner.invoke(app, [str(src)])
        assert result.exit_code == 0
        assert "#include <stdio.h>" in (tmp_path / "a.c").read_text(encoding="utf-8")
        assert "#define MAGIC 7" in (tmp_path / "b.c").read_text(encoding="utf-8")

    def test_uses_symbol_for_filename(self, tmp_path: Path, monkeypatch: Any) -> None:
        src = _write(tmp_path / "multi.c", _multi_two())
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )

        result = runner.invoke(app, [str(src)])
        assert result.exit_code == 0
        assert (tmp_path / "func_a.c").exists()
        assert (tmp_path / "func_b.c").exists()

    def test_derives_name_from_c_definition_without_symbol_annotation(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """Function name should come from C definition even without // SYMBOL:."""
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
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )

        result = runner.invoke(app, [str(src)])
        assert result.exit_code == 0
        # Name derived from C definition, not VA fallback
        assert (tmp_path / "first.c").exists()
        assert (tmp_path / "named.c").exists()

    def test_dry_run_does_not_create_files(self, tmp_path: Path, monkeypatch: Any) -> None:
        src = _write(tmp_path / "multi.c", _multi_two())
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )

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
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )

        result = runner.invoke(app, [str(src)])
        assert result.exit_code != 0
        assert "at least two function blocks" in result.output

    def test_errors_when_output_exists_without_force(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        src = _write(tmp_path / "multi.c", _multi_two())
        _write(tmp_path / "func_a.c", "stale\n")
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )

        result = runner.invoke(app, [str(src)])
        assert result.exit_code != 0
        assert "Output file already exists" in result.output

    def test_force_overwrites_existing_files(self, tmp_path: Path, monkeypatch: Any) -> None:
        src = _write(tmp_path / "multi.c", _multi_two())
        existing = _write(tmp_path / "func_a.c", "stale\n")
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )

        result = runner.invoke(app, ["--force", str(src)])
        assert result.exit_code == 0
        assert "// FUNCTION: SERVER 0x10001000" in existing.read_text(encoding="utf-8")

    def test_json_output_structure(self, tmp_path: Path, monkeypatch: Any) -> None:
        src = _write(tmp_path / "multi.c", _multi_two())
        payloads: list[dict[str, Any]] = []
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )
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
            "rebrew.split.require_config",
            lambda target=None, json_mode=False: _make_cfg(tmp_path, marker="SERVER"),
        )

        result = runner.invoke(app, [str(src)])
        assert result.exit_code == 0
        assert (tmp_path / "server_a.c").exists()
        assert (tmp_path / "server_b.c").exists()
        assert not (tmp_path / "client_a.c").exists()


class TestSplitExtractVA:
    """Tests for --va single-function extraction mode."""

    def test_extracts_single_function_with_preamble(self, tmp_path: Path, monkeypatch: Any) -> None:
        src = _write(tmp_path / "multi.c", _multi_two())
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )

        result = runner.invoke(app, ["--va", "0x10001000", str(src)])
        assert result.exit_code == 0
        out = tmp_path / "multi_c" / "func_a.c"
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "#include <stdio.h>" in content
        assert "// FUNCTION: SERVER 0x10001000" in content
        assert "int func_a(void)" in content

    def test_removes_extracted_block_from_source(self, tmp_path: Path, monkeypatch: Any) -> None:
        src = _write(tmp_path / "multi.c", _multi_two())
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )

        result = runner.invoke(app, ["--va", "0x10001000", str(src)])
        assert result.exit_code == 0
        remaining = src.read_text(encoding="utf-8")
        assert "0x10001000" not in remaining
        assert "// FUNCTION: SERVER 0x10002000" in remaining
        assert "#include <stdio.h>" in remaining

    def test_dry_run_does_not_modify_files(self, tmp_path: Path, monkeypatch: Any) -> None:
        src = _write(tmp_path / "multi.c", _multi_two())
        original = src.read_text(encoding="utf-8")
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )

        result = runner.invoke(app, ["--dry-run", "--va", "0x10001000", str(src)])
        assert result.exit_code == 0
        assert not (tmp_path / "multi_c" / "func_a.c").exists()
        assert src.read_text(encoding="utf-8") == original

    def test_errors_on_unknown_va(self, tmp_path: Path, monkeypatch: Any) -> None:
        src = _write(tmp_path / "multi.c", _multi_two())
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )

        result = runner.invoke(app, ["--va", "0xDEADBEEF", str(src)])
        assert result.exit_code != 0
        assert "No function block found" in result.output

    def test_errors_on_invalid_hex_va(self, tmp_path: Path, monkeypatch: Any) -> None:
        """Non-hex --va should produce a clear error, not a traceback."""
        src = _write(tmp_path / "multi.c", _multi_two())
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )

        result = runner.invoke(app, ["--va", "not_hex", str(src)])
        assert result.exit_code != 0
        assert "Invalid VA" in result.output

    def test_va_force_overwrites(self, tmp_path: Path, monkeypatch: Any) -> None:
        """--va --force should overwrite an existing extracted file."""
        src = _write(tmp_path / "multi.c", _multi_two())
        out_dir = tmp_path / "multi_c"
        out_dir.mkdir()
        _write(out_dir / "func_a.c", "stale\n")
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )

        result = runner.invoke(app, ["--va", "0x10001000", "--force", str(src)])
        assert result.exit_code == 0
        content = (out_dir / "func_a.c").read_text(encoding="utf-8")
        assert "// FUNCTION: SERVER 0x10001000" in content

    def test_va_extracts_last_block_deletes_source(self, tmp_path: Path, monkeypatch: Any) -> None:
        """Extracting the only remaining block should delete the source file."""
        content = (
            "#include <stdio.h>\n"
            "\n"
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
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )

        result = runner.invoke(app, ["--va", "0x10001000", str(src)])
        assert result.exit_code == 0
        assert (tmp_path / "single_c" / "only.c").exists()
        assert not src.exists()  # source deleted when no blocks remain

    def test_va_json_output(self, tmp_path: Path, monkeypatch: Any) -> None:
        """--va --json should produce correct structured output."""
        src = _write(tmp_path / "multi.c", _multi_two())
        payloads: list[dict[str, Any]] = []
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )
        monkeypatch.setattr("rebrew.split.json_print", lambda data: payloads.append(data))

        result = runner.invoke(app, ["--json", "--va", "0x10001000", str(src)])
        assert result.exit_code == 0
        assert len(payloads) == 1
        payload = payloads[0]
        assert payload["count"] == 1
        assert len(payload["files"]) == 1
        assert payload["files"][0]["va"] == "0x10001000"
        # output_dir should be the va_out_dir, not the parent
        assert "multi_c" in payload["output_dir"]

    def test_va_with_output_dir_override(self, tmp_path: Path, monkeypatch: Any) -> None:
        """--va with --output-dir should use the override directory."""
        src = _write(tmp_path / "multi.c", _multi_two())
        custom_dir = tmp_path / "custom_out"
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )

        result = runner.invoke(
            app, ["--va", "0x10001000", "--output-dir", str(custom_dir), str(src)]
        )
        assert result.exit_code == 0
        assert (custom_dir / "func_a.c").exists()
        assert not (tmp_path / "multi_c").exists()  # default dir not created

    def test_va_adjusts_relative_includes(self, tmp_path: Path, monkeypatch: Any) -> None:
        """--va should rewrite relative #include paths when extracting to a subdirectory."""
        content = (
            '#include "../command_internal.h"\n'
            '#include "../../Units/Error/error.h"\n'
            "#include <stdio.h>\n"
            "\n"
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: EXACT\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 1\n"
            "// CFLAGS: /O2\n"
            "\n"
            "int func_a(void) { return 0; }\n"
            "\n"
            "// FUNCTION: SERVER 0x10002000\n"
            "// STATUS: MATCHING\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 1\n"
            "// CFLAGS: /O2\n"
            "\n"
            "int func_b(void) { return 1; }\n"
        )
        src = _write(tmp_path / "multi.c", content)
        monkeypatch.setattr(
            "rebrew.split.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )

        result = runner.invoke(app, ["--va", "0x10001000", str(src)])
        assert result.exit_code == 0
        extracted = (tmp_path / "multi_c" / "func_a.c").read_text(encoding="utf-8")
        # Relative includes should have ../ prepended
        assert '#include "../../command_internal.h"' in extracted
        assert '#include "../../../Units/Error/error.h"' in extracted
        # System includes unchanged
        assert "#include <stdio.h>" in extracted


class TestAdjustRelativeIncludes:
    """Unit tests for the _adjust_relative_includes helper."""

    def test_adjusts_relative_quoted_includes(self) -> None:
        from rebrew.split import _adjust_relative_includes

        text = '#include "../header.h"\n#include "sub/foo.h"\n'
        result = _adjust_relative_includes(text)
        assert '#include "../../header.h"' in result
        assert '#include "../sub/foo.h"' in result

    def test_leaves_system_includes_unchanged(self) -> None:
        from rebrew.split import _adjust_relative_includes

        text = "#include <stdio.h>\n#include <windows.h>\n"
        result = _adjust_relative_includes(text)
        assert result == text

    def test_leaves_absolute_paths_unchanged(self) -> None:
        from rebrew.split import _adjust_relative_includes

        text = '#include "/usr/include/foo.h"\n#include "C:\\SDK\\bar.h"\n'
        result = _adjust_relative_includes(text)
        assert result == text

    def test_handles_empty_preamble(self) -> None:
        from rebrew.split import _adjust_relative_includes

        assert _adjust_relative_includes("") == ""
