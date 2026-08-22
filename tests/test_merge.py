"""Tests for the rebrew merge command."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from rebrew.merge import app

runner = CliRunner()


def _make_cfg(tmp_path: Path, marker: str = "SERVER") -> Any:
    return SimpleNamespace(
        marker=marker, source_ext=".c", reversed_dir=tmp_path, metadata_dir=tmp_path.parent
    )


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _single(
    va: int,
    symbol: str,
    *,
    preamble: str = "",
    status: str = "EXACT",
    origin: str = "GAME",
    size: int = 10,
    cflags: str = "/O2",
    extra: str = "",
    module: str = "SERVER",
) -> str:
    name = symbol.lstrip("_")
    return (
        f"{preamble}"
        f"// FUNCTION: {module} 0x{va:08x}\n"
        f"// STATUS: {status}\n"
        f"// ORIGIN: {origin}\n"
        f"// SIZE: {size}\n"
        f"// CFLAGS: {cflags}\n"
        f"// SYMBOL: {symbol}\n"
        f"{extra}"
        "\n"
        f"int {name}(void) {{ return {va & 1}; }}\n"
    )


def _invoke(tmp_path: Path, monkeypatch: Any, *args: str) -> tuple[Any, Path]:
    """Run the merge CLI, returning (result, output path)."""
    out = tmp_path / "merged.c"
    monkeypatch.setattr(
        "rebrew.merge.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
    )
    result = runner.invoke(app, ["--output", str(out), *args])
    return result, out


class TestMergeBasic:
    def test_merges_two_files(self, tmp_path: Path, monkeypatch: Any) -> None:
        a = _write(tmp_path / "a.c", _single(0x10001000, "_func_a"))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_func_b"))

        result, out = _invoke(tmp_path, monkeypatch, str(a), str(b))
        assert result.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert "_func_a" in text
        assert "_func_b" in text

    def test_duplicate_va_across_inputs_errors(self, tmp_path: Path, monkeypatch: Any) -> None:
        """Merging files that both annotate the same VA would create duplicate
        FUNCTION markers (lint E013) — reject before writing."""
        a = _write(tmp_path / "a.c", _single(0x10001000, "_func_a"))
        b = _write(tmp_path / "b.c", _single(0x10001000, "_func_b"))  # same VA

        result, out = _invoke(tmp_path, monkeypatch, str(a), str(b))
        assert result.exit_code != 0
        assert "Duplicate VA" in result.output
        assert not out.exists()

    def test_deduplicates_include_lines(self, tmp_path: Path, monkeypatch: Any) -> None:
        include = "#include <stdio.h>\n"
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a", preamble=include))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b", preamble=include))

        result, out = _invoke(tmp_path, monkeypatch, str(a), str(b))
        assert result.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert text.count("#include <stdio.h>") == 1

    def test_deduplicates_extern_declarations(self, tmp_path: Path, monkeypatch: Any) -> None:
        ext = "extern int g_value;\n"
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a", preamble=ext))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b", preamble=ext))

        result, out = _invoke(tmp_path, monkeypatch, str(a), str(b))
        assert result.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert text.count("extern int g_value;") == 1

    def test_sorts_function_blocks_by_va(self, tmp_path: Path, monkeypatch: Any) -> None:
        high = _write(tmp_path / "high.c", _single(0x10003000, "_high"))
        low = _write(tmp_path / "low.c", _single(0x10001000, "_low"))

        result, out = _invoke(tmp_path, monkeypatch, str(high), str(low))
        assert result.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert text.find("0x10001000") < text.find("0x10003000")

    def test_consolidate_hoists_declarations(self, tmp_path: Path, monkeypatch: Any) -> None:
        """--consolidate hoists per-block includes/externs/typedefs to the top."""
        block_extra = "#include <stdio.h>\nextern int helper(void);\ntypedef int HANDLE;\n"
        a = _write(
            tmp_path / "a.c",
            _single(0x10001000, "_a", extra=block_extra),
        )
        b = _write(
            tmp_path / "b.c",
            _single(0x10002000, "_b", extra="#include <stdio.h>\nextern int helper(char*);\n"),
        )

        result, out = _invoke(tmp_path, monkeypatch, "--consolidate", str(a), str(b))
        assert result.exit_code == 0, result.output
        text = out.read_text(encoding="utf-8")
        # hoisted once, above the first function marker
        assert text.index("#include <stdio.h>") < text.index("// FUNCTION: SERVER 0x10001000")
        assert text.count("#include <stdio.h>") == 1
        assert text.count("extern int helper") == 1
        assert "typedef int HANDLE;" in text
        # and the bodies keep their markers
        assert text.count("// FUNCTION: SERVER") == 2

    def test_consolidate_merges_intrinsics(self, tmp_path: Path, monkeypatch: Any) -> None:
        a = _write(
            tmp_path / "a.c",
            _single(0x10001000, "_a", extra="#pragma intrinsic(memcpy)\n"),
        )
        b = _write(
            tmp_path / "b.c",
            _single(0x10002000, "_b", extra="#pragma intrinsic(memset)\n"),
        )
        result, out = _invoke(tmp_path, monkeypatch, "--consolidate", str(a), str(b))
        assert result.exit_code == 0, result.output
        text = out.read_text(encoding="utf-8")
        assert "#pragma intrinsic(memcpy, memset)" in text
        assert text.count("#pragma intrinsic") == 1

    def test_dry_run_does_not_create_output(self, tmp_path: Path, monkeypatch: Any) -> None:
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a"))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b"))

        result, out = _invoke(tmp_path, monkeypatch, "--dry-run", str(a), str(b))
        assert result.exit_code == 0
        assert not out.exists()

    def test_errors_with_fewer_than_two_files(self, tmp_path: Path, monkeypatch: Any) -> None:
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a"))

        result, out = _invoke(tmp_path, monkeypatch, str(a))
        assert result.exit_code != 0
        assert "at least two source files" in result.output

    def test_errors_when_output_exists_without_force(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a"))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b"))
        _write(tmp_path / "merged.c", "stale\n")

        result, out = _invoke(tmp_path, monkeypatch, str(a), str(b))
        assert result.exit_code != 0
        assert "Output file already exists" in result.output

    def test_delete_removes_inputs_after_success(self, tmp_path: Path, monkeypatch: Any) -> None:
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a"))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b"))

        result, out = _invoke(tmp_path, monkeypatch, "--delete", "--force", str(a), str(b))
        assert result.exit_code == 0
        assert out.exists()
        assert not a.exists()
        assert not b.exists()

    def test_json_output_structure(self, tmp_path: Path, monkeypatch: Any) -> None:
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a"))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b"))
        payloads: list[dict[str, Any]] = []
        monkeypatch.setattr("rebrew.merge.json_print", lambda data: payloads.append(data))

        result, out = _invoke(tmp_path, monkeypatch, "--json", str(a), str(b))
        assert result.exit_code == 0
        assert len(payloads) == 1
        payload = payloads[0]
        assert payload["count"] == 2
        assert payload["input_count"] == 2
        assert "inputs" in payload
        assert "vas" in payload

    def test_delete_json_requires_force(self, tmp_path: Path, monkeypatch: Any) -> None:
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a"))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b"))

        result, out = _invoke(tmp_path, monkeypatch, "--delete", "--json", str(a), str(b))
        assert result.exit_code != 0
        assert "Pass --force" in result.output
        assert a.exists()
        assert b.exists()
        assert not out.exists()

    def test_preserves_all_annotation_keys(self, tmp_path: Path, monkeypatch: Any) -> None:
        extra = (
            "// BLOCKER: manual\n"
            "// BLOCKER_DELTA: 5\n"
            "// SOURCE: CRT.C:10\n"
            "// NOTE: note text\n"
            "// GHIDRA: yes\n"
            "// STRUCT: Foo\n"
            "// CALLERS: _caller\n"
            "// GLOBALS: g1, g2\n"
        )
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a", extra=extra, status="NEAR_MATCHING"))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b", status="EXACT"))

        result, out = _invoke(tmp_path, monkeypatch, str(a), str(b))
        assert result.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert "// STATUS: NEAR_MATCHING" in text
        assert "// ORIGIN: GAME" in text
        assert "// SIZE: 10" in text
        assert "// CFLAGS: /O2" in text
        assert "// SYMBOL: _a" in text
        assert "// BLOCKER: manual" in text
        assert "// BLOCKER_DELTA: 5" in text
        assert "// SOURCE: CRT.C:10" in text
        assert "// NOTE: note text" in text
        assert "// GHIDRA: yes" in text
        assert "// STRUCT: Foo" in text
        assert "// CALLERS: _caller" in text
        assert "// GLOBALS: g1, g2" in text


class TestMergeHelpers:
    def test_block_metadata_extracts_marker(self) -> None:
        from rebrew.merge import _block_metadata

        meta = _block_metadata("// FUNCTION: SERVER 0x10001000\nint f(void) {}\n")
        assert meta == {"module": "SERVER", "va": 0x10001000}

    def test_block_metadata_no_marker_returns_none(self) -> None:
        from rebrew.merge import _block_metadata

        assert _block_metadata("int f(void) {}\n") is None

    def test_merge_preambles_dedups_and_collapses_blanks(self) -> None:
        from rebrew.merge import _merge_preambles

        out = _merge_preambles(
            ["#include <a.h>\n\n#include <a.h>\n\nint x;\n", "#include <b.h>\n\n\n"]
        )
        assert out.count("#include <a.h>") == 1
        assert out.count("#include <b.h>") == 1
        # No double blank lines inside; trailing blanks stripped.
        assert "\n\n\n" not in out
        assert not out.endswith("\n\n\n")

    def test_merge_preambles_empty(self) -> None:
        from rebrew.merge import _merge_preambles

        assert _merge_preambles(["", ""]) == ""

    def test_collect_input_files_filters_extension(self, tmp_path: Path) -> None:
        from rebrew.merge import _collect_input_files

        a = _write(tmp_path / "a.c", "")
        _write(tmp_path / "b.h", "")
        files = _collect_input_files([str(a), str(tmp_path / "b.h")], _make_cfg(tmp_path))
        assert files == [a]  # .h filtered out, .c kept, deduped


class TestMergeErrors:
    def test_no_sources_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import typer

        from rebrew.merge import main

        monkeypatch.setattr(
            "rebrew.merge.require_config",
            lambda target=None, json_mode=False: _make_cfg(Path("/tmp")),
        )
        with pytest.raises(typer.Exit):
            main(sources=[], output="out.c")

    def test_fewer_than_two_valid_files_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import typer

        from rebrew.merge import main

        a = _write(tmp_path / "a.c", _single(0x1000, "_a"))
        monkeypatch.setattr(
            "rebrew.merge.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )
        with pytest.raises(typer.Exit):
            main(sources=[str(a)], output=str(tmp_path / "out.c"))

    def test_non_matching_module_blocks_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import typer

        from rebrew.merge import main

        # Both files use module GAME but cfg.marker is SERVER → no matching blocks.
        a = _write(tmp_path / "a.c", _single(0x1000, "_a", module="GAME"))
        b = _write(tmp_path / "b.c", _single(0x2000, "_b", module="GAME"))
        monkeypatch.setattr(
            "rebrew.merge.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )
        with pytest.raises(typer.Exit):
            main(sources=[str(a), str(b)], output=str(tmp_path / "out.c"))


class TestMergeInputScanning:
    def test_directory_input_scanned(self, tmp_path: Path, monkeypatch: Any) -> None:
        sub = tmp_path / "src" / "SERVER"
        sub.mkdir(parents=True)
        _write(sub / "a.c", _single(0x1000, "_fn_a"))
        _write(sub / "b.c", _single(0x2000, "_fn_b"))
        result, out = _invoke(tmp_path, monkeypatch, str(sub))
        assert result.exit_code == 0
        assert out.exists()
        text = out.read_text(encoding="utf-8")
        assert "fn_a" in text and "fn_b" in text

    def test_missing_file_skipped(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "a.c", _single(0x1000, "_fn_a"))
        _write(tmp_path / "b.c", _single(0x2000, "_fn_b"))
        result, out = _invoke(
            tmp_path,
            monkeypatch,
            str(tmp_path / "nope.c"),
            str(tmp_path / "a.c"),
            str(tmp_path / "b.c"),
        )
        assert result.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert "fn_a" in text and "fn_b" in text

    def test_wrong_extension_skipped(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "a.txt", _single(0x1000, "_fn_a"))
        _write(tmp_path / "a.c", _single(0x1000, "_fn_a"))
        _write(tmp_path / "b.c", _single(0x2000, "_fn_b"))
        result, out = _invoke(
            tmp_path,
            monkeypatch,
            str(tmp_path / "a.txt"),
            str(tmp_path / "a.c"),
            str(tmp_path / "b.c"),
        )
        assert result.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert "fn_a" in text and "fn_b" in text

    def test_duplicate_input_deduplicated(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "a.c", _single(0x1000, "_fn_a"))
        _write(tmp_path / "b.c", _single(0x2000, "_fn_b"))
        result, out = _invoke(
            tmp_path,
            monkeypatch,
            str(tmp_path / "a.c"),
            str(tmp_path / "a.c"),
            str(tmp_path / "b.c"),
        )
        assert result.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert text.count("fn_a") == 2  # once in the marker, once in the body

    def test_delete_skips_output_itself(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "a.c", _single(0x1000, "_fn_a"))
        _write(tmp_path / "b.c", _single(0x2000, "_fn_b"))
        out = tmp_path / "merged.c"
        monkeypatch.setattr(
            "rebrew.merge.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )
        result = runner.invoke(
            app,
            [
                "--output",
                str(out),
                "--delete",
                "--force",
                str(tmp_path / "a.c"),
                str(tmp_path / "b.c"),
            ],
        )
        assert result.exit_code == 0
        assert not (tmp_path / "a.c").exists()
        assert not (tmp_path / "b.c").exists()
        assert out.exists()


class TestMergeCommentPreamble:
    def test_strips_decomp_comment_blocks_from_preamble(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """Ghidra decompilation-reference blocks must not pollute the merge
        preamble (naive union breaks the /* */ nesting → C2143 on compile)."""
        decomp = "/* Ghidra decompilation reference:\n * Symbol: _a\n */\n#include <stdio.h>\n"
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a", preamble=decomp))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b", preamble=decomp))
        _invoke(tmp_path, monkeypatch, str(a), str(b))
        out = tmp_path / "merged.c"
        text = out.read_text(encoding="utf-8")
        assert "#include <stdio.h>" in text
        assert "Ghidra decompilation reference" not in text
        assert "Symbol: _a" not in text
        # Both markers survive.
        assert "0x10001000" in text and "0x10002000" in text
