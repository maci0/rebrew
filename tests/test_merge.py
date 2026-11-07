"""Tests for the rebrew source merge command."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from source_util import SourceFixture, write_source
from typer.testing import CliRunner

from rebrew.merge import app

runner = CliRunner()


def _make_cfg(tmp_path: Path, module: str = "SERVER") -> Any:
    return SimpleNamespace(
        module=module, source_ext=".c", reversed_dir=tmp_path, metadata_dir=tmp_path
    )


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_source(path, content, encoding="utf-8")
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
) -> SourceFixture:
    name = symbol.lstrip("_")
    return SourceFixture(
        preamble
        + extra
        + f"/* ADDRESS: {module} 0x{va:08x} */\n"
        + f"int {name}(void) {{ return {va & 1}; }}\n",
        {
            f"{module}.0x{va:08x}": {
                "kind": "FUNCTION",
                "status": status,
                "size": size,
                "cflags": cflags,
                "symbol": symbol,
            }
        },
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

        result, out = _invoke(tmp_path, monkeypatch, "--force", str(a), str(b))
        assert result.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert "func_a" in text
        assert "func_b" in text

    def test_stacked_block_keeps_body_when_target_module_is_not_first(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """A shared body stacks GOLD above SERVER; the SERVER merge must keep it."""
        stacked = SourceFixture(
            "/* ADDRESS: GOLD 0x00421ed0 */\n/* ADDRESS: SERVER 0x10003140 */\n\nint stacked_body(void) { return 7; }\n",
            {"GOLD.0x00421ed0": {"kind": "FUNCTION"}, "SERVER.0x10003140": {"kind": "FUNCTION"}},
        )
        a = _write(tmp_path / "a.c", stacked)
        b = _write(tmp_path / "b.c", _single(0x10004000, "_func_b"))

        result, out = _invoke(tmp_path, monkeypatch, "--force", str(a), str(b))
        assert result.exit_code == 0, result.output
        text = out.read_text(encoding="utf-8")
        assert "int stacked_body(void) { return 7; }" in text
        assert (
            SourceFixture(
                "/* ADDRESS: SERVER 0x10003140 */", {"SERVER.0x10003140": {"kind": "FUNCTION"}}
            )
            in text
        )
        assert (
            SourceFixture(
                "/* ADDRESS: GOLD 0x00421ed0 */", {"GOLD.0x00421ed0": {"kind": "FUNCTION"}}
            )
            in text
        )

    def test_duplicate_va_across_inputs_errors(self, tmp_path: Path, monkeypatch: Any) -> None:
        """Merging files that both annotate the same VA would create duplicate
        FUNCTION markers (lint E013) — reject before writing."""
        a = _write(tmp_path / "a.c", _single(0x10001000, "_func_a"))
        b = _write(tmp_path / "b.c", _single(0x10001000, "_func_b"))  # same VA

        result, out = _invoke(tmp_path, monkeypatch, "--force", str(a), str(b))
        assert result.exit_code != 0
        assert "Nothing was written" in result.output
        assert not out.exists()

    def test_deduplicates_include_lines(self, tmp_path: Path, monkeypatch: Any) -> None:
        include = "#include <stdio.h>\n"
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a", preamble=include))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b", preamble=include))

        result, out = _invoke(tmp_path, monkeypatch, "--force", str(a), str(b))
        assert result.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert text.count("#include <stdio.h>") == 1

    def test_deduplicates_extern_declarations(self, tmp_path: Path, monkeypatch: Any) -> None:
        ext = "extern int g_value;\n"
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a", preamble=ext))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b", preamble=ext))

        result, out = _invoke(tmp_path, monkeypatch, "--force", str(a), str(b))
        assert result.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert text.count("extern int g_value;") == 1

    def test_sorts_function_blocks_by_va(self, tmp_path: Path, monkeypatch: Any) -> None:
        high = _write(tmp_path / "high.c", _single(0x10003000, "_high"))
        low = _write(tmp_path / "low.c", _single(0x10001000, "_low"))

        result, out = _invoke(tmp_path, monkeypatch, "--force", str(high), str(low))
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

        result, out = _invoke(tmp_path, monkeypatch, "--force", "--consolidate", str(a), str(b))
        assert result.exit_code == 0, result.output
        text = out.read_text(encoding="utf-8")
        # hoisted once, above the first function marker
        assert text.index("#include <stdio.h>") < text.index(
            SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */", {"SERVER.0x10001000": {"kind": "FUNCTION"}}
            )
        )
        assert text.count("#include <stdio.h>") == 1
        assert text.count("extern int helper") == 1
        assert "typedef int HANDLE;" in text
        # and the bodies keep their markers
        assert text.count("ADDRESS: SERVER") == 2
        # conflicting externs are warned on stderr with the kept spelling
        assert "conflicting externs for helper" in result.output

    def test_consolidate_merges_intrinsics(self, tmp_path: Path, monkeypatch: Any) -> None:
        a = _write(
            tmp_path / "a.c",
            _single(0x10001000, "_a", extra="#pragma intrinsic(memcpy)\n"),
        )
        b = _write(
            tmp_path / "b.c",
            _single(0x10002000, "_b", extra="#pragma intrinsic(memset)\n"),
        )
        result, out = _invoke(tmp_path, monkeypatch, "--force", "--consolidate", str(a), str(b))
        assert result.exit_code == 0, result.output
        text = out.read_text(encoding="utf-8")
        assert "#pragma intrinsic(memcpy, memset)" in text
        assert text.count("#pragma intrinsic") == 1

    def test_consolidate_json_carries_extern_evidence(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """Conflicting/dropped externs surface in the --json payload."""
        from rebrew.merge import ExternReport, consolidate_declarations

        merged, report = consolidate_declarations(
            "extern int helper(void);\nextern int helper(char*);\nint f(void) { return 0; }\n"
        )
        assert isinstance(report, ExternReport)
        assert "helper" in report.conflicts
        assert len(report.conflicts["helper"]) == 2
        assert report.resolved and "helper" in report.resolved[0]
        assert report.dropped == []
        assert merged.count("extern int helper") == 1
        a = _write(
            tmp_path / "a.c",
            _single(0x10001000, "_a", extra="extern int helper(void);\n"),
        )
        b = _write(
            tmp_path / "b.c",
            _single(0x10002000, "_b", extra="extern int helper(char*);\n"),
        )
        payloads: list[dict[str, Any]] = []
        monkeypatch.setattr("rebrew.merge.json_print", lambda data: payloads.append(data))
        result, _out = _invoke(
            tmp_path, monkeypatch, "--force", "--consolidate", "--json", str(a), str(b)
        )
        assert result.exit_code == 0
        assert "helper" in payloads[0]["extern_conflicts"]

    def test_extern_conflict_across_inputs_dry_run_and_apply_refuses(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        a = _write(
            tmp_path / "a.c",
            _single(0x10001000, "_a", preamble="extern int fcn_005356e0(void);\n"),
        )
        b = _write(
            tmp_path / "b.c",
            _single(0x10002000, "_b", preamble="void fcn_005356e0(void);\n"),
        )
        payloads: list[dict[str, Any]] = []
        monkeypatch.setattr("rebrew.merge.json_print", lambda data: payloads.append(data))
        dry, out = _invoke(tmp_path, monkeypatch, "--dry-run", "--json", str(a), str(b))
        assert dry.exit_code == 0, dry.output
        assert len(payloads) == 1
        conflicts = payloads[0]["extern_conflicts"]
        assert "fcn_005356e0" in conflicts
        assert len(conflicts["fcn_005356e0"]) == 2
        assert not out.exists()

        apply, out = _invoke(tmp_path, monkeypatch, "--force", str(a), str(b))
        assert apply.exit_code != 0
        assert "Nothing was written" in apply.output
        assert not out.exists()

    def test_identical_extern_across_inputs_stays_clean(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        decl = "extern int fcn_005356e0(void);\n"
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a", preamble=decl))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b", preamble=decl))
        payloads: list[dict[str, Any]] = []
        monkeypatch.setattr("rebrew.merge.json_print", lambda data: payloads.append(data))
        result, out = _invoke(tmp_path, monkeypatch, "--force", "--json", str(a), str(b))
        assert result.exit_code == 0, result.output
        assert payloads[0]["extern_conflicts"] == {}
        assert out.read_text(encoding="utf-8").count("extern int fcn_005356e0") == 1

    def test_consolidate_keeps_a_multiline_extern_whole(self) -> None:
        """A parameter list split across lines must not glue onto the next extern."""
        from rebrew.merge import consolidate_declarations

        merged, report = consolidate_declarations(
            "extern int read(void* out, int size,\n"
            "                 int count);\n"
            "extern int helper(void);\n"
            "int f(void) { return 0; }\n"
        )
        assert report.dropped == []
        assert "extern int read(void* out, int size, int count);\n" in merged
        assert "extern int helper(void);\n" in merged
        assert merged.index("read") < merged.index("helper")
        assert ";extern" not in merged

        merged, report = consolidate_declarations(
            "extern const float g_const_0_0;\n"
            "#ifdef __clang__\n"
            "#pragma clang diagnostic pop\n"
            "#endif\n"
            "extern void* __cdecl gm_Search(int);\n"
            "int f(void) { return 0; }\n"
        )
        assert report.dropped == []
        assert "#ifdef __clang__\n" in merged
        assert "; #ifdef" not in merged
        assert ";#ifdef" not in merged

    def test_consolidate_names_cdecl_and_const_pointer_externs(self) -> None:
        """A qualifier or calling convention is not the symbol name."""
        from rebrew.merge import consolidate_declarations

        merged, report = consolidate_declarations(
            "extern int (* const rows[2])[4];\n"
            "extern char (* const buf[3])[4];\n"
            "int f(void) { return 0; }\n"
        )
        assert "(* const rows" in merged
        assert "(* const buf" in merged
        assert "const" not in report.conflicts
        assert report.dropped == []

        merged, report = consolidate_declarations(
            "extern char (__cdecl *row)[4];\n"
            "extern char (__cdecl *row)[8];\n"
            "int f(void) { return 0; }\n"
        )
        assert "row" in report.conflicts
        assert report.dropped == []

        merged, report = consolidate_declarations(
            "extern void (__cdecl *cb)(int);\n"
            "extern void (__cdecl *cb)(char *);\n"
            "int f(void) { return 0; }\n"
        )
        assert "cb" in report.conflicts
        assert report.dropped == []

    def test_dry_run_does_not_create_output(self, tmp_path: Path, monkeypatch: Any) -> None:
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a"))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b"))

        result, out = _invoke(tmp_path, monkeypatch, "--dry-run", str(a), str(b))
        assert result.exit_code == 0
        assert not out.exists()

    def test_errors_with_fewer_than_two_files(self, tmp_path: Path, monkeypatch: Any) -> None:
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a"))

        result, out = _invoke(tmp_path, monkeypatch, "--force", str(a))
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

        result, out = _invoke(tmp_path, monkeypatch, "--force", "--json", str(a), str(b))
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
        from rebrew.metadata.functions import get_entry, set_fields

        a = _write(tmp_path / "a.c", _single(0x10001000, "_a", status="NEAR_MATCHING"))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b", status="EXACT"))
        fields = {
            "blocker": "manual",
            "blocker_delta": 5,
            "source": "CRT.C:10",
            "note": "note text",
            "ghidra": "yes",
            "struct": "Foo",
            "callers": "_caller",
            "globals": ["g1", "g2"],
        }
        set_fields(tmp_path, 0x10001000, fields, module="SERVER")
        result, out = _invoke(tmp_path, monkeypatch, "--force", str(a), str(b))
        assert result.exit_code == 0, result.output
        row = get_entry(tmp_path, 0x10001000, "SERVER")
        assert all(row[key] == value for key, value in fields.items())
        assert row["status"] == "NEAR_MATCHING"
        assert row["file"] == "merged.c"
        assert "STATUS:" not in out.read_text()

    def test_block_metadata_extracts_marker(self) -> None:
        from rebrew.merge import block_metadata

        meta = block_metadata(
            SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\nint f(void) {}\n",
                {"SERVER.0x10001000": {"kind": "FUNCTION"}},
            )
        )
        assert meta == {"module": "SERVER", "va": 0x10001000}

    def test_block_metadata_no_marker_returns_none(self) -> None:
        from rebrew.merge import block_metadata

        assert block_metadata("int f(void) {}\n") is None

    def test_merge_preambles_dedups_and_collapses_blanks(self) -> None:
        from rebrew.merge import merge_preambles

        out = merge_preambles(
            ["#include <a.h>\n\n#include <a.h>\n\nint x;\n", "#include <b.h>\n\n\n"]
        )
        assert out.count("#include <a.h>") == 1
        assert out.count("#include <b.h>") == 1
        # No double blank lines inside; trailing blanks stripped.
        assert "\n\n\n" not in out
        assert not out.endswith("\n\n\n")

    def test_merge_preambles_empty(self) -> None:
        from rebrew.merge import merge_preambles

        assert merge_preambles(["", ""]) == ""

    def test_merge_preambles_keeps_distinct_multiline_typedefs(self) -> None:
        from rebrew.merge import merge_preambles

        first = "typedef struct {\n    int x;\n} First;\n"
        second = "typedef struct {\n    int y;\n} Second;\n"
        for preambles in ([first + second], [first, second]):
            out = merge_preambles(preambles)
            assert first in out
            assert second in out
        out = merge_preambles(
            ["typedef struct { int x;\n} First;\n", "typedef struct { int x;\n} Second;\n"]
        )
        assert out.count("typedef struct { int x;") == 2

    def test_collect_input_files_filters_extension(self, tmp_path: Path) -> None:
        from rebrew.merge import _collect_input_files

        a = _write(tmp_path / "a.c", "")
        _write(tmp_path / "b.h", "")
        files = _collect_input_files([str(a), str(tmp_path / "b.h")], _make_cfg(tmp_path))
        assert files == [a]  # .h filtered out, .c kept, deduped

    def test_collect_input_files_keeps_an_explicit_output(self, tmp_path: Path) -> None:
        """Merging fragments into an existing file names that file as input and output."""
        from rebrew.merge import _collect_input_files

        a = _write(tmp_path / "a.c", "")
        b = _write(tmp_path / "b.c", "")
        files = _collect_input_files([str(a), str(b)], _make_cfg(tmp_path), exclude=a)
        assert files == [a, b]

    def test_collect_input_files_skips_the_output_found_in_a_directory(
        self, tmp_path: Path
    ) -> None:
        from rebrew.merge import _collect_input_files

        a = _write(tmp_path / "a.c", "")
        b = _write(tmp_path / "b.c", "")
        files = _collect_input_files([str(tmp_path)], _make_cfg(tmp_path), exclude=a)
        assert files == [b]

    def test_resolve_externs_reports_dropped_and_conflicts(self) -> None:
        from rebrew.merge import _resolve_externs

        report = _resolve_externs(
            ["", "extern int x;", "extern int y(void);", "extern int y(char*);"]
        )
        assert report.dropped == [""]
        assert report.resolved.count("extern int x;") == 1
        assert report.conflicts["y"] == ["extern int y(void);", "extern int y(char*);"]
        assert len([d for d in report.resolved if " y(" in d]) == 1


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

        # Both files use module GAME but cfg.module is SERVER → no matching blocks.
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
        result, out = _invoke(tmp_path, monkeypatch, "--force", str(sub))
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
            "--force",
            str(tmp_path / "nope.c"),
            str(tmp_path / "a.c"),
            str(tmp_path / "b.c"),
        )
        assert result.exit_code == 0
        text = out.read_text(encoding="utf-8")
        # Each source contributes its SYMBOL header and its definition, so a
        # skipped input would show up as a doubled name, not just a present
        # one.
        assert text.count("fn_a") == 1
        assert text.count("fn_b") == 1

    def test_wrong_extension_skipped(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "a.txt", _single(0x1000, "_fn_a"))
        _write(tmp_path / "a.c", _single(0x1000, "_fn_a"))
        _write(tmp_path / "b.c", _single(0x2000, "_fn_b"))
        result, out = _invoke(
            tmp_path,
            monkeypatch,
            "--force",
            str(tmp_path / "a.txt"),
            str(tmp_path / "a.c"),
            str(tmp_path / "b.c"),
        )
        assert result.exit_code == 0
        text = out.read_text(encoding="utf-8")
        # a.txt and a.c both define fn_a; only the .c one is read, so the
        # name appears once. Merging both would double it.
        assert text.count("fn_a") == 1
        assert text.count("fn_b") == 1

    def test_duplicate_input_deduplicated(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "a.c", _single(0x1000, "_fn_a"))
        _write(tmp_path / "b.c", _single(0x2000, "_fn_b"))
        result, out = _invoke(
            tmp_path,
            monkeypatch,
            "--force",
            str(tmp_path / "a.c"),
            str(tmp_path / "a.c"),
            str(tmp_path / "b.c"),
        )
        assert result.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert text.count("fn_a") == 1  # once in the marker, once in the body

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

    def test_force_rerun_with_output_inside_input_dir(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """The previous merge output must not be collected as an input: a
        --force re-run used to abort with a duplicate-VA error."""
        sub = tmp_path / "src" / "SERVER"
        sub.mkdir(parents=True)
        _write(sub / "a.c", _single(0x1000, "_fn_a"))
        _write(sub / "b.c", _single(0x2000, "_fn_b"))
        out = sub / "all.c"
        monkeypatch.setattr(
            "rebrew.merge.require_config", lambda target=None, json_mode=False: _make_cfg(tmp_path)
        )
        first = runner.invoke(app, ["--output", str(out), "--force", str(sub)])
        assert first.exit_code == 0, first.output
        inputs = {path: path.read_bytes() for path in (sub / "a.c", sub / "b.c")}
        original_output = out.read_bytes()
        second = runner.invoke(app, ["--output", str(out), "--force", str(sub)])
        assert second.exit_code == 0, second.output
        assert out.read_bytes() == original_output
        assert {path: path.read_bytes() for path in inputs} == inputs

    def test_force_rerun_rejects_binding_moved_to_another_output(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        from rebrew.metadata.functions import record_function_rows

        a = _write(tmp_path / "a.c", _single(0x1000, "_a"))
        b = _write(tmp_path / "b.c", _single(0x2000, "_b"))
        first, out = _invoke(tmp_path, monkeypatch, "--force", str(a), str(b))
        assert first.exit_code == 0, first.output
        record_function_rows(
            tmp_path, [{"module": "SERVER", "va": 0x1000, "identity": {"file": "other.c"}}]
        )
        original_output = out.read_bytes()
        metadata = (tmp_path / "rebrew-functions.toml").read_bytes()
        second, _ = _invoke(tmp_path, monkeypatch, "--force", str(a), str(b))
        assert second.exit_code != 0
        assert "address anchor conflicts" in second.output
        assert "Nothing was written" in second.output
        assert out.read_bytes() == original_output
        assert (tmp_path / "rebrew-functions.toml").read_bytes() == metadata

    def test_foreign_file_preserves_encoding_in_merged_output(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        a = _write(
            tmp_path / "a.c", _single(0x1000, "_fn_a", module="CLIENT", preamble="// café\n")
        )
        a.write_bytes(a.read_text().encode("cp1252"))
        _write(tmp_path / "b.c", _single(0x2000, "_fn_b"))
        _write(tmp_path / "c.c", _single(0x3000, "_fn_c"))
        result, out = _invoke(
            tmp_path, monkeypatch, "--force", str(a), str(tmp_path / "b.c"), str(tmp_path / "c.c")
        )
        assert result.exit_code == 0, result.output
        text = out.read_bytes().decode("cp1252")
        assert "café" in text and "fn_a" in text and "fn_b" in text


class TestMergeCommentPreamble:
    def test_strips_decomp_comment_blocks_from_preamble(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """Ghidra decompilation-reference blocks must not pollute the merge
        preamble (naive union breaks the /* */ nesting → C2143 on compile)."""
        decomp = "/* Ghidra decompilation reference:\n * Symbol: _a\n */\n#include <stdio.h>\n"
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a", preamble=decomp))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b", preamble=decomp))
        _invoke(tmp_path, monkeypatch, "--force", str(a), str(b))
        out = tmp_path / "merged.c"
        text = out.read_text(encoding="utf-8")
        assert "#include <stdio.h>" in text
        assert "Ghidra decompilation reference" not in text
        assert "Symbol: _a" not in text
        # Both markers survive.
        assert "0x10001000" in text and "0x10002000" in text


class TestMergeEncodings:
    def test_conflicting_legacy_encodings_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two legacy inputs in different encodings cannot both round-trip into
        the single output encoding; merge must say so instead of dropping one."""
        a = tmp_path / "a.c"
        b = tmp_path / "b.c"
        # 0xA9 alone decodes as shift_jis; 0x81 + a space forces the cp1252 path.
        a.write_bytes(b"// \xa9 note\n/* ADDRESS: SERVER 0x1000 */\nint a(void){return 0;}\n")
        b.write_bytes(b"// \x81 note\n/* ADDRESS: SERVER 0x2000 */\nint b(void){return 0;}\n")
        _seed(tmp_path, [("SERVER", 0x1000, "_a")], file="a.c")
        _seed(tmp_path, [("SERVER", 0x2000, "_b")], file="b.c")
        result, _out = _invoke(tmp_path, monkeypatch, "--force", str(a), str(b))
        assert result.exit_code != 0
        assert "conflicting source encodings" in result.output


class TestMergeShared:
    """--shared collapses twin copies into one stacked block (ADR-022)."""

    def _twin(self, module: str, va: int, body: str, size_line: str = "") -> str:
        size = ""
        return SourceFixture(
            f"/* ADDRESS: {module} 0x{va:08x} */\n{size}{body}\n",
            {f"{module}.0x{va:08x}": {"kind": "FUNCTION", "size": 14 if size_line else 0}},
        )

    def test_identical_twins_stack(self, tmp_path: Path, monkeypatch: Any) -> None:
        body = "int __cdecl cm_MarkAndReturn(int cmd, char* result)\n{\n\treturn 0;\n}\n"
        _write(tmp_path / "a.c", self._twin("SERVER", 0x1000D330, body))
        _write(tmp_path / "b.c", self._twin("GOLDTL", 0x4C75E0, body, "size"))
        out = tmp_path / "shared.c"
        monkeypatch.setattr(
            "rebrew.merge.require_config",
            lambda target=None, json_mode=False: _make_cfg(tmp_path),
        )
        result = runner.invoke(
            app,
            [
                "--output",
                str(out),
                "--force",
                "--shared",
                str(tmp_path / "a.c"),
                str(tmp_path / "b.c"),
            ],
        )
        assert result.exit_code == 0, result.output
        text = out.read_text(encoding="utf-8")
        assert text.count("cm_MarkAndReturn") == 1
        assert (
            SourceFixture(
                "/* ADDRESS: SERVER 0x1000d330 */", {"SERVER.0x1000d330": {"kind": "FUNCTION"}}
            )
            in text
        )
        assert (
            SourceFixture(
                "/* ADDRESS: GOLDTL 0x004c75e0 */", {"GOLDTL.0x004c75e0": {"kind": "FUNCTION"}}
            )
            in text
        )

    def test_divergent_twins_refused(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(
            tmp_path / "c.c",
            self._twin(
                "SERVER", 0x1000D340, "int __cdecl cm_Other(int c)\n{\n\treturn c + 1;\n}\n"
            ),
        )
        _write(
            tmp_path / "d.c",
            self._twin("GOLDTL", 0x4C75F0, "int __cdecl cm_Other(int c)\n{\n\treturn c + 2;\n}\n"),
        )
        out = tmp_path / "out.c"
        monkeypatch.setattr(
            "rebrew.merge.require_config",
            lambda target=None, json_mode=False: _make_cfg(tmp_path),
        )
        result = runner.invoke(
            app,
            [
                "--output",
                str(out),
                "--force",
                "--shared",
                str(tmp_path / "c.c"),
                str(tmp_path / "d.c"),
            ],
        )
        assert result.exit_code != 0
        assert "cm_Other" in result.output
        assert not out.exists()

    def test_normalize_body_ignores_markers_and_size(self) -> None:
        from rebrew.merge import normalize_body

        a = SourceFixture(
            "/* ADDRESS: SERVER 0x1000 */\n\nint f(void){return 1;}\n",
            {"SERVER.0x1000": {"kind": "FUNCTION", "size": 11}},
        )
        b = SourceFixture(
            "/* ADDRESS: GOLDTL 0x2000 */\nint f(void){return 1;}\n",
            {"GOLDTL.0x2000": {"kind": "FUNCTION"}},
        )
        assert normalize_body(a) == normalize_body(b)


class TestMergeSameVaAcrossModules:
    """Same VA in different modules is NOT a duplicate (lint E013 keys
    (module, va) — DLLs at one base share VAs across targets)."""

    def test_same_va_other_module_stacks(self, tmp_path: Path, monkeypatch: Any) -> None:
        body = "int twin(void){return 1;}\n"
        _write(
            tmp_path / "a.c",
            SourceFixture(
                f"/* ADDRESS: V1 0x00401000 */\n\n{body}",
                {"V1.0x00401000": {"kind": "FUNCTION", "size": 11}},
            ),
        )
        _write(
            tmp_path / "b.c",
            SourceFixture(
                f"/* ADDRESS: V2 0x00401000 */\n\n{body}",
                {"V2.0x00401000": {"kind": "FUNCTION", "size": 11}},
            ),
        )
        out = tmp_path / "shared.c"
        monkeypatch.setattr(
            "rebrew.merge.require_config",
            lambda target=None, json_mode=False: _make_cfg(tmp_path),
        )
        result = runner.invoke(
            app,
            [
                "--output",
                str(out),
                "--force",
                "--shared",
                str(tmp_path / "a.c"),
                str(tmp_path / "b.c"),
            ],
        )
        assert result.exit_code == 0, result.output
        text = out.read_text(encoding="utf-8")
        assert (
            SourceFixture("/* ADDRESS: V1 0x00401000 */", {"V1.0x00401000": {"kind": "FUNCTION"}})
            in text
        )
        assert (
            SourceFixture("/* ADDRESS: V2 0x00401000 */", {"V2.0x00401000": {"kind": "FUNCTION"}})
            in text
        )
        assert text.count("int twin") == 1


class TestMergeDataFirst:
    """DATA/GLOBAL blocks sort before FUNCTION blocks (C89 decl-before-use)."""

    def test_data_blocks_lead(self, tmp_path: Path, monkeypatch: Any) -> None:
        from typer.testing import CliRunner

        from rebrew.merge import app

        write_source(
            tmp_path / "a.c",
            "/* ADDRESS: V1 0x401000 */\n\nint f(void){return s[0];}\n",
            encoding="utf-8",
            metadata_fields={"V1.0x401000": {"kind": "FUNCTION", "size": 11}},
        )
        write_source(
            tmp_path / "b.c",
            '/* ADDRESS: V1 0x1002d990 */\nchar s[] = "x";\n',
            encoding="utf-8",
            metadata_fields={"V1.0x1002d990": {"kind": "DATA"}},
        )
        out = tmp_path / "m.c"
        monkeypatch.setattr(
            "rebrew.merge.require_config",
            lambda target=None, json_mode=False: _make_cfg(tmp_path),
        )
        # Flags precede positionals: trailing options after the variadic
        # file list are consumed as paths, never parsed (upstream click).
        result = CliRunner().invoke(
            app,
            [
                "--output",
                str(out),
                "--force",
                "--shared",
                str(tmp_path / "a.c"),
                str(tmp_path / "b.c"),
            ],
        )
        assert result.exit_code == 0, result.output
        text = out.read_text(encoding="utf-8")
        assert text.index("char s[]") < text.index("int f(void)")

    def test_vtable_and_string_blocks_lead(self, tmp_path: Path, monkeypatch: Any) -> None:
        """Every data marker sorts ahead of code, not just DATA/GLOBAL."""
        from typer.testing import CliRunner

        from rebrew.merge import app

        write_source(
            tmp_path / "a.c",
            "/* ADDRESS: V1 0x401000 */\n\nint f(void){return s[0];}\n",
            encoding="utf-8",
            metadata_fields={"V1.0x401000": {"kind": "FUNCTION", "size": 11}},
        )
        write_source(
            tmp_path / "b.c",
            '/* ADDRESS: V1 0x1002d990 */\nchar s[] = "x";\n',
            encoding="utf-8",
            metadata_fields={"V1.0x1002d990": {"kind": "VTABLE"}},
        )
        write_source(
            tmp_path / "c.c",
            '/* ADDRESS: V1 0x1002e000 */\nchar t[] = "y";\n',
            encoding="utf-8",
            metadata_fields={"V1.0x1002e000": {"kind": "STRING"}},
        )
        out = tmp_path / "m.c"
        monkeypatch.setattr(
            "rebrew.merge.require_config",
            lambda target=None, json_mode=False: _make_cfg(tmp_path),
        )
        result = CliRunner().invoke(
            app,
            [
                "--output",
                str(out),
                "--force",
                "--shared",
                str(tmp_path / "a.c"),
                str(tmp_path / "b.c"),
                str(tmp_path / "c.c"),
            ],
        )
        assert result.exit_code == 0, result.output
        text = out.read_text(encoding="utf-8")
        assert text.index("char s[]") < text.index("int f(void)")
        assert text.index("char t[]") < text.index("int f(void)")


class TestMergeCrlfInputs:
    """CRLF inputs merge to a uniformly CRLF output, not a mix."""

    def test_merged_output_has_no_bare_lf(self, tmp_path: Path, monkeypatch: Any) -> None:
        a = tmp_path / "a.c"
        b = tmp_path / "b.c"
        _write(a, _single(0x10001000, "_a", preamble="#include <stdio.h>\n"))
        _write(b, _single(0x10002000, "_b"))
        a.write_bytes(
            _single(0x10001000, "_a", preamble="#include <stdio.h>\n")
            .encode()
            .replace(b"\n", b"\r\n")
        )
        b.write_bytes(_single(0x10002000, "_b").encode().replace(b"\n", b"\r\n"))

        result, out = _invoke(tmp_path, monkeypatch, "--force", str(a), str(b))
        assert result.exit_code == 0
        raw = out.read_bytes()
        assert b"\r\n" in raw
        assert raw.replace(b"\r\n", b"").count(b"\n") == 0

    def test_lf_inputs_stay_lf(self, tmp_path: Path, monkeypatch: Any) -> None:
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a"))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b"))

        result, out = _invoke(tmp_path, monkeypatch, "--force", str(a), str(b))
        assert result.exit_code == 0
        assert b"\r" not in out.read_bytes()


def _meta_cfg(tmp_path: Path) -> Any:
    return SimpleNamespace(
        module="SERVER", source_ext=".c", reversed_dir=tmp_path, metadata_dir=tmp_path
    )


def _seed(tmp_path: Path, rows: list[tuple[str, int, str]], *, file: str) -> None:
    from rebrew.metadata.functions import record_function_identity

    for module, va, symbol in rows:
        record_function_identity(
            tmp_path,
            module=module,
            va=va,
            file=file,
            kind="FUNCTION",
            symbol=symbol,
            name=symbol[1:] if symbol.startswith("_") else symbol,
        )


def _invoke_meta(tmp_path: Path, monkeypatch: Any, *args: str) -> tuple[Any, Path]:
    out = tmp_path / "merged.c"
    monkeypatch.setattr(
        "rebrew.merge.require_config",
        lambda target=None, json_mode=False: _meta_cfg(tmp_path),
    )
    return runner.invoke(app, ["--output", str(out), *args]), out


class TestRebaseIncludes:
    def test_respells_relative_include_for_a_new_directory(self, tmp_path: Path) -> None:
        from rebrew.source_paths import rebase_includes

        (tmp_path / "cmd").mkdir()
        (tmp_path / "cmd" / "sub").mkdir()
        (tmp_path / "cmd" / "internal.h").write_text("")
        text = '#include "../internal.h"\n#include "../missing.h"\n#include <stdio.h>\n'

        out = rebase_includes(text, tmp_path / "cmd" / "sub", tmp_path / "cmd")

        assert out == '#include "internal.h"\n#include "../missing.h"\n#include <stdio.h>\n'

    def test_markerless_merge_rebases_includes(self, tmp_path: Path, monkeypatch: Any) -> None:
        (tmp_path / "cmd" / "sub").mkdir(parents=True)
        (tmp_path / "cmd" / "internal.h").write_text("")
        _write(
            tmp_path / "cmd" / "sub" / "a.c",
            '#include "../internal.h"\nint func_a(void) { return 0; }\n',
        )
        _write(tmp_path / "cmd" / "sub" / "b.c", "int func_b(void) { return 1; }\n")
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a")], file="cmd/sub/a.c")
        _seed(tmp_path, [("SERVER", 0x10002000, "_func_b")], file="cmd/sub/b.c")
        monkeypatch.setattr(
            "rebrew.merge.require_config",
            lambda target=None, json_mode=False: _meta_cfg(tmp_path),
        )
        out = tmp_path / "cmd" / "merged.c"

        result = runner.invoke(
            app,
            [
                "--output",
                str(out),
                "--force",
                str(tmp_path / "cmd/sub/a.c"),
                str(tmp_path / "cmd/sub/b.c"),
            ],
        )

        assert result.exit_code == 0, result.output
        assert '#include "internal.h"' in out.read_text(encoding="utf-8")


class TestMarkerlessMerge:
    """A migrated file is merged from its function rows, not from a marker line."""

    @pytest.mark.parametrize("delete", [False, True])
    @pytest.mark.parametrize("dry_run", [False, True])
    def test_legacy_markers_retarget_existing_managed_rows(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, delete: bool, dry_run: bool
    ) -> None:
        from rebrew.metadata.data import load_data_metadata, record_data_rows
        from rebrew.metadata.functions import load_metadata, update_source_status

        a = _write(tmp_path / "a.c", _single(0x401000, "_func_a", module="GOLD"))
        b = _write(tmp_path / "b.c", _single(0x402000, "_func_b", module="GOLD"))
        _seed(
            tmp_path, [("GOLD", 0x401000, "_func_a"), ("GOLDTL", 0x501000, "_func_a")], file="a.c"
        )
        _seed(tmp_path, [("GOLD", 0x402000, "_func_b")], file="b.c")
        _seed(tmp_path, [("GOLD", 0x403000, "_unrelated")], file="other.c")
        update_source_status(
            tmp_path,
            "EXACT",
            "GOLD",
            0x401000,
            updated_by="verify",
            verification={"status": "EXACT", "writer": "verify", "input_hash": "a" * 64},
        )
        record_data_rows(
            tmp_path,
            [
                {
                    "module": "GOLDTL",
                    "va": 0x601000,
                    "identity": {"file": "a.c", "name": "view", "kind": "GLOBAL"},
                }
            ],
        )
        old_functions = load_metadata(tmp_path)
        old_data = load_data_metadata(tmp_path)
        old_sources = (a.read_bytes(), b.read_bytes())
        args = ["--force", "--shared", "--json"]
        if delete:
            args.append("--delete")
        if dry_run:
            args.append("--dry-run")
        args.extend([str(a), str(b)])
        result, out = _invoke_meta(tmp_path, monkeypatch, *args)
        assert result.exit_code == 0, result.output
        if dry_run:
            assert not out.exists()
            assert load_metadata(tmp_path) == old_functions
            assert load_data_metadata(tmp_path) == old_data
            assert (a.read_bytes(), b.read_bytes()) == old_sources
            return
        current = load_metadata(tmp_path)
        for key in [("GOLD", 0x401000), ("GOLDTL", 0x501000), ("GOLD", 0x402000)]:
            assert current[key]["file"] == "merged.c"
            ignore = {"file", "updated_at", "updated_by"}
            assert {k: v for k, v in current[key].items() if k not in ignore} == {
                k: v for k, v in old_functions[key].items() if k not in ignore
            }
        assert current[("GOLD", 0x403000)] == old_functions[("GOLD", 0x403000)]
        assert load_data_metadata(tmp_path)[("GOLDTL", 0x601000)]["file"] == "merged.c"
        assert "ADDRESS: GOLD" in out.read_text()
        assert a.exists() is not delete and b.exists() is not delete

    def test_legacy_merge_restores_output_and_inputs_if_data_retarget_fails(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        from rebrew.metadata.data import record_data_rows
        from rebrew.metadata.functions import load_metadata

        a = _write(tmp_path / "a.c", _single(0x401000, "_func_a", module="GOLD"))
        b = _write(tmp_path / "b.c", _single(0x402000, "_func_b", module="GOLD"))
        _seed(tmp_path, [("GOLD", 0x401000, "_func_a")], file="a.c")
        _seed(tmp_path, [("GOLD", 0x402000, "_func_b")], file="b.c")
        record_data_rows(
            tmp_path,
            [
                {
                    "module": "GOLD",
                    "va": 0x601000,
                    "identity": {"file": "a.c", "name": "view", "kind": "GLOBAL"},
                }
            ],
        )
        output = _write(tmp_path / "merged.c", "existing output\n")
        old = (a.read_bytes(), b.read_bytes(), output.read_bytes())

        def fail(*args: Any, **kwargs: Any) -> None:
            raise OSError("data writer unavailable")

        monkeypatch.setattr("rebrew.merge.record_data_rows", fail)
        result, out = _invoke_meta(
            tmp_path, monkeypatch, "--force", "--shared", "--delete", str(a), str(b)
        )
        assert result.exit_code != 0
        assert "data writer unavailable" in result.output
        assert (a.read_bytes(), b.read_bytes(), out.read_bytes()) == old
        assert load_metadata(tmp_path)[("GOLD", 0x401000)]["file"] == "a.c"

    @pytest.mark.parametrize("dry_run", [False, True])
    def test_legacy_merge_refuses_to_drop_a_managed_foreign_definition(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, dry_run: bool
    ) -> None:
        from rebrew.metadata.functions import load_metadata

        a = _write(
            tmp_path / "a.c",
            _single(0x10001000, "_func_a") + _single(0x401000, "_foreign", module="GOLD"),
        )
        b = _write(tmp_path / "b.c", _single(0x10002000, "_func_b"))
        _seed(
            tmp_path,
            [("SERVER", 0x10001000, "_func_a"), ("GOLD", 0x401000, "_foreign")],
            file="a.c",
        )
        _seed(tmp_path, [("SERVER", 0x10002000, "_func_b")], file="b.c")
        old = (a.read_bytes(), b.read_bytes(), load_metadata(tmp_path))
        args = ["--force", "--delete"]
        if dry_run:
            args.append("--dry-run")
        result, out = _invoke_meta(tmp_path, monkeypatch, *args, str(a), str(b))
        assert result.exit_code == 0, result.output
        if dry_run:
            assert not out.exists()
            assert (a.read_bytes(), b.read_bytes(), load_metadata(tmp_path)) == old
        else:
            assert "int foreign(void)" in out.read_text()
            assert load_metadata(tmp_path)[("GOLD", 0x401000)]["file"] == "merged.c"

    def test_files_sort_by_the_active_targets_va(self, tmp_path: Path, monkeypatch: Any) -> None:
        """A shared body's lower client VA must not sort it ahead of earlier server code."""
        _write(tmp_path / "a.c", "int func_a(void) { return 0; }\n")
        _write(tmp_path / "b.c", "int func_b(void) { return 1; }\n")
        _seed(
            tmp_path,
            [("SERVER", 0x10002000, "_func_a"), ("GOLDTL", 0x400000, "_func_a")],
            file="a.c",
        )
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_b")], file="b.c")

        result, out = _invoke_meta(
            tmp_path, monkeypatch, "--force", str(tmp_path / "a.c"), str(tmp_path / "b.c")
        )

        assert result.exit_code == 0, result.output
        text = out.read_text(encoding="utf-8")
        assert text.index("func_b") < text.index("func_a")

    def test_rows_move_with_the_definitions(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.metadata.data import load_data_metadata, record_data_rows
        from rebrew.metadata.functions import load_metadata, update_field, update_source_status

        _write(
            tmp_path / "a.c",
            "#include <stdio.h>\n\n"
            "static int helper(void) { return 2; }\n\n"
            "static int g_local = 1;\n\n"
            "int g_table[4] = {1, 2, 3, 4};\n\n"
            "int func_a(void) { return helper(); }\n",
        )
        _write(
            tmp_path / "b.c",
            "#include <stdio.h>\n\nint func_b(void) { return 1; }\n",
        )
        _seed(
            tmp_path,
            [("SERVER", 0x10001000, "_func_a"), ("GOLD", 0x20001000, "_func_a")],
            file="a.c",
        )
        _seed(tmp_path, [("SERVER", 0x10002000, "_func_b")], file="b.c")
        update_source_status(
            tmp_path,
            "EXACT",
            "SERVER",
            0x10001000,
            updated_by="verify",
            verification={"status": "EXACT", "writer": "verify", "input_hash": "a" * 64},
        )
        update_field(tmp_path, 0x10001000, "note", "keep", "SERVER")
        record_data_rows(
            tmp_path,
            [
                {
                    "module": "SERVER",
                    "va": 0x10025000,
                    "identity": {"file": "a.c", "kind": "DATA", "name": "g_table"},
                }
            ],
        )

        result, out = _invoke_meta(
            tmp_path, monkeypatch, "--force", str(tmp_path / "a.c"), str(tmp_path / "b.c")
        )
        assert result.exit_code == 0, result.output
        text = out.read_text(encoding="utf-8")
        assert text.count("#include <stdio.h>") == 1
        assert "static int helper(void) { return 2; }" in text
        assert "static int g_local = 1;" in text
        assert "int g_table[4] = {1, 2, 3, 4};" in text
        assert "int func_a(void) { return helper(); }" in text
        assert "int func_b(void) { return 1; }" in text
        assert "// FUNCTION:" not in text
        assert "SOURCE: naked" not in text
        assert text.index("g_local") < text.index("g_table") < text.index("func_a")
        assert text.index("func_a") < text.index("func_b")
        rows = load_metadata(tmp_path)
        assert rows[("SERVER", 0x10001000)]["file"] == "merged.c"
        assert rows[("GOLD", 0x20001000)]["file"] == "merged.c"
        assert rows[("SERVER", 0x10002000)]["file"] == "merged.c"
        kept = rows[("SERVER", 0x10001000)]
        assert kept["status"] == "EXACT"
        assert kept["note"] == "keep"
        assert kept["updated_by"] == "verify"
        assert kept["verification"]["input_hash"] == "a" * 64
        data = load_data_metadata(tmp_path)
        assert list(data) == [("SERVER", 0x10025000)]
        assert data[("SERVER", 0x10025000)]["file"] == "merged.c"

    def test_dry_run_writes_nothing(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "a.c", "int func_a(void) { return 0; }\n")
        _write(tmp_path / "b.c", "int func_b(void) { return 1; }\n")
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a")], file="a.c")
        _seed(tmp_path, [("SERVER", 0x10002000, "_func_b")], file="b.c")
        before = (tmp_path / "rebrew-functions.toml").read_bytes()
        source = (tmp_path / "a.c").read_bytes()

        result, out = _invoke_meta(
            tmp_path, monkeypatch, "--dry-run", str(tmp_path / "a.c"), str(tmp_path / "b.c")
        )
        assert result.exit_code == 0, result.output
        assert not out.exists()
        assert (tmp_path / "rebrew-functions.toml").read_bytes() == before
        assert (tmp_path / "a.c").read_bytes() == source

    def test_preprocessor_definition_writes_nothing(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "a.c", "#if 1\nint func_a(void) { return 0; }\n#endif\n")
        _write(tmp_path / "b.c", "int func_b(void) { return 1; }\n")
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a")], file="a.c")
        _seed(tmp_path, [("SERVER", 0x10002000, "_func_b")], file="b.c")
        before = (tmp_path / "a.c").read_bytes()

        result, out = _invoke_meta(
            tmp_path, monkeypatch, "--force", str(tmp_path / "a.c"), str(tmp_path / "b.c")
        )
        assert result.exit_code != 0
        assert "preprocessor" in result.output
        assert not out.exists()
        assert (tmp_path / "a.c").read_bytes() == before
        from rebrew.metadata.functions import load_metadata

        assert load_metadata(tmp_path)[("SERVER", 0x10001000)]["file"] == "a.c"

    def test_shared_identical_bodies_keep_one_definition(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        body = "int func_a(void) { return 1; }\n"
        _write(tmp_path / "a.c", body)
        _write(tmp_path / "b.c", body)
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a")], file="a.c")
        _seed(tmp_path, [("GOLD", 0x20001000, "_func_a")], file="b.c")

        result, out = _invoke_meta(
            tmp_path,
            monkeypatch,
            "--shared",
            "--force",
            str(tmp_path / "a.c"),
            str(tmp_path / "b.c"),
        )
        assert result.exit_code == 0, result.output
        assert out.read_text(encoding="utf-8").count("int func_a(void)") == 1
        from rebrew.metadata.functions import load_metadata

        rows = load_metadata(tmp_path)
        assert rows[("SERVER", 0x10001000)]["file"] == "merged.c"
        assert rows[("GOLD", 0x20001000)]["file"] == "merged.c"

    def test_shared_divergent_bodies_write_nothing(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "a.c", "int func_a(void) { return 1; }\n")
        _write(tmp_path / "b.c", "int func_a(void) { return 2; }\n")
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a")], file="a.c")
        _seed(tmp_path, [("GOLD", 0x20001000, "_func_a")], file="b.c")

        result, out = _invoke_meta(
            tmp_path,
            monkeypatch,
            "--shared",
            "--force",
            str(tmp_path / "a.c"),
            str(tmp_path / "b.c"),
        )
        assert result.exit_code != 0
        assert "differs" in result.output
        assert not out.exists()
        from rebrew.metadata.functions import load_metadata

        assert load_metadata(tmp_path)[("SERVER", 0x10001000)]["file"] == "a.c"

    def test_duplicate_name_without_shared_writes_nothing(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        _write(tmp_path / "a.c", "int func_a(void) { return 1; }\n")
        _write(tmp_path / "b.c", "int func_a(void) { return 1; }\n")
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a")], file="a.c")
        _seed(tmp_path, [("SERVER", 0x10002000, "_func_a")], file="b.c")

        result, out = _invoke_meta(
            tmp_path, monkeypatch, "--force", str(tmp_path / "a.c"), str(tmp_path / "b.c")
        )
        assert result.exit_code != 0
        assert "more than one input" in result.output
        assert not out.exists()

    def test_failed_retarget_restores_the_output(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.metadata.data import record_data_rows
        from rebrew.metadata.functions import load_metadata

        _write(tmp_path / "a.c", "int g_table = 1;\n\nint func_a(void) { return g_table; }\n")
        _write(tmp_path / "b.c", "int func_b(void) { return 1; }\n")
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a")], file="a.c")
        _seed(tmp_path, [("SERVER", 0x10002000, "_func_b")], file="b.c")
        record_data_rows(
            tmp_path,
            [
                {
                    "module": "SERVER",
                    "va": 0x10025000,
                    "identity": {"file": "a.c", "kind": "DATA", "name": "g_table"},
                }
            ],
        )

        def _boom(*_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("disk full")

        monkeypatch.setattr("rebrew.merge.record_data_rows", _boom)
        result, out = _invoke_meta(
            tmp_path, monkeypatch, "--force", str(tmp_path / "a.c"), str(tmp_path / "b.c")
        )
        assert result.exit_code != 0
        assert "restored" in result.output
        assert not out.exists()
        assert load_metadata(tmp_path)[("SERVER", 0x10001000)]["file"] == "a.c"

    def test_json_without_force_writes_nothing(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "a.c", "int func_a(void) { return 0; }\n")
        _write(tmp_path / "b.c", "int func_b(void) { return 1; }\n")
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a")], file="a.c")
        _seed(tmp_path, [("SERVER", 0x10002000, "_func_b")], file="b.c")

        result, out = _invoke_meta(
            tmp_path, monkeypatch, "--json", str(tmp_path / "a.c"), str(tmp_path / "b.c")
        )
        assert result.exit_code != 0
        assert "Pass --force" in result.output
        assert not out.exists()

    def test_mixed_marker_and_migrated_inputs_write_nothing(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        marker = _write(tmp_path / "a.c", _single(0x10001000, "_func_a"))
        _write(tmp_path / "b.c", "int func_b(void) { return 1; }\n")
        _seed(tmp_path, [("SERVER", 0x10002000, "_func_b")], file="b.c")
        before = marker.read_bytes()

        result, out = _invoke_meta(
            tmp_path, monkeypatch, "--force", str(marker), str(tmp_path / "b.c")
        )
        assert result.exit_code == 0, result.output
        assert "func_a" in out.read_text() and "func_b" in out.read_text()
        assert marker.read_bytes() == before

    def test_delete_removes_migrated_inputs(self, tmp_path: Path, monkeypatch: Any) -> None:
        a = _write(tmp_path / "a.c", "int func_a(void) { return 0; }\n")
        b = _write(tmp_path / "b.c", "int func_b(void) { return 1; }\n")
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a")], file="a.c")
        _seed(tmp_path, [("SERVER", 0x10002000, "_func_b")], file="b.c")

        result, out = _invoke_meta(tmp_path, monkeypatch, "--delete", "--force", str(a), str(b))
        assert result.exit_code == 0, result.output
        assert out.exists()
        assert not a.exists()
        assert not b.exists()

    def test_nonstatic_without_a_row_writes_nothing(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(
            tmp_path / "a.c",
            "int func_a(void) { return 0; }\n\nint extra(void) { return 3; }\n",
        )
        _write(tmp_path / "b.c", "int func_b(void) { return 1; }\n")
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a")], file="a.c")
        _seed(tmp_path, [("SERVER", 0x10002000, "_func_b")], file="b.c")

        result, out = _invoke_meta(
            tmp_path, monkeypatch, "--force", str(tmp_path / "a.c"), str(tmp_path / "b.c")
        )
        assert result.exit_code != 0
        assert "no function row" in result.output
        assert not out.exists()
        from rebrew.metadata.functions import load_metadata

        assert load_metadata(tmp_path)[("SERVER", 0x10001000)]["file"] == "a.c"

    def test_function_row_without_a_definition_writes_nothing(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        _write(tmp_path / "a.c", "int func_a(void) { return 0; }\n")
        _write(tmp_path / "b.c", "int func_b(void) { return 1; }\n")
        _seed(
            tmp_path,
            [("SERVER", 0x10001000, "_func_a"), ("SERVER", 0x10003000, "_func_missing")],
            file="a.c",
        )
        _seed(tmp_path, [("SERVER", 0x10002000, "_func_b")], file="b.c")

        result, out = _invoke_meta(
            tmp_path, monkeypatch, "--force", str(tmp_path / "a.c"), str(tmp_path / "b.c")
        )
        assert result.exit_code != 0
        assert "no C definition" in result.output
        assert not out.exists()
        from rebrew.metadata.functions import load_metadata

        assert load_metadata(tmp_path)[("SERVER", 0x10003000)]["file"] == "a.c"

    def test_data_row_without_an_object_follows_the_merge(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """An extern declaration or compiler literal has a row but no definition to copy."""
        from rebrew.metadata.data import load_data_metadata, record_data_rows

        _write(tmp_path / "a.c", "int func_a(void) { return 0; }\n")
        _write(tmp_path / "b.c", "int func_b(void) { return 1; }\n")
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a")], file="a.c")
        _seed(tmp_path, [("SERVER", 0x10002000, "_func_b")], file="b.c")
        record_data_rows(
            tmp_path,
            [
                {
                    "module": "SERVER",
                    "va": 0x10025000,
                    "identity": {"file": "a.c", "kind": "DATA", "name": "g_missing"},
                }
            ],
        )

        result, out = _invoke_meta(
            tmp_path, monkeypatch, "--force", str(tmp_path / "a.c"), str(tmp_path / "b.c")
        )
        assert result.exit_code == 0, result.output
        assert out.exists()
        assert load_data_metadata(tmp_path)[("SERVER", 0x10025000)]["file"] == "merged.c"

    def test_one_row_claimed_by_two_definitions_writes_nothing(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        from rebrew.metadata.functions import record_function_identity

        _write(
            tmp_path / "a.c",
            "int func_a(void) { return 0; }\n\nint func_b(void) { return 1; }\n",
        )
        _write(tmp_path / "c.c", "int func_c(void) { return 2; }\n")
        record_function_identity(
            tmp_path,
            module="SERVER",
            va=0x10001000,
            file="a.c",
            kind="FUNCTION",
            symbol="_func_a",
            name="func_b",
        )
        _seed(tmp_path, [("SERVER", 0x10003000, "_func_c")], file="c.c")

        result, out = _invoke_meta(
            tmp_path, monkeypatch, "--force", str(tmp_path / "a.c"), str(tmp_path / "c.c")
        )
        assert result.exit_code != 0
        assert "matches" in result.output
        assert not out.exists()

    def test_multi_declarator_writes_nothing(self, tmp_path: Path, monkeypatch: Any) -> None:
        _write(tmp_path / "a.c", "int alpha, beta;\n\nint func_a(void) { return 0; }\n")
        _write(tmp_path / "b.c", "int func_b(void) { return 1; }\n")
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a")], file="a.c")
        _seed(tmp_path, [("SERVER", 0x10002000, "_func_b")], file="b.c")

        result, out = _invoke_meta(
            tmp_path, monkeypatch, "--force", str(tmp_path / "a.c"), str(tmp_path / "b.c")
        )
        assert result.exit_code != 0
        assert "did not parse" in result.output
        assert not out.exists()

    def test_crlf_inputs_stay_crlf(self, tmp_path: Path, monkeypatch: Any) -> None:
        a = _write(tmp_path / "a.c", "int func_a(void) { return 0; }\n")
        b = _write(tmp_path / "b.c", "int func_b(void) { return 1; }\n")
        a.write_bytes(a.read_bytes().replace(b"\n", b"\r\n"))
        b.write_bytes(b.read_bytes().replace(b"\n", b"\r\n"))
        _seed(tmp_path, [("SERVER", 0x10001000, "_func_a")], file="a.c")
        _seed(tmp_path, [("SERVER", 0x10002000, "_func_b")], file="b.c")

        result, out = _invoke_meta(tmp_path, monkeypatch, "--force", str(a), str(b))
        assert result.exit_code == 0, result.output
        raw = out.read_bytes()
        assert b"\r\n" in raw
        assert raw.replace(b"\r\n", b"").count(b"\n") == 0


class TestMergeNativeOrder:
    @pytest.mark.parametrize("dry_run", [False, True])
    def test_interleaving_required_refuses_before_any_write(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, dry_run: bool
    ) -> None:
        from tree_snapshot import snapshot_with_stat

        first = _single(0x10001000, "_first")
        last = _single(0x10003000, "_last")
        a = _write(
            tmp_path / "a.c",
            SourceFixture(str(first) + str(last), first.metadata_fields | last.metadata_fields),
        )
        b = _write(tmp_path / "b.c", _single(0x10002000, "_middle"))
        destination = tmp_path / "merged.c"
        destination.write_text("/* existing output must survive refusal */\n")
        before = snapshot_with_stat(tmp_path)
        flags = ["--force", "--delete", *(["--dry-run"] if dry_run else [])]
        result, out = _invoke(tmp_path, monkeypatch, *flags, str(a), str(b))
        assert result.exit_code != 0
        assert "native order" in result.output and "middle" in result.output
        assert out == destination and before == snapshot_with_stat(tmp_path)

    def test_other_target_order_is_checked(self, tmp_path: Path, monkeypatch: Any) -> None:
        a = _write(
            tmp_path / "a.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\n/* ADDRESS: CLIENT 0x402000 */\n"
                "int first(void) { return 1; }\n",
                {
                    "SERVER.0x10001000": {"kind": "FUNCTION"},
                    "CLIENT.0x00402000": {"kind": "FUNCTION"},
                },
            ),
        )
        b = _write(
            tmp_path / "b.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x10002000 */\n/* ADDRESS: CLIENT 0x401000 */\n"
                "int second(void) { return 2; }\n",
                {
                    "SERVER.0x10002000": {"kind": "FUNCTION"},
                    "CLIENT.0x00401000": {"kind": "FUNCTION"},
                },
            ),
        )
        result, out = _invoke(tmp_path, monkeypatch, "--force", "--dry-run", str(a), str(b))
        assert result.exit_code != 0
        assert "CLIENT native order" in result.output and not out.exists()


class TestMergeTargetParticipation:
    @pytest.mark.parametrize("dry_run", [False, True])
    def test_foreign_function_and_helper_never_enter_selected_target(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, dry_run: bool
    ) -> None:
        from tree_snapshot import snapshot_with_stat

        from rebrew.config import ProjectConfig

        a = _write(tmp_path / "server.c", _single(0x10001000, "_server_only"))
        b = _write(
            tmp_path / "client.c",
            _single(
                0x402000,
                "_client_only",
                module="CLIENT",
                preamble="static int client_helper(void) { return 2; }\n",
            ),
        )
        cfg = ProjectConfig(
            root=tmp_path, reversed_dir=tmp_path, module="SERVER", target_name="server"
        )
        monkeypatch.setattr("rebrew.merge.require_config", lambda **kwargs: cfg)
        output = tmp_path / "merged.c"
        output.write_text("/* retain existing output */\n")
        before = snapshot_with_stat(tmp_path)
        result = runner.invoke(
            app,
            [
                "--output",
                str(output),
                "--force",
                "--delete",
                *(["--dry-run"] if dry_run else []),
                str(a),
                str(b),
            ],
        )
        assert result.exit_code != 0
        assert "target participation" in result.output
        assert before == snapshot_with_stat(tmp_path)

    def test_identical_shared_body_keeps_its_original_providers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.config import ProjectConfig

        (tmp_path / "rebrew-project.toml").write_text('[metadata]\nbackend = "toml"\n')
        a = _write(tmp_path / "server.c", _single(0x10001000, "_same"))
        b = _write(tmp_path / "client.c", _single(0x402000, "_same", module="CLIENT"))
        cfgs = [
            ProjectConfig(root=tmp_path, reversed_dir=tmp_path, module=m, target_name=m)
            for m in ("SERVER", "CLIENT")
        ]
        monkeypatch.setattr("rebrew.merge.require_config", lambda **kwargs: cfgs[0])
        monkeypatch.setattr("rebrew.source_organization.organization_configs", lambda cfg: cfgs)
        result = runner.invoke(
            app, ["--output", str(tmp_path / "shared.c"), "--force", "--shared", str(a), str(b)]
        )
        assert result.exit_code == 0, result.output
        text = (tmp_path / "shared.c").read_text()
        assert text.count("int same") == 1
        assert "ADDRESS: SERVER" in text and "ADDRESS: CLIENT" in text

    def test_storage_only_support_scope_is_not_lost_or_added_to_functions(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from tree_snapshot import snapshot_with_stat

        from rebrew.config import ProjectConfig
        from rebrew.metadata.source_provenance import set_source_file
        from rebrew.source_selection import collect_target_sources

        storage = _write(tmp_path / "storage.c", "int object;\n")
        for module in ("SERVER", "CLIENT"):
            set_source_file(tmp_path, "storage.c", module, "evidenced target storage")
        first = _single(0x401000, "_a", module="CLIENT")
        second = _single(0x402000, "_b", module="CLIENT")
        functions = _write(tmp_path / "functions.c", first + second)
        cfgs = [
            ProjectConfig(root=tmp_path, reversed_dir=tmp_path, module=m, target_name=m)
            for m in ("SERVER", "CLIENT")
        ]
        assert storage in collect_target_sources(cfgs[0], "SERVER")[0]
        assert functions not in collect_target_sources(cfgs[0], "SERVER")[0]
        assert {storage, functions} <= set(collect_target_sources(cfgs[1], "CLIENT")[0])
        monkeypatch.setattr("rebrew.merge.require_config", lambda **kwargs: cfgs[1])
        monkeypatch.setattr("rebrew.source_organization.organization_configs", lambda cfg: cfgs)
        before = snapshot_with_stat(tmp_path)
        result = runner.invoke(
            app,
            [
                "--output",
                str(tmp_path / "merged.c"),
                "--force",
                "--delete",
                str(storage),
                str(functions),
            ],
        )
        assert result.exit_code != 0 and "target participation" in result.output
        assert before == snapshot_with_stat(tmp_path)


class TestTransactionalMerge:
    @pytest.mark.parametrize("backend", ["toml", "sqlite"])
    def test_merge_rehomes_provenance_and_uses_reviewed_digest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str
    ) -> None:
        import json

        from rebrew.config import ProjectConfig
        from rebrew.metadata.source_provenance import (
            document_assembly,
            load_source_files,
            load_source_provenance,
            set_source_file,
        )

        (tmp_path / "rebrew-project.toml").write_text(f'[metadata]\nbackend = "{backend}"\n')
        a = _write(tmp_path / "a.c", _single(0x10001000, "_first"))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_second"))
        out = tmp_path / "merged.c"
        document_assembly(tmp_path, a, "first", "SERVER", "original assembly evidence")
        set_source_file(tmp_path, "a.c", "SERVER", "reviewed support reason")
        cfg = ProjectConfig(
            root=tmp_path, reversed_dir=tmp_path, module="SERVER", target_name="SERVER"
        )
        monkeypatch.setattr("rebrew.merge.require_config", lambda **kwargs: cfg)
        base = ["--output", str(out), "--force", "--delete", "--json"]
        preview = runner.invoke(app, [*base, "--dry-run", str(a), str(b)])
        assert preview.exit_code == 0, preview.output
        digest = json.loads(preview.output)["input_digest"]
        applied = runner.invoke(app, [*base, "--expected-digest", digest, str(a), str(b)])
        assert applied.exit_code == 0, applied.output
        assert out.exists() and not a.exists() and not b.exists()
        assert {r.file for r in load_source_provenance(tmp_path)} == {"merged.c"}
        assert {r.file for r in load_source_files(tmp_path)} == {"merged.c"}

    @pytest.mark.parametrize("backend", ["toml", "sqlite"])
    def test_failure_after_retarget_restores_sources_and_stores(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str
    ) -> None:
        from rebrew.config import ProjectConfig
        from rebrew.metadata.storage import metadata_store

        (tmp_path / "rebrew-project.toml").write_text(f'[metadata]\nbackend = "{backend}"\n')
        a = _write(tmp_path / "a.c", _single(0x10001000, "_first"))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_second"))
        out = tmp_path / "merged.c"
        out.write_text("/* existing output */\n")
        cfg = ProjectConfig(
            root=tmp_path, reversed_dir=tmp_path, module="SERVER", target_name="SERVER"
        )
        monkeypatch.setattr("rebrew.merge.require_config", lambda **kwargs: cfg)
        stores = [
            metadata_store(tmp_path / n) for n in ("rebrew-data.toml", "rebrew-functions.toml")
        ]
        before = [p.read_bytes() for p in (a, b, out)], [s.snapshot() for s in stores]

        def fail(*args: Any, **kwargs: Any) -> None:
            raise ValueError("injected provenance failure")

        monkeypatch.setattr("rebrew.metadata.source_provenance.replace_source_metadata", fail)
        result = runner.invoke(app, ["--output", str(out), "--force", "--delete", str(a), str(b)])
        assert result.exit_code != 0 and "injected provenance failure" in result.output
        assert ([p.read_bytes() for p in (a, b, out)], [s.snapshot() for s in stores]) == before
        assert not list(tmp_path.glob(".rebrew-stage-*"))

    @pytest.mark.parametrize("backend", ["toml", "sqlite"])
    def test_stale_review_rejects_source_changes_without_writes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str
    ) -> None:
        import json

        from rebrew.config import ProjectConfig
        from rebrew.metadata.storage import metadata_store

        (tmp_path / "rebrew-project.toml").write_text(f'[metadata]\nbackend = "{backend}"\n')
        a = _write(tmp_path / "a.c", _single(0x10001000, "_first"))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_second"))
        out = tmp_path / "merged.c"
        cfg = ProjectConfig(
            root=tmp_path, reversed_dir=tmp_path, module="SERVER", target_name="SERVER"
        )
        monkeypatch.setattr("rebrew.merge.require_config", lambda **kwargs: cfg)
        base = ["--output", str(out), "--force", "--delete", "--json"]
        preview = runner.invoke(app, [*base, "--dry-run", str(a), str(b)])
        assert preview.exit_code == 0, preview.output
        digest = json.loads(preview.output)["input_digest"]
        a.write_bytes(a.read_bytes() + b"/* changed */\n")
        before = (
            a.read_bytes(),
            b.read_bytes(),
            metadata_store(tmp_path / "rebrew-functions.toml").snapshot(),
        )
        result = runner.invoke(app, [*base, "--expected-digest", digest, str(a), str(b)])
        assert result.exit_code != 0 and "inputs changed" in result.output
        assert (
            a.read_bytes(),
            b.read_bytes(),
            metadata_store(tmp_path / "rebrew-functions.toml").snapshot(),
        ) == before
        assert not out.exists()


@pytest.mark.parametrize("backend", ["toml", "sqlite"])
def test_transactional_merge_rejects_stale_transitive_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str
) -> None:
    import json

    from rebrew.config import ProjectConfig
    from rebrew.metadata.storage import metadata_store

    (tmp_path / "rebrew-project.toml").write_text(f'[metadata]\nbackend = "{backend}"\n')
    a = _write(tmp_path / "a.c", _single(0x10001000, "_first", preamble='#include "shared.h"\n'))
    b = _write(tmp_path / "b.c", _single(0x10002000, "_second"))
    (tmp_path / "shared.h").write_text('#include "nested.h"\n')
    nested = tmp_path / "nested.h"
    nested.write_text("#define VALUE 1\n")
    out = tmp_path / "merged.c"
    cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path, module="SERVER", target_name="SERVER")
    monkeypatch.setattr("rebrew.merge.require_config", lambda **kwargs: cfg)
    base = ["--output", str(out), "--force", "--delete", "--json"]
    preview = runner.invoke(app, [*base, "--dry-run", str(a), str(b)])
    assert preview.exit_code == 0, preview.output
    digest = json.loads(preview.output)["input_digest"]
    nested.write_text("#define VALUE 2\n")
    before = (
        a.read_bytes(),
        b.read_bytes(),
        metadata_store(tmp_path / "rebrew-functions.toml").snapshot(),
    )
    result = runner.invoke(app, [*base, "--expected-digest", digest, str(a), str(b)])
    assert result.exit_code != 0 and "inputs changed" in result.output
    assert (
        a.read_bytes(),
        b.read_bytes(),
        metadata_store(tmp_path / "rebrew-functions.toml").snapshot(),
    ) == before
    assert not out.exists()


def test_transactional_merge_rejects_retargeted_header_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rebrew.config import ProjectConfig

    (tmp_path / "rebrew-project.toml").write_text('[metadata]\nbackend = "toml"\n')
    a = _write(tmp_path / "a.c", _single(0x10001000, "_first", preamble='#include "alias.h"\n'))
    b = _write(tmp_path / "b.c", _single(0x10002000, "_second"))
    (tmp_path / "actual.h").write_text("#define VALUE 1\n")
    (tmp_path / "alias.h").symlink_to("actual.h")
    out = tmp_path / "merged.c"
    cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path, module="SERVER", target_name="SERVER")
    monkeypatch.setattr("rebrew.merge.require_config", lambda **kwargs: cfg)
    args = ["--output", str(out), "--force", "--delete", "--json"]
    preview = runner.invoke(app, [*args, "--dry-run", str(a), str(b)])
    assert preview.exit_code != 0 and "symlinked include search context" in preview.output
    assert a.exists() and b.exists() and not out.exists()


def test_transactional_merge_rejects_config_changed_while_loading_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rebrew.config import ProjectConfig

    config = tmp_path / "rebrew-project.toml"
    config.write_text('[metadata]\nbackend = "toml"\n')
    a = _write(tmp_path / "a.c", _single(0x10001000, "_first"))
    b = _write(tmp_path / "b.c", _single(0x10002000, "_second"))
    cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path, module="SERVER", target_name="SERVER")
    monkeypatch.setattr("rebrew.merge.require_config", lambda **kwargs: cfg)

    def change_config(context: ProjectConfig) -> list[ProjectConfig]:
        config.write_text('[metadata]\nbackend = "toml"\n# changed\n')
        return [context]

    monkeypatch.setattr("rebrew.source_organization.organization_configs", change_config)
    out = tmp_path / "merged.c"
    result = runner.invoke(app, ["--output", str(out), "--dry-run", "--json", str(a), str(b)])
    assert result.exit_code != 0 and "config changed" in result.output
    assert a.exists() and b.exists() and not out.exists()


def test_transactional_merge_rejects_alias_change_after_header_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import rebrew.merge as merge
    from rebrew.config import ProjectConfig

    (tmp_path / "rebrew-project.toml").write_text('[metadata]\nbackend = "toml"\n')
    a = _write(tmp_path / "a.c", _single(0x10001000, "_first", preamble='#include "alias.h"\n'))
    b = _write(tmp_path / "b.c", _single(0x10002000, "_second"))
    (tmp_path / "actual.h").write_text("#define VALUE 1\n")
    alias = tmp_path / "alias.h"
    alias.write_text("#define VALUE 1\n")
    cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path, module="SERVER", target_name="SERVER")
    monkeypatch.setattr(merge, "require_config", lambda **kwargs: cfg)
    load = merge._merge_include_inputs

    def change_after_read(*args: Any) -> Any:
        result = load(*args)
        alias.unlink()
        alias.symlink_to("actual.h")
        return result

    monkeypatch.setattr(merge, "_merge_include_inputs", change_after_read)
    out = tmp_path / "merged.c"
    result = runner.invoke(app, ["--output", str(out), "--dry-run", "--json", str(a), str(b)])
    assert result.exit_code != 0 and "includes changed" in result.output
    assert a.exists() and b.exists() and not out.exists()


@pytest.mark.parametrize("timing", ["before_lock", "after_publication"])
def test_transactional_merge_rejects_earlier_include_created_before_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, timing: str
) -> None:
    import json

    import rebrew.metadata.coordinated as coordinated
    from rebrew.config import ProjectConfig

    (tmp_path / "rebrew-project.toml").write_text('[metadata]\nbackend = "toml"\n')
    src, early, late = (tmp_path / name for name in ("src", "early", "late"))
    for directory in (src, early, late):
        directory.mkdir()
    (late / "api.h").write_text("#define VALUE 1\n")
    a = _write(src / "a.c", _single(0x10001000, "_first", preamble="#include <api.h>\n"))
    b = _write(src / "b.c", _single(0x10002000, "_second"))
    out = src / "merged.c"
    cfg = ProjectConfig(
        root=tmp_path,
        reversed_dir=src,
        module="SERVER",
        target_name="SERVER",
        base_cflags=f"/I{early} /I{late}",
    )
    monkeypatch.setattr("rebrew.merge.require_config", lambda **kwargs: cfg)
    args = ["--output", str(out), "--force", "--delete", "--json"]
    preview = runner.invoke(app, [*args, "--dry-run", str(a), str(b)])
    assert preview.exit_code == 0, preview.output
    digest = json.loads(preview.output)["input_digest"]
    if timing == "before_lock":
        original = coordinated.coordinated_transaction

        def create_shadow(*args: Any, **kwargs: Any) -> Any:
            (early / "api.h").write_text("#define VALUE 1\n")
            return original(*args, **kwargs)

        monkeypatch.setattr(coordinated, "coordinated_transaction", create_shadow)
    else:
        publish = coordinated.CoordinatedStage.publish

        def publish_then_shadow(stage: Any, path: Path, content: bytes) -> None:
            publish(stage, path, content)
            (early / "api.h").write_text("#define VALUE 1\n")

        monkeypatch.setattr(coordinated.CoordinatedStage, "publish", publish_then_shadow)
    result = runner.invoke(app, [*args, "--expected-digest", digest, str(a), str(b)])
    assert result.exit_code != 0 and "resolution changed" in result.output
    assert a.exists() and b.exists() and not out.exists()


def test_transactional_merge_refuses_unresolved_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rebrew.config import ProjectConfig

    (tmp_path / "rebrew-project.toml").write_text('[metadata]\nbackend = "toml"\n')
    a = _write(tmp_path / "a.c", _single(0x10001000, "_first", preamble='#include "missing.h"\n'))
    b = _write(tmp_path / "b.c", _single(0x10002000, "_second"))
    cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path, module="SERVER", target_name="SERVER")
    monkeypatch.setattr("rebrew.merge.require_config", lambda **kwargs: cfg)
    result = runner.invoke(
        app, ["--output", str(tmp_path / "merged.c"), "--force", "--delete", str(a), str(b)]
    )
    assert result.exit_code != 0 and "include closure is incomplete" in result.output
    assert a.exists() and b.exists() and not (tmp_path / "merged.c").exists()


def _accept_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, preamble: str = '#include "missing.h"\n'
) -> tuple[Path, Path, Path]:
    from rebrew.config import ProjectConfig

    (tmp_path / "rebrew-project.toml").write_text('[metadata]\nbackend = "toml"\n')
    a = _write(tmp_path / "a.c", _single(0x10001000, "_first", preamble=preamble))
    b = _write(tmp_path / "b.c", _single(0x10002000, "_second"))
    cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path, module="SERVER", target_name="SERVER")
    monkeypatch.setattr("rebrew.merge.require_config", lambda **kwargs: cfg)
    return a, b, tmp_path / "merged.c"


def test_merge_accept_unresolved_includes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import json

    a, b, out = _accept_project(tmp_path, monkeypatch)

    def run(*flags: str) -> Any:
        return runner.invoke(
            app,
            [
                "--output",
                str(out),
                "--force",
                "--delete",
                "--dry-run",
                "--json",
                *flags,
                str(a),
                str(b),
            ],
        )

    refused = run()
    assert refused.exit_code != 0 and "include closure is incomplete" in refused.output
    wrong = run("--accept-unresolved-includes", "other.h")
    assert wrong.exit_code != 0 and "include closure is incomplete" in wrong.output
    accepted = run("--accept-unresolved-includes", "missing.h")
    assert accepted.exit_code == 0, accepted.output
    payload = json.loads(accepted.output)
    assert payload["accepted_unresolved_includes"] == ["missing.h"]
    tolerated = payload["tolerated_unresolved_includes"]
    assert len(tolerated) == 1 and tolerated[0]["missing"] == ["missing.h"]
    assert tolerated[0]["target"] == "SERVER"
    assert all(path.exists() for path in (a, b)) and not out.exists()

    applied = runner.invoke(
        app,
        [
            "--output",
            str(out),
            "--force",
            "--delete",
            "--json",
            "--expected-digest",
            payload["input_digest"],
            "--accept-unresolved-includes",
            "missing.h",
            str(a),
            str(b),
        ],
    )
    assert applied.exit_code == 0, applied.output
    assert out.exists() and not a.exists() and not b.exists()


def test_merge_accept_unresolved_includes_digest_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json

    a, b, out = _accept_project(tmp_path, monkeypatch)
    base = ["--output", str(out), "--force", "--dry-run", "--json"]
    one = runner.invoke(app, [*base, "--accept-unresolved-includes", "missing.h", str(a), str(b)])
    two = runner.invoke(
        app,
        [
            *base,
            "--accept-unresolved-includes",
            "missing.h",
            "--accept-unresolved-includes",
            "stdio.h",
            str(a),
            str(b),
        ],
    )
    assert one.exit_code == 0 and two.exit_code == 0, (one.output, two.output)
    assert json.loads(one.output)["input_digest"] != json.loads(two.output)["input_digest"]
    assert json.loads(two.output)["accepted_unresolved_includes"] == ["missing.h", "stdio.h"]


@pytest.mark.parametrize("name", ["/etc/passwd", "../secret.h", "C:\\win.h", ""])
def test_merge_accept_unresolved_includes_rejects_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    a, b, out = _accept_project(tmp_path, monkeypatch)
    result = runner.invoke(
        app,
        [
            "--output",
            str(out),
            "--force",
            "--dry-run",
            "--json",
            "--accept-unresolved-includes",
            name,
            str(a),
            str(b),
        ],
    )
    assert result.exit_code != 0 and "accept-unresolved-includes" in result.output
    assert all(path.exists() for path in (a, b)) and not out.exists()
