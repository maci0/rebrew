"""Tests for BinSync state validation and reconciliation helpers."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from source_util import write_source


class TestRemoteSyncRecords:
    def test_identity_order_exact_suffix_and_comments(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.binsync import state

        monkeypatch.setattr(
            state,
            "load_binsync_comments",
            lambda _: {
                0x1004: {"func_addr": 0x1000, "comment": "body"},
                0x1001: {"func_addr": 0x1000, "comment": "[rebrew:note] private"},
                0x1002: {"func_addr": 0x1000, "comment": "[rebrew:ghidra] private"},
                0x2004: {"func_addr": 0x2000, "comment": "fallback"},
                0x3004: {"func_addr": 0x3000, "comment": "no owner"},
                0x4004: {"func_addr": None, "comment": "unknown"},
            },
        )
        monkeypatch.setattr(state, "incoming_type_records", lambda _: {})
        local: dict[str, dict[str, Any]] = {
            "function.WRONG.0x01000": {},
            "function.FIRST.0x1000": {},
            "function.SECOND.0x1000": {},
            "global.FIRST.0x5000": {},
            "global.SECOND.0x5000": {},
        }
        cfg: Any = SimpleNamespace(module="GAME", target_name="game")
        result = state.remote_sync_records(
            cfg,
            tmp_path,
            {0x1000: {"name": "f", "evidence": "private"}, 0x2000: {"name": "g"}},
            {0x5000: {"name": "v"}},
            local,
        )
        assert list(result) == [
            "function.FIRST.0x1000",
            "function.GAME.0x2000",
            "global.FIRST.0x5000",
        ]
        assert result["function.FIRST.0x1000"] == {
            "name": "f",
            "comments": {"0x00001004": {"comment": "body", "func_addr": 0x1000}},
        }
        assert result["function.GAME.0x2000"]["comments"] == {
            "0x00002004": {"comment": "fallback", "func_addr": 0x2000}
        }


class TestDefinitionValidation:
    def test_directive_behind_a_comment_is_refused(self) -> None:
        """The preprocessor reads text with comments removed, so test it that way."""
        from rebrew.binsync.importer import _definition_is_valid

        smuggled = "typedef struct S {\n\tint x;\n/*c*/#define REBREW_PWNED 1\n} S;"
        assert _definition_is_valid(smuggled, "S", {"kind": "struct"}) is False
        # A directive inside a comment is not a directive: comments are removed
        # before the preprocessor reads the line.
        assert (
            _definition_is_valid(
                "// #define X 1\ntypedef struct S { int x; } S;", "S", {"kind": "struct"}
            )
            is True
        )
        assert (
            _definition_is_valid("typedef struct S { int x; } S;", "S", {"kind": "struct"}) is True
        )


class TestResultFieldReaders:
    """The CLI printers narrow the loosely-typed result dict instead of asserting it."""

    def test_count_defaults_and_narrows(self) -> None:
        from rebrew.binsync.state import result_count

        assert result_count({}, "applied_structs") == 0
        assert result_count({"applied_structs": None}, "applied_structs") == 0
        assert result_count({"applied_structs": 3}, "applied_structs") == 3
        with pytest.raises(TypeError):
            result_count({"applied_structs": "3"}, "applied_structs")

    def test_rows_rejects_non_mapping_entry(self) -> None:
        from rebrew.binsync.state import result_rows

        assert result_rows({}, "proposed") == []
        assert result_rows({"proposed": [{"va": "0x1000"}]}, "proposed") == [{"va": "0x1000"}]
        with pytest.raises(TypeError):
            result_rows({"proposed": ["0x1000"]}, "proposed")

    def test_paths_rejects_non_list(self) -> None:
        from rebrew.binsync.state import result_paths

        assert result_paths({}, "warnings") == []
        assert result_paths({"warnings": ["a.c"]}, "warnings") == ["a.c"]
        with pytest.raises(TypeError):
            result_paths({"warnings": "a.c"}, "warnings")


class TestLoadBinsyncState:
    def test_missing_functions_dir_is_reported(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A state dir with no functions/ reads as empty, which is also the
        "nothing to import" signal; the globals beside it would then never be
        applied with nothing saying why."""
        from rebrew.binsync.state import load_binsync_state

        (tmp_path / "globals.toml").write_text("", encoding="utf-8")
        with caplog.at_level("WARNING"):
            funcs, _globals = load_binsync_state(tmp_path)
        assert funcs == {}
        assert "no functions" in caplog.text


class TestGlobalNameAndType:
    def test_bare_pointer_to_array(self, tmp_path: Path) -> None:
        """``char (*g_row)[4]`` is one pointer, and it has no ``extern``.

        The name sits inside parentheses, so the declaration after the
        marker was skipped. ``int (*table[4])`` is four pointers.
        """
        from types import SimpleNamespace

        from rebrew.binsync.state import global_name_and_type

        src = tmp_path / "src"
        src.mkdir()
        write_source(
            src / "g.c",
            "/* ADDRESS: SERVER 0x1000 */\nchar (*g_row)[4];\n/* ADDRESS: SERVER 0x2000 */\nint (*table[4]);\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "DATA"}, "SERVER.0x2000": {"kind": "DATA"}},
        )
        cfg = SimpleNamespace(reversed_dir=src)
        assert global_name_and_type(cfg, 0x1000, "g.c") == ("g_row", "char (*)[4]")
        assert global_name_and_type(cfg, 0x2000, "g.c") == ("table", "int *[4]")


class TestCommentWrapping:
    def test_declib_rewrap_compares_equal(self) -> None:
        """declib wraps comment text at 100 columns, also after a word's hyphen."""
        from rebrew.binsync import serial
        from rebrew.binsync.state import normalize_comment_text

        note = (
            "Frees memory allocated by m_AllocTracked. Decrements the counters in the tracking "
            "structure and asserts that the global memory counts don't underflow. Emits fatal "
            "error on double-free or wild pointer; length = total_length - bytes_received."
        )
        wrapped = serial.new_comment(0x1001, 0x1000, note).comment
        assert "\n" in wrapped
        assert normalize_comment_text(wrapped) == normalize_comment_text(note)
