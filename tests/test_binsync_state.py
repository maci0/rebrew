"""Tests for BinSync state validation and reconciliation helpers."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
lazy from pathlib import Path

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


class TestSyncHealthMetadataSnapshots:
    def test_health_scan_loads_each_store_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.binsync import state
        from rebrew.metadata import data, functions

        cfg: Any = SimpleNamespace(
            metadata_dir=tmp_path,
            root=tmp_path,
            reversed_dir=tmp_path,
            module="SERVER",
            target_name="server",
            arch="x86_32",
        )
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        function_rows: dict[tuple[str, int], dict[str, Any]] = {
            ("SERVER", 0x1000): {"origins": {"name": {"value_hash": "stale"}}},
            ("SERVER", 0x1010): {"origins": {}},
        }
        data_rows: dict[tuple[str, int], dict[str, Any]] = {
            ("SERVER", 0x2000): {"origins": {"note": {"value_hash": "stale"}}}
        }
        loads: list[str] = []

        def load_functions(*_args: Any, **_kwargs: Any) -> dict[tuple[str, int], dict[str, Any]]:
            loads.append("function")
            return function_rows

        def load_data(*_args: Any, **_kwargs: Any) -> dict[tuple[str, int], dict[str, Any]]:
            loads.append("global")
            return data_rows

        def unexpected_granular_read(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            raise AssertionError("health scan must use its batch metadata snapshot")

        monkeypatch.setattr(state, "load_manifest", lambda _path: {})
        monkeypatch.setattr(state, "binary_identity", lambda _cfg: "")
        monkeypatch.setattr(state, "artifact_hash", lambda _path: "")
        monkeypatch.setattr(state, "load_sync_baseline", lambda *_args: {})
        monkeypatch.setattr(functions, "load_metadata", load_functions)
        monkeypatch.setattr(data, "load_data_metadata", load_data)
        monkeypatch.setattr(functions, "get_entry", unexpected_granular_read)
        monkeypatch.setattr(data, "get_data_entry", unexpected_granular_read)
        local = {
            "function.SERVER.0x1000": {"name": "one"},
            "function.SERVER.0x1010": {"name": "two"},
            "global.SERVER.0x2000": {"note": "global"},
        }

        health = state.sync_health(cfg, state_dir, local, {})

        assert sorted(loads) == ["function", "global"]
        assert {row["identity"] for row in health["stale_origins"]} == {
            "function.SERVER.0x1000",
            "global.SERVER.0x2000",
        }


class TestRecordSyncOrigins:
    def test_loads_each_store_once_for_all_changed_identities(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.binsync import state
        from rebrew.metadata import data, functions

        function_rows: dict[tuple[str, int], dict[str, Any]] = {
            ("SERVER", 0x1000): {"origins": {"size": {"tool": "verify"}}},
            ("SERVER", 0x1010): {"origins": {}},
        }
        data_rows: dict[tuple[str, int], dict[str, Any]] = {
            ("SERVER", 0x2000): {"origins": {"size": {"tool": "verify"}}}
        }
        loads: list[str] = []
        updates: dict[str, list[dict[str, Any]]] = {"function": [], "global": []}

        def load_functions(*_args: Any, **_kwargs: Any) -> dict[tuple[str, int], dict[str, Any]]:
            loads.append("function")
            return function_rows

        def load_data(*_args: Any, **_kwargs: Any) -> dict[tuple[str, int], dict[str, Any]]:
            loads.append("global")
            return data_rows

        def unexpected_granular_read(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            raise AssertionError("reconciliation must use its batch metadata snapshot")

        def save_functions(_directory: Any, rows: list[dict[str, Any]]) -> None:
            updates["function"].extend(rows)

        def save_data(_directory: Any, rows: list[dict[str, Any]]) -> None:
            updates["global"].extend(rows)

        monkeypatch.setattr(functions, "load_metadata", load_functions)
        monkeypatch.setattr(data, "load_data_metadata", load_data)
        monkeypatch.setattr(functions, "get_entry", unexpected_granular_read)
        monkeypatch.setattr(data, "get_data_entry", unexpected_granular_read)
        monkeypatch.setattr(functions, "set_fields_batch", save_functions)
        monkeypatch.setattr(data, "set_data_fields_batch", save_data)
        monkeypatch.setattr(state, "sync_origin", lambda _path: {"tool": "binsync"})
        before = {
            "function.SERVER.0x1000": {"name": "old"},
            "function.SERVER.0x1010": {"name": "unchanged"},
            "global.SERVER.0x2000": {"note": "old"},
        }
        after = {
            "function.SERVER.0x1000": {"name": "new"},
            "function.SERVER.0x1010": {"name": "unchanged"},
            "global.SERVER.0x2000": {"note": "new"},
        }
        remote = {key: dict(value) for key, value in after.items()}

        cfg: Any = SimpleNamespace(metadata_dir=tmp_path)
        state.record_sync_origins(cfg, tmp_path, before, after, remote)

        assert sorted(loads) == ["function", "global"]
        assert updates["function"] == [
            {
                "module": "SERVER",
                "va": 0x1000,
                "fields": {
                    "origins": {
                        "size": {"tool": "verify"},
                        "name": {
                            "tool": "binsync",
                            "value_hash": state.sync_value_hash("name", "new", kind="function"),
                        },
                    }
                },
                "updated_by": "binsync-import",
            }
        ]
        assert updates["global"] == [
            {
                "module": "SERVER",
                "va": 0x2000,
                "fields": {
                    "origins": {
                        "size": {"tool": "verify"},
                        "note": {
                            "tool": "binsync",
                            "value_hash": state.sync_value_hash("note", "new", kind="global"),
                        },
                    }
                },
                "updated_by": "binsync-import",
            }
        ]


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


class TestDefinitionFileScan:
    """The type-definition collectors share one tree walk, not one per collector."""

    @staticmethod
    def _cfg(tmp_path: Path) -> SimpleNamespace:
        src = tmp_path / "src"
        src.mkdir(exist_ok=True)
        (src / "point.h").write_text(
            "typedef struct { int x; int y; } Point;\n"
            "typedef enum { RED, GREEN } Color;\n"
            "typedef unsigned int uint_alias;\n",
            encoding="utf-8",
        )
        return SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            metadata_dir=tmp_path,
            source_ext=".c",
            module="GAME",
            target_name="GAME",
        )

    @staticmethod
    def _count_walks(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
        import rebrew.sources as sources

        real = sources.scan_files
        walks: list[Any] = []

        def counted(*args: Any, **kwargs: Any) -> list[Path]:
            walks.append(args)
            return real(*args, **kwargs)

        monkeypatch.setattr(sources, "scan_files", counted)
        return walks

    def test_type_records_walk_the_tree_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.binsync.state import type_sync_records

        cfg = self._cfg(tmp_path)
        walks = self._count_walks(monkeypatch)
        records = type_sync_records(cfg)  # type: ignore[arg-type]
        assert walks == [(cfg.reversed_dir,)]
        assert "struct.Point" in records
        assert "enum.Color" in records
        assert "typedef.uint_alias" in records

    def test_watch_paths_walk_the_tree_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.binsync.state import sync_watch_paths

        cfg = self._cfg(tmp_path)
        walks = self._count_walks(monkeypatch)
        paths = sync_watch_paths(cfg, tmp_path / "state")  # type: ignore[arg-type]
        assert walks == [(cfg.reversed_dir,)]
        assert cfg.reversed_dir / "point.h" in paths
