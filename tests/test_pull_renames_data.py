"""Data-present tests for ghidra/commands.pull_ghidra_renames with mocked MCP."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest


def _cfg(tmp_path: Path, **overrides: object) -> SimpleNamespace:
    src = tmp_path / "src" / "SERVER"
    src.mkdir(parents=True, exist_ok=True)
    defaults: dict = {
        "reversed_dir": src,
        "metadata_dir": tmp_path,
        "marker": "SERVER",
        "root": tmp_path,
        "symbol_prefix": None,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _patch_mcp(
    monkeypatch: pytest.MonkeyPatch,
    *,
    functions: list | None = None,
    data_labels: list | None = None,
    plate_comments: list | None = None,
    pre_comments: list | None = None,
    offline: bool = False,
) -> None:
    """Stub httpx.Client + MCP fetch helpers in the commands namespace."""
    import rebrew.ghidra.commands as cmds

    fake_client = SimpleNamespace()

    class _FakeHttpxClient:
        def __init__(self, timeout: float = 30.0) -> None:
            pass

        def __enter__(self) -> object:
            return fake_client

        def __exit__(self, *a: object) -> None:
            return None

    monkeypatch.setattr(cmds.httpx, "Client", _FakeHttpxClient)
    if offline:
        import httpx

        def _offline(*_a: object, **_k: object) -> object:
            raise httpx.RequestError("refused", request=None)

        monkeypatch.setattr(cmds, "init_mcp_session", _offline)
    else:
        monkeypatch.setattr(cmds, "init_mcp_session", lambda *a, **k: "sess")
        monkeypatch.setattr(cmds, "fetch_all_functions", lambda *a, **k: functions or [])
        monkeypatch.setattr(cmds, "fetch_all_symbols", lambda *a, **k: data_labels or [])
        monkeypatch.setattr(cmds, "fetch_mcp_tool", lambda *a, **k: plate_comments or [])
    # Keep the data-annotation scan out of the picture (tests pass entries directly).
    monkeypatch.setattr("rebrew.data.scan_data_annotations", lambda *a, **k: [])


def _function_entry(va: str, name: str) -> dict:
    return {"va": va, "tool_name": name, "size": 0x20}


def _data_entry(va: str, name: str) -> dict:
    return {"va": va, "name": name}


def _comment_entry(va: str, comment: str) -> dict:
    return {"address": va, "comment": comment}


class TestPullDataPresent:
    def test_function_dry_run_update(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "func.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint func_10001000(void) { return 0; }\n",
            encoding="utf-8",
        )
        entries = [
            {
                "va": 0x1000,
                "symbol": "func_10001000",
                "name": "func_10001000",
                "module": "SERVER",
                "marker_type": "FUNCTION",
                "filepath": "func.c",
                "note": "",
                "ghidra": "",
            }
        ]
        _patch_mcp(monkeypatch, functions=[_function_entry("0x1000", "BetterName")])
        result = cmds.pull_ghidra_renames(entries, cfg, dry_run=True)
        assert result.updated == 1
        assert result.changes[0].action == "update"
        assert result.changes[0].ghidra_value == "BetterName"

    def test_data_entry_real_update_writes_metadata(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.ghidra.commands as cmds
        from rebrew.data_metadata import load_data_metadata

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "globals.c").write_text(
            "// DATA: SERVER 0x1000\nint g_old;\n", encoding="utf-8"
        )
        entries = [
            {
                "va": 0x1000,
                "symbol": "g_old",
                "name": "g_old",
                "module": "SERVER",
                "marker_type": "DATA",
                "filepath": "globals.c",
                "note": "",
                "ghidra": "",
            }
        ]
        _patch_mcp(monkeypatch, data_labels=[_data_entry("0x1000", "g_new")])
        result = cmds.pull_ghidra_renames(entries, cfg, dry_run=False, accept_ghidra=True)
        assert result.updated == 1
        assert result.changes[0].field == "NAME"
        assert result.changes[0].action == "update"
        # Name landed in rebrew-data.toml at the metadata root (not reversed_dir).
        meta = load_data_metadata(cfg.metadata_dir)
        assert any(m.get("name") == "g_new" for m in meta.values())
        assert load_data_metadata(cfg.reversed_dir) == {}

    def test_meaningful_conflict(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "func.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint func_a(void) { return 0; }\n",
            encoding="utf-8",
        )
        entries = [
            {
                "va": 0x1000,
                "symbol": "_parse_message",
                "name": "parse_message",
                "module": "SERVER",
                "marker_type": "FUNCTION",
                "filepath": "func.c",
                "note": "",
                "ghidra": "",
            }
        ]
        _patch_mcp(monkeypatch, functions=[_function_entry("0x1000", "GhidraName")])
        result = cmds.pull_ghidra_renames(entries, cfg, dry_run=True)
        assert result.updated == 0
        assert result.conflicts == 1
        assert result.changes[0].action == "conflict"

    def test_accept_local_records_ghidra(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.ghidra.commands as cmds
        from rebrew.metadata import get_entry

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "func.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint func_a(void) { return 0; }\n",
            encoding="utf-8",
        )
        entries = [
            {
                "va": 0x1000,
                "symbol": "_parse_message",
                "name": "parse_message",
                "module": "SERVER",
                "marker_type": "FUNCTION",
                "filepath": "func.c",
                "note": "",
                "ghidra": "",
            }
        ]
        _patch_mcp(monkeypatch, functions=[_function_entry("0x1000", "GhidraName")])
        result = cmds.pull_ghidra_renames(entries, cfg, dry_run=False, accept_local=True)
        assert result.updated == 1
        assert result.changes[0].action == "update (keep local)"
        entry = get_entry(cfg.metadata_dir, 0x1000, "SERVER")
        assert entry.get("ghidra") == "GhidraName"

    def test_existing_ghidra_annotation_skips(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "func.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint func_a(void) { return 0; }\n",
            encoding="utf-8",
        )
        entries = [
            {
                "va": 0x1000,
                "symbol": "_parse_message",
                "name": "parse_message",
                "module": "SERVER",
                "marker_type": "FUNCTION",
                "filepath": "func.c",
                "note": "",
                "ghidra": "GhidraName",  # conflict already tracked
            }
        ]
        _patch_mcp(monkeypatch, functions=[_function_entry("0x1000", "GhidraName")])
        result = cmds.pull_ghidra_renames(entries, cfg, dry_run=True)
        assert result.updated == 0
        assert result.conflicts == 0

    def test_underscore_only_difference_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "func.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint func_a(void) { return 0; }\n",
            encoding="utf-8",
        )
        entries = [
            {
                "va": 0x1000,
                "symbol": "_parse_message",
                "name": "parse_message",
                "module": "SERVER",
                "marker_type": "FUNCTION",
                "filepath": "func.c",
                "note": "",
                "ghidra": "",
            }
        ]
        _patch_mcp(monkeypatch, functions=[_function_entry("0x1000", "func_a")])
        result = cmds.pull_ghidra_renames(entries, cfg, dry_run=True)
        assert result.updated == 0
        assert result.conflicts == 0

    def test_filter_origin_skips(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "func.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint func_10001000(void) { return 0; }\n",
            encoding="utf-8",
        )
        entries = [
            {
                "va": 0x1000,
                "symbol": "func_10001000",
                "name": "func_10001000",
                "module": "SERVER",
                "marker_type": "FUNCTION",
                "filepath": "func.c",
                "note": "",
                "ghidra": "",
            }
        ]
        _patch_mcp(monkeypatch, functions=[_function_entry("0x1000", "BetterName")])
        result = cmds.pull_ghidra_renames(entries, cfg, dry_run=True, filter_origin="OTHER")
        assert result.updated == 0

    def test_generic_ghidra_name_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "func.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint func_10001000(void) { return 0; }\n",
            encoding="utf-8",
        )
        entries = [
            {
                "va": 0x1000,
                "symbol": "func_10001000",
                "name": "func_10001000",
                "module": "SERVER",
                "marker_type": "FUNCTION",
                "filepath": "func.c",
                "note": "",
                "ghidra": "",
            }
        ]
        _patch_mcp(monkeypatch, functions=[_function_entry("0x1000", "FUN_10001000")])
        result = cmds.pull_ghidra_renames(entries, cfg, dry_run=True)
        assert result.updated == 0

    def test_note_update_real(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.ghidra.commands as cmds
        from rebrew.metadata import get_entry

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "func.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint func_10001000(void) { return 0; }\n",
            encoding="utf-8",
        )
        entries = [
            {
                "va": 0x1000,
                "symbol": "func_10001000",
                "name": "func_10001000",
                "module": "SERVER",
                "marker_type": "FUNCTION",
                "filepath": "func.c",
                "note": "",
                "ghidra": "",
            }
        ]
        _patch_mcp(
            monkeypatch,
            functions=[_function_entry("0x1000", "func_10001000")],
            plate_comments=[_comment_entry("0x1000", "hello world")],
        )
        result = cmds.pull_ghidra_renames(entries, cfg, dry_run=False)
        assert result.updated == 1
        assert result.changes[0].field == "NOTE"
        entry = get_entry(cfg.metadata_dir, 0x1000, "SERVER")
        assert entry.get("note") == "hello world"

    def test_note_update_dry_run(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "func.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint func_10001000(void) { return 0; }\n",
            encoding="utf-8",
        )
        entries = [
            {
                "va": 0x1000,
                "symbol": "func_10001000",
                "name": "func_10001000",
                "module": "SERVER",
                "marker_type": "FUNCTION",
                "filepath": "func.c",
                "note": "old note",
                "ghidra": "",
            }
        ]
        _patch_mcp(
            monkeypatch,
            functions=[_function_entry("0x1000", "func_10001000")],
            plate_comments=[_comment_entry("0x1000", "new note")],
        )
        result = cmds.pull_ghidra_renames(entries, cfg, dry_run=True)
        assert result.updated == 1
        assert result.changes[0].action == "update"
        # Nothing written in dry-run.
        from rebrew.metadata import get_entry

        assert get_entry(cfg.metadata_dir, 0x1000, "SERVER") == {}

    def test_rebrew_comment_skipped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "func.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint func_10001000(void) { return 0; }\n",
            encoding="utf-8",
        )
        entries = [
            {
                "va": 0x1000,
                "symbol": "func_10001000",
                "name": "func_10001000",
                "module": "SERVER",
                "marker_type": "FUNCTION",
                "filepath": "func.c",
                "note": "",
                "ghidra": "",
            }
        ]
        _patch_mcp(
            monkeypatch,
            functions=[_function_entry("0x1000", "func_10001000")],
            plate_comments=[_comment_entry("0x1000", "[rebrew] generated")],
        )
        result = cmds.pull_ghidra_renames(entries, cfg, dry_run=True)
        assert result.updated == 0

    def test_no_changes_message(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        _patch_mcp(monkeypatch)
        result = cmds.pull_ghidra_renames([], cfg, dry_run=True)
        assert result.updated == 0


class TestPullOfflineCache:
    def test_function_cache_loaded_offline(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "func.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint func_10001000(void) { return 0; }\n",
            encoding="utf-8",
        )
        (cfg.reversed_dir / "function_structure.json").write_text(
            json.dumps([_function_entry("0x1000", "CachedName")]), encoding="utf-8"
        )
        entries = [
            {
                "va": 0x1000,
                "symbol": "func_10001000",
                "name": "func_10001000",
                "module": "SERVER",
                "marker_type": "FUNCTION",
                "filepath": "func.c",
                "note": "",
                "ghidra": "",
            }
        ]
        _patch_mcp(monkeypatch, offline=True)
        result = cmds.pull_ghidra_renames(entries, cfg, dry_run=True)
        assert result.updated == 1
        assert result.changes[0].ghidra_value == "CachedName"

    def test_broken_cache_ignored(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "function_structure.json").write_text("{broken", encoding="utf-8")
        _patch_mcp(monkeypatch, offline=True)
        result = cmds.pull_ghidra_renames([], cfg, dry_run=True)
        assert result.updated == 0

    def test_data_label_cache_loaded_offline(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "globals.c").write_text(
            "// DATA: SERVER 0x1000\nint g_old;\n", encoding="utf-8"
        )
        (cfg.reversed_dir / "ghidra_data_labels.json").write_text(
            json.dumps([_data_entry("0x1000", "g_cached")]), encoding="utf-8"
        )
        entries = [
            {
                "va": 0x1000,
                "symbol": "g_old",
                "name": "g_old",
                "module": "SERVER",
                "marker_type": "DATA",
                "filepath": "globals.c",
                "note": "",
                "ghidra": "",
            }
        ]
        _patch_mcp(monkeypatch, offline=True)
        result = cmds.pull_ghidra_renames(entries, cfg, dry_run=True, accept_ghidra=True)
        assert result.updated == 1
        assert result.changes[0].ghidra_value == "g_cached"


class TestPullEdgeCases:
    def test_missing_filepath_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        entries = [
            {
                "va": 0x1000,
                "symbol": "func_10001000",
                "name": "func_10001000",
                "module": "SERVER",
                "marker_type": "FUNCTION",
                "filepath": "missing.c",  # does not exist
                "note": "",
                "ghidra": "",
            }
        ]
        _patch_mcp(monkeypatch, functions=[_function_entry("0x1000", "BetterName")])
        result = cmds.pull_ghidra_renames(entries, cfg, dry_run=True)
        assert result.updated == 0

    def test_path_traversal_skipped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        # File exists but resolves OUTSIDE reversed_dir → guarded.
        (tmp_path / "src" / "escape.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint escape(void) { return 0; }\n",
            encoding="utf-8",
        )
        entries = [
            {
                "va": 0x1000,
                "symbol": "escape",
                "name": "escape",
                "module": "SERVER",
                "marker_type": "FUNCTION",
                "filepath": "../escape.c",  # resolves outside src/SERVER
                "note": "",
                "ghidra": "",
            }
        ]
        _patch_mcp(monkeypatch, functions=[_function_entry("0x1000", "BetterName")])
        result = cmds.pull_ghidra_renames(entries, cfg, dry_run=True)
        assert result.updated == 0

    def test_json_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:

        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        _patch_mcp(monkeypatch)
        result = cmds.pull_ghidra_renames([], cfg, dry_run=True, json_output=True)
        assert result.updated == 0

    def test_bad_function_va_ignored(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "func.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint func_10001000(void) { return 0; }\n",
            encoding="utf-8",
        )
        entries = [
            {
                "va": 0x1000,
                "symbol": "func_10001000",
                "name": "func_10001000",
                "module": "SERVER",
                "marker_type": "FUNCTION",
                "filepath": "func.c",
                "note": "",
                "ghidra": "",
            }
        ]
        _patch_mcp(
            monkeypatch,
            functions=[
                _function_entry("0x1000", "Good"),
                _function_entry("zzz", "Bad"),  # unparseable VA → ignored
            ],
        )
        result = cmds.pull_ghidra_renames(entries, cfg, dry_run=True)
        assert result.updated == 1
