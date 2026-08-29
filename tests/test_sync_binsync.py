"""Tests for the BinSync-primary sync command (ghidra/cli.py) and the
structural MCP op builders (ghidra/commands.py)."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import rebrew.ghidra.cli as sync_cli
from rebrew.ghidra.commands import build_bookmark_commands, build_new_function_commands

runner = CliRunner()


def _cfg(tmp_path: Path) -> SimpleNamespace:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    return SimpleNamespace(
        target_binary=tmp_path / "x.dll",
        reversed_dir=src,
        root=tmp_path,
        target_name="T",
        metadata_dir=tmp_path,
        function_list=tmp_path / "functions.txt",
        marker="T",
        iat_thunks=[],
        compiler_profile="msvc6",
        source_ext=".c",
    )


def _patch_cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    cfg = _cfg(tmp_path)
    monkeypatch.setattr(sync_cli, "require_config", lambda target=None, json_mode=False: cfg)
    return cfg


class TestBuilders:
    def test_bookmark_ops_for_statuses(self) -> None:
        entries = [
            {"va": 0x1000, "status": "EXACT", "marker_type": "FUNCTION"},
            {"va": 0x2000, "status": "STUB", "marker_type": "FUNCTION"},
            {"va": 0x3000, "status": "EXACT", "marker_type": "DATA"},  # excluded
            {"va": 0x4000, "status": "", "marker_type": "FUNCTION"},  # no status
        ]
        ops = build_bookmark_commands(entries, "/x.dll")
        assert len(ops) == 2
        assert all(o["tool"] == "set-bookmark" for o in ops)
        assert ops[0]["args"]["addressOrSymbol"] == "0x00001000"
        assert ops[0]["args"]["category"] == "rebrew/exact"

    def test_create_functions_empty_registry(self) -> None:
        assert build_new_function_commands({}, "/x.dll") == []

    def test_create_functions_list_only_entry(self) -> None:
        registry = {
            0x1000: {
                "detected_by": ["list"],  # not in Ghidra → create
                "canonical_size": 64,
                "size_by_tool": {"list": 64},
            },
            0x2000: {
                "detected_by": ["list", "ghidra"],  # already there → skip
                "canonical_size": 32,
                "size_by_tool": {"list": 32},
            },
        }
        ops = build_new_function_commands(registry, "/x.dll")
        assert len(ops) == 1
        assert ops[0]["tool"] == "create-function"
        assert ops[0]["args"]["address"] == "0x00001000"


class TestSyncCli:
    def test_no_action_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_cfg(tmp_path, monkeypatch)
        r = runner.invoke(sync_cli.app, [])
        assert r.exit_code == 2
        assert "No action specified" in r.output

    def test_push_requires_state_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_cfg(tmp_path, monkeypatch)
        r = runner.invoke(sync_cli.app, ["--push"])
        assert r.exit_code == 2
        assert "--state-dir" in r.output

    def test_push_and_pull_mutually_exclusive(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_cfg(tmp_path, monkeypatch)
        r = runner.invoke(sync_cli.app, ["--push", "--pull", "--state-dir", "x"])
        assert r.exit_code == 2
        assert "mutually exclusive" in r.output

    def test_accept_flags_mutually_exclusive(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_cfg(tmp_path, monkeypatch)
        r = runner.invoke(
            sync_cli.app, ["--pull", "--state-dir", "x", "--accept-binsync", "--accept-local"]
        )
        assert r.exit_code == 2
        assert "mutually exclusive" in r.output

    def test_push_routes_to_export_state(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_cfg(tmp_path, monkeypatch)
        calls: dict = {}

        def _fake_export(cfg_, out, **kw):
            calls["out"] = out
            calls["kw"] = kw
            return {"outdir": str(out), "functions": 3, "globals": 1, "structs": 1, "empty": False}

        def _fake_print(result, *, json_output, dry_run):
            calls["printed"] = True

        monkeypatch.setattr("rebrew.binsync_export.export_state", _fake_export)
        monkeypatch.setattr("rebrew.binsync_export._print_export_result", _fake_print)
        state = tmp_path / "state"
        r = runner.invoke(sync_cli.app, ["--push", "--state-dir", str(state)])
        assert r.exit_code == 0
        assert calls["out"] == state
        assert calls["kw"]["dry_run"] is False
        assert calls["printed"]

    def test_pull_routes_to_import_state(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_cfg(tmp_path, monkeypatch)
        calls: dict = {}

        def _fake_import(cfg_, src, **kw):
            calls["src"] = src
            calls["kw"] = kw
            return {"state_dir": str(src), "applied_names": 2, "touched_vas": [0x1000]}

        def _fake_print(result, *, json_output, dry_run):
            calls["printed"] = True

        monkeypatch.setattr("rebrew.binsync_import.import_state", _fake_import)
        monkeypatch.setattr("rebrew.binsync_import._print_import_result", _fake_print)
        state = tmp_path / "state"
        r = runner.invoke(sync_cli.app, ["--pull", "--state-dir", str(state), "--create-missing"])
        assert r.exit_code == 0
        assert calls["src"] == state
        assert calls["kw"]["create_missing"] is True
        assert calls["printed"]

    def test_pull_create_functions_chains_mcp(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Option-1 chain: imported VAs are created in Ghidra via MCP."""
        _patch_cfg(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "rebrew.binsync_import.import_state",
            lambda cfg_, src, **kw: {"touched_vas": [0x1000, 0x2000]},
        )
        monkeypatch.setattr("rebrew.binsync_import._print_import_result", lambda result, **kw: None)
        monkeypatch.setattr("rebrew.ghidra.cli._probe_program_path", lambda cfg, ep, pp, j: pp)
        applied: list[dict] = []

        def _fake_apply(ops, endpoint):
            applied.extend(ops)
            return len(ops), 0

        monkeypatch.setattr("rebrew.ghidra.client.apply_commands_via_mcp", _fake_apply)
        state = tmp_path / "state"
        r = runner.invoke(sync_cli.app, ["--pull", "--state-dir", str(state), "--create-functions"])
        assert r.exit_code == 0
        assert len(applied) == 2
        assert all(o["tool"] == "create-function" for o in applied)
        assert applied[0]["args"]["address"] == "0x00001000"

    def test_create_functions_standalone(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_cfg(tmp_path, monkeypatch)
        monkeypatch.setattr("rebrew.ghidra.cli._probe_program_path", lambda cfg, ep, pp, j: pp)
        monkeypatch.setattr("rebrew.catalog.parse_function_list", lambda _p: [])
        monkeypatch.setattr(
            "rebrew.catalog.build_function_registry",
            lambda *a, **k: {
                0x1000: {"detected_by": ["list"], "canonical_size": 8, "size_by_tool": {"list": 8}}
            },
        )
        applied: list[dict] = []

        def _fake_apply(ops, endpoint):
            applied.extend(ops)
            return len(ops), 0

        monkeypatch.setattr("rebrew.ghidra.client.apply_commands_via_mcp", _fake_apply)
        r = runner.invoke(sync_cli.app, ["--create-functions"])
        assert r.exit_code == 0
        assert len(applied) == 1
        assert applied[0]["tool"] == "create-function"

    def test_summary_previews_export(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_cfg(tmp_path, monkeypatch)
        calls: dict = {}

        def _fake_export(cfg_, out, **kw):
            calls["dry_run"] = kw.get("dry_run")
            return {"outdir": str(out), "functions": 0, "globals": 0, "structs": 0, "empty": True}

        monkeypatch.setattr("rebrew.binsync_export.export_state", _fake_export)
        monkeypatch.setattr(
            "rebrew.binsync_export._print_export_result",
            lambda result, **kw: (_ for _ in ()).throw(SystemExit(0)),
        )
        state = tmp_path / "state"
        r = runner.invoke(sync_cli.app, ["--summary", "--state-dir", str(state)])
        assert calls["dry_run"] is True  # summary is a dry-run preview
        assert r.exit_code == 0
