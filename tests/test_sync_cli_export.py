"""Tests for ghidra/cli.py sync command surface (export path)."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import rebrew.ghidra.cli as sync_cli

runner = CliRunner()


def _patch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> SimpleNamespace:
    cfg = SimpleNamespace(
        root=tmp_path,
        reversed_dir=tmp_path / "src",
        metadata_dir=tmp_path,
        marker="SERVER",
        iat_thunks=[],
        target_name="T",
        source_ext=".c",
    )
    cfg.reversed_dir.mkdir(exist_ok=True)
    monkeypatch.setattr(sync_cli, "require_config", lambda target=None, json_mode=False: cfg)
    monkeypatch.setattr(sync_cli, "scan_reversed_dir", lambda _d, cfg=None: [])
    monkeypatch.setattr(sync_cli, "resolve_program_path", lambda cfg: "game.exe")
    monkeypatch.setattr(
        sync_cli,
        "build_sync_commands",
        lambda *a, **k: [{"tool": "create-label", "name": "x"}],
    )
    return cfg


class TestSyncExport:
    def test_export_writes_commands_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch(monkeypatch, tmp_path)
        r = runner.invoke(sync_cli.app, ["--export"])
        assert r.exit_code == 0
        out = tmp_path / "ghidra_commands.json"
        assert out.exists()
        payload = json.loads(out.read_text())
        assert payload == [{"tool": "create-label", "name": "x"}]

    def test_dry_run_writes_nothing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """--dry-run must not materialize ghidra_commands.json — it is a
        multi-hundred-KB artifact and the flag promises "Preview changes
        without writing"."""
        _patch(monkeypatch, tmp_path)
        r = runner.invoke(sync_cli.app, ["--push", "--dry-run", "--json"])
        assert r.exit_code == 0
        payload = json.loads(r.stdout)
        assert payload["dry_run"] is True
        assert payload["operations"] == 1
        assert not (tmp_path / "ghidra_commands.json").exists()

    def test_no_action_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, tmp_path)
        r = runner.invoke(sync_cli.app, [])
        assert r.exit_code != 0
