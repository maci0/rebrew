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

    def test_bookmark_at_va_zero(self) -> None:
        """16-bit targets place functions at VA 0; dropping it loses the bookmark."""
        entries = [{"va": 0, "status": "EXACT", "marker_type": "FUNCTION"}]
        ops = build_bookmark_commands(entries, "/x.dll")
        assert len(ops) == 1
        assert ops[0]["args"]["addressOrSymbol"] == "0x00000000"

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

        monkeypatch.setattr("rebrew.binsync.export.export_state", _fake_export)
        monkeypatch.setattr("rebrew.binsync.export._print_export_result", _fake_print)
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

        monkeypatch.setattr("rebrew.binsync.importer.import_state", _fake_import)
        monkeypatch.setattr("rebrew.binsync.importer._print_import_result", _fake_print)
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
            "rebrew.binsync.importer.import_state",
            lambda cfg_, src, **kw: {"touched_vas": [0x1000, 0x2000]},
        )
        monkeypatch.setattr(
            "rebrew.binsync.importer._print_import_result", lambda result, **kw: None
        )
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

    def test_create_functions_dry_run_does_not_apply(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--dry-run previews the MCP ops: no POST, and no Ghidra round-trip."""
        _patch_cfg(tmp_path, monkeypatch)

        def _must_not_probe(*_a, **_k):
            raise AssertionError("dry run must not contact Ghidra")

        monkeypatch.setattr(sync_cli, "_probe_program_path", _must_not_probe)
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
        r = runner.invoke(sync_cli.app, ["--create-functions", "--dry-run"])
        assert r.exit_code == 0
        assert applied == []
        assert "Would apply 1 operation(s)" in r.output

    def test_bookmarks_dry_run_does_not_apply(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--dry-run on --bookmarks must not set bookmarks in Ghidra."""
        _patch_cfg(tmp_path, monkeypatch)

        def _must_not_probe(*_a, **_k):
            raise AssertionError("dry run must not contact Ghidra")

        monkeypatch.setattr(sync_cli, "_probe_program_path", _must_not_probe)
        monkeypatch.setattr(
            "rebrew.catalog.scan_reversed_dir",
            lambda *_a, **_k: [{"va": 0x1000, "status": "EXACT", "marker_type": "FUNCTION"}],
        )
        applied: list[dict] = []

        def _fake_apply(ops, endpoint):
            applied.extend(ops)
            return len(ops), 0

        monkeypatch.setattr("rebrew.ghidra.client.apply_commands_via_mcp", _fake_apply)
        r = runner.invoke(sync_cli.app, ["--bookmarks", "--dry-run"])
        assert r.exit_code == 0
        assert applied == []
        assert "Would apply 1 operation(s)" in r.output

    def test_summary_previews_export(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_cfg(tmp_path, monkeypatch)
        calls: dict = {}

        def _fake_export(cfg_, out, **kw):
            calls["dry_run"] = kw.get("dry_run")
            return {"outdir": str(out), "functions": 0, "globals": 0, "structs": 0, "empty": True}

        monkeypatch.setattr("rebrew.binsync.export.export_state", _fake_export)
        monkeypatch.setattr(
            "rebrew.binsync.export._print_export_result",
            lambda result, **kw: (_ for _ in ()).throw(SystemExit(0)),
        )
        state = tmp_path / "state"
        r = runner.invoke(sync_cli.app, ["--summary", "--state-dir", str(state)])
        assert calls["dry_run"] is True  # summary is a dry-run preview
        assert r.exit_code == 0


class TestMcpApplyFallback:
    """_mcp_apply falls back MCP->cli only when nothing was applied; after
    partial application it errors instead of re-applying."""

    def _ops(self) -> list[dict]:
        return [
            {"tool": "create-function", "args": {"address": "0x1000"}},
            {"tool": "create-function", "args": {"address": "0x2000"}},
        ]

    def test_clean_failure_falls_back_to_cli(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Transport dead before anything landed: CLI backend applies the ops."""

        cfg = _cfg(tmp_path)
        monkeypatch.setattr(
            "rebrew.ghidra.client.apply_commands_via_mcp",
            lambda ops, endpoint: (_ for _ in ()).throw(OSError("conn refused")),
        )
        applied: list[list[dict]] = []
        monkeypatch.setattr(
            "rebrew.ghidra.cli_backend.apply_commands_via_cli",
            lambda ops, **kw: applied.append(ops) or (len(ops), 0),
        )
        sync_cli._mcp_apply(self._ops(), "http://x", "/prog", False, cfg)
        assert applied == [self._ops()]

    def test_partial_application_errors_instead(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        """McpApplyAborted (ops landed): error, never re-apply via CLI."""
        from typer import Exit

        from rebrew.ghidra.client import McpApplyAborted

        def _boom(ops: list[dict], endpoint: str) -> tuple[int, int]:
            raise McpApplyAborted("transport failed at op 2/2", applied=2, errors=1)

        monkeypatch.setattr("rebrew.ghidra.client.apply_commands_via_mcp", _boom)
        cli_calls: list[list[dict]] = []
        monkeypatch.setattr(
            "rebrew.ghidra.cli_backend.apply_commands_via_cli",
            lambda ops, **kw: cli_calls.append(ops) or (0, 0),
        )
        with pytest.raises(Exit) as excinfo:
            sync_cli._mcp_apply(self._ops(), "http://x", "/prog", False, None)
        assert excinfo.value.exit_code == 2
        assert cli_calls == [], "CLI fallback must not re-apply partial ops"
        assert "may have been applied" in capsys.readouterr().err

    def test_partial_application_json_error(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        """The abort error honors --json with the error/code envelope."""
        import json

        from typer import Exit

        from rebrew.ghidra.client import McpApplyAborted

        def _boom(ops: list[dict], endpoint: str) -> tuple[int, int]:
            raise McpApplyAborted("transport failed at op 2/2", applied=2, errors=1)

        monkeypatch.setattr("rebrew.ghidra.client.apply_commands_via_mcp", _boom)
        with pytest.raises(Exit):
            sync_cli._mcp_apply(self._ops(), "http://x", "/prog", True, None)
        data = json.loads(capsys.readouterr().out)
        assert data["code"] == 2
        assert "may have been applied" in data["error"]
