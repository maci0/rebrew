"""CLI-level tests for ghidra/cli.py main() dispatch (probe, pull, summary, apply)."""

import json
from types import SimpleNamespace

import pytest
import typer
from typer.testing import CliRunner

from rebrew.cli import EXIT_ERROR, EXIT_MISMATCH
from rebrew.ghidra.cli import app

runner = CliRunner()


class _FakeResp:
    def __init__(self, *, headers: dict | None = None) -> None:
        self.headers = headers or {"content-type": "application/json"}
        self.status_code = 200
        self.text = ""

    def raise_for_status(self) -> None:
        return None


class _FakeClient:
    def __init__(self, script: list) -> None:
        self._script = list(script)

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def post(self, *_a: object, **_k: object) -> object:
        return self._script.pop(0)


def _make_cfg(tmp_path: pytest.TempPathFactory) -> SimpleNamespace:
    src = tmp_path / "src" / "SERVER"
    src.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(
        target_name="SERVER",
        reversed_dir=src,
        metadata_dir=tmp_path,
        marker="SERVER",
        root=tmp_path,
        source_ext=".c",
        target_binary=tmp_path / "fake.dll",
        function_list=tmp_path / "funcs.json",
        iat_thunks=set(),
        dll_exports={},
        ghidra_program_path="",
    )


def _entry(
    va: int = 0x10001000,
    *,
    module: str = "SERVER",
    marker_type: str = "FUNCTION",
    symbol: str = "_my_func",
    name: str = "my_func",
    status: str = "RELOC",
    size: int = 100,
) -> dict:
    return {
        "va": va,
        "module": module,
        "marker_type": marker_type,
        "symbol": symbol,
        "name": name,
        "status": status,
        "size": size,
        "origin": "GAME",
        "filepath": "src/SERVER/my_func.c",
    }


def _patch_probe(
    monkeypatch: pytest.MonkeyPatch,
    *,
    session: str = "sess-1",
    program_path: str = "/server.dll",
    raise_error: bool = False,
) -> None:
    monkeypatch.setattr("rebrew.ghidra.cli.httpx.Client", lambda **kw: _FakeClient([_FakeResp()]))
    monkeypatch.setattr("rebrew.ghidra.cli.init_mcp_session", lambda c, e: session)

    def _validate(*_a: object, **_k: object) -> str:
        if raise_error:
            raise ValueError("no MCP")
        return program_path

    monkeypatch.setattr("rebrew.ghidra.cli.validate_program_path", _validate)


class TestProbeAndPullDispatch:
    def test_types_out_by_module_conflict(self, tmp_path: pytest.TempPathFactory) -> None:
        cfg = _make_cfg(tmp_path)
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr("rebrew.ghidra.cli.require_config", lambda **kw: cfg)
        try:
            result = runner.invoke(app, ["--pull-structs", "--types-out", "types.h", "--by-module"])
        finally:
            monkeypatch.undo()
        assert result.exit_code != 0
        assert "mutually exclusive" in result.output

    def test_pull_uses_validated_program_path(
        self, tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.ghidra.cli.require_config", lambda **kw: cfg)
        monkeypatch.setattr("rebrew.ghidra.cli.scan_reversed_dir", lambda d, cfg=None: [])
        _patch_probe(monkeypatch, program_path="/validated/path")
        seen: dict = {}

        def _pull(*a: object, **kw: object) -> SimpleNamespace:
            seen["args"] = a
            seen.update(kw)
            return SimpleNamespace(conflicts=0)

        monkeypatch.setattr("rebrew.ghidra.cli.pull_ghidra_renames", _pull)
        result = runner.invoke(app, ["--pull", "--dry-run", "--json"])
        assert result.exit_code == 0
        assert seen["args"][3] == "/validated/path"  # positional program_path
        assert seen["json_output"] is True

    def test_pull_probe_failure_falls_back(
        self, tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.ghidra.cli.require_config", lambda **kw: cfg)
        monkeypatch.setattr("rebrew.ghidra.cli.scan_reversed_dir", lambda d, cfg=None: [])
        _patch_probe(monkeypatch, raise_error=True)
        seen: dict = {}

        def _pull(*a: object, **kw: object) -> SimpleNamespace:
            seen["args"] = a
            seen.update(kw)
            return SimpleNamespace(conflicts=0)

        monkeypatch.setattr("rebrew.ghidra.cli.pull_ghidra_renames", _pull)
        result = runner.invoke(app, ["--pull", "--dry-run", "--json"])
        assert result.exit_code == 0
        assert seen["args"][3] == "/fake.dll"  # derived from binary name

    def test_pull_conflicts_message(
        self, tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.ghidra.cli.require_config", lambda **kw: cfg)
        monkeypatch.setattr("rebrew.ghidra.cli.scan_reversed_dir", lambda d, cfg=None: [])
        _patch_probe(monkeypatch)
        monkeypatch.setattr(
            "rebrew.ghidra.cli.pull_ghidra_renames",
            lambda *_a, **kw: SimpleNamespace(conflicts=2),
        )
        result = runner.invoke(app, ["--pull", "--json"])
        assert result.exit_code == 0
        assert "Conflicts detected during name pull" in result.output

    def test_extended_pull_dispatch(
        self, tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--pull-signatures/--pull-structs/--pull-comments/--pull-data dispatch."""
        cfg = _make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.ghidra.cli.require_config", lambda **kw: cfg)
        monkeypatch.setattr("rebrew.ghidra.cli.scan_reversed_dir", lambda d, cfg=None: [])
        _patch_probe(monkeypatch)
        calls: dict[str, list] = {
            "prototypes": [],
            "structs": [],
            "comments": [],
            "data": [],
        }

        def _proto(*a: object, **k: object) -> None:
            calls["prototypes"].append((a, k))

        def _structs(*a: object, **k: object) -> None:
            calls["structs"].append((a, k))

        def _comments(*a: object, **k: object) -> None:
            calls["comments"].append((a, k))

        def _data(*a: object, **k: object) -> None:
            calls["data"].append((a, k))

        monkeypatch.setattr("rebrew.ghidra.cli.pull_prototypes_cmd", _proto)
        monkeypatch.setattr("rebrew.ghidra.cli.pull_structs_cmd", _structs)
        monkeypatch.setattr("rebrew.ghidra.cli.pull_comments_cmd", _comments)
        monkeypatch.setattr("rebrew.ghidra.cli.pull_data_cmd", _data)

        result = runner.invoke(
            app,
            [
                "--pull-signatures",
                "--pull-structs",
                "--by-module",
                "--pull-comments",
                "--pull-data",
            ],
        )
        assert result.exit_code == 0
        assert len(calls["prototypes"]) == 1
        assert len(calls["structs"]) == 1
        assert len(calls["comments"]) == 1
        assert len(calls["data"]) == 1
        # pull_structs_cmd receives types_out/by_module keywords (cfg, endpoint,
        # program_path, dry_run are positional).
        _args, kwargs = calls["structs"][0]
        assert kwargs["by_module"] is True
        assert _args[3] is False  # dry_run positional


class TestSummary:
    def _setup(self, tmp_path, monkeypatch, entries) -> SimpleNamespace:
        cfg = _make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.ghidra.cli.require_config", lambda **kw: cfg)
        monkeypatch.setattr("rebrew.ghidra.cli.scan_reversed_dir", lambda d, cfg=None: entries)
        return cfg

    def test_summary_json_counts(self, tmp_path: pytest.TempPathFactory, monkeypatch) -> None:
        entries = [
            _entry(0x10001000),
            _entry(0x10002000, marker_type="DATA", symbol="g_data", name="g_data", status="EXACT"),
        ]
        self._setup(tmp_path, monkeypatch, entries)
        result = runner.invoke(app, ["--summary", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["entries"] == 2
        assert data["unique_vas"] == 2
        assert data["by_module"] == {"SERVER": 2}
        assert data["operations"]["total"] >= 1
        assert data["operations"]["create_function"] == 1  # DATA entries skip create-function

    def test_summary_text_output(self, tmp_path: pytest.TempPathFactory, monkeypatch) -> None:
        entries = [_entry(0x10001000)]
        self._setup(tmp_path, monkeypatch, entries)
        result = runner.invoke(app, ["--summary"])
        assert result.exit_code == 0
        assert "Annotations: 1 entries, 1 unique VAs" in result.output
        assert "Total:" in result.output


class TestExportAndApply:
    def _setup(self, tmp_path, monkeypatch, entries=None, commands=None) -> SimpleNamespace:
        cfg = _make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.ghidra.cli.require_config", lambda **kw: cfg)
        monkeypatch.setattr(
            "rebrew.ghidra.cli.scan_reversed_dir",
            lambda d, cfg=None: entries if entries is not None else [],
        )
        if commands is not None:
            (cfg.root / "ghidra_commands.json").write_text(json.dumps(commands), encoding="utf-8")
        return cfg

    def test_export_writes_commands_file(
        self, tmp_path: pytest.TempPathFactory, monkeypatch
    ) -> None:
        cfg = self._setup(tmp_path, monkeypatch, entries=[_entry(0x10001000)])
        result = runner.invoke(app, ["--export"])
        assert result.exit_code == 0
        out = cfg.root / "ghidra_commands.json"
        assert out.exists()
        assert len(json.loads(out.read_text(encoding="utf-8"))) > 0
        assert "Exported" in result.output

    def test_apply_dry_run_json(self, tmp_path: pytest.TempPathFactory, monkeypatch) -> None:
        self._setup(tmp_path, monkeypatch)
        result = runner.invoke(app, ["--apply", "--dry-run", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == {
            "dry_run": True,
            "operations": 0,
            "endpoint": "http://localhost:8080/mcp/message",
        }

    def test_apply_missing_commands_file(
        self, tmp_path: pytest.TempPathFactory, monkeypatch
    ) -> None:
        self._setup(tmp_path, monkeypatch)
        result = runner.invoke(app, ["--apply"])
        assert result.exit_code != 0
        assert "not found. Run --export first." in result.output

    def test_apply_bad_json_errors(self, tmp_path: pytest.TempPathFactory, monkeypatch) -> None:
        cfg = self._setup(tmp_path, monkeypatch)
        (cfg.root / "ghidra_commands.json").write_text("{not json", encoding="utf-8")
        result = runner.invoke(app, ["--apply"])
        assert result.exit_code != 0
        assert "Failed to read" in result.output

    def test_apply_success(self, tmp_path: pytest.TempPathFactory, monkeypatch) -> None:
        self._setup(
            tmp_path,
            monkeypatch,
            commands=[{"tool": "create-label", "args": {"address": "0x1"}}],
        )
        monkeypatch.setattr(
            "rebrew.ghidra.cli.apply_commands_via_mcp", lambda cmds, endpoint="": (1, 0)
        )
        result = runner.invoke(app, ["--apply"])
        assert result.exit_code == 0
        assert "Applied 1/1 operations successfully" in result.output

    def test_apply_errors_exit_mismatch(
        self, tmp_path: pytest.TempPathFactory, monkeypatch
    ) -> None:
        self._setup(
            tmp_path,
            monkeypatch,
            commands=[{"tool": "create-label", "args": {"address": "0x1"}}],
        )
        monkeypatch.setattr(
            "rebrew.ghidra.cli.apply_commands_via_mcp", lambda cmds, endpoint="": (1, 1)
        )
        result = runner.invoke(app, ["--apply"])
        assert result.exit_code == EXIT_MISMATCH
        assert "1 operations failed" in result.output

    def test_apply_mcp_connection_error_exits_clean(
        self, tmp_path: pytest.TempPathFactory, monkeypatch
    ) -> None:
        """A RuntimeError from the MCP backend (connection refused) must exit
        with EXIT_ERROR and a clean message — NOT escape to main.py's catch-all,
        which re-raises typer.Exit outside click's handler (raw traceback +
        wrong exit code)."""
        self._setup(
            tmp_path,
            monkeypatch,
            commands=[{"tool": "create-label", "args": {"address": "0x1"}}],
        )

        def _boom(cmds, endpoint=""):
            raise RuntimeError("Failed to initialize MCP session: [Errno 111] Connection refused")

        monkeypatch.setattr("rebrew.ghidra.cli.apply_commands_via_mcp", _boom)
        result = runner.invoke(app, ["--apply"])
        assert result.exit_code == EXIT_ERROR
        assert "Failed to initialize MCP session" in result.output
        assert "Traceback" not in result.output


class TestRefreshCacheAndSizes:
    def test_refresh_cache_json(self, tmp_path: pytest.TempPathFactory, monkeypatch) -> None:
        cfg = _make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.ghidra.cli.require_config", lambda **kw: cfg)
        monkeypatch.setattr("rebrew.ghidra.cli.scan_reversed_dir", lambda d, cfg=None: [])
        _patch_probe(monkeypatch)
        monkeypatch.setattr("rebrew.ghidra.cli._refresh_structure_cache", lambda *a, **k: ["fn1"])
        monkeypatch.setattr("rebrew.ghidra.cli._refresh_data_labels_cache", lambda *a, **k: ["dl1"])
        result = runner.invoke(app, ["--refresh-cache", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["function_count"] == 1
        assert data["data_label_count"] == 1

    def test_sync_sizes_empty(self, tmp_path: pytest.TempPathFactory, monkeypatch) -> None:
        cfg = _make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.ghidra.cli.require_config", lambda **kw: cfg)
        monkeypatch.setattr("rebrew.ghidra.cli.scan_reversed_dir", lambda d, cfg=None: [])
        monkeypatch.setattr("rebrew.ghidra.cli.parse_function_list", lambda p: [])
        monkeypatch.setattr("rebrew.ghidra.cli.build_function_registry", lambda *a, **k: {})
        monkeypatch.setattr("rebrew.ghidra.cli.build_size_sync_commands", lambda *a, **k: [])
        monkeypatch.setattr("rebrew.ghidra.cli.build_new_function_commands", lambda *a, **k: [])
        result = runner.invoke(app, ["--sync-sizes", "--sync-new-functions"])
        assert result.exit_code == 0
        assert "Size sync: 0 functions need boundary expansion" in result.output
        assert "New functions: 0 list-only functions to create in Ghidra" in result.output

    def test_sync_sizes_exports_commands(
        self, tmp_path: pytest.TempPathFactory, monkeypatch
    ) -> None:
        cfg = _make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.ghidra.cli.require_config", lambda **kw: cfg)
        monkeypatch.setattr("rebrew.ghidra.cli.scan_reversed_dir", lambda d, cfg=None: [])
        monkeypatch.setattr("rebrew.ghidra.cli.parse_function_list", lambda p: [])
        monkeypatch.setattr("rebrew.ghidra.cli.build_function_registry", lambda *a, **k: {})
        monkeypatch.setattr(
            "rebrew.ghidra.cli.build_size_sync_commands",
            lambda *a, **k: [
                {
                    "tool": "set-function-size",
                    "args": {"address": "0x1000", "size": 128},
                    "_meta": {"ghidra_size": 64, "canonical_size": 128, "reason": "expand"},
                }
            ],
        )
        monkeypatch.setattr("rebrew.ghidra.cli.build_new_function_commands", lambda *a, **k: [])
        result = runner.invoke(app, ["--sync-sizes"])
        assert result.exit_code == 0
        out = cfg.root / "ghidra_size_commands.json"
        assert out.exists()
        cmds = json.loads(out.read_text(encoding="utf-8"))
        assert len(cmds) == 1
        # _meta is popped before export.
        assert "_meta" not in cmds[0]
        assert "Exported 1 operations to" in result.output

    def test_sync_new_functions_prints_meta(
        self, tmp_path: pytest.TempPathFactory, monkeypatch
    ) -> None:
        cfg = _make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.ghidra.cli.require_config", lambda **kw: cfg)
        monkeypatch.setattr("rebrew.ghidra.cli.scan_reversed_dir", lambda d, cfg=None: [])
        monkeypatch.setattr("rebrew.ghidra.cli.parse_function_list", lambda p: [])
        monkeypatch.setattr("rebrew.ghidra.cli.build_function_registry", lambda *a, **k: {})
        monkeypatch.setattr("rebrew.ghidra.cli.build_size_sync_commands", lambda *a, **k: [])
        monkeypatch.setattr(
            "rebrew.ghidra.cli.build_new_function_commands",
            lambda *a, **k: [
                {
                    "tool": "create-function",
                    "args": {"address": "0x2000"},
                    "_meta": {"list_size": 32},
                }
            ],
        )
        result = runner.invoke(app, ["--sync-new-functions"])
        assert result.exit_code == 0
        assert "New functions: 1 list-only functions to create in Ghidra" in result.output
        assert "0x2000: list size 32" in result.output

    def test_sync_sizes_push_error_exits(
        self, tmp_path: pytest.TempPathFactory, monkeypatch
    ) -> None:
        cfg = _make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.ghidra.cli.require_config", lambda **kw: cfg)
        monkeypatch.setattr("rebrew.ghidra.cli.scan_reversed_dir", lambda d, cfg=None: [])
        _patch_probe(monkeypatch)
        monkeypatch.setattr("rebrew.ghidra.cli.parse_function_list", lambda p: [])
        monkeypatch.setattr("rebrew.ghidra.cli.build_function_registry", lambda *a, **k: {})
        monkeypatch.setattr(
            "rebrew.ghidra.cli.build_size_sync_commands",
            lambda *a, **k: [
                {
                    "tool": "set-function-size",
                    "args": {"address": "0x1000", "size": 128},
                    "_meta": {"ghidra_size": 64, "canonical_size": 128, "reason": "expand"},
                }
            ],
        )
        monkeypatch.setattr("rebrew.ghidra.cli.build_new_function_commands", lambda *a, **k: [])
        # First apply (ghidra_commands.json) succeeds; size apply fails.
        calls = {"n": 0}

        def _apply(cmds: object, endpoint: str = "") -> tuple:
            calls["n"] += 1
            if calls["n"] == 1:
                return (1, 0)
            return (0, 1)

        monkeypatch.setattr("rebrew.ghidra.cli.apply_commands_via_mcp", _apply)
        result = runner.invoke(app, ["--push", "--sync-sizes"])
        assert result.exit_code == EXIT_MISMATCH
        assert "1 operations failed" in result.output

    def test_apply_dry_run_text(self, tmp_path: pytest.TempPathFactory, monkeypatch) -> None:
        cfg = _make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.ghidra.cli.require_config", lambda **kw: cfg)
        monkeypatch.setattr("rebrew.ghidra.cli.scan_reversed_dir", lambda d, cfg=None: [])
        result = runner.invoke(app, ["--apply", "--dry-run"])
        assert result.exit_code == 0
        assert "Dry run: would apply 0 operations to Ghidra via" in result.output

    def test_summary_with_structs_and_signatures(
        self, tmp_path: pytest.TempPathFactory, monkeypatch
    ) -> None:
        """Real struct/signature extraction feeds parse-c-structure + prototypes ops."""
        cfg = _make_cfg(tmp_path)
        (cfg.reversed_dir / "real.h").write_text(
            "typedef struct { int x; } MyThing;\n", encoding="utf-8"
        )
        # types.h must be skipped (auto-generated Ghidra file).
        (cfg.reversed_dir / "types.h").write_text(
            "typedef unsigned int undefined4;\n", encoding="utf-8"
        )
        (cfg.reversed_dir / "foo.c").write_text(
            "struct Local { int y; };\n"
            "// FUNCTION: SERVER 0x10001000\n"
            "int my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        entries = [_entry(0x10001000)]
        monkeypatch.setattr("rebrew.ghidra.cli.require_config", lambda **kw: cfg)
        monkeypatch.setattr("rebrew.ghidra.cli.scan_reversed_dir", lambda d, cfg=None: entries)
        result = runner.invoke(app, ["--summary"])
        assert result.exit_code == 0
        assert "Push 2 struct definitions" in result.output  # MyThing typedef + struct Local
        assert "Set 1 function prototypes" in result.output  # my_func
        assert "Create 1 functions" in result.output


class TestRefreshCacheFunctions:
    """Direct tests for _refresh_structure_cache / _refresh_data_labels_cache."""

    def _cfg(self, tmp_path: pytest.TempPathFactory) -> SimpleNamespace:
        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        return SimpleNamespace(reversed_dir=src, target_name="SERVER", root=tmp_path)

    def _patch_fetch(
        self,
        monkeypatch: pytest.MonkeyPatch,
        *,
        funcs: list | None = None,
        syms: list | None = None,
    ) -> None:
        monkeypatch.setattr(
            "rebrew.ghidra.cli.httpx.Client", lambda **kw: _FakeClient([_FakeResp()])
        )
        monkeypatch.setattr("rebrew.ghidra.cli.init_mcp_session", lambda c, e: "s")
        monkeypatch.setattr("rebrew.ghidra.cli.fetch_all_functions", lambda *a, **k: funcs or [])
        monkeypatch.setattr("rebrew.ghidra.client.fetch_all_symbols", lambda *a, **k: syms or [])

    def test_structure_cache_json(self, tmp_path: pytest.TempPathFactory, monkeypatch) -> None:
        from rebrew.ghidra.cli import _refresh_structure_cache

        cfg = self._cfg(tmp_path)
        funcs = [
            {"va": "0x10001000", "size": "128", "tool_name": "my_func"},
            {"va": 0x2000, "size": 8},  # int VA/size passthrough
        ]
        self._patch_fetch(monkeypatch, funcs=funcs)
        entries = _refresh_structure_cache(cfg, "http://x", "/p", False, json_output=True)
        assert entries == [
            {"va": 0x10001000, "size": 128, "tool_name": "my_func"},
            {"va": 0x2000, "size": 8},
        ]

    def test_structure_cache_dry_run_writes_nothing(
        self, tmp_path: pytest.TempPathFactory, monkeypatch
    ) -> None:
        from rebrew.ghidra.cli import _refresh_structure_cache

        cfg = self._cfg(tmp_path)
        self._patch_fetch(monkeypatch, funcs=[{"va": 0x1000, "size": 8}])
        entries = _refresh_structure_cache(cfg, "http://x", "/p", dry_run=True, json_output=False)
        assert len(entries) == 1
        assert not (cfg.reversed_dir / "function_structure.json").exists()

    def test_structure_cache_writes_file(
        self, tmp_path: pytest.TempPathFactory, monkeypatch
    ) -> None:
        import json as _json

        from rebrew.ghidra.cli import _refresh_structure_cache

        cfg = self._cfg(tmp_path)
        self._patch_fetch(monkeypatch, funcs=[{"va": 0x1000, "size": 8, "ghidra_name": "g"}])
        _refresh_structure_cache(cfg, "http://x", "/p", dry_run=False, json_output=False)
        out = cfg.reversed_dir / "function_structure.json"
        assert out.exists()
        data = _json.loads(out.read_text(encoding="utf-8"))
        assert data == [{"va": 0x1000, "size": 8, "tool_name": "g"}]

    def test_structure_cache_empty_errors(
        self, tmp_path: pytest.TempPathFactory, monkeypatch
    ) -> None:
        from rebrew.ghidra.cli import _refresh_structure_cache

        cfg = self._cfg(tmp_path)
        self._patch_fetch(monkeypatch, funcs=[])
        with pytest.raises(typer.Exit):
            _refresh_structure_cache(cfg, "http://x", "/p", False, json_output=False)

    def test_structure_cache_http_error_errors(
        self, tmp_path: pytest.TempPathFactory, monkeypatch
    ) -> None:
        import httpx

        from rebrew.ghidra.cli import _refresh_structure_cache

        cfg = self._cfg(tmp_path)

        def _boom(*_a: object, **_k: object) -> object:
            raise httpx.ConnectError("down")

        monkeypatch.setattr("rebrew.ghidra.cli.httpx.Client", _boom)
        with pytest.raises(typer.Exit):
            _refresh_structure_cache(cfg, "http://x", "/p", False, json_output=False)

    def test_data_labels_json_and_dry_run(
        self, tmp_path: pytest.TempPathFactory, monkeypatch
    ) -> None:
        from rebrew.ghidra.cli import _refresh_data_labels_cache

        cfg = self._cfg(tmp_path)
        self._patch_fetch(monkeypatch, syms=[{"address": "0x5000", "name": "g_x"}])
        labels = _refresh_data_labels_cache(cfg, "http://x", "/p", True, json_output=True)
        assert labels == [{"address": "0x5000", "name": "g_x"}]
        # dry_run write path
        labels = _refresh_data_labels_cache(cfg, "http://x", "/p", True, json_output=False)
        assert len(labels) == 1
        assert not (cfg.reversed_dir / "ghidra_data_labels.json").exists()

    def test_data_labels_writes_file(self, tmp_path: pytest.TempPathFactory, monkeypatch) -> None:
        import json as _json

        from rebrew.ghidra.cli import _refresh_data_labels_cache

        cfg = self._cfg(tmp_path)
        self._patch_fetch(monkeypatch, syms=[{"address": "0x5000", "name": "g_x"}])
        _refresh_data_labels_cache(cfg, "http://x", "/p", False, json_output=False)
        out = cfg.reversed_dir / "ghidra_data_labels.json"
        assert out.exists()
        assert _json.loads(out.read_text(encoding="utf-8")) == [
            {"address": "0x5000", "name": "g_x"}
        ]

    def test_data_labels_http_error_errors(
        self, tmp_path: pytest.TempPathFactory, monkeypatch
    ) -> None:
        import httpx

        from rebrew.ghidra.cli import _refresh_data_labels_cache

        cfg = self._cfg(tmp_path)

        def _boom(*_a: object, **_k: object) -> object:
            raise httpx.ConnectError("down")

        monkeypatch.setattr("rebrew.ghidra.cli.httpx.Client", _boom)
        with pytest.raises(typer.Exit):
            _refresh_data_labels_cache(cfg, "http://x", "/p", False, json_output=False)

    def test_data_labels_empty_returns_empty(
        self, tmp_path: pytest.TempPathFactory, monkeypatch
    ) -> None:
        """Unlike the structure cache, an empty data-label set is not an error."""
        from rebrew.ghidra.cli import _refresh_data_labels_cache

        cfg = self._cfg(tmp_path)
        self._patch_fetch(monkeypatch, syms=[])
        assert _refresh_data_labels_cache(cfg, "http://x", "/p", False, json_output=True) == []


class TestPushDedup:
    """--export/--apply idempotency: applied operations are tracked and
    skipped on the next export (--force re-pushes everything)."""

    def _setup(self, tmp_path, monkeypatch) -> SimpleNamespace:
        cfg = _make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.ghidra.cli.require_config", lambda **kw: cfg)
        monkeypatch.setattr(
            "rebrew.ghidra.cli.scan_reversed_dir",
            lambda d, cfg=None: [_entry(0x10001000)],
        )
        return cfg

    def test_apply_records_pushed_hashes(self, tmp_path, monkeypatch) -> None:
        from rebrew.ghidra.cli import _load_pushed_hashes, _op_hash

        commands = [{"tool": "create-label", "args": {"address": "0x1"}}]
        cfg = self._setup(tmp_path, monkeypatch)
        (cfg.root / "ghidra_commands.json").write_text(json.dumps(commands), encoding="utf-8")
        monkeypatch.setattr(
            "rebrew.ghidra.cli.apply_commands_via_mcp", lambda cmds, endpoint="": (1, 0)
        )
        result = runner.invoke(app, ["--apply"])
        assert result.exit_code == 0
        assert _op_hash(commands[0]) in _load_pushed_hashes(cfg)

    def test_export_skips_already_applied(self, tmp_path, monkeypatch) -> None:
        from rebrew.ghidra.cli import _op_hash, _record_pushed_hashes

        cfg = self._setup(tmp_path, monkeypatch)
        # Learn the exact op set the CLI builds (programPath etc.), then
        # simulate a previous push by recording those hashes.
        runner.invoke(app, ["--export", "--force"])
        first_ops = json.loads((cfg.root / "ghidra_commands.json").read_text(encoding="utf-8"))
        _record_pushed_hashes(cfg, {_op_hash(o) for o in first_ops})

        result = runner.invoke(app, ["--export"])
        assert result.exit_code == 0
        out = cfg.root / "ghidra_commands.json"
        assert json.loads(out.read_text(encoding="utf-8")) == []
        assert "already applied, skipped" in result.output

    def test_force_re_exports_everything(self, tmp_path, monkeypatch) -> None:
        from rebrew.ghidra.cli import _op_hash, _record_pushed_hashes

        cfg = self._setup(tmp_path, monkeypatch)
        runner.invoke(app, ["--export", "--force"])
        first_ops = json.loads((cfg.root / "ghidra_commands.json").read_text(encoding="utf-8"))
        _record_pushed_hashes(cfg, {_op_hash(o) for o in first_ops})

        result = runner.invoke(app, ["--export", "--force"])
        assert result.exit_code == 0
        out = cfg.root / "ghidra_commands.json"
        assert len(json.loads(out.read_text(encoding="utf-8"))) > 0
        assert "already applied" not in result.output

    def test_apply_force_still_records(self, tmp_path, monkeypatch) -> None:
        """--force bypasses the EXPORT filter, not the APPLY recording — the
        state must not lag reality after a forced push."""
        from rebrew.ghidra.cli import _load_pushed_hashes, _op_hash

        commands = [{"tool": "create-label", "args": {"address": "0x1"}}]
        cfg = self._setup(tmp_path, monkeypatch)
        (cfg.root / "ghidra_commands.json").write_text(json.dumps(commands), encoding="utf-8")
        monkeypatch.setattr(
            "rebrew.ghidra.cli.apply_commands_via_mcp", lambda cmds, endpoint="": (1, 0)
        )
        result = runner.invoke(app, ["--apply", "--force"])
        assert result.exit_code == 0
        assert _op_hash(commands[0]) in _load_pushed_hashes(cfg)


class TestWatchMode:
    """--watch re-pushes on change; requires --push."""

    def test_watch_requires_push(self, tmp_path, monkeypatch) -> None:
        cfg = _make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.ghidra.cli.require_config", lambda **kw: cfg)
        result = runner.invoke(app, ["--watch", "--apply"])
        assert result.exit_code != 0
        assert "--watch requires --push" in result.output

    def test_watch_retest_runs_push(self, tmp_path, monkeypatch) -> None:
        cfg = _make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.ghidra.cli.require_config", lambda **kw: cfg)
        monkeypatch.setattr(
            "rebrew.ghidra.cli.scan_reversed_dir",
            lambda d, cfg=None: [_entry(0x10001000)],
        )
        captured: dict[str, object] = {}

        def fake_watch(paths, retest, interval=1.0):
            captured["paths"] = list(paths)
            retest()  # one live re-push

        monkeypatch.setattr("rebrew.utils.watch_files", fake_watch)
        result = runner.invoke(app, ["--watch", "--push", "--dry-run"])
        assert result.exit_code == 0
        assert "Dry run" in result.output  # the retest re-ran the push
        assert len(captured["paths"]) > 0  # watched sources

    def test_watch_watches_metadata_file(self, tmp_path, monkeypatch) -> None:
        cfg = _make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.ghidra.cli.require_config", lambda **kw: cfg)
        captured: dict[str, object] = {}

        def fake_watch(paths, retest, interval=1.0):
            captured["paths"] = [str(p) for p in paths]
            raise KeyboardInterrupt

        monkeypatch.setattr("rebrew.utils.watch_files", fake_watch)
        runner.invoke(app, ["--watch", "--push"])
        assert any("rebrew-function.toml" in p for p in captured["paths"])


class TestCliBackendWiring:
    """ghidra_backend = "cli" routes the apply through the ghidra-cli binary
    instead of ReVa MCP."""

    def test_cli_backend_used(self, tmp_path, monkeypatch) -> None:
        cfg = _make_cfg(tmp_path)
        cfg.ghidra_backend = "cli"  # type: ignore[attr-defined]
        cfg.ghidra_program_path = "/x.dll"  # type: ignore[attr-defined]
        monkeypatch.setattr("rebrew.ghidra.cli.require_config", lambda **kw: cfg)
        monkeypatch.setattr(
            "rebrew.ghidra.cli.scan_reversed_dir",
            lambda d, cfg=None: [_entry(0x10001000)],
        )
        monkeypatch.setattr("rebrew.ghidra.cli.resolve_program_path", lambda cfg: "/x.dll")
        (cfg.root / "ghidra_commands.json").write_text(
            json.dumps([{"tool": "create-label", "args": {"address": "0x1", "name": "x"}}]),
            encoding="utf-8",
        )
        captured: dict[str, object] = {}

        def fake_cli(commands, *, program, project, ghidra_cli="ghidra-cli"):
            captured["program"] = program
            captured["ghidra_cli"] = ghidra_cli
            return (1, 0)

        monkeypatch.setattr("rebrew.ghidra.cli_backend.apply_commands_via_cli", fake_cli)
        result = runner.invoke(app, ["--apply"])
        assert result.exit_code == 0
        assert captured["program"] == "/x.dll"

    def test_reva_backend_default(self, tmp_path, monkeypatch) -> None:
        cfg = _make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.ghidra.cli.require_config", lambda **kw: cfg)
        (cfg.root / "ghidra_commands.json").write_text(
            json.dumps([{"tool": "create-label", "args": {"address": "0x1", "name": "x"}}]),
            encoding="utf-8",
        )
        called: dict[str, bool] = {"mcp": False, "cli": False}

        def fake_mcp(commands, endpoint=""):
            called["mcp"] = True
            return (1, 0)

        def fake_cli(commands, *, program, project):
            called["cli"] = True
            return (1, 0)

        monkeypatch.setattr("rebrew.ghidra.cli.apply_commands_via_mcp", fake_mcp)
        monkeypatch.setattr("rebrew.ghidra.cli_backend.apply_commands_via_cli", fake_cli)
        result = runner.invoke(app, ["--apply"])
        assert result.exit_code == 0
        assert called["mcp"] is True
        assert called["cli"] is False


class TestPullBackendDispatch:
    """pull_ghidra_renames routes its fetch through the ghidra-cli backend
    when ghidra_backend == "cli" — the MCP fetchers must not run."""

    def test_cli_backend_skips_mcp_fetchers(self, tmp_path, monkeypatch) -> None:
        from rebrew.ghidra.commands import pull_ghidra_renames

        cfg = _make_cfg(tmp_path)
        cfg.ghidra_backend = "cli"  # type: ignore[attr-defined]
        called: dict[str, bool] = {"mcp": False}

        def _boom(*_a: object, **_k: object) -> list[object]:
            called["mcp"] = True
            return []

        monkeypatch.setattr(
            "rebrew.ghidra.cli_backend.fetch_pull_data_via_cli",
            lambda **kw: {"functions": [], "symbols": [], "plate": [], "pre": []},
        )
        monkeypatch.setattr("rebrew.ghidra.commands.fetch_all_functions", _boom)
        monkeypatch.setattr("rebrew.ghidra.commands.fetch_all_symbols", _boom)
        monkeypatch.setattr("rebrew.ghidra.commands.fetch_mcp_tool", _boom)

        result = pull_ghidra_renames(  # type: ignore[arg-type]
            [], cfg, endpoint="http://x", program_path="/x.dll", dry_run=True, json_output=True
        )
        assert called["mcp"] is False
        assert result.conflicts == 0

    def test_reva_backend_still_fetches_mcp(self, tmp_path, monkeypatch) -> None:
        from rebrew.ghidra.commands import pull_ghidra_renames

        cfg = _make_cfg(tmp_path)
        cfg.ghidra_backend = "reva"  # type: ignore[attr-defined]
        calls: list[str] = []

        def _fake_fetch(*_a: object, **_k: object) -> list[object]:
            calls.append("mcp")
            return []

        monkeypatch.setattr("rebrew.ghidra.commands.init_mcp_session", lambda *a, **k: "sess")
        monkeypatch.setattr("rebrew.ghidra.commands.fetch_all_functions", _fake_fetch)
        monkeypatch.setattr("rebrew.ghidra.commands.fetch_all_symbols", _fake_fetch)
        monkeypatch.setattr("rebrew.ghidra.commands.fetch_mcp_tool", _fake_fetch)
        pull_ghidra_renames(  # type: ignore[arg-type]
            [], cfg, endpoint="http://x", program_path="/x.dll", dry_run=True, json_output=True
        )
        # The MCP fetchers ran for the default reva backend.
        assert calls
