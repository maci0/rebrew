"""Tests for rebrew sync --pull-structs (E16: --types-out and --by-module)."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from rebrew.ghidra.commands import _infer_struct_module, pull_structs

# ---------------------------------------------------------------------------
# Fake MCP infrastructure
# ---------------------------------------------------------------------------


def _make_cfg(tmp_path: Path) -> Any:
    """Return a minimal config-like namespace with reversed_dir set."""
    reversed_dir = tmp_path / "src"
    reversed_dir.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(reversed_dir=reversed_dir)


def _patch_pull_structs(monkeypatch: Any, structs_list: Any, info_by_name: dict[str, Any]) -> None:
    """Patch MCP helpers so pull_structs runs without a live Ghidra instance."""

    def _fake_init(client: Any, endpoint: str) -> str:
        _ = client, endpoint
        return "sess-x"

    def _fake_fetch_raw(
        client: Any,
        endpoint: str,
        tool_name: str,
        arguments: dict[str, Any],
        request_id: int,
        session_id: str = "",
    ) -> Any:
        _ = client, endpoint, request_id, session_id
        if tool_name == "list-structures":
            return structs_list
        if tool_name == "get-structure-info":
            name = arguments.get("structureName", "")
            return info_by_name.get(name)
        return None

    monkeypatch.setattr("rebrew.ghidra.commands.init_mcp_session", _fake_init)
    monkeypatch.setattr("rebrew.ghidra.commands.fetch_mcp_tool_raw", _fake_fetch_raw)

    class _FakeClient:
        def __init__(self, timeout: float) -> None:
            _ = timeout

        def __enter__(self) -> "_FakeClient":
            return self

        def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
            return None

    monkeypatch.setattr("rebrew.ghidra.commands.httpx.Client", _FakeClient)


# ---------------------------------------------------------------------------
# _infer_struct_module helper
# ---------------------------------------------------------------------------


class TestInferStructModule:
    """Tests for the _infer_struct_module() helper."""

    def test_namespace_field(self) -> None:
        assert _infer_struct_module({"namespace": "server"}) == "SERVER"

    def test_category_field(self) -> None:
        assert _infer_struct_module({"category": "Client"}) == "CLIENT"

    def test_category_path_strips_leading_slash(self) -> None:
        assert _infer_struct_module({"categoryPath": "/Engine/Types"}) == "ENGINE"

    def test_category_path_no_leading_slash(self) -> None:
        assert _infer_struct_module({"categoryPath": "Engine/Types"}) == "ENGINE"

    def test_no_fields_returns_none(self) -> None:
        assert _infer_struct_module({"size": 8}) is None

    def test_non_dict_returns_none(self) -> None:
        assert _infer_struct_module("typedef struct Foo {};") is None

    def test_empty_namespace_returns_none(self) -> None:
        assert _infer_struct_module({"namespace": ""}) is None

    def test_slash_only_returns_none(self) -> None:
        assert _infer_struct_module({"namespace": "/"}) is None


# ---------------------------------------------------------------------------
# Default behavior: single types.h
# ---------------------------------------------------------------------------


class TestPullStructsDefault:
    """Default behavior — single types.h unchanged when no extra flags passed."""

    def test_writes_types_h(self, monkeypatch: Any, tmp_path: Path) -> None:
        structs_list = [{"name": "MyStruct"}]
        info = {"cDefinition": "typedef struct MyStruct { int x; } MyStruct;"}
        _patch_pull_structs(monkeypatch, structs_list, {"MyStruct": info})

        cfg = _make_cfg(tmp_path)
        pull_structs(cfg, "http://fake/mcp", "/game.exe", dry_run=False)

        out = cfg.reversed_dir / "types.h"
        assert out.exists()
        content = out.read_text()
        assert "MyStruct" in content
        assert "#ifndef TYPES_H" in content

    def test_dry_run_does_not_write(self, monkeypatch: Any, tmp_path: Path) -> None:
        structs_list = [{"name": "MyStruct"}]
        info = {"cDefinition": "typedef struct MyStruct { int x; } MyStruct;"}
        _patch_pull_structs(monkeypatch, structs_list, {"MyStruct": info})

        cfg = _make_cfg(tmp_path)
        pull_structs(cfg, "http://fake/mcp", "/game.exe", dry_run=True)

        out = cfg.reversed_dir / "types.h"
        assert not out.exists()

    def test_includes_typedef_preamble(self, monkeypatch: Any, tmp_path: Path) -> None:
        structs_list = [{"name": "S"}]
        info = {"cDefinition": "typedef struct S { int v; } S;"}
        _patch_pull_structs(monkeypatch, structs_list, {"S": info})

        cfg = _make_cfg(tmp_path)
        pull_structs(cfg, "http://fake/mcp", "/game.exe", dry_run=False)

        content = (cfg.reversed_dir / "types.h").read_text()
        assert "uint8_t" in content
        assert "uint32_t" in content

    def test_fields_format(self, monkeypatch: Any, tmp_path: Path) -> None:
        """Structs returned as fields list are rendered correctly."""
        structs_list = [{"name": "Vec3"}]
        info = {"fields": [{"name": "x", "dataType": "float", "offset": 0}], "size": 12}
        _patch_pull_structs(monkeypatch, structs_list, {"Vec3": info})

        cfg = _make_cfg(tmp_path)
        pull_structs(cfg, "http://fake/mcp", "/game.exe", dry_run=False)

        content = (cfg.reversed_dir / "types.h").read_text()
        assert "float x;" in content
        assert "offset 0x0" in content

    def test_no_structures_found(self, monkeypatch: Any, tmp_path: Path) -> None:
        """No structures → no file created, no error."""
        _patch_pull_structs(monkeypatch, "unexpected string", {})
        cfg = _make_cfg(tmp_path)
        pull_structs(cfg, "http://fake/mcp", "/game.exe", dry_run=False)
        assert not (cfg.reversed_dir / "types.h").exists()

    def test_empty_list(self, monkeypatch: Any, tmp_path: Path) -> None:
        _patch_pull_structs(monkeypatch, [], {})
        cfg = _make_cfg(tmp_path)
        pull_structs(cfg, "http://fake/mcp", "/game.exe", dry_run=False)
        assert not (cfg.reversed_dir / "types.h").exists()


# ---------------------------------------------------------------------------
# --types-out: override output path
# ---------------------------------------------------------------------------


class TestPullStructsTypesOut:
    """--types-out writes to the specified path instead of types.h."""

    def test_writes_to_custom_path(self, monkeypatch: Any, tmp_path: Path) -> None:
        structs_list = [{"name": "S"}]
        info = {"cDefinition": "typedef struct S { int v; } S;"}
        _patch_pull_structs(monkeypatch, structs_list, {"S": info})

        cfg = _make_cfg(tmp_path)
        custom = tmp_path / "out" / "my_types.h"
        custom.parent.mkdir(parents=True, exist_ok=True)
        pull_structs(cfg, "http://fake/mcp", "/game.exe", dry_run=False, types_out=custom)

        assert custom.exists()
        assert not (cfg.reversed_dir / "types.h").exists()
        assert "TYPES_H" in custom.read_text()

    def test_dry_run_does_not_write(self, monkeypatch: Any, tmp_path: Path) -> None:
        structs_list = [{"name": "S"}]
        info = {"cDefinition": "typedef struct S { int v; } S;"}
        _patch_pull_structs(monkeypatch, structs_list, {"S": info})

        cfg = _make_cfg(tmp_path)
        custom = tmp_path / "my_types.h"
        pull_structs(cfg, "http://fake/mcp", "/game.exe", dry_run=True, types_out=custom)
        assert not custom.exists()


# ---------------------------------------------------------------------------
# --by-module: per-module files
# ---------------------------------------------------------------------------


class TestPullStructsByModule:
    """--by-module writes separate files per inferred origin module."""

    def test_single_module(self, monkeypatch: Any, tmp_path: Path) -> None:
        structs_list = [{"name": "PlayerData", "namespace": "server"}]
        info = {"cDefinition": "typedef struct PlayerData { int hp; } PlayerData;"}
        _patch_pull_structs(monkeypatch, structs_list, {"PlayerData": info})

        cfg = _make_cfg(tmp_path)
        pull_structs(cfg, "http://fake/mcp", "/game.exe", dry_run=False, by_module=True)

        out = cfg.reversed_dir / "types_server.h"
        assert out.exists()
        assert not (cfg.reversed_dir / "types.h").exists()
        content = out.read_text()
        assert "PlayerData" in content
        assert "#ifndef TYPES_SERVER_H" in content

    def test_multiple_modules(self, monkeypatch: Any, tmp_path: Path) -> None:
        structs_list = [
            {"name": "PlayerData", "namespace": "server"},
            {"name": "Packet", "namespace": "client"},
        ]
        info_map = {
            "PlayerData": {"cDefinition": "typedef struct PlayerData { int hp; } PlayerData;"},
            "Packet": {"cDefinition": "typedef struct Packet { int id; } Packet;"},
        }
        _patch_pull_structs(monkeypatch, structs_list, info_map)

        cfg = _make_cfg(tmp_path)
        pull_structs(cfg, "http://fake/mcp", "/game.exe", dry_run=False, by_module=True)

        assert (cfg.reversed_dir / "types_server.h").exists()
        assert (cfg.reversed_dir / "types_client.h").exists()
        assert not (cfg.reversed_dir / "types.h").exists()
        assert "PlayerData" in (cfg.reversed_dir / "types_server.h").read_text()
        assert "Packet" in (cfg.reversed_dir / "types_client.h").read_text()

    def test_shared_structs_land_in_types_shared(self, monkeypatch: Any, tmp_path: Path) -> None:
        """Structs with no namespace attribution go into types_shared.h."""
        structs_list = [{"name": "CommonVec3"}]  # no namespace field
        info = {
            "cDefinition": "typedef struct CommonVec3 { float x; float y; float z; } CommonVec3;"
        }
        _patch_pull_structs(monkeypatch, structs_list, {"CommonVec3": info})

        cfg = _make_cfg(tmp_path)
        pull_structs(cfg, "http://fake/mcp", "/game.exe", dry_run=False, by_module=True)

        out = cfg.reversed_dir / "types_shared.h"
        assert out.exists()
        assert "CommonVec3" in out.read_text()
        assert "#ifndef TYPES_SHARED_H" in out.read_text()

    def test_mixed_attributed_and_shared(self, monkeypatch: Any, tmp_path: Path) -> None:
        """Some structs with namespace, some without."""
        structs_list = [
            {"name": "NetMsg", "namespace": "server"},
            {"name": "BaseObj"},  # no namespace
        ]
        info_map = {
            "NetMsg": {"cDefinition": "typedef struct NetMsg { int type; } NetMsg;"},
            "BaseObj": {"cDefinition": "typedef struct BaseObj { int id; } BaseObj;"},
        }
        _patch_pull_structs(monkeypatch, structs_list, info_map)

        cfg = _make_cfg(tmp_path)
        pull_structs(cfg, "http://fake/mcp", "/game.exe", dry_run=False, by_module=True)

        assert (cfg.reversed_dir / "types_server.h").exists()
        assert (cfg.reversed_dir / "types_shared.h").exists()
        assert not (cfg.reversed_dir / "types.h").exists()

    def test_dry_run_does_not_write(self, monkeypatch: Any, tmp_path: Path) -> None:
        structs_list = [{"name": "S", "namespace": "engine"}]
        info = {"cDefinition": "typedef struct S { int v; } S;"}
        _patch_pull_structs(monkeypatch, structs_list, {"S": info})

        cfg = _make_cfg(tmp_path)
        pull_structs(cfg, "http://fake/mcp", "/game.exe", dry_run=True, by_module=True)

        assert not (cfg.reversed_dir / "types_engine.h").exists()

    def test_module_from_info_dict_when_list_has_no_namespace(
        self, monkeypatch: Any, tmp_path: Path
    ) -> None:
        """Module falls back to info dict when list entry has no namespace."""
        structs_list = [{"name": "RenderCmd"}]  # no namespace in list
        info = {
            "cDefinition": "typedef struct RenderCmd { int cmd; } RenderCmd;",
            "namespace": "engine",  # namespace available in info dict
        }
        _patch_pull_structs(monkeypatch, structs_list, {"RenderCmd": info})

        cfg = _make_cfg(tmp_path)
        pull_structs(cfg, "http://fake/mcp", "/game.exe", dry_run=False, by_module=True)

        assert (cfg.reversed_dir / "types_engine.h").exists()
        assert not (cfg.reversed_dir / "types_shared.h").exists()


# ---------------------------------------------------------------------------
# Mutual exclusion: --types-out + --by-module rejected in CLI
# ---------------------------------------------------------------------------


class TestPullStructsMutualExclusion:
    """--types-out and --by-module are mutually exclusive at CLI level."""

    def test_mutual_exclusion_via_cli(self, monkeypatch: Any, tmp_path: Path) -> None:
        """Passing both flags raises an error_exit before touching Ghidra."""
        from typer.testing import CliRunner

        from rebrew.ghidra.cli import app

        runner = CliRunner()

        # Patch require_config so no project file is needed.
        cfg = _make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.ghidra.cli.require_config", lambda **_kw: cfg)

        result = runner.invoke(
            app,
            ["--pull-structs", "--types-out", str(tmp_path / "x.h"), "--by-module"],
        )
        # error_exit calls typer.Exit(code=1) — exit code should be non-zero.
        assert result.exit_code != 0
        assert "mutually exclusive" in result.output
