"""Tests for rebrew sync validation and config loading."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from rebrew.config import load_config
from rebrew.ghidra.cli import _refresh_data_labels_cache, _refresh_structure_cache
from rebrew.ghidra.commands import resolve_program_path, validate_program_path


class _FakeClient:
    def __init__(self, timeout: float) -> None:
        _ = timeout

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None


class TestResolveProgramPath:
    def test_uses_configured_override(self) -> None:
        cfg = SimpleNamespace(
            target_binary=Path("/tmp/server.dll"),
            ghidra_program_path="/Server/server.dll",
        )
        assert resolve_program_path(cfg) == "/Server/server.dll"

    def test_derives_from_binary_name_when_missing(self) -> None:
        cfg = SimpleNamespace(target_binary=Path("/tmp/server.dll"))
        assert resolve_program_path(cfg) == "/server.dll"

    def test_derives_from_binary_name_when_empty(self) -> None:
        cfg = SimpleNamespace(target_binary=Path("/tmp/server.dll"), ghidra_program_path="")
        assert resolve_program_path(cfg) == "/server.dll"


class TestValidateProgramPath:
    def test_validate_match(self, monkeypatch: Any) -> None:
        def mock_fetch(
            client: Any,
            endpoint: str,
            tool_name: str,
            args: dict[str, Any],
            request_id: int,
            session_id: str = "",
        ) -> dict[str, str]:
            return {
                "programPath": "/server.dll",
                "language": "x86:LE:32:default",
            }

        monkeypatch.setattr("rebrew.ghidra.commands.fetch_mcp_tool_raw", mock_fetch)
        result = validate_program_path(None, "http://localhost:8080/mcp/message", "/server.dll", "")
        assert result == "/server.dll"


class TestRefreshCacheJson:
    def test_structure_cache_json_returns_entries_without_writing(
        self, tmp_path: Path, monkeypatch: Any, capsys: Any
    ) -> None:
        cfg = SimpleNamespace(reversed_dir=tmp_path)

        monkeypatch.setattr("rebrew.ghidra.cli.httpx.Client", _FakeClient)
        monkeypatch.setattr("rebrew.ghidra.cli.init_mcp_session", lambda client, endpoint: "sid")
        monkeypatch.setattr(
            "rebrew.ghidra.cli.fetch_all_functions",
            lambda client, endpoint, program_path, session_id: [
                {"va": "0x10001000", "size": "0x20", "tool_name": "FUN_10001000"}
            ],
        )

        result = _refresh_structure_cache(
            cfg,
            "http://fake/mcp",
            "/server.dll",
            dry_run=False,
            json_output=True,
        )

        assert result == [{"va": 0x10001000, "size": 0x20, "tool_name": "FUN_10001000"}]
        assert not (tmp_path / "function_structure.json").exists()
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_data_labels_cache_json_returns_symbols_without_writing(
        self, tmp_path: Path, monkeypatch: Any, capsys: Any
    ) -> None:
        cfg = SimpleNamespace(reversed_dir=tmp_path)
        symbols = [{"address": "0x10002000", "name": "g_value"}]

        monkeypatch.setattr("rebrew.ghidra.cli.httpx.Client", _FakeClient)
        monkeypatch.setattr("rebrew.ghidra.cli.init_mcp_session", lambda client, endpoint: "sid")
        monkeypatch.setattr(
            "rebrew.ghidra.client.fetch_all_symbols",
            lambda client, endpoint, program_path, session_id: symbols,
        )

        result = _refresh_data_labels_cache(
            cfg,
            "http://fake/mcp",
            "/server.dll",
            dry_run=False,
            json_output=True,
        )

        assert result == symbols
        assert not (tmp_path / "ghidra_data_labels.json").exists()
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_validate_mismatch_warns_and_uses_ghidra_path(
        self, monkeypatch: Any, capsys: Any
    ) -> None:
        def mock_fetch(
            client: Any,
            endpoint: str,
            tool_name: str,
            args: dict[str, Any],
            request_id: int,
            session_id: str = "",
        ) -> dict[str, str]:
            return {
                "programPath": "/Server/server.dll",
                "language": "x86:LE:32:default",
            }

        monkeypatch.setattr("rebrew.ghidra.commands.fetch_mcp_tool_raw", mock_fetch)
        result = validate_program_path(None, "http://localhost:8080/mcp/message", "/server.dll", "")
        captured = capsys.readouterr()
        assert result == "/Server/server.dll"
        assert "Ghidra has '/Server/server.dll' open" in captured.err
        assert 'ghidra_program_path = "/Server/server.dll"' in captured.err

    def test_validate_mcp_error_returns_original(self, monkeypatch: Any) -> None:
        def mock_fetch(
            client: Any,
            endpoint: str,
            tool_name: str,
            args: dict[str, Any],
            request_id: int,
            session_id: str = "",
        ) -> dict[str, Any]:
            raise RuntimeError("mcp unavailable")

        monkeypatch.setattr("rebrew.ghidra.commands.fetch_mcp_tool_raw", mock_fetch)
        result = validate_program_path(None, "http://localhost:8080/mcp/message", "/server.dll", "")
        assert result == "/server.dll"

    def test_validate_none_result_returns_original(self, monkeypatch: Any) -> None:
        def mock_fetch(
            client: Any,
            endpoint: str,
            tool_name: str,
            args: dict[str, Any],
            request_id: int,
            session_id: str = "",
        ) -> None:
            return None

        monkeypatch.setattr("rebrew.ghidra.commands.fetch_mcp_tool_raw", mock_fetch)
        result = validate_program_path(None, "http://localhost:8080/mcp/message", "/server.dll", "")
        assert result == "/server.dll"


class TestConfigGhidraPath:
    def _make_project(self, tmp_path: Path, toml_content: str) -> Path:
        (tmp_path / "rebrew-project.toml").write_text(toml_content, encoding="utf-8")
        return tmp_path

    def test_config_loads_ghidra_program_path(self, tmp_path: Path) -> None:
        root = self._make_project(
            tmp_path,
            """\
[project]
default_target = "main"

[targets.main]
binary = "game.exe"
ghidra_program_path = "/Project/game.exe"
""",
        )
        cfg = load_config(root)
        assert cfg.ghidra_program_path == "/Project/game.exe"

    def test_config_defaults_ghidra_program_path_empty(self, tmp_path: Path) -> None:
        root = self._make_project(
            tmp_path,
            """\
[project]
default_target = "main"

[targets.main]
binary = "game.exe"
""",
        )
        cfg = load_config(root)
        assert cfg.ghidra_program_path == ""
