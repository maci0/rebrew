"""Tests for rebrew sync validation and config loading."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from rebrew.config import load_config
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
