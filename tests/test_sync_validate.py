from pathlib import Path
from types import SimpleNamespace
from typing import Any

from rebrew.config import load_config
from rebrew.sync import _resolve_program_path, _validate_program_path


class TestResolveProgramPath:
    def test_uses_configured_override(self) -> None:
        cfg = SimpleNamespace(
            target_binary=Path("/tmp/server.dll"),
            ghidra_program_path="/Server/server.dll",
        )
        assert _resolve_program_path(cfg) == "/Server/server.dll"

    def test_derives_from_binary_name_when_missing(self) -> None:
        cfg = SimpleNamespace(target_binary=Path("/tmp/server.dll"))
        assert _resolve_program_path(cfg) == "/server.dll"

    def test_derives_from_binary_name_when_empty(self) -> None:
        cfg = SimpleNamespace(target_binary=Path("/tmp/server.dll"), ghidra_program_path="")
        assert _resolve_program_path(cfg) == "/server.dll"


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

        monkeypatch.setattr("rebrew.sync._fetch_mcp_tool_raw", mock_fetch)
        result = _validate_program_path(
            None, "http://localhost:8080/mcp/message", "/server.dll", ""
        )
        assert result == "/server.dll"

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

        monkeypatch.setattr("rebrew.sync._fetch_mcp_tool_raw", mock_fetch)
        result = _validate_program_path(
            None, "http://localhost:8080/mcp/message", "/server.dll", ""
        )
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

        monkeypatch.setattr("rebrew.sync._fetch_mcp_tool_raw", mock_fetch)
        result = _validate_program_path(
            None, "http://localhost:8080/mcp/message", "/server.dll", ""
        )
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

        monkeypatch.setattr("rebrew.sync._fetch_mcp_tool_raw", mock_fetch)
        result = _validate_program_path(
            None, "http://localhost:8080/mcp/message", "/server.dll", ""
        )
        assert result == "/server.dll"


class TestConfigGhidraPath:
    def _make_project(self, tmp_path: Path, toml_content: str) -> Path:
        (tmp_path / "rebrew-project.toml").write_text(toml_content, encoding="utf-8")
        return tmp_path

    def test_config_loads_ghidra_program_path(self, tmp_path: Path) -> None:
        root = self._make_project(
            tmp_path,
            """\
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
[targets.main]
binary = "game.exe"
""",
        )
        cfg = load_config(root)
        assert cfg.ghidra_program_path == ""
