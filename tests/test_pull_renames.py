"""Tests for ghidra/commands.py pull_ghidra_renames with mocked MCP."""

from pathlib import Path
from types import SimpleNamespace

import pytest


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(reversed_dir=tmp_path, metadata_dir=tmp_path, marker="SERVER")


class TestPullGhidraRenames:
    def test_empty_entries_no_changes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
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
        monkeypatch.setattr(cmds, "init_mcp_session", lambda *a, **k: "sess")
        monkeypatch.setattr(cmds, "fetch_all_functions", lambda *a, **k: [])
        monkeypatch.setattr(cmds, "fetch_all_symbols", lambda *a, **k: [])
        monkeypatch.setattr(cmds, "fetch_mcp_tool", lambda *a, **k: [])

        result = cmds.pull_ghidra_renames([], _cfg(tmp_path), dry_run=True)
        assert result.updated == 0
        assert result.changes == []

    def test_offline_fallback_no_crash(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import httpx

        import rebrew.ghidra.commands as cmds

        class _FakeHttpxClient:
            def __init__(self, timeout: float = 30.0) -> None:
                pass

            def __enter__(self) -> object:
                return SimpleNamespace()

            def __exit__(self, *a: object) -> None:
                return None

        monkeypatch.setattr(cmds.httpx, "Client", _FakeHttpxClient)
        monkeypatch.setattr(
            cmds,
            "init_mcp_session",
            lambda *a, **k: (_ for _ in ()).throw(
                httpx.RequestError("connect refused", request=None)
            ),
        )
        result = cmds.pull_ghidra_renames([], _cfg(tmp_path), dry_run=True)
        # Offline fallback: no cache file → no changes, no crash.
        assert result.changes == []
