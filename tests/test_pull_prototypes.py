"""Tests for ghidra/commands.py pull_prototypes with mocked MCP."""

from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        reversed_dir=tmp_path,
        metadata_dir=tmp_path,
        marker="SERVER",
        source_ext=".c",
    )


def _fake_httpx_client() -> type:
    class _FakeHttpxClient:
        def __init__(self, timeout: float = 30.0) -> None:
            pass

        def __enter__(self) -> object:
            return SimpleNamespace()

        def __exit__(self, *a: object) -> None:
            return None

    return _FakeHttpxClient


def _capture_console(monkeypatch: pytest.MonkeyPatch, module: object) -> StringIO:
    buf = StringIO()
    monkeypatch.setattr(
        module,
        "console",
        Console(file=buf, force_terminal=True, width=120, no_color=True, highlight=False),
    )
    return buf


class TestPullPrototypes:
    def test_empty_pages_no_changes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.ghidra.commands as cmds

        monkeypatch.setattr(cmds.httpx, "Client", _fake_httpx_client())
        monkeypatch.setattr(cmds, "init_mcp_session", lambda *a, **k: "sess")
        monkeypatch.setattr(cmds, "fetch_mcp_tool_raw", lambda *a, **k: [])
        buf = _capture_console(monkeypatch, cmds)

        before = list(tmp_path.iterdir())
        cmds.pull_prototypes([], _cfg(tmp_path), "http://x", "prog", dry_run=True)
        assert list(tmp_path.iterdir()) == before
        out = buf.getvalue()
        assert "Fetched 0 functions from Ghidra" in out
        assert "Successfully pulled 0 prototypes." in out

    def test_missing_source_skips_write(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Signature present but source file missing → no write, still no crash."""
        import rebrew.ghidra.commands as cmds

        monkeypatch.setattr(cmds.httpx, "Client", _fake_httpx_client())
        monkeypatch.setattr(cmds, "init_mcp_session", lambda *a, **k: "sess")
        monkeypatch.setattr(
            cmds,
            "fetch_mcp_tool_raw",
            lambda *a, **k: [{"address": "0x1000", "signature": "int my_fn(int x)"}],
        )
        buf = _capture_console(monkeypatch, cmds)

        entry = {
            "va": 0x1000,
            "marker_type": "FUNCTION",
            "filepath": "missing.c",
            "prototype": "",
        }
        cmds.pull_prototypes([entry], _cfg(tmp_path), "http://x", "prog", dry_run=False)
        assert not (tmp_path / "missing.c").exists()
        out = buf.getvalue()
        assert "Fetched 1 functions from Ghidra" in out
        # Missing file skips the update path entirely.
        assert "Updated prototype" not in out
        assert "Successfully pulled 0 prototypes." in out

    def test_signature_applied(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """End-to-end: MCP signature is written as // PROTOTYPE on the source file."""
        import rebrew.ghidra.commands as cmds

        src = tmp_path / "func.c"
        src.write_text(
            "// FUNCTION: SERVER 0x1000\nint my_fn(void) { return 0; }\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(cmds.httpx, "Client", _fake_httpx_client())
        monkeypatch.setattr(cmds, "init_mcp_session", lambda *a, **k: "sess")
        monkeypatch.setattr(
            cmds,
            "fetch_mcp_tool_raw",
            lambda *a, **k: [{"address": "0x1000", "signature": "int my_fn(int x)"}],
        )
        entry = {
            "va": 0x1000,
            "marker_type": "FUNCTION",
            "filepath": "func.c",
            "prototype": "",
            "symbol": "_my_fn",
            "name": "my_fn",
        }
        cmds.pull_prototypes([entry], _cfg(tmp_path), "http://x", "prog", dry_run=False)
        assert "// PROTOTYPE: int my_fn(int x)" in src.read_text(encoding="utf-8")

    def test_offline_raises_runtime_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import httpx

        import rebrew.ghidra.commands as cmds

        monkeypatch.setattr(cmds.httpx, "Client", _fake_httpx_client())
        monkeypatch.setattr(
            cmds,
            "init_mcp_session",
            lambda *a, **k: (_ for _ in ()).throw(
                httpx.RequestError("connect refused", request=None)
            ),
        )
        with pytest.raises(RuntimeError, match="Error connecting"):
            cmds.pull_prototypes([], _cfg(tmp_path), "http://x", "prog", dry_run=True)


class TestPullStructs:
    def test_empty_structs_writes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.ghidra.commands as cmds

        monkeypatch.setattr(cmds.httpx, "Client", _fake_httpx_client())
        monkeypatch.setattr(cmds, "init_mcp_session", lambda *a, **k: "sess")
        monkeypatch.setattr(cmds, "fetch_mcp_tool_raw", lambda *a, **k: [])

        cfg = SimpleNamespace(
            reversed_dir=tmp_path, metadata_dir=tmp_path, marker="SERVER", source_ext=".c"
        )
        before = {p.name for p in tmp_path.iterdir()}
        cmds.pull_structs(cfg, "http://x", "prog", dry_run=True)
        assert {p.name for p in tmp_path.iterdir()} == before

    def test_offline_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        import rebrew.ghidra.commands as cmds

        monkeypatch.setattr(cmds.httpx, "Client", _fake_httpx_client())
        monkeypatch.setattr(
            cmds,
            "init_mcp_session",
            lambda *a, **k: (_ for _ in ()).throw(httpx.RequestError("down", request=None)),
        )
        cfg = SimpleNamespace(
            reversed_dir=tmp_path, metadata_dir=tmp_path, marker="SERVER", source_ext=".c"
        )
        with pytest.raises(RuntimeError, match="Error connecting"):
            cmds.pull_structs(cfg, "http://x", "prog", dry_run=True)
