"""Tests for rebrew sync --pull-datatypes (enum/typedef inventory pull).

ReVa's MCP protocol (cyberkaida/reverse-engineering-assistant) exposes
user-defined enums/typedefs via ``get-data-types`` with ``categoryPath``
``/Enum`` and ``/TypeDef``; it does not expose enum member values, so the
pull emits a name/size/category manifest header.
"""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from rebrew.ghidra.commands import pull_datatypes


def _make_cfg(tmp_path: Path) -> Any:
    reversed_dir = tmp_path / "src"
    reversed_dir.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(reversed_dir=reversed_dir)


def _patch_mcp(
    monkeypatch: Any, pages: dict[tuple[str, int], dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    """Patch MCP helpers; returns the captured get-data-types arguments.

    *pages* is keyed by ``(categoryPath, startIndex)`` so each category's
    pagination is served independently.
    """
    calls: list[dict[str, Any]] = []

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
        if tool_name == "get-data-types":
            calls.append(arguments)
            key = (arguments.get("categoryPath", ""), int(arguments.get("startIndex", 0)))
            return pages.get(key)
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
    return {"calls": calls}


def _page(items: list[dict[str, Any]], start: int = 0) -> dict[str, Any]:
    return {
        "archiveName": "",
        "categoryPath": "/Enum",
        "includeSubcategories": True,
        "startIndex": start,
        "totalCount": len(items),
        "returnedCount": len(items),
        "dataTypes": items,
    }


def _enum(name: str, size: int, category: str = "/Enum") -> dict[str, Any]:
    return {
        "name": name,
        "displayName": name,
        "categoryPath": category,
        "size": size,
        "alignment": 4,
        "dataTypeName": "EnumDataType",
    }


def _typedef(name: str, size: int, category: str = "/TypeDef") -> dict[str, Any]:
    return {
        "name": name,
        "displayName": name,
        "categoryPath": category,
        "size": size,
        "alignment": 4,
        "dataTypeName": "TypedefDataType",
    }


class TestPullDatatypes:
    def test_writes_manifest_header(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _make_cfg(tmp_path)
        pages = {
            ("/Enum", 0): _page([_enum("COLOR", 4), _enum("STATE", 1)], start=0),
            ("/TypeDef", 0): _page([_typedef("LPCSTR", 4)], start=0),
        }
        _patch_mcp(monkeypatch, pages)
        pull_datatypes(cfg, "http://mcp", "/server.dll")
        out = tmp_path / "src" / "enums_types.h"
        assert out.is_file()
        text = out.read_text(encoding="utf-8")
        assert "REBREW_DATATYPES_H" in text
        assert "COLOR - size 4 - /Enum" in text
        assert "STATE - size 1 - /Enum" in text
        assert "LPCSTR - size 4 - /TypeDef" in text
        assert "enum member values" in text  # limitation note present

    def test_paginates(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _make_cfg(tmp_path)
        pages = {
            ("/Enum", 0): {
                "archiveName": "",
                "categoryPath": "/Enum",
                "includeSubcategories": True,
                "startIndex": 0,
                "totalCount": 3,
                "returnedCount": 2,
                "dataTypes": [_enum("A", 4), _enum("B", 4)],
            },
            ("/Enum", 2): {
                "archiveName": "",
                "categoryPath": "/Enum",
                "includeSubcategories": True,
                "startIndex": 2,
                "totalCount": 3,
                "returnedCount": 1,
                "dataTypes": [_enum("C", 4)],
            },
            ("/TypeDef", 0): {
                "archiveName": "",
                "categoryPath": "/TypeDef",
                "includeSubcategories": True,
                "startIndex": 0,
                "totalCount": 0,
                "returnedCount": 0,
                "dataTypes": [],
            },
        }
        captured = _patch_mcp(monkeypatch, pages)
        pull_datatypes(cfg, "http://mcp", "/server.dll")
        # Two pages for /Enum, then the /TypeDef attempt.
        assert len(captured["calls"]) == 3
        text = (tmp_path / "src" / "enums_types.h").read_text(encoding="utf-8")
        assert "A - size 4" in text and "C - size 4" in text

    def test_dry_run_does_not_write(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _make_cfg(tmp_path)
        _patch_mcp(monkeypatch, {("/Enum", 0): _page([_enum("COLOR", 4)], start=0)})
        pull_datatypes(cfg, "http://mcp", "/server.dll", dry_run=True)
        assert not (tmp_path / "src" / "enums_types.h").exists()

    def test_custom_output_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _make_cfg(tmp_path)
        _patch_mcp(monkeypatch, {("/Enum", 0): _page([_enum("COLOR", 4)], start=0)})
        out = tmp_path / "custom.h"
        pull_datatypes(cfg, "http://mcp", "/server.dll", types_out=out)
        assert out.is_file()

    def test_no_datatypes_no_write(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _make_cfg(tmp_path)
        _patch_mcp(
            monkeypatch,
            {
                ("/Enum", 0): {
                    "archiveName": "",
                    "categoryPath": "/Enum",
                    "includeSubcategories": True,
                    "startIndex": 0,
                    "totalCount": 0,
                    "returnedCount": 0,
                    "dataTypes": [],
                },
                ("/TypeDef", 0): {
                    "archiveName": "",
                    "categoryPath": "/TypeDef",
                    "includeSubcategories": True,
                    "startIndex": 0,
                    "totalCount": 0,
                    "returnedCount": 0,
                    "dataTypes": [],
                },
            },
        )
        pull_datatypes(cfg, "http://mcp", "/server.dll")
        assert not (tmp_path / "src" / "enums_types.h").exists()

    def test_registered_in_sync_help(self) -> None:
        from rebrew.ghidra.cli import app

        result = CliRunner().invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "--pull-datatypes" in result.output


class TestPullDatatypesMergeSafe:
    def test_repull_preserves_user_section_and_is_idempotent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _make_cfg(tmp_path)
        pages = {
            ("/Enum", 0): _page([_enum("COLOR", 4), _enum("STATE", 1)], start=0),
            ("/TypeDef", 0): _page([_typedef("LPCSTR", 4)], start=0),
        }
        _patch_mcp(monkeypatch, pages)
        pull_datatypes(cfg, "http://mcp", "/server.dll")
        out = tmp_path / "src" / "enums_types.h"
        text = out.read_text(encoding="utf-8")
        assert "USER DEFINITIONS" in text
        # User edits a manual enum inside the preserved section.
        edited = text.replace("#endif", "enum Color { RED = 1, BLUE = 2 };\n#endif", 1)
        out.write_text(edited, encoding="utf-8")

        # Re-pull with identical data: user edit survives, bytes are stable.
        _patch_mcp(monkeypatch, pages)
        pull_datatypes(cfg, "http://mcp", "/server.dll")
        final = out.read_text(encoding="utf-8")
        assert "RED = 1" in final  # manual definition preserved
        assert final.count("#endif") == 1  # guard never duplicated
        assert final == edited  # byte-identical re-pull

    def test_no_user_section_writes_marker(self, tmp_path: Path, monkeypatch) -> None:
        cfg = _make_cfg(tmp_path)
        _patch_mcp(monkeypatch, {("/Enum", 0): _page([_enum("COLOR", 4)], start=0)})
        pull_datatypes(cfg, "http://mcp", "/server.dll")
        text = (tmp_path / "src" / "enums_types.h").read_text(encoding="utf-8")
        assert "USER DEFINITIONS" in text
        assert "survive re-pulls" in text
