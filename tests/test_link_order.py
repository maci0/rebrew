"""Tests for rebrew link-order — enforce VA order into CMakeLists.txt SOURCES."""

from __future__ import annotations

import json
import shutil
import warnings
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from rebrew.link_order import find_sources_block, normalize_listed, render_block

_TOML_CFG = """
[project]
default_target = "server"

[targets.server]
binary = "server.dll"
reversed_dir = "src"
"""

_CMAKE_SET = """cmake_minimum_required(VERSION 3.20)
project(server C)

set(SOURCES
  src/b.c
  src/a.c
)

add_library(server STATIC ${SOURCES})
"""

_CMAKE_INLINE = """cmake_minimum_required(VERSION 3.20)
project(server C)

add_library(server STATIC
  src/b.c
  src/a.c
)
"""

_FIXTURE = Path(__file__).parent / "fixtures" / "mini_pe.exe"


def _make_project(tmp_path: Path, files: dict[str, int | None], cmake: str = _CMAKE_SET) -> None:
    (tmp_path / "rebrew-project.toml").write_text(_TOML_CFG, encoding="utf-8")
    shutil.copy(_FIXTURE, tmp_path / "server.dll")
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    for name, va in files.items():
        content = "int x;\n"
        if va is not None:
            content += f"// FUNCTION: server.dll 0x{va:x}\nvoid f(void) {{}}\n"
        (src / name).write_text(content, encoding="utf-8")
    (tmp_path / "CMakeLists.txt").write_text(cmake, encoding="utf-8")


def _invoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *args: str) -> Any:
    from rebrew.link_order import app

    monkeypatch.chdir(tmp_path)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return CliRunner().invoke(app, list(args))


def _stdout(result: Any) -> str:
    """Stdout only — the human summary goes to stderr."""
    assert result.exit_code in (0, 1)
    out = result.stdout
    return out if isinstance(out, str) else result.output


class TestFindSourcesBlock:
    def test_set_sources_wins(self) -> None:
        text = _CMAKE_SET + "\nadd_executable(other src/c.c)\n"
        block = find_sources_block(text, {".c"})
        assert block is not None
        assert block.label == "set(SOURCES ...)"
        assert block.managed == ["src/b.c", "src/a.c"]

    def test_add_library_fallback(self) -> None:
        block = find_sources_block(_CMAKE_INLINE, {".c"})
        assert block is not None
        assert block.managed == ["src/b.c", "src/a.c"]

    def test_empty_add_library_not_a_list(self) -> None:
        block = find_sources_block("add_library(server STATIC)\n", {".c"})
        assert block is None

    def test_no_list_returns_none(self) -> None:
        block = find_sources_block("project(x C)\n", {".c"})
        assert block is None

    def test_keywords_not_managed(self) -> None:
        block = find_sources_block(_CMAKE_INLINE, {".c"})
        assert block is not None
        assert block.managed == ["src/b.c", "src/a.c"]


class TestLinkOrderCli:
    def test_preview_lists_va_order(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(tmp_path, {"a.c": 0x10001000, "b.c": 0x10003000})
        result = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0
        assert _stdout(result).splitlines()[:2] == ["src/a.c", "src/b.c"]

    def test_apply_rewrites_in_place(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(tmp_path, {"a.c": 0x10001000, "b.c": 0x10003000})
        result = _invoke(tmp_path, monkeypatch, "--apply")
        assert result.exit_code == 0
        text = (tmp_path / "CMakeLists.txt").read_text(encoding="utf-8")
        assert text.index("src/a.c") < text.index("src/b.c")
        assert "set(SOURCES" in text
        assert "add_library(server STATIC ${SOURCES})" in text

    def test_apply_is_idempotent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(tmp_path, {"a.c": 0x10001000, "b.c": 0x10003000})
        assert _invoke(tmp_path, monkeypatch, "--apply").exit_code == 0
        before = (tmp_path / "CMakeLists.txt").read_text(encoding="utf-8")
        result = _invoke(tmp_path, monkeypatch, "--apply")
        assert result.exit_code == 0
        assert (tmp_path / "CMakeLists.txt").read_text(encoding="utf-8") == before

    def test_dry_run_does_not_write(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(tmp_path, {"a.c": 0x10001000, "b.c": 0x10003000})
        before = (tmp_path / "CMakeLists.txt").read_text(encoding="utf-8")
        result = _invoke(tmp_path, monkeypatch, "--apply", "--dry-run")
        assert result.exit_code == 0
        assert (tmp_path / "CMakeLists.txt").read_text(encoding="utf-8") == before
        assert "src/a.c" in _stdout(result)

    def test_check_exits_mismatch_on_drift(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(tmp_path, {"a.c": 0x10001000, "b.c": 0x10003000})
        result = _invoke(tmp_path, monkeypatch, "--check")
        assert result.exit_code == 1
        assert "src/a.c" in _stdout(result)
        assert "src/b.c" in _stdout(result)

    def test_check_passes_when_in_sync(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(tmp_path, {"a.c": 0x10001000, "b.c": 0x10003000})
        assert _invoke(tmp_path, monkeypatch, "--apply").exit_code == 0
        result = _invoke(tmp_path, monkeypatch, "--check")
        assert result.exit_code == 0

    def test_check_and_apply_conflict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(tmp_path, {"a.c": 0x10001000})
        result = _invoke(tmp_path, monkeypatch, "--check", "--apply")
        assert result.exit_code == 2

    def test_json_payload(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(tmp_path, {"a.c": 0x10001000, "b.c": 0x10003000})
        result = _invoke(tmp_path, monkeypatch, "--check", "--json")
        assert result.exit_code == 1
        payload = json.loads(_stdout(result))
        assert payload["ordered"] == ["src/a.c", "src/b.c"]
        assert payload["current"] == ["src/b.c", "src/a.c"]
        assert payload["in_sync"] is False
        assert "src/a.c" in payload["diff"]

    def test_missing_cmakelists_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(tmp_path, {"a.c": 0x10001000})
        (tmp_path / "CMakeLists.txt").unlink()
        result = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 2

    def test_keywords_preserved_on_apply(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            {"a.c": 0x10001000, "b.c": 0x10003000},
            _CMAKE_INLINE.replace("STATIC", "STATIC WIN32"),
        )
        assert _invoke(tmp_path, monkeypatch, "--apply").exit_code == 0
        text = (tmp_path / "CMakeLists.txt").read_text(encoding="utf-8")
        assert "STATIC WIN32" in " ".join(text.split())
        assert text.index("src/a.c") < text.index("src/b.c")

    def test_extra_source_appended_on_apply(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(tmp_path, {"a.c": 0x10001000, "b.c": 0x10003000, "c.c": 0x10002000})
        assert _invoke(tmp_path, monkeypatch, "--apply").exit_code == 0
        text = (tmp_path / "CMakeLists.txt").read_text(encoding="utf-8")
        assert text.index("src/a.c") < text.index("src/c.c") < text.index("src/b.c")


class TestRenderHelpers:
    def test_render_preserves_outside_text(self) -> None:
        text = "header\nset(SOURCES\n  b.c\n  a.c\n)\nfooter\n"
        block = find_sources_block(text, {".c"})
        assert block is not None
        rendered = render_block(text, block, ["a.c", "b.c"])
        assert rendered.startswith("header\n")
        assert rendered.endswith("footer\n")
        assert rendered.index("a.c") < rendered.index("b.c")

    def test_render_drops_surplus_entry(self) -> None:
        text = "set(SOURCES\n  a.c\n  gone.c\n)\n"
        block = find_sources_block(text, {".c"})
        assert block is not None
        rendered = render_block(text, block, ["a.c"])
        assert "gone.c" not in rendered
        assert "a.c" in rendered

    def test_normalize_listed_maps_absolute(self, tmp_path: Path) -> None:
        listed = normalize_listed(
            tmp_path, [str(tmp_path / "src" / "a.c")], {str(tmp_path / "src" / "a.c"): "src/a.c"}
        )
        assert listed == ["src/a.c"]
