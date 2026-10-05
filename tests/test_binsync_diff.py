"""Binsync diff name comparison for decorated MSVC symbols."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from rebrew.main import app

runner = CliRunner()

pytest.importorskip("declib")

_VA = 0x401000
_FIXTURES = Path(__file__).parent / "fixtures"


def _project(tmp_path: Path, body: str) -> None:
    (tmp_path / "rebrew-project.toml").write_text(
        "[project]\nname = 'probe'\ndefault_target = 'A'\n"
        "[compiler]\nprofile = 'msvc-6.0'\ncommand = 'CL.EXE'\n"
        "[targets.A]\nbinary = 'a.exe'\nreversed_dir = 'src/a'\n",
        encoding="utf-8",
    )
    src = tmp_path / "src" / "a"
    src.mkdir(parents=True)
    (tmp_path / "src" / "shared").mkdir()
    shutil.copy(_FIXTURES / "mini_pe.exe", tmp_path / "a.exe")
    (src / "fn.c").write_text(
        f"// FUNCTION: A 0x{_VA:08x}\n{body}\n",
        encoding="utf-8",
    )


def _state(tmp_path: Path, name: str) -> Path:
    from declib.artifacts import Function, FunctionHeader

    state = tmp_path / "state"
    funcs = state / "functions"
    funcs.mkdir(parents=True)
    (state / "metadata.toml").write_text('user = "test"\nversion = "test"\n', encoding="utf-8")
    header = FunctionHeader(name=name, addr=_VA)
    (funcs / f"{_VA:08x}.toml").write_text(
        Function(addr=_VA, size=0, header=header).dumps(),
        encoding="utf-8",
    )
    return state


def _diff(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: Path) -> dict[str, Any]:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["binsync", "diff", "--json", str(state)], catch_exceptions=False)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        raise AssertionError(
            f"exit={result.exit_code} stdout={result.stdout!r} stderr={result.stderr!r}"
        ) from None


def _name_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in payload.get("items", []) if item.get("field") == "name"]


class TestDecoratedDiffName:
    def test_vectorcall_matches_the_c_name(self, tmp_path: Path, monkeypatch) -> None:
        """``hook@@12`` is the same function as ``hook``.

        Diff stripped one leading ``_`` only, so the vectorcall symbol
        was reported as a different name.
        """
        _project(tmp_path, "void hook(void) {}")
        payload = _diff(tmp_path, monkeypatch, _state(tmp_path, "hook@@12"))
        assert _name_items(payload) == []

    def test_fastcall_matches_the_c_name(self, tmp_path: Path, monkeypatch) -> None:
        _project(tmp_path, "void keeps(void) {}")
        payload = _diff(tmp_path, monkeypatch, _state(tmp_path, "@keeps@4"))
        assert _name_items(payload) == []

    def test_double_underscore_stays_distinct(self, tmp_path: Path, monkeypatch) -> None:
        """``__foo`` is ``_foo``, not the cdecl function ``foo``."""
        _project(tmp_path, "void foo(void) {}")
        payload = _diff(tmp_path, monkeypatch, _state(tmp_path, "__foo"))
        names = _name_items(payload)
        assert names
        assert names[0]["binsync"] == "__foo"

    def test_cdecl_prefix_still_matches(self, tmp_path: Path, monkeypatch) -> None:
        _project(tmp_path, "void bar(void) {}")
        payload = _diff(tmp_path, monkeypatch, _state(tmp_path, "_bar"))
        assert _name_items(payload) == []
