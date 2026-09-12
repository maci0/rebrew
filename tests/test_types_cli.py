"""Tests for rebrew.types_cli — evidence collection + name resolution."""

from pathlib import Path
from typing import Any

import pytest

from rebrew.types_cli import _first_function_name, collect_evidence


class TestCollectEvidence:
    def test_merges_named_evidence(self, tmp_path: Path) -> None:
        a = tmp_path / "a.dec.c"
        a.write_text("PlayerInfo *p;\np->field_0 = 1;\np->field_8 = 2;\n")
        b = tmp_path / "b.dec.c"
        b.write_text("PlayerInfo *q;\nq->field_0 = 1;\n")
        assert collect_evidence([a, b]) == {"PlayerInfo": {0: 4, 8: 4}}

    def test_missing_file_skipped(self, tmp_path: Path) -> None:
        assert collect_evidence([tmp_path / "nope.dec.c"]) == {}

    def test_empty_dir_input(self) -> None:
        assert collect_evidence([]) == {}


class TestFirstFunctionName:
    def test_returns_first_definition(self) -> None:
        assert (
            _first_function_name(
                "int __cdecl foo(void) { return 0; }\nint __cdecl bar(void) { return 1; }"
            )
            == "foo"
        )

    def test_no_function_returns_empty(self) -> None:
        assert _first_function_name("int x;\n") == ""


class TestApplyType:
    """`types apply-type` must write on --json, and not on --dry-run."""

    def _project(self, tmp_path: Path) -> Path:
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "A"\n'
            '[targets.A]\nbinary = "a.exe"\nreversed_dir = "src"\n',
            encoding="utf-8",
        )
        src = tmp_path / "src"
        src.mkdir()
        f = src / "foo.c"
        f.write_text("int foo(int a, int b) { return a + b; }\n", encoding="utf-8")
        return f

    def _invoke(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *args: str) -> Any:
        from typer.testing import CliRunner

        from rebrew.main import app

        monkeypatch.chdir(tmp_path)
        return CliRunner().invoke(app, ["types", "apply-type", *args])

    def test_json_still_writes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        f = self._project(tmp_path)
        result = self._invoke(
            tmp_path, monkeypatch, str(f), "--param", "1", "--type", "PlayerInfo *", "--json"
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["dry_run"] is False
        text = f.read_text(encoding="utf-8")
        assert "PlayerInfo *" in text and "int b" not in text

    def test_dry_run_writes_nothing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        f = self._project(tmp_path)
        before = f.read_text(encoding="utf-8")
        result = self._invoke(
            tmp_path,
            monkeypatch,
            str(f),
            "--param",
            "1",
            "--type",
            "PlayerInfo *",
            "--dry-run",
            "--json",
        )
        assert result.exit_code == 0, result.output
        assert f.read_text(encoding="utf-8") == before
