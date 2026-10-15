"""Tests for rebrew data mark-literals: link-map literals into rebrew-data.toml rows."""

import tomllib
from pathlib import Path
from typing import Any

import pytest
from cli_json import cli_payload
from source_util import write_store_fixture
from typer.testing import CliRunner, Result

PROJECT_TOML = """\
[project]
name = "t"
default_target = "server.dll"

[targets."server.dll"]
binary = "original/server.dll"
format = "pe"
arch = "x86_32"
reversed_dir = "src"
marker = "SERVER"

[compiler]
profile = "gcc-14.2.0"
command = "gcc"
includes = ""
libs = ""
"""

STORE = 'format = 2\n["SERVER.0x10003004"]\nname = "s_abc"\nsize = 4\nsection = ".data"\nlink_symbol = "_s_abc"\n\n["SERVER.0x10002000"]\nname = "flt_2000"\nsize = 8\nsection = ".rdata"\nstorage_kind = "object"\n\n["SERVER.0x10003014"]\nname = "s_def"\nsection = ".data"\nstorage_kind = "literal"\nlink_symbol = "??_C@_03DEF@def?$AA@"\n\n["SERVER.0x10003020"]\nname = "view"\nsection = ".data"\nstorage_kind = "alias"\nbacking = "g_c"\n\n["SERVER.0x10003000"]\nname = "g_a"\nsection = ".data"\n'

MAP = """\
  Start         Length     Name                   Class
 0002:00000000 00000100H .rdata                  DATA
 0003:00000000 00000100H .data                   DATA

  Address         Publics by Value              Rva+Base     Lib:Object

 0003:00000000       _g_a                       10003000     a.c.obj
 0003:00000004       ??_C@_03ABC@abc?$AA@       10003004     a.c.obj
 0003:00000014       ??_C@_03DEF@def?$AA@       10003014     b.c.obj
 0003:00000020       ??_C@_03GHI@ghi?$AA@       10003020     c.c.obj
 0002:00000000       __real@8@4008fa00000000000000 10002000     a.c.obj
"""


def _project(tmp_path: Path) -> Path:
    (tmp_path / "rebrew-project.toml").write_text(PROJECT_TOML, encoding="utf-8")
    (tmp_path / "src").mkdir()
    write_store_fixture(tmp_path / "rebrew-data.toml", STORE, encoding="utf-8")
    (tmp_path / "server.map").write_text(MAP, encoding="utf-8")
    return tmp_path


def _invoke(*args: str) -> Result:
    from rebrew.app.main import app

    return CliRunner().invoke(app, ["data", "mark-literals", "--link-map", "server.map", *args])


def _store(root: Path) -> dict[str, Any]:
    return tomllib.loads((root / "rebrew-data.toml").read_text(encoding="utf-8"))


class TestMarkLiterals:
    def test_dry_run_reports_without_writing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        monkeypatch.chdir(root)
        before = (root / "rebrew-data.toml").read_bytes()
        result = _invoke("--dry-run", "--json")
        assert result.exit_code == 0, result.output
        payload = cli_payload(result)
        assert payload["dry_run"] is True
        assert payload["marked"] == [
            {
                "va": "0x10002000",
                "symbol": "__real@8@4008fa00000000000000",
                "storage_kind_was": "object",
                "link_symbol_was": None,
            },
            {
                "va": "0x10003004",
                "symbol": "??_C@_03ABC@abc?$AA@",
                "storage_kind_was": None,
                "link_symbol_was": "_s_abc",
            },
        ]
        assert payload["unchanged"] == 1
        assert payload["conflicts"] == [
            {
                "va": "0x10003020",
                "symbol": "??_C@_03GHI@ghi?$AA@",
                "reason": "storage_kind is alias",
            }
        ]
        assert (root / "rebrew-data.toml").read_bytes() == before

    def test_write_marks_rows_and_is_idempotent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        monkeypatch.chdir(root)
        result = _invoke("--json")
        assert result.exit_code == 0, result.output
        store = _store(root)
        assert store["SERVER.0x10003004"]["storage_kind"] == "literal"
        assert store["SERVER.0x10003004"]["link_symbol"] == "??_C@_03ABC@abc?$AA@"
        assert store["SERVER.0x10003004"]["updated_by"] == "data"
        assert store["SERVER.0x10002000"]["storage_kind"] == "literal"
        assert store["SERVER.0x10002000"]["link_symbol"] == "__real@8@4008fa00000000000000"
        assert store["SERVER.0x10003020"]["storage_kind"] == "alias"
        assert "storage_kind" not in store["SERVER.0x10003000"]

        again = _invoke("--json")
        assert again.exit_code == 0, again.output
        payload = cli_payload(again)
        assert payload["marked"] == []
        assert payload["unchanged"] == 3

    def test_text_output_summarizes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(_project(tmp_path))
        monkeypatch.setenv("COLUMNS", "200")
        result = _invoke("--dry-run")
        assert result.exit_code == 0, result.output
        assert "Would mark 2 literal row(s); 1 already marked, 1 conflict(s)." in result.output
        assert "0x10003020: storage_kind is alias" in result.output

    def test_missing_map_is_an_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        root = _project(tmp_path)
        (root / "server.map").unlink()
        monkeypatch.chdir(root)
        result = _invoke("--json")
        assert result.exit_code == 2
        assert "cannot read link map" in cli_payload(result)["error"]
