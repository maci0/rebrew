"""Tests for rebrew build check-tu-data: per-object TU shape from an MSVC link map."""

import json
from pathlib import Path

import pytest
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

# a.c.obj is one TU; b.c.obj holds a TU boundary (_g_next follows its
# literals); c.c.obj ends in named strings; LIBCMT and .bss rows are ignored.
MAP = """\
 server

  Start         Length     Name                   Class
 0001:00000000 00001000H .text                   CODE
 0002:00000000 00000100H .rdata                  DATA
 0003:00000000 00000100H .data                   DATA
 0003:00000100 00000100H .bss                    DATA

  Address         Publics by Value              Rva+Base     Lib:Object

 0001:00000000       _func                      10001000 f   a.c.obj
 0003:00000000       _g_a                       10003000     a.c.obj
 0003:00000004       ??_C@_03ABC@abc?$AA@       10003004     a.c.obj
 0003:00000010       _g_b                       10003010     b.c.obj
 0003:00000014       ??_C@_03DEF@def?$AA@       10003014     b.c.obj
 0003:00000018       _g_next                    10003018     b.c.obj
 0003:00000020       _g_c                       10003020     c.c.obj
 0003:00000024       _s_hello                   10003024     c.c.obj
 0003:00000030       ??_C@_03GHI@ghi?$AA@       10003030     LIBCMT:output.obj
 0003:00000034       _crt_after                 10003034     LIBCMT:output.obj
 0002:00000000       __real@8@4008fa00000000000000 10002000     a.c.obj
 0002:00000008       _k_table                   10002008     a.c.obj
 0003:00000100       _bss_x                     10003100     a.c.obj
"""


def _project(tmp_path: Path) -> Path:
    (tmp_path / "rebrew-project.toml").write_text(PROJECT_TOML, encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "server.map").write_text(MAP, encoding="utf-8")
    return tmp_path


def _invoke(*args: str) -> Result:
    from rebrew.app.main import app

    return CliRunner().invoke(app, ["build", "check-tu-data", *args])


class TestCheckTuData:
    def test_json_reports_every_object_section_and_its_breaks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(_project(tmp_path))
        result = _invoke("--json")
        assert result.exit_code == 1, result.output
        payload = json.loads(result.stdout)
        assert payload["link_map"].endswith("build/server.map")
        rows = {(row["object"], row["section"]): row for row in payload["objects"]}
        assert sorted(rows) == [
            ("a.c.obj", ".data"),
            ("a.c.obj", ".rdata"),
            ("b.c.obj", ".data"),
            ("c.c.obj", ".data"),
        ]
        assert rows[("a.c.obj", ".data")]["shape"] == "D1L1"
        assert rows[("a.c.obj", ".data")]["issues"] == []
        assert rows[("b.c.obj", ".data")]["shape"] == "D1L1D1"
        assert rows[("b.c.obj", ".data")]["issues"] == [
            {"kind": "data_after_literals", "va": "0x10003018", "symbol": "_g_next"}
        ]
        assert rows[("c.c.obj", ".data")]["issues"] == [
            {"kind": "named_strings", "count": 1, "symbols": ["_s_hello"]}
        ]
        # __real@ is a literal; plain data after it in .rdata is a boundary too.
        assert rows[("a.c.obj", ".rdata")]["shape"] == "L1D1"
        assert payload["checked"] == 4
        assert payload["flagged"] == 3
        assert [row["first_va"] for row in payload["objects"]] == [
            "0x10002000",
            "0x10003000",
            "0x10003010",
            "0x10003020",
        ]

    def test_text_output_lists_flagged_objects(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(_project(tmp_path))
        monkeypatch.setenv("COLUMNS", "200")
        result = _invoke()
        assert result.exit_code == 1
        assert "TU boundary before _g_next at 0x10003018" in result.output
        assert "1 trailing named string(s)" in result.output
        assert "checked 4 object section(s), 3 flagged" in result.output

    def test_clean_map_exits_zero(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        root = _project(tmp_path)
        clean = "\n".join(
            line
            for line in MAP.splitlines()
            if not any(drop in line for drop in ("b.c.obj", "c.c.obj", "_k_table"))
        )
        (root / "clean.map").write_text(clean, encoding="utf-8")
        monkeypatch.chdir(root)
        result = _invoke("--link-map", "clean.map", "--json")
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["flagged"] == 0

    def test_missing_map_is_an_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(_project(tmp_path))
        result = _invoke("--link-map", "nope.map", "--json")
        assert result.exit_code == 2
        assert "cannot read link map" in json.loads(result.stdout)["error"]
