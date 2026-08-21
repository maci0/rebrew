"""Recoverage schema contract test.

Recoverage (the sibling dashboard) is a pure consumer of ``db/coverage.db``
built by ``rebrew build-db`` from ``db/data_*.json`` written by ``rebrew
catalog --data-json``.  This test runs that real pipeline on the checked-in
fixture binary and asserts the SQLite schema contains exactly the objects and
columns recoverage queries — so a rebrew change that silently breaks the
dashboard is caught here, without importing recoverage.

Recoverage's queries (src/recoverage/api.py): metadata(key/value), sections,
cells(state/functions/label/parent_function), functions, globals,
verify_results(verified_at/byte_delta/diff_lines), section_cell_stats view.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

from typer.testing import CliRunner

from rebrew.build_db import build_db
from rebrew.main import app

FIXTURES = Path(__file__).parent / "fixtures"

_PROJECT_TOML = """\
[project]
name = "schema"
default_target = "SERVER"
jobs = 1

[targets."SERVER"]
binary = "original/mini_pe.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src/SERVER"
function_list = "src/SERVER/functions.txt"
bin_dir = "bin/SERVER"
source_ext = ".c"
marker = "SERVER"

[compiler]
profile = "gcc-pe"
command = "i686-w64-mingw32-gcc"
includes = ""
libs = ""
cflags = "-O2"
base_cflags = ""
timeout = 60
"""


def _build_fixture_project(tmp_path: Path, monkeypatch) -> Path:
    root = tmp_path / "proj"
    (root / "original").mkdir(parents=True)
    (root / "src" / "SERVER").mkdir(parents=True)
    (root / "bin" / "SERVER").mkdir(parents=True)
    shutil.copy(FIXTURES / "mini_pe.exe", root / "original" / "mini_pe.exe")
    (root / "rebrew-project.toml").write_text(_PROJECT_TOML, encoding="utf-8")
    (root / "src" / "SERVER" / "functions.txt").write_text(
        "0x00401000 11 _func1\n0x00401010 10 _func2\n", encoding="utf-8"
    )
    (root / "src" / "SERVER" / "fcn.c").write_text(
        "// FUNCTION: SERVER 0x00401000\nint __cdecl _func1(void) { return 0; }\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(root)
    return root


def _run_pipeline(tmp_path: Path, monkeypatch) -> Path:
    """catalog --data-json → build-db; returns the project root."""
    root = _build_fixture_project(tmp_path, monkeypatch)
    result = CliRunner().invoke(app, ["catalog", "--data-json", "--json"])
    assert result.exit_code == 0, result.output
    data_json = root / "db" / "data_SERVER.json"
    assert data_json.is_file(), "catalog --data-json did not write db/data_SERVER.json"
    build_db(root)
    return root


class TestRecoverageContract:
    def test_pipeline_produces_data_json_and_db(self, tmp_path, monkeypatch) -> None:
        root = _run_pipeline(tmp_path, monkeypatch)
        assert (root / "db" / "coverage.db").is_file()
        # The data JSON has the top-level structure recoverage's importer reads.
        data = json.loads((root / "db" / "data_SERVER.json").read_text(encoding="utf-8"))
        for key in ("sections", "functions", "summary"):
            assert key in data, f"data JSON missing {key}"

    def test_db_schema_matches_recoverage_queries(self, tmp_path, monkeypatch) -> None:
        root = _run_pipeline(tmp_path, monkeypatch)
        conn = sqlite3.connect(root / "db" / "coverage.db")
        c = conn.cursor()

        # Objects recoverage's api.py queries.
        c.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view') ORDER BY name")
        objects = {r[0] for r in c.fetchall()}
        for required in (
            "metadata",
            "sections",
            "cells",
            "functions",
            "globals",
            "verify_results",
            "section_cell_stats",
        ):
            assert required in objects, f"missing DB object {required}"

        # cells carries the recoverage-specific label/parent_function columns.
        c.execute("PRAGMA table_info(cells)")
        cell_cols = {r[1] for r in c.fetchall()}
        for col in ("state", "functions", "label", "parent_function"):
            assert col in cell_cols, f"cells missing column {col}"

        # verify_results has the diff columns the detail API reads.
        c.execute("PRAGMA table_info(verify_results)")
        vr_cols = {r[1] for r in c.fetchall()}
        for col in (
            "verified_at",
            "byte_delta",
            "diff_lines",
            "similarity",
            "reg_delta",
            "effective_match",
        ):
            assert col in vr_cols, f"verify_results missing column {col}"

        # The target is registered in metadata (recoverage lists targets from it).
        c.execute("SELECT COUNT(DISTINCT target) FROM metadata")
        assert c.fetchone()[0] >= 1
        conn.close()

    def test_cells_populated_from_real_catalog(self, tmp_path, monkeypatch) -> None:
        """Cells come from the real binary parse, not a hand-written fixture."""
        root = _run_pipeline(tmp_path, monkeypatch)
        conn = sqlite3.connect(root / "db" / "coverage.db")
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM cells WHERE target = 'SERVER' AND section_name = '.text'")
        assert c.fetchone()[0] > 0
        conn.close()
