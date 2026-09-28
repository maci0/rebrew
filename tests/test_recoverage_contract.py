"""Coverage document contract test.

Recoverage (the sibling dashboard) is a pure consumer of
``db/coverage-<target>.toml`` written by ``rebrew build-db``, which scans the
project in-process.  This test runs the real pipeline on the
checked-in fixture binary and asserts the document still carries every fact the
dashboard reads, through the same reader (``rebrew.coverage_toml``) the
dashboard uses — so a rebrew change that silently breaks it is caught here,
without importing the sibling package.

What the consumer needs, and what this file pins:

* a document the reader parses, naming its target and schema ``version`` at
  the top level;
* sections carrying their cells, each with ``state``, ``functions``,
  ``label`` and ``parent_function``;
* functions carrying the ``status``, ``module``, ``size`` and ``files`` the
  dashboard's list columns render;
* globals carrying ``decl``, ``size`` and ``module``;
* verify results carrying ``va``, ``verified_at`` and the five measurement
  columns, with an unmeasured one stored as ``""`` (TOML has no null).

The SQLite schema's derived objects — ``section_cell_stats``, the zstd
section-cells cache, the ``db_version`` stamp — went with the database and are
not part of this contract; nothing here imports ``sqlite3`` or ``zstandard``.
"""

from __future__ import annotations

import json
import shutil
import tomllib
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from rebrew.build_db import FUNCTION_DB_STATUSES, build_db
from rebrew.coverage_toml import load_coverage
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
bin_dir = "bin/SERVER"
source_ext = ".c"
marker = "SERVER"

[compiler]
profile = "mingw-16.2.0"
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
    (root / "src" / "SERVER" / "function_structure.json").write_text(
        json.dumps(
            [
                {"va": 0x00401000, "size": 11, "name": "_func1"},
                {"va": 0x00401010, "size": 10, "name": "_func2"},
            ]
        ),
        encoding="utf-8",
    )
    (root / "src" / "SERVER" / "fcn.c").write_text(
        "// FUNCTION: SERVER 0x00401000\nint __cdecl _func1(void) { return 0; }\n",
        encoding="utf-8",
    )
    (root / "src" / "SERVER" / "globals.c").write_text(
        "// GLOBAL: SERVER 0x00404000\nint g_flag;\n", encoding="utf-8"
    )
    monkeypatch.chdir(root)
    return root


def _run_pipeline(tmp_path: Path, monkeypatch) -> Path:
    """``rebrew build-db`` over a fixture project; returns the root."""
    root = _build_fixture_project(tmp_path, monkeypatch)
    result = CliRunner().invoke(app, ["build-db"])
    assert result.exit_code == 0, result.output
    return root


def _document(root: Path, target: str = "SERVER") -> dict[str, Any]:
    """The written document, parsed straight from disk.

    ``tomllib`` rather than :func:`load_coverage`, because the on-disk key
    names are the contract the consumer reads: a reader that renamed a field
    on the way in would hide a document that no other tool can read.
    """
    path = root / "db" / f"coverage-{target}.toml"
    assert path.is_file(), f"build-db did not write {path}"
    return tomllib.loads(path.read_text(encoding="utf-8"))


class TestRecoverageContract:
    def test_pipeline_writes_a_document_the_reader_parses(self, tmp_path, monkeypatch) -> None:
        root = _run_pipeline(tmp_path, monkeypatch)
        assert not (root / "db" / "coverage.db").exists()
        doc = _document(root)
        # The target is written twice (top level and filename) from one value,
        # and the reader refuses the document when the two disagree.
        assert isinstance(doc["version"], int)
        assert doc["target"] == "SERVER"
        snapshot = load_coverage(root, "SERVER")
        assert snapshot.target == "SERVER"
        assert snapshot.version == doc["version"]

    def test_sections_carry_their_cells(self, tmp_path, monkeypatch) -> None:
        """Cells come from the real binary parse, not a hand-written fixture."""
        root = _run_pipeline(tmp_path, monkeypatch)
        cells = _document(root)["sections"][".text"]["cells"]
        assert cells, "the fixture binary produced no .text cells"
        for cell in cells:
            assert {
                "start",
                "end",
                "span",
                "state",
                "functions",
                "label",
                "parent_function",
            } <= set(cell)
            assert cell["state"]
            assert isinstance(cell["functions"], list)
        # The detail panel resolves a clicked cell to its functions, so at
        # least the annotated one has to come back linked to its own cell.
        linked = [va for cell in cells for va in cell["functions"]]
        assert "0x00401000" in linked

        cell = load_coverage(root, "SERVER").sections[".text"].cells[0]
        assert isinstance(cell.state, str)
        assert isinstance(cell.functions, tuple)
        assert isinstance(cell.label, str)
        assert isinstance(cell.parent_function, str)

    def test_functions_carry_status_module_size_and_files(self, tmp_path, monkeypatch) -> None:
        root = _run_pipeline(tmp_path, monkeypatch)
        rows = _document(root)["functions"]
        assert rows, "the fixture binary produced no function rows"
        for row in rows:
            assert {"va", "name", "status", "module", "size", "files"} <= set(row)
            assert row["status"] in FUNCTION_DB_STATUSES
        func1 = {row["va"]: row for row in rows}[0x00401000]
        assert func1["name"] == "_func1"
        assert func1["module"] == "SERVER"
        assert func1["size"] == 11
        assert func1["files"] == ["fcn.c"]

        stored = load_coverage(root, "SERVER").functions[0]
        assert stored.files == ("fcn.c",)
        assert stored.size == 11

    def test_globals_carry_decl_size_and_module(self, tmp_path, monkeypatch) -> None:
        """The dashboard renders a global's declaration, size and module.

        The global comes from a ``// GLOBAL:`` annotation in the fixture tree,
        so a contract test that can never see a global row is a guard that
        cannot fail.  Everything else in the document still comes from the real
        parse.
        """
        root = _run_pipeline(tmp_path, monkeypatch)

        (row,) = _document(root)["globals"]
        assert {"decl", "size", "module"} <= set(row)
        assert row["decl"] == "int g_flag;"
        assert row["size"] == 4
        assert row["module"] == "SERVER"
        (item,) = load_coverage(root, "SERVER").globals
        assert (item.decl, item.size, item.module) == ("int g_flag;", 4, "SERVER")

    def test_verify_results_carry_their_measurement_columns(self, tmp_path, monkeypatch) -> None:
        """The dashboard's verify rows come from .rebrew/verify_cache.json."""
        import rebrew.verify_cache as vc
        from rebrew.annotation import Annotation
        from rebrew.config import load_config

        root = _build_fixture_project(tmp_path, monkeypatch)
        cache_path = root / ".rebrew" / "verify_cache.json"
        cache_path.parent.mkdir(parents=True, exist_ok=True)

        # The project's OWN config, not a hand-rolled stand-in: build_db
        # imports the cache only when cache_identity_matches accepts it, and
        # that check spans the compiler identity. A cache written by a config
        # that merely looks like this one is correctly refused, which is the
        # point of the check and not what this test is about.
        cfg = load_config(root, target="SERVER")

        entries = [
            Annotation(
                va=0x00401000,
                name="_func1",
                symbol="_func1",
                module="SERVER",
                status="EXACT",
                size=11,
                filepath="fcn.c",
            )
        ]
        results = [
            {
                "va": "0x00401000",
                "name": "_func1",
                "symbol": "_func1",
                "module": "SERVER",
                "filepath": "fcn.c",
                "size": 11,
                "status": "EXACT",
                "message": "EXACT MATCH",
                "passed": True,
                "match_percent": 100.0,
                "delta": 0,
            }
        ]
        vc.save_verify_cache(cache_path, cfg, results, entries)
        build_db(root, regen=True)

        (row,) = _document(root)["verify_results"]
        assert {
            "va",
            "verified_at",
            "byte_delta",
            "diff_lines",
            "similarity",
            "reg_delta",
            "effective_match",
        } <= set(row)
        assert row["va"] == 0x00401000
        assert row["byte_delta"] == 0
        # TOML has no null, and the reader documents that the writer stores an
        # absent measurement as "": a reader must not read it as 0.
        assert row["diff_lines"] == ""
        assert load_coverage(root, "SERVER").verify_results[0]["byte_delta"] == 0

    def test_pipeline_writes_no_intermediate_file(self, tmp_path, monkeypatch) -> None:
        """The document is built in-process; nothing else lands in db/."""
        root = _run_pipeline(tmp_path, monkeypatch)
        assert sorted(p.name for p in (root / "db").iterdir()) == ["coverage-SERVER.toml"]
        doc = _document(root)
        assert doc["target"] == "SERVER"
        assert doc["sections"][".text"]["cells"]
        assert doc["functions"]

    def test_rebuild_over_own_output_is_idempotent(self, tmp_path, monkeypatch) -> None:
        """Re-running build-db on its own output must work and change nothing.

        This is the ordinary case (a user re-running build-db, a second
        --regen), and it is where the writer's read-the-previous-document step
        runs: the history baseline comes from the file the last build wrote, so
        a second pass has to parse it rather than refuse it.  Nothing else
        moved, so the rewrite is byte-identical.
        """
        root = _run_pipeline(tmp_path, monkeypatch)
        path = root / "db" / "coverage-SERVER.toml"
        before = path.read_bytes()
        build_db(root)
        assert path.read_bytes() == before
        assert load_coverage(root, "SERVER").functions
