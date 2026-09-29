"""Tests for ``rebrew build-db`` — the typer front over the TOML writer.

``rebrew build-db`` reads ``db/data_*.json`` (or regenerates the catalog
in-process with ``--regen``) and writes one clear-text document per target,
``db/coverage-<target>.toml``.  The writer itself is
:func:`rebrew.coverage_toml.write_coverage_toml` and is tested in
``test_coverage_toml.py``; what this file pins is the COMMAND: which files it
writes, what ``--target`` / ``--regen`` / ``--json`` / ``--force`` do, and the
errors a malformed snapshot produces.

The SQLite storage engine these tests used to drive is gone, so every schema
DDL / PRAGMA / sqlite_master assertion went with it.  What replaced them is a
parse of the written document: the file IS the artifact now, so a test that
reads it back is the strongest available check.
"""

import copy
import hashlib
import json
import logging
import tomllib
import unicodedata
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from rebrew.build_db import app
from rebrew.coverage_db import _KNOWN_CELL_STATES

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

#: One catalog snapshot, in the shape ``rebrew catalog --data-json`` writes.
#: The section carries one cell in every state a bucket is served for, so a
#: state the writer drops or re-spells shows up as a missing key.
_CELL_STATES = ("exact", "none", "stub", "reloc", "near_match", "near_matching")

SAMPLE_DATA: dict[str, Any] = {
    "sections": {
        ".text": {
            "va": 0x10001000,
            "size": 4096,
            "fileOffset": 0x1000,
            "unitBytes": 64,
            "columns": 64,
            "cells": [
                {
                    "start": index * 64,
                    "end": (index + 1) * 64,
                    "span": index + 1,
                    "state": state,
                    "functions": [f"func_{state}"],
                }
                for index, state in enumerate(_CELL_STATES)
            ],
        },
    },
    "globals": {
        "g_counter": {
            "va": 0x10030000,
            "name": "g_counter",
            "decl": "int g_counter;",
            "files": ["globals.c"],
            "origin": "GAME",
            "size": 4,
        },
        "g_buffer": {
            "va": 0x10030100,
            "name": "g_buffer",
            "decl": "char g_buffer[256];",
            "files": ["globals.c"],
            "origin": "GAME",
            "size": 256,
        },
    },
    "summary": {"totalFunctions": 2, "matchedFunctions": 1, "textSize": 4096},
    "functions": {
        "func_a": {
            "name": "func_a",
            "vaStart": "0x10001000",
            "size": 64,
            "fileOffset": 0x1000,
            "status": "EXACT",
            "origin": "GAME",
            "cflags": "/O2",
            "symbol": "_func_a",
            "markerType": "FUNCTION",
            "ghidra_name": "FUN_10001000",
            "list_name": "fcn.10001000",
            "is_thunk": False,
            "is_export": True,
            "sha256": "abcd1234",
            "files": ["func_a.c"],
            "detected_by": ["ghidra", "list"],
            "size_by_tool": {"ghidra": 64, "list": 64},
            "textOffset": 0,
            "blocker": "",
            "blockerDelta": None,
            "size_reason": "ghidra",
            "similarity": 1.0,
        },
        "func_b": {
            "name": "func_b",
            "vaStart": "0x10001080",
            "size": 128,
            "fileOffset": 0x1080,
            "status": "STUB",
            "origin": "GAME",
            "markerType": "STUB",
            "files": ["func_b.c"],
            "textOffset": 0x80,
            "blocker": "needs vtable",
            "blockerDelta": 12,
            "similarity": 0.85,
        },
    },
    "paths": {"originalDll": "/original/Server/server.dll"},
}


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class FakeCatalog:
    """Stands in for ``build_catalog_data``; the command has no other input.

    The writer builds the coverage dict in-process, so the seam a test needs
    is the catalog itself: *data* is what every target gets, *per_target*
    overrides one, and *asked* records the targets that were built.
    """

    def __init__(self) -> None:
        self.data: dict[str, Any] = copy.deepcopy(SAMPLE_DATA)
        self.per_target: dict[str, dict[str, Any]] = {}
        self.asked: list[str] = []

    def build(self, cfg: Any) -> dict[str, Any]:
        self.asked.append(cfg.target_name)
        return {"data": copy.deepcopy(self.per_target.get(cfg.target_name, self.data))}


@pytest.fixture
def catalog(monkeypatch: pytest.MonkeyPatch) -> FakeCatalog:
    fake = FakeCatalog()
    monkeypatch.setattr("rebrew.catalog.pipeline.build_catalog_data", fake.build)
    return fake


def _write_config(root_dir: Path, *targets: str) -> Path:
    """A project config naming *targets*; the documents are built from it."""
    root_dir.mkdir(parents=True, exist_ok=True)
    body = f'[project]\nname = "testbin"\ndefault_target = "{targets[0]}"\n\n'
    for name in targets:
        body += f'[targets."{name}"]\nmarker = "GAME"\nbinary = "orig/{name}.dll"\n\n'
    path = root_dir / "rebrew-project.toml"
    path.write_text(body, encoding="utf-8")
    return path


@pytest.fixture
def project_root(tmp_path: Path, catalog: FakeCatalog) -> Path:
    """A minimal project with one target and nothing else on disk."""
    (tmp_path / "db").mkdir()
    _write_config(tmp_path, "testbin")
    return tmp_path


def _document(root_dir: Path, target: str) -> dict[str, Any]:
    """The parsed ``coverage-<target>.toml`` the command wrote."""
    path = root_dir / "db" / f"coverage-{target}.toml"
    assert path.is_file(), f"{path} was not written"
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _json_payload(output: str) -> dict[str, Any]:
    """The ``--json`` envelope out of a CliRunner result.

    ``--json`` silences the ``Wrote`` lines but not the reader's per-target
    ``Processing <target>...`` progress line, which lands on stdout first.
    """
    start = output.index("{")
    return json.loads(output[start:])


def _build(runner: CliRunner, root_dir: Path, *args: str):
    return runner.invoke(app, ["--root", str(root_dir), *args])


# ---------------------------------------------------------------------------
# The command writes the document
# ---------------------------------------------------------------------------


class TestBuildDbCommand:
    def test_writes_one_document_per_target(self, runner: CliRunner, project_root: Path) -> None:
        result = _build(runner, project_root)

        assert result.exit_code == 0, result.output
        path = project_root / "db" / "coverage-testbin.toml"
        assert path.is_file()
        # Rich soft-wraps the path at the console width, mid-name and all.
        assert "Wrote" in result.output
        assert path.name in "".join(result.output.split())
        doc = _document(project_root, "testbin")
        assert doc["target"] == "testbin"
        assert isinstance(doc["version"], int)
        # The snapshot's facts are all in the file: no db/coverage.db exists.
        assert not (project_root / "db" / "coverage.db").exists()
        assert sorted(doc) == [
            "functions",
            "globals",
            "history",
            "metadata",
            "sections",
            "target",
            "verify_results",
            "version",
        ]

    def test_functions_round_trip_every_stored_field(
        self, runner: CliRunner, project_root: Path
    ) -> None:
        assert _build(runner, project_root).exit_code == 0

        rows = {row["va"]: row for row in _document(project_root, "testbin")["functions"]}
        assert sorted(rows) == [0x10001000, 0x10001080]
        func_a = rows[0x10001000]
        assert func_a["name"] == "func_a"
        assert func_a["vaStart"] == "0x10001000"
        assert func_a["size"] == 64
        assert func_a["fileOffset"] == 0x1000
        assert func_a["status"] == "EXACT"
        assert func_a["module"] == "GAME"
        assert func_a["cflags"] == "/O2"
        assert func_a["symbol"] == "_func_a"
        assert func_a["markerType"] == "FUNCTION"
        assert func_a["ghidra_name"] == "FUN_10001000"
        assert func_a["list_name"] == "fcn.10001000"
        assert (func_a["is_thunk"], func_a["is_export"]) == (0, 1)
        assert func_a["sha256"] == "abcd1234"
        assert func_a["files"] == ["func_a.c"]
        assert func_a["detected_by"] == ["ghidra", "list"]
        assert func_a["size_by_tool"] == {"ghidra": 64, "list": 64}
        assert func_a["textOffset"] == 0
        assert func_a["size_reason"] == "ghidra"
        assert func_a["similarity"] == 1.0

        func_b = rows[0x10001080]
        assert func_b["status"] == "STUB"
        assert func_b["blocker"] == "needs vtable"
        assert func_b["blockerDelta"] == 12
        assert func_b["textOffset"] == 0x80
        assert func_b["similarity"] == 0.85

    def test_sections_and_cells_round_trip(self, runner: CliRunner, project_root: Path) -> None:
        assert _build(runner, project_root).exit_code == 0

        doc = _document(project_root, "testbin")
        assert sorted(doc["sections"]) == [".text"]
        section = doc["sections"][".text"]
        assert section["va"] == 0x10001000
        assert section["size"] == 4096
        assert section["fileOffset"] == 0x1000
        assert section["unitBytes"] == 64
        assert section["columns"] == 64
        # One cell per state, each stored lower-case in spatial order.
        assert [(cell["start"], cell["state"]) for cell in section["cells"]] == [
            (index * 64, state) for index, state in enumerate(_CELL_STATES)
        ]
        assert section["cells"][0]["functions"] == ["func_exact"]

    def test_globals_and_paths_round_trip(self, runner: CliRunner, project_root: Path) -> None:
        assert _build(runner, project_root).exit_code == 0

        doc = _document(project_root, "testbin")
        rows = {row["name"]: row for row in doc["globals"]}
        assert rows["g_counter"]["va"] == 0x10030000
        assert rows["g_counter"]["module"] == "GAME"
        assert rows["g_counter"]["size"] == 4
        assert rows["g_buffer"]["size"] == 256
        assert doc["metadata"]["paths"] == {"originalDll": "/original/Server/server.dll"}

    def test_function_statuses_canonicalize_and_typos_become_unknown(
        self, runner: CliRunner, tmp_path: Path, catalog: FakeCatalog
    ) -> None:
        """A lowercase or alias status names a real one; a typo is UNKNOWN."""
        catalog.per_target["alpha"] = {
            "sections": {},
            "globals": {},
            "summary": {},
            "functions": {
                "0x1000": {"name": "a", "size": 8, "status": "exact"},
                "0x2000": {"name": "b", "size": 8, "status": "NEAR_MATCH"},
                "0x3000": {"name": "c", "size": 8, "status": "TYPO_STATUS"},
            },
            "paths": {},
        }
        _write_config(tmp_path, "alpha")

        assert _build(runner, tmp_path).exit_code == 0

        rows = _document(tmp_path, "alpha")["functions"]
        assert [(row["va"], row["status"]) for row in rows] == [
            (0x1000, "EXACT"),
            (0x2000, "NEAR_MATCHING"),
            (0x3000, "UNKNOWN"),
        ]

    def test_bool_size_does_not_become_one(
        self, runner: CliRunner, tmp_path: Path, catalog: FakeCatalog
    ) -> None:
        """``bool`` is an ``int`` subclass, so ``True`` must not store size 1."""
        catalog.per_target["alpha"] = {
            "sections": {},
            "globals": {},
            "summary": {},
            "functions": {
                "0x1000": {
                    "name": "a",
                    "size": True,
                    "fileOffset": False,
                    "status": "STUB",
                },
            },
            "paths": {},
        }
        _write_config(tmp_path, "alpha")

        assert _build(runner, tmp_path).exit_code == 0

        row = _document(tmp_path, "alpha")["functions"][0]
        # TOML has no null, so both absent values are the empty string.
        assert (row["size"], row["fileOffset"]) == ("", "")

    def test_function_key_falls_back_to_va_start(
        self, runner: CliRunner, tmp_path: Path, catalog: FakeCatalog
    ) -> None:
        """A readable key is optional: a bad one defers to ``vaStart``."""
        catalog.per_target["alpha"] = {
            "sections": {},
            "globals": {},
            "summary": {},
            "functions": {
                "adler32": {"name": "adler32", "vaStart": "268439552", "size": 64},
            },
            "paths": {},
        }
        _write_config(tmp_path, "alpha")

        assert _build(runner, tmp_path).exit_code == 0

        assert _document(tmp_path, "alpha")["functions"][0]["va"] == 268439552

    def test_unparseable_va_rows_are_skipped_and_the_target_is_named(
        self, runner: CliRunner, tmp_path: Path, catalog: FakeCatalog
    ) -> None:
        """No ``(target, 0)`` poison row, and the warning names the target."""
        catalog.per_target["edge"] = {
            "sections": {},
            "globals": {"bad-key": {"name": "g", "size": 4}},
            "summary": {},
            "functions": {
                "not-a-va": {"name": "bad", "size": 8, "status": "STUB"},
                "0x1000": {"name": "good", "size": 8, "status": "STUB"},
            },
            "paths": {},
        }
        _write_config(tmp_path, "edge")

        result = _build(runner, tmp_path)

        assert result.exit_code == 0, result.output
        doc = _document(tmp_path, "edge")
        assert [row["name"] for row in doc["functions"]] == ["good"]
        assert doc["globals"] == []
        assert "edge: skipped 1" in result.output
        assert "data_edge.json" not in result.output

    def test_unparseable_global_va_falls_back_to_its_va_field(
        self, runner: CliRunner, tmp_path: Path, catalog: FakeCatalog
    ) -> None:
        """A global keyed by a name but carrying an int ``va`` lands at that VA."""
        catalog.per_target["edge"] = {
            "sections": {},
            "globals": {
                "g_weird": {"name": "g_weird", "va": 0x2000, "decl": "int g_weird;"},
                "no_va": {"name": "g_gone", "decl": "int g_gone;"},
            },
            "summary": {},
            "functions": {},
            "paths": {},
        }
        _write_config(tmp_path, "edge")

        assert _build(runner, tmp_path).exit_code == 0

        rows = _document(tmp_path, "edge")["globals"]
        assert [(row["va"], row["name"]) for row in rows] == [(0x2000, "g_weird")]

    def test_duplicate_cell_starts_keep_the_last_row(
        self,
        runner: CliRunner,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
        catalog: FakeCatalog,
    ) -> None:
        """A negative start clamped onto a real start=0 cell must not abort."""
        catalog.per_target["t"] = {
            "sections": {
                ".text": {
                    "va": 0x10000000,
                    "size": 256,
                    "unitBytes": 64,
                    "columns": 64,
                    "cells": [
                        {"start": -1, "end": 10, "span": 1, "state": "none"},
                        {
                            "start": 0,
                            "end": 10,
                            "span": 1,
                            "state": "exact",
                            "functions": ["f"],
                        },
                    ],
                },
            },
            "globals": {},
            "summary": {},
            "functions": {},
            "paths": {},
        }
        _write_config(tmp_path, "t")

        with caplog.at_level(logging.WARNING):
            result = _build(runner, tmp_path)

        assert result.exit_code == 0, result.output
        cells = _document(tmp_path, "t")["sections"][".text"]["cells"]
        assert [(cell["start"], cell["state"], cell["functions"]) for cell in cells] == [
            (0, "exact", ["f"])
        ]
        assert any("duplicate cell" in r.message for r in caplog.records)

    def test_duplicate_function_and_global_vas_keep_the_last_row(
        self,
        runner: CliRunner,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
        catalog: FakeCatalog,
    ) -> None:
        """Keys spelling one VA (hex and decimal) collapse; last row wins."""
        catalog.per_target["t"] = {
            "sections": {},
            "globals": {
                "0x10003000": {"name": "g_old", "size": 4},
                str(0x10003000): {"name": "g_new", "size": 4},
            },
            "summary": {},
            "functions": {
                "0x10001000": {"name": "f_old", "size": 16, "status": "STUB"},
                str(0x10001000): {"name": "f_new", "size": 16, "status": "EXACT"},
            },
            "paths": {},
        }
        _write_config(tmp_path, "t")

        with caplog.at_level(logging.WARNING):
            result = _build(runner, tmp_path)

        assert result.exit_code == 0, result.output
        doc = _document(tmp_path, "t")
        assert [(row["va"], row["name"], row["status"]) for row in doc["functions"]] == [
            (0x10001000, "f_new", "EXACT")
        ]
        assert [(row["va"], row["name"]) for row in doc["globals"]] == [(0x10003000, "g_new")]
        assert sum("duplicate" in r.message for r in caplog.records) == 2

    def test_negative_section_and_cell_extents_are_clamped(
        self, runner: CliRunner, tmp_path: Path, catalog: FakeCatalog
    ) -> None:
        """A stray negative from hand-edited JSON must not reach the document."""
        catalog.per_target["alpha"] = {
            "sections": {
                ".text": {
                    "va": -1,
                    "size": -64,
                    "fileOffset": -8,
                    "unitBytes": 0,
                    "columns": 0,
                    "cells": [{"start": 64, "end": 32, "span": 1, "state": "exact"}],
                },
            },
            "globals": {},
            "summary": {},
            "functions": {},
            "paths": {},
        }
        _write_config(tmp_path, "alpha")

        assert _build(runner, tmp_path).exit_code == 0

        section = _document(tmp_path, "alpha")["sections"][".text"]
        assert (section["va"], section["size"], section["fileOffset"]) == (0, 0, 0)
        # Non-positive geometry falls back rather than rendering a zero-width cell.
        assert (section["unitBytes"], section["columns"]) == (64, 64)
        # `end` is raised to `start`, so the span is empty rather than inverted.
        assert [(cell["start"], cell["end"]) for cell in section["cells"]] == [(64, 64)]

    def test_configured_db_dir_is_used(
        self, runner: CliRunner, tmp_path: Path, catalog: FakeCatalog
    ) -> None:
        """The output directory is the project's ``[project].db_dir``."""
        configured = tmp_path / "coverage"
        configured.mkdir()
        (tmp_path / "rebrew-project.toml").write_text(
            """\
[project]
default_target = "main"
db_dir = "coverage"

[targets.main]
binary = "test.exe"
""",
            encoding="utf-8",
        )

        assert _build(runner, tmp_path).exit_code == 0

        assert (configured / "coverage-main.toml").is_file()
        assert not (tmp_path / "db" / "coverage-main.toml").exists()


# ---------------------------------------------------------------------------
# Target selection
# ---------------------------------------------------------------------------


class TestRootResolution:
    """``--root`` is omitted the way ``rebrew verify`` omits it: walk up.

    The command used to default to ``Path.cwd()``, so running it from a
    subdirectory of a project reported a missing ``rebrew-project.toml`` there
    and left a stray ``db/`` behind.  ``require_root`` makes every command
    resolve the flag the same way.
    """

    def test_omitted_root_finds_the_project_from_a_subdirectory(
        self, runner: CliRunner, project_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        nested = project_root / "src" / "main" / "deep"
        nested.mkdir(parents=True)
        monkeypatch.chdir(nested)

        result = runner.invoke(app, [])

        assert result.exit_code == 0, result.output
        assert (project_root / "db" / "coverage-testbin.toml").is_file()
        assert not (nested / "db").exists()

    def test_outside_a_project_the_error_names_the_fix(
        self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        outside = tmp_path / "not-a-project"
        outside.mkdir()
        monkeypatch.chdir(outside)

        result = runner.invoke(app, [])

        assert result.exit_code == 2, result.output
        assert "rebrew-project.toml" in result.output


class TestTargetSelection:
    @staticmethod
    def _two_targets(root_dir: Path, catalog: FakeCatalog) -> None:
        for name in ("alpha", "beta"):
            data = copy.deepcopy(SAMPLE_DATA)
            data["functions"] = {
                f"func_{name}": {
                    "name": f"func_{name}",
                    "vaStart": "0x10001000",
                    "size": 64,
                    "status": "EXACT",
                }
            }
            catalog.per_target[name] = data
        _write_config(root_dir, "alpha", "beta")

    def test_scoped_run_writes_only_that_target(
        self, runner: CliRunner, tmp_path: Path, catalog: FakeCatalog
    ) -> None:
        self._two_targets(tmp_path, catalog)

        result = _build(runner, tmp_path, "--target", "alpha")

        assert result.exit_code == 0, result.output
        assert (tmp_path / "db" / "coverage-alpha.toml").is_file()
        assert not (tmp_path / "db" / "coverage-beta.toml").exists()
        assert [row["name"] for row in _document(tmp_path, "alpha")["functions"]] == ["func_alpha"]

    def test_unscoped_run_writes_every_target(
        self, runner: CliRunner, tmp_path: Path, catalog: FakeCatalog
    ) -> None:
        self._two_targets(tmp_path, catalog)

        assert _build(runner, tmp_path).exit_code == 0

        written = sorted(path.name for path in (tmp_path / "db").glob("coverage-*.toml"))
        assert written == ["coverage-alpha.toml", "coverage-beta.toml"]

    def test_a_scoped_run_leaves_the_other_document_alone(
        self, runner: CliRunner, tmp_path: Path, catalog: FakeCatalog
    ) -> None:
        """``--target alpha`` rewrites alpha and touches nothing else.

        The SQLite writer's scoped path deleted and restored rows per target;
        the TOML writer opens one file, so the sibling document must be
        byte-identical afterwards.
        """
        self._two_targets(tmp_path, catalog)
        assert _build(runner, tmp_path).exit_code == 0
        beta = tmp_path / "db" / "coverage-beta.toml"
        before = beta.read_bytes()

        assert _build(runner, tmp_path, "--target", "alpha").exit_code == 0

        assert beta.read_bytes() == before

    def test_nonexistent_target_exits(self, runner: CliRunner, project_root: Path) -> None:
        result = _build(runner, project_root, "--target", "nonexistent")

        assert result.exit_code == 2
        assert "Config error for target 'nonexistent'" in result.output
        assert not (project_root / "db" / "coverage-nonexistent.toml").exists()

    def test_a_target_repeated_in_all_targets_is_built_once(
        self, runner: CliRunner, tmp_path: Path, catalog: FakeCatalog
    ) -> None:
        """A target listed twice is one document.

        ``all_targets`` comes from config now, but a project that lists one
        target under two spellings normalized alike would otherwise be built
        twice and overwrite its own document.
        """
        _write_config(tmp_path, "alpha", "beta")
        shadowed = unicodedata.normalize("NFD", "café")
        assert shadowed != "café"
        _write_config(tmp_path, "alpha", shadowed, "beta")

        result = _build(runner, tmp_path)

        assert result.exit_code == 0, result.output
        assert catalog.asked == ["alpha", "café", "beta"]


# ---------------------------------------------------------------------------
# Output modes: --json and --force
# ---------------------------------------------------------------------------


class TestJsonAndForce:
    def test_json_reports_files_and_targets(self, runner: CliRunner, project_root: Path) -> None:
        result = _build(runner, project_root, "--json")

        assert result.exit_code == 0, result.output
        payload = _json_payload(result.output)
        assert payload["targets_processed"] == ["testbin"]
        assert payload["coverage_files"] == [str(project_root / "db" / "coverage-testbin.toml")]
        assert Path(payload["coverage_files"][0]).is_file()

    def test_json_lists_every_target_written(
        self, runner: CliRunner, tmp_path: Path, catalog: FakeCatalog
    ) -> None:
        _write_config(tmp_path, "alpha", "beta")

        result = _build(runner, tmp_path, "--json")

        assert result.exit_code == 0, result.output
        payload = _json_payload(result.output)
        assert payload["targets_processed"] == ["alpha", "beta"]
        assert [Path(path).name for path in payload["coverage_files"]] == [
            "coverage-alpha.toml",
            "coverage-beta.toml",
        ]
        # Nothing was printed outside the JSON envelope.
        assert "Wrote" not in result.output

        result = _build(runner, tmp_path, "--json")

        assert result.exit_code == 0, result.output
        payload = _json_payload(result.output)
        assert payload["targets_processed"] == ["alpha", "beta"]
        assert [Path(path).name for path in payload["coverage_files"]] == [
            "coverage-alpha.toml",
            "coverage-beta.toml",
        ]
        # Nothing was printed outside the JSON envelope.
        assert "Wrote" not in result.output

    def test_force_is_accepted_and_changes_nothing(
        self, runner: CliRunner, project_root: Path
    ) -> None:
        """``--force`` is a documented NO-OP: each document is replaced whole."""
        assert _build(runner, project_root).exit_code == 0
        path = project_root / "db" / "coverage-testbin.toml"
        first = path.read_bytes()

        result = _build(runner, project_root, "--force")

        assert result.exit_code == 0, result.output
        assert path.read_bytes() == first
        assert hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256(first).digest()

    def test_rerun_is_byte_identical_without_force(
        self, runner: CliRunner, project_root: Path
    ) -> None:
        """A rebuild of unchanged input writes the same bytes.

        The header carries no timestamp for exactly this reason, and the
        history array gains a row only when a status moves.
        """
        assert _build(runner, project_root).exit_code == 0
        path = project_root / "db" / "coverage-testbin.toml"
        first = path.read_bytes()

        assert _build(runner, project_root).exit_code == 0

        assert path.read_bytes() == first
        assert _document(project_root, "testbin")["history"] == []

    def test_history_records_a_status_change(
        self, runner: CliRunner, project_root: Path, catalog: FakeCatalog
    ) -> None:
        assert _build(runner, project_root).exit_code == 0

        catalog.data["functions"]["func_a"]["status"] = "RELOC"
        _write_config(project_root, "testbin")

        assert _build(runner, project_root).exit_code == 0

        history = _document(project_root, "testbin")["history"]
        assert [(row["va"], row["old_status"], row["new_status"]) for row in history] == [
            (0x10001000, "EXACT", "RELOC")
        ]


# ---------------------------------------------------------------------------
# Cell-state vocabulary
# ---------------------------------------------------------------------------


class TestCellStateVocabulary:
    """``docs/COVERAGE_DOCUMENT.md``'s Cell States table is the storable vocabulary.

    The set is derived from ``KNOWN_STATUSES`` plus the gap/data states, so
    adding an annotation ``STATUS`` widens it silently.  The doc is the only
    place a reader learns which states a document may hold, and it already
    omitted ``extract_error`` / ``invalid_va`` / ``verified`` / ``drift`` /
    ``unchecked`` while the writer accepted all five.
    """

    def test_documented_cell_states_match_the_known_set(self) -> None:
        import re

        doc = (Path(__file__).resolve().parents[1] / "docs" / "COVERAGE_DOCUMENT.md").read_text(
            encoding="utf-8"
        )
        section = doc.split("#### Cell States", 1)[1].split("\n### ", 1)[0]
        documented = {
            state
            for line in section.splitlines()
            if line.startswith("| `")
            for state in re.findall(r"`([a-z_]+)`", line.split("|")[1])
        }
        assert documented == _KNOWN_CELL_STATES

    def test_every_known_state_round_trips_into_a_document(
        self,
        runner: CliRunner,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
        catalog: FakeCatalog,
    ) -> None:
        """No state is coerced to ``unknown``: each one is stored verbatim."""
        states = sorted(_KNOWN_CELL_STATES)
        catalog.per_target["vocab"] = {
            "sections": {
                ".text": {
                    "va": 0x1000,
                    "size": 64 * len(states),
                    "unitBytes": 64,
                    "columns": 64,
                    "cells": [
                        {
                            "start": index * 64,
                            "end": (index + 1) * 64,
                            "span": 1,
                            "state": state,
                        }
                        for index, state in enumerate(states)
                    ],
                },
            },
            "globals": {},
            "summary": {},
            "functions": {},
            "paths": {},
        }
        _write_config(tmp_path, "vocab")

        with caplog.at_level(logging.WARNING):
            result = _build(runner, tmp_path)

        assert result.exit_code == 0, result.output
        assert "not in known set" not in result.output
        stored = [
            cell["state"] for cell in _document(tmp_path, "vocab")["sections"][".text"]["cells"]
        ]
        assert stored == states
