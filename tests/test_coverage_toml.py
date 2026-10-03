"""Tests for coverage_toml.py — the clear-text TOML coverage writer.

The load-bearing test is :class:`TestParityWithBuildDb`: it feeds one synthetic
catalog through both this writer and the pure normalization ``build_db`` uses,
and requires the file to say the same thing about every field.  A field the TOML
adds, drops or re-spells shows up there as a diff, which is the whole point of
reusing those helpers instead of transcribing them.
"""

import copy
import json
import logging
import os
import re
import tomllib
import unicodedata
from collections.abc import Callable
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

import pytest

from rebrew import coverage_toml, utils
from rebrew.coverage_db import (
    _KNOWN_CELL_STATES,
    HISTORY_RETENTION,
    clamp_nonneg_int,
    dedupe_cell_rows,
    normalize_cell_row,
    parse_int,
    resolve_db_dir,
)
from rebrew.coverage_toml import (
    _FUNCTION_COLUMNS,
    _GLOBAL_COLUMNS,
    _TOML_VERSION,
    _VERIFY_RESULTS_COLUMNS,
    CoverageSnapshot,
    CoverageTomlError,
    Function,
    Global,
    _read_previous,
    load_all_coverage,
    load_coverage,
    render_coverage_toml,
    write_coverage_toml,
)
from rebrew.utils import atomic_write_text, floor_pct

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TARGET = "server.dll"

#: One cell per known state, so an unmapped or renamed state cannot pass.
#: Distinct starts: two cells sharing one are deduped, and the whole class
#: would then be asserting nothing.
STATE_CELLS: list[dict[str, Any]] = [
    {
        "start": index * 64,
        "end": (index + 1) * 64,
        "span": 1,
        "state": state,
        "functions": [f"fn_{state}"],
    }
    for index, state in enumerate(sorted(_KNOWN_CELL_STATES))
]

SAMPLE_DATA: dict[str, Any] = {
    "sections": {
        ".text": {
            "va": 0x10001000,
            "size": 4096,
            "fileOffset": 0x1000,
            "unitBytes": 64,
            "columns": 64,
            "cells": [
                *STATE_CELLS,
                # Hand-edited case, a padded cell, and a cell carrying both
                # optional fields.
                {"start": 4096, "end": 4160, "span": 2, "state": "EXACT", "functions": []},
                {"start": 4160, "end": 4224, "span": 1, "state": "padding", "functions": []},
                {
                    "start": 4224,
                    "end": 4288,
                    "span": 1,
                    "state": "data",
                    "functions": ["0x10001000"],
                    "label": "s_g_counter",
                    "parent_function": "adler32",
                },
                {"start": 4288, "end": 4300, "span": 1, "functions": None},
            ],
        },
        ".data": {
            "va": 0x10030000,
            "size": 256,
            "fileOffset": 0x2000,
            "unitBytes": 0,
            "columns": -1,
            "cells": [
                {"start": 0, "end": 16, "span": 1, "state": "exact", "functions": ["g_a"]},
                {"start": 16, "end": 32, "span": 1, "state": "thunk", "functions": []},
            ],
        },
        # No va / fileOffset: exercises the None → "" half of the schema.
        ".bss": {"size": 8, "cells": []},
    },
    "globals": {
        "0x10030000": {
            "va": 0x10030000,
            "name": "g_counter",
            "decl": "int g_counter;",
            "files": ["globals.c"],
            "origin": "GAME",
            "size": 4,
            "status": "verified",
        },
        "0x10030100": {
            "name": "g_buffer",
            "files": [],
            "size": -8,
            "status": "nonsense",
        },
        # Unparseable VA: skipped, with a warning.
        "not-a-va": {"va": "zzz", "name": "g_bad", "size": 4},
    },
    "functions": {
        "0x10001000": {
            "name": "adler32",
            "size": 304,
            "status": "exact",
            "module": "GAME",
            "markerType": "FUNCTION",
            "cflags": ["-O2"],
            "symbol": "adler32",
            "fileOffset": 0x1000,
            "textOffset": 0x20,
            "sha256": "abc",
            "files": ["zlib.c"],
            "detected_by": ["flirt"],
            "size_by_tool": {"gcc": 300},
            "similarity": 1.5,
            "is_export": True,
            "updated_by": "tester",
            "updated_at": "2026-01-01T00:00:00+00:00",
        },
        # Key unparseable, vaStart usable.  No markerType, fileOffset or
        # similarity: exercises the "" half of every optional field.
        "zzz": {"vaStart": "0x10001100", "name": "crc32", "size": 16, "status": "STUB"},
        # Neither key nor vaStart parseable: skipped, with a warning.
        # ("0xdead" would not do — it is a valid hex address.)
        "not_a_va": {"name": "no_va", "size": 4},
        "0x10001200": {"name": "a_lib", "size": 4, "status": "RELOC", "markerType": "LIBRARY"},
        # A data row: build_db's marker filter must keep it out of
        # function_stats even though the file still stores it.
        "0x10001300": {"name": "a_data", "size": 8, "status": "EXACT", "markerType": "DATA"},
        # An unknown markerType sanitizes to FUNCTION rather than being kept.
        "0x10001400": {"name": "a_nope", "size": 2, "status": "STUB", "markerType": "NOPE"},
    },
    "paths": {"bin": "build/server.dll", "orig": "src"},
    "summary": {"totalFunctions": 4, "coveragePercent": 50.0},
}


@pytest.fixture
def data() -> dict[str, Any]:
    return copy.deepcopy(SAMPLE_DATA)


@pytest.fixture
def write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Callable[[dict[str, Any]], list[Path]]:
    """Return a writer that runs the real entry point over a faked catalog read.

    Only ``load_coverage_datasets`` is replaced, so the db_dir resolution, the
    previous-file read, the atomic write and every normalization stay on the
    path under test.  The seam is patched where it is used: the module imports
    the helper by name, so patching ``rebrew.build_db`` would leave this
    module's binding alone.
    """
    (tmp_path / "db").mkdir()

    def _write(target_data: dict[str, Any]) -> list[Path]:
        monkeypatch.setattr(
            coverage_toml,
            "load_coverage_datasets",
            lambda *a, **k: [(TARGET, target_data)],
            raising=True,
        )
        return write_coverage_toml(tmp_path)

    return _write


@pytest.fixture
def written(write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any]) -> dict[str, Any]:
    """The parsed document for one write of :data:`SAMPLE_DATA`."""
    paths = write(data)
    assert [path.name for path in paths] == [f"coverage-{TARGET}.toml"]
    return tomllib.loads(paths[0].read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# 1. Parity with the source data
# ---------------------------------------------------------------------------


class TestParityWithBuildDb:
    def test_top_level_and_metadata(self, written: dict[str, Any]) -> None:
        assert written["version"] == _TOML_VERSION
        assert written["target"] == TARGET
        # `paths` is a fact from catalog.  `function_stats` is NOT here: it is a
        # pure function of the rows below it and is derived at load instead.
        assert written["metadata"] == {"paths": SAMPLE_DATA["paths"]}

    def test_sections_round_trip(self, written: dict[str, Any]) -> None:
        sections = written["sections"]
        assert sorted(sections) == [".bss", ".data", ".text"]
        # Non-positive geometry falls back, exactly as the sections row does.
        assert sections[".data"]["unitBytes"] == 64
        assert sections[".data"]["columns"] == 64
        # Absent va/fileOffset become "", never a fabricated 0.
        assert sections[".bss"]["va"] == ""
        assert sections[".bss"]["fileOffset"] == ""
        assert sections[".text"]["va"] == 0x10001000
        assert sections[".text"]["size"] == 4096
        assert sections[".text"]["fileOffset"] == 0x1000
        assert sections[".text"]["unitBytes"] == 64
        assert sections[".text"]["columns"] == 64

    def test_cells_match_the_normalizer(self, written: dict[str, Any]) -> None:
        expected = _reference_cell_rows(SAMPLE_DATA["sections"][".text"]["cells"])
        got = written["sections"][".text"]["cells"]
        # dedupe_cell_rows sorts by start, and so does the file's row order.
        expected.sort(key=lambda row: row[2])
        assert [row["start"] for row in got] == [row[2] for row in expected]
        for row, want in zip(got, expected, strict=True):
            # _CellRow: (target, section, start, end, span, state, functions,
            # label, parent_function)
            assert row["section"] == want[1]
            assert row["start"] == want[2]
            assert row["end"] == want[3]
            assert row["span"] == want[4]
            assert row["state"] == want[5]
            # The DB stores functions as a JSON string; the file stores the
            # array build_db serialized.
            assert row["functions"] == json.loads(want[6])
            assert row["label"] == (want[7] or "")
            assert row["parent_function"] == (want[8] or "")
        # _reference_cell_rows runs the same normalizer the writer runs, so a
        # regression there moves both sides at once.  One row is pinned to
        # literals from SAMPLE_DATA to keep the comparison honest.
        labelled = next(row for row in got if row["start"] == 4224)
        assert labelled == {
            "section": ".text",
            "start": 4224,
            "end": 4288,
            "span": 1,
            "state": "data",
            "functions": ["0x10001000"],
            "label": "s_g_counter",
            "parent_function": "adler32",
        }

    def test_every_known_state_round_trips(self, written: dict[str, Any]) -> None:
        states = {row["state"] for row in written["sections"][".text"]["cells"]}
        assert set(_KNOWN_CELL_STATES) <= states
        # Case-folded by _canonical_cell_state, not stored verbatim.
        assert "exact" in states
        assert "EXACT" not in states

    def test_functions_match_the_field_mapping(self, written: dict[str, Any]) -> None:
        got = {row["va"]: row for row in written["functions"]}
        assert sorted(got) == [0x10001000, 0x10001100, 0x10001200, 0x10001300, 0x10001400]
        adler = got[0x10001000]
        assert set(adler) == set(_FUNCTION_COLUMNS)
        assert adler["name"] == "adler32"
        assert adler["vaStart"] == "0x10001000"
        assert adler["size"] == 304
        assert adler["fileOffset"] == 0x1000
        assert adler["status"] == "EXACT"
        assert adler["module"] == "GAME"
        assert adler["cflags"] == ["-O2"]
        assert adler["symbol"] == "adler32"
        assert adler["markerType"] == "FUNCTION"
        assert adler["is_export"] == 1
        assert adler["is_thunk"] == 0
        assert adler["sha256"] == "abc"
        assert adler["files"] == ["zlib.c"]
        assert adler["detected_by"] == ["flirt"]
        assert adler["size_by_tool"] == {"gcc": 300}
        assert adler["textOffset"] == 0x20
        assert adler["similarity"] == 1.0
        assert adler["updated_by"] == "tester"
        assert adler["updated_at"] == "2026-01-01T00:00:00+00:00"
        # A missing key falls back to vaStart, exactly as the DB row does; an
        # unknown markerType sanitizes to FUNCTION rather than being kept.
        assert got[0x10001100]["name"] == "crc32"
        assert got[0x10001100]["vaStart"] == "0x10001100"
        assert got[0x10001100]["status"] == "STUB"
        assert got[0x10001200]["markerType"] == "LIBRARY"
        assert got[0x10001300]["markerType"] == "DATA"
        assert got[0x10001400]["markerType"] == "FUNCTION"
        # Absent optional fields become "", not 0 — a fabricated 0 would read
        # as a real size/offset.
        assert got[0x10001100]["fileOffset"] == ""
        assert got[0x10001100]["similarity"] == ""

    def test_globals_match_the_field_mapping(self, written: dict[str, Any]) -> None:
        got = {row["va"]: row for row in written["globals"]}
        assert sorted(got) == [0x10030000, 0x10030100]
        counter = got[0x10030000]
        assert set(counter) == set(_GLOBAL_COLUMNS)
        assert counter["name"] == "g_counter"
        assert counter["decl"] == "int g_counter;"
        assert counter["files"] == ["globals.c"]
        assert counter["module"] == "GAME"
        assert counter["size"] == 4
        assert counter["status"] == "VERIFIED"
        # Negative size clamps to 0; an unknown status empties.
        assert got[0x10030100]["size"] == 0
        assert got[0x10030100]["status"] == ""


# ---------------------------------------------------------------------------
# 2. Derived-not-stored
# ---------------------------------------------------------------------------


class TestDerivedNotStored:
    def test_emitted_text_carries_no_derived_objects(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any]
    ) -> None:
        text = write(data)[0].read_text(encoding="utf-8")
        for derived in ("section_cell_stats", "coverage_pct", "coveragePercent", "cells_json"):
            assert derived not in text

    def test_scalars_are_derivable_from_the_written_rows(self, written: dict[str, Any]) -> None:
        """A per-section byte total is a fold over cells, not a stored column."""
        cells = written["sections"][".data"]["cells"]
        assert sum(row["end"] - row["start"] for row in cells) == 32
        # No stored byte total per cell, and no per-section one either.
        assert all("size" not in row and "bytes" not in row for row in cells)
        assert "stats" not in written["sections"][".data"]
        # span is stored: it is a fact from the catalog, not a derivation.
        assert all("span" in row for row in cells)


# ---------------------------------------------------------------------------
# 3./4. Unparseable rows and unknown states
# ---------------------------------------------------------------------------


class TestSkippedRows:
    def test_unparseable_function_and_global_are_skipped(
        self,
        write: Callable[[dict[str, Any]], list[Path]],
        data: dict[str, Any],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # The write happens here, not in a fixture: the warnings go to the
        # Rich stderr console and this is the read that sees them.
        doc = tomllib.loads(write(data)[0].read_text(encoding="utf-8"))
        out = re.sub(r"\s+", " ", capsys.readouterr().err)
        assert "skipped 1 function row(s) with unparseable VA (no valid key or vaStart)" in out
        assert "skipped 1 global row(s) with unparseable VA (no valid key or va field)" in out
        # Absent, not fatal: the good rows are still there.
        assert sorted(row["va"] for row in doc["functions"]) == [
            0x10001000,
            0x10001100,
            0x10001200,
            0x10001300,
            0x10001400,
        ]
        assert len(doc["globals"]) == 2

    def test_unknown_cell_state_coerces_and_warns(
        self,
        write: Callable[[dict[str, Any]], list[Path]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        data = copy.deepcopy(SAMPLE_DATA)
        data["sections"][".text"]["cells"].append(
            {"start": 9999, "end": 10000, "span": 1, "state": "brand_new", "functions": []}
        )
        doc = tomllib.loads(write(data)[0].read_text(encoding="utf-8"))
        cell = next(c for c in doc["sections"][".text"]["cells"] if c["start"] == 9999)
        assert cell["state"] == "unknown"
        assert "brand_new" in caplog.text


# ---------------------------------------------------------------------------
# 5. History carry-forward
# ---------------------------------------------------------------------------


class TestHistory:
    def test_status_change_is_recorded_and_old_rows_survive(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any]
    ) -> None:
        path = write(data)[0]
        first = tomllib.loads(path.read_text(encoding="utf-8"))
        assert first["history"] == []

        # A status change on one function, and a second build carrying it.
        data["functions"]["0x10001000"]["status"] = "RELOC"
        write(data)
        second = tomllib.loads(path.read_text(encoding="utf-8"))
        assert len(second["history"]) == 1
        row = second["history"][0]
        assert row["va"] == 0x10001000
        assert (row["old_status"], row["new_status"]) == ("EXACT", "RELOC")
        assert row["changed_at"]
        assert row["updated_by"] == "tester"

        # A third build with no change keeps the row and adds nothing.
        write(data)
        third = tomllib.loads(path.read_text(encoding="utf-8"))
        assert third["history"] == second["history"]

    def test_retention_cap(self, data: dict[str, Any]) -> None:
        previous = {
            "version": _TOML_VERSION,
            # A previous STUB for a function the fixture now reports EXACT, so
            # this build contributes one delta of its own.
            "functions": [{"va": 0x10001000, "status": "STUB"}],
            "history": [
                {
                    "va": 0x10001000,
                    "old_status": "STUB",
                    "new_status": "EXACT",
                    "changed_at": _minute_stamp(i),
                    "updated_by": "seed",
                }
                for i in range(HISTORY_RETENTION + 50)
            ],
        }
        doc = tomllib.loads(render_coverage_toml(TARGET, copy.deepcopy(data), previous=previous))
        history = doc["history"]
        # 10050 carried + 1 new, capped at the same retention the DB uses.
        assert len(history) == HISTORY_RETENTION
        # Oldest 51 carried rows dropped; this build's delta is the newest.
        assert history[0]["changed_at"] == _minute_stamp(51)
        assert (history[-1]["old_status"], history[-1]["new_status"]) == ("STUB", "EXACT")
        assert history[-1]["updated_by"] == "tester"

    def test_older_version_file_starts_history_empty(self, data: dict[str, Any]) -> None:
        previous = {
            "version": _TOML_VERSION - 1,
            "history": [{"va": 1, "changed_at": "2020-01-01T00:00:00+00:00"}],
        }
        doc = tomllib.loads(render_coverage_toml(TARGET, data, previous=previous))
        assert doc["history"] == []

    def test_unreadable_previous_file_starts_history_empty(self, tmp_path: Path) -> None:
        assert _read_previous(tmp_path / "missing.toml") == {}
        broken = tmp_path / "broken.toml"
        broken.write_text("this is not = = toml", encoding="utf-8")
        assert _read_previous(broken) == {}


# ---------------------------------------------------------------------------
# 6. verify_results: the cache is the source, the previous file is the fallback
# ---------------------------------------------------------------------------


def _write_cache(root: Path, target: str, entries: Any, *, mtime_ns: int | None = None) -> Path:
    """Seed ``.rebrew/verify_cache.toml`` — the verify_results import source.

    Same document shape ``tests/test_build_db.py`` seeds, because this file's
    rows have to be the rows that writer imports: one implementation, two
    destinations.
    """
    cache_dir = root / ".rebrew"
    cache_dir.mkdir(exist_ok=True)
    from cache_util import cache_text

    path = cache_dir / "verify_cache.toml"
    path.write_text(
        cache_text({"version": 2, "target": target, "entries": entries}), encoding="utf-8"
    )
    if mtime_ns is not None:
        os.utime(path, ns=(mtime_ns, mtime_ns))
    return path


def _cache_stamp(path: Path) -> str:
    """The stamp the writer derives from *path*: the cache file's mtime, UTC."""
    return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).isoformat()


class TestVerifyResults:
    """A first run publishes the cache's rows instead of writing none.

    The whole defect: the writer only ever carried ``verify_results`` forward
    from a previous file, so a project whose TOML was written once — every
    project, the first time — shipped an empty table and the dashboard's
    ``last_verify`` panel had nothing to read.
    """

    ENTRY: dict[str, Any] = {
        "va": "0x10001000",
        "status": "NEAR_MATCHING",
        "delta": 3,
        "diff_lines": 7,
        "similarity": 85.5,
        "reg_delta": 2,
        "effective_match": True,
    }

    def test_entries_produce_rows(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        cache = _write_cache(tmp_path, TARGET, {"0x10001000": self.ENTRY})
        doc = tomllib.loads(write(data)[0].read_text(encoding="utf-8"))

        assert len(doc["verify_results"]) == 1
        row = doc["verify_results"][0]
        # The file's row shape IS the database's row shape, less `target`: the
        # same column names the dashboard's `last_verify` payload reads.
        assert set(row) == set(_VERIFY_RESULTS_COLUMNS)
        assert row["va"] == 0x10001000
        assert row["byte_delta"] == 3
        assert row["diff_lines"] == 7
        # Percent scale in the cache, unit interval in the column.
        assert row["similarity"] == pytest.approx(0.855)
        assert row["reg_delta"] == 2
        assert row["effective_match"] == 1
        assert row["verified_at"] == _cache_stamp(cache)

        # And the reader the dashboards use sees them.
        assert len(load_coverage(tmp_path, TARGET).verify_results) == 1

    def test_absent_values_are_empty_not_zero(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        """A verdict with no diff_lines is not a verdict with 0 of them."""
        _write_cache(tmp_path, TARGET, {"0x10001000": {"va": "0x10001000", "delta": 3}})
        row = tomllib.loads(write(data)[0].read_text(encoding="utf-8"))["verify_results"][0]
        assert row["byte_delta"] == 3
        assert row["diff_lines"] == ""
        assert row["similarity"] == ""
        assert row["reg_delta"] == ""
        assert row["effective_match"] == ""

    def test_a_foreign_cache_keeps_the_previous_rows(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        """A cache measured for another target must not overwrite this file.

        The identity guard is the one ``rebrew verify`` uses, so a stale cache
        left by a rebuild of a different binary cannot be republished as this
        target's current verdicts.
        """
        _write_cache(tmp_path, TARGET, {"0x10001000": self.ENTRY})
        path = write(data)[0]
        first = tomllib.loads(path.read_text(encoding="utf-8"))["verify_results"]
        assert len(first) == 1

        # Another target's cache: ours by nothing but the file's location.
        _write_cache(tmp_path, "other.dll", {"0x20002000": {"va": "0x20002000", "delta": 9}})
        second = tomllib.loads(write(data)[0].read_text(encoding="utf-8"))["verify_results"]
        assert second == first

    def test_an_unusable_cache_keeps_the_previous_rows(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        """A table whose every VA is unusable is not an empty table.

        The distinction the shared importer draws with ``None`` vs ``[]``: one
        corrupt cache entry must not wipe a target's verdicts.
        """
        _write_cache(tmp_path, TARGET, {"0x10001000": self.ENTRY})
        path = write(data)[0]
        first = tomllib.loads(path.read_text(encoding="utf-8"))["verify_results"]

        # TOML has no null: a missing va would fall back to the table key and
        # read as usable, so the unusable row spells a va that cannot parse,
        # which is the same rejected entry the JSON-era null produced.
        _write_cache(tmp_path, TARGET, {"0x10001000": {"va": "not-a-va", "delta": 3}})
        second = tomllib.loads(write(data)[0].read_text(encoding="utf-8"))["verify_results"]
        assert second == first

    def test_an_empty_entries_table_prunes(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        """The target was fully unverified, so its rows go — it IS an answer."""
        _write_cache(tmp_path, TARGET, {"0x10001000": self.ENTRY})
        path = write(data)[0]
        assert len(tomllib.loads(path.read_text(encoding="utf-8"))["verify_results"]) == 1

        _write_cache(tmp_path, TARGET, {})
        assert tomllib.loads(write(data)[0].read_text(encoding="utf-8"))["verify_results"] == []
        assert load_coverage(tmp_path, TARGET).verify_results == ()

    def test_unchanged_measurements_keep_the_earlier_stamp(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        """``verified_at`` is when the verdict was measured, not when it was read.

        The cache's mtime moves on every verify run, so stamping it on every
        rebuild would relabel an unchanged verdict as freshly measured.
        """
        cache = _write_cache(tmp_path, TARGET, {"0x10001000": self.ENTRY})
        path = write(data)[0]
        first = tomllib.loads(path.read_text(encoding="utf-8"))["verify_results"][0]
        assert first["verified_at"] == _cache_stamp(cache)

        # Same verdict, re-written cache: the mtime moves, the measurement
        # time does not.  Bumped explicitly so the test cannot pass on a
        # same-second mtime that never moved at all.
        cache = _write_cache(tmp_path, TARGET, {"0x10001000": self.ENTRY})
        bumped = cache.stat().st_mtime_ns + 10**9
        os.utime(cache, ns=(bumped, bumped))
        again = tomllib.loads(write(data)[0].read_text(encoding="utf-8"))["verify_results"][0]
        assert again["verified_at"] == first["verified_at"]

        # A verdict that actually changed is re-measured, so its stamp moves to
        # the cache's new mtime.
        changed = dict(self.ENTRY, delta=9)
        cache = _write_cache(tmp_path, TARGET, {"0x10001000": changed})
        bumped = cache.stat().st_mtime_ns + 2 * 10**9
        os.utime(cache, ns=(bumped, bumped))
        third = tomllib.loads(write(data)[0].read_text(encoding="utf-8"))["verify_results"][0]
        assert third["byte_delta"] == 9
        assert third["verified_at"] == _cache_stamp(cache)
        assert third["verified_at"] != first["verified_at"]

    def test_no_cache_writes_none_and_keeps_what_was_there(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        """A project with no cache publishes nothing, and rewrites nothing away."""
        path = write(data)[0]
        assert tomllib.loads(path.read_text(encoding="utf-8"))["verify_results"] == []

        previous = {
            "version": _TOML_VERSION,
            "verify_results": [
                {
                    "va": 0x10001000,
                    "verified_at": "2026-01-01T00:00:00+00:00",
                    "byte_delta": 3,
                }
            ],
        }
        doc = tomllib.loads(render_coverage_toml(TARGET, data, previous=previous))
        assert doc["verify_results"] == previous["verify_results"]


# ---------------------------------------------------------------------------
# 6. Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_two_writes_are_byte_identical(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any]
    ) -> None:
        path = write(data)[0]
        first = path.read_bytes()
        write(data)
        assert path.read_bytes() == first

    def test_key_insertion_order_does_not_change_the_file(self, data: dict[str, Any]) -> None:
        """The catalog's JSON key order is stable but meaningless; VA order wins."""
        shuffled = copy.deepcopy(data)
        shuffled["functions"] = dict(reversed(list(data["functions"].items())))
        shuffled["globals"] = dict(reversed(list(data["globals"].items())))
        assert render_coverage_toml(TARGET, shuffled) == render_coverage_toml(TARGET, data)

    def test_no_array_of_tables(self, data: dict[str, Any]) -> None:
        """[[cells]] is the slow form; the whole file must not contain one."""
        text = render_coverage_toml(TARGET, data)
        assert "[[" not in text

    def test_the_appended_row_replays_from_its_instant(self, data: dict[str, Any]) -> None:
        """A replayed build stamps its delta from the instant it is given.

        The wall clock is the one input a driver cannot reproduce, so the row a
        build appends is the only part of the document that could differ
        between two runs of the same scan.
        """
        previous = {
            "version": _TOML_VERSION,
            "functions": [{"va": 0x10001000, "status": "STUB"}],
            "history": [],
        }
        stamp = datetime(2024, 1, 1, 12, 0, tzinfo=UTC)
        first = tomllib.loads(
            render_coverage_toml(TARGET, copy.deepcopy(data), previous=previous, now=stamp)
        )
        second = tomllib.loads(
            render_coverage_toml(TARGET, copy.deepcopy(data), previous=previous, now=stamp)
        )
        assert first == second
        assert first["history"][-1]["changed_at"] == stamp.isoformat()


# ---------------------------------------------------------------------------
# 7. Atomicity
# ---------------------------------------------------------------------------


class TestAtomic:
    def test_no_tmp_left_after_a_successful_write(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any]
    ) -> None:
        path = write(data)[0]
        assert path.is_file()
        assert list(path.parent.glob("*.tmp")) == []

    def test_failed_write_leaves_the_previous_file_intact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "coverage-x.toml"
        atomic_write_text(path, "good\n")

        def boom(src: object, dst: object) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(cast(Any, utils).os, "replace", boom)
        with pytest.raises(OSError, match="disk full"):
            atomic_write_text(path, "bad\n")
        assert path.read_text(encoding="utf-8") == "good\n"
        assert list(tmp_path.glob("*.tmp")) == []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minute_stamp(minutes: int) -> str:
    """A strictly increasing ISO-8601 stamp *minutes* after 2026-01-01T00:00Z.

    Retention sorts the stamps as text, which is only chronological because
    they are zero-padded ISO instants — the property `_merge_history` relies
    on and this seed has to actually have.
    """
    day, rest = divmod(minutes, 24 * 60)
    hour, minute = divmod(rest, 60)
    return f"2026-01-{1 + day:02d}T{hour:02d}:{minute:02d}:00+00:00"


def _reference_cell_rows(cells: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    return dedupe_cell_rows(
        [normalize_cell_row(TARGET, ".text", cell) for cell in cells if isinstance(cell, dict)],
        target_name=TARGET,
        sec_name=".text",
    )


def test_resolve_db_dir_is_the_source_of_the_output_dir(tmp_path: Path) -> None:
    assert resolve_db_dir(tmp_path) == tmp_path / "db"


def test_parse_int_is_not_reimplemented() -> None:
    """The writer borrows build_db's integer parsing, including its 64-bit cap."""
    assert parse_int("0x10") == 16
    assert parse_int(2**63, default=-1) == -1


# ---------------------------------------------------------------------------
# 8. The reader: round-trip, derived values, immutability, memo, failures
# ---------------------------------------------------------------------------

#: ``_FUNCTION_COLUMNS`` entries build_db allows NULL.  A NULL reaches the file
#: as ``""``, and the reader's contract is that those read back as ``None``
#: (an unknown size is not size 0) while text columns keep the empty string.
#: Taken from build_db's ``functions`` DDL, not from the reader.
_NULLABLE_FUNCTION_COLUMNS = frozenset(
    {"size", "fileOffset", "textOffset", "blockerDelta", "similarity"}
)


def _stored(value: Any) -> Any:
    """The reader's shape for a stored TOML value: arrays become tuples, tables
    become read-only mappings, scalars stay as written."""
    if isinstance(value, list):
        return tuple(value)
    if isinstance(value, dict):
        return MappingProxyType(value)
    return value


class TestRoundTrip:
    """Reader fields equal the rows the writer wrote, field for field."""

    def test_sections_and_cells(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        path = write(data)[0]
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
        snap = load_coverage(tmp_path, TARGET)

        assert snap.target == TARGET
        assert snap.version == _TOML_VERSION
        assert sorted(snap.sections) == sorted(doc["sections"])
        for name, table in doc["sections"].items():
            section = snap.sections[name]
            assert section.name == name
            assert section.size == table["size"]
            # `file_offset` and `va` keep the None: a `.bss` has no file offset
            # at all, and reading that back as 0 is what let `/asm` and
            # `/bytes` serve bytes from the start of the file for a section
            # that has none.  The scalars below have no absent value to spell.
            assert section.file_offset == (table["fileOffset"] or None)
            assert section.unit_bytes == table["unitBytes"]
            assert section.columns == table["columns"]
            # NULL va: the file spells it "", the reader reads it as None.
            assert section.va == (table["va"] or None)
            assert len(section.cells) == len(table["cells"])
            for cell, row in zip(section.cells, table["cells"], strict=True):
                assert cell.start == row["start"]
                assert cell.end == row["end"]
                assert cell.span == row["span"]
                assert cell.state == row["state"]
                assert cell.functions == tuple(row["functions"])
                assert cell.label == row["label"]
                assert cell.parent_function == row["parent_function"]
                assert cell.size == row["end"] - row["start"]

        # The concrete rows, not just the frozen ones: a NaN-ish default would
        # still compare equal to a table that stored the same wrong value.
        text = snap.sections[".text"]
        assert (text.va, text.size, text.file_offset) == (0x10001000, 4096, 0x1000)
        assert text.unit_bytes == 64 and text.columns == 64
        assert snap.sections[".bss"].va is None
        # An absent fileOffset stays absent: a `.bss` has no file offset at
        # all, and collapsing it to 0 is what made a section with no file
        # bytes indistinguishable from one starting at offset 0.
        assert snap.sections[".bss"].file_offset is None
        assert snap.sections[".data"].unit_bytes == 64  # 0 fell back, as the writer does
        labelled = next(cell for cell in text.cells if cell.label)
        assert (labelled.label, labelled.parent_function) == ("s_g_counter", "adler32")
        assert labelled.functions == ("0x10001000",)
        assert labelled.size == 64
        # functions = None in the catalog is stored as [], not as a crash.
        assert any(cell.functions == () for cell in text.cells)

    def test_functions_match_the_stored_columns(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        path = write(data)[0]
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
        snap = load_coverage(tmp_path, TARGET)

        # The class IS the writer's column list: a column added, dropped or
        # renamed there fails here rather than being silently omitted.
        assert tuple(Function.__slots__) == _FUNCTION_COLUMNS
        assert sorted(snap.functions_by_va) == sorted(row["va"] for row in doc["functions"])
        assert [fn.va for fn in snap.functions] == [row["va"] for row in doc["functions"]]

        for row in doc["functions"]:
            fn = snap.functions_by_va[row["va"]]
            for column in _FUNCTION_COLUMNS:
                stored = row[column]
                expected = (
                    None
                    if column in _NULLABLE_FUNCTION_COLUMNS and stored == ""
                    else _stored(stored)
                )
                assert getattr(fn, column) == expected, (column, row["va"])

        # One row written out in full: types, and both halves of the NULL rule.
        assert snap.functions_by_va[0x10001000] == Function(
            va=0x10001000,
            name="adler32",
            vaStart="0x10001000",
            size=304,
            fileOffset=0x1000,
            status="EXACT",
            module="GAME",
            cflags=("-O2",),
            symbol="adler32",
            markerType="FUNCTION",
            ghidra_name="",
            list_name="",
            is_thunk=0,
            is_export=1,
            sha256="abc",
            files=("zlib.c",),
            detected_by=("flirt",),
            size_by_tool={"gcc": 300},
            textOffset=0x20,
            blocker="",
            blockerDelta=None,
            size_reason="",
            similarity=1.0,
            updated_by="tester",
            updated_at="2026-01-01T00:00:00+00:00",
        )
        crc = snap.functions_by_va[0x10001100]
        assert (crc.name, crc.vaStart, crc.status) == ("crc32", "0x10001100", "STUB")
        assert (crc.size, crc.fileOffset, crc.textOffset, crc.similarity) == (16, None, None, None)
        assert crc.files == () and crc.detected_by == ()
        assert dict(crc.size_by_tool) == {}
        assert crc.is_thunk == 0 and crc.is_export == 0

    def test_globals_match_the_stored_columns(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        path = write(data)[0]
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
        snap = load_coverage(tmp_path, TARGET)

        assert tuple(Global.__slots__) == _GLOBAL_COLUMNS
        assert len(snap.globals) == len(doc["globals"])
        by_va = {g.va: g for g in snap.globals}
        for row in doc["globals"]:
            g = by_va[row["va"]]
            for column in _GLOBAL_COLUMNS:
                assert getattr(g, column) == _stored(row[column]), (column, row["va"])
        assert by_va[0x10030000] == Global(
            va=0x10030000,
            name="g_counter",
            decl="int g_counter;",
            files=("globals.c",),
            declared_in=("globals.c",),
            module="GAME",
            size=4,
            status="VERIFIED",
        )

    def test_metadata_holds_only_facts(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        """Nothing derivable is written, and the reader derives it anyway.

        `function_stats` is a pure function of the function rows, so a stored
        copy would be a second thing to keep in step on every rebuild.  It is
        not in the file, and the snapshot carries it regardless.
        """
        path = write(data)[0]
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
        assert "function_stats" not in doc["metadata"]
        snap = load_coverage(tmp_path, TARGET)
        assert snap.function_stats["total"] == 4
        assert snap.function_stats["matched_bytes"] == 260
        assert dict(snap.paths) == doc["metadata"]["paths"]
        assert snap.history == () and snap.verify_results == ()


class TestDerivedAtLoad:
    """Every derived number is computed from the cells, by hand, in the test."""

    def test_buckets_covered_bytes_and_pct(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        # A 'none' cell, so covered is neither 0 nor the whole section and a
        # formula that ignored the state would pass.
        data["sections"][".data"]["cells"].append(
            {"start": 32, "end": 64, "span": 2, "state": "none", "functions": []}
        )
        write(data)
        snap = load_coverage(tmp_path, TARGET)
        section = snap.sections[".data"]

        expected_buckets: dict[str, int] = {}
        for cell in section.cells:
            expected_buckets[cell.state] = expected_buckets.get(cell.state, 0) + (
                cell.end - cell.start
            )
        assert dict(section.buckets) == expected_buckets
        assert expected_buckets == {"exact": 16, "thunk": 16, "none": 32}

        expected_covered = sum(size for state, size in expected_buckets.items() if state != "none")
        expected_total = sum(cell.end - cell.start for cell in section.cells)
        assert section.covered_bytes == expected_covered == 32
        assert section.coverage_pct == floor_pct(expected_covered, expected_total, 2) == 50.0
        assert section.cell_count == len(section.cells) == 3

    def test_pct_floors_instead_of_rounding_up_to_a_full_section(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        """One unaccounted byte in 20000 reads 99.99, not the 100.0 rounding gives.

        ``catalog.grid`` floors its coverage figure for exactly this reason, so
        a rounding percentage here would disagree with the CLI beside it.
        """
        cells = data["sections"][".data"]["cells"]
        cells.clear()
        cells.append({"start": 0, "end": 19999, "span": 20000, "state": "exact", "functions": []})
        cells.append({"start": 19999, "end": 20000, "span": 1, "state": "none", "functions": []})
        write(data)
        section = load_coverage(tmp_path, TARGET).sections[".data"]
        assert section.covered_bytes == 19999
        assert round(19999 / 20000 * 100, 2) == 100.0
        assert section.coverage_pct == 99.99

    def test_empty_section_does_not_divide_by_zero(
        self,
        written: dict[str, Any],
        write: Callable[[dict[str, Any]], list[Path]],
        data: dict[str, Any],
        tmp_path: Path,
    ) -> None:
        write(data)
        assert written["sections"][".bss"]["cells"] == []
        section = load_coverage(tmp_path, TARGET).sections[".bss"]
        assert section.cells == ()
        assert dict(section.buckets) == {}
        assert (section.covered_bytes, section.coverage_pct, section.cell_count) == (0, 0.0, 0)

    def test_function_stats_are_hand_derived_from_the_rows(
        self,
        write: Callable[[dict[str, Any]], list[Path]],
        data: dict[str, Any],
        tmp_path: Path,
    ) -> None:
        """The derived stats equal arithmetic done in the test, not a rerun of it.

        The fixture stores six functions.  ``not_a_va`` has no parseable VA and
        is skipped; ``a_data`` carries markerType DATA and is data, so four
        FUNCTION rows remain.  Each size is then cut at the next row's start,
        which bites only adler32: it stores 304 but crc32 starts 0x100 later, so
        it contributes 256 and the other three contribute their stored sizes.
        """
        write(data)
        stats = load_coverage(tmp_path, TARGET).function_stats

        assert stats["total"] == 4  # adler32, crc32, a_lib, a_nope
        assert dict(stats["by_status"]) == {"EXACT": 1, "RELOC": 1, "STUB": 2}
        # 256 + 16 + 4 + 2 = 278 identified bytes: a STUB placeholder's span
        # counts, which is why this figure is not the headline.
        assert stats["covered_bytes"] == 278
        # 260 = 256 (EXACT adler32) + 4 (RELOC a_lib); the two STUB spans
        # (crc32 16, a_nope 2) are bytes no compiled source claims.
        assert stats["matched_bytes"] == 260
        # A blank module stays "", so crc32, a_lib and a_nope do not share
        # GAME's bucket, which holds adler32 alone.
        assert dict(stats["by_module_counts"]) == {"": 3, "GAME": 1}
        assert stats["total_bytes"] == clamp_nonneg_int(data["sections"][".text"]["size"])

    def test_functions_by_va_is_the_same_objects(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        write(data)
        snap = load_coverage(tmp_path, TARGET)
        assert set(snap.functions_by_va) == {fn.va for fn in snap.functions}
        for fn in snap.functions:
            assert snap.functions_by_va[fn.va] is fn


class TestImmutability:
    """A snapshot is a point-in-time value: nothing a caller holds can be edited."""

    def _snap(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> CoverageSnapshot:
        write(data)
        return load_coverage(tmp_path, TARGET)

    def test_cells_tuple_is_immutable(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        cell = self._snap(write, data, tmp_path).sections[".text"].cells[0]
        with pytest.raises(FrozenInstanceError):
            cell.start = 1  # type: ignore[misc]
        with pytest.raises(FrozenInstanceError):
            cell.functions += ("x",)  # type: ignore[misc]

    def test_sections_mapping_is_immutable(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        snap = self._snap(write, data, tmp_path)
        with pytest.raises(TypeError):
            snap.sections[".text"] = None  # type: ignore[index]

    def test_buckets_mapping_is_immutable(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        section = self._snap(write, data, tmp_path).sections[".text"]
        with pytest.raises(TypeError):
            section.buckets["exact"] = 0  # type: ignore[index]

    def test_function_stats_is_immutable_including_nested_tables(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        stats = self._snap(write, data, tmp_path).function_stats
        with pytest.raises(TypeError):
            stats["total"] = 0  # type: ignore[index]
        with pytest.raises(TypeError):
            stats["by_status"]["EXACT"] = 0

    def test_snapshot_field_is_frozen(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        snap = self._snap(write, data, tmp_path)
        with pytest.raises(FrozenInstanceError):
            snap.target = "other"  # type: ignore[misc]


class TestMemo:
    def test_unchanged_directory_returns_the_same_objects(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        write(data)
        first = load_all_coverage(tmp_path)
        second = load_all_coverage(tmp_path)
        assert first is second
        assert first[TARGET] is second[TARGET]
        assert load_coverage(tmp_path, TARGET).target == TARGET

    def test_rewrite_loads_the_new_content(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        path = write(data)[0]
        before = load_all_coverage(tmp_path)
        assert before[TARGET].functions_by_va[0x10001000].status == "EXACT"

        data["functions"]["0x10001000"]["status"] = "RELOC"
        write(data)
        # The write moved the mtime already; bump it explicitly so the test
        # cannot depend on a clock tick landing inside one build.
        st = path.stat()
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 10**9))

        after = load_all_coverage(tmp_path)
        assert after is not before
        assert after[TARGET] is not before[TARGET]
        assert after[TARGET].functions_by_va[0x10001000].status == "RELOC"

    def test_same_length_edit_is_caught_by_the_mtime(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        """A rewrite that keeps the byte count only moves mtime_ns."""
        path = write(data)[0]
        before = load_coverage(tmp_path, TARGET)
        assert before.sections[".data"].buckets == {"exact": 16, "thunk": 16}

        text = path.read_text(encoding="utf-8")
        # Same length both sides ("exact" -> "reloc"), so the byte count is
        # unchanged and only mtime_ns can report the rebuild.
        edited = text.replace('"exact"', '"reloc"')
        assert len(edited) == len(text) and edited != text
        path.write_text(edited, encoding="utf-8", newline="\n")
        st = path.stat()
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 10**9))

        after = load_coverage(tmp_path, TARGET)
        assert after is not before
        assert after.sections[".data"].buckets == {"reloc": 16, "thunk": 16}

    def test_rename_over_at_the_same_size_and_mtime_invalidates(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        """A replace-in-place with the stat fields restored still invalidates.

        The mtime-only key cannot see this: a ``cp -p`` restore, a git checkout
        of a restored file, or a coarse-timestamp filesystem all land a new
        inode at the same byte count and the same mtime_ns.  Only the inode
        distinguishes the two documents, so it is part of the key.
        """
        path = write(data)[0]
        before = load_all_coverage(tmp_path)
        assert before[TARGET].sections[".data"].buckets == {"exact": 16, "thunk": 16}

        text = path.read_text(encoding="utf-8")
        edited = text.replace('"exact"', '"reloc"')
        assert len(edited) == len(text) and edited != text
        st = path.stat()
        # Stage the new content beside the target and rename it over, so the
        # path keeps its name and size but lands a fresh inode.
        staged = path.with_name(path.name + ".staged")
        staged.write_text(edited, encoding="utf-8", newline="\n")
        os.utime(staged, ns=(st.st_atime_ns, st.st_mtime_ns))
        os.replace(staged, path)
        assert path.stat().st_ino != st.st_ino
        assert path.stat().st_mtime_ns == st.st_mtime_ns
        assert path.stat().st_size == st.st_size

        after = load_all_coverage(tmp_path)
        assert after is not before
        assert after[TARGET].sections[".data"].buckets == {"reloc": 16, "thunk": 16}

    def test_added_and_removed_files_invalidate(
        self, monkeypatch: pytest.MonkeyPatch, data: dict[str, Any], tmp_path: Path
    ) -> None:
        (tmp_path / "db").mkdir()

        def two(*args: Any, **kwargs: Any) -> list[tuple[str, Any]]:
            return [(TARGET, copy.deepcopy(data)), ("other.dll", copy.deepcopy(data))]

        monkeypatch.setattr(coverage_toml, "load_coverage_datasets", two, raising=True)
        write_coverage_toml(tmp_path)
        assert sorted(load_all_coverage(tmp_path)) == ["other.dll", TARGET]

        (tmp_path / "db" / "coverage-other.dll.toml").unlink()
        assert sorted(load_all_coverage(tmp_path)) == [TARGET]

    def test_nfd_filename_keys_the_snapshot_nfc(
        self, monkeypatch: pytest.MonkeyPatch, data: dict[str, Any], tmp_path: Path
    ) -> None:
        """A decomposed filename still keys the snapshot under the NFC name.

        macOS hands back the NFD spelling of a filename from a decomposing
        volume, while the writer spells the file from the NFC config target
        name and every lookup arrives NFC. Keying the snapshot on the raw
        filename made an NFC `?target=` miss a document that was on disk.
        """
        nfc = "café.dll"
        nfd = unicodedata.normalize("NFD", nfc)
        assert nfc != nfd

        monkeypatch.setattr(
            coverage_toml,
            "load_coverage_datasets",
            lambda *a, **k: [(nfc, copy.deepcopy(data))],
            raising=True,
        )
        write_coverage_toml(tmp_path)
        doc = tmp_path / "db" / f"coverage-{nfc}.toml"
        # Spell the file the way a decomposing filesystem stores it.
        doc.rename(tmp_path / "db" / f"coverage-{nfd}.toml")
        coverage_toml._ALL_CACHE = None

        assert list(load_all_coverage(tmp_path)) == [nfc]


class TestReaderFailures:
    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(CoverageTomlError, match="cannot read"):
            load_coverage(tmp_path, TARGET)

    def test_wrong_version_raises(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        path = write(data)[0]
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                f"version = {_TOML_VERSION}\n", f"version = {_TOML_VERSION + 1}\n"
            ),
            encoding="utf-8",
            newline="\n",
        )
        with pytest.raises(CoverageTomlError, match="version is"):
            load_coverage(tmp_path, TARGET)

    def test_non_int_version_raises(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        path = write(data)[0]
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                f"version = {_TOML_VERSION}\n", f'version = "{_TOML_VERSION}"\n'
            ),
            encoding="utf-8",
            newline="\n",
        )
        with pytest.raises(CoverageTomlError, match="version is"):
            load_coverage(tmp_path, TARGET)

    def test_malformed_toml_raises(self, tmp_path: Path) -> None:
        (tmp_path / "db").mkdir()
        (tmp_path / "db" / f"coverage-{TARGET}.toml").write_text(
            "this is not = = toml\n", encoding="utf-8"
        )
        with pytest.raises(CoverageTomlError, match="malformed TOML"):
            load_coverage(tmp_path, TARGET)

    def test_empty_file_raises(self, tmp_path: Path) -> None:
        (tmp_path / "db").mkdir()
        (tmp_path / "db" / f"coverage-{TARGET}.toml").write_text("", encoding="utf-8")
        with pytest.raises(CoverageTomlError, match="version is"):
            load_coverage(tmp_path, TARGET)

    def test_renamed_document_raises(self, data: dict[str, Any], tmp_path: Path) -> None:
        """A document naming another target is not this target's coverage."""
        (tmp_path / "db").mkdir()
        (tmp_path / "db" / "coverage-server.dll.toml").write_text(
            render_coverage_toml("client.dll", data), encoding="utf-8"
        )
        with pytest.raises(CoverageTomlError, match="target is"):
            load_coverage(tmp_path, TARGET)

    def test_load_all_skips_a_corrupt_file(
        self,
        monkeypatch: pytest.MonkeyPatch,
        data: dict[str, Any],
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        (tmp_path / "db").mkdir()
        monkeypatch.setattr(
            coverage_toml,
            "load_coverage_datasets",
            lambda *a, **k: [(TARGET, copy.deepcopy(data)), ("other.dll", copy.deepcopy(data))],
            raising=True,
        )
        write_coverage_toml(tmp_path)
        (tmp_path / "db" / "coverage-other.dll.toml").write_text("not = = toml\n", encoding="utf-8")

        with caplog.at_level(logging.WARNING, logger="rebrew.coverage_toml"):
            snapshots = load_all_coverage(tmp_path)
        # Two of three targets beats a 500: the healthy one still loads.
        assert sorted(snapshots) == [TARGET]
        assert snapshots[TARGET].functions
        assert "coverage-other.dll.toml" in caplog.text
        assert "malformed TOML" in caplog.text

    def test_no_coverage_files_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / "db").mkdir()
        assert load_all_coverage(tmp_path) == {}
        assert load_all_coverage(tmp_path / "absent") == {}

    def test_malformed_project_config_raises_instead_of_exiting_the_process(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Both readers run inside a WSGI request; a broken config is a 4xx/500
        page, not a ``SystemExit`` that takes the whole server down.

        ``build_db.resolve_db_dir`` calls typer's ``error_exit`` here, so this
        pins the reader path against the resolver a CLI is allowed to use.
        """
        (tmp_path / "rebrew-project.toml").write_text("this is not = = toml\n", encoding="utf-8")

        for reader in (
            lambda: load_coverage(tmp_path, TARGET),
            lambda: load_all_coverage(tmp_path),
        ):
            with pytest.raises(CoverageTomlError, match="rebrew-project.toml"):
                reader()
        # Nothing on stdout: a dashboard must not print a config error into the
        # response it is still building.
        assert capsys.readouterr().out == ""

    def test_target_none_needs_exactly_one_file(
        self, monkeypatch: pytest.MonkeyPatch, data: dict[str, Any], tmp_path: Path
    ) -> None:
        (tmp_path / "db").mkdir()
        monkeypatch.setattr(
            coverage_toml,
            "load_coverage_datasets",
            lambda *a, **k: [(TARGET, data)],
            raising=True,
        )
        write_coverage_toml(tmp_path)
        assert load_coverage(tmp_path).target == TARGET

        other = copy.deepcopy(data)
        monkeypatch.setattr(
            coverage_toml,
            "load_coverage_datasets",
            lambda *a, **k: [(TARGET, data), ("other.dll", other)],
            raising=True,
        )
        write_coverage_toml(tmp_path)
        with pytest.raises(CoverageTomlError, match="expected exactly one"):
            load_coverage(tmp_path)

    def test_target_with_a_path_separator_is_refused(
        self, write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
    ) -> None:
        """A target id reaches this reader from a request path; a filename does
        not get to escape the db directory."""
        write(data)
        for bad in ("../coverage-server.dll", "sub/server.dll", "", "."):
            with pytest.raises(CoverageTomlError, match="is not a target name"):
                load_coverage(tmp_path, bad)


def test_lone_surrogate_in_a_name_still_renders_a_parsable_document() -> None:
    """A cp1252 byte read with surrogateescape must not poison the whole file.

    ``json.dumps`` escapes U+DC80 as ``\\udc80``, which TOML has no escape for,
    so the document would be written and then rejected by every reader.
    """
    from rebrew.coverage_toml import render_coverage_toml

    data = copy.deepcopy(SAMPLE_DATA)
    fns = data["functions"]
    key = next(iter(fns))
    fns[key] = {**fns[key], "name": "Caf\udc80"}
    doc = tomllib.loads(render_coverage_toml(TARGET, data, previous={}))
    assert any(fn["name"] == "Caf\ufffd" for fn in doc["functions"])


def test_global_ownership_round_trips_and_old_rows_do_not_become_owners(
    write: Callable[[dict[str, Any]], list[Path]], data: dict[str, Any], tmp_path: Path
) -> None:
    row = data["globals"]["0x10030000"]
    row.update(
        owners=["owner.c", "LIBCMT:heap.obj"], referenced_in=["use.c"], declared_in=["globals.h"]
    )
    write(data)
    symbol = next(g for g in load_coverage(tmp_path, TARGET).globals if g.va == 0x10030000)
    assert symbol.owners == ("owner.c", "LIBCMT:heap.obj")
    assert symbol.referenced_in == ("use.c",)
    assert symbol.declared_in == ("globals.h",)
