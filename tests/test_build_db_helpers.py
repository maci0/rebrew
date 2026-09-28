"""Tests for the pure helpers in :mod:`rebrew.build_db`.

``build_db`` no longer has a storage engine: the document writer in
:mod:`rebrew.coverage_toml` imports every normalizer below rather than
restating it, so these are the one implementation of "what does this catalog
value mean".  A clamp that moves here moves for both writers or neither.

The SQLite-integer bounds the clamps enforce are kept even though TOML has no
integer width.  They are not a storage fact: the two writers have to agree on
which catalog values are usable, and the columns these feed were sized for
them.
"""

import json
import logging
from pathlib import Path

import pytest
import typer

from rebrew.build_db import (
    _clamp_verify_similarity,
    clamp_nonneg_int,
    clamp_unit_interval,
    dedupe_cell_rows,
    normalize_cell_row,
    parse_int,
    resolve_db_dir,
)


class TestParseInt:
    def test_int_passthrough(self) -> None:
        assert parse_int(42) == 42

    def test_hex_and_decimal_strings(self) -> None:
        assert parse_int("0x10") == 16
        assert parse_int("10") == 10

    def test_invalid_uses_default(self) -> None:
        assert parse_int("zzz", default=7) == 7
        assert parse_int(None, default=3) == 3

    def test_rejects_beyond_sqlite_integer_range(self) -> None:
        """A value past 2**63-1 is out of range for every column it feeds."""
        assert parse_int(2**63, default=7) == 7
        assert parse_int(str(2**63), default=7) == 7
        assert parse_int(1e30, default=7) == 7
        assert parse_int(-(2**63) - 1, default=7) == 7
        assert parse_int(2**63 - 1) == 2**63 - 1


class TestClampNonnegInt:
    def test_rejects_nonfinite_floats(self) -> None:
        """NaN/±inf must not become deltas (int(inf) raises; NaN→bound invents)."""
        assert clamp_nonneg_int(float("nan")) is None
        assert clamp_nonneg_int(float("inf")) is None
        assert clamp_nonneg_int(float("-inf")) is None

    def test_rejects_nonintegral_floats(self) -> None:
        """Truncating 12.9→12 (or -1.5→0) would store a wrong byte_delta."""
        assert clamp_nonneg_int(12.9) is None
        assert clamp_nonneg_int(-1.5) is None

    def test_accepts_integral_floats(self) -> None:
        assert clamp_nonneg_int(12.0) == 12
        assert clamp_nonneg_int(0.0) == 0

    def test_clamps_negative(self) -> None:
        assert clamp_nonneg_int(-3) == 0
        assert clamp_nonneg_int(-4.0) == 0

    def test_rejects_beyond_sqlite_integer_range(self) -> None:
        assert clamp_nonneg_int(2**63) is None
        assert clamp_nonneg_int(str(2**63)) is None
        assert clamp_nonneg_int(1e30) is None
        assert clamp_nonneg_int(2**63 - 1) == 2**63 - 1


class TestClampUnitInterval:
    def test_rejects_nonfinite(self) -> None:
        """NaN must not become 1.0 via max/min unordered-comparison quirk."""
        assert clamp_unit_interval(float("nan")) is None
        assert clamp_unit_interval(float("inf")) is None
        assert clamp_unit_interval(float("-inf")) is None
        assert clamp_unit_interval("nan") is None
        assert clamp_unit_interval("NaN") is None
        assert clamp_unit_interval("inf") is None
        assert clamp_unit_interval("-inf") is None

    def test_clamps_finite_out_of_range(self) -> None:
        assert clamp_unit_interval(1.5) == 1.0
        assert clamp_unit_interval(-0.1) == 0.0
        assert clamp_unit_interval("1.25") == 1.0
        assert clamp_unit_interval(0.42) == 0.42


class TestClampVerifySimilarity:
    def test_scales_percent_scores(self) -> None:
        """Verify writes 0–100; the stored column is 0–1 — 85.5 must not become 1.0."""
        assert _clamp_verify_similarity(85.5) == pytest.approx(0.855)
        assert _clamp_verify_similarity(100.0) == 1.0
        assert _clamp_verify_similarity(50) == 0.5
        assert _clamp_verify_similarity("72.5") == pytest.approx(0.725)

    def test_scales_sub_one_percent(self) -> None:
        """The verify cache is always 0–100; 1.0 means 1%, not a perfect match."""
        assert _clamp_verify_similarity(1.0) == pytest.approx(0.01)
        assert _clamp_verify_similarity(0.85) == pytest.approx(0.0085)
        assert _clamp_verify_similarity(0.0) == 0.0

    def test_rejects_nonfinite_and_above_100(self) -> None:
        assert _clamp_verify_similarity(float("nan")) is None
        assert _clamp_verify_similarity(float("inf")) is None
        assert _clamp_verify_similarity(101.0) is None
        assert _clamp_verify_similarity(-0.1) == 0.0


class TestNormalizeCellRow:
    def test_basic(self) -> None:
        row = normalize_cell_row(
            "T", ".text", {"start": 0, "end": 64, "span": 64, "state": "exact"}
        )
        assert row[2] == 0
        assert row[3] == 64
        assert row[5] == "exact"

    def test_unknown_state_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        """An out-of-set cell state (hand-edited JSON typo) must warn and be
        coerced to ``unknown``: the written document holds the state verbatim,
        so storing the typo would paint a bucket no reader has a name for."""
        with caplog.at_level(logging.WARNING):
            row = normalize_cell_row("T", ".text", {"state": "excat"})
        assert row[5] == "unknown"
        assert any("not in known set" in r.message for r in caplog.records)

    @pytest.mark.parametrize("state", ["extract_error", "invalid_va"])
    def test_persisted_function_statuses_are_known(self, state: str) -> None:
        """grid.py lowercases an annotation STATUS into a cell state, so every
        ``KNOWN_STATUSES`` value (incl. EXTRACT_ERROR / INVALID_VA) must pass
        the sanitizer rather than being coerced to ``unknown``."""
        row = normalize_cell_row("T", ".text", {"state": state})
        assert row[5] == state

    @pytest.mark.parametrize(
        ("spelling", "expected"),
        [("EXACT", "exact"), ("Stub", "stub"), (" Near_Matching ", "near_matching")],
    )
    def test_state_spelling_normalized(
        self, spelling: str, expected: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A differently-cased state names a state the store already holds.
        Left as-is it counted as neither its own bucket nor a known gap state:
        every reader compares lower-case literals."""
        with caplog.at_level(logging.WARNING):
            row = normalize_cell_row("T", ".text", {"state": spelling})
        assert row[5] == expected
        assert not any("not in known set" in r.message for r in caplog.records)

    def test_clamping(self) -> None:
        row = normalize_cell_row("T", ".text", {"start": -5, "end": -1})
        assert row[2] == 0  # start clamped
        assert row[3] == 0  # end clamped to >= start
        assert row[4] == 1  # span floored

    def test_non_list_functions(self) -> None:
        row = normalize_cell_row("T", ".text", {"functions": "not-a-list"})
        assert row[6] == "[]"

    def test_label_and_parent(self) -> None:
        row = normalize_cell_row("T", ".text", {"label": "x", "parent_function": "f"})
        assert row[7] == "x"
        assert row[8] == "f"

    def test_dedupe_keeps_last_and_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        """Two cells sharing a start after the clamp must not both be written:
        the document's row order is what a reader walks, and the pair would
        report one span twice."""
        first = normalize_cell_row("T", ".text", {"start": -1, "end": 8, "state": "none"})
        second = normalize_cell_row(
            "T", ".text", {"start": 0, "end": 8, "state": "exact", "functions": ["f"]}
        )
        assert first[2] == second[2] == 0
        with caplog.at_level(logging.WARNING):
            rows = dedupe_cell_rows([first, second], target_name="T", sec_name=".text")
        assert len(rows) == 1
        assert rows[0][5] == "exact"
        assert rows[0][6] == '["f"]'
        assert any("duplicate cell" in r.message for r in caplog.records)

    def test_dedupe_noop_when_unique(self) -> None:
        a = normalize_cell_row("T", ".text", {"start": 0, "end": 8})
        b = normalize_cell_row("T", ".text", {"start": 8, "end": 16})
        assert dedupe_cell_rows([a, b], target_name="T", sec_name=".text") == [a, b]


class TestResolveDbDir:
    def test_no_config_falls_back_to_db(self, tmp_path: Path) -> None:
        assert resolve_db_dir(tmp_path) == tmp_path / "db"

    def test_config_db_dir(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-project.toml").write_text(
            "\n".join(
                [
                    "[project]",
                    'default_target = "main"',
                    'db_dir = "custom_db"',
                    "",
                    "[targets.main]",
                    'binary = "x.exe"',
                    'reversed_dir = "src"',
                ]
            ),
            encoding="utf-8",
        )
        assert resolve_db_dir(tmp_path) == tmp_path / "custom_db"

    def test_broken_config_fails_loud_rather_than_falling_back(self, tmp_path: Path) -> None:
        """A config that exists but does not parse must not silently write to db/."""
        (tmp_path / "rebrew-project.toml").write_text("[project\n", encoding="utf-8")
        with pytest.raises(typer.Exit):
            resolve_db_dir(tmp_path)


def test_normalized_cells_are_the_documents_row_shape() -> None:
    """The helper's row and the file's cell table are one shape read both ways.

    ``coverage_toml._CELL_COLUMNS`` names this tuple less its leading target,
    so a column added here without it there is the drift that module exists to
    prevent.  Pinned here because this is where the row is built.
    """
    from rebrew.coverage_toml import _CELL_COLUMNS

    row = normalize_cell_row("T", ".text", {"start": 0, "end": 8, "label": "x"})
    assert len(row) - 1 == len(_CELL_COLUMNS)
    assert (row[3], row[4], row[5]) == (8, 1, "none")
    assert json.loads(row[6]) == []
