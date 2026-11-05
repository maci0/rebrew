"""Property-based fuzzing for the GA run log (``ga_runs.jsonl``) loader.

``.rebrew/ga_runs.jsonl`` is untrusted input — hand-edited, spliced across
projects by ``--seed-solutions-file``, or left torn by a crashed batch — and
``load_solutions`` derives the winning solution fingerprint from it.  A single
malformed record must never break seeding for the whole batch or crash the
caller.  The harnesses below feed arbitrary JSON values, structure-aware win
records, and raw log bytes, and assert:

* the loader never raises for any log content (malformed lines/records are
  skipped, per the documented contract);
* every surviving entry is a fully-typed ``SolutionEntry`` whose fields have
  the shapes downstream readers rely on (``find_similar`` arithmetic,
  ``seed_mutations`` splat, stale-check string compare);
* the newest win per ``(target, symbol)`` wins, and a win written through
  ``record_ga_run`` reads back unchanged (pair assertion across the
  persistence boundary).
"""

from __future__ import annotations

import json
import math
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.matcher.solutions import (
    _entry_from_record,
    load_solutions_file,
)

_MAX_EXAMPLES = 100

#: Any value a JSON document can carry, including broken-exporter shapes.
_json_scalar = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**63), max_value=2**64),
    st.floats(allow_nan=True, allow_infinity=True),
    st.text(max_size=12),
)

_json_value = st.one_of(
    _json_scalar,
    st.lists(_json_scalar, max_size=3),
    st.dictionaries(st.text(max_size=6), _json_scalar, max_size=3),
)

_RECORD_KEYS = (
    "symbol",
    "cflags",
    "size",
    "source_file",
    "target",
    "score",
    "solved_at",
    "generations",
    "mutations",
    "source_sha",
    "matched",
    "ts",
    "va",
)


def _assert_well_typed(entry: Any) -> None:
    """The shapes ``find_similar`` / the seeding loop actually consume."""
    assert isinstance(entry.symbol, str) and entry.symbol
    assert isinstance(entry.cflags, str)
    assert isinstance(entry.source_file, str)
    assert isinstance(entry.target, str)
    assert isinstance(entry.size, int) and not isinstance(entry.size, bool)
    assert isinstance(entry.score, (int, float)) and not isinstance(entry.score, bool)
    # A stored NaN/inf score is a claim about a GA fitness that never
    # existed: ``record_ga_run`` writes it as null, so a surviving entry
    # with a non-finite score is a corrupted record, not a fingerprint.
    assert math.isfinite(entry.score)
    assert isinstance(entry.generations, int) and not isinstance(entry.generations, bool)
    assert isinstance(entry.solved_at, str)
    assert isinstance(entry.source_sha, str)
    assert isinstance(entry.mutations, tuple)
    assert all(isinstance(m, str) for m in entry.mutations)


@st.composite
def _record_with_valid_identity(draw: st.DrawFn) -> dict[str, Any]:
    """A record whose required identity fields are always valid.

    Pure random keys almost never spell all of symbol/cflags/size/
    source_file, so the coercion of the *optional* fields would never be
    reached.  This strategy always supplies them, and draws every optional
    field from adversarial JSON values.
    """
    record: dict[str, Any] = {
        "symbol": draw(st.text(alphabet="_abc", min_size=1, max_size=8)),
        "cflags": draw(st.text(max_size=8)),
        "size": draw(st.integers(1, 0x100000)),
        "source_file": draw(st.text(alphabet="ab/c.", min_size=1, max_size=8)),
        "target": draw(st.text(alphabet="ABC", max_size=3)),
        "matched": True,
    }
    for key in ("score", "solved_at", "generations", "mutations", "source_sha"):
        if draw(st.booleans()):
            record[key] = draw(_json_value)
    return record


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(st.dictionaries(st.sampled_from(_RECORD_KEYS), _json_value, max_size=8))
def test_entry_from_record_never_raises(record: dict[str, Any]) -> None:
    """Any record shape coerces to None or a fully-typed entry — never raises."""
    entry = _entry_from_record(record)
    if entry is not None:
        _assert_well_typed(entry)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(_record_with_valid_identity())
def test_valid_identity_optional_fields_typed(record: dict[str, Any]) -> None:
    """With valid identity, mistyped optional fields are rejected or coerced typed.

    A surviving entry must never carry a string ``generations``, a non-string
    ``solved_at``/``source_sha``, a non-string mutation, or a non-finite
    score: downstream readers do arithmetic/comparisons on them.
    """
    entry = _entry_from_record(record)
    if entry is not None:
        _assert_well_typed(entry)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(st.dictionaries(st.sampled_from(_RECORD_KEYS), _json_value, max_size=8))
def test_entry_from_record_malformed_fields_rejected(record: dict[str, Any]) -> None:
    """A record whose required fields are mistyped returns None, not a half entry."""
    entry = _entry_from_record(record)
    if entry is None:
        return
    # Required identity/fingerprint fields must be present and usable.
    assert isinstance(record.get("symbol"), str) and record["symbol"]
    assert isinstance(record.get("cflags"), str)
    assert isinstance(record.get("source_file"), str)
    assert isinstance(record.get("target", ""), str)
    assert isinstance(record.get("size"), int) and not isinstance(record["size"], bool)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(st.binary(max_size=1024))
def test_arbitrary_log_bytes_never_raise(tmp_path_factory: Any, data: bytes) -> None:
    """Raw log bytes — torn writes, garbage, empty — are skipped, never crash."""
    path = tmp_path_factory.mktemp("ga_runs_fuzz") / "ga_runs.jsonl"
    path.write_bytes(data)
    entries = load_solutions_file(path)
    assert isinstance(entries, list)
    for entry in entries:
        _assert_well_typed(entry)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    st.lists(st.dictionaries(st.sampled_from(_RECORD_KEYS), _json_value, max_size=6), max_size=8)
)
def test_jsonl_of_records_never_raises(
    tmp_path_factory: Any, records: list[dict[str, Any]]
) -> None:
    """A JSONL log of arbitrary records loads; winners are well-typed and deduped."""
    path = tmp_path_factory.mktemp("ga_runs_fuzz") / "ga_runs.jsonl"
    lines = [json.dumps(rec, default=str) if not isinstance(rec, str) else rec for rec in records]
    # Inject malformed lines between records.
    lines.insert(0, "not json at all {{{")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    entries = load_solutions_file(path)
    keys = [(e.target, e.symbol) for e in entries]
    assert len(keys) == len(set(keys)), "duplicate (target, symbol) survived dedup"
    assert keys == sorted(keys), "winners are not in (target, symbol) order"
    for entry in entries:
        _assert_well_typed(entry)


@st.composite
def _win_record(draw: st.DrawFn) -> dict[str, Any]:
    """A well-formed win record (the shape ``record_ga_run`` writes)."""
    return {
        "ts": "2026-01-01T00:00:00+00:00",
        "target": draw(st.text(alphabet="ABC", max_size=4)),
        "va": str(draw(st.integers(0, 0xFFFFFFFF))),
        "symbol": draw(st.text(alphabet="_abc", min_size=1, max_size=8)),
        "matched": True,
        "score": draw(st.floats(min_value=0.0, max_value=100.0, allow_nan=False)),
        "generations": draw(st.integers(0, 1000)),
        "cflags": draw(st.sampled_from(["/O2", "/Od /Gd", ""])),
        "size": draw(st.integers(1, 0x100000)),
        "source_file": draw(st.text(alphabet="ab/c.", min_size=1, max_size=10)),
        "mutations": draw(st.lists(st.sampled_from(["mut_a", "mut_b"]), max_size=3)),
    }


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(st.lists(_win_record(), min_size=1, max_size=6))
def test_newest_win_per_key_wins(tmp_path_factory: Any, records: list[dict[str, Any]]) -> None:
    """Dedup keeps the last record per (target, symbol), in sorted key order."""
    path = tmp_path_factory.mktemp("ga_runs_fuzz") / "ga_runs.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
    entries = load_solutions_file(path)
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for rec in records:
        latest[(rec["target"], rec["symbol"])] = rec
    assert [(e.target, e.symbol) for e in entries] == sorted(latest)
    for entry in entries:
        _assert_well_typed(entry)
        assert entry.cflags == latest[(entry.target, entry.symbol)]["cflags"]
        assert entry.size == latest[(entry.target, entry.symbol)]["size"]


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(_win_record())
def test_write_then_read_round_trips(tmp_path_factory: Any, rec: dict[str, Any]) -> None:
    """Pair assertion across the persistence boundary: a written win reads back.

    One record per example: ``record_ga_run`` drops a repeat of the previous
    record (a replay is a duplicate, not a new run), so a list of records
    sharing a key does not accumulate — the file holds exactly the wins
    written, newest per key.
    """
    from rebrew.matcher.solutions import record_ga_run

    root = tmp_path_factory.mktemp("ga_runs_fuzz")
    (root / ".rebrew").mkdir()
    record_ga_run(
        root,
        target=rec["target"],
        va=rec["va"],
        symbol=rec["symbol"],
        matched=True,
        score=rec["score"],
        generations=rec["generations"],
        cflags=rec["cflags"],
        size=rec["size"],
        source_file=rec["source_file"],
        mutations=list(rec["mutations"]),
        solved_at=rec["ts"],
    )
    entries = load_solutions_file(root / ".rebrew" / "ga_runs.jsonl")
    assert [(e.target, e.symbol) for e in entries] == [(rec["target"], rec["symbol"])]
    entry = entries[0]
    _assert_well_typed(entry)
    assert entry.cflags == rec["cflags"]
    assert entry.size == rec["size"]
    assert entry.generations == rec["generations"]
    assert entry.mutations == tuple(rec["mutations"])
