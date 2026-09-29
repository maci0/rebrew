"""coverage_db.py – the coverage pipeline's normalizers.

The coverage snapshot is clear-text per-target TOML (``db/coverage-<target>.toml``);
:mod:`rebrew.coverage_toml` renders and writes it, and :mod:`rebrew.build_db` is
a thin typer front over :func:`build_db` here.

What lives here is everything the reader and the writer share and neither may
restate: the catalog loaders (``load_coverage_datasets``), the value normalizers
the writer imports (``parse_int``, ``normalize_cell_row``, ``dedupe_by_va``, …),
and the verify-cache import (``import_verify_rows``).  A second copy of the cell
clamp or the verify row mapping is exactly the drift the TOML module exists to
remove, so they are here rather than beside either consumer.  The command half
owns the Typer app and nothing imports it, so a reader like
``coverage_toml`` depends on this module rather than on a console script.

The SQLite writer that used to live here is gone: schema DDL, the version gate,
the ``--force`` unlink/restore, the zstd section-cell cache and the
``function_stats`` reference aggregate all existed to serve a database file, and
there is no database file.  The aggregate survives as
:func:`rebrew.coverage_toml._derive_function_stats`, and
``tests/test_coverage_toml.py`` now derives its expected numbers by hand from
the fixture rather than running a second implementation of the same arithmetic.
"""

import contextlib
import json
import logging
import math
import unicodedata
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from rebrew.cli import (
    console,
    error_exit,
    json_print,
)
from rebrew.config import load_config
from rebrew.data_metadata import (
    DATA_STATUS_DRIFT,
    DATA_STATUS_UNCHECKED,
    DATA_STATUS_VERIFIED,
)
from rebrew.workspace import db_dir
from rebrew.workspace.status import COVERAGE_DB_STATUSES, KNOWN_STATUSES

log = logging.getLogger(__name__)

#: Statuses a ``functions.status`` may hold: ``KNOWN_STATUSES`` plus ``UNKNOWN``
#: (what a catalog row that omits STATUS gets).  The TOML writer applies the
#: same set to every row it stores, so the sanitizer and this set are one rule.
FUNCTION_DB_STATUSES: frozenset[str] = COVERAGE_DB_STATUSES

#: Statuses allowed in ``globals.status``.  Empty string (no verdict yet)
#: plus the three data-metadata verdicts — derived from the same constants
#: ``data_metadata`` / the grid emit so the two writers cannot drift from the
#: annotation vocabulary.
GLOBAL_DB_STATUSES: frozenset[str] = frozenset(
    {
        "",
        DATA_STATUS_VERIFIED,
        DATA_STATUS_DRIFT,
        DATA_STATUS_UNCHECKED,
    }
)


#: Per-target retention cap for the history: only the newest N status-change
#: rows per target survive a rebuild.  The dashboard pages the newest 100 (max
#: 5000) — keeping 10k per target preserves 2+ full pages of history while
#: bounding unbounded growth.
HISTORY_RETENTION = 10_000

#: Fallback cell geometry for a section row whose hand-edited JSON omits
#: ``unitBytes``/``columns`` or carries a non-positive value (a zero-width grid
#: cell is not a cell).
DEFAULT_GRID_GEOMETRY = 64

#: SQLite stores INTEGERs in 8 bytes and the driver raised ``OverflowError``
#: for anything wider, so a JSON number past this range is a malformed row, not
#: a storable one.  A TOML integer is unbounded, but the range is kept: the
#: clamps below are what the two writers agree a catalog value means, and
#: widening it now would silently change which rows the file accepts.
_SQLITE_INT_MAX = 2**63 - 1
_SQLITE_INT_MIN = -(2**63)


def _coerce_int(value: Any) -> int | None:
    """Parse an integer from JSON-ish input, or ``None`` when *value* is unusable.

    ``bool`` is rejected on its own: it subclasses ``int``, so ``True`` would
    land as ``1``.  Non-finite floats (``NaN``, ``±inf``) are rejected because
    ``int(inf)`` raises, and on Python 3.13+ ``max``/``min`` with ``NaN`` can
    silently pick a bound (``max(0, min(1, nan))`` → ``1``), which would invent
    a delta.  Non-integral floats (``12.9``, ``-1.5``) are rejected too:
    ``int()`` truncates toward zero and would store a wrong byte_delta (``12``
    for ``12.9``, or ``0`` after clamping a truncated ``-1``).  A value outside
    the signed 64-bit range the removed SQLite writer enforced (see
    :data:`_SQLITE_INT_MAX`) is out of range for every field it feeds.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            return None
        parsed = int(value)
    elif isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            parsed = int(s, 0)
        except ValueError:
            return None
    else:
        return None
    return parsed if _SQLITE_INT_MIN <= parsed <= _SQLITE_INT_MAX else None


def parse_int(value: Any, default: int = 0) -> int:
    """Parse an integer from JSON-ish input, returning *default* on invalid values."""
    parsed = _coerce_int(value)
    return default if parsed is None else parsed


def clamp_nonneg_int(value: Any) -> int | None:
    """Return a non-negative int, or ``None`` when *value* is absent/unusable."""
    parsed = _coerce_int(value)
    return None if parsed is None else max(0, parsed)


def positive_int_or(value: Any, default: int) -> int:
    """Return *value* when it is a positive ``int``, else *default*.

    ``bool`` is rejected on its own: it subclasses ``int``, so ``True``
    passes both an ``isinstance(..., int)`` and a ``> 0`` guard and would
    land as a 1-byte grid cell, one cell per byte of the section.  A value
    past the 64-bit ceiling is rejected for the reason :func:`parse_int`
    drops it.
    """
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= _SQLITE_INT_MAX:
        return default
    return value


def _as_finite_float(value: Any) -> float | None:
    """Read a stored cell as a finite float, or ``None`` when it is not one.

    The one reader every numeric column shares: SQLite hands back ``int``,
    ``float`` or the text a hand-edited document wrote, and ``bool`` reads as
    1/0 unless refused here.  Non-finite results are rejected because
    ``max(0.0, min(1.0, nan))`` returns ``1.0`` on Python 3.13+ (unordered
    comparison keeps the finite bound), which would store a perfect score
    for a corrupt value.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        if isinstance(value, float) and not math.isfinite(value):
            return None
        return float(value)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        parsed = float(text)
    except ValueError:
        return None
    return parsed if math.isfinite(parsed) else None


def clamp_unit_interval(value: Any) -> float | None:
    """Return a float in ``[0.0, 1.0]``, or ``None`` when *value* is absent/unusable."""
    parsed = _as_finite_float(value)
    if parsed is None:
        return None
    return max(0.0, min(1.0, parsed))


def _clamp_verify_similarity(value: Any) -> float | None:
    """Normalize verify-cache similarity into the document's ``[0.0, 1.0]`` field.

    ``rebrew verify`` stores ``code_similarity`` on a 0–100 percent scale
    (``Sim %`` in the summary table).  The coverage document and
    ``docs/COVERAGE_DOCUMENT.md`` use the unit interval.  Always divide by 100:
    a pass-through for ``[0, 1]`` treated ``1.0`` (1% Sim) as a perfect
    match and ``0.5`` (0.5%) as 50%.  This helper is only used for the
    verify-cache import path, which is always percent-scale.  Non-finite
    and ``> 100`` inputs are rejected; negatives clamp to ``0.0``.
    """
    parsed = _as_finite_float(value)
    if parsed is None or parsed > 100.0:
        return None
    return max(0.0, min(1.0, parsed / 100.0))


def _clamp_effective_match(value: Any) -> int | None:
    """Return ``0``, ``1``, or ``None`` for the effective-match flag column."""
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value if value in (0, 1) else None
    if isinstance(value, float) and value in (0.0, 1.0):
        return int(value)
    if isinstance(value, str):
        s = value.strip()
        if s in ("0", "1"):
            return int(s)
    return None


#: Known cell states emitted by catalog/grid.py.  Function cells set
#: ``state = item["status"].lower()``, so every ``KNOWN_STATUSES`` value can
#: appear lowercased (including ``extract_error`` / ``invalid_va``).  Deriving
#: those from ``KNOWN_STATUSES`` keeps the CHECK and the sanitizer in lockstep
#: with the annotation vocabulary.  Gap/label states and
#: data-metadata verdicts are not function STATUSes, so they are unioned in
#: explicitly.  ``near_match`` is the accepted alias for ``near_matching``.
_GAP_AND_DATA_CELL_STATES: frozenset[str] = frozenset(
    {
        "near_match",
        "unknown",
        "none",
        "padding",
        "data",
        "thunk",
        DATA_STATUS_VERIFIED.lower(),
        DATA_STATUS_DRIFT.lower(),
        DATA_STATUS_UNCHECKED.lower(),
    }
)
_KNOWN_CELL_STATES: frozenset[str] = (
    frozenset(s.lower() for s in KNOWN_STATUSES) | _GAP_AND_DATA_CELL_STATES
)


#: One normalized ``cells`` insert row:
#: ``(target, section_name, start, end, span, state, functions_json, label, parent)``.
_CellRow = tuple[str, str, int, int, int, str, str, str | None, str | None]


def _canonical_cell_state(value: Any) -> str | None:
    """Return the known cell state *value* names, or ``None`` if it names none.

    Case and surrounding whitespace are normalized first: every entry in
    :data:`_KNOWN_CELL_STATES` is lower-case by construction, so a hand-edited
    ``"EXACT"`` or ``"Stub"`` names a state the store already holds rather than
    an unknown one.  A cell left in the wrong case silently counted as neither
    its own state nor a known gap state in ``section_cell_stats`` and in the
    per-section byte summary, because every reader there compares lower-case
    literals.
    """
    state = str(value or "none").strip().lower()
    return state if state in _KNOWN_CELL_STATES else None


def normalize_cell_row(target_name: str, sec_name: str, cell: dict[str, Any]) -> _CellRow:
    """Return a DB-safe cell row from generated coverage JSON."""
    start = max(0, parse_int(cell.get("start"), 0))
    end = max(start, parse_int(cell.get("end"), start))
    span = max(1, parse_int(cell.get("span"), 1))
    state = _canonical_cell_state(cell.get("state"))
    if state is None:
        log.warning(
            "build_db: cell state %r not in known set — coercing to "
            "'unknown' (check the generator or hand-edited JSON); known: %s",
            cell.get("state"),
            ", ".join(sorted(_KNOWN_CELL_STATES)),
        )
        state = "unknown"
    functions = cell.get("functions", [])
    if not isinstance(functions, list):
        functions = []
    label = cell.get("label")
    parent_function = cell.get("parent_function")
    return (
        target_name,
        sec_name,
        start,
        end,
        span,
        state,
        json.dumps(functions),
        str(label) if label is not None else None,
        str(parent_function) if parent_function is not None else None,
    )


def dedupe_cell_rows(
    rows: list[_CellRow],
    *,
    target_name: str,
    sec_name: str,
) -> list[_CellRow]:
    """Collapse rows that share ``start`` after normalization.

    ``cells`` is keyed ``PRIMARY KEY (target, section_name, start)``.  Hand-
    edited JSON (or a negative ``start`` clamped to 0 next to a real
    ``start: 0`` cell) would otherwise abort the whole rebuild.  Last row wins
    so a later real cell overrides a clamped collision; results are sorted by
    ``start`` for stable inserts.
    """
    if len(rows) < 2:
        return rows
    by_start: dict[int, _CellRow] = {}
    for row in rows:
        by_start[row[2]] = row
    dropped = len(rows) - len(by_start)
    if dropped:
        log.warning(
            "build_db: %s %s: dropped %d duplicate cell row(s) sharing the "
            "same start after normalization (UNIQUE target/section/start); "
            "last wins",
            target_name,
            sec_name,
            dropped,
        )
    return sorted(by_start.values(), key=lambda r: r[2])


def dedupe_by_va(
    rows: list[tuple[Any, ...]], *, target_name: str, table: str
) -> list[tuple[Any, ...]]:
    """Collapse rows sharing ``va`` (index 1) so the ``(target, va)`` PK holds.

    Two JSON keys can spell one VA (``"0x401000"`` and ``"4198400"``, or a bad
    key recovered from ``vaStart``); inserting both would abort the whole
    rebuild.  Last row wins, matching :func:`dedupe_cell_rows`.
    """
    by_va = {row[1]: row for row in rows}
    dropped = len(rows) - len(by_va)
    if dropped:
        log.warning(
            "build_db: %s: dropped %d duplicate %s row(s) sharing a VA "
            "(PRIMARY KEY target/va); last wins",
            target_name,
            dropped,
            table,
        )
    return list(by_va.values())


def resolve_db_dir(root_dir: Path, *, json_output: bool = False) -> Path:
    """Return the configured database directory, falling back when no config exists.

    The path comes from the shared ``rebrew.workspace.db_dir`` resolver, so a
    dashboard and this writer never disagree on where ``coverage-<target>.toml``
    lives.  A config that is present but broken still fails loud here rather
    than silently falling back to ``db/``.
    """
    if not (root_dir / "rebrew-project.toml").exists():
        return root_dir / "db"
    try:
        load_config(root_dir)
    except (FileNotFoundError, KeyError, ValueError, TypeError) as exc:
        error_exit(f"Config error: {exc}", json_mode=json_output)
    return db_dir(root_dir)


def load_coverage_datasets(
    root_dir: Path,
    *,
    target: str | None,
    json_output: bool,
    regen: bool,
) -> list[tuple[str, dict[str, Any]]]:
    """Build the catalog input for every target to write.

    The coverage dict is generated in-process by
    :func:`rebrew.catalog.pipeline.build_catalog_data`; there is no snapshot
    file in between, so a document can never describe an older tree than the
    one that produced it.

    *regen* is accepted and dropped: generating in this process is the only
    mode left, so there is nothing for it to select.  It stays in the signature
    because it is an existing call shape and ``build-db --regen`` an existing
    command line.
    """
    from rebrew.catalog.pipeline import build_catalog_data

    base_cfg = load_config(root_dir)
    targets = [target] if target else (base_cfg.all_targets or [base_cfg.target_name])
    # A target repeated in all_targets would be built twice, and the second
    # pass aborts the whole rebuild on the (target, key) and (target, name)
    # primary keys.  Build it once, in first-seen order, rather than losing
    # every target to one repeat.
    if len(set(targets)) != len(targets):
        log.warning(
            "build_db: duplicate target(s) in all_targets: %s; building each once",
            ", ".join(sorted(set(targets))),
        )
        targets = list(dict.fromkeys(targets))
    datasets: list[tuple[str, dict[str, Any]]] = []
    for tgt in targets:
        try:
            tgt_cfg = load_config(root_dir, target=tgt)
        except (FileNotFoundError, KeyError, ValueError, TypeError) as exc:
            error_exit(f"Config error for target {tgt!r}: {exc}", json_mode=json_output)
        console.print(f"Processing {tgt}...")
        datasets.append((unicodedata.normalize("NFC", tgt), build_catalog_data(tgt_cfg)["data"]))
    return datasets


def write_coverage(
    root_dir: Path,
    *,
    target: str | None,
    force: bool,
    json_output: bool,
    regen: bool = False,
) -> list[Path]:
    """Write every target's document and report the result.  Returns the paths.

    The output directory is created first: the writer replaces files in place
    (``os.replace`` of a sibling temp file) and has nothing to put a project's
    first document into.

    *force* is accepted and dropped: :func:`rebrew.coverage_toml.
    write_coverage_toml` replaces each document whole, so there is no stale
    schema to migrate past and no partial state to recover.  It stays in the
    signature because ``rebrew build-db --force`` is an existing command line
    and a script that passes it should not start exiting 2.
    """
    from rebrew.coverage_toml import write_coverage_toml

    db_directory = resolve_db_dir(root_dir, json_output=json_output)
    db_directory.mkdir(parents=True, exist_ok=True)
    written = write_coverage_toml(
        root_dir, target=target, force=force, json_output=json_output, regen=regen
    )
    # The filename IS the target name (coverage_toml resolves one from the
    # other in both directions), so the stem is the only place a caller of the
    # writer can read back which datasets it wrote.
    targets = [path.stem.removeprefix("coverage-") for path in written]
    if json_output:
        json_print(
            {"coverage_files": [str(path) for path in written], "targets_processed": targets}
        )
    else:
        for path in written:
            console.print(f"[green]Wrote {path}[/green]")
    return written


def build_db(
    project_root: Path | None = None,
    target: str | None = None,
    json_output: bool = False,
    force: bool = False,
    regen: bool = False,
) -> None:
    """Write the configured project's ``coverage-<target>.toml`` documents.

    The in-process twin of the ``build-db`` command, kept as a function so a
    tool that writes coverage inside its own process (recoverage's ``regen``)
    has a call to make.  It is the same code path the command runs.

    *regen* is accepted and dropped, exactly as ``build-db --regen`` accepts it
    and drops it: the analysis always runs here.
    """
    root_dir = Path(project_root).resolve() if project_root else Path.cwd().resolve()
    write_coverage(root_dir, target=target, force=force, json_output=json_output, regen=regen)


def _verify_cache_belongs_to_project(root_dir: Path, target_name: str, raw: dict[str, Any]) -> bool:
    """Whether a raw verify-cache document holds this project's current verdicts.

    Delegates to the one identity predicate in :mod:`rebrew.verify_cache`, so
    the rows imported into ``verify_results`` are the same rows ``rebrew
    verify`` and ``rebrew status`` would serve.  A directory with no project
    config has no compiler or binary identity to compare and falls back to
    the target-and-version check.
    """
    from rebrew.verify_cache import CACHE_VERSION, cache_identity_matches

    if not (root_dir / "rebrew-project.toml").exists():
        return raw.get("target") == target_name and raw.get("version") == CACHE_VERSION
    return cache_identity_matches(raw, load_config(root_dir, target=target_name))


def import_verify_rows(
    root_dir: Path,
    target_name: str,
    previous_measured: Mapping[int, tuple[Any, ...]],
    now_iso: str,
) -> list[tuple[Any, ...]] | None:
    """Rows for ``verify_results``, or ``None`` when the cache says nothing about this target.

    The one implementation behind that table: the verify cache is the only
    source of it, and the row mapping plus the three-state answer below are the
    whole rule.  A second spelling of either is exactly the drift the TOML
    module exists to remove.

    The three-state answer is the whole contract, because reading it as a list
    loses the difference between two facts:

    * ``None`` — no cache, an unreadable one, one belonging to another target or
      compiler config, an ``entries`` value that is not a table, or a table
      whose every row is unusable.  The caller keeps whatever rows it has.
    * ``[]`` — the cache is ours and its ``entries`` table is empty.  That is an
      answer about this target (it holds no verdicts), so the caller prunes.
    * otherwise the rows ``(target, va, verified_at, byte_delta, diff_lines,
      similarity, reg_delta, effective_match)``.

    *previous_measured* is keyed by VA: ``(its five measurement fields, the
    stamp it was measured at)``, which
    :func:`rebrew.coverage_toml._previous_measured` reads out of the previous
    document.  *now_iso* is only the fallback stamp for when the cache file's
    mtime cannot be read.
    """
    from rebrew.verify_cache import CACHE_FILENAME, load_verify_cache_raw

    cache_path = Path(root_dir) / ".rebrew" / CACHE_FILENAME
    raw = load_verify_cache_raw(SimpleNamespace(root=root_dir))
    # The cache stores verdicts measured against one compiler config and one
    # binary image; the same predicate verify/status use decides whether those
    # rows are still this project's rows.  A cache left behind by a rebuild of
    # the target binary must not be republished as current, so the compiler and
    # binary identity guards apply here too, not just target and version.
    if not isinstance(raw, dict) or not _verify_cache_belongs_to_project(
        root_dir, target_name, raw
    ):
        return None
    entries = raw.get("entries")
    if not isinstance(entries, dict):
        return None

    # verified_at is when the cache was last updated, and its file mtime is the
    # only stamp the cache document does not already carry.
    verified_at = now_iso
    with contextlib.suppress(OSError):
        verified_at = str(datetime.fromtimestamp(cache_path.stat().st_mtime, tz=UTC).isoformat())

    rows: list[tuple[Any, ...]] = []
    for va_key, item in entries.items():
        if not isinstance(item, dict):
            continue
        # int(str(...), 0), not parse_int: this spelling keeps a negative VA by
        # clamping it to 0 below, where parse_int would drop the row, and it
        # rejects a float VA the same way it rejects a non-numeric one.
        try:
            va_int = int(str(item.get("va", va_key)), 0)
        except (ValueError, TypeError) as exc:
            # The whole-wipe guard below covers an entries table that yields
            # nothing; one unreadable VA would still silently drop that row
            # from the rebuilt coverage document.
            log.warning(
                "build_db: verify cache entry %r has an unusable va (%s); "
                "its verdict is dropped from the coverage document",
                va_key,
                exc,
            )
            continue
        rows.append(
            (
                target_name,
                max(0, va_int),
                verified_at,
                clamp_nonneg_int(item.get("delta")),
                clamp_nonneg_int(item.get("diff_lines")),
                _clamp_verify_similarity(item.get("similarity")),
                clamp_nonneg_int(item.get("reg_delta")),
                _clamp_effective_match(item.get("effective_match")),
            )
        )
    if not rows:
        # An ``entries`` table that exists but yields no parseable VA is not the
        # empty table: nothing is known, so the caller must not prune.  A ``[]``
        # here would let one corrupt cache wipe a target's rows.
        return [] if not entries else None
    # A rebuild re-measures the same verdicts from the same cache, and the cache
    # file's mtime moves on every verify run, so stamping that mtime would
    # relabel an unchanged verdict as freshly measured on every build-db.  A row
    # whose measurements are identical keeps the time it was first measured; a
    # changed or new verdict gets the new one.
    for index, row in enumerate(rows):
        known = previous_measured.get(row[1])
        if known is not None and tuple(known[0]) == row[3:]:
            rows[index] = (row[0], row[1], str(known[1]), *row[3:])
    return rows
