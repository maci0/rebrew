"""recommend.py — deterministic project advice: TU layout + hygiene + next steps.

Aggregates cheap deterministic signals into one read-only command (each lane
reuses the module that owns the check, never reimplements it):

* **TU layout** (``merge``/``split``/``move``): :mod:`rebrew.cu_map`
  clusters vs current source files.
* **link-order**: sources not in VA order in ``CMakeLists.txt``
  (:mod:`rebrew.link_order`).
* **orphans**: metadata blocks with no source marker
  (:mod:`rebrew.orphans`, prunable subset only).
* **lint-fixable**: ``rebrew lint --fix`` would change files (W019 inline
  metadata, W029 redundant cflags, W016 backfillable SECTION).
* **shared-twins**: per-target twin copies collapsible via
  ``rebrew merge --shared`` (:mod:`rebrew.merge` normalization).
* **next-action**: highest-ROI item from :mod:`rebrew.todo` (pointer only,
  so ``recommend`` never duplicates the todo ranking logic).
* **flag-split**: one file holds functions with divergent per-function
  CFLAGS/TOOLCHAIN — one TU compiles with one flag set, so split by flags.
* **fix-sizes**: functions with no SIZE annotation — ``verify --fix-sizes``
  backfills from the binary.
* **lint-errors**: E-code findings need human fixes (``rebrew lint`` shows).
* **foreign-sources**: files carrying no marker for this target are excluded
  from the build (:func:`rebrew.cmake_sources.collect`).

``--apply`` executes only the safe mechanical fixes (``lint --fix``,
``link-order --apply``, ``orphans --prune`` of the prunable subset,
``merge --shared`` twins). TU merge/split/move stay advisory — they change
build semantics and need a human.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from rebrew.cli import TargetOption, error_exit, json_print, require_config
from rebrew.config import ProjectConfig, inventory_path_for

console = Console(stderr=True)
log = logging.getLogger(__name__)

#: Symbol inside a W021 message (``global '<name>' is also annotated in ...``).
_W021_SYMBOL_RE = re.compile(r"global '([^']+)'")

#: VA token inside a W028 message.
_W028_VA_RE = re.compile(r"0x[0-9a-fA-F]+")

app = typer.Typer(
    help="Deterministic project advice: TU layout, hygiene, next steps.",
    rich_markup_mode="rich",
)

#: Lanes ``--apply`` may execute.  Mechanical and revertible (lint --fix,
#: link-order --apply, orphans --prune of the prunable subset, merge
#: --shared of identical bodies).  TU merge/split/move change build
#: semantics and stay advisory.
APPLYABLE = frozenset({"link-order", "orphans", "lint-fixable", "shared-twins"})


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Recommendation:
    """One advisory action."""

    kind: str  # lane name: "merge" | "split" | "move" | "link-order" | ...
    cluster_id: int
    confidence: float
    functions: list[int]
    files: list[str]
    evidence: list[str] = field(default_factory=list)
    command: str = ""
    applyable: bool = False

    def to_dict(self, names: dict[int, str] | None = None) -> dict[str, Any]:
        """Serialize for JSON output."""
        label = names or {}
        return {
            "kind": self.kind,
            "cluster_id": self.cluster_id,
            "confidence": self.confidence,
            "functions": [
                {"va": f"0x{va:08x}", "name": label.get(va, "")} for va in self.functions
            ],
            "files": self.files,
            "evidence": self.evidence,
            "command": self.command,
            "applyable": self.applyable,
        }


# ---------------------------------------------------------------------------
# TU layout lane (pure core)
# ---------------------------------------------------------------------------


def _merge_command(files: list[str], out: str) -> str:
    """`rebrew merge` invocation for *files* into *out*."""
    return f"rebrew merge {' '.join(files)} -o {out} --consolidate"


def recommend_layout(
    clusters: list[Any],
    va_to_file: dict[int, str],
    *,
    min_confidence: float = 0.0,
) -> list[Recommendation]:
    """Diff binary clusters against source layout.

    Args:
        clusters: :class:`rebrew.cu_map.TUCluster` list (only
            ``cluster_id`` / ``functions`` / ``confidence`` / ``evidence``
            are read).
        va_to_file: ``{function VA: reversed_dir-relative source path}``.
        min_confidence: skip clusters below this confidence.

    Returns:
        Recommendations ordered by (kind, cluster_id): merges first, then
        moves, then splits — merges fix the most layout at once.
    """
    recs: list[Recommendation] = []
    for cluster in clusters:
        if cluster.confidence < min_confidence:
            continue
        vas = [va for va in cluster.functions if va in va_to_file]
        if len(vas) < 2:
            continue
        files = sorted({va_to_file[va] for va in vas})
        if len(files) == 1:
            continue
        counts: dict[str, int] = {}
        for va in vas:
            counts[va_to_file[va]] = counts.get(va_to_file[va], 0) + 1
        if len(files) >= 3 or min(counts.values()) >= 2:
            out = str(Path(files[0]).parent / f"merged_tu{cluster.cluster_id}.c")
            recs.append(
                Recommendation(
                    kind="merge",
                    cluster_id=cluster.cluster_id,
                    confidence=cluster.confidence,
                    functions=sorted(vas),
                    files=files,
                    evidence=list(cluster.evidence),
                    command=_merge_command(files, out),
                )
            )
            continue
        # One file holds the bulk, one stray function lives elsewhere.
        odd = min(counts, key=lambda f: counts[f])
        majority = max(counts, key=lambda f: counts[f])
        strays = sorted(va for va in vas if va_to_file[va] == odd)
        recs.append(
            Recommendation(
                kind="move",
                cluster_id=cluster.cluster_id,
                confidence=cluster.confidence,
                functions=strays,
                files=files,
                evidence=[*cluster.evidence, f"{odd} holds {len(strays)} of {len(vas)}"],
                command="; ".join(
                    f"move 0x{va:08x} block from {odd} to {majority}" for va in strays
                ),
            )
        )
    # Split: one file spans 2+ clusters (computed over merge/move survivors
    # so a file already told to merge is not also told to split).
    merged_files = {f for r in recs if r.kind == "merge" for f in r.files}
    file_clusters: dict[str, set[int]] = {}
    for cluster in clusters:
        for va in cluster.functions:
            name = va_to_file.get(va)
            if name and name not in merged_files:
                file_clusters.setdefault(name, set()).add(cluster.cluster_id)
    for name, cids in sorted(file_clusters.items()):
        if len(cids) > 1:
            recs.append(
                Recommendation(
                    kind="split",
                    cluster_id=min(cids),
                    confidence=0.0,
                    functions=[],
                    files=[name],
                    evidence=[f"spans clusters {sorted(cids)}"],
                    command=f"rebrew split {name}",
                )
            )
    order = {"merge": 0, "move": 1, "split": 2}
    recs.sort(key=lambda r: (order[r.kind], r.cluster_id))
    return recs


def flag_conflicts(
    recs: list[Recommendation],
    va_flags: dict[int, str],
) -> list[Recommendation]:
    """Annotate merge recs whose members carry divergent per-function CFLAGS.

    A TU compiles with one flag set, so a merge across flag sets needs the
    flags reconciled first — the annotation names the blocker instead of
    emitting a merge that cannot compile.
    """
    for rec in recs:
        if rec.kind != "merge":
            continue
        flags = {va_flags.get(va, "") for va in rec.functions}
        if len(flags) > 1:
            rec.evidence.append(f"divergent CFLAGS {sorted(flags)} — reconcile first")
            rec.command = ""
    return recs


# ---------------------------------------------------------------------------
# Hygiene lanes (pure cores over precomputed inputs)
# ---------------------------------------------------------------------------


def recommend_link_order(
    current: list[str],
    ordered: list[str],
) -> Recommendation | None:
    """Advise ``rebrew link-order --apply`` when CMake order drifts.

    Both lists are the CMake SOURCES entries in current vs VA-sorted order.
    """
    if current == ordered:
        return None
    return Recommendation(
        kind="link-order",
        cluster_id=-1,
        confidence=1.0,
        functions=[],
        files=[],
        evidence=[f"{len(current)} sources out of VA order"],
        command="rebrew link-order --apply",
        applyable=True,
    )


def recommend_orphans(
    prunable: list[dict[str, Any]],
) -> Recommendation | None:
    """Advise ``rebrew orphans --prune`` for the prunable subset.

    Takes :func:`rebrew.orphans.split_prunable` output (matched STATUS held
    back), so earned STATUS is never at risk.
    """
    if not prunable:
        return None
    return Recommendation(
        kind="orphans",
        cluster_id=-1,
        confidence=1.0,
        functions=[],
        files=[],
        evidence=[f"{len(prunable)} orphaned metadata blocks (matched held back)"],
        command="rebrew orphans --prune",
        applyable=True,
    )


#: Lint codes ``rebrew lint --fix`` resolves mechanically (inline metadata
#: migration, redundant cflags, backfillable SECTION).  Everything else needs
#: a human edit, so it stays out of this lane.
FIXABLE_LINT = frozenset({"W019", "W029", "W016"})


def recommend_lint_fixable(
    warnings: list[tuple[str, str]],
) -> Recommendation | None:
    """Advise ``rebrew lint --fix`` when fixable codes fire.

    *warnings* are ``(file, code)`` pairs aggregated over the batch.
    """
    fixable = sorted({f"{f}: {c}" for f, c in warnings if c in FIXABLE_LINT})
    if not fixable:
        return None
    return Recommendation(
        kind="lint-fixable",
        cluster_id=-1,
        confidence=1.0,
        functions=[],
        files=sorted({f for f, _ in warnings if any(h.startswith(f + ":") for h in fixable)}),
        evidence=[f"{len(fixable)} fixable findings ({sorted(FIXABLE_LINT)})"],
        command="rebrew lint --fix",
        applyable=True,
    )


def recommend_shared_twins(
    groups: list[list[str]],
) -> list[Recommendation]:
    """Advise ``rebrew merge --shared`` per twin group.

    *groups* are file lists with identical normalized bodies (grouped by
    :func:`rebrew.merge._normalize_body`); singletons never arrive here.
    """
    recs = []
    for i, files in enumerate(groups):
        ordered = sorted(files)
        recs.append(
            Recommendation(
                kind="shared-twins",
                cluster_id=i,
                confidence=1.0,
                functions=[],
                files=ordered,
                evidence=["identical bodies across per-target copies"],
                command=f"rebrew merge {' '.join(ordered)} -o <shared> --shared",
                applyable=True,
            )
        )
    return recs


def recommend_next_action(
    command: str,
    description: str,
) -> Recommendation | None:
    """Pointer to the highest-ROI todo item (no duplicate ranking logic)."""
    if not command:
        return None
    return Recommendation(
        kind="next-action",
        cluster_id=-1,
        confidence=1.0,
        functions=[],
        files=[],
        evidence=[description],
        command=command,
    )


def recommend_merge_sweep_hint(
    unmatched_clusters: int,
) -> Recommendation | None:
    """Point at ``merge-sweep --dry-run`` when TU partitions are unproven."""
    if unmatched_clusters <= 1:
        return None
    return Recommendation(
        kind="merge-sweep",
        cluster_id=-1,
        confidence=1.0,
        functions=[],
        files=[],
        evidence=[f"{unmatched_clusters} clusters without a proven partition"],
        command="rebrew merge-sweep --dry-run",
    )


def recommend_flag_split(
    va_to_file: dict[int, str],
    va_to_flags: dict[int, tuple[str, str]],
) -> list[Recommendation]:
    """Advise splitting files whose functions need different flag sets.

    One TU compiles with one toolchain/flag set.  A file mixing ``/O1`` and
    ``/O2`` (or two toolchains) cannot match both functions at once — split
    it so each TU is flag-homogeneous.  Only functions with an explicit
    per-function override participate; project defaults are uniform by
    definition.
    """
    by_file: dict[str, dict[tuple[str, str], list[int]]] = {}
    for va, flags in va_to_flags.items():
        name = va_to_file.get(va)
        if name is None:
            continue
        by_file.setdefault(name, {}).setdefault(flags, []).append(va)
    recs = []
    for name, groups in sorted(by_file.items()):
        if len(groups) <= 1:
            continue
        parts = sorted(f"{tc or '*'} {fl or '*'}: {len(v)}" for (tc, fl), v in groups.items())
        recs.append(
            Recommendation(
                kind="flag-split",
                cluster_id=-1,
                confidence=1.0,
                functions=sorted(va for vs in groups.values() for va in vs),
                files=[name],
                evidence=[f"mixed flag sets — {'; '.join(parts)}"],
                command=f"rebrew split {name}",
            )
        )
    return recs


def recommend_fix_sizes(
    va_to_size: dict[int, int],
) -> Recommendation | None:
    """Advise ``verify --fix-sizes`` when functions lack SIZE annotations."""
    missing = sorted(va for va, size in va_to_size.items() if size <= 0)
    if not missing:
        return None
    shown = ", ".join(f"0x{va:08x}" for va in missing[:5])
    if len(missing) > 5:
        shown += f" +{len(missing) - 5} more"
    return Recommendation(
        kind="fix-sizes",
        cluster_id=-1,
        confidence=1.0,
        functions=missing,
        files=[],
        evidence=[f"{len(missing)} functions without SIZE ({shown})"],
        command="rebrew verify --fix-sizes",
    )


def recommend_lint_errors(
    errors: list[tuple[str, str, str]],
) -> list[Recommendation]:
    """Surface lint E-codes as human-fix items (one rec per file).

    *errors* are ``(file, code, message)`` triples; ``rebrew lint`` owns the
    full text, so the rec points there instead of duplicating it.
    """
    by_file: dict[str, list[str]] = {}
    for name, code, _msg in errors:
        by_file.setdefault(name, []).append(code)
    return [
        Recommendation(
            kind="lint-errors",
            cluster_id=-1,
            confidence=1.0,
            functions=[],
            files=[name],
            evidence=[f"{len(codes)} error(s): {sorted(set(codes))}"],
            command=f"rebrew lint {name}",
        )
        for name, codes in sorted(by_file.items())
    ]


def recommend_foreign_sources(
    foreign: list[str],
    marker: str,
) -> Recommendation | None:
    """Note files excluded from this target's build (no marker for it)."""
    if not foreign:
        return None
    return Recommendation(
        kind="foreign-sources",
        cluster_id=-1,
        confidence=1.0,
        functions=[],
        files=sorted(foreign),
        evidence=[f"{len(foreign)} files carry no {marker} marker — excluded from build"],
        command="rebrew cmake-sources --json",
    )


def recommend_cluster_fill(
    clusters: list[Any],
    va_to_file: dict[int, str],
    registry_vas: set[int],
    *,
    min_confidence: float = 0.0,
) -> list[Recommendation]:
    """Advise skeletoning unreversed functions that sit inside a TU cluster.

    A cluster whose members are half-reversed is one object file: the missing
    VAs belong in the same TU as their reversed neighbors, and
    ``skeleton --append`` targets the neighbor file directly.  Only VAs in
    the function inventory participate (no phantom work).
    """
    recs = []
    for cluster in clusters:
        if cluster.confidence < min_confidence:
            continue
        have = sorted(va for va in cluster.functions if va in va_to_file)
        missing = sorted(
            va for va in cluster.functions if va not in va_to_file and va in registry_vas
        )
        if len(have) < 1 or not missing:
            continue
        neighbor = va_to_file[have[0]]
        shown = ", ".join(f"0x{va:08x}" for va in missing[:5])
        if len(missing) > 5:
            shown += f" +{len(missing) - 5} more"
        recs.append(
            Recommendation(
                kind="cluster-fill",
                cluster_id=cluster.cluster_id,
                confidence=cluster.confidence,
                functions=missing,
                files=[neighbor],
                evidence=[
                    f"{len(missing)} unreversed in cluster ({shown})",
                    *list(cluster.evidence),
                ],
                command="; ".join(
                    f"rebrew skeleton 0x{va:08x} --append {neighbor}" for va in missing[:3]
                )
                + ("; …" if len(missing) > 3 else ""),
            )
        )
    return recs


def recommend_matched_orphans(
    orphans: list[dict[str, Any]],
) -> list[Recommendation]:
    """Flag matched orphans: earned STATUS with no source marker.

    The ``orphans`` lane prunes the safe subset; these are held back because
    deleting them destroys matched work.  The fix is re-attaching a marker,
    never pruning — so they surface here as human-fix items.
    """
    matched = [o for o in orphans if o.get("status") in ("EXACT", "RELOC", "PROVEN")]
    return [
        Recommendation(
            kind="matched-orphans",
            cluster_id=-1,
            confidence=1.0,
            functions=[],
            files=[],
            evidence=[f"{o.get('module')} {o.get('va')} claims {o.get('status')} with no marker"],
            command=f"re-attach marker for {o.get('module')} {o.get('va')} (never --include-matched)",
        )
        for o in matched
    ]


def recommend_data_drift(
    drift: list[tuple[str, int, str]],
) -> Recommendation | None:
    """Advise ``verify --data`` when data symbols drift from reference bytes.

    *drift* are ``(module, va, name)`` triples with STATUS DRIFT.
    """
    if not drift:
        return None
    shown = ", ".join(name for _, _, name in drift[:5])
    if len(drift) > 5:
        shown += f" +{len(drift) - 5} more"
    return Recommendation(
        kind="data-drift",
        cluster_id=-1,
        confidence=1.0,
        functions=[va for _, va, _ in drift],
        files=[],
        evidence=[f"{len(drift)} data symbols drift ({shown})"],
        command="rebrew verify --data",
    )


def recommend_stub_sort(
    stub_vas: list[int],
    covered: set[int],
) -> Recommendation | None:
    """Advise ``document-unmatched`` when unannotated inventory functions remain."""
    missing = sorted(va for va in stub_vas if va not in covered)
    if not missing:
        return None
    return Recommendation(
        kind="stub-sort",
        cluster_id=-1,
        confidence=1.0,
        functions=missing[:10],
        files=[],
        evidence=[f"{len(missing)} inventory functions without annotations"],
        command="rebrew document-unmatched --json",
    )


def recommend_build_check(
    drift: list[dict[str, str]],
) -> Recommendation | None:
    """Advise re-running configure when build/ flags drift from CMake."""
    if not drift:
        return None
    first = ", ".join(
        f"{d.get('obj', '').rsplit('/', 1)[-1]}:{d.get('flag', '')}" for d in drift[:3]
    )
    return Recommendation(
        kind="build-check",
        cluster_id=-1,
        confidence=1.0,
        functions=[],
        files=[],
        evidence=[f"{len(drift)} unrecorded flag token(s) in build.make (first: {first})"],
        command="rebrew build-check",
    )


#: Verify-cache statuses that name the next mechanical step (mirrors the
#: todo lanes that consume the same cache).  Matched/NEAR/pre-verify states
#: stay out — todo already ranks that work.
_VERIFY_FAILURE_COMMANDS = {
    "COMPILE_ERROR": "rebrew test 0x{va:08x}",
    "EXTRACT_ERROR": "rebrew test 0x{va:08x}",
    "MISSING_SIZE": "rebrew verify --fix-sizes",
}


def recommend_verify_failures(
    entries: dict[str, Any],
) -> list[Recommendation]:
    """Surface actionable verify-cache failures (one rec per VA).

    *entries* maps ``0x%08x`` VA keys to objects with a ``status`` attr
    (the normalized :func:`rebrew.todo._load_verify_entries` shape, with
    todo's target guard already applied by the caller).
    """
    recs = []
    for key, entry in sorted(entries.items()):
        status = str(getattr(entry, "status", "") or "")
        template = _VERIFY_FAILURE_COMMANDS.get(status)
        if template is None:
            continue
        try:
            va = int(key, 16)
        except ValueError:
            continue
        recs.append(
            Recommendation(
                kind="verify-failures",
                cluster_id=-1,
                confidence=1.0,
                functions=[va],
                files=[],
                evidence=[f"verify status {status}"],
                command=template.format(va=va),
            )
        )
    return recs


def recommend_missing_externs(
    extern_refs: list[tuple[str, str]],
    known_names: set[str],
) -> list[Recommendation]:
    """Advise implementing extern callees nothing defines yet.

    *extern_refs* are ``(caller_file, callee)`` pairs from
    :func:`rebrew.c_parser.find_extern_function_names`; *known_names* holds
    every defined symbol spelling (raw, stripped, underscore-prefixed).
    One rec per missing callee, callers listed as evidence.
    """
    by_callee: dict[str, set[str]] = {}
    for caller, callee in extern_refs:
        if callee in known_names or callee.lstrip("_") in known_names:
            continue
        by_callee.setdefault(callee, set()).add(caller)
    return [
        Recommendation(
            kind="missing-externs",
            cluster_id=-1,
            confidence=1.0,
            functions=[],
            files=[],
            evidence=[f"declared by {len(callers)} file(s): {sorted(callers)[:3]}"],
            command=f"rebrew skeleton --symbol {callee}",
        )
        for callee, callers in sorted(by_callee.items())
    ]


def recommend_default_names(
    named: list[tuple[int, str]],
) -> list[Recommendation]:
    """Advise renaming functions still carrying decompiler default names."""
    from rebrew.lint import _DEFAULT_FUNC_NAME_PATTERNS

    hits = sorted(
        va for va, name in named if any(p.fullmatch(name) for p in _DEFAULT_FUNC_NAME_PATTERNS)
    )
    if not hits:
        return []
    return [
        Recommendation(
            kind="default-names",
            cluster_id=-1,
            confidence=1.0,
            functions=hits[:10],
            files=[],
            evidence=[f"{len(hits)} functions with default names"],
            command="; ".join(f"rebrew rename 0x{va:08x} <name>" for va in hits[:3])
            + ("; …" if len(hits) > 3 else ""),
        )
    ]


def recommend_stale_cache(
    cache_mtime_ns: int,
    newest_source_mtime_ns: int,
) -> Recommendation | None:
    """Advise ``rebrew verify`` when sources are newer than the verify cache."""
    if newest_source_mtime_ns <= cache_mtime_ns:
        return None
    return Recommendation(
        kind="stale-cache",
        cluster_id=-1,
        confidence=1.0,
        functions=[],
        files=[],
        evidence=["sources changed since the last verify run"],
        command="rebrew verify",
    )


def recommend_duplicate_globals(
    warnings: list[tuple[str, str]],
) -> list[Recommendation]:
    """Surface W021 duplicate-global collisions (one rec per symbol).

    *warnings* are ``(file, symbol)`` pairs aggregated over the batch lint
    pass — the second annotator of a symbol fires W021 there, so the pair
    carries the colliding files.
    """
    by_symbol: dict[str, set[str]] = {}
    for name, symbol in warnings:
        by_symbol.setdefault(symbol, set()).add(name)
    return [
        Recommendation(
            kind="duplicate-globals",
            cluster_id=-1,
            confidence=1.0,
            functions=[],
            files=sorted(files),
            evidence=[f"global '{symbol}' annotated in {len(files)} files"],
            command=f"keep one definition of {symbol}, extern elsewhere",
        )
        for symbol, files in sorted(by_symbol.items())
        if len(files) > 1
    ]


def recommend_stale_markers(
    warnings: list[tuple[str, str]],
) -> list[Recommendation]:
    """Surface W028 stale markers (VA matches no function start).

    *warnings* are ``(file, va)`` pairs; the fix is re-annotate or refresh
    the function list, per the lint hint.
    """
    by_file: dict[str, set[str]] = {}
    for name, va in warnings:
        by_file.setdefault(name, set()).add(va)
    return [
        Recommendation(
            kind="stale-markers",
            cluster_id=-1,
            confidence=1.0,
            functions=[],
            files=[name],
            evidence=[f"{len(vas)} stale marker(s): {sorted(vas)[:3]}"],
            command=f"rebrew lint {name}",
        )
        for name, vas in sorted(by_file.items())
    ]


def recommend_start_data(
    unchecked: list[tuple[str, int, str]],
) -> Recommendation | None:
    """Advise ``verify --data`` for never-verified data symbols.

    *unchecked* are ``(module, va, name)`` triples with STATUS UNCHECKED or
    absent (mirrors the todo start-data lane, aggregated to one rec).
    """
    if not unchecked:
        return None
    shown = ", ".join(name for _, _, name in unchecked[:5])
    if len(unchecked) > 5:
        shown += f" +{len(unchecked) - 5} more"
    return Recommendation(
        kind="start-data",
        cluster_id=-1,
        confidence=1.0,
        functions=[va for _, va, _ in unchecked[:10]],
        files=[],
        evidence=[f"{len(unchecked)} data symbols never verified ({shown})"],
        command="rebrew verify --data",
    )


def recommend_backfill_blockers(
    stubs_without_blocker: int,
) -> Recommendation | None:
    """Advise ``document-unmatched --backfill-blockers`` for bare STUBs."""
    if stubs_without_blocker <= 0:
        return None
    return Recommendation(
        kind="backfill-blockers",
        cluster_id=-1,
        confidence=1.0,
        functions=[],
        files=[],
        evidence=[f"{stubs_without_blocker} STUBs without BLOCKER text"],
        command="rebrew document-unmatched --backfill-blockers",
    )


# ---------------------------------------------------------------------------
# Loaders (I/O edge)
# ---------------------------------------------------------------------------


def load_layout(
    cfg: ProjectConfig,
) -> tuple[
    dict[int, str], dict[int, str], dict[int, str], dict[int, tuple[str, str]], dict[int, int]
]:
    """Return ``(va_to_file, va_to_name, va_to_flags, va_to_flagsets, va_to_size)``."""
    from rebrew.annotation import parse_c_file_multi
    from rebrew.sources import iter_sources, target_marker
    from rebrew.utils import rel_display_path

    va_to_file: dict[int, str] = {}
    names: dict[int, str] = {}
    flags: dict[int, str] = {}
    flagsets: dict[int, tuple[str, str]] = {}
    sizes: dict[int, int] = {}
    for cfile in iter_sources(cfg.reversed_dir, cfg):
        rel = rel_display_path(cfile, cfg.reversed_dir)
        for entry in parse_c_file_multi(
            cfile, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir
        ):
            if entry.is_data or not entry.va:
                continue
            va_to_file[entry.va] = rel
            names[entry.va] = entry.symbol or cfile.stem
            if entry.cflags:
                flags[entry.va] = entry.cflags
            if entry.cflags or entry.toolchain:
                flagsets[entry.va] = (entry.toolchain, entry.cflags)
            sizes[entry.va] = entry.size
    return va_to_file, names, flags, flagsets, sizes


@contextmanager
def _lane(name: str) -> Iterator[None]:
    """Isolate one hygiene lane: its failure drops only its recommendations.

    Logged at WARNING so a broken lane (bad input, renamed helper) is visible
    instead of silently producing no advice forever.
    """
    try:
        yield
    except Exception:
        log.warning("recommend: %s lane failed, its advice is omitted", name, exc_info=True)


def _collect_hygiene(
    cfg: ProjectConfig,
    covered: set[int] | None = None,
    names: dict[int, str] | None = None,
) -> list[Recommendation]:
    """Run the cheap hygiene lanes; a failing lane logs a warning and adds nothing."""
    recs: list[Recommendation] = []
    names = names or {}

    with _lane("link-order"):
        from rebrew.link_order import find_sources_block, normalize_listed, order_sources
        from rebrew.sources import iter_sources, source_exts
        from rebrew.utils import rel_display_path

        cmake = cfg.root / "CMakeLists.txt"
        if cmake.is_file():
            text = cmake.read_text(encoding="utf-8")
            files = list(iter_sources(cfg.reversed_dir, cfg))
            ordered, _ = order_sources(files, marker=cfg.marker)
            by_key = {
                str(p.resolve()): rel_display_path(p, cfg.root) for p in ordered if p.is_absolute()
            }
            by_key.update(
                {str((cfg.root / p.name).resolve()): p.name for p in ordered if not p.is_absolute()}
            )
            exts = {ext.lower() for ext in source_exts(cfg)}
            block = find_sources_block(text, exts)
            if block is not None:
                current = normalize_listed(cfg.root, block.managed, by_key)
                want = [by_key.get(str(p.resolve()), p.name) for p in ordered]
                listed = set(block.managed) | set(current)
                want = [w for w in want if w in listed]
                rec = recommend_link_order(current, want)
                if rec:
                    recs.append(rec)

    with _lane("orphans"):
        from rebrew.orphans import find_orphans, split_prunable

        fn, data = find_orphans(cfg)
        rec = recommend_orphans(split_prunable(cfg, fn, data))
        if rec:
            recs.append(rec)
        from rebrew.orphans import _orphan_dicts

        recs.extend(recommend_matched_orphans(_orphan_dicts(cfg, fn, data)))

    with _lane("lint"):
        from rebrew.lint import lint_file
        from rebrew.sources import iter_sources

        warnings: list[tuple[str, str]] = []
        lint_errors: list[tuple[str, str, str]] = []
        dup_globals: list[tuple[str, str]] = []
        stale: list[tuple[str, str]] = []
        seen_vas: dict[Any, str] = {}
        seen_globals: dict[str, str] = {}
        for cfile in iter_sources(cfg.reversed_dir, cfg):
            res = lint_file(cfile, cfg, seen_vas=seen_vas, seen_globals=seen_globals)
            for _, code, msg in res.warnings:
                warnings.append((str(cfile), code))
                if code == "W021":
                    m = _W021_SYMBOL_RE.search(msg)
                    if m:
                        dup_globals.append((str(cfile), m.group(1)))
                elif code == "W028":
                    m = _W028_VA_RE.search(msg)
                    if m:
                        stale.append((str(cfile), m.group(0)))
            for _line, code, msg in res.errors:
                lint_errors.append((str(cfile), code, msg))
        rec = recommend_lint_fixable(warnings)
        if rec:
            recs.append(rec)
        recs.extend(recommend_lint_errors(lint_errors))
        recs.extend(recommend_duplicate_globals(dup_globals))
        recs.extend(recommend_stale_markers(stale))

    with _lane("shared-twins"):
        from rebrew.annotation import split_annotation_sections
        from rebrew.merge import _block_metadata, _normalize_body
        from rebrew.sources import iter_sources
        from rebrew.utils import read_source_text

        bodies: dict[str, list[str]] = {}
        for cfile in iter_sources(cfg.reversed_dir, cfg):
            try:
                text, _ = read_source_text(cfile)
            except OSError:
                continue
            _, blocks = split_annotation_sections(text)
            if len(blocks) != 1:
                continue
            meta = _block_metadata(blocks[0])
            if meta is None:
                continue
            bodies.setdefault(_normalize_body(blocks[0]), []).append(str(cfile))
        twins = [sorted(v) for v in bodies.values() if len(v) > 1]
        recs.extend(recommend_shared_twins(twins))

    with _lane("data-status"):
        from rebrew.data_metadata import load_data_metadata

        data_entries = load_data_metadata(cfg.metadata_dir).items()
        drift = [
            (module, va, str(fields.get("name") or f"DAT_{va:08x}"))
            for (module, va), fields in data_entries
            if str(fields.get("status") or "").upper() == "DRIFT"
        ]
        rec = recommend_data_drift(drift)
        if rec:
            recs.append(rec)
        unchecked = [
            (module, va, str(fields.get("name") or f"DAT_{va:08x}"))
            for (module, va), fields in data_entries
            if str(fields.get("status") or "").upper() in ("", "UNCHECKED")
        ]
        start = recommend_start_data(unchecked)
        if start:
            recs.append(start)

    with _lane("build-check"):
        from rebrew.build_check import check as build_check

        result = build_check()
        if result.get("status") == "drift":
            rec = recommend_build_check(result.get("drift", []))
            if rec:
                recs.append(rec)

    with _lane("verify-failures"):
        from rebrew.todo import _load_verify_entries

        recs.extend(recommend_verify_failures(_load_verify_entries(cfg)))

    with _lane("stale-cache"):
        from rebrew.sources import iter_sources

        cache_path = cfg.root / ".rebrew" / "verify_cache.json"
        try:
            cache_mtime_ns = cache_path.stat().st_mtime_ns
        except OSError:
            cache_mtime_ns = 0
        newest_ns = 0
        for cfile in iter_sources(cfg.reversed_dir, cfg):
            try:
                newest_ns = max(newest_ns, cfile.stat().st_mtime_ns)
            except OSError:
                continue
        rec = recommend_stale_cache(cache_mtime_ns, newest_ns)
        if rec:
            recs.append(rec)

    with _lane("missing-externs"):
        from rebrew.c_parser import find_extern_function_names
        from rebrew.sources import iter_sources
        from rebrew.utils import read_source_text, rel_display_path

        refs: list[tuple[str, str]] = []
        known: set[str] = set(names.values())
        known.update(n.lstrip("_") for n in names.values())
        known.update("_" + n.lstrip("_") for n in names.values())
        for cfile in iter_sources(cfg.reversed_dir, cfg):
            rel = rel_display_path(cfile, cfg.reversed_dir)
            try:
                text, _ = read_source_text(cfile)
            except OSError:
                continue
            for callee in find_extern_function_names(text):
                refs.append((rel, callee))
        recs.extend(recommend_missing_externs(refs, known))

    with _lane("default-names"):
        recs.extend(recommend_default_names([(va, n) for va, n in names.items()]))

    with _lane("todo"):
        from rebrew.naming import load_data
        from rebrew.todo import collect_all

        ghidra_funcs, existing, covered_vas = load_data(cfg)
        if covered is None:
            covered = set(covered_vas)
        from rebrew.catalog import cached_function_list

        funcs = cached_function_list(cfg)
        stub = recommend_stub_sort([int(f["va"]) for f in funcs], covered)
        if stub:
            recs.append(stub)
        bare = sum(
            1
            for info in existing.values()
            if info.get("status") == "STUB" and not info.get("blocker")
        )
        backfill = recommend_backfill_blockers(bare)
        if backfill:
            recs.append(backfill)
        items = collect_all(cfg, ghidra_funcs, existing, covered_vas)
        actionable = [i for i in items if i.command and i.category != "documented"]
        if actionable:
            top = actionable[0]
            rec = recommend_next_action(top.command, f"{top.category}: {top.description}")
            if rec:
                recs.append(rec)

    with _lane("foreign-sources"):
        from rebrew.cmake_sources import collect as collect_sources
        from rebrew.sources import target_marker
        from rebrew.utils import rel_display_path

        marker = target_marker(cfg) or cfg.target_name
        _own, foreign = collect_sources(cfg, marker)
        rels = []
        for p in foreign:
            try:
                rels.append(p.relative_to(cfg.root).as_posix())
            except ValueError:
                rels.append(rel_display_path(p, cfg.reversed_dir))
        rec = recommend_foreign_sources(rels, marker)
        if rec:
            recs.append(rec)

    return recs


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew recommend · · · · · · · · All lanes (TU layout + hygiene + next)\n\n"
    "  rebrew recommend -c tu · · · · · · Only TU layout (merge/split/move)\n\n"
    "  rebrew recommend -c hygiene · · · Only hygiene (link-order/orphans/lint)\n\n"
    "  rebrew recommend --apply · · · · · Auto-fix safe lanes (lint, link-order,\n"
    "                                  orphans-prune, shared twins)\n\n"
    "  rebrew recommend --json · · · · · Machine-readable output\n\n"
    "[dim]Read-only by default. --apply runs only mechanical fixes; TU "
    "merge/split/move stay advisory.[/dim]"
)

_KIND_TO_LANE = {
    "merge": "tu",
    "split": "tu",
    "move": "tu",
    "flag-split": "tu",
    "fix-sizes": "tu",
    "cluster-fill": "tu",
    "link-order": "hygiene",
    "orphans": "hygiene",
    "matched-orphans": "hygiene",
    "lint-fixable": "hygiene",
    "lint-errors": "hygiene",
    "shared-twins": "hygiene",
    "foreign-sources": "hygiene",
    "data-drift": "hygiene",
    "start-data": "hygiene",
    "duplicate-globals": "hygiene",
    "stale-markers": "hygiene",
    "build-check": "hygiene",
    "stale-cache": "hygiene",
    "backfill-blockers": "next",
    "verify-failures": "next",
    "missing-externs": "next",
    "default-names": "next",
    "stub-sort": "next",
    "next-action": "next",
    "merge-sweep": "next",
}


@app.callback(invoke_without_command=True)
def main(
    category: str | None = typer.Option(
        None, "--category", "-c", help="Filter lanes: tu, hygiene, next"
    ),
    min_confidence: float = typer.Option(
        0.0, "--min-confidence", help="Skip TU clusters below this confidence"
    ),
    apply: bool = typer.Option(
        False, "--apply", help="Auto-fix safe lanes (lint, link-order, orphans, twins)"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Deterministic project advice: TU layout, hygiene, next steps."""
    cfg = require_config(target=target, json_mode=json_output)

    bin_path = cfg.target_binary
    if not bin_path.exists():
        error_exit(f"Target binary not found: {bin_path}", json_mode=json_output)

    from rebrew.binary_loader import load_binary
    from rebrew.catalog import build_function_registry, cached_function_list
    from rebrew.cu_map import cluster_functions

    funcs = cached_function_list(cfg)
    if not funcs:
        error_exit(
            "No function inventory (needed here) — run `rebrew intake` first",
            json_mode=json_output,
        )
    ghidra_path = inventory_path_for(cfg.reversed_dir, cfg)
    info = load_binary(bin_path)
    registry = build_function_registry(funcs, cfg, ghidra_path=ghidra_path, bin_path=bin_path)
    clusters = cluster_functions(registry, info, cfg)

    va_to_file, names, va_flags, va_flagsets, va_sizes = load_layout(cfg)
    recs = flag_conflicts(
        recommend_layout(clusters, va_to_file, min_confidence=min_confidence), va_flags
    )
    recs.extend(recommend_flag_split(va_to_file, va_flagsets))
    fix_sizes = recommend_fix_sizes(va_sizes)
    if fix_sizes:
        recs.append(fix_sizes)
    recs.extend(
        recommend_cluster_fill(clusters, va_to_file, set(registry), min_confidence=min_confidence)
    )
    recs.extend(_collect_hygiene(cfg, set(va_to_file), names))
    unmatched = sum(
        1
        for c in clusters
        if any(va in va_to_file for va in c.functions) and c.confidence >= min_confidence
    )
    hint = recommend_merge_sweep_hint(max(0, unmatched - 1))
    if hint:
        recs.append(hint)

    if category:
        wanted = category.lower()
        recs = [r for r in recs if _KIND_TO_LANE.get(r.kind) == wanted]

    if apply and not dry_run:
        _apply_safe(cfg, recs, json_output)
        return
    if apply and dry_run:
        for rec in recs:
            if rec.applyable:
                rec.command = "[dry-run] " + rec.command

    if json_output:
        json_print({"recommendations": [r.to_dict(names) for r in recs]})
        return

    if not recs:
        console.print("Nothing to recommend — layout and hygiene look clean.")
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("Kind", style="cyan")
    table.add_column("Detail")
    table.add_column("Conf", justify="right")
    table.add_column("Command", style="yellow")
    for rec in recs:
        detail = "\n".join(rec.files) if rec.files else rec.kind
        if rec.kind in ("merge", "move"):
            detail += "\n" + ", ".join(f"0x{va:08x}" for va in rec.functions)
        if rec.evidence:
            detail += "\n[dim]" + "; ".join(rec.evidence) + "[/dim]"
        table.add_row(rec.kind, detail, f"{rec.confidence:.2f}", rec.command or "—")
    console.print(table)


def _apply_safe(cfg: ProjectConfig, recs: list[Recommendation], json_mode: bool) -> None:
    """Execute applyable lanes via their owning commands' helpers."""
    from typer.testing import CliRunner

    from rebrew.main import app as umbrella

    applied: list[str] = []
    runner = CliRunner()
    for rec in recs:
        if not rec.applyable or rec.kind not in APPLYABLE:
            continue
        if rec.kind == "lint-fixable":
            result = runner.invoke(
                umbrella,
                ["lint", "--fix", *(["--target", cfg.target_name] if cfg.target_name else [])],
            )
            applied.append(f"lint --fix ({result.exit_code})")
        elif rec.kind == "link-order":
            result = runner.invoke(
                umbrella,
                [
                    "link-order",
                    "--apply",
                    *(["--target", cfg.target_name] if cfg.target_name else []),
                ],
            )
            applied.append(f"link-order --apply ({result.exit_code})")
        elif rec.kind == "orphans":
            result = runner.invoke(
                umbrella,
                ["orphans", "--prune", *(["--target", cfg.target_name] if cfg.target_name else [])],
            )
            applied.append(f"orphans --prune ({result.exit_code})")
        elif rec.kind == "shared-twins":
            out = cfg.root / "src" / "shared" / "twins.c"
            cmd = ["merge", *rec.files, "-o", str(out), "--shared"]
            result = runner.invoke(umbrella, cmd)
            applied.append(f"rebrew {' '.join(cmd)} ({result.exit_code})")
    if json_mode:
        json_print({"applied": applied})
    else:
        console.print(f"Applied {len(applied)} fix(es): " + ", ".join(applied))


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
