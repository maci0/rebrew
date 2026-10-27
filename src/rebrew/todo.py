"""todo.py – Prioritized action dashboard for rebrew projects.

Synthesizes verify results, coverage data, and function catalog into a single
ranked list of "what to work on next" with ROI scoring.

Usage::

    rebrew todo                     Top 20 actions by ROI
    rebrew todo --limit 50          Show top 50
    rebrew todo --category fix-delta        Filter by category
    rebrew todo --stats             Show coverage stats header
    rebrew todo --json              Machine-readable output
"""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
lazy import json
lazy import os
lazy import shlex
lazy from collections.abc import Callable, Sequence
lazy from pathlib import Path

if TYPE_CHECKING:
    from rebrew.catalog import FunctionEntry
    from rebrew.verify_cache import VerifyCacheEntry

import typer
lazy from rich.panel import Panel
lazy from rich.table import Table

from rebrew.cli import (
    AllTargetsOption,
    TargetOption,
    all_targets_run,
    console,
    error_exit,
    json_print,
    option_default,
    require_config,
    require_non_negative,
)
from rebrew.status_style import STATUS_COLORS
lazy from rebrew.compiler.compile import NEAR_MATCH_THRESHOLD
lazy from rebrew.config import ProjectConfig, inventory_path_for
lazy from rebrew.metadata.functions import GA_CEILING_PREFIX
lazy from rebrew.naming import (
    detect_unmatchable,
    estimate_difficulty,
    find_neighbor_file,
    ignored_symbols,
    inside_annotated_vas,
    load_data,
    parse_byte_delta,
)
lazy from rebrew.present import ratio_bar
lazy from rebrew.status import effective_status
lazy from rebrew.utils import floor_pct
lazy from rebrew.workspace.status import (
    EARNED_STATUSES,
    FUZZY_STATUSES,
    INFRASTRUCTURE_STATUSES,
    MATCHED_STATUSES,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Category constants
# ---------------------------------------------------------------------------

CAT_SETUP = "setup"
CAT_COMPILE_ERROR = "compile-error"
CAT_EXTRACT_ERROR = "extract-error"
CAT_FIX_DELTA = "fix-delta"
CAT_IMPROVE_MATCH = "improve-match"
CAT_START_FUNCTION = "start-function"
CAT_MISSING_ANNOTATION = "missing-annotation"
CAT_IDENTIFY_LIBRARY = "identify-library"
CAT_RUN_PROVER = "run-prover"
CAT_DOCUMENTED = "documented"
# Byte-exact via a generated naked skeleton (`source = "naked"`) — reproduced,
# NOT decompiled: it stays on the list until the real C body matches.
CAT_NAKED = "naked-reconstruction"
# Data symbol whose built bytes differ from the reference (`verify --data`
# wrote STATUS DRIFT in rebrew-data.toml).
CAT_DATA_DRIFT = "data-drift"
# Data symbol never verified (STATUS UNCHECKED or absent in rebrew-data.toml).
CAT_START_DATA = "start-data"
# RELOC match: byte-identical only after relocation masking, so the compiler /
# linker output is not identical on its own.  Closing it needs EXACT.
CAT_EXACT_ONLY = "exact-only"
# Span whose bytes in the shipped image a postlink fixer rewrote, so they are
# not what the toolchain emitted.  Needs a configured `raw_link` to detect.
CAT_POSTLINK = "postlink-mangled"

# Proving is only feasible when few bytes actually differ: symbolic execution
# over hundreds of mismatched bytes just times out.  Cap the estimated byte
# delta for measured (verify-cached) candidates; unmeasured ones stay eligible.
_PROVE_MAX_DIFF_BYTES = 8

#: Largest function the angr prover is offered.  Symbolic execution over a
#: multi-kilobyte body exhausts its timeout regardless of how few bytes
#: differ, so the queue is capped by extent as well as by delta.  Unrelated to
#: the ROI size bands in ``calculate_roi``, which rank effort, not feasibility.
_PROVE_MAX_FUNC_BYTES = 500

#: Blocker substrings that mark a STUB as a documented *non-target* (intake /
#: document-unmatched write these for IAT import thunks and Delphi application
#: code).  Such functions are explicitly not decomp work — they must never be
#: suggested as fix-delta quick-wins or flag-sweep targets.
_NON_TARGET_MARKERS = ("not a decomp target", "not reproducible")

_CATEGORY_COLORS = {
    CAT_SETUP: "bold white",
    CAT_COMPILE_ERROR: "red",
    CAT_EXTRACT_ERROR: "red",
    CAT_FIX_DELTA: "green",
    CAT_IMPROVE_MATCH: "yellow",
    CAT_START_FUNCTION: "cyan",
    CAT_MISSING_ANNOTATION: "dim",
    CAT_IDENTIFY_LIBRARY: "blue",
    CAT_RUN_PROVER: "cyan",
    CAT_DOCUMENTED: "dim",
    CAT_NAKED: "magenta",
    CAT_DATA_DRIFT: "yellow",
    CAT_START_DATA: "cyan",
    CAT_EXACT_ONLY: "blue",
    CAT_POSTLINK: "magenta",
}

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class TodoItem:
    """A single prioritized action item."""

    category: str
    roi_score: float
    va: int
    name: str
    size: int
    filename: str
    description: str
    command: str
    byte_delta: int | None = None
    difficulty: int = 0
    status: str = ""
    match_percent: float | None = None
    mutations: list[str] = field(default_factory=list)
    blocker: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON output."""
        d: dict[str, Any] = {
            "category": self.category,
            "roi_score": round(self.roi_score, 1),
            "va": f"0x{self.va:08x}",
            "name": self.name,
            "size": self.size,
            "filename": self.filename,
            "description": self.description,
            "command": self.command,
        }
        if self.byte_delta is not None:
            d["byte_delta"] = self.byte_delta
        if self.difficulty:
            d["difficulty"] = self.difficulty
        if self.status:
            d["status"] = self.status
        if self.match_percent is not None:
            d["match_percent"] = self.match_percent
        if self.mutations:
            d["mutations"] = self.mutations
        if self.blocker:
            d["blocker"] = self.blocker
        return d


def _item_domain(item: TodoItem) -> str:
    """``data`` or ``code``. The two do not replace each other at one address."""
    if item.category in {CAT_DATA_DRIFT, CAT_START_DATA}:
        return "data"
    return "code"


# ---------------------------------------------------------------------------
# Unified Continuous Scoring
# ---------------------------------------------------------------------------


def calculate_roi(size: int, match_pct: float | None, delta: int | None) -> float:
    """Calculate a continuous ROI score (0-100).

    User Workflow Heuristic: Higher match percentage is often HARDER to finish
    because it implies fighting the compiler (register allocation, instruction scheduling).
    Therefore, rewrite tasks (low match) are prioritized over near-match tasks,
    unless the near-match task has a small, actionable byte delta.
    """
    if match_pct is None:
        match_pct = 0.0
    # 0-100 only: a percent above 100 (corrupt cache row) drives the base
    # score negative and would rank a function as easier than a fresh one.
    match_pct = max(0.0, min(100.0, match_pct))

    # Invert the score: 0% match = 65 base, 100% match = 25 base
    base_score = 65.0 - (match_pct * 0.4)

    modifier = 0.0

    # 1. Delta Boosts (Small explicit byte differences are quick wins)
    if delta is not None:
        if delta <= 4:
            modifier += 25.0
        elif delta <= 20:
            modifier += 15.0

    # 2. Size Modifiers (Smaller functions are easier to cognitively load and rewrite)
    if size < 50:
        modifier += 15.0
    elif size < 150:
        modifier += 10.0
    elif size < 300:
        modifier += 5.0
    elif size > 1000:
        modifier -= 15.0
    elif size > 500:
        modifier -= 5.0

    # 3. Stubborn Diff Penalty (High match >= 90%, no explicit small delta)
    if match_pct >= 90.0 and (delta is None or delta > 20):
        modifier -= 15.0

    final_score = base_score + modifier
    return min(89.0, max(1.0, final_score))


# ---------------------------------------------------------------------------
# Collector functions
# ---------------------------------------------------------------------------


def _collect_setup_steps(
    cfg: ProjectConfig,
    ghidra_funcs: list[FunctionEntry],
    existing: dict[int, dict[str, str]],
) -> list[TodoItem]:
    """Detect missing project setup steps for fresh/incomplete projects.

    Returns high-priority setup items that guide the user through initial
    project configuration. Scored 90-99 so they always appear first.
    """
    from rebrew.verify_cache import cache_path_for

    items: list[TodoItem] = []

    def add(base_score: float, description: str, command: str) -> None:
        items.append(
            TodoItem(
                category=CAT_SETUP,
                roi_score=base_score - len(items) - 1,
                va=0,
                name="",
                size=0,
                filename="",
                description=description,
                command=command,
            )
        )

    if not inventory_path_for(Path(cfg.reversed_dir), cfg).exists():
        add(99.0, "Export function inventory from Ghidra/r2/rizin", "rebrew doctor")
        return items  # Can't do much more without the inventory

    if not ghidra_funcs:
        return items

    if not existing:
        add(99.0, f"Run todo to survey {len(ghidra_funcs)} functions", "rebrew todo --json")
        add(99.0, "Generate first skeleton files to start reversing", "rebrew skeleton --batch 5")
    elif not cache_path_for(cfg, for_read=True).exists():
        add(90.0, f"Run first verify on {len(existing)} functions", "rebrew verify")

    return items


def _collect_active_functions(
    existing: dict[int, dict[str, str]],
    size_by_va: dict[int, int],
    name_by_va: dict[int, str],
    verify_entries: dict[str, VerifyCacheEntry],
    caller_counts: dict[str, int] | None = None,
) -> list[TodoItem]:
    """Collect and score all incomplete functions currently tracked in the project.

    Compile errors, near misses, stubs, and verify failures share one pass
    and one continuous ROI score.
    """
    items: list[TodoItem] = []

    # 1. Gather all unique VAs between metadata and verify cache
    metadata_vas = set(existing.keys())
    verify_vas = set()
    from rebrew.metadata.document import canonical_va_key

    for va_str in verify_entries:
        va = canonical_va_key(va_str)
        if isinstance(va, int):
            verify_vas.add(va)

    all_vas = metadata_vas | verify_vas

    for va in all_vas:
        info = existing.get(va, {})
        status = info.get("status", "STUB")

        # The annotated SIZE is what verify compares; the inventory extent
        # can carry alignment padding or run into a missed neighbour.
        try:
            size = int(info.get("size") or 0) or size_by_va.get(va) or 0
        except TypeError, ValueError:
            size = size_by_va.get(va) or 0
        name = info.get("symbol") or name_by_va.get(va) or f"FUN_{va:08x}"
        filename = info.get("filename", "")

        va_key = f"0x{va:08x}"
        v_entry = verify_entries.get(va_key)
        v_status = v_entry.status if v_entry else None
        # Same rule as `rebrew status`: a stale metadata EXACT whose cached
        # verdict no longer matches is live work. Canonical spelling, so a
        # hand-edited "skip" parks the same way SKIP does.
        status = effective_status(status, v_status)

        # User-parked: intentional "don't touch" — never surface as actionable
        # work (flag sweep / GA / prove) until someone unparks with force.
        if status == "SKIP":
            continue

        # Skip finished functions — except naked reconstructions: byte-exact
        # via a generated skeleton (`source = "naked"`) is reproduced, not
        # decompiled, so it stays actionable until the real C body matches
        # (ct-recomp's NAKED_REQUIRED vs PURE_C_EXACT distinction).
        if status in MATCHED_STATUSES:
            if info.get("source") == "naked":
                items.append(
                    TodoItem(
                        category=CAT_NAKED,
                        roi_score=0.0,
                        va=va,
                        name=name,
                        size=size,
                        filename=filename,
                        description=(
                            "Byte-exact via generated naked asm — implement the "
                            "real C body and drop the REBREW_ALLOW_NAKED fence"
                        ),
                        command=f"rebrew test 0x{va:08x}",
                        status=status,
                    )
                )
            elif status == "RELOC":
                # Matched only after masking linker-filled addresses, so the
                # bytes are not identical straight out of the toolchain.  A
                # project at 100% byte-matched is still this far from an
                # identical build, and todo used to report "nothing to do".
                items.append(
                    TodoItem(
                        category=CAT_EXACT_ONLY,
                        roi_score=0.0,
                        va=va,
                        name=name,
                        size=size,
                        filename=filename,
                        description=(
                            "RELOC — identical only with relocations masked; "
                            "the toolchain output itself still differs"
                        ),
                        command=f"rebrew test 0x{va:08x} --linked",
                        status=status,
                    )
                )
            continue

        # Documented non-targets (IAT import thunks, Delphi application code):
        # the blocker already states they are not decomp work, so a 6-byte
        # thunk must not surface as a "5B diff — try flag sweep" quick-win.
        # Keep them listed under their own category so the decision is auditable.
        if status == "STUB" and any(m in info.get("blocker", "") for m in _NON_TARGET_MARKERS):
            items.append(
                TodoItem(
                    category=CAT_DOCUMENTED,
                    roi_score=-1.0,  # never outranks actionable work
                    va=va,
                    name=name,
                    size=size,
                    filename=filename,
                    description=f"Documented non-target — {info.get('blocker', '')[:60]}",
                    command="",
                    status=status,
                    blocker=info.get("blocker", ""),
                )
            )
            continue

        v_match = v_entry.match_percent if v_entry else None
        v_delta = v_entry.delta if v_entry else None
        unmeasured = v_status in (*INFRASTRUCTURE_STATUSES, "MISSING_SIZE", "INTERNAL_ERROR")
        if unmeasured:
            # Failed runs carry default metrics, not a byte comparison.
            v_delta = None
            v_match = None

        # If verify says it compiled and size changed, or we don't have verify, fallback to metadata parsing
        calc_delta = v_delta
        if calc_delta is None and status in FUZZY_STATUSES and not unmeasured:
            raw_bd = info.get("blocker_delta", "")
            try:
                calc_delta = int(raw_bd) if raw_bd else parse_byte_delta(info.get("blocker", ""))
            except ValueError:
                calc_delta = parse_byte_delta(info.get("blocker", ""))

        zero_delta = calc_delta == 0
        if zero_delta:
            calc_delta = None
            v_match = None

        # VA form — CWD-independent (rebrew test resolves the VA via resolve_source_arg).
        cmd = f"rebrew test 0x{va:08x}"

        # GA mutation suggestions parsed from a near-diag-written blocker
        # (populated in the improve-match branch below).
        mutations: list[str] = []

        if status == "COMPILE_ERROR":
            category = CAT_COMPILE_ERROR
            desc = "Compile error — fix syntax/includes"
            score = 200.0  # High priority blocker

        elif status == "EXTRACT_ERROR":
            # The symbol was not found in the compiled .obj (wrong symbol,
            # optimized-away function, or a STUB binding whose decorated name
            # doesn't match).  delta is 0 (no bytes extracted), so without
            # this branch it would fall into fix-delta as a misleading
            # "0B diff" quick-win.  Surface it as a tooling/annotation issue
            # instead — a flag sweep cannot fix a missing symbol.
            category = CAT_EXTRACT_ERROR
            desc = "Symbol not found in .obj — check STUB/FUNCTION binding, symbol name, or implementation"
            score = 150.0  # High priority: nothing else can proceed until resolved

        elif (not name or name.startswith("FUN_")) and v_status not in (
            "NEAR_MATCHING",
            "MISSING_SIZE",
        ):
            # Verify state wins over the placeholder name: a measured
            # NEAR_MATCHING result is matched work and belongs to the
            # verify-driven branches below (which apply the STRUCTURAL demotion
            # and surface blockers/GA hints), and MISSING_SIZE has its own
            # self-heal lane.  Handling them here duplicated that logic minus
            # the demotion, so a STRUCTURAL 20B diff was offered as a flag-sweep
            # quick-win and a placeholder MISSING_SIZE was sent to `skeleton`.
            category = CAT_MISSING_ANNOTATION
            desc = "Missing C function definition (needs skeleton)"
            score = calculate_roi(size, v_match, calc_delta)
            cmd = f"rebrew skeleton 0x{va:08x}"

        elif v_status == "MISSING_SIZE":
            # No SIZE anywhere (marker + metadata): rebrew test refuses the
            # entry and byte extraction is vacuous.  The self-heal path is
            # verify --fix-sizes backfilling the binary-derived size.
            category = CAT_MISSING_ANNOTATION
            desc = "Missing SIZE annotation — backfill with rebrew verify --fix-sizes"
            score = calculate_roi(size, v_match, calc_delta)
            cmd = "rebrew verify --fix-sizes"

        elif zero_delta:
            category = CAT_IMPROVE_MATCH
            desc = "Zero delta without a byte-match verdict — rerun rebrew test"
            score = calculate_roi(size, v_match, calc_delta)

        elif status == "PROVEN":
            # Semantic equivalence is established but the bytes still differ:
            # the prover has nothing left to add and the GA/flag sweep that
            # led here already ran, so this is improve-match work.
            category = CAT_IMPROVE_MATCH
            desc = "PROVEN, bytes still differ"
            blocker = info.get("blocker", "")
            if blocker:
                desc += f" — Blocked: {blocker[:50]}"
            score = calculate_roi(size, v_match, calc_delta)
            cmd = f"rebrew diff 0x{va:08x}"

        elif info.get("blocker", "").startswith(GA_CEILING_PREFIX):
            # The GA exhausted on a register-only delta — byte-exact is not
            # reproducible from portable C, so no flag sweep / GA item helps.
            # The prover lane needs angr: without it, there is nothing to
            # run, so classify as improve-match with a match/near-diag
            # command instead of routing to a prover that cannot execute.
            from rebrew.prove import angr_available

            if angr_available():
                category = CAT_RUN_PROVER
                desc = "GA ceiling (register-only delta) — prove semantic equivalence for PROVEN"
                score = calculate_roi(size, v_match, calc_delta) + 10.0
                cmd = f"rebrew prove 0x{va:08x}"
            else:
                category = CAT_IMPROVE_MATCH
                desc = (
                    "GA ceiling (register-only delta) — angr unavailable, "
                    "no prover to run; try match variants or near-diag"
                )
                score = calculate_roi(size, v_match, calc_delta)
                cmd = f"rebrew diagnose near 0x{va:08x}"

        elif calc_delta is not None and calc_delta <= 20:
            category = CAT_FIX_DELTA
            desc = f"{calc_delta}B diff — try flag sweep, GA, or padding adjustments"
            score = calculate_roi(size, v_match, calc_delta)
            blocker = info.get("blocker", "")
            # A near-diag STRUCTURAL verdict means the diff is control-flow
            # layout, not a flag/padding quick-win — demote it so the item is
            # not offered as one (regression: smygb's 0x00404a90 stayed a
            # "20B diff — try flag sweep" item after the sweep already ran
            # and near-diag classified it STRUCTURAL).
            if "STRUCTURAL" in blocker:
                category = CAT_IMPROVE_MATCH
                desc = f"Needs implementation/fixing — Blocked: {blocker[:70]}"
                cmd = f"rebrew diff 0x{va:08x}"
            elif blocker:
                desc += f" — Blocked: {blocker[:60]}"
                if calc_delta <= 4:
                    # VA form (not the reversed_dir-relative filename): commands
                    # stay runnable from the project root — rebrew diff resolves
                    # the VA to its source via resolve_source_arg.
                    cmd = f"rebrew diff 0x{va:08x}"
                else:
                    cmd = f"rebrew match flags 0x{va:08x}"
            elif calc_delta <= 4:
                # VA form (not the reversed_dir-relative filename): commands
                # stay runnable from the project root — rebrew diff resolves
                # the VA to its source via resolve_source_arg.
                cmd = f"rebrew diff 0x{va:08x}"
            else:
                cmd = f"rebrew match flags 0x{va:08x}"

        else:
            category = CAT_IMPROVE_MATCH
            desc = "Needs implementation/fixing"
            score = calculate_roi(size, v_match, calc_delta)

            blocker = info.get("blocker", "")
            if blocker:
                desc += f" — Blocked: {blocker[:50]}"
                # near-diag --fix-blocker writes the suggested GA operators
                # after "— try: "; expose them as structured data (and a
                # short terminal hint) so todo consumers can act without
                # re-running near-diag.
                try_marker = "— try: "
                if try_marker in blocker:
                    tail = blocker.split(try_marker, 1)[1]
                    mutations = [m.strip() for m in tail.split(",") if m.strip()]
                    if mutations:
                        desc += f" [try: {', '.join(mutations[:3])}]"

            # VA form (not the reversed_dir-relative filename): commands
            # stay runnable from the project root — rebrew diff resolves
            # the VA to its source via resolve_source_arg.
            cmd = f"rebrew diff 0x{va:08x}"

        items.append(
            TodoItem(
                category=category,
                roi_score=score + _caller_boost(name, caller_counts),
                va=va,
                name=name,
                size=size,
                filename=filename,
                description=_caller_suffix(desc, name, caller_counts),
                command=cmd,
                byte_delta=calc_delta,
                status=status,
                match_percent=v_match,
                mutations=mutations,
                blocker=info.get("blocker", "") or "",
            )
        )

    return items


def _caller_boost(name: str, caller_counts: dict[str, int] | None) -> float:
    """ROI bonus for functions other unmatched work waits on (leaf-first)."""
    if not caller_counts:
        return 0.0
    callers = caller_counts.get(name, 0) + caller_counts.get("_" + name, 0)
    return min(15.0, 5.0 * callers)


def _caller_suffix(desc: str, name: str, caller_counts: dict[str, int] | None) -> str:
    """Append "unblocks N caller(s)" when other files declare this function."""
    if not caller_counts:
        return desc
    callers = caller_counts.get(name, 0) + caller_counts.get("_" + name, 0)
    if callers <= 0:
        return desc
    return f"{desc} — unblocks {callers} caller(s)"


def _collect_prover_candidates(
    existing: dict[int, dict[str, str]],
    size_by_va: dict[int, int],
    verify_entries: dict[str, Any],
) -> list[TodoItem]:
    """Collect functions suitable for symbolic equivalence proving."""
    # Check if the angr extra is installed — find_spec probe; never import
    # angr here (the real import costs ~0.5 s and this lane runs per todo).
    from rebrew.prove import angr_available

    has_angr = angr_available()

    if not has_angr:
        return []

    items: list[TodoItem] = []
    for va, info in existing.items():
        ann_status = info.get("status", "STUB")
        # Byte-matched needs no proof; PROVEN already has one.
        if ann_status in EARNED_STATUSES:
            continue
        va_key = f"0x{va:08x}"
        cached = verify_entries.get(va_key)
        # The shared overlay, not a bare "cache wins": a metadata STUB keeps
        # its classification over a placeholder verdict.
        reported = effective_status(ann_status, cached.status if cached else None)
        if reported != "NEAR_MATCHING":
            continue
        if cached and cached.delta == 0:
            continue  # Retest the contradictory verdict before offering proof.
        # Metadata SIZE is authoritative (the real function extent — Ghidra's
        # can be stale, e.g. 340 vs the actual 752 for GetCommandPayloadSize);
        # prefer it so the size cap below uses the true extent.
        try:
            size = int(info.get("size") or 0) or size_by_va.get(va) or 0
        except TypeError, ValueError:
            size = size_by_va.get(va) or 0
        # A negative SIZE is truthy, so it survives the `or` chain above and
        # then fails `size == 0` below, which also makes est_diff negative and
        # disarms the too-far-apart gate.  Clamp to 0 so a nonsense extent is
        # treated as the unknown it is, the way status.py / coverage_toml.py
        # treat it.
        size = max(size, 0)
        if size > _PROVE_MAX_FUNC_BYTES or size == 0:
            continue

        filename = info.get("filename", "")
        match_pct = cached.match_percent if cached else None
        byte_delta = cached.delta if cached else None

        # A measured candidate whose bytes are far apart (e.g. 65% match on a
        # 340B function) is not provable — the prover just exhausts its
        # timeout.  Skip it; it belongs in improve-match/fix-delta instead.
        if match_pct is not None:
            # Clamp: the field is a fraction of the function's bytes, and a
            # cached value above 100 makes est_diff negative, so the gate below
            # never fires and a badly mismatched function is queued for the
            # prover.  Clamped, not rejected: an out-of-range row still means
            # "measured, and not a match".
            match_pct = max(0.0, min(100.0, match_pct))
            est_diff = size * (100.0 - match_pct) / 100.0
            if est_diff > _PROVE_MAX_DIFF_BYTES:
                continue

        items.append(
            TodoItem(
                category=CAT_RUN_PROVER,
                # Prover is most useful at high match% (few diffs to prove).
                # Give it a bonus so it wins dedup over improve-match/fix-delta.
                roi_score=calculate_roi(size, match_pct, None)
                + (10.0 if match_pct and match_pct >= NEAR_MATCH_THRESHOLD * 100 else -10.0),
                va=va,
                name=info.get("symbol", ""),
                size=size,
                filename=filename,
                description="NEAR_MATCHING + small — prove semantic equivalence",
                command=f"rebrew prove 0x{va:08x}",
                status=reported,
                match_percent=match_pct,
                byte_delta=byte_delta,
            )
        )
    return items


def load_verify_entries(cfg: ProjectConfig) -> dict[str, VerifyCacheEntry]:
    """Load verify cache entries, returning {} on missing/corrupt cache.

    Mirrors status.py's target guard: each selected cache still records the
    ``target`` identity of the run that wrote it.  Another target's
    entries must never drive todo's categories/deltas — a CLIENT run would
    otherwise surface SERVER's EXACTs as phantom fix-delta quick-wins.
    """
    from rebrew.verify_cache import load_verify_cache_raw

    raw = load_verify_cache_raw(cfg)
    if raw is None:
        return {}
    try:
        from rebrew.verify_cache import VerifyCache

        data = VerifyCache.from_dict(raw)
    except (ValueError, AttributeError, ImportError, TypeError) as exc:
        # An unreadable cache is not the same verdict as an empty one: every
        # category below is derived from these entries, so returning {} here
        # makes "your cache does not parse" print as "nothing to do".
        log.warning(
            "verify cache at %s is unreadable (%s: %s); todo is reporting against an empty cache",
            cfg.reversed_dir,
            type(exc).__name__,
            exc,
        )
        return {}
    # One shared identity guard: version, target, compiler config, and binary.
    # Re-deriving it here is how todo came to accept a cache the compile path
    # rejects — another target's entries surfaced as phantom quick-wins, and a
    # cache earned under a superseded compiler config kept driving categories
    # and deltas after `rebrew verify` had stopped serving it.
    from rebrew.verify_cache import cache_identity_matches

    if not cache_identity_matches(raw, cfg):
        return {}
    # Re-key canonically: the cache is a JSON file, so a VA may be spelled
    # "0x1000" instead of "0x00001000" (the union at `:317` already normalizes
    # with `canonical_va_key`, and every consumer looks entries up with
    # `f"0x{va:08x}"` — an unnormalized key was seen by the coverage header but
    # missed by the category/delta selection and the prove queue).
    from rebrew.metadata.document import canonical_va_key

    normalized: dict[str, VerifyCacheEntry] = {}
    for key, entry in data.entries.items():
        va = canonical_va_key(key)
        normalized[f"0x{va:08x}" if isinstance(va, int) else str(key)] = entry
    return normalized


def _load_target_binary(cfg: ProjectConfig) -> Any | None:
    """Parse the target binary for unmatchable detection, or ``None``.

    A parse failure is not the same answer as "no binary": the callers below
    pass the result to ``detect_unmatchable``, which treats ``None`` as "no
    unmatchable evidence" and would recommend library and thunk stubs as new
    work.  Report the failure and continue, so the operator knows the lanes
    below are running unfiltered.
    """
    bin_path = getattr(cfg, "target_binary", None)
    if not bin_path or not Path(bin_path).exists():
        return None
    from rebrew.formats.binary_loader import load_binary

    try:
        return load_binary(Path(bin_path))
    except (OSError, ValueError, RuntimeError) as exc:
        log.warning("cannot parse %s: %s", bin_path, exc, exc_info=True)
        console.print(
            f"[yellow]WARNING: cannot parse {bin_path} ({exc}); "
            "unmatchable detection is disabled[/yellow]"
        )
        return None


def _inferred_module(name: str) -> str:
    """Library module for a bare function name, or "" when unclassified.

    ``FunctionEntry`` carries no module (only va/size/name/tool_name), so every
    module-aware branch here (the identify-library lane and
    ``estimate_difficulty``'s reference-source levels) infers it from the name
    with the same heuristic the FLIRT/import backends use.
    """
    from rebrew.identify_library import infer_module

    return infer_module(name, "")


def _collect_new_functions(
    ghidra_funcs: list[FunctionEntry],
    existing: dict[int, dict[str, str]],
    covered_vas: dict[int, str],
    cfg: ProjectConfig,
    skip_vas: frozenset[int] | set[int] = frozenset(),
) -> list[TodoItem]:
    """Collect uncovered functions as start-function candidates.

    *skip_vas* are never candidates: attributed library code and pseudo-
    functions found against rows the caller has already removed from
    *existing*.  Skipping them first keeps them out of the 50-item cap.
    """
    ignored = ignored_symbols(cfg)
    iat_set: set[int] = set(getattr(cfg, "iat_thunks", None) or [])
    sorted_covered = sorted(covered_vas)

    # `va in existing` only catches an EXACT start match, so a VA that falls
    # *inside* an already-annotated function was recommended as new work.  That
    # is never actionable: the enclosing function may already be EXACT, and
    # "reverse this" would duplicate matched code.  It happens constantly
    # because heuristic discovery emits switch arms as pseudo-functions
    # (`case.0x1000ad61.*`) and splits bodies it cannot walk — on guild-rebrew
    # 18 of 20 start-function actions were such artifacts, 17 of them switch
    # arms and one 420 bytes inside an EXACT function.  Build real spans from
    # the annotated sizes and skip anything they contain.
    # Built from the annotated sizes, shared with `rebrew status`.
    pseudo_vas = inside_annotated_vas(ghidra_funcs, existing) | set(skip_vas)

    # Statically linked library code sits in .text looking exactly like game
    # code, and reversing it is wasted work -- the linker supplies those bytes
    # anyway.  AGENTS.md makes this the FIRST check before reversing anything
    # (68 functions were once reversed by mistake and matched for weeks).
    # Recommending it as new work is therefore actively harmful, and it was
    # happening: all three surviving start-function actions on guild-rebrew
    # were LIBCMT (`_ftell`, `_strncnt`, `___ld12mul`).  Reuse lib_match's own
    # index so `todo` and `lib-match` cannot disagree.
    _lib_index = None
    from rebrew.lib_match import index_library, stock_lib_cache

    # Only this project's profile: the archive is another toolchain's code, so
    # indexing one extracted for a different profile would filter this list
    # against library bodies the build never links.
    _profile = str(getattr(cfg, "compiler_profile", "") or "")
    _cached = stock_lib_cache(cfg.root, "LIBCMT.LIB", _profile) if _profile else None
    if _cached is not None and _cached.exists():
        try:
            _lib_index = index_library(_cached)
        except Exception as exc:  # any archive parse failure; the filter is advisory
            console.print(
                f"[yellow]WARNING: cannot index {_cached} ({exc}); "
                "library functions are not filtered from the list[/yellow]"
            )

    _lib_probe_warned = False

    def _library_match(probe: int, probe_size: int) -> list[tuple[str, str]]:
        """Candidate symbols when *probe* is linked library code."""
        nonlocal _lib_probe_warned
        if _lib_index is None:
            return []
        from rebrew.formats.binary_loader import extract_raw_bytes
        from rebrew.lib_match import match_bytes

        try:
            data = extract_raw_bytes(cfg.target_binary, probe, probe_size or 64)
        except (OSError, ValueError, RuntimeError) as exc:
            # An unreadable target disables the filter for every probe; say so
            # once instead of recommending library code as new work silently.
            if not _lib_probe_warned:
                _lib_probe_warned = True
                console.print(
                    f"[yellow]WARNING: cannot read {cfg.target_binary} at 0x{probe:08x} "
                    f"({exc}); library functions may not be filtered[/yellow]"
                )
            return []
        return match_bytes(_lib_index, data)

    # Load binary for unmatchable detection
    binary_info = _load_target_binary(cfg)

    items: list[TodoItem] = []
    for func in ghidra_funcs:
        if len(items) >= 50:
            break
        va = func.va
        size = func.size
        name = func.name or f"FUN_{va:08x}"

        if va in existing or va in iat_set or name in ignored:
            continue
        if va in pseudo_vas:
            continue
        lib = _library_match(va, size)
        if lib:
            # Not new work, but not done either: no library_*.h attributes it
            # yet, so `rebrew status` still counts it as unstarted.
            symbols = sorted({sym for sym, _ in lib})
            objects = ", ".join(sorted({obj for _, obj in lib}))
            items.append(
                TodoItem(
                    category=CAT_IDENTIFY_LIBRARY,
                    roi_score=max(10.0, calculate_roi(size, 0.0, None) - 10.0),
                    va=va,
                    name=symbols[0] if len(symbols) == 1 else name,
                    size=size,
                    filename="",
                    description=f"linked library code ({objects}); candidates: "
                    + ", ".join(symbols)
                    + ": record a LIBRARY row, "
                    "do not reverse",
                    command=f"rebrew library match --stock-lib LIBCMT.LIB --va 0x{va:08x}",
                )
            )
            continue
        if size < 10:
            continue

        reason = detect_unmatchable(
            va,
            size,
            binary_info,
            iat_set,
            ignored,
            name,
            cs_arch=getattr(cfg, "capstone_arch", None),
            cs_mode=getattr(cfg, "capstone_mode", None),
        )
        if reason:
            continue

        difficulty, desc = estimate_difficulty(
            size, name, _inferred_module(name), ignored=ignored, cfg=cfg
        )
        if difficulty == 0:
            continue

        neighbor = find_neighbor_file(va, covered_vas, _sorted_keys=sorted_covered)
        # --append takes a reversed_dir-relative path; leave it as-is (skeleton
        # resolves it against reversed_dir) but keep the VA for the function.
        if neighbor:
            cmd = f"rebrew skeleton 0x{va:08x} --append {neighbor}"
        else:
            cmd = f"rebrew skeleton 0x{va:08x}"

        items.append(
            TodoItem(
                category=CAT_START_FUNCTION,
                roi_score=max(10.0, calculate_roi(size, 0.0, None) - difficulty * 2),
                va=va,
                name=name,
                size=size,
                filename=neighbor or "",
                description=desc,
                command=cmd,
                difficulty=difficulty,
            )
        )

    return items


def _collect_library_candidates(
    ghidra_funcs: list[FunctionEntry],
    existing: dict[int, dict[str, str]],
    cfg: ProjectConfig,
) -> list[TodoItem]:
    """Collect uncovered functions with library module for identification."""
    lib_modules = set(cfg.library_modules) if cfg.library_modules else {"ZLIB", "MSVCRT"}
    # Same non-targets the start-function lane skips: an IAT thunk or ASM
    # builtin is import glue / compiler support, not a library function to
    # identify, and a sub-10B row is not actionable.
    ignored: set[str] = set(getattr(cfg, "ignored_symbols", None) or [])
    iat_set: set[int] = set(getattr(cfg, "iat_thunks", None) or [])
    binary_info = _load_target_binary(cfg)
    items: list[TodoItem] = []
    for func in ghidra_funcs:
        va = func.va
        if va in existing or va in iat_set:
            continue
        size = func.size
        name = func.name or f"FUN_{va:08x}"
        if name in ignored or size < 10:
            continue
        # A probe failure must not read as "matchable work": the function is
        # then recommended as a candidate, which is exactly the wrong answer
        # for a thunk or library stub the probe could not classify.
        try:
            unmatchable = detect_unmatchable(va, size, binary_info, iat_set, ignored, name)
        except (TypeError, ValueError, AttributeError) as exc:
            log.warning(
                "unmatchable probe failed for %s (0x%08x): %s", name, va, exc, exc_info=True
            )
            continue
        if unmatchable:
            continue
        # FunctionEntry carries no module (only va/size/name/tool_name), so the
        # old `hasattr(func, "module")` was always False and this lane never
        # emitted.  The module is inferred from the name; an unclassifiable name
        # infers "" and is skipped.
        module = _inferred_module(name)
        if not module or module not in lib_modules:
            continue

        items.append(
            TodoItem(
                category=CAT_IDENTIFY_LIBRARY,
                roi_score=max(10.0, calculate_roi(size, 0.0, None) - 10.0),
                va=va,
                name=name,
                size=size,
                filename="",
                description=f"{module or 'library'} function — check reference sources or FLIRT",
                command=f"rebrew library scan-signatures --va 0x{va:08x}",
            )
        )
    return items


# Process-local extern names. The JSON file is the next process's cache.
_EXTERN_CACHE: dict[str, dict[str, Any]] = {}


def _extern_path_key(path: Path) -> str:
    # The source walk yields real absolute paths, so only a relative spelling
    # (or a symlinked config root) needs the component walk.
    if path.is_absolute():
        return str(path)
    try:
        return str(path.resolve())
    except OSError:
        return str(path)


def _display_path(path: Path, base: Path, base_text: str) -> str:
    """``rel_display_path`` without a path walk for a plain descendant."""
    text = str(path)
    if text.startswith(base_text):
        relative = text[len(base_text) :]
        if relative and "//" not in relative and "/./" not in relative:
            return relative
    from rebrew.utils import rel_display_path

    return rel_display_path(path, base)


def _extern_source_stamp(path: Path) -> list[int] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return [stat.st_mtime_ns, stat.st_size, stat.st_ino]


def _extern_cache_dir(cfg: ProjectConfig) -> Path:
    directory = getattr(cfg, "metadata_dir", None) or cfg.reversed_dir
    return Path(directory)


def _extern_entry(raw: object) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    stamp = raw.get("stamp")
    names = raw.get("names")
    if (
        not isinstance(stamp, list)
        or len(stamp) != 3
        or any(type(part) is not int for part in stamp)
        or not isinstance(names, list)
        or any(not isinstance(name, str) for name in names)
    ):
        return None
    return {"stamp": stamp, "names": names}


def _begin_extern_cache(directory: Path) -> dict[str, Any]:
    key = _extern_path_key(directory)
    cached = _EXTERN_CACHE.get(key)
    if cached is not None:
        return cached
    files: dict[str, dict[str, Any]] = {}
    cache_path = directory / ".rebrew" / "extern-names.json"
    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
    except OSError, UnicodeError, json.JSONDecodeError, TypeError:
        payload = None
    if isinstance(payload, dict):
        for path_key, raw in payload.items():
            parsed = _extern_entry(raw)
            if isinstance(path_key, str) and parsed is not None:
                files[path_key] = parsed
    record: dict[str, Any] = {"dir": directory, "files": files, "dirty": False}
    _EXTERN_CACHE[key] = record
    return record


def _flush_extern_cache(cache: dict[str, Any]) -> None:
    """Write extern names for the next process. A failure leaves the counts."""
    if not cache.get("dirty"):
        return
    cache_path = Path(cache["dir"]) / ".rebrew" / "extern-names.json"
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = cache_path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(cache["files"], separators=(",", ":")), encoding="utf-8")
        os.replace(temporary, cache_path)
    except OSError:
        return
    cache["dirty"] = False


def _caller_counts(
    cfg: ProjectConfig,
    matched_files: set[str] | None = None,
    *,
    scanned: Sequence[Path] | None = None,
) -> dict[str, int]:
    """Count unresolved callers per callee name from extern declarations.

    Scans reversed sources for ``extern`` function declarations: each file
    whose own function is still unmatched counts as one unresolved caller
    of every extern callee it declares.  Best-effort (unparseable files
    skipped); returns ``{callee name: caller count}``.

    *matched_files* (relative paths, from the metadata store) are skipped: a
    caller that is already byte-matched no longer needs its callees
    implemented, so it must not add ROI or an "unblocks N caller(s)" note.
    The skip happens after the name lookup, so a matched file still fills
    the cache. Unchanged sources reuse ``.rebrew/extern-names.json``. A
    source that does not contain ``extern`` is stored empty and is not parsed.
    """
    from rebrew.c_parser import find_extern_function_names
    from rebrew.sources import iter_sources
    from rebrew.utils import read_source_text

    counts: dict[str, int] = {}
    try:
        files = list(iter_sources(cfg.reversed_dir, cfg, scanned=scanned))
    except OSError:
        return counts
    cache = _begin_extern_cache(_extern_cache_dir(cfg))
    base = Path(cfg.reversed_dir)
    base_text = str(base).rstrip("/") + "/"
    for path in files:
        key = _extern_path_key(path)
        stamp = _extern_source_stamp(path)
        entry = cache["files"].get(key)
        if stamp is not None and entry is not None and entry["stamp"] == stamp:
            names = entry["names"]
        else:
            try:
                text = read_source_text(path)[0]
            except OSError as exc:
                # Its externs contribute no call counts, which would misrank the
                # work list.  Say which file was dropped.
                log.warning("skipping unreadable source %s: %s", path, exc)
                continue
            names = [] if "extern" not in text else find_extern_function_names(text)
            if stamp is not None:
                cache["files"][key] = {"stamp": stamp, "names": names}
                cache["dirty"] = True
        if matched_files and _display_path(path, base, base_text) in matched_files:
            continue
        for callee in names:
            counts[callee] = counts.get(callee, 0) + 1
    _flush_extern_cache(cache)
    return counts


def _collect_data_drift(cfg: ProjectConfig) -> list[TodoItem]:
    """Collect data symbols whose built bytes drift from the reference.

    Reads rebrew-data.toml STATUS verdicts written by ``verify --data``.
    Data VAs live in a separate address space from function VAs in practice
    (.data/.rdata vs .text), so no dedup against function items is needed.
    """
    from rebrew.data_layout import data_symbol_size
    from rebrew.metadata.data import load_data_metadata, module_visible_to_target
    from rebrew.status import postlink_copied_ranges, span_is_copied

    items: list[TodoItem] = []
    copied = postlink_copied_ranges(cfg)
    for (module, va), fields in load_data_metadata(cfg.metadata_dir).items():
        if not module_visible_to_target(module, cfg):
            continue
        verdict = str(fields.get("status") or "").upper()
        if verdict not in ("DRIFT", "DISPLACED"):
            continue
        name = str(fields.get("name") or f"DAT_{va:08x}")
        size = data_symbol_size(fields, arch=getattr(cfg, "arch", "x86_32"))
        if span_is_copied(va, size, copied):
            continue
        items.append(
            TodoItem(
                category=CAT_DATA_DRIFT,
                roi_score=50.0,
                va=va,
                name=name,
                size=size,
                filename="",
                description=(
                    f"data symbol {name} is linked away from its reference address ({module} 0x{va:x})"
                    if verdict == "DISPLACED"
                    else f"data symbol {name} differs from reference bytes ({module} 0x{va:x})"
                ),
                command="rebrew verify --data",
                status=verdict,
                blocker=str(fields.get("note") or ""),
            )
        )
    return items


def _zero_fill_tail_checker(cfg: ProjectConfig) -> Callable[[dict[str, Any]], bool]:
    """Return a predicate: does this metadata symbol live in a zero-fill tail?

    A section's bytes past ``raw_size`` exist in memory but not in the file, so
    the loader zero-fills them and ``section_symbol_bytes`` deliberately skips
    them.  ``verify --data`` can therefore never mark them VERIFIED.

    The binary is loaded once, lazily, on the first call that needs it, and any
    load failure degrades to "not in a tail" -- the conservative answer, since
    wrongly skipping a symbol would hide real work.
    """
    cache: dict[str, Any] = {}
    missing = object()

    def in_tail(fields: dict[str, Any]) -> bool:
        from rebrew.data_layout import data_symbol_size

        section = str(fields.get("section") or "")
        if section in ("", ".idata", ".bss"):
            return section == ".bss"
        sections: Any = cache.get("sections", missing)
        if sections is missing:
            try:
                from rebrew.formats.binary_loader import load_binary

                sections = load_binary(cfg.target_binary).sections
            except OSError, ValueError, KeyError, AttributeError, ImportError:
                sections = None
            cache["sections"] = sections
        if not sections:
            return False
        sec = sections.get(section)
        if sec is None:
            return False
        size = data_symbol_size(fields, arch=getattr(cfg, "arch", "x86_32"))
        if size <= 0:
            return False
        offset = int(fields.get("va") or 0) - int(sec.va)
        if offset < 0 or offset >= int(sec.size or sec.raw_size):
            return False
        return bool(offset + size > int(sec.raw_size))

    return in_tail


def _collect_start_data(cfg: ProjectConfig) -> list[TodoItem]:
    """Collect data symbols never verified (STATUS UNCHECKED or absent).

    The data-side "undone work" lane: same file already read for drift, so
    this costs one more filter pass, not another load.  Command verifies
    just the symbol's section scope.

    Import-table and BSS-resident entries are skipped. They are not C to
    edit. ``verify --data`` reads an import slot from ``.rdata`` and compares
    a zero-fill span as zeros when the built image covers it. A raw link's
    import-name RVAs may differ, and that drift is not a source edit.

    * Import slots (``__imp__`` / ``section = ".idata"``) are supplied by the
      linker from the import directory.  One project carried 84 of them, every
      IAT dword, and the image has no .idata section at all; the IAT sits at
      the head of .rdata.
    * BSS slots have no file bytes. The loader zero-fills them, and so does
      the built image where its virtual size covers the span. Symbols declared
      ``.bss`` are the obvious case; so are symbols declared ``.data`` that sit
      beyond that section's raw extent. A span past the built virtual size
      stays UNCHECKED.

    Measured on the project that motivated this: of 207 UNCHECKED entries, all
    207 were un-clearable, and independent byte comparison found every one of
    them already correct (5 with file bytes byte-identical, 111 in the zero-fill
    tail, 84 import slots, 7 without a size).
    """
    from rebrew.data_layout import data_symbol_size
    from rebrew.metadata.data import (
        data_status_bucket,
        load_data_metadata,
        module_visible_to_target,
    )

    in_zero_fill_tail = _zero_fill_tail_checker(cfg)
    items: list[TodoItem] = []
    for (module, va), fields in load_data_metadata(cfg.metadata_dir).items():
        # One metadata file serves every target in a unified tree, so a row's
        # module decides whether THIS target still owes work.  Without the
        # filter the server's todo listed 20 GOLDTL data symbols (0x6624a0,
        # 0x773d80, …): VAs no server marker can ever clear. Library modules
        # stay; they are linked into this binary.
        if not module_visible_to_target(module, cfg):
            continue
        # Same unchecked bucket as ``rebrew status``, including a hand-edited
        # spelling the writer would have rejected.
        if data_status_bucket(fields.get("status")) != "unchecked":
            continue
        name = str(fields.get("name") or "")
        section = str(fields.get("section") or "").lower()
        if name.startswith("__imp_") or section in (".idata", ".bss"):
            continue
        if in_zero_fill_tail({**fields, "va": va}):
            continue
        name = str(fields.get("name") or f"DAT_{va:08x}")
        size = data_symbol_size(fields, arch=getattr(cfg, "arch", "x86_32"))
        items.append(
            TodoItem(
                category=CAT_START_DATA,
                roi_score=10.0,
                va=va,
                name=name,
                size=size,
                filename="",
                description=f"data symbol {name} never verified ({module} 0x{va:x})",
                command="rebrew verify --data",
                status=str(fields.get("status") or "UNCHECKED"),
                blocker=str(fields.get("note") or ""),
            )
        )
    return items


# ---------------------------------------------------------------------------
# Main collection + ranking
# ---------------------------------------------------------------------------


def _text_layout_differs(raw_info: Any, built_info: Any) -> bool:
    """True when the two images give .text a different VA or virtual size."""

    def text_span(info: Any) -> tuple[int, int] | None:
        sections = getattr(info, "sections", None) or {}
        section = sections.get(".text")
        if section is None:
            return None
        return int(section.va), int(section.size)

    raw_span = text_span(raw_info)
    built_span = text_span(built_info)
    if raw_span is None or built_span is None:
        return True
    return raw_span != built_span


def _postlink_rewritten_checker(cfg: ProjectConfig) -> Callable[[int, int], bool]:
    """Return a predicate: did a postlink fixer rewrite this span's bytes?

    True when the shipped image's bytes at ``[va, va + size)`` differ from the
    pre-postlink ``raw_link`` image, i.e. the deliverable carries bytes the
    compiler and linker did not emit.  Both images are read and parsed once, on
    the first call that needs them; any failure degrades to "not rewritten" —
    the conservative answer, since claiming a rewrite that did not happen would
    invent work.
    """
    from rebrew.formats.binary_loader import load_binary, va_to_file_offset
    from rebrew.status import find_built_image

    cache: dict[str, Any] = {}
    missing = object()

    def rewritten(va: int, size: int) -> bool:
        if size <= 0:
            return False
        images = cache.get("images", missing)
        if images is missing:
            images = None
            raw = getattr(cfg, "raw_link", None)
            built = find_built_image(cfg.root, cfg.target_name, None)
            if raw and built and Path(raw) != built:
                try:
                    images = (
                        Path(raw).read_bytes(),
                        built.read_bytes(),
                        load_binary(Path(raw)),
                        load_binary(built),
                    )
                except OSError, ValueError, KeyError, RuntimeError:
                    images = None
            cache["images"] = images
        if images is None:
            return False
        raw_bytes, built_bytes, raw_info, built_info = images
        raw_off = int(va_to_file_offset(raw_info, va))
        built_off = int(va_to_file_offset(built_info, va))
        if raw_off < 0 or built_off < 0:
            return False
        # Absolute VAs only compare meaningfully when both images place the same
        # function at the same address. Two independent links order functions
        # differently, so a shifted layout would sample unrelated bytes and report
        # a rewrite that never happened. Compare only when the containing .text
        # spans agree; otherwise the conservative answer is "not rewritten".
        if _text_layout_differs(raw_info, built_info):
            return False
        return bool(
            raw_bytes[raw_off : raw_off + size] != built_bytes[built_off : built_off + size]
        )

    return rewritten


def _collect_postlink_rewritten(
    cfg: ProjectConfig,
    existing: dict[int, dict[str, str]],
    size_by_va: dict[int, int],
) -> list[TodoItem]:
    """Collect functions whose shipped bytes a postlink fixer produced.

    ``rebrew build postlink`` rewrites ``.text`` IAT slot operands, absolute data
    operands, and call/jump targets, so a function can be byte-matched in the
    deliverable while the toolchain never emitted those bytes.  Only detectable
    when the project configures ``raw_link``; without it the lane is empty
    rather than guessed.
    """
    rewritten = _postlink_rewritten_checker(cfg)
    items: list[TodoItem] = []
    for va, info in existing.items():
        try:
            size = int(info.get("size") or 0) or size_by_va.get(va) or 0
        except TypeError, ValueError:
            size = size_by_va.get(va) or 0
        if not rewritten(va, size):
            continue
        items.append(
            TodoItem(
                category=CAT_POSTLINK,
                roi_score=0.0,
                va=va,
                name=str(info.get("symbol") or f"FUN_{va:08x}"),
                size=size,
                filename=str(info.get("filename", "")),
                description=(
                    "postlink rewrote these bytes — the raw link does not "
                    "produce them, so the build is not toolchain-identical"
                ),
                command=f"rebrew test 0x{va:08x} --linked",
                status=str(info.get("status") or ""),
            )
        )
    return items


def _collect_missing_bindings(
    cfg: ProjectConfig, existing: dict[int, dict[str, str]]
) -> list[TodoItem]:
    """Keep missing managed definitions visible without claiming source coverage."""
    from rebrew.c_parser import function_signatures
    from rebrew.config import target_module
    from rebrew.metadata.bindings import derive_c_symbol
    from rebrew.metadata.functions import load_metadata
    from rebrew.utils import preset_module_key, read_source_text, rel_display_path

    target_module_name = preset_module_key(target_module(cfg) or "")
    items: list[TodoItem] = []
    for (module, va), row in load_metadata(cfg.metadata_dir, deepcopy=False).items():
        stored = str(row.get("file") or "")
        if (
            va in existing
            or preset_module_key(module) != target_module_name
            or row.get("kind") not in {"FUNCTION", "STUB"}
            or row.get("status") == "SKIP"
            or Path(stored).suffix.casefold() not in {".c", ".cpp", ".cc", ".cxx"}
        ):
            continue
        path = cfg.root / stored.replace("\\", "/")
        # A valid definition outside the normal source walk is not missing.
        if path.is_file():
            definitions = function_signatures(read_source_text(path)[0])
            symbol = str(row.get("symbol") or "")
            if symbol in {derive_c_symbol(name, proto) for name, proto in definitions.items()}:
                continue
        items.append(
            TodoItem(
                category=CAT_EXTRACT_ERROR,
                roi_score=150.0,
                va=va,
                name=str(row.get("symbol") or row.get("name") or f"FUN_{va:08x}"),
                size=int(row.get("size") or 0),
                filename=rel_display_path(path, cfg.reversed_dir),
                description=f"Managed source {'definition' if path.is_file() else 'file'} missing: {stored}",
                command=f"rebrew test 0x{va:08x}",
                status="EXTRACT_ERROR",
                blocker=str(row.get("blocker") or ""),
            )
        )
    return items


def collect_all(
    cfg: ProjectConfig,
    ghidra_funcs: list[FunctionEntry],
    existing: dict[int, dict[str, str]],
    covered_vas: dict[int, str],
    exclude_vas: set[int] | None = None,
    *,
    scanned: Sequence[Path] | None = None,
) -> list[TodoItem]:
    """Collect and rank all todo items by ROI score (descending).

    *exclude_vas* holds VA rows that are linked library code (``external_vas``:
    ``LIBRARY`` markers plus configured external modules).  They are not work:
    the bytes come from the archive, so neither "improve this match" nor
    "start this function" is a runnable action — the server's ``library_msvc.h``
    rows alone filled 11 of the top 20 slots before this filter.
    """
    items: list[TodoItem] = []

    # Setup steps for fresh/incomplete projects (scored highest)
    items.extend(_collect_setup_steps(cfg, ghidra_funcs, existing))
    items.extend(_collect_missing_bindings(cfg, existing))

    size_by_va: dict[int, int] = {f.va: f.size for f in ghidra_funcs}
    name_by_va: dict[int, str] = {f.va: f.name or "" for f in ghidra_funcs}
    verify_entries = load_verify_entries(cfg)

    # 1. Collect all active functions tracked in the project
    # A caller whose own function is already byte-matched does not need its
    # callees implemented, so it must not boost them (the caller-count
    # docstring's "unresolved caller" contract).
    matched_files = {
        str(info.get("filename", ""))
        for info in existing.values()
        if str(info.get("status", "")).upper() in MATCHED_STATUSES
    }
    items.extend(
        _collect_active_functions(
            existing,
            size_by_va,
            name_by_va,
            verify_entries,
            _caller_counts(cfg, matched_files, scanned=scanned),
        )
    )

    # 2. Collect specialized candidates
    items.extend(_collect_prover_candidates(existing, size_by_va, verify_entries))
    items.extend(
        _collect_new_functions(ghidra_funcs, existing, covered_vas, cfg, exclude_vas or set())
    )
    items.extend(_collect_library_candidates(ghidra_funcs, existing, cfg))
    items.extend(_collect_postlink_rewritten(cfg, existing, size_by_va))
    items.extend(_collect_data_drift(cfg))
    items.extend(_collect_start_data(cfg))

    # Library rows are never actions (see the docstring): drop them before
    # ranking so they cannot displace real work.
    if exclude_vas:
        items = [item for item in items if item.va not in exclude_vas]

    # One action per code address, and one per data address. Setup items
    # (va=0) are category-level, so they skip dedup. A function and a data
    # symbol can share an address; folding them into one VA dropped the
    # function, because exact-only scores 0 and start-data scores 10.
    best: dict[tuple[str, int], TodoItem] = {}
    non_va_items: list[TodoItem] = []
    for item in items:
        if item.va == 0:
            non_va_items.append(item)
            continue
        key = (_item_domain(item), item.va)
        prev = best.get(key)
        if prev is None or item.roi_score > prev.roi_score:
            best[key] = item
    items = non_va_items + list(best.values())

    if getattr(cfg, "execution_backend", "") == "unshare":
        raw_link = getattr(cfg, "raw_link", None)
        command = ""
        next_step = "build and configure a raw linker image before verification"
        if raw_link is not None and Path(raw_link).is_file():
            command = (
                "rebrew verify --text --raw-link "
                f"--built {shlex.quote(str(raw_link))} --target {shlex.quote(cfg.target_name)}"
            )
            next_step = "compare the configured raw linker image"
        for item in items:
            if item.category in {CAT_EXACT_ONLY, CAT_POSTLINK}:
                item.command = command
                item.description += f"; unshare cannot run linked comparison; {next_step}"

    # Sort by ROI descending
    items.sort(key=lambda x: (-x.roi_score, x.va))
    return items


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew todo  # Top 20 actions by ROI (size + similarity to target)\n\n"
    "  rebrew todo --limit 50  # Show top 50\n\n"
    "  # Filter to quick-win near-misses (<= 20B diff)\n"
    "  rebrew todo --category fix-delta\n\n"
    "  # Filter to functions needing general work\n"
    "  rebrew todo --category improve-match\n\n"
    "  rebrew todo --json  # Machine-readable JSON output\n\n"
    "[bold]Categories (interleaved globally by continuous ROI score):[/bold]\n\n"
    "  setup · · · · · · · · · Project setup steps (fresh projects)\n\n"
    "  compile-error · · · · · Failed verify syntax/includes\n\n"
    "  extract-error · · · · · Symbol not found in .obj: binding/symbol/implementation issue\n\n"
    "  fix-delta · · · · · · · Known tiny byte diffs (<= 20B): flag sweeps, padding, GA\n\n"
    "  improve-match · · · · · Functions in-progress without a known small delta\n\n"
    "  start-function · · · ·  Uncovered functions, ranked by difficulty\n\n"
    "  missing-annotation · ·  Found in Ghidra but missing C body or SIZE metadata\n\n"
    "  identify-library · · ·  Uncovered library-origin functions\n\n"
    "  run-prover · · · · · ·  Small nearly-matching functions (angr equivalence)\n\n"
    "  documented · · · · · ·  IAT thunks / non-reproducible code. Audit only, hidden from the default list\n\n"
    "  data-drift · · · · · ·  Data symbol differs from reference bytes. Run `rebrew verify --data`\n\n"
    "  start-data · · · · · ·  Data symbol never verified. Run `rebrew verify --data`\n\n"
    "  exact-only · · · · · ·  RELOC matches: identical only with relocations masked, not straight out of the toolchain\n\n"
    "  postlink-mangled · · ·  Functions whose shipped bytes a postlink fixer rewrote (needs `raw_link` configured)\n\n"
    "[dim]Reads from function_structure.json, source files, and .rebrew/verify_cache.toml.[/dim]"
)

#: Title letters. These five stay visible at zero; every other status is
#: printed beside them when its count is nonzero, so the letters partition
#: the covered functions instead of hiding SIZE_MISMATCH and the rest.
_LETTER_STATUSES = (
    ("EXACT", "E", STATUS_COLORS["EXACT"]),
    ("RELOC", "R", STATUS_COLORS["RELOC"]),
    ("PROVEN", "P", STATUS_COLORS["PROVEN"]),
    ("NEAR_MATCHING", "M", STATUS_COLORS["NEAR_MATCHING"]),
    ("STUB", "S", STATUS_COLORS["STUB"]),
)


def _coverage_status_markup(status_counts: dict[str, int]) -> str:
    """E/R/P/M/S plus every other nonzero status, one token per covered row."""
    parts = [
        f"[{color}]{status_counts.get(name, 0)}{letter}[/{color}]"
        for name, letter, color in _LETTER_STATUSES
    ]
    known = {name for name, _letter, _color in _LETTER_STATUSES}
    for name in sorted(status_counts):
        count = status_counts[name]
        if name not in known and count:
            color = STATUS_COLORS.get(name, "dim")
            parts.append(f"[{color}]{count} {name}[/{color}]")
    return " ".join(parts)


app = typer.Typer(
    help="Prioritized action list: what to work on next for highest ROI.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    count: int = typer.Option(20, "--limit", "-n", help="Number of items to show (0 = none)"),
    category: str | None = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category (fix-delta, start-function, compile-error, ...)",
    ),
    stats: bool = typer.Option(False, "--stats", "-s", help="Show coverage stats header"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
    all_targets: bool = AllTargetsOption,
) -> None:
    """Show prioritized actions ranked by ROI."""
    category = option_default(category, None)
    count = require_non_negative(
        option_default(count, 20), "--limit", json_mode=option_default(json_output, False)
    )
    if category is not None and category not in _CATEGORY_COLORS:
        error_exit(
            f"Unknown category {category!r}; choose one of: {', '.join(_CATEGORY_COLORS)}",
            json_mode=json_output,
        )
    all_targets = option_default(all_targets, False)
    if all_targets_run(
        target=target,
        all_targets=all_targets,
        json_mode=json_output,
        run_one=lambda n: main(
            count=count,
            category=category,
            stats=stats,
            json_output=json_output,
            target=n,
            all_targets=False,
        ),
    ):
        return
    cfg = require_config(target=target, json_mode=json_output)
    from rebrew.sources import scan_files

    tree = scan_files(cfg.reversed_dir)
    try:
        ghidra_funcs, existing, covered_vas = load_data(cfg, tree=tree)
        from rebrew.naming import external_vas, scope_to_target

        # Before scoping: external .lib rows carry library modules
        # (D3DX8, MSVCRT, …) and leave the denominator as identified
        # external code whatever the module — the flag is
        # `targets.<name>.external_libs` (same rule as `rebrew status`).
        library_vas = external_vas(existing, getattr(cfg, "external_libs", None))
        existing = scope_to_target(existing, cfg)
        # Switch arms and split bodies inside an annotated function (library
        # rows included) are not functions: the rule `rebrew status` uses.
        pseudo_vas = inside_annotated_vas(ghidra_funcs, existing)
        # Library rows are NOT work: their bytes come from the linked archive,
        # so "improve-match / needs implementation" is a false action item.
        # The server's `library_msvc.h` alone contributed 11 of the top 20
        # items before this filter (round 1380: `_ftell`, `__ftell_lk`,
        # `_realloc`, … all correctly attributed, all unrunnable).
        existing = {va: info for va, info in existing.items() if va not in library_vas}
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        error_exit(f"Failed to load project data: {exc}", json_mode=json_output)
    all_items = collect_all(
        cfg,
        ghidra_funcs,
        existing,
        covered_vas,
        exclude_vas=library_vas | pseudo_vas,
        scanned=tree,
    )

    # Coverage stats (always computed for JSON, optional for terminal)
    # Overlay verify cache on annotation statuses (same logic + target guard
    # as status.py — a different target's cache must not leak into this
    # project's coverage stats).
    from rebrew.status import load_verify_statuses

    verify_statuses = load_verify_statuses(cfg)

    from rebrew.metadata.functions import canonical_status

    status_counts: dict[str, int] = {}
    documented = 0
    for va_int, info in existing.items():
        # External .lib attributions count for nothing (same rule as
        # `rebrew status`): identifications, not bodies to match.
        if va_int in library_vas:
            continue
        ann_status = info.get("status", "STUB")
        s = effective_status(ann_status, verify_statuses.get(va_int))
        # Documented non-targets stay STUB, the bucket `rebrew status` uses.
        # `documented` is how many of those STUB rows carry the marker, not
        # a seventh bucket and not the NO_SOURCE remainder.
        if (
            s == "STUB"
            and canonical_status(ann_status or "") == "STUB"
            and any(m in info.get("blocker", "") for m in _NON_TARGET_MARKERS)
        ):
            documented += 1
        status_counts[s] = status_counts.get(s, 0) + 1
    function_vas = {va for va in existing if va not in library_vas}
    ghidra_vas = {f.va for f in ghidra_funcs}
    total_funcs = len(function_vas | (ghidra_vas - library_vas - pseudo_vas))
    covered = len(function_vas)
    # Denominator mirrors `rebrew status` exactly (the two must not
    # disagree): covered FUNCTION rows plus the ghidra inventory MINUS
    # identified library code (CRT/zlib/static libs — "never reverse"
    # attributions, not pending work).  The older shapes both lied:
    # `ghidra_funcs` alone went over 100% (library rows outside the
    # inventory), and `ghidra ∪ covered` counted library attributions as
    # unfinished functions (28% where status said 42% for the same tree).
    # When the target binary is on disk, the live status report replaces
    # these counts so a second loop cannot drift from it.
    text_bytes = 0
    accounted_bytes = 0
    byte_coverage_pct: float | None = None
    binary = Path(getattr(cfg, "target_binary", "") or "")
    if binary.is_file():
        try:
            from rebrew.status import collect_status

            progress = collect_status(cfg)
        except OSError, ValueError, KeyError:
            progress = None
        else:
            if progress is not None and progress.load_error:
                progress = None
        if progress is not None:
            status_counts = dict(progress.status_counts)
            total_funcs = progress.total_functions
            covered = progress.covered_functions
            if progress.total_text_bytes > 0:
                text_bytes = progress.total_text_bytes
                accounted_bytes = progress.accounted_text_bytes
                byte_coverage_pct = progress.byte_coverage_pct
    exact = status_counts.get("EXACT", 0)
    reloc = status_counts.get("RELOC", 0)
    proven = status_counts.get("PROVEN", 0)
    matching = status_counts.get("NEAR_MATCHING", 0)
    stub = status_counts.get("STUB", 0)
    denominator = total_funcs
    # Function ratio. PROVEN bytes still differ from the target. This is
    # `StatusReport.matched_pct`, not the code account.
    pct = floor_pct(exact + reloc, denominator)
    if byte_coverage_pct is not None:
        pct_label = f"{byte_coverage_pct}% of .text"
    else:
        pct_label = f"{pct}% of functions"

    if category:
        all_items = [i for i in all_items if i.category == category]
    else:
        # Documented non-targets are audit info, not work — hide them from the
        # default actionable list (still visible via `-c documented` and the
        # coverage stats below).
        all_items = [i for i in all_items if i.category != CAT_DOCUMENTED]

    display_items = all_items[:count]

    if json_output:
        cat_summary: dict[str, int] = {}
        for item in all_items:
            cat_summary[item.category] = cat_summary.get(item.category, 0) + 1
        json_print(
            {
                "coverage": {
                    "ghidra_funcs": total_funcs,
                    "covered": covered,
                    "exact": exact,
                    "reloc": reloc,
                    "proven": proven,
                    "matching": matching,
                    "stub": stub,
                    "documented": documented,
                    "pct_matched": pct,
                    "byte_coverage_pct": byte_coverage_pct,
                    "statuses": status_counts,
                },
                "total_items": len(all_items),
                "count": len(display_items),
                "summary": cat_summary,
                "items": [i.to_dict() for i in display_items],
            }
        )
        return

    if denominator > 0 or text_bytes > 0:
        # One bar. With a known .text it is the code account; otherwise the
        # function ratio, labeled as functions. Per-row Match % is neither.
        render_matched_headline(
            exact + reloc,
            denominator,
            accounted_bytes=accounted_bytes,
            text_bytes=text_bytes,
        )

    if stats or not display_items:
        # Show coverage stats header
        toolchain = (
            f"  [dim]· [green]{exact}[/green] identical straight from the toolchain[/dim]"
            if reloc
            else ""
        )
        extra = "".join(
            f"  [{STATUS_COLORS.get(name, 'dim')}]{name}: {status_counts[name]}"
            f"[/{STATUS_COLORS.get(name, 'dim')}]"
            for name in sorted(status_counts)
            if name not in {row[0] for row in _LETTER_STATUSES} and status_counts[name]
        )
        console.print(
            f"  [bold]Coverage[/bold]: {covered} covered"
            f"  ({total_funcs} in Ghidra function list)"
            f"  [{STATUS_COLORS['EXACT']}]EXACT: {exact}[/{STATUS_COLORS['EXACT']}]"
            f"  [{STATUS_COLORS['RELOC']}]RELOC: {reloc}[/{STATUS_COLORS['RELOC']}]"
            f"  [{STATUS_COLORS['PROVEN']}]PROVEN: {proven}[/{STATUS_COLORS['PROVEN']}]"
            f"  [{STATUS_COLORS['NEAR_MATCHING']}]NEAR_MATCHING: {matching}[/{STATUS_COLORS['NEAR_MATCHING']}]"
            f"  [{STATUS_COLORS['STUB']}]STUB: {stub}[/{STATUS_COLORS['STUB']}]"
            f"  [dim]DOCUMENTED: {documented}[/dim]"
            f"{extra}"
            f"  → [bold]{exact + reloc}/{denominator}[/bold] functions byte-matched{toolchain}"
        )

    if not display_items:
        console.print("No action items found. Great progress!")
        return

    # Match % is the figure that must not read as 100% for a near miss.  Fixed
    # widths that sum past a dumb terminal (80) are reduced evenly and that
    # column collapses to nothing, so only Name and Description flex.
    table = Table(
        show_header=True, header_style="bold", pad_edge=False, expand=True, padding=(0, 1)
    )
    table.add_column("#", style="dim", width=3, justify="right", no_wrap=True)
    table.add_column("Cat", width=10, no_wrap=True, overflow="ellipsis")
    table.add_column("VA", width=10, no_wrap=True, overflow="ellipsis")
    table.add_column("Sz", width=6, justify="right", no_wrap=True)
    table.add_column("Name", ratio=1, no_wrap=True, overflow="ellipsis")
    table.add_column("Match %", width=7, justify="right", no_wrap=True)
    table.add_column("Δ", width=5, justify="right", no_wrap=True)
    table.add_column("Description", ratio=2, no_wrap=True, overflow="ellipsis")

    for i, item in enumerate(display_items, 1):
        color = _CATEGORY_COLORS.get(item.category, "white")
        cat_label = item.category.replace("-", "\u2011")  # non-breaking hyphen for display
        match_str = (
            f"{floor_pct(item.match_percent, 100):.1f}%" if item.match_percent is not None else "—"
        )
        delta_str = f"{item.byte_delta}B" if item.byte_delta is not None else "—"
        table.add_row(
            str(i),
            f"[{color}]{cat_label}[/{color}]",
            f"0x{item.va:08x}" if item.va else "",
            f"{item.size}B" if item.size else "",
            item.name,
            match_str,
            delta_str,
            item.description,
        )

    # Category summary subtitle
    cat_parts: dict[str, int] = {}
    for item in all_items:
        cat_parts[item.category] = cat_parts.get(item.category, 0) + 1
    subtitle = "  ".join(
        f"[{_CATEGORY_COLORS.get(cat, 'white')}]{cat}: {cnt}[/{_CATEGORY_COLORS.get(cat, 'white')}]"
        for cat, cnt in sorted(cat_parts.items(), key=lambda x: -x[1])
    )

    panel = Panel(
        table,
        title=(
            f"[bold]Rebrew TODO[/bold] — {len(all_items)} actions"
            f"  {_coverage_status_markup(status_counts)} ({pct_label})"
        ),
        subtitle=subtitle,
        border_style="blue",
    )
    console.print(panel)
    console.print(f"  Showing top {len(display_items)} of {len(all_items)} items")
    console.print(
        "  Tip: use [bold]rebrew todo --category <category>[/bold] to filter  |  [bold]rebrew todo --stats[/bold] for stats"
    )


def render_matched_headline(
    matched: int,
    total: int,
    *,
    accounted_bytes: int = 0,
    text_bytes: int = 0,
) -> None:
    """Print the same progress line ``rebrew status`` prints.

    With a known virtual ``.text``, that is the code account (matched
    functions, identified libraries, and alignment padding) and the
    byte-matched function count under it. Without a measured section the
    function share is the percentage, and it is not called a byte match.
    """
    if text_bytes > 0:
        from rebrew.status import CODE_ACCOUNT_CAPTION, code_account_headline

        pct = floor_pct(accounted_bytes, text_bytes)
        console.print(f"  [bold]{code_account_headline(pct, accounted_bytes, text_bytes)}[/bold]")
        console.print(f"  [dim]{CODE_ACCOUNT_CAPTION}[/dim]")
        console.print(ratio_bar(accounted_bytes, text_bytes))
        if total > 0:
            console.print(f"  {matched}/{total} functions byte-matched")
        return
    pct = floor_pct(matched, total)
    console.print(f"  [bold]{matched}/{total} functions  ({pct}%)[/bold]")
    if total > 0:
        console.print(ratio_bar(matched, total))


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
