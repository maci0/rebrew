"""todo.py – Prioritized action dashboard for rebrew projects.

Synthesizes verify results, coverage data, and function catalog into a single
ranked list of "what to work on next" with ROI scoring.

Usage::

    rebrew todo                     Top 20 actions by ROI
    rebrew todo --count 50          Show top 50
    rebrew todo -c fix-delta        Filter by category
    rebrew todo --stats             Show coverage stats header
    rebrew todo --json              Machine-readable output
"""

import contextlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rebrew.catalog import FunctionEntry
    from rebrew.verify_cache import VerifyCacheEntry

import typer
from rich.panel import Panel
from rich.table import Table

from rebrew.cli import (
    AllTargetsOption,
    TargetOption,
    all_targets_run,
    console,
    error_exit,
    json_print,
    option_default,
    require_config,
)
from rebrew.compile import NEAR_MATCH_THRESHOLD
from rebrew.config import ProjectConfig, inventory_path_for
from rebrew.metadata import GA_CEILING_PREFIX
from rebrew.naming import (
    detect_unmatchable,
    estimate_difficulty,
    find_neighbor_file,
    ignored_symbols,
    inside_annotated_vas,
    load_data,
    parse_byte_delta,
)
from rebrew.status import effective_status
from rebrew.utils import floor_pct
from rebrew.workspace.status import MATCHED_STATUSES

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
# Byte-exact via a generated naked skeleton (`// SOURCE: naked`) — reproduced,
# NOT decompiled: it stays on the list until the real C body matches.
CAT_NAKED = "naked-reconstruction"
# Data symbol whose built bytes differ from the reference (`verify --data`
# wrote STATUS DRIFT in rebrew-data.toml).
CAT_DATA_DRIFT = "data-drift"
# Data symbol never verified (STATUS UNCHECKED or absent in rebrew-data.toml).
CAT_START_DATA = "start-data"

# Proving is only feasible when few bytes actually differ: symbolic execution
# over hundreds of mismatched bytes just times out.  Cap the estimated byte
# delta for measured (verify-cached) candidates; unmeasured ones stay eligible.
_PROVE_MAX_DIFF_BYTES = 8

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
    ghidra_funcs: list["FunctionEntry"],
    existing: dict[int, dict[str, str]],
) -> list[TodoItem]:
    """Detect missing project setup steps for fresh/incomplete projects.

    Returns high-priority setup items that guide the user through initial
    project configuration. Scored 90-99 so they always appear first.
    """
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
    elif not (cfg.root / ".rebrew" / "verify_cache.json").exists():
        add(90.0, f"Run first verify on {len(existing)} functions", "rebrew verify")

    return items


def _collect_active_functions(
    existing: dict[int, dict[str, str]],
    size_by_va: dict[int, int],
    name_by_va: dict[int, str],
    verify_entries: dict[str, "VerifyCacheEntry"],
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
    from rebrew.verify_cache import canonical_va_key

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
        except (TypeError, ValueError):
            size = size_by_va.get(va) or 0
        name = info.get("symbol") or name_by_va.get(va) or f"FUN_{va:08x}"
        filename = info.get("filename", "")

        # User-parked: intentional "don't touch" — never surface as actionable
        # work (flag sweep / GA / prove) until someone unparks with force.
        if status == "SKIP":
            continue

        va_key = f"0x{va:08x}"
        v_entry = verify_entries.get(va_key)
        v_status = v_entry.status if v_entry else None
        # Same rule as `rebrew status`: a stale metadata EXACT whose cached
        # verdict no longer matches is live work.
        status = effective_status(status, v_status)

        # Skip finished functions — except naked reconstructions: byte-exact
        # via a generated skeleton (`// SOURCE: naked`) is reproduced, not
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
        if v_status == "MISSING_SIZE":
            # Nothing was extracted (0 target bytes), so the cached delta 0 is
            # vacuous — never present it as a "0B diff" quick-win.
            v_delta = None
            v_match = None

        # If verify says it compiled and size changed, or we don't have verify, fallback to metadata parsing
        calc_delta = v_delta
        if calc_delta is None and status in ("NEAR_MATCHING", "PROVEN"):
            raw_bd = info.get("blocker_delta", "")
            try:
                calc_delta = int(raw_bd) if raw_bd else parse_byte_delta(info.get("blocker", ""))
            except ValueError:
                calc_delta = parse_byte_delta(info.get("blocker", ""))

        # VA form — CWD-independent (rebrew test resolves the VA via resolve_source_arg).
        cmd = f"rebrew test 0x{va:08x}"

        # GA mutation suggestions parsed from a near-diag-written blocker
        # (populated in the improve-match branch below).
        mutations: list[str] = []

        if v_status == "COMPILE_ERROR":
            category = CAT_COMPILE_ERROR
            desc = "Compile error — fix syntax/includes"
            score = 200.0  # High priority blocker

        elif v_status == "EXTRACT_ERROR":
            # The symbol was not found in the compiled .obj (wrong symbol,
            # optimized-away function, or a STUB marker whose decorated name
            # doesn't match).  delta is 0 (no bytes extracted), so without
            # this branch it would fall into fix-delta as a misleading
            # "0B diff" quick-win.  Surface it as a tooling/annotation issue
            # instead — a flag sweep cannot fix a missing symbol.
            category = CAT_EXTRACT_ERROR
            desc = "Symbol not found in .obj — check STUB/FUNCTION marker, symbol name, or implementation"
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
                cmd = f"rebrew near-diag 0x{va:08x}"

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
                    cmd = f"rebrew match --flag-sweep-only 0x{va:08x}"
            elif calc_delta <= 4:
                # VA form (not the reversed_dir-relative filename): commands
                # stay runnable from the project root — rebrew diff resolves
                # the VA to its source via resolve_source_arg.
                cmd = f"rebrew diff 0x{va:08x}"
            else:
                cmd = f"rebrew match --flag-sweep-only 0x{va:08x}"

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
        if ann_status in MATCHED_STATUSES or ann_status == "PROVEN":
            continue
        va_key = f"0x{va:08x}"
        cached = verify_entries.get(va_key)
        effective_status = cached.status if cached else ann_status
        if effective_status != "NEAR_MATCHING":
            continue
        # Metadata SIZE is authoritative (the real function extent — Ghidra's
        # can be stale, e.g. 340 vs the actual 752 for GetCommandPayloadSize);
        # prefer it so the size cap below uses the true extent.
        try:
            size = int(info.get("size") or 0) or size_by_va.get(va) or 0
        except (TypeError, ValueError):
            size = size_by_va.get(va) or 0
        if size > 500 or size == 0:
            continue

        filename = info.get("filename", "")
        match_pct = cached.match_percent if cached else None
        byte_delta = cached.delta if cached else None

        # A measured candidate whose bytes are far apart (e.g. 65% match on a
        # 340B function) is not provable — the prover just exhausts its
        # timeout.  Skip it; it belongs in improve-match/fix-delta instead.
        if match_pct is not None:
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
                status=effective_status,
                match_percent=match_pct,
                byte_delta=byte_delta,
            )
        )
    return items


def _load_verify_entries(cfg: ProjectConfig) -> dict[str, "VerifyCacheEntry"]:
    """Load verify cache entries, returning {} on missing/corrupt cache.

    Mirrors status.py's target guard: the cache is a single shared file whose
    ``target`` field identifies the run that wrote it.  Another target's
    entries must never drive todo's categories/deltas — a CLIENT run would
    otherwise surface SERVER's EXACTs as phantom fix-delta quick-wins.
    """
    from rebrew.verify_cache import load_verify_cache_raw

    raw = load_verify_cache_raw(cfg)
    if raw is None:
        return {}
    try:
        from rebrew.verify_cache import CACHE_VERSION, VerifyCache

        data = VerifyCache.from_dict(raw)
    except (ValueError, AttributeError, ImportError, TypeError):
        return {}
    if data.version != CACHE_VERSION:
        return {}
    # Mirrors status.py's target guard: any mismatch is rejected, including a
    # legacy cache with no `target` against a named target (the old
    # `and data.target` accepted that one, so todo's categories/deltas could be
    # driven by a cache `rebrew status` refuses to read).  A minimal config with
    # no `target_name` still accepts a target-less cache (tests, tools).
    cache_target = data.target
    cfg_target = getattr(cfg, "target_name", None)
    if cache_target != cfg_target and (cache_target or cfg_target):
        return {}
    from rebrew.verify_cache import _binary_id

    if data.binary_id and data.binary_id != _binary_id(cfg):
        return {}
    # Re-key canonically: the cache is a JSON file, so a VA may be spelled
    # "0x1000" instead of "0x00001000" (the union at `:317` already normalizes
    # with `canonical_va_key`, and every consumer looks entries up with
    # `f"0x{va:08x}"` — an unnormalized key was seen by the coverage header but
    # missed by the category/delta selection and the prove queue).
    from rebrew.verify_cache import canonical_va_key

    normalized: dict[str, VerifyCacheEntry] = {}
    for key, entry in data.entries.items():
        va = canonical_va_key(key)
        normalized[f"0x{va:08x}" if isinstance(va, int) else str(key)] = entry
    return normalized


def _inferred_module(name: str) -> str:
    """Library module for a bare function name, or "" when unclassified.

    ``FunctionEntry`` carries no module (only va/size/name/tool_name), so every
    module-aware branch here (the identify-library lane and
    ``estimate_difficulty``'s reference-source levels) infers it from the name
    with the same heuristic the FLIRT/import backends use.
    """
    from rebrew.identify_library import _infer_module

    return _infer_module(name, "")


def _collect_new_functions(
    ghidra_funcs: list["FunctionEntry"],
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

    _cached = stock_lib_cache(cfg.root, "LIBCMT.LIB")
    if _cached.exists():
        try:
            _lib_index = index_library(_cached)
        except Exception as exc:  # any archive parse failure; the filter is advisory
            console.print(
                f"[yellow]WARNING: cannot index {_cached} ({exc}); "
                "library functions are not filtered from the list[/yellow]"
            )

    _lib_probe_warned = False

    def _library_match(probe: int, probe_size: int) -> tuple[str, str] | None:
        """``(symbol, object)`` when *probe* is linked library code, else None."""
        nonlocal _lib_probe_warned
        if _lib_index is None:
            return None
        from rebrew.binary_loader import extract_raw_bytes
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
            return None
        return match_bytes(_lib_index, data)

    # Load binary for unmatchable detection
    binary_info = None
    bin_path = cfg.target_binary
    if bin_path.exists():
        with contextlib.suppress(OSError, ValueError, RuntimeError):
            from rebrew.binary_loader import load_binary

            binary_info = load_binary(bin_path)

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
        if lib is not None:
            # Not new work, but not done either: no library_*.h attributes it
            # yet, so `rebrew status` still counts it as unstarted.
            sym, obj = lib
            items.append(
                TodoItem(
                    category=CAT_IDENTIFY_LIBRARY,
                    roi_score=max(10.0, calculate_roi(size, 0.0, None) - 10.0),
                    va=va,
                    name=sym,
                    size=size,
                    filename="",
                    description=f"linked library code ({obj}): add a // LIBRARY: marker, "
                    "do not reverse",
                    command=f"rebrew lib-match --stock-lib LIBCMT.LIB --va 0x{va:08x}",
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
    ghidra_funcs: list["FunctionEntry"],
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
    binary_info = None
    bin_path = getattr(cfg, "target_binary", None)
    if bin_path and bin_path.exists():
        with contextlib.suppress(OSError, ValueError, RuntimeError):
            from rebrew.binary_loader import load_binary

            binary_info = load_binary(bin_path)
    items: list[TodoItem] = []
    for func in ghidra_funcs:
        va = func.va
        if va in existing or va in iat_set:
            continue
        size = func.size
        name = func.name or f"FUN_{va:08x}"
        if name in ignored or size < 10:
            continue
        with contextlib.suppress(TypeError, ValueError, AttributeError):
            if detect_unmatchable(va, size, binary_info, iat_set, ignored, name):
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
                command=f"rebrew flirt --va 0x{va:08x}",
            )
        )
    return items


def _caller_counts(cfg: ProjectConfig, matched_files: set[str] | None = None) -> dict[str, int]:
    """Count unresolved callers per callee name from extern declarations.

    Scans reversed sources for ``extern`` function declarations: each file
    whose own function is still unmatched counts as one unresolved caller
    of every extern callee it declares.  Best-effort (unparseable files
    skipped); returns ``{callee name: caller count}``.

    *matched_files* (relative paths, from the metadata store) are skipped: a
    caller that is already byte-matched no longer needs its callees
    implemented, so it must not add ROI or an "unblocks N caller(s)" note.
    """
    from rebrew.c_parser import find_extern_function_names
    from rebrew.sources import iter_sources
    from rebrew.utils import rel_display_path

    counts: dict[str, int] = {}
    try:
        files = list(iter_sources(cfg.reversed_dir, cfg))
    except OSError:
        return counts
    for path in files:
        if matched_files and rel_display_path(path, cfg.reversed_dir) in matched_files:
            continue
        try:
            from rebrew.utils import read_source_text

            text = read_source_text(path)[0]
        except OSError:
            continue
        for callee in find_extern_function_names(text):
            counts[callee] = counts.get(callee, 0) + 1
    return counts


def _collect_data_drift(cfg: ProjectConfig) -> list[TodoItem]:
    """Collect data symbols whose built bytes drift from the reference.

    Reads rebrew-data.toml STATUS verdicts written by ``verify --data``.
    Data VAs live in a separate address space from function VAs in practice
    (.data/.rdata vs .text), so no dedup against function items is needed.
    """
    from rebrew.data_metadata import load_data_metadata

    items: list[TodoItem] = []
    for (module, va), fields in load_data_metadata(cfg.metadata_dir).items():
        if str(fields.get("status") or "").upper() != "DRIFT":
            continue
        name = str(fields.get("name") or f"DAT_{va:08x}")
        try:
            size = int(fields.get("size") or 0)
        except (TypeError, ValueError):
            size = 0
        items.append(
            TodoItem(
                category=CAT_DATA_DRIFT,
                roi_score=50.0,
                va=va,
                name=name,
                size=size,
                filename="",
                description=f"data symbol {name} differs from reference bytes ({module} 0x{va:x})",
                command="rebrew verify --data",
                status="DRIFT",
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
        section = str(fields.get("section") or "")
        if section in ("", ".idata", ".bss"):
            return section == ".bss"
        sections: Any = cache.get("sections", missing)
        if sections is missing:
            try:
                from rebrew.binary_loader import load_binary

                sections = load_binary(cfg.target_binary).sections
            except (OSError, ValueError, KeyError, AttributeError, ImportError):
                sections = None
            cache["sections"] = sections
        if not sections:
            return False
        sec = sections.get(section)
        if not sections:
            return False
        sec = sections.get(section)
        if sec is None:
            return False
        try:
            size = int(fields.get("size") or 0)
        except (TypeError, ValueError):
            size = 0
        if size <= 0:
            try:
                from rebrew.data_layout import estimate_type_size

                size = estimate_type_size(str(fields.get("type") or ""))
            except (ImportError, ValueError):
                size = 0
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

    Import-table and BSS-resident entries are skipped, because
    ``rebrew verify --data`` cannot clear either kind, so leaving them in turns
    the lane into a list of permanent false positives.

    * Import slots (``__imp__`` / ``section = ".idata"``) are supplied by the
      linker from the import directory.  One project carried 84 of them -- every
      IAT dword -- and the image has no .idata section at all; the IAT sits at
      the head of .rdata.
    * BSS slots have no file bytes.  ``section_symbol_bytes`` skips any symbol
      whose extent runs past its section's ``raw_size`` (the zero-fill tail), so
      those VAs never reach ``verify_data_bytes``, never appear in its
      ``matched`` set, and are never written back as VERIFIED.  Symbols declared
      ``.bss`` are the obvious case; so are symbols declared ``.data`` that sit
      beyond that section's raw extent, which is the same thing spelled
      differently.  They are correct by construction -- both images zero-fill
      them -- so there is nothing to verify.

    Measured on the project that motivated this: of 207 UNCHECKED entries, all
    207 were un-clearable, and independent byte comparison found every one of
    them already correct (5 with file bytes byte-identical, 111 in the zero-fill
    tail, 84 import slots, 7 without a size).
    """
    from rebrew.data_metadata import load_data_metadata
    from rebrew.sources import target_marker

    marker = target_marker(cfg)
    in_zero_fill_tail = _zero_fill_tail_checker(cfg)
    items: list[TodoItem] = []
    for (module, va), fields in load_data_metadata(cfg.metadata_dir).items():
        # One metadata file serves every target in a unified tree, so a row's
        # module decides whether THIS target still owes work.  Without the
        # filter the server's todo listed 20 GOLDTL data symbols (0x6624a0,
        # 0x773d80, …) -- VAs no server marker can ever clear.
        if marker and module != marker:
            continue
        if str(fields.get("status") or "").upper() not in ("", "UNCHECKED"):
            continue
        name = str(fields.get("name") or "")
        section = str(fields.get("section") or "").lower()
        if name.startswith("__imp_") or section in (".idata", ".bss"):
            continue
        if in_zero_fill_tail({**fields, "va": va}):
            continue
        name = str(fields.get("name") or f"DAT_{va:08x}")
        try:
            size = int(fields.get("size") or 0)
        except (TypeError, ValueError):
            size = 0
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


def collect_all(
    cfg: ProjectConfig,
    ghidra_funcs: list["FunctionEntry"],
    existing: dict[int, dict[str, str]],
    covered_vas: dict[int, str],
    exclude_vas: set[int] | None = None,
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

    size_by_va: dict[int, int] = {f.va: f.size for f in ghidra_funcs}
    name_by_va: dict[int, str] = {f.va: f.name or "" for f in ghidra_funcs}
    verify_entries = _load_verify_entries(cfg)

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
            existing, size_by_va, name_by_va, verify_entries, _caller_counts(cfg, matched_files)
        )
    )

    # 2. Collect specialized candidates
    items.extend(_collect_prover_candidates(existing, size_by_va, verify_entries))
    items.extend(
        _collect_new_functions(ghidra_funcs, existing, covered_vas, cfg, exclude_vas or set())
    )
    items.extend(_collect_library_candidates(ghidra_funcs, existing, cfg))
    items.extend(_collect_data_drift(cfg))
    items.extend(_collect_start_data(cfg))

    # Library rows are never actions (see the docstring): drop them before
    # ranking so they cannot displace real work.
    if exclude_vas:
        items = [item for item in items if item.va not in exclude_vas]

    # Deduplicate by VA — keep only the highest-ROI item per function.
    # Setup items (va=0) are category-level, not per-function, so they skip dedup.
    best: dict[int, TodoItem] = {}
    non_va_items: list[TodoItem] = []
    for item in items:
        if item.va == 0:
            non_va_items.append(item)
            continue
        prev = best.get(item.va)
        if prev is None or item.roi_score > prev.roi_score:
            best[item.va] = item
    items = non_va_items + list(best.values())

    # Sort by ROI descending
    items.sort(key=lambda x: (-x.roi_score, x.va))
    return items


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew todo · · · · · · · · · · Top 20 actions by ROI (size + similarity to target)\n\n"
    "  rebrew todo --count 50 · · · · · Show top 50\n\n"
    "  rebrew todo -c fix-delta · · · · Filter to quick-win near-misses (<= 20B diff)\n\n"
    "  rebrew todo -c improve-match · · Filter to functions needing general work\n\n"
    "  rebrew todo --json · · · · · · · Machine-readable JSON output\n\n"
    "[bold]Categories (interleaved globally by continuous ROI score):[/bold]\n\n"
    "  setup · · · · · · · · · Project setup steps (fresh projects)\n\n"
    "  compile-error · · · · · Failed verify syntax/includes\n\n"
    "  extract-error · · · · · Symbol not found in .obj — marker/symbol/implementation issue\n\n"
    "  fix-delta · · · · · · · Known tiny byte diffs (<= 20B) — flag sweeps, padding, GA\n\n"
    "  improve-match · · · · · Functions in-progress without a known small delta\n\n"
    "  start-function · · · · · Uncovered functions, ranked by difficulty\n\n"
    "  missing-annotation · · · Found in Ghidra but missing C body or SIZE annotation\n\n"
    "  identify-library · · · · Uncovered library-origin functions\n\n"
    "  run-prover · · · · · · · Small nearly-matching functions (angr equivalence)\n\n"
    "  documented · · · · · · · IAT thunks / non-reproducible code — audit only, "
    "hidden from the default list\n\n"
    "  data-drift · · · · · · · Data symbol differs from reference bytes — run\n\n"
    "                         `rebrew verify --data`\n\n"
    "  start-data · · · · · · · Data symbol never verified — run\n\n"
    "                         `rebrew verify --data`\n\n"
    "[dim]Reads from function_structure.json, source files, and .rebrew/verify_cache.json.[/dim]"
)

app = typer.Typer(
    help="Prioritized action list: what to work on next for highest ROI.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    count: int = typer.Option(20, "--count", "-n", help="Number of items to show"),
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
    try:
        ghidra_funcs, existing, covered_vas = load_data(cfg)
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
        cfg, ghidra_funcs, existing, covered_vas, exclude_vas=library_vas | pseudo_vas
    )

    # Coverage stats (always computed for JSON, optional for terminal)
    # Overlay verify cache on annotation statuses (same logic + target guard
    # as status.py — a different target's cache must not leak into this
    # project's coverage stats).
    from rebrew.status import load_verify_statuses

    verify_statuses = load_verify_statuses(cfg)

    status_counts: dict[str, int] = {}
    documented = 0
    for va_int, info in existing.items():
        # External .lib attributions count for nothing (same rule as
        # `rebrew status`): identifications, not bodies to match.
        if va_int in library_vas:
            continue
        ann_status = info.get("status", "STUB")
        if ann_status == "STUB" and any(m in info.get("blocker", "") for m in _NON_TARGET_MARKERS):
            documented += 1
        s = effective_status(ann_status, verify_statuses.get(va_int))
        status_counts[s] = status_counts.get(s, 0) + 1
    function_vas = {va for va in existing if va not in library_vas}
    ghidra_vas = {f.va for f in ghidra_funcs}
    total_funcs = len(function_vas | (ghidra_vas - library_vas - pseudo_vas))
    covered = len(function_vas)
    exact = status_counts.get("EXACT", 0)
    reloc = status_counts.get("RELOC", 0)
    proven = status_counts.get("PROVEN", 0)
    matching = status_counts.get("NEAR_MATCHING", 0)
    stub = status_counts.get("STUB", 0)
    # Denominator mirrors `rebrew status` exactly (the two must not
    # disagree): covered FUNCTION rows plus the ghidra inventory MINUS
    # identified library code (CRT/zlib/static libs — "never reverse"
    # attributions, not pending work).  The older shapes both lied:
    # `ghidra_funcs` alone went over 100% (library rows outside the
    # inventory), and `ghidra ∪ covered` counted library attributions as
    # unfinished functions (28% where status said 42% for the same tree).
    denominator = total_funcs
    # Byte-matched only: PROVEN bytes still differ from the target.
    pct = floor_pct(exact + reloc, denominator)

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
                },
                "total_items": len(all_items),
                "count": len(display_items),
                "summary": cat_summary,
                "items": [i.to_dict() for i in display_items],
            }
        )
        return

    if stats or not display_items:
        # Show coverage stats header
        console.print(
            f"  [bold]Coverage[/bold]: {covered} covered"
            f"  ({total_funcs} in Ghidra function list)"
            f"  [green]EXACT: {exact}[/green]"
            f"  [cyan]RELOC: {reloc}[/cyan]"
            f"  [magenta]PROVEN: {proven}[/magenta]"
            f"  [yellow]NEAR_MATCHING: {matching}[/yellow]"
            f"  [dim]STUB: {stub}[/dim]"
            f"  [dim]DOCUMENTED: {documented}[/dim]"
            f"  → [bold]{pct}%[/bold] byte-matched"
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
        title=f"[bold]Rebrew TODO[/bold] — {len(all_items)} actions"
        f"  [green]{exact}E[/green] [cyan]{reloc}R[/cyan]"
        f" [magenta]{proven}P[/magenta] [yellow]{matching}M[/yellow]"
        f" [dim]{stub}S[/dim] ({pct}%)",
        subtitle=subtitle,
        border_style="blue",
    )
    console.print(panel)
    console.print(f"  Showing top {len(display_items)} of {len(all_items)} items")
    console.print(
        "  Tip: use [bold]rebrew todo -c <category>[/bold] to filter  |  [bold]rebrew todo -s[/bold] for stats"
    )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
