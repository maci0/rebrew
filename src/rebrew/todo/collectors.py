"""Action collectors for ``rebrew todo``."""

import logging
from typing import TYPE_CHECKING, Any
lazy import importlib.util
lazy import math
lazy import shlex
lazy import sys
lazy from collections.abc import Callable, Sequence
lazy from pathlib import Path

if TYPE_CHECKING:
    from rebrew.catalog import FunctionEntry
    from rebrew.config import ProjectConfig
    from rebrew.verify.cache import VerifyCacheEntry

lazy from rebrew.compiler.compile import NEAR_MATCH_THRESHOLD
lazy from rebrew.config import inventory_path_for
lazy from rebrew.metadata.functions import GA_CEILING_PREFIX
lazy from rebrew.naming import (
    detect_unmatchable,
    estimate_difficulty,
    find_neighbor_file,
    ignored_symbols,
    inside_annotated_vas,
    parse_byte_delta,
)
lazy from rebrew.utils import console as default_console
lazy from rebrew.workspace.status import (
    EARNED_STATUSES,
    FUZZY_STATUSES,
    INFRASTRUCTURE_STATUSES,
    MATCHED_STATUSES,
    STATUS_ALIASES,
    STUB_PLACEHOLDER_STATUSES,
)

from .models import (
    CAT_COMPILE_ERROR,
    CAT_DATA_DRIFT,
    CAT_DOCUMENTED,
    CAT_EXACT_ONLY,
    CAT_EXTRACT_ERROR,
    CAT_FIX_DELTA,
    CAT_IDENTIFY_LIBRARY,
    CAT_IMPROVE_MATCH,
    CAT_MISSING_ANNOTATION,
    CAT_NAKED,
    CAT_POSTLINK,
    CAT_RUN_PROVER,
    CAT_SETUP,
    CAT_START_DATA,
    CAT_START_FUNCTION,
    NON_TARGET_MARKERS,
    PROVE_MAX_DIFF_BYTES,
    PROVE_MAX_FUNC_BYTES,
    TodoItem,
    calculate_roi,
    caller_boost,
    caller_counts,
    caller_suffix,
    item_domain,
    load_verify_entries,
    rank_by_impact,
)

log = logging.getLogger(__name__)


def _default_effective_status(ann_status: str, cached: str | None) -> str:
    """Fallback overlay matching ``rebrew.status.effective_status``."""

    def _fold(value: str) -> str:
        folded = value.strip().upper()
        return STATUS_ALIASES.get(folded, folded)

    ann = _fold(ann_status or "")
    cache = _fold(cached) if cached and str(cached).strip() else None
    if ann in ("PROVEN", "SKIP"):
        return ann
    if (
        ann == "STUB"
        and cache is not None
        and (cache == "STUB" or cache in STUB_PLACEHOLDER_STATUSES)
    ):
        return ann
    return cache or ann or "STUB"


def _default_angr_available() -> bool:
    """Fallback ``find_spec`` probe matching ``rebrew.matching.prove.angr_available``."""
    if "angr" in sys.modules:
        return sys.modules["angr"] is not None
    try:
        return importlib.util.find_spec("angr") is not None
    except ImportError, ValueError:
        return False


def _default_span_is_copied(va: int, size: int, copied: list[tuple[int, int]]) -> bool:
    """Return True when ``[va, va + size)`` lies inside any copied range."""
    if size <= 0:
        return False
    end = va + size
    return any(lo <= va and end <= hi for lo, hi in copied)


def _default_find_built_image(
    root: Path, target_name: str, raw_link: Path | None = None
) -> Path | None:
    """Fallback built-image locator matching ``rebrew.status.find_built_image``."""
    if raw_link is not None:
        path = Path(raw_link)
        return path if path.is_file() else None
    direct = Path(root) / "build" / target_name
    return direct if direct.is_file() else None


def collect_setup_steps(
    cfg: ProjectConfig,
    ghidra_funcs: list[FunctionEntry],
    existing: dict[int, dict[str, str]],
) -> list[TodoItem]:
    """Detect missing project setup steps for fresh/incomplete projects.

    Returns high-priority setup items that guide the user through initial
    project configuration. Scored 90-99 so they always appear first.
    """
    from rebrew.verify.cache import cache_path_for

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


def collect_active_functions(
    existing: dict[int, dict[str, str]],
    size_by_va: dict[int, int],
    name_by_va: dict[int, str],
    verify_entries: dict[str, VerifyCacheEntry],
    caller_counts_map: dict[str, int] | None = None,
    *,
    effective_status_fn: Callable[[str, str | None], str] | None = None,
    prover_available_fn: Callable[[], bool] | None = None,
) -> list[TodoItem]:
    """Collect and score all incomplete functions currently tracked in the project.

    Compile errors, near misses, stubs, and verify failures share one pass
    and one effort heuristic; collection ranks their affected scope afterward.
    """
    from rebrew.metadata.document import canonical_va_key

    overlay_status = effective_status_fn or _default_effective_status
    probe_angr = prover_available_fn or _default_angr_available

    items: list[TodoItem] = []
    prover_available: bool | None = None  # one angr probe per call, taken on first need

    # 1. Gather all unique VAs between metadata and verify cache
    # Keep the historical lookup semantics: only the zero-padded spelling
    # ``0x%08x`` was ever consulted, so short-spelling verify rows were
    # visible in the VA union but never joined. Building an int map would
    # change results for those rows; instead precompute the padded key
    # per verify entry once.
    verify_vas: set[int] = set()
    padded: dict[int, Any] = {}
    for va_str, entry in verify_entries.items():
        va = canonical_va_key(va_str)
        if isinstance(va, int):
            verify_vas.add(va)
            if va_str == f"0x{va:08x}":
                padded[va] = entry

    all_vas = set(existing) | verify_vas

    for va in all_vas:
        info = existing.get(va, {})
        v_entry = padded.get(va)
        v_status = v_entry.status if v_entry else None
        # Same rule as `rebrew status`: a stale metadata EXACT whose cached
        # verdict no longer matches is live work. Canonical spelling, so a
        # hand-edited "skip" parks the same way SKIP does.
        status = overlay_status(info.get("status", "STUB"), v_status)

        # User-parked: intentional "don't touch" — never surface as actionable
        # work (flag sweep / GA / prove) until someone unparks with force.
        if status == "SKIP":
            continue

        # Skip finished functions — except naked reconstructions: byte-exact
        # via a generated skeleton (`source = "naked"`) is reproduced, not
        # decompiled, so it stays actionable until the real C body matches
        # (ct-recomp's NAKED_REQUIRED vs PURE_C_EXACT distinction).
        matched = status in MATCHED_STATUSES
        naked = matched and info.get("source") == "naked"
        if matched and not naked and status != "RELOC":
            continue

        # The annotated SIZE is what verify compares; the inventory extent
        # can carry alignment padding or run into a missed neighbour.
        try:
            size = int(info.get("size") or 0) or size_by_va.get(va) or 0
        except TypeError, ValueError:
            size = size_by_va.get(va) or 0
        name = info.get("symbol") or name_by_va.get(va) or f"FUN_{va:08x}"
        filename = info.get("filename", "")

        if matched:
            if naked:
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
            else:
                # Matched only after masking linker-filled addresses, so the
                # bytes are not identical straight out of the toolchain.  A
                # project at 100% byte-matched is still this far from an
                # identical build, so it stays actionable.
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
        blocker = info.get("blocker", "")
        if status == "STUB" and any(m in blocker for m in NON_TARGET_MARKERS):
            items.append(
                TodoItem(
                    category=CAT_DOCUMENTED,
                    roi_score=-1.0,  # never outranks actionable work
                    va=va,
                    name=name,
                    size=size,
                    filename=filename,
                    description=f"Documented non-target — {blocker[:60]}",
                    command="",
                    status=status,
                    blocker=blocker,
                )
            )
            continue

        v_match = v_entry.match_percent if v_entry else None
        v_delta = v_entry.delta if v_entry else None
        unmeasured = v_status in (*INFRASTRUCTURE_STATUSES, "MISSING_SIZE")
        if unmeasured:
            # Failed runs carry default metrics, not a byte comparison.
            v_delta = None
            v_match = None

        # If verify says it compiled and size changed, or we don't have verify, fallback to metadata parsing
        calc_delta = v_delta
        if calc_delta is None and status in FUZZY_STATUSES and not unmeasured:
            raw_bd = info.get("blocker_delta", "")
            try:
                calc_delta = int(raw_bd) if raw_bd else parse_byte_delta(blocker)
            except ValueError:
                calc_delta = parse_byte_delta(blocker)

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
            # No SIZE anywhere (binding + metadata): rebrew test refuses the
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
            if blocker:
                desc += f" — Blocked: {blocker[:50]}"
            score = calculate_roi(size, v_match, calc_delta)
            cmd = f"rebrew diff 0x{va:08x}"

        elif blocker.startswith(GA_CEILING_PREFIX):
            # The GA exhausted on a register-only delta — byte-exact is not
            # reproducible from portable C, so no flag sweep / GA item helps.
            # The prover lane needs angr: without it, there is nothing to
            # run, so classify as improve-match with a match/near-diag
            # command instead of routing to a prover that cannot execute.
            if prover_available is None:
                prover_available = probe_angr()
            if prover_available:
                category = CAT_RUN_PROVER
                desc = "GA ceiling (register-only delta) — prove semantic equivalence for PROVEN"
                score = calculate_roi(size, v_match, calc_delta) + 10.0
                cmd = f"rebrew prove 0x{va:08x}"
            else:
                category = CAT_IMPROVE_MATCH
                desc = (
                    "GA ceiling (register-only delta) — angr unavailable, "
                    "no prover to run; try match variants or diagnose near"
                )
                score = calculate_roi(size, v_match, calc_delta)
                cmd = f"rebrew diagnose near 0x{va:08x}"

        elif calc_delta is not None and calc_delta <= 20:
            category = CAT_FIX_DELTA
            desc = f"{calc_delta}B diff — try flag sweep, GA, or padding adjustments"
            score = calculate_roi(size, v_match, calc_delta)
            # A near-diag STRUCTURAL verdict means the diff is control-flow
            # layout, not a flag/padding quick-win, so demote it rather than
            # offering it as one.
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

            if blocker:
                desc += f" — Blocked: {blocker[:50]}"
                # rebrew diagnose near --fix-blocker writes the suggested GA operators
                # after "— try: "; expose them as structured data (and a
                # short terminal hint) so todo consumers can act without
                # re-running diagnose near.
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
                roi_score=score + caller_boost(name, caller_counts_map),
                va=va,
                name=name,
                size=size,
                filename=filename,
                description=caller_suffix(desc, name, caller_counts_map),
                command=cmd,
                byte_delta=calc_delta,
                status=status,
                match_percent=v_match,
                mutations=mutations,
                blocker=blocker or "",
            )
        )

    return items


def collect_prover_candidates(
    existing: dict[int, dict[str, str]],
    size_by_va: dict[int, int],
    verify_entries: dict[str, Any],
    *,
    effective_status_fn: Callable[[str, str | None], str] | None = None,
    prover_available_fn: Callable[[], bool] | None = None,
) -> list[TodoItem]:
    """Collect functions suitable for symbolic equivalence proving."""
    # find_spec probe; never import angr here (import costs ~0.5 s).
    probe_angr = prover_available_fn or _default_angr_available
    overlay_status = effective_status_fn or _default_effective_status

    has_angr = probe_angr()
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
        reported = overlay_status(ann_status, cached.status if cached else None)
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
        # treated as the unknown it is, the way status.py / coverage/toml.py
        # treat it.
        size = max(size, 0)
        if size > PROVE_MAX_FUNC_BYTES or size == 0:
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
            # "measured, and not a match".  Non-finite reads as unmeasured
            # (0.0): max/min with NaN returns the 100.0 bound on Python 3.13+,
            # queuing a corrupt row as a perfect match.
            if not math.isfinite(match_pct):
                match_pct = 0.0
            match_pct = max(0.0, min(100.0, match_pct))
            est_diff = size * (100.0 - match_pct) / 100.0
            if est_diff > PROVE_MAX_DIFF_BYTES:
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


def load_target_binary(cfg: ProjectConfig, *, out_console: Any = None) -> Any | None:
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

    target_console = default_console if out_console is None else out_console
    try:
        return load_binary(Path(bin_path))
    except (OSError, ValueError, RuntimeError) as exc:
        log.warning("cannot parse %s: %s", bin_path, exc, exc_info=True)
        target_console.print(
            f"[yellow]WARNING: cannot parse {bin_path} ({exc}); "
            "unmatchable detection is disabled[/yellow]"
        )
        return None


def inferred_module(
    name: str,
    *,
    infer_module_fn: Callable[[str, str], str] | None = None,
) -> str:
    """Library module for a bare function name, or "" when unclassified.

    ``FunctionEntry`` carries no module (only va/size/name/tool_name), so every
    module-aware branch here (the identify-library lane and
    ``estimate_difficulty``'s reference-source levels) infers it from the name
    with the same heuristic the FLIRT/import backends use.
    """
    if infer_module_fn is None:
        return ""
    return infer_module_fn(name, "")


def collect_new_functions(
    ghidra_funcs: list[FunctionEntry],
    existing: dict[int, dict[str, str]],
    covered_vas: dict[int, str],
    cfg: ProjectConfig,
    skip_vas: frozenset[int] | set[int] = frozenset(),
    *,
    unmatchable_detector: Callable[..., str | None] | None = None,
    infer_module_fn: Callable[[str, str], str] | None = None,
    stock_lib_fns: tuple[Any, Any, Any, Any] | None = None,
    out_console: Any = None,
) -> list[TodoItem]:
    """Collect uncovered functions as start-function candidates.

    *skip_vas* are never candidates: attributed library code and pseudo-
    functions found against rows the caller has already removed from
    *existing*.  Skipping them first keeps them out of the 50-item cap.
    """
    target_console = default_console if out_console is None else out_console
    unmatchable_fn = unmatchable_detector or detect_unmatchable
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
    # anyway.  Identify it before reversing anything (68 functions were once
    # reversed by mistake and matched for weeks).
    # Recommending it as new work is therefore actively harmful, and it was
    # happening: all three surviving start-function actions on guild-rebrew
    # were LIBCMT (`_ftell`, `_strncnt`, `___ld12mul`).  Reuse lib_match's own
    # index so `todo` and `library match` cannot disagree.
    lib_index = None
    match_bytes_fn = None
    if stock_lib_fns is not None:
        stock_lib_cache, stock_lib_valid, index_library, match_bytes_fn = stock_lib_fns
        # Only this project's profile: the archive is another toolchain's code, so
        # indexing one extracted for a different profile would filter this list
        # against library bodies the build never links.
        profile = str(getattr(cfg, "compiler_profile", "") or "")
        cached = stock_lib_cache(cfg.root, "LIBCMT.LIB", profile) if profile else None
        if cached is not None and stock_lib_valid(cached):
            try:
                lib_index = index_library(cached)
            except Exception as exc:  # any archive parse failure; the filter is advisory
                target_console.print(
                    f"[yellow]WARNING: cannot index {cached} ({exc}); "
                    "library functions are not filtered from the list[/yellow]"
                )
        elif cached is not None and cached.exists():
            target_console.print(
                f"[yellow]WARNING: ignoring incomplete stock archive {cached}; "
                "run `rebrew library match --stock-lib LIBCMT.LIB` to refresh it[/yellow]"
            )

    lib_probe_warned = False

    def _library_match(probe: int, probe_size: int) -> list[tuple[str, str]]:
        """Candidate symbols when *probe* is linked library code."""
        nonlocal lib_probe_warned
        if lib_index is None or match_bytes_fn is None:
            return []
        from rebrew.formats.binary_loader import extract_raw_bytes

        try:
            data = extract_raw_bytes(cfg.target_binary, probe, probe_size or 64)
        except (OSError, ValueError, RuntimeError) as exc:
            # An unreadable target disables the filter for every probe; say so
            # once instead of recommending library code as new work silently.
            if not lib_probe_warned:
                lib_probe_warned = True
                target_console.print(
                    f"[yellow]WARNING: cannot read {cfg.target_binary} at 0x{probe:08x} "
                    f"({exc}); library functions may not be filtered[/yellow]"
                )
            return []
        return list(match_bytes_fn(lib_index, data))

    # Load binary for unmatchable detection
    binary_info = load_target_binary(cfg, out_console=target_console)

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

        reason = unmatchable_fn(
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
            size,
            name,
            inferred_module(name, infer_module_fn=infer_module_fn),
            ignored=ignored,
            cfg=cfg,
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


def collect_library_candidates(
    ghidra_funcs: list[FunctionEntry],
    existing: dict[int, dict[str, str]],
    cfg: ProjectConfig,
    *,
    unmatchable_detector: Callable[..., str | None] | None = None,
    infer_module_fn: Callable[[str, str], str] | None = None,
    out_console: Any = None,
) -> list[TodoItem]:
    """Collect uncovered functions with library module for identification."""
    unmatchable_fn = unmatchable_detector or detect_unmatchable
    lib_modules = set(cfg.library_modules) if cfg.library_modules else {"ZLIB", "MSVCRT"}
    # Same non-targets the start-function lane skips: an IAT thunk or ASM
    # builtin is import glue / compiler support, not a library function to
    # identify, and a sub-10B row is not actionable.
    ignored: set[str] = set(getattr(cfg, "ignored_symbols", None) or [])
    iat_set: set[int] = set(getattr(cfg, "iat_thunks", None) or [])
    binary_info = load_target_binary(cfg, out_console=out_console)
    items: list[TodoItem] = []
    for func in ghidra_funcs:
        va = func.va
        if va in existing or va in iat_set:
            continue
        size = func.size
        name = func.name or f"FUN_{va:08x}"
        if name in ignored or size < 10:
            continue
        # FunctionEntry carries no module (only va/size/name/tool_name), so the
        # module is inferred from the name; an unclassifiable name infers "" and
        # is skipped.  Infer before the byte probe so only this target's library
        # modules are disassembled; ordinary game code is not scanned to be
        # discarded one step later.
        module = inferred_module(name, infer_module_fn=infer_module_fn)
        if not module or module not in lib_modules:
            continue
        # A probe failure must not read as "matchable work": the function is
        # then recommended as a candidate, which is exactly the wrong answer
        # for a thunk or library stub the probe could not classify.
        try:
            unmatchable = unmatchable_fn(va, size, binary_info, iat_set, ignored, name)
        except (TypeError, ValueError, AttributeError) as exc:
            log.warning(
                "unmatchable probe failed for %s (0x%08x): %s", name, va, exc, exc_info=True
            )
            continue
        if unmatchable:
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


def collect_data_drift(
    cfg: ProjectConfig,
    data_entries: dict[tuple[str, int], dict[str, Any]] | None = None,
    *,
    copied_ranges_fn: Callable[[ProjectConfig], list[tuple[int, int]]] | None = None,
    span_is_copied_fn: Callable[[int, int, list[tuple[int, int]]], bool] | None = None,
) -> list[TodoItem]:
    """Collect data symbols whose built bytes drift from the reference.

    Reads rebrew-data.toml STATUS verdicts written by ``verify --data``.
    Data VAs live in a separate address space from function VAs in practice
    (.data/.rdata vs .text), so no dedup against function items is needed.

    *data_entries* is the shared read-only table from
    :func:`rebrew.metadata.data.load_data_metadata`; the caller that also
    collects start-data loads it once for both lanes.
    """
    from rebrew.data.layout import data_symbol_size
    from rebrew.metadata.data import load_data_metadata, module_visible_to_target

    items: list[TodoItem] = []
    copied = copied_ranges_fn(cfg) if copied_ranges_fn is not None else []
    is_copied = span_is_copied_fn or _default_span_is_copied
    if data_entries is None:
        data_entries = load_data_metadata(cfg.metadata_dir, deepcopy=False)
    for (module, va), fields in data_entries.items():
        if not module_visible_to_target(module, cfg):
            continue
        verdict = str(fields.get("status") or "").upper()
        if verdict not in ("DRIFT", "DISPLACED"):
            continue
        name = str(fields.get("name") or f"DAT_{va:08x}")
        size = data_symbol_size(fields, arch=getattr(cfg, "arch", "x86_32"))
        if is_copied(va, size, copied):
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


def zero_fill_tail_checker(cfg: ProjectConfig) -> Callable[[dict[str, Any]], bool]:
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
        from rebrew.data.layout import data_symbol_size

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
        address = fields.get("va")
        if address is None:
            return False
        offset = int(address) - int(sec.va)
        if offset < 0 or offset >= int(sec.size or sec.raw_size):
            return False
        return bool(offset + size > int(sec.raw_size))

    return in_tail


def collect_start_data(
    cfg: ProjectConfig,
    data_entries: dict[tuple[str, int], dict[str, Any]] | None = None,
) -> list[TodoItem]:
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
    from rebrew.data.layout import data_symbol_size
    from rebrew.metadata.data import (
        data_status_bucket,
        load_data_metadata,
        module_visible_to_target,
    )

    in_zero_fill_tail = zero_fill_tail_checker(cfg)
    items: list[TodoItem] = []
    if data_entries is None:
        data_entries = load_data_metadata(cfg.metadata_dir, deepcopy=False)
    for (module, va), fields in data_entries.items():
        # One metadata file serves every target in a unified tree, so a row's
        # module decides whether THIS target still owes work.  Without the
        # filter the server's todo listed 20 GOLDTL data symbols (0x6624a0,
        # 0x773d80, …): VAs no server row can ever clear. Library modules
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


def text_layout_differs(raw_info: Any, built_info: Any) -> bool:
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


def postlink_rewritten_checker(
    cfg: ProjectConfig,
    *,
    find_built_image_fn: Callable[[Path, str, Path | None], Path | None] | None = None,
) -> Callable[[int, int], bool]:
    """Return a predicate: did a postlink fixer rewrite this span's bytes?

    True when the shipped image's bytes at ``[va, va + size)`` differ from the
    pre-postlink ``raw_link`` image, i.e. the deliverable carries bytes the
    compiler and linker did not emit.  Both images are read and parsed once, on
    the first call that needs them; any failure degrades to "not rewritten" —
    the conservative answer, since claiming a rewrite that did not happen would
    invent work.
    """
    from rebrew.formats.binary_loader import load_binary, va_to_file_offset

    find_image = find_built_image_fn or _default_find_built_image
    cache: dict[str, Any] = {}
    missing = object()

    def rewritten(va: int, size: int) -> bool:
        if size <= 0:
            return False
        images = cache.get("images", missing)
        if images is missing:
            images = None
            raw = getattr(cfg, "raw_link", None)
            built = find_image(cfg.root, cfg.target_name, None)
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
        if text_layout_differs(raw_info, built_info):
            return False
        return bool(
            raw_bytes[raw_off : raw_off + size] != built_bytes[built_off : built_off + size]
        )

    return rewritten


def collect_postlink_rewritten(
    cfg: ProjectConfig,
    existing: dict[int, dict[str, str]],
    size_by_va: dict[int, int],
    *,
    find_built_image_fn: Callable[[Path, str, Path | None], Path | None] | None = None,
) -> list[TodoItem]:
    """Collect functions whose shipped bytes a postlink fixer produced.

    ``rebrew build postlink`` rewrites ``.text`` IAT slot operands, absolute data
    operands, and call/jump targets, so a function can be byte-matched in the
    deliverable while the toolchain never emitted those bytes.  Only detectable
    when the project configures ``raw_link``; without it the lane is empty
    rather than guessed.
    """
    rewritten = postlink_rewritten_checker(cfg, find_built_image_fn=find_built_image_fn)
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


def collect_missing_bindings(
    cfg: ProjectConfig, existing: dict[int, dict[str, str]]
) -> list[TodoItem]:
    """Keep missing managed definitions visible without claiming source coverage."""
    from rebrew.c_syntax.parser import function_signatures
    from rebrew.config import target_module
    from rebrew.metadata.bindings import derive_c_symbol
    from rebrew.metadata.functions import load_metadata
    from rebrew.utils import preset_module_key, read_source_text, rel_display_path

    target_module_name = preset_module_key(target_module(cfg) or "")
    items: list[TodoItem] = []
    # Derived symbols for one existing file stay fixed for this collect.
    symbols_by_path: dict[Path, set[str]] = {}
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
            symbols = symbols_by_path.get(path)
            if symbols is None:
                definitions = function_signatures(read_source_text(path)[0])
                symbols = {derive_c_symbol(name, proto) for name, proto in definitions.items()}
                symbols_by_path[path] = symbols
            symbol = str(row.get("symbol") or "")
            if symbol in symbols:
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
    verify_entries_loader: Callable[[ProjectConfig], dict[str, VerifyCacheEntry]] | None = None,
    unmatchable_detector: Callable[..., str | None] | None = None,
    effective_status_fn: Callable[[str, str | None], str] | None = None,
    prover_available_fn: Callable[[], bool] | None = None,
    infer_module_fn: Callable[[str, str], str] | None = None,
    stock_lib_fns: tuple[Any, Any, Any, Any] | None = None,
    copied_ranges_fn: Callable[[ProjectConfig], list[tuple[int, int]]] | None = None,
    span_is_copied_fn: Callable[[int, int, list[tuple[int, int]]], bool] | None = None,
    find_built_image_fn: Callable[[Path, str, Path | None], Path | None] | None = None,
    out_console: Any = None,
) -> list[TodoItem]:
    """Collect and rank actions by affected bytes, using effort to break ties.

    *exclude_vas* holds VA rows that are linked library code (``external_vas``:
    ``LIBRARY`` rows plus configured external modules).  They are not work:
    the bytes come from the archive, so neither "improve this match" nor
    "start this function" is a runnable action — the server's ``library_msvc.h``
    rows alone filled 11 of the top 20 slots before this filter.
    """
    items: list[TodoItem] = []

    # Setup steps for fresh/incomplete projects (scored highest)
    items.extend(collect_setup_steps(cfg, ghidra_funcs, existing))
    items.extend(collect_missing_bindings(cfg, existing))

    size_by_va: dict[int, int] = {f.va: f.size for f in ghidra_funcs}
    name_by_va: dict[int, str] = {f.va: f.name or "" for f in ghidra_funcs}
    load_entries = verify_entries_loader or load_verify_entries
    verify_entries = load_entries(cfg)

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
        collect_active_functions(
            existing,
            size_by_va,
            name_by_va,
            verify_entries,
            caller_counts(cfg, matched_files, scanned=scanned),
            effective_status_fn=effective_status_fn,
            prover_available_fn=prover_available_fn,
        )
    )

    # 2. Collect specialized candidates
    items.extend(
        collect_prover_candidates(
            existing,
            size_by_va,
            verify_entries,
            effective_status_fn=effective_status_fn,
            prover_available_fn=prover_available_fn,
        )
    )
    items.extend(
        collect_new_functions(
            ghidra_funcs,
            existing,
            covered_vas,
            cfg,
            exclude_vas or set(),
            unmatchable_detector=unmatchable_detector,
            infer_module_fn=infer_module_fn,
            stock_lib_fns=stock_lib_fns,
            out_console=out_console,
        )
    )
    items.extend(
        collect_library_candidates(
            ghidra_funcs,
            existing,
            cfg,
            unmatchable_detector=unmatchable_detector,
            infer_module_fn=infer_module_fn,
            out_console=out_console,
        )
    )
    items.extend(
        collect_postlink_rewritten(
            cfg,
            existing,
            size_by_va,
            find_built_image_fn=find_built_image_fn,
        )
    )
    # Both data lanes read the same store; one read-only load serves them.
    from rebrew.metadata.data import load_data_metadata

    data_entries = load_data_metadata(cfg.metadata_dir, deepcopy=False)
    items.extend(
        collect_data_drift(
            cfg,
            data_entries,
            copied_ranges_fn=copied_ranges_fn,
            span_is_copied_fn=span_is_copied_fn,
        )
    )
    items.extend(collect_start_data(cfg, data_entries))

    # Library rows are never actions (see the docstring): drop them before
    # ranking so they cannot displace real work.
    if exclude_vas:
        items = [item for item in items if item.category == CAT_SETUP or item.va not in exclude_vas]

    # One action per code address, and one per data address. Setup items
    # are category-level, so they skip dedup. A function and a data
    # symbol can share an address; folding them into one VA dropped the
    # function, because exact-only scores 0 and start-data scores 10.
    best: dict[tuple[str, int], TodoItem] = {}
    non_va_items: list[TodoItem] = []
    for item in items:
        if item.category == CAT_SETUP:
            non_va_items.append(item)
            continue
        key = (item_domain(item), item.va)
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

    return rank_by_impact(items)


__all__ = [
    "collect_active_functions",
    "collect_all",
    "collect_data_drift",
    "collect_library_candidates",
    "collect_missing_bindings",
    "collect_new_functions",
    "collect_postlink_rewritten",
    "collect_prover_candidates",
    "collect_setup_steps",
    "collect_start_data",
    "inferred_module",
    "load_target_binary",
    "postlink_rewritten_checker",
    "text_layout_differs",
    "zero_fill_tail_checker",
]
