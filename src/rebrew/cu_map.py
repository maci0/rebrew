"""cu_map.py – Compilation unit boundary inference.

MSVC6 linker places functions from the same .obj (translation unit)
contiguously in .text with only alignment padding between them.  This module
exploits that deterministic layout plus binary-level call analysis to infer
which functions were compiled together.

Algorithm
---------
**Pass 1 – Contiguity clustering**: sort functions by VA, walk consecutive
pairs, classify inter-function gaps (padding, jump table, small/large
non-padding) and split at large gaps.

**Pass 2 – Call-graph refinement**: disassemble each function, extract call
targets, and boost confidence for clusters containing functions that are only
called from within the same cluster (static-function signal).

Optional weighted signals
-------------------------
Two further signals are available but **off by default**; a caller that
supplies one is asking for its evidence and its cost:

- ``jump_table_alignment`` (int): successive jump tables inside one object
  file sit at a constant alignment remainder; a change implies a new object
  file.  This is splat's ``vram_diff % 8`` heuristic, whose modulus is a
  PSX/GCC assumption.  The alignment is a required parameter rather than a
  guessed default, because measurement on the MSVC targets here falsifies
  the premise: in smygb-rebrew (MSVC 6.0, ``/O1``) all 22 detected tables are
  4-byte aligned (the pointer width, and the only invariant that holds) while
  the ``% 8`` remainder is ``{0, 4}`` and ``% 16`` takes every value, and a
  single function's own six tables change their ``% 8`` remainder five times.
  So ``alignment=4`` never fires (no signal), and 8 or 16 fire on noise: on
  smygb-rebrew the modulus 8 signal splits one cluster off at 0x40f2f0, and
  nothing in the binary establishes that boundary.  Treat the signal as a
  hypothesis generator, not evidence.
- ``single_ref_data`` (bool): a ``.rdata``/``.data`` object referenced by
  exactly one function belongs to that function's compilation unit.  Two
  consecutive functions whose exclusively-owned objects run contiguously in
  the data section are therefore likely one object file, which vetoes a
  contiguity split and raises confidence.  It only ever merges: a bond never
  creates a boundary, so it cannot contradict the contiguity pass.

Both disassemble more than the default path does (one per-function
disassembly for the data signal, one per-function scan for tables in the
alignment signal), so neither runs unless asked for.
"""

from dataclasses import dataclass
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from rebrew.analysis import data_references, section_range
from rebrew.binary_loader import BinaryInfo, extract_bytes_at_va, load_binary
from rebrew.catalog import (
    RegistryEntry,
    build_function_registry,
    is_jump_table,
    parse_function_list,
)
from rebrew.cli import TargetOption, error_exit, json_print, require_config
from rebrew.config import FUNCTION_STRUCTURE_JSON, ProjectConfig

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Optional-signal constants
# ---------------------------------------------------------------------------

#: Window (bytes) tested at each 4-byte step of a function's extent when
#: locating jump-table starts, capped to the function's own size.
_JUMP_TABLE_WINDOW = 32

#: Smallest window that can hold the two pointers
#: :func:`rebrew.catalog.is_jump_table` requires.
_JUMP_TABLE_MIN_WINDOW = 8

#: Confidence added when a cluster is internally consistent with the
#: jump-table alignment signal (no discontinuity inside it).
JUMP_TABLE_ALIGN_BOOST = 0.05

#: Confidence added when a cluster contains a single-reference-data bond.
SINGLE_REF_DATA_BOOST = 0.05

#: Maximum byte distance between the last exclusively-owned data object of
#: one function and the first of the next for the pair to count as bonded.
SINGLE_REF_DATA_MAX_GAP = 16

#: Sections whose objects participate in the single-reference-data signal.
_DATA_SECTIONS = (".rdata", ".data", ".rodata")

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class TUCluster:
    """A group of functions inferred to belong to the same translation unit.

    Attributes:
        cluster_id: Unique cluster identifier.
        functions: Sorted list of function VAs in this cluster.
        gap_classes: Classification of each inter-function gap
            (``'padding'``, ``'jump_table'``, ``'small_nonpadding'``,
            ``'large_nonpadding'``, ``'unknown'`` — bytes unavailable).
        confidence: Confidence score 0.0–1.0; higher means stronger TU evidence.
        evidence: Human-readable justifications for the clustering decision.
    """

    cluster_id: int
    functions: list[int]
    gap_classes: list[str]
    confidence: float
    evidence: list[str]


# ---------------------------------------------------------------------------
# Gap analysis (pure, testable)
# ---------------------------------------------------------------------------


def _classify_gap(
    data: bytes,
    text_va: int,
    text_size: int,
    padding_bytes: tuple[int, ...] = (0xCC, 0x90),
) -> str:
    """Classify a gap between two consecutive functions.

    Returns one of: ``"padding"``, ``"jump_table"``, ``"small_nonpadding"``,
    ``"large_nonpadding"``.
    """
    if len(data) == 0:
        return "padding"

    # All padding bytes?
    if all(b in padding_bytes for b in data):
        return "padding"

    # Jump table?
    if is_jump_table(data, text_va, text_size):
        return "jump_table"

    # Size-based threshold
    if len(data) <= 64:
        return "small_nonpadding"
    return "large_nonpadding"


def _contiguity_score(gap_classes: list[str]) -> tuple[float, list[str]]:
    """Compute a confidence score from gap classifications.

    Returns ``(score, evidence)`` where score is in [0.40, 1.0].
    ``"unknown"`` gaps (bytes unavailable) carry no signal either way: no
    penalty, no confidence.
    """
    if not gap_classes:
        return 1.0, ["single function"]

    score = 1.0
    evidence: list[str] = []
    n_padding = 0
    n_jt = 0
    n_small = 0
    n_unknown = 0
    n_bond = 0

    for gc in gap_classes:
        if gc == "padding":
            n_padding += 1
        elif gc == "jump_table":
            score -= 0.05
            n_jt += 1
        elif gc == "small_nonpadding":
            score -= 0.10
            n_small += 1
        elif gc == "unknown":
            n_unknown += 1
        elif gc == "data_bond":
            # Single-reference-data evidence (optional signal): a gap the
            # contiguity pass would have split on, held together by the data
            # layout.  Neutral here; its boost is applied by the caller.
            n_bond += 1

    if n_padding == len(gap_classes):
        evidence.append("all gaps are padding")
    else:
        parts = []
        if n_padding:
            parts.append(f"{n_padding} padding")
        if n_jt:
            parts.append(f"{n_jt} jump table")
        if n_small:
            parts.append(f"{n_small} small non-padding")
        if n_unknown:
            parts.append(f"{n_unknown} unknown")
        if n_bond:
            parts.append(f"{n_bond} single-reference data bond")
        evidence.append("gaps: " + ", ".join(parts))

    score = max(score, 0.40)
    return round(score, 2), evidence


# ---------------------------------------------------------------------------
# Call scanning
# ---------------------------------------------------------------------------


def _scan_call_targets(
    info: BinaryInfo,
    registry: dict[int, RegistryEntry],
    cfg: ProjectConfig | None,
) -> dict[int, set[int]]:
    """Disassemble each function and extract direct CALL targets.

    Returns ``{caller_va: {callee_vas}}`` for callees present in the registry.
    """
    try:
        from capstone import CS_ARCH_X86, CS_MODE_32, Cs
    except ImportError:
        return {}

    arch = cfg.capstone_arch if cfg else CS_ARCH_X86
    mode = cfg.capstone_mode if cfg else CS_MODE_32
    md = Cs(arch, mode)

    registry_vas = set(registry.keys())
    call_map: dict[int, set[int]] = {}

    for va, entry in registry.items():
        size = int(entry.get("canonical_size", 0))
        if size <= 0:
            continue
        code = extract_bytes_at_va(info, va, size, trim_padding=False)
        if not code:
            continue

        targets: set[int] = set()
        for insn in md.disasm(code, va):
            if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
                try:
                    target = int(insn.op_str, 16)
                except ValueError:
                    continue
                if target in registry_vas and target != va:
                    targets.add(target)
        if targets:
            call_map[va] = targets

    return call_map


def _invert_call_map(call_map: dict[int, set[int]]) -> dict[int, set[int]]:
    """Build inverse mapping: ``{callee_va: {caller_vas}}``."""
    caller_map: dict[int, set[int]] = {}
    for caller, callees in call_map.items():
        for callee in callees:
            caller_map.setdefault(callee, set()).add(caller)
    return caller_map


def _call_graph_boost(
    cluster_vas: set[int],
    caller_map: dict[int, set[int]],
) -> tuple[float, list[str]]:
    """Compute confidence boost from static-function signals.

    A function called **only** by functions within the same cluster is likely
    a static (file-scope) function — strong evidence of same-TU membership.

    Returns ``(boost, evidence)`` with boost capped at 0.10.
    """
    static_signals = 0
    for va in cluster_vas:
        callers = caller_map.get(va)
        if callers and callers.issubset(cluster_vas):
            static_signals += 1

    boost = min(static_signals * 0.05, 0.10)
    evidence: list[str] = []
    if static_signals:
        evidence.append(
            f"{static_signals} static-function signal{'s' if static_signals != 1 else ''}"
        )
    return boost, evidence


# ---------------------------------------------------------------------------
# Optional signals
# ---------------------------------------------------------------------------


def _validate_alignment(alignment: int) -> int:
    """Validate a jump-table alignment modulus (a positive power of two).

    An alignment is a power of two by definition; ``0`` would divide by zero
    and a non-power-of-two is a caller mistake, so both fail loud instead of
    producing a meaningless remainder comparison.
    """
    if alignment < 1 or (alignment & (alignment - 1)) != 0:
        raise ValueError(f"jump_table_alignment must be a positive power of two, got {alignment}")
    return alignment


def _find_jump_tables(
    info: BinaryInfo,
    functions: list[tuple[int, int]],
    arch: str = "x86_32",
) -> list[int]:
    """VAs of jump-table starts found inside *functions* (``(va, size)`` pairs).

    A jump table is an aligned run of at least two pointers into ``.text``
    (the same test :func:`rebrew.catalog.is_jump_table` applies to gaps).  It
    is located by testing a :data:`_JUMP_TABLE_WINDOW`-byte window (capped to
    the function's size) at every 4-byte-ALIGNED absolute address of each
    function's extent and keeping the first offset of each run of consecutive
    detections: inside a table every step starts on an entry, so one table
    contributes one run.  Because :func:`~rebrew.catalog.is_jump_table` skips
    a leading NOP/``INT3`` alignment prefix, a reported start is the first
    skippable byte before the table when one is present.  Best-effort: a code
    region whose bytes happen to be pointer-shaped is reported as a table.

    Returns the starts in ascending order.
    """
    tables: list[int] = []
    for va, size in functions:
        code = extract_bytes_at_va(info, va, size, trim_padding=False)
        if code is None or len(code) < _JUMP_TABLE_MIN_WINDOW:
            continue
        # Tables hold 32-bit pointers, so candidate starts are 4-byte aligned
        # in absolute VA even when the function itself is not.
        run_start: int | None = None
        for offset in range((-va) % 4, len(code) - _JUMP_TABLE_MIN_WINDOW + 1, 4):
            tail = min(_JUMP_TABLE_WINDOW, len(code) - offset)
            window = code[offset : offset + tail - tail % 4]
            if is_jump_table(window, info.text_va, info.text_size, arch):
                if run_start is None:
                    run_start = offset
            elif run_start is not None:
                tables.append(va + run_start)
                run_start = None
        if run_start is not None:
            tables.append(va + run_start)
    return sorted(set(tables))


def _owner_of(va: int, functions: list[tuple[int, int]]) -> int | None:
    """VA of the function whose extent contains *va*, or None.

    *functions* must be sorted by VA (the eligible list is); the search is a
    linear walk bounded by the caller's list size.
    """
    for start, size in functions:
        if start <= va < start + size:
            return start
    return None


def _jump_table_split_vas(
    tables: list[int],
    alignment: int,
    functions: list[tuple[int, int]],
) -> dict[int, str]:
    """Function VAs that must start a new object file, with the evidence.

    Successive jump tables emitted by one compiler invocation were assumed to
    share the same alignment remainder, so a change implies the tables came
    from different object files.  Only the FIRST table of each owning function
    is compared: two tables of one function are in one object file by
    construction, so a remainder change between them cannot indicate a
    boundary (measured on smygb-rebrew: a single MSVC 6 function's own six
    tables change their ``% 8`` remainder five times).
    """
    first_by_owner: dict[int, int] = {}
    for table in tables:
        owner = _owner_of(table, functions)
        if owner is not None:
            first_by_owner.setdefault(owner, table)

    ordered = sorted(first_by_owner.items())
    splits: dict[int, str] = {}
    for (prev_owner, prev), (owner, curr) in zip(ordered, ordered[1:], strict=False):
        if prev % alignment == curr % alignment:
            continue
        splits[owner] = (
            f"jump-table alignment change: 0x{prev:08x} (function 0x{prev_owner:08x}, "
            f"%{alignment}={prev % alignment}) -> 0x{curr:08x} "
            f"(%{alignment}={curr % alignment})"
        )
    return splits


def _data_ranges(info: BinaryInfo) -> list[tuple[str, int, int]]:
    """``(name, start_va, size)`` of the data sections a reference can target."""
    ranges: list[tuple[str, int, int]] = []
    for name in _DATA_SECTIONS:
        rng = section_range(info, name)
        if rng is not None:
            ranges.append((name, rng[0], rng[1]))
    if not ranges:
        # 16-bit NE: the data lives in non-code segments, not named sections.
        for seg in getattr(info, "ne_segments", []) or []:
            if not getattr(seg, "is_code", True):
                ranges.append((f"SEG{seg.index}", seg.base_va, seg.length))
    return ranges


def _exclusive_data_owners(
    info: BinaryInfo,
    functions: list[tuple[int, int]],
) -> dict[int, list[int]]:
    """``{function_va: [data_va, ...]}`` for objects it alone references.

    Each function's own bytes are decoded (:func:`rebrew.analysis.data_references`),
    so filler between functions cannot desynchronize the stream; every
    absolute reference into a data range is attributed to the function
    containing it, and a data VA referenced by exactly one function is that
    function's own object.
    """
    if not functions:
        return {}
    ranges = _data_ranges(info)
    if not ranges:
        return {}

    def _in_data(va: int) -> bool:
        return any(start <= va < start + size for _name, start, size in ranges)

    owners: dict[int, set[int]] = {}
    for func_va, size in functions:
        for xref in data_references(info, func_va, size):
            if not _in_data(xref.to_va):
                continue
            owners.setdefault(xref.to_va, set()).add(func_va)

    owned: dict[int, list[int]] = {}
    for data_va, funcs in owners.items():
        if len(funcs) == 1:
            owned.setdefault(next(iter(funcs)), []).append(data_va)
    for vas in owned.values():
        vas.sort()
    return owned


def _single_ref_data_bonds(
    info: BinaryInfo,
    functions: list[tuple[int, int]],
) -> dict[int, int]:
    """``{function_va: predecessor_va}`` for functions bonded by data layout.

    A function's exclusively-owned objects are emitted into its object
    file's data, so two consecutive functions whose owned objects run
    contiguously (the second's first object starting within
    :data:`SINGLE_REF_DATA_MAX_GAP` bytes of the first's last) are likely
    one object file.  Weak evidence on its own: the bond vetoes a split and
    adds confidence, it never creates a boundary.
    """
    owned = _exclusive_data_owners(info, functions)
    bonds: dict[int, int] = {}
    for (prev_va, _), (curr_va, _) in zip(functions, functions[1:], strict=False):
        prev_owned = owned.get(prev_va)
        curr_owned = owned.get(curr_va)
        if not prev_owned or not curr_owned:
            continue
        gap = curr_owned[0] - prev_owned[-1]
        if 0 <= gap <= SINGLE_REF_DATA_MAX_GAP:
            bonds[curr_va] = prev_va
    return bonds


# ---------------------------------------------------------------------------
# Main algorithm
# ---------------------------------------------------------------------------


def cluster_functions(
    registry: dict[int, RegistryEntry],
    info: BinaryInfo,
    cfg: ProjectConfig | None,
    *,
    jump_table_alignment: int | None = None,
    single_ref_data: bool = False,
) -> list[TUCluster]:
    """Cluster functions into inferred translation units.

    Pass 1: contiguity clustering based on gap analysis.
    Pass 2: call-graph refinement (if capstone available).

    Overlapping registry ranges are a registry error (``ValueError``), not
    padding: merging them would inflate same-TU confidence from corrupt
    input.  Gaps whose bytes are unavailable classify as ``"unknown"`` (no
    boundary, no signal) rather than ``large_nonpadding``.

    Args:
        registry: Function VA → registry entry.
        info: Loaded target binary.
        cfg: Project config (padding bytes, capstone arch/mode, ``arch``).
        jump_table_alignment: Enable the jump-table alignment signal with
            this modulus (a positive power of two).  ``None`` (the default)
            leaves it off; the value is deliberately not defaulted, because
            splat's 8 is a PSX/GCC figure that does not transfer to MSVC; see
            the module docstring.
        single_ref_data: Enable the single-reference-data signal (off by
            default).  Costs one linear reference scan of the code sections.
    """
    alignment = (
        _validate_alignment(jump_table_alignment) if jump_table_alignment is not None else None
    )
    padding_bytes = tuple(cfg.padding_bytes) if cfg else (0xCC, 0x90)
    text_va = info.text_va
    text_size = info.text_size

    # Filter: no thunks, no zero-size, only .text functions
    text_end = text_va + text_size
    eligible: list[tuple[int, RegistryEntry]] = []

    for va, entry in sorted(registry.items()):
        if entry.get("is_thunk"):
            continue
        size = int(entry.get("canonical_size", 0))
        if size <= 0:
            continue
        if va < text_va or va >= text_end:
            continue
        eligible.append((va, entry))

    if not eligible:
        return []

    extents = [(va, int(entry.get("canonical_size", 0))) for va, entry in eligible]
    arch = (getattr(cfg, "arch", "") or "x86_32") if cfg is not None else "x86_32"

    # Optional signals, each computed only when asked for.
    signal_splits: dict[int, str] = {}
    if alignment is not None:
        signal_splits = _jump_table_split_vas(
            _find_jump_tables(info, extents, arch), alignment, extents
        )
    bonds: dict[int, int] = _single_ref_data_bonds(info, extents) if single_ref_data else {}

    # --- Pass 1: contiguity clustering ---
    clusters_raw: list[list[tuple[int, RegistryEntry]]] = [[eligible[0]]]
    gap_classes_raw: list[list[str]] = [[]]
    # Signal-driven split evidence, keyed by the cluster the split STARTED.
    split_evidence: dict[int, str] = {}

    for i in range(1, len(eligible)):
        prev_va, prev_entry = eligible[i - 1]
        curr_va, curr_entry = eligible[i]
        prev_size = int(prev_entry.get("canonical_size", 0))
        gap_start = prev_va + prev_size
        gap_len = curr_va - gap_start

        if gap_len < 0:
            # Overlapping functions mean the registry contradicts itself —
            # merging them would inflate same-TU confidence from corrupt
            # input, so fail instead of labeling padding.
            prev_end = prev_va + prev_size
            raise ValueError(
                f"overlapping functions 0x{prev_va:08x} (ends 0x{prev_end:08x}) "
                f"and 0x{curr_va:08x}: fix the registry before clustering"
            )
        elif gap_len == 0:
            gc = "padding"
        else:
            gap_data = extract_bytes_at_va(info, gap_start, gap_len, trim_padding=False)
            # ``b""`` means the section's file-backed bytes are exhausted (a
            # zero-filled tail with VirtualSize > SizeOfRawData): unavailable,
            # NOT padding.  Classifying it as padding kept two functions in one
            # TU on a positive signal that does not exist.
            if not gap_data:
                gc = "unknown"
            else:
                gc = _classify_gap(gap_data, text_va, text_size, padding_bytes)

        if gc == "large_nonpadding" and curr_va in bonds:
            # Single-reference data says this function's objects and its
            # predecessor's are one object file's data layout, so the
            # non-padding gap between the functions is not a TU boundary.
            clusters_raw[-1].append((curr_va, curr_entry))
            gap_classes_raw[-1].append("data_bond")
        elif gc == "large_nonpadding" or curr_va in signal_splits:
            # TU boundary — start new cluster
            clusters_raw.append([(curr_va, curr_entry)])
            gap_classes_raw.append([])
            if curr_va in signal_splits:
                split_evidence[len(clusters_raw) - 1] = signal_splits[curr_va]
        else:
            clusters_raw[-1].append((curr_va, curr_entry))
            gap_classes_raw[-1].append(gc)

    # --- Pass 2: call-graph refinement ---
    call_map = _scan_call_targets(info, registry, cfg)
    caller_map = _invert_call_map(call_map) if call_map else {}

    # Build final clusters
    result: list[TUCluster] = []
    for cid, (funcs, gaps) in enumerate(zip(clusters_raw, gap_classes_raw, strict=True)):
        vas = [va for va, _ in funcs]
        score, evidence = _contiguity_score(gaps)

        if call_map:
            boost, call_evidence = _call_graph_boost(set(vas), caller_map)
            score = min(round(score + boost, 2), 1.0)
            evidence.extend(call_evidence)

        if alignment is not None and len(vas) > 1 and cid not in split_evidence:
            # Every table inside this cluster agrees on the alignment
            # remainder: consistent with one object file.
            score = min(round(score + JUMP_TABLE_ALIGN_BOOST, 2), 1.0)
            evidence.append(f"jump tables agree on % {alignment} alignment")
        if split_evidence.get(cid):
            evidence.append(split_evidence[cid])

        n_bonds = sum(1 for gc in gaps if gc == "data_bond")
        if n_bonds:
            evidence.append(f"{n_bonds} single-reference data bond{'s' if n_bonds != 1 else ''}")
            score = min(round(score + n_bonds * SINGLE_REF_DATA_BOOST, 2), 1.0)

        result.append(
            TUCluster(
                cluster_id=cid,
                functions=vas,
                gap_classes=gaps,
                confidence=score,
                evidence=evidence,
            )
        )

    return result


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def _cluster_to_dict(
    cluster: TUCluster,
    registry: dict[int, RegistryEntry],
) -> dict[str, Any]:
    """Convert a TUCluster to a JSON-serializable dict."""
    func_dicts: list[dict[str, Any]] = []
    for idx, va in enumerate(cluster.functions):
        entry = registry.get(va, {})
        name = entry.get("list_name") or entry.get("ghidra_name") or ""
        size = int(entry.get("canonical_size", 0))
        # gap_after: gap class for the gap after this function, None for last
        gap_after: str | None = None
        if idx < len(cluster.gap_classes):
            gap_after = cluster.gap_classes[idx]
        func_dicts.append(
            {
                "va": f"0x{va:08X}",
                "name": name,
                "size": size,
                "gap_after": gap_after,
            }
        )

    va_start = cluster.functions[0]
    va_end = cluster.functions[-1]
    last_entry = registry.get(va_end, {})
    last_size = int(last_entry.get("canonical_size", 0))
    va_end_actual = va_end + last_size

    return {
        "cluster_id": cluster.cluster_id,
        "va_start": f"0x{va_start:08X}",
        "va_end": f"0x{va_end_actual:08X}",
        "function_count": len(cluster.functions),
        "confidence": cluster.confidence,
        "evidence": cluster.evidence,
        "functions": func_dicts,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Cluster target binary functions into inferred translation units.

    Uses inter-function gap analysis and call-graph signals to identify
    which functions were likely compiled from the same .c/.cpp source file.

    Runs with both optional signals off; the only CLI entry to this module is
    ``rebrew graph --cu-map``, whose forwarder (``rebrew.depgraph``) passes
    the target and JSON options only.  Enable a signal through
    :func:`cluster_functions` directly.
    """
    cfg = require_config(target=target, json_mode=json_output)

    # Load binary
    bin_path = cfg.target_binary
    if not bin_path.exists():
        error_exit(f"Target binary not found: {bin_path}", json_mode=json_output)
    info = load_binary(bin_path)

    # Build function registry
    func_list_path = cfg.function_list
    if not func_list_path.exists():
        error_exit(f"Function list not found: {func_list_path}", json_mode=json_output)
    funcs = parse_function_list(func_list_path)

    reversed_dir = cfg.reversed_dir
    ghidra_path = reversed_dir / FUNCTION_STRUCTURE_JSON if reversed_dir else None

    registry = build_function_registry(funcs, cfg, ghidra_path=ghidra_path, bin_path=bin_path)

    # Cluster
    clusters = cluster_functions(registry, info, cfg)

    # Count unclustered
    clustered_vas: set[int] = set()
    for c in clusters:
        clustered_vas.update(c.functions)
    total_funcs = len(registry)
    clustered_count = len(clustered_vas)

    if json_output:
        cluster_dicts = [_cluster_to_dict(c, registry) for c in clusters]
        # Unclustered
        unclustered = []
        for va, entry in sorted(registry.items()):
            if va not in clustered_vas:
                reason = "thunk" if entry.get("is_thunk") else "unknown size"
                if int(entry.get("canonical_size", 0)) > 0 and not entry.get("is_thunk"):
                    reason = "outside .text"
                unclustered.append({"va": f"0x{va:08X}", "reason": reason})

        json_print(
            {
                "total_functions": total_funcs,
                "clustered_functions": clustered_count,
                "total_clusters": len(clusters),
                "clusters": cluster_dicts,
                "unclustered": unclustered,
            }
        )
        return

    # Rich table output
    console.print(
        f"\n[bold]Compilation Unit Map[/bold]  "
        f"({clustered_count}/{total_funcs} functions in {len(clusters)} clusters)\n"
    )

    table = Table(show_header=True, header_style="bold")
    table.add_column("Cluster", justify="right", style="dim")
    table.add_column("VA Range", style="cyan")
    table.add_column("Funcs", justify="right")
    table.add_column("Bytes", justify="right")
    table.add_column("Conf", justify="right")
    table.add_column("Boundary", style="yellow")

    for cluster in clusters:
        va_start = cluster.functions[0]
        va_end_va = cluster.functions[-1]
        last_entry = registry.get(va_end_va, {})
        last_size = int(last_entry.get("canonical_size", 0))
        va_end = va_end_va + last_size

        total_bytes = va_end - va_start
        boundary = ", ".join(cluster.evidence) if cluster.evidence else "—"

        table.add_row(
            str(cluster.cluster_id),
            f"{va_start:08X}–{va_end:08X}",
            str(len(cluster.functions)),
            f"{total_bytes:,}",
            f"{cluster.confidence:.2f}",
            boundary,
        )

    console.print(table)
