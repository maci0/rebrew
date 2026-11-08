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
"""

from dataclasses import dataclass
lazy from typing import Any

import typer

from rebrew.cli import TargetOption, console, error_exit, json_print, require_config
lazy from rebrew.analysis import direct_call_target
lazy from rebrew.catalog import (
    RegistryEntry,
    build_function_registry,
    is_jump_table,
)
lazy from rebrew.config import ProjectConfig, inventory_path_for
lazy from rebrew.formats.binary_loader import capstone_config_for, extract_bytes_at_va, load_binary
lazy from rebrew.formats.binary_model import BinaryInfo
lazy from rebrew.utils import TerminalTable

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


def classify_gap(
    data: bytes,
    text_va: int,
    text_size: int,
    padding_bytes: tuple[int, ...] = (0xCC, 0x90),
    arch: str = "x86_32",
    endian: str = "",
) -> str:
    """Classify a gap between two consecutive functions.

    Returns one of: ``"padding"``, ``"jump_table"``, ``"small_nonpadding"``,
    ``"large_nonpadding"``.

    *arch* and *endian* are the image's, forwarded to
    :func:`rebrew.catalog.is_jump_table`. A 64-bit or big-endian pointer
    table is not a table when those stay at the x86-32 default.
    """
    if len(data) == 0:
        return "padding"

    if all(b in padding_bytes for b in data):
        return "padding"

    if is_jump_table(data, text_va, text_size, arch, endian):
        return "jump_table"

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
        evidence.append("gaps: " + ", ".join(parts))

    score = max(score, 0.40)
    return round(score, 2), evidence


# ---------------------------------------------------------------------------
# Call scanning
# ---------------------------------------------------------------------------


def scan_call_targets(
    info: BinaryInfo,
    registry: dict[int, RegistryEntry],
    cfg: ProjectConfig | None,
) -> dict[int, set[int]]:
    """Disassemble each function and extract direct call targets.

    A project config supplies the capstone arch and mode.  Without one, the
    image's own arch, endianness, and container (NE/MZ is 16-bit) do.
    ``call``, ``bl``/``blx``, ``jal``, and ``bsr`` with an immediate address
    count; register-indirect calls do not.

    Returns ``{caller_va: {callee_vas}}`` for callees present in the registry.
    """
    try:
        from capstone import Cs
    except ImportError:
        return {}

    if cfg is not None:
        arch = cfg.capstone_arch
        mode = cfg.capstone_mode
    else:
        arch, mode = capstone_config_for(info)
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
            target = direct_call_target(insn.mnemonic, insn.op_str)
            if target is not None and target in registry_vas and target != va:
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
# Main algorithm
# ---------------------------------------------------------------------------


def cluster_functions(
    registry: dict[int, RegistryEntry],
    info: BinaryInfo,
    cfg: ProjectConfig | None,
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
    """
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

    configured = getattr(cfg, "arch", "") if cfg is not None else ""
    arch = configured or getattr(info, "arch", "") or "x86_32"
    endian = getattr(info, "endian", "") or ""

    # --- Pass 1: contiguity clustering ---
    clusters_raw: list[list[tuple[int, RegistryEntry]]] = [[eligible[0]]]
    gap_classes_raw: list[list[str]] = [[]]

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
        if gap_len == 0:
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
                gc = classify_gap(gap_data, text_va, text_size, padding_bytes, arch, endian)

        if gc == "large_nonpadding":
            # TU boundary — start new cluster
            clusters_raw.append([(curr_va, curr_entry)])
            gap_classes_raw.append([])
        else:
            clusters_raw[-1].append((curr_va, curr_entry))
            gap_classes_raw[-1].append(gc)

    # --- Pass 2: call-graph refinement ---
    call_map = scan_call_targets(info, registry, cfg)
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
# Library entry point (also used by the depgraph command)
# ---------------------------------------------------------------------------


def run_cu_map(json_output: bool = False, target: str | None = None) -> None:
    """Cluster target binary functions into inferred translation units.

    Uses inter-function gap analysis and call-graph signals to identify
    which functions were likely compiled from the same .c/.cpp source file.
    """
    cfg = require_config(target=target, json_mode=json_output)

    bin_path = cfg.target_binary
    if not bin_path.exists():
        error_exit(f"Target binary not found: {bin_path}", json_mode=json_output)
    info = load_binary(bin_path)

    from rebrew.catalog import cached_function_list

    funcs = cached_function_list(cfg)
    if not funcs:
        error_exit(
            "No function inventory (needed here) — run `rebrew intake` first", json_mode=json_output
        )

    reversed_dir = cfg.reversed_dir
    ghidra_path = inventory_path_for(reversed_dir, cfg)

    registry = build_function_registry(funcs, cfg, ghidra_path=ghidra_path, bin_path=bin_path)

    clusters = cluster_functions(registry, info, cfg)

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

    table = TerminalTable(show_header=True, header_style="bold")
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


def main(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Cluster target binary functions into inferred translation units."""
    run_cu_map(json_output=json_output, target=target)
