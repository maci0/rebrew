"""merge_sweep.py - deterministic TU-partition search over cu_map clusters.

``rebrew cu-map`` infers translation units from gap analysis plus call-graph
signals, but the inference never compiles anything: a boundary it proposes
may not reproduce.  This tool closes the loop.  It starts from the
:func:`rebrew.cu_map.cluster_functions` partition and hill-climbs toward the
partition whose merged translation units compile to the most matched bytes:

- **Phase A (merge)**: greedily merge adjacent cluster pairs that share a
  call edge or a string, accepting only moves that increase total matched
  bytes (ties: fewer clusters, then lower VA).
- **Phase B (split)**: greedily split clusters at internal
  ``large_nonpadding`` gaps, accepting strict improvements and ties.

Both phases repeat to a fixpoint (cap: 3 passes, 2n compiles).  Scoring
compiles each merged TU once via the :mod:`rebrew.merge` machinery plus
:func:`rebrew.compile.compile_and_compare` per function, and compares the
sum of matched bytes.  Traversal is VA-ordered, there is no RNG, and every
accepted move is appended to a JSON audit log.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.annotation import parse_c_file_multi
from rebrew.binary_loader import extract_raw_bytes, load_binary
from rebrew.catalog import (
    build_function_registry,
    parse_function_list,
)
from rebrew.cli import (
    TargetOption,
    error_exit,
    json_print,
    require_config,
    resolve_compile_overrides,
)
from rebrew.config import FUNCTION_STRUCTURE_JSON, ProjectConfig
from rebrew.core import build_name_to_va
from rebrew.sources import iter_sources, target_marker

console = Console(stderr=True)

app = typer.Typer(
    help="Deterministic TU-partition search over cu-map clusters.",
    rich_markup_mode="rich",
)

#: Search caps from the spec: at most 3 full passes, at most 2n compiles.
DEFAULT_MAX_PASSES = 3

#: Gap classes that mark a compilation-unit boundary (cu_map splits on these).
BOUNDARY_GAP_CLASSES = frozenset({"large_nonpadding"})


# ---------------------------------------------------------------------------
# Pure partition logic (no compiler)
# ---------------------------------------------------------------------------


def _partition_key(partition: list[list[int]]) -> tuple[tuple[int, ...], ...]:
    """Hashable key for one partition (sorted VAs per cluster, VA-ordered)."""
    return tuple(tuple(sorted(cluster)) for cluster in partition)


def _shared_call_edge(
    left: set[int],
    right: set[int],
    call_map: dict[int, set[int]],
) -> bool:
    """True when any call crosses the left/right boundary in either direction."""
    for caller, callees in call_map.items():
        if caller in left and not callees.isdisjoint(right):
            return True
        if caller in right and not callees.isdisjoint(left):
            return True
    return False


def _shared_string(
    left: set[int],
    right: set[int],
    func_strings: dict[int, set[int]],
) -> bool:
    """True when a function in *left* and one in *right* reference one string."""
    left_strings: set[int] = set()
    for va in left:
        left_strings |= func_strings.get(va, set())
    if not left_strings:
        return False
    return any(left_strings & func_strings.get(va, set()) for va in right)


def _merge_candidates(
    partition: list[list[int]],
    call_map: dict[int, set[int]],
    func_strings: dict[int, set[int]],
) -> list[tuple[int, int, str]]:
    """Adjacent merge candidates in VA order as ``(left_idx, right_idx, reason)``.

    A pair qualifies when it shares a call edge (``"call"``) or a referenced
    string (``"string"``); a pair sharing both reports ``"call+string"``.
    """
    out: list[tuple[int, int, str]] = []
    for i in range(len(partition) - 1):
        left = set(partition[i])
        right = set(partition[i + 1])
        reasons: list[str] = []
        if _shared_call_edge(left, right, call_map):
            reasons.append("call")
        if _shared_string(left, right, func_strings):
            reasons.append("string")
        if reasons:
            out.append((i, i + 1, "+".join(reasons)))
    return out


def _split_candidates(
    partition: list[list[int]],
    gap_classes: dict[tuple[int, int], str],
) -> list[tuple[int, int]]:
    """Split points in VA order as ``(cluster_idx, position_after)``.

    Position *k* of a cluster splits after its k-th function (1-based) when
    the gap between function k-1 and k is a ``large_nonpadding`` boundary.
    """
    out: list[tuple[int, int]] = []
    for i, cluster in enumerate(partition):
        for k in range(1, len(cluster)):
            if gap_classes.get((cluster[k - 1], cluster[k])) in BOUNDARY_GAP_CLASSES:
                out.append((i, k))
    return out


def _apply_merge(partition: list[list[int]], left: int, right: int) -> list[list[int]]:
    """Return *partition* with clusters *left* and *right* joined."""
    merged = sorted(partition[left] + partition[right])
    return partition[:left] + [merged] + partition[right + 1 :]


def _apply_split(partition: list[list[int]], cluster: int, at: int) -> list[list[int]]:
    """Return *partition* with cluster *cluster* split after its *at*-th function."""
    left = partition[cluster][:at]
    right = partition[cluster][at:]
    return partition[:cluster] + [left, right] + partition[cluster + 1 :]


def _rank_key(partition: list[list[int]], score: int) -> tuple[int, int, int]:
    """Ordering key for one candidate partition.

    Primary key is matched bytes; ties break toward fewer clusters, then
    lower first VA, so winner selection among equal-scoring candidates is
    deterministic.
    """
    first_va = partition[0][0] if partition and partition[0] else 0
    return (score, -len(partition), -first_va)


def search_partitions(
    initial: list[list[int]],
    score_fn: Callable[[list[list[int]]], int],
    call_map: dict[int, set[int]],
    func_strings: dict[int, set[int]],
    gap_classes: dict[tuple[int, int], str],
    *,
    max_passes: int = DEFAULT_MAX_PASSES,
    max_compiles: int | None = None,
    on_accept: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[list[list[int]], int, list[dict[str, Any]], int]:
    """Hill-climb *initial* toward the highest-scoring TU partition.

    Phase A merges adjacent cluster pairs sharing a call edge or string;
    Phase B splits clusters at internal ``large_nonpadding`` gaps.  Both
    repeat to a fixpoint.  *score_fn* maps a partition to total matched
    bytes; scores memoize per partition key so a revisited shape never
    recompiles.  Returns ``(partition, score, moves, compile_count)`` where
    each move records its phase, kind, affected VAs, reason, and scores.
    """
    memo: dict[tuple[tuple[int, ...], ...], int] = {}
    compiles = 0

    def scored(partition: list[list[int]]) -> int:
        nonlocal compiles
        key = _partition_key(partition)
        hit = memo.get(key)
        if hit is not None:
            return hit
        if max_compiles is not None and compiles >= max_compiles:
            raise _BudgetExhausted
        value = score_fn(partition)
        compiles += 1
        memo[key] = value
        return value

    moves: list[dict[str, Any]] = []
    try:
        current = [sorted(cluster) for cluster in initial]
        best = scored(current)
        for sweep in range(max(1, max_passes)):
            changed = False
            for phase in ("merge", "split"):
                while True:
                    incumbent = best
                    winner: list[list[int]] | None = None
                    winner_key: tuple[int, int, int] | None = None
                    winner_info: dict[str, Any] = {}
                    if phase == "merge":
                        cands: list[tuple[list[list[int]], dict[str, Any]]] = [
                            (
                                _apply_merge(current, left, right),
                                {
                                    "kind": "merge",
                                    "left": list(current[left]),
                                    "right": list(current[right]),
                                    "reason": reason,
                                },
                            )
                            for left, right, reason in _merge_candidates(
                                current, call_map, func_strings
                            )
                        ]
                    else:
                        cands = [
                            (
                                _apply_split(current, cluster, at),
                                {
                                    "kind": "split",
                                    "cluster": list(current[cluster]),
                                    "at": current[cluster][at],
                                },
                            )
                            for cluster, at in _split_candidates(current, gap_classes)
                        ]
                    for cand_partition, info in cands:
                        score = scored(cand_partition)
                        key = _rank_key(cand_partition, score)
                        if winner_key is None or key > winner_key:
                            winner = cand_partition
                            winner_key = key
                            winner_info = info
                    if winner is None or winner_key is None:
                        break
                    # Merges need strictly more matched bytes; splits accept
                    # ties (a zero-cost split still reveals a real boundary).
                    if winner_key[0] < best or (phase == "merge" and winner_key[0] == best):
                        break
                    best = winner_key[0]
                    current = winner
                    changed = True
                    move = {
                        "pass": sweep,
                        "phase": phase,
                        **winner_info,
                        "before": incumbent,
                        "after": best,
                        "clusters": len(current),
                    }
                    moves.append(move)
                    if on_accept is not None:
                        on_accept(move)
            if not changed:
                break
    except _BudgetExhausted:
        pass
    return current, best, moves, compiles


class _BudgetExhausted(Exception):
    """Internal signal: the compile budget ran out mid-search."""


# ---------------------------------------------------------------------------
# Binary-derived inputs (call graph, strings, gaps)
# ---------------------------------------------------------------------------


def _function_call_map(
    registry: dict[int, Any],
    info: Any,
    cfg: ProjectConfig | None,
) -> dict[int, set[int]]:
    """Caller VA to callee-VA set, restricted to functions in *registry*."""
    from rebrew.cu_map import _scan_call_targets

    return _scan_call_targets(info, registry, cfg)


def _function_strings(info: Any) -> dict[int, set[int]]:
    """Function VA to referenced string-VA set."""
    from rebrew.analysis import iter_strings, string_refs

    strings = iter_strings(info)
    refs = string_refs(info, strings)
    string_vas = {s.va for s in strings}
    out: dict[int, set[int]] = {}
    for string_va, xrefs in refs.items():
        if string_va not in string_vas:
            continue
        for xref in xrefs:
            out.setdefault(xref.from_va, set()).add(string_va)
    return out


def _gap_classes(
    vas: list[int],
    registry: dict[int, Any],
    info: Any,
    cfg: ProjectConfig | None,
) -> dict[tuple[int, int], str]:
    """Gap class for each consecutive VA pair, via cu_map's classifier."""
    from rebrew.binary_loader import extract_bytes_at_va
    from rebrew.cu_map import _classify_gap

    padding = tuple(cfg.padding_bytes) if cfg else (0xCC, 0x90)
    text_va = info.text_va
    text_size = info.text_size
    out: dict[tuple[int, int], str] = {}
    for prev_va, curr_va in zip(vas, vas[1:], strict=True):
        size = int(registry.get(prev_va, {}).get("canonical_size", 0))
        gap_start = prev_va + size
        gap_len = curr_va - gap_start
        if gap_len <= 0:
            out[(prev_va, curr_va)] = "padding"
            continue
        gap_data = extract_bytes_at_va(info, gap_start, gap_len, trim_padding=False)
        if gap_data is None:
            out[(prev_va, curr_va)] = "large_nonpadding"
        else:
            out[(prev_va, curr_va)] = _classify_gap(gap_data, text_va, text_size, padding)
    return out


def _initial_partition(
    registry: dict[int, Any],
    info: Any,
    cfg: ProjectConfig | None,
) -> list[list[int]]:
    """cluster_functions output as VA-ordered VA lists."""
    from rebrew.cu_map import cluster_functions

    clusters = cluster_functions(registry, info, cfg)
    return [sorted(c.functions) for c in clusters]


# ---------------------------------------------------------------------------
# Compile-backed scoring (merge machinery + compile_and_compare)
# ---------------------------------------------------------------------------


class _PartitionScorer:
    """Score one partition as total matched bytes over its merged TUs.

    Each cluster becomes one merged TU in a temp dir (via
    :func:`rebrew.merge` helpers), compiled once; every function in the TU
    is extracted by symbol and compared with
    :func:`rebrew.compile.compile_and_compare`, and the matched-byte counts
    are summed.  A cluster with no reversed source scores 0 without
    compiling.
    """

    def __init__(
        self,
        cfg: ProjectConfig,
        annotations: dict[int, Any],
        name_to_va: dict[str, int],
    ) -> None:
        self._cfg = cfg
        self._annotations = annotations
        self._name_to_va = name_to_va

    def _cluster_text(self, cluster: list[int]) -> str | None:
        """Merged TU text for *cluster*, or None when no source covers it."""
        from rebrew.annotation import split_annotation_sections
        from rebrew.merge import _block_metadata, _merge_preambles
        from rebrew.utils import read_source_text

        preambles: list[str] = []
        blocks: list[tuple[int, str]] = []
        marker = target_marker(self._cfg)
        seen_files: set[str] = set()
        for va in cluster:
            ann = self._annotations.get(va)
            if ann is None:
                continue
            path = Path(ann.filepath)
            if not path.is_absolute():
                path = self._cfg.reversed_dir / path
            key = str(path)
            if key not in seen_files:
                seen_files.add(key)
                try:
                    text, _ = read_source_text(path)
                except OSError:
                    continue
                preamble, file_blocks = split_annotation_sections(text)
                preambles.append(preamble)
                for block in file_blocks:
                    meta = _block_metadata(block)
                    if meta is None:
                        continue
                    if marker and str(meta["module"]).lower() != marker.lower():
                        continue
                    blocks.append((int(meta["va"]), block.strip("\n")))
        if not blocks:
            return None
        wanted = set(cluster)
        picked = sorted({va: block for va, block in blocks if va in wanted}.items())
        if not picked:
            return None
        merged = _merge_preambles(preambles) + "\n\n".join(b for _, b in picked) + "\n"
        return merged

    def _score_cluster(self, cluster: list[int], workdir: Path) -> int:
        from rebrew.compile import compile_and_compare

        text = self._cluster_text(cluster)
        if text is None:
            return 0
        tu_path = workdir / f"tu_{cluster[0]:08x}.c"
        tu_path.write_text(text, encoding="utf-8")
        total = 0
        for va in cluster:
            ann = self._annotations.get(va)
            if ann is None or ann.size <= 0:
                continue
            symbol = ann.symbol or ("" if ann.name.startswith("_") else "_" + ann.name)
            if not symbol:
                continue
            target_bytes = extract_raw_bytes(self._cfg.target_binary, va, ann.size)
            if not target_bytes:
                continue
            toolchain, cflags = resolve_compile_overrides(
                self._cfg,
                tu_path.parent,
                getattr(ann, "toolchain", ""),
                getattr(ann, "cflags", ""),
                getattr(ann, "module", ""),
            )
            result = compile_and_compare(
                self._cfg,
                tu_path,
                symbol,
                target_bytes,
                cflags,
                name_to_va=self._name_to_va,
                section_va=va,
                toolchain=toolchain,
            )
            if result.obj_bytes is None or result.matched:
                total += len(target_bytes) if result.matched else 0
                continue
            total += int(round(result.match_percent / 100.0 * len(target_bytes)))
        return total

    def __call__(self, partition: list[list[int]]) -> int:
        with tempfile.TemporaryDirectory(prefix="merge_sweep_") as tmp:
            workdir = Path(tmp)
            return sum(self._score_cluster(cluster, workdir) for cluster in partition)


def _load_annotations(cfg: ProjectConfig) -> dict[int, Any]:
    """VA to annotation over every reversed source for the active target."""
    from rebrew.cli import iter_annotations

    marker = target_marker(cfg)
    out: dict[int, Any] = {}
    for _path, anns in iter_annotations(
        iter_sources(cfg.reversed_dir, cfg),
        target=marker,
        metadata_dir=cfg.metadata_dir,
    ):
        for ann in anns:
            if ann.va and ann.va not in out:
                out[ann.va] = ann
    return out


def _initial_partition_for_annotated(
    partition: list[list[int]],
    annotated: set[int],
) -> list[list[int]]:
    """Restrict *partition* to annotated functions, preserving VA order."""
    return [
        sorted(va for va in cluster if va in annotated)
        for cluster in partition
        if any(va in annotated for va in cluster)
    ]


def _parse_annotations_fallback(cfg: ProjectConfig) -> dict[int, Any]:
    """VA to annotation via direct per-file parse (no metadata overlay)."""
    marker = target_marker(cfg)
    out: dict[int, Any] = {}
    for src in iter_sources(cfg.reversed_dir, cfg):
        try:
            anns = parse_c_file_multi(src, target_name=marker)
        except (OSError, ValueError):
            continue
        for ann in anns:
            if ann.va and ann.va not in out:
                out[ann.va] = ann
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def main(
    passes: int = typer.Option(
        DEFAULT_MAX_PASSES, "--passes", help="Search passes over the partition"
    ),
    max_compiles: int | None = typer.Option(None, "--max-compiles", help="Cap on TU compilations"),
    audit: str | None = typer.Option(None, "--audit", help="Write the JSON audit log to FILE"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Search cu-map TU partitions for the most matched bytes."""
    from rebrew.utils import atomic_write_text

    cfg = require_config(target=target, json_mode=json_output)
    if passes < 1:
        error_exit("--passes must be at least 1", json_mode=json_output)
    if max_compiles is not None and max_compiles < 1:
        error_exit("--max-compiles must be at least 1", json_mode=json_output)

    if not cfg.target_binary.exists():
        error_exit(f"Target binary not found: {cfg.target_binary}", json_mode=json_output)
    if not cfg.function_list.exists():
        error_exit(f"Function list not found: {cfg.function_list}", json_mode=json_output)
    info = load_binary(cfg.target_binary)

    funcs = parse_function_list(cfg.function_list)
    ghidra_path = cfg.reversed_dir / FUNCTION_STRUCTURE_JSON if cfg.reversed_dir else None
    registry = build_function_registry(
        funcs, cfg, ghidra_path=ghidra_path, bin_path=cfg.target_binary
    )
    if not registry:
        error_exit("No functions in registry", json_mode=json_output)

    annotations = _load_annotations(cfg)
    if not annotations:
        annotations = _parse_annotations_fallback(cfg)
    if not annotations:
        error_exit("No annotated functions found", json_mode=json_output)

    full_initial = _initial_partition(registry, info, cfg)
    annotated = set(annotations)
    initial = _initial_partition_for_annotated(full_initial, annotated)
    if not initial:
        initial = [sorted(annotated)]

    vas = sorted(annotated)
    call_map = _function_call_map(registry, info, cfg)
    func_strings = _function_strings(info)
    gaps = _gap_classes(vas, registry, info, cfg)

    if dry_run:
        candidates = _merge_candidates(initial, call_map, func_strings)
        splits = _split_candidates(initial, gaps)
        payload: dict[str, Any] = {
            "dry_run": True,
            "clusters": len(initial),
            "initial_partition": [[f"0x{va:08X}" for va in cluster] for cluster in initial],
            "merge_candidates": [
                {
                    "left": [f"0x{va:08X}" for va in initial[left]],
                    "right": [f"0x{va:08X}" for va in initial[right]],
                    "reason": reason,
                }
                for left, right, reason in candidates
            ],
            "split_candidates": [
                {
                    "cluster": [f"0x{va:08X}" for va in initial[cluster]],
                    "at": f"0x{initial[cluster][at]:08X}",
                }
                for cluster, at in splits
            ],
        }
        if json_output:
            json_print(payload)
            return
        console.print(
            f"[bold]merge-sweep dry run[/bold]: {len(initial)} initial cluster(s), "
            f"{len(candidates)} merge candidate(s), {len(splits)} split candidate(s)"
        )
        for left, right, reason in candidates:
            console.print(
                f"  merge {[f'0x{v:08X}' for v in initial[left]]} + "
                f"{[f'0x{v:08X}' for v in initial[right]]} ({reason})"
            )
        for cluster, at in splits:
            console.print(
                f"  split {[f'0x{v:08X}' for v in initial[cluster]]} "
                f"at 0x{initial[cluster][at]:08X}"
            )
        return

    default_cap = 2 * max(len(initial), 1)
    cap = max_compiles if max_compiles is not None else default_cap
    scorer = _PartitionScorer(cfg, annotations, build_name_to_va(cfg))
    audit_moves: list[dict[str, Any]] = []

    def on_accept(move: dict[str, Any]) -> None:
        audit_moves.append(move)
        left = move.get("left", move.get("cluster", []))
        console.print(
            f"  {move['phase']} {move['kind']}: {[f'0x{v:08X}' for v in left]} "
            f"{move['before']} -> {move['after']} bytes"
        )

    final, best, moves, compiles = search_partitions(
        initial,
        scorer,
        call_map,
        func_strings,
        gaps,
        max_passes=passes,
        max_compiles=cap,
        on_accept=on_accept,
    )

    audit_log = [
        {
            "pass": move["pass"],
            "phase": move["phase"],
            "kind": move["kind"],
            "reason": move.get("reason", ""),
            "vas": [f"0x{v:08X}" for v in move.get("left", move.get("cluster", []))],
            "before": move["before"],
            "after": move["after"],
            "clusters": move["clusters"],
        }
        for move in moves
    ]
    if audit is not None:
        atomic_write_text(Path(audit), json.dumps(audit_log, indent=2) + "\n")

    payload = {
        "clusters": len(final),
        "initial_clusters": len(initial),
        "matched_bytes": best,
        "compiles": compiles,
        "moves": len(moves),
        "audit": audit_log,
        "partition": [[f"0x{va:08X}" for va in cluster] for cluster in final],
    }
    if json_output:
        json_print(payload)
        return
    console.print(
        f"[bold]merge-sweep[/bold]: {len(initial)} -> {len(final)} cluster(s), "
        f"{best} matched bytes ({len(moves)} move(s), {compiles} compile(s))"
    )


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
