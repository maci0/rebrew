"""bench_perf10_workflow.py — load-independent microbenchmarks of two workflow kernels.

1. ``todo_rank``: ``rebrew.todo._collect_active_functions`` then ``_rank_by_impact``
   over synthetic metadata rows and verify-cache entries (the aggregation behind
   ``rebrew todo``; no disk, no project scan).
2. ``data_inventory``: the pure analysis behind ``rebrew data list`` over a synthetic
   ``ScanResult`` and PE section table: ``enrich_with_sections``, the out-of-range
   cross-check ``execute_data`` runs, ``section_summary``, ``verify_bss_layout``
   and ``ScanResult.to_dict``.

Inputs come from a fixed seed. Imports and fixture creation sit outside the timed
region; CPU time (``process_time_ns``) is the primary clock, wall time is recorded
beside it. Every workload asserts exact results so a no-op cannot pass.

    python tools/bench_perf10_workflow.py            # table
    python tools/bench_perf10_workflow.py --json     # one JSON document
"""

from __future__ import annotations

lazy import argparse
lazy import hashlib
lazy import json
lazy import random
lazy import statistics
lazy import sys
lazy import time
lazy from collections.abc import Callable
lazy from typing import Any

SEED = 20260630
REPEAT = 9

TODO_FUNCTIONS = 24000
TODO_FILES = 1500
TODO_VERIFY_ONLY = 1500
TODO_CALLEES = 400

DATA_GLOBALS = 12000
DATA_SECTIONS = (
    (".text", 0x401000, 0x60000),
    (".rdata", 0x461000, 0x10000),
    (".data", 0x471000, 0x20000),
    (".bss", 0x491000, 0x40000),
)
DATA_TYPES = (
    "int",
    "unsigned int",
    "char",
    "short",
    "float",
    "double",
    "void *",
    "char *",
    "int [16]",
    "unsigned char [256]",
    "struct Foo",
    "const char *[8]",
    "DWORD",
)

#: Pinned from the unmodified tree; the optimized run must reproduce them exactly.
EXPECTED: dict[str, Any] = {
    "todo_rank": {
        "items": 19173,
        "categories": {
            "compile-error": 1247,
            "documented": 340,
            "exact-only": 2220,
            "extract-error": 687,
            "fix-delta": 1815,
            "improve-match": 9843,
            "missing-annotation": 1900,
            "naked-reconstruction": 59,
            "run-prover": 1062,
        },
        "digest": "45395c677609f154",
    },
    "data_inventory": {
        "sections": 4,
        "out_of_range": 611,
        "bss_entries": 3557,
        "bss_gaps": 27,
        "bss_coverage_bytes": 260494,
        "digest": "3476a19d97d5de28",
    },
}


def measure(
    fn: Callable[[], Any],
    *,
    cache_state: str,
    reset: Callable[[], None] | None = None,
    repeat: int = REPEAT,
) -> dict[str, Any]:
    """Run *fn* once untimed, then *repeat* timed runs; keep CPU and wall samples.

    *reset* runs untimed before each sample, for workloads measured cold.
    """
    fn()
    cpu: list[float] = []
    wall: list[float] = []
    for _ in range(repeat):
        if reset is not None:
            reset()
        w0 = time.perf_counter_ns()
        c0 = time.process_time_ns()
        fn()
        cpu.append((time.process_time_ns() - c0) / 1e9)
        wall.append((time.perf_counter_ns() - w0) / 1e9)
    return {
        "cache_state": cache_state,
        "cpu_median_seconds": statistics.median(cpu),
        "wall_median_seconds": statistics.median(wall),
        "cpu_samples": cpu,
        "wall_samples": wall,
    }


def _digest(parts: list[str]) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(part.encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()[:16]


# ---------------------------------------------------------------------------
# todo_rank
# ---------------------------------------------------------------------------

_BLOCKERS = (
    "",
    "",
    "",
    "(3B diff) register allocation",
    "12B diff: ordering",
    "229B vs 205B",
    "GA_CEILING: register-only delta",
    "STRUCTURAL: loop layout — try: reorder_decls, swap_operands, split_expr",
    "not a decomp target: IAT thunk",
    "needs struct recovery before the loop matches",
)
_STATUSES = (
    "STUB",
    "STUB",
    "NEAR_MATCHING",
    "NEAR_MATCHING",
    "EXACT",
    "EXACT",
    "RELOC",
    "COMPILE_ERROR",
    "EXTRACT_ERROR",
    "PROVEN",
    "SKIP",
    "NEAR_MATCH",
)
_VERIFY_STATUSES = (
    "EXACT",
    "RELOC",
    "NEAR_MATCHING",
    "NEAR_MATCHING",
    "STUB",
    "SIZE_MISMATCH",
    "COMPILE_ERROR",
    "MISSING_SIZE",
    "INTERNAL_ERROR",
)


def _make_todo_inputs(rng: random.Random) -> tuple[Any, ...]:
    from rebrew.verify_cache import VerifyCacheEntry

    existing: dict[int, dict[str, str]] = {}
    size_by_va: dict[int, int] = {}
    name_by_va: dict[int, str] = {}
    verify: dict[str, VerifyCacheEntry] = {}
    va = 0x401000
    for i in range(TODO_FUNCTIONS + TODO_VERIFY_ONLY):
        va += rng.randrange(16, 1800, 16)
        size = rng.choice((8, 24, 48, 96, 160, 280, 420, 700, 1200, 2400))
        size_by_va[va] = size + rng.choice((0, 0, 4, 12))
        name_by_va[va] = f"FUN_{va:08x}" if i % 5 == 0 else f"Func_{i}"
        if i < TODO_FUNCTIONS:
            row = {
                "status": rng.choice(_STATUSES),
                "filename": f"file_{i % TODO_FILES}.c",
                "symbol": "" if i % 11 == 0 else f"Func_{i}",
                "blocker": rng.choice(_BLOCKERS),
            }
            if i % 3:
                row["size"] = str(size)
            if i % 17 == 0:
                row["blocker_delta"] = str(rng.randrange(0, 40))
            if i % 97 == 0:
                row["source"] = "naked"
            existing[va] = row
        if i % 4 != 3:
            status = rng.choice(_VERIFY_STATUSES)
            key = f"0x{va:08x}" if i % 7 else f"0x{va:x}"
            verify[key] = VerifyCacheEntry(
                status=status,
                match_percent=None
                if status in {"MISSING_SIZE", "INTERNAL_ERROR"}
                else round(rng.uniform(0, 100), 1),
                delta=None if i % 5 == 0 else rng.randrange(0, 60),
            )
    callees = {
        f"Func_{rng.randrange(TODO_FUNCTIONS)}": rng.randrange(1, 5) for _ in range(TODO_CALLEES)
    }
    return existing, size_by_va, name_by_va, verify, callees


def bench_todo_rank() -> dict[str, Any]:
    from rebrew.todo import _collect_active_functions, _rank_by_impact

    rng = random.Random(SEED)
    existing, size_by_va, name_by_va, verify, callees = _make_todo_inputs(rng)

    def run() -> list[Any]:
        return _rank_by_impact(
            _collect_active_functions(existing, size_by_va, name_by_va, verify, callees)
        )

    def summarize(ranked: list[Any]) -> tuple[int, dict[str, int], str]:
        counts: dict[str, int] = {}
        for item in ranked:
            counts[item.category] = counts.get(item.category, 0) + 1
        return (
            len(ranked),
            dict(sorted(counts.items())),
            _digest(
                [
                    f"{i.category}|{i.va}|{i.name}|{i.size}|{i.filename}|{i.roi_score!r}|{i.byte_delta}|"
                    f"{i.status}|{i.match_percent}|{i.impact_bytes}|{i.affected_functions}|"
                    f"{i.command}|{i.description}|{i.blocker}|{','.join(i.mutations)}"
                    for i in ranked
                ]
            ),
        )

    items, categories, digest = summarize(run())
    expected = EXPECTED["todo_rank"]
    assert (items, categories, digest) == (
        expected["items"],
        expected["categories"],
        expected["digest"],
    ), (items, categories, digest)
    out = measure(
        run,
        cache_state="warm: deferred imports and the angr probe primed by one untimed run",
    )
    out["dimensions"] = {
        "metadata_rows": len(existing),
        "verify_entries": len(verify),
        "verify_only_vas": TODO_VERIFY_ONLY,
        "source_files": TODO_FILES,
        "caller_counts": len(callees),
        "ranked_items": items,
        "categories": categories,
    }
    return out


# ---------------------------------------------------------------------------
# data_inventory
# ---------------------------------------------------------------------------


def _data_type(rng: random.Random) -> str:
    """A scalar or a sized array; array bounds give several hundred distinct spellings."""
    base = rng.choice(DATA_TYPES)
    if rng.randrange(3) == 0:
        return f"{base.split(' [')[0]} [{rng.randrange(1, 400)}]"
    return base


def _make_scan(rng: random.Random) -> tuple[Any, dict[str, dict[str, Any]]]:
    from rebrew.data_scan import GlobalEntry, ScanResult

    sections = {name: {"va": va, "size": size} for name, va, size in DATA_SECTIONS}
    scan = ScanResult()
    data_sections = [s for s in DATA_SECTIONS if s[0] != ".text"]
    for i in range(DATA_GLOBALS):
        name = f"g_Var{i}"
        pick = rng.randrange(20)
        if pick == 0:
            va = 0
        elif pick == 1:
            va = 0x7F000000 + i * 4  # misses every section
        else:
            _, base, size = data_sections[rng.randrange(len(data_sections))]
            va = base + rng.randrange(0, size - 64, 4)
        entry = GlobalEntry(
            name=name,
            va=va,
            type_str=_data_type(rng),
            annotated=bool(va) and i % 9 != 0,
            size=rng.choice((None, None, None, 4, 16, 64, 1024)),
        )
        for k in range(1 + (i % 3)):
            entry.declare(f"file_{(i + k) % 700}.c")
        if i % 4 == 0:
            entry.defined_in.append(f"file_{i % 700}.c")
        if i % 31 == 0:
            entry.library_owners.append({"member": "LIBCMT.LIB", "object": "crt0.obj"})
        scan.globals[name] = entry
    scan.type_conflicts = [
        {"name": f"g_Var{i}", "types": {"int": ["a.c"], "char": ["b.c"]}} for i in range(0, 600, 3)
    ]
    return scan, sections


def _reset_type_size_memo() -> None:
    """Clear the per-spelling size memo where the build has one."""
    from rebrew.data_layout import estimate_type_size

    clear = getattr(estimate_type_size, "cache_clear", None)
    if clear is not None:
        clear()


def bench_data_inventory() -> dict[str, Any]:
    from rebrew.data_render import section_summary
    from rebrew.data_scan import enrich_with_sections, verify_bss_layout

    rng = random.Random(SEED + 1)
    scan, sections = _make_scan(rng)

    def run() -> tuple[list[dict[str, Any]], list[tuple[str, int]], Any, dict[str, Any]]:
        for entry in scan.globals.values():
            entry.section = ""
        enrich_with_sections(scan, sections)
        # The cross-check execute_data performs before rendering the inventory.
        ranges = [
            (s["va"], s["va"] + s["size"])
            for s in sections.values()
            if s.get("va") and s.get("size")
        ]
        out_of_range = [
            (n, g.va)
            for n, g in scan.globals.items()
            if g.va and not any(lo <= g.va < hi for lo, hi in ranges)
        ]
        return (
            section_summary(scan, sections),
            out_of_range,
            verify_bss_layout(scan, sections),
            scan.to_dict(),
        )

    def summarize(
        result: tuple[list[dict[str, Any]], list[tuple[str, int]], Any, dict[str, Any]],
    ) -> tuple[int, int, int, int, int, str]:
        summary, out_of_range, bss, payload = result
        digest = _digest(
            [json.dumps(summary, sort_keys=True), json.dumps(bss.to_dict(), sort_keys=True)]
            + [json.dumps(payload["summary"], sort_keys=True)]
            + [f"{k}|{json.dumps(v, sort_keys=True)}" for k, v in payload["globals"].items()]
            + [f"{n}@{va}" for n, va in out_of_range]
        )
        return (
            len(summary),
            len(out_of_range),
            len(bss.known_entries),
            len(bss.gaps),
            bss.coverage_bytes,
            digest,
        )

    got = summarize(run())
    expected = EXPECTED["data_inventory"]
    assert got == (
        expected["sections"],
        expected["out_of_range"],
        expected["bss_entries"],
        expected["bss_gaps"],
        expected["bss_coverage_bytes"],
        expected["digest"],
    ), got
    out = measure(
        run,
        cache_state=(
            "cold: type-size memo cleared before every timed run (one CLI pass); "
            "deferred imports and the tree-sitter parser primed by one untimed run"
        ),
        reset=_reset_type_size_memo,
    )
    out["dimensions"] = {
        "globals": DATA_GLOBALS,
        "sections": len(sections),
        "type_conflicts": len(scan.type_conflicts),
        "summary_sections": got[0],
        "out_of_range": got[1],
        "bss_entries": got[2],
        "bss_gaps": got[3],
        "bss_coverage_bytes": got[4],
    }
    return out


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------

WORKLOADS: dict[str, Callable[[], dict[str, Any]]] = {
    "todo_rank": bench_todo_rank,
    "data_inventory": bench_data_inventory,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args(argv)
    results = {name: fn() for name, fn in WORKLOADS.items()}
    document = {
        "seed": SEED,
        "repeat": REPEAT,
        "python": sys.version.split()[0],
        "workloads": results,
    }
    if args.json:
        print(json.dumps(document, indent=2))
    else:
        for name, r in results.items():
            print(
                f"{name:16} cpu {r['cpu_median_seconds'] * 1000:9.2f} ms   "
                f"wall {r['wall_median_seconds'] * 1000:9.2f} ms   [{r['cache_state']}]"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
