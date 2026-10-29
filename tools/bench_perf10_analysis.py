"""bench_perf10_analysis.py — load-independent microbenchmarks of two analysis kernels.

1. ``depgraph_build``: ``rebrew.depgraph.build_graph`` over a synthetic source tree.
2. ``struct_extract_recover``: ``extract_structs_from_file`` over a synthetic header,
   then ``parse_decomp_for_structs`` + ``synthesize_struct`` over synthetic decompilations.

Inputs come from a fixed seed. Imports and fixture creation sit outside the timed
region; CPU time (``process_time_ns``) is the primary clock, wall time is recorded
beside it. Every workload asserts exact results so a no-op cannot pass.

    python tools/bench_perf10_analysis.py            # table
    python tools/bench_perf10_analysis.py --json     # one JSON document
"""

from __future__ import annotations

lazy import argparse
lazy import json
lazy import random
lazy import statistics
lazy import sys
lazy import tempfile
lazy import time
lazy from collections.abc import Callable
lazy from pathlib import Path
lazy from typing import Any

SEED = 20260629
REPEAT = 9

DEP_FILES = 120
DEP_FUNCS_PER_FILE = 4
DEP_EXTERNS_PER_FILE = 24

STRUCT_COUNT = 400
STRUCT_FIELDS = 8
DECOMP_FUNCS = 300
DECOMP_ACCESSES = 24
DECOMP_TYPES = 12


def measure(fn: Callable[[], Any], *, cache_state: str, repeat: int = REPEAT) -> dict[str, Any]:
    """Run *fn* once untimed, then *repeat* timed runs; keep CPU and wall samples."""
    fn()
    cpu: list[float] = []
    wall: list[float] = []
    for _ in range(repeat):
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


# ---------------------------------------------------------------------------
# depgraph_build
# ---------------------------------------------------------------------------


def _make_dep_tree(root: Path, rng: random.Random) -> tuple[int, int]:
    """Write DEP_FILES sources; return (function count, expected edge count)."""
    names = [f"Func_{i}_{j}" for i in range(DEP_FILES) for j in range(DEP_FUNCS_PER_FILE)]
    edges = 0
    for i in range(DEP_FILES):
        callees = rng.sample(names, DEP_EXTERNS_PER_FILE)
        lines = [f"extern int __cdecl {name}(int);" for name in callees]
        bodies = []
        for j in range(DEP_FUNCS_PER_FILE):
            va = 0x10001000 + (i * DEP_FUNCS_PER_FILE + j) * 0x100
            mine = callees[j::DEP_FUNCS_PER_FILE]
            calls = " ".join(f"{c}(a);" for c in mine)
            bodies.append(
                f"/* ADDRESS: SERVER 0x{va:08x} */\n"
                f"int __cdecl Func_{i}_{j}(int a) {{ {calls} return a; }}\n"
            )
        (root / f"file_{i}.c").write_text(
            "\n".join(lines) + "\n\n" + "\n".join(bodies), encoding="utf-8"
        )
        edges += DEP_EXTERNS_PER_FILE * DEP_FUNCS_PER_FILE
    return len(names), edges


def bench_depgraph_build() -> dict[str, Any]:
    from rebrew.depgraph import build_graph

    rng = random.Random(SEED)
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        funcs, _ = _make_dep_tree(root, rng)

        def run() -> tuple[int, int]:
            nodes, edges, dispatch = build_graph(root)
            assert not dispatch
            return len(nodes), len(edges)

        got = run()
        expected = EXPECTED["depgraph_build"]
        assert got == tuple(expected), (got, expected)
        out = measure(
            run, cache_state="warm: process-level C syntax caches primed by one untimed run"
        )
        out["dimensions"] = {
            "files": DEP_FILES,
            "functions": funcs,
            "externs_per_file": DEP_EXTERNS_PER_FILE,
            "nodes": got[0],
            "edges": got[1],
        }
        return out


# ---------------------------------------------------------------------------
# struct_extract_recover
# ---------------------------------------------------------------------------

_TYPES = ["char", "short", "int", "double"]
_WIDTH = {"char": 1, "short": 2, "int": 4, "double": 8}


def _make_header(path: Path, rng: random.Random) -> None:
    parts = []
    for s in range(STRUCT_COUNT):
        fields = "\n".join(f"    {rng.choice(_TYPES)} field_{k:x};" for k in range(STRUCT_FIELDS))
        if s % 2:
            parts.append(f"typedef struct S{s}_s {{\n{fields}\n}} S{s};\n")
        else:
            parts.append(f"struct T{s} {{\n{fields}\n}};\n")
        parts.append(f"typedef unsigned int Alias{s};\n")
    path.write_text("\n".join(parts), encoding="utf-8")


def _make_decomps(rng: random.Random) -> list[str]:
    texts = []
    for f in range(DECOMP_FUNCS):
        lines = [
            f"void func_{f}(Type{f % DECOMP_TYPES} *this, short *a0, void *raw, int v1) {{",
            f"  pOther = (Other{f % DECOMP_TYPES} *)raw;",
        ]
        for _ in range(DECOMP_ACCESSES):
            kind = rng.randrange(6)
            off = rng.randrange(0, 0x200, 4)
            if kind == 0:
                lines.append(f"  this->field_{off:x} = 1;")
            elif kind == 1:
                lines.append(f"  *(int *)(this + 0x{off:x}) = v1;")
            elif kind == 2:
                lines.append(f"  *(short *)&a0[{off // 2}] = 2;")
            elif kind == 3:
                lines.append(f"  v1 = a0[0x{off // 2:x}];")
            elif kind == 4:
                lines.append(f"  *(short *)(raw + {off}) = 3;")
            else:
                lines.append(f"  raw->field_{off:x} = v1;")
        lines.append("}")
        texts.append("\n".join(lines))
    return texts


def bench_struct_extract_recover() -> dict[str, Any]:
    from rebrew.struct_parser import extract_structs_from_file
    from rebrew.struct_recover import parse_decomp_for_structs, synthesize_struct

    rng = random.Random(SEED + 1)
    decomps = _make_decomps(rng)
    with tempfile.TemporaryDirectory() as d:
        header = Path(d) / "types.h"
        _make_header(header, rng)

        def run() -> tuple[int, int, int, int]:
            structs = list(extract_structs_from_file(header))
            named = 0
            anon = 0
            rendered = 0
            for text in decomps:
                result = parse_decomp_for_structs(text)
                named += len(result.named)
                anon += len(result.anonymous)
                for name, ev in result.named.items():
                    if ev.offsets:
                        try:
                            synthesize_struct(name, ev.offsets)
                            rendered += 1
                        except ValueError:
                            pass
            return len(structs), named, anon, rendered

        got = run()
        expected = EXPECTED["struct_extract_recover"]
        assert got == tuple(expected), (got, expected)
        out = measure(
            run,
            cache_state="warm: tree-sitter parser and compiled regexes primed by one untimed run",
        )
        out["dimensions"] = {
            "header_structs": STRUCT_COUNT,
            "decompilations": DECOMP_FUNCS,
            "accesses_per_decomp": DECOMP_ACCESSES,
            "extracted_structs": got[0],
            "named_bases": got[1],
            "anonymous_vars": got[2],
            "synthesized": got[3],
        }
        return out


# Exact results with SEED; set after the first baseline run and identical for every revision.
EXPECTED: dict[str, tuple[int, ...]] = {
    "depgraph_build": (480, 2874),
    "struct_extract_recover": (400, 600, 300, 600),
}

WORKLOADS: dict[str, Callable[[], dict[str, Any]]] = {
    "depgraph_build": bench_depgraph_build,
    "struct_extract_recover": bench_struct_extract_recover,
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()
    results = {name: fn() for name, fn in WORKLOADS.items()}
    doc = {"seed": SEED, "repeat": REPEAT, "python": sys.version.split()[0], "workloads": results}
    if args.json:
        print(json.dumps(doc, indent=2))
        return
    for name, r in results.items():
        print(
            f"{name:26} cpu {r['cpu_median_seconds'] * 1000:9.2f} ms  "
            f"wall {r['wall_median_seconds'] * 1000:9.2f} ms  {r['dimensions']}"
        )


if __name__ == "__main__":
    main()
