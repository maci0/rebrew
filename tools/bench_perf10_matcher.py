"""Two load-independent matcher microbenchmarks on seeded synthetic inputs.

``binary_similarity_aggregate``
    :func:`rebrew.binary_similarity.aggregate_similarity` over a rectangular
    set of signature records (mnemonic histograms, call and branch counts).
``score_candidate_heuristic``
    :func:`rebrew.matcher.scoring.score_candidate` without reloc offsets, with
    the target precomputed, over mutated copies of one x86-32 function (the
    heuristic normalization + mnemonic alignment path of the GA hot loop).

Imports and fixture construction are outside the timed region.  The primary
clock is ``time.process_time_ns``; ``perf_counter_ns`` is sampled alongside.
Both results are checked against a SHA-256 of the canonical result, so a
change that alters output (or an input that degenerates into a no-op) fails.

Usage::

    python tools/bench_perf10_matcher.py --json
"""

from __future__ import annotations

import os
lazy import argparse
lazy import hashlib
lazy import json
lazy import math
lazy import random
lazy import statistics
lazy import struct
lazy import sys
lazy import time
lazy from collections.abc import Callable
lazy from typing import Any

# One BLAS thread: process_time sums every thread's CPU, and spinning workers
# on a loaded host inflate it.  Set before numpy is first imported.
for _var in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ[_var] = "1"

SEED = 20261029
SAMPLES = 9
WARMUP_RUNS = 1

# binary_similarity_aggregate dimensions
SIG_FUNCS_A = 1400
SIG_FUNCS_B = 1100
SIG_VOCAB = 320
SIG_MNEMONICS_PER_FUNC = (6, 40)
SIG_COUNT_MAX = 12
SIG_LOW_COUNT = 10
SIG_REFERENCE_ROWS = 12

# score_candidate_heuristic dimensions
TARGET_SIZES = (30, 60, 120, 200, 320, 480)  # instructions per target function
CANDIDATES_PER_TARGET = 60
MUTATION_FRACTION = (0.01, 0.2)  # share of a function's instructions edited per candidate
X86_ADDR_BASE = 0x10000000

EXPECTED_DIGEST = {
    "binary_similarity_aggregate": "b68d79de9a0c597c090defc2a001ced3d30cbec5ea6049585723069739ba3cb6",
    "score_candidate_heuristic": "9143d17d8bc77b307798e2c8d8bf9d88e97aa7be7d17a43ad44d62c184654f4b",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _build_signature_funcs(rng: random.Random, n: int, base_va: int) -> list[dict[str, Any]]:
    vocab = [f"op{i}" for i in range(SIG_VOCAB)]
    funcs: list[dict[str, Any]] = []
    for i in range(n):
        names = rng.sample(vocab, rng.randint(*SIG_MNEMONICS_PER_FUNC))
        funcs.append(
            {
                "va": base_va + i * 0x40,
                "size": rng.randint(16, 4096),
                "name": f"fn_{base_va:x}_{i}",
                "signature": {
                    "histogram": {m: rng.randint(1, 9) for m in names},
                    "calls": rng.randint(0, SIG_COUNT_MAX),
                    "branches": rng.randint(0, SIG_COUNT_MAX),
                },
            }
        )
    # undecodable functions are skipped by the aggregator; keep a few so that path runs
    for k in range(0, n, 97):
        funcs[k]["signature"] = None
    return funcs


def _addr(rng: random.Random) -> bytes:
    return struct.pack("<I", X86_ADDR_BASE + rng.randrange(0, 0x100000))


def _insn(rng: random.Random) -> bytes:
    """One random x86-32 instruction; several carry address-like fields."""
    kind = rng.randrange(14)
    reg = rng.randrange(8)
    if kind == 0:
        return b"\xe8" + _addr(rng)  # call rel32
    if kind == 1:
        return b"\xa1" + _addr(rng)  # mov eax, [abs32]
    if kind == 2:
        return b"\x68" + _addr(rng)  # push imm32
    if kind == 3:
        return bytes([0xB8 + reg]) + _addr(rng)  # mov reg, imm32
    if kind == 4:
        return b"\xff\x15" + _addr(rng)  # call [abs32]
    if kind == 5:
        return bytes([0x8B, 0x05 | (reg << 3)]) + _addr(rng)  # mov reg, [abs32]
    if kind == 6:
        return bytes([0x8D, 0x04 | (reg << 3), 0x85 | (rng.randrange(8) << 3)]) + _addr(rng)
    if kind == 7:
        return b"\x0f" + bytes([0x80 + rng.randrange(16)]) + _addr(rng)  # jcc near
    if kind == 8:
        return bytes([0x8B, 0xC0 | (reg << 3) | rng.randrange(8)])  # mov reg, reg
    if kind == 9:
        return bytes([0x83, 0xC0 | rng.randrange(8), rng.randrange(1, 100)])  # add reg, imm8
    if kind == 10:
        return bytes([0x8B, 0x45 | (reg << 3), rng.randrange(256)])  # mov reg, [ebp+d8]
    if kind == 11:
        return bytes([0x50 + reg])  # push reg
    if kind == 12:
        return bytes([0x74, rng.randrange(1, 100)])  # jz short
    return bytes([0x3B, 0xC0 | (reg << 3) | rng.randrange(8)])  # cmp reg, reg


def _build_scoring_inputs(rng: random.Random) -> list[tuple[bytes, list[bytes]]]:
    """One ``(target, candidates)`` pair per entry of :data:`TARGET_SIZES`."""
    pairs: list[tuple[bytes, list[bytes]]] = []
    for size in TARGET_SIZES:
        insns = [_insn(rng) for _ in range(size)]
        target = b"\x55\x8b\xec" + b"".join(insns) + b"\x5d\xc3"
        candidates: list[bytes] = []
        for _ in range(CANDIDATES_PER_TARGET):
            mutated = list(insns)
            edits = max(1, round(size * rng.uniform(*MUTATION_FRACTION)))
            for _m in range(edits):
                slot = rng.randrange(len(mutated))
                op = rng.randrange(3)
                if op == 0:
                    mutated[slot] = _insn(rng)  # replace
                elif op == 1:
                    mutated.insert(slot, _insn(rng))  # insert
                elif len(mutated) > 1:
                    del mutated[slot]  # delete
            candidates.append(b"\x55\x8b\xec" + b"".join(mutated) + b"\x5d\xc3")
        pairs.append((target, candidates))
    return pairs


# ---------------------------------------------------------------------------
# Workloads: each returns (dimensions, cache_state, callable, canonical, verify)
# ---------------------------------------------------------------------------


def _canonical_digest(obj: Any) -> str:
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def _reference_score(sa: dict[str, Any], sb: dict[str, Any]) -> float:
    """Pure-python restatement of the size-less structural score (0-100)."""
    ha, hb = sa["histogram"], sb["histogram"]
    na = math.sqrt(sum(c * c for c in ha.values()))
    nb = math.sqrt(sum(c * c for c in hb.values()))
    cos = sum(c * hb.get(m, 0) for m, c in ha.items()) / (na * nb) if na and nb else 0.0

    def ratio(x: int, y: int) -> float:
        if x == y:
            return 1.0
        return min(x, y) / max(x, y) if max(x, y) else 0.0

    return (
        0.6 * min(1.0, cos) * 100
        + 0.2 * ratio(sa["calls"], sb["calls"]) * 100
        + 0.2 * ratio(sa["branches"], sb["branches"]) * 100
    )


def _workload_binary_similarity() -> dict[str, Any]:
    from rebrew.binary_similarity import aggregate_similarity, score_matrix

    rng = random.Random(SEED)
    funcs_a = _build_signature_funcs(rng, SIG_FUNCS_A, 0x401000)
    funcs_b = _build_signature_funcs(rng, SIG_FUNCS_B, 0x501000)
    sigs_a = [f["signature"] for f in funcs_a if f["signature"] is not None]
    sigs_b = [f["signature"] for f in funcs_b if f["signature"] is not None]

    def run() -> dict[str, Any]:
        return aggregate_similarity(funcs_a, funcs_b, low_count=SIG_LOW_COUNT)

    def verify(result: dict[str, Any]) -> None:
        assert result["functions_a"] == len(sigs_a) < SIG_FUNCS_A
        assert result["functions_b"] == len(sigs_b) < SIG_FUNCS_B
        assert len(result["low"]) == SIG_LOW_COUNT
        # not a no-op: scores spread across several buckets
        assert sum(1 for b in result["buckets"] if b["count"]) >= 2, result["buckets"]
        # independent pure-python check of full score rows
        matrix = score_matrix(sigs_a[:SIG_REFERENCE_ROWS], sigs_b)
        assert matrix.shape == (SIG_REFERENCE_ROWS, len(sigs_b))
        for i in range(SIG_REFERENCE_ROWS):
            for j in range(0, len(sigs_b), 7):
                ref = _reference_score(sigs_a[i], sigs_b[j])
                assert abs(float(matrix[i, j]) - ref) < 1e-5, (i, j, matrix[i, j], ref)

    return {
        "name": "binary_similarity_aggregate",
        "dimensions": {
            "funcs_a": SIG_FUNCS_A,
            "funcs_b": SIG_FUNCS_B,
            "scored_a": len(sigs_a),
            "scored_b": len(sigs_b),
            "vocab": SIG_VOCAB,
            "mnemonics_per_func": list(SIG_MNEMONICS_PER_FUNC),
            "pairs": len(sigs_a) * len(sigs_b),
            "seed": SEED,
        },
        "cache_state": "warm: numpy imported and one untimed call made; the kernel keeps no cross-call cache",
        "run": run,
        "verify": verify,
    }


def _workload_score_candidate() -> dict[str, Any]:
    from rebrew.matcher.scoring import precompute_target, score_candidate

    rng = random.Random(SEED + 1)
    cases = [
        (target, candidates, *precompute_target(target))
        for target, candidates in _build_scoring_inputs(rng)
    ]
    total = len(TARGET_SIZES) * CANDIDATES_PER_TARGET

    def run() -> list[list[float]]:
        out: list[list[float]] = []
        for target, candidates, norm_target, target_mnems in cases:
            for cand in candidates:
                sc = score_candidate(
                    target, cand, _pre_norm_target=norm_target, _pre_target_mnems=target_mnems
                )
                out.append(
                    [
                        sc.length_diff,
                        sc.byte_score,
                        sc.reloc_score,
                        round(sc.mnemonic_score, 9),
                        sc.prologue_bonus,
                    ]
                )
        return out

    def verify(result: list[list[float]]) -> None:
        assert len(result) == total
        assert all(c != t for t, cands, *_ in cases for c in cands)
        # not a no-op: both byte-level and mnemonic-level differences are scored
        assert sum(1 for r in result if r[2] > 0) > total // 2
        assert sum(1 for r in result if r[3] > 0) > total // 5
        assert len({tuple(r) for r in result}) > total // 2

    return {
        "name": "score_candidate_heuristic",
        "dimensions": {
            "target_insns": list(TARGET_SIZES),
            "target_bytes": [len(c[0]) for c in cases],
            "candidates_per_target": CANDIDATES_PER_TARGET,
            "candidates": total,
            "mutation_fraction": list(MUTATION_FRACTION),
            "reloc_offsets": None,
            "seed": SEED + 1,
        },
        "cache_state": (
            "warm: per-thread capstone handles built by the untimed warm-up and the targets "
            "precomputed; score_candidate memoizes nothing per candidate"
        ),
        "run": run,
        "verify": verify,
    }


WORKLOADS: tuple[Callable[[], dict[str, Any]], ...] = (
    _workload_binary_similarity,
    _workload_score_candidate,
)


# ---------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------


def _measure(wl: dict[str, Any]) -> dict[str, Any]:
    run: Callable[[], Any] = wl["run"]
    first = run()
    for _ in range(WARMUP_RUNS - 1):
        run()
    wl["verify"](first)
    digest = _canonical_digest(first)
    expected = EXPECTED_DIGEST[wl["name"]]
    if expected:
        assert digest == expected, f"{wl['name']}: result digest {digest} != {expected}"
    cpu: list[int] = []
    wall: list[int] = []
    for _ in range(SAMPLES):
        c0, w0 = time.process_time_ns(), time.perf_counter_ns()
        result = run()
        c1, w1 = time.process_time_ns(), time.perf_counter_ns()
        assert _canonical_digest(result) == digest, f"{wl['name']}: result changed between runs"
        cpu.append(c1 - c0)
        wall.append(w1 - w0)
    return {
        "dimensions": wl["dimensions"],
        "cache_state": wl["cache_state"],
        "result_sha256": digest,
        "cpu_ns": {"median": int(statistics.median(cpu)), "samples": cpu},
        "wall_ns": {"median": int(statistics.median(wall)), "samples": wall},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args(argv)

    results: dict[str, Any] = {}
    for build in WORKLOADS:
        wl = build()
        results[wl["name"]] = _measure(wl)
    doc = {"python": sys.version.split()[0], "clock": "process_time_ns", "workloads": results}
    if args.json:
        print(json.dumps(doc, indent=2))
    else:
        for name, r in results.items():
            print(
                f"{name}: cpu median {r['cpu_ns']['median'] / 1e6:.1f} ms, "
                f"wall median {r['wall_ns']['median'] / 1e6:.1f} ms"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
