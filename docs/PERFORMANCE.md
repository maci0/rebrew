# Rebrew Performance Notes

Measured facts about where rebrew's hot paths spend time, and what was done
(and deliberately *not* done) about it.

## GA scoring hot loop (`score_candidate`)

Profiled on 512-byte functions with 40 reloc offsets (5000 iterations):

| Component | Share of per-call time | Verdict |
|---|---|---|
| capstone disassembly | ≈ 40 % | C library; not vectorizable. The target side is pre-computed once per function (`precompute_target` → `_pre_norm_target`/`_pre_target_mnems`); per-candidate cost is dominated by the unavoidable candidate disassembly. |
| `difflib.SequenceMatcher` | ≈ 27 % | Scoring weights are calibrated to it; swapping it changes behavior. |
| numpy byte compare / prologue / reloc mask | ≈ 30 % | Already vectorized. A numpy fancy-indexing prototype for `_normalize_with_reloc_offsets` measured *slower* (0.7×) than the slice-assignment loop — do not "vectorize" it. |

### Fast paths (added, behavior-identical)

Two shortcuts skip work without approximating — both produce exactly the
scores the full computation would:

1. **Identical bytes** (`target_bytes == candidate_bytes`): every metric is
   zero except the prologue bonus, so the candidate disassembly and the numpy
   compares are skipped entirely.  Hits often in converged GA populations,
   where many members are byte-identical copies.
2. **Mnemonic-equality** (`target_mnems == cand_mnems`): the GA's common case
   is candidates that differ from the target only in immediates/reloc slots
   (`mov eax, 0x10` vs `mov eax, 0x20` — same mnemonics).  SequenceMatcher on
   equal lists emits exactly one `equal` opcode covering everything, so the
   shortcut skips difflib's O(n) setup.

**Measured:** 5000 mixed candidates (40 % identical, 30 % mnemonic-equal,
30 % arbitrary mutations) on a 512-byte function with 40 relocs:

- before: **0.669 s**
- after: **0.380 s** — **1.76× faster** wall-clock on the scoring loop.

The `_pre_*` contract is locked by `TestPrecomputedTarget` in
`tests/test_scoring.py`; the fast paths are covered by
`TestScoreFastPaths` (exact zero metrics, mnemonic-equality reference check,
and a differing-mnemonics case that must still be penalized).

## What was measured and rejected

- **Fancy-indexing reloc normalization** — 0.7× slower; kept the slice loop.
- **Replacing `SequenceMatcher`** — changes calibrated scoring; rejected.

## GA bottleneck: compilation, not scoring

Measured on smygb (512-byte function, real MSVC6 toolchain):

- one compile + byte-compare (`rebrew test`): **≈ 585 ms**
- one `score_candidate` call (reloc path, precomputed target): **≈ 0.36 ms**

Scoring is ~1600× cheaper than a compile, so the GA's wall-clock is
dominated by Wine/compiler subprocesses (which the compile cache
mitigates), not by the numpy/capstone scoring path. Future perf work on
the GA should target compile throughput (cache hit rate, parallel
compiles), not `score_candidate`.

## Idempotency

Every offline `--json` command is deterministic across runs — enforced by
`tools/check_idempotency.py` (16 commands, run twice, byte-compared) as a CI
step; see `docs/CI.md`.
