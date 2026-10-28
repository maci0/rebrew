# Review follow-ups: 6.7.0

Fifty further independent hot-path reviews (051–100) covered 187 synthetic
load/cache/shape cases against v6.6.0 (`6b78453d`). Each review includes a
runnable benchmark, raw CPU/wall samples, output checks and a separate profile.
The supplemental experiment archive preserves that baseline evidence. This
release fixes all three reported correctness findings and implements the five
profiled performance follow-ups. A profile alone was not treated as a speedup.

## Correctness

- Review 067: concurrent atomic replacement could make a directory enumeration
  omit an existing coverage document. Directory metadata now guards the scan;
  a changed directory triggers another attempt. Three unsuccessful attempts
  produce a coverage error instead of an empty bootstrap or unbounded retry.
  A deterministic concurrent replacement test covers the race. Paired synthetic
  request runs observed empty bootstraps in 9/42 baseline responses and 0/42
  candidate responses. This is not a guarantee for arbitrary concurrent writers.
- Review 089: the C AST now identifies outer typedef declarators rather than
  stopping at an inner member. Overlapping field evidence fails before output;
  unaligned fields use byte arrays. Compiler offset tests cover gaps and
  alignment. Unreadable sources also stop recovery so missing declarations
  cannot silently become duplicate output. The target layout assumptions are
  documented in the CLI guide; conflicting evidence requires reconciliation.

## Production measurements

These are medians from at least five raw samples per case, with correctness
checks outside timers and full output hashes equal between baseline and
candidate. Times are process CPU milliseconds unless stated otherwise.
Fixtures use warm local caches. They are component measurements, not real-game
or whole-command speed claims; shared-host scheduling affects the samples.

| Review and workload | Baseline | Candidate |
|---|---:|---:|
| 054: 30 binding changes | 1,769 | 458 |
| 060: 2,000 override resolutions, 64 directories, depth 5 | 153 | 46 |
| 060: same calls/depth, 65 directories | 252 | 114 |
| 060: same calls/depth, 96 directories | 165 | 54 |
| 063: 240 catalog functions, disjoint extents | 139 | 89 |
| 063: same rows, dense overlapping extents | 1,487 | 96 |
| 063: dense branch-heavy extents | 1,584 | 1,585 |
| 075: 240 functions, 1,920 dependency edges | 254 | 78 |
| 066: 100 alternating-target fold iterations | 1.28 | 1.42 |

Binding batches reuse retirement validation only inside the current locked
document, updating that state after each change. Dependency graphs collect
function uses once per source while preserving file-scope references and
per-build source freshness. The catalog admission check only excludes byte
strings lacking relative jump opcodes; Capstone remains the authority. Tests
compare the filter against Capstone for jump classes, prefixes and randomized
bytes. The branch-heavy disjoint fixture showed about 4% overhead.

The project-root cache now evicts the least recently used entry and is bounded
at 256 directories. Configuration backend edits/removal/recreation and cache
eviction are tested. The existing discovered-root cache does not detect a new
closer project configuration during the same process; eviction is not an
invalidation mechanism. A fresh process discovers it normally.

Dashboard fold caches retain weak references and at most nine entries of folded
strings. At generation eight of the 1,600-function/1,600-global refresh fixture,
tracemalloc current allocation fell from 18.78 MB to 5.30 MB. This is tracked
allocation, not RSS; old folded strings remain bounded until eviction. Snapshot
identity checks still prevent stale results when object IDs are reused.

## Scope and reproduction

The original review archive and supplemental fix measurements contain the
scripts, raw samples, hashes, profiles and per-review omissions. Set
`REBREW_BENCH_BASELINE` to the checkout being measured and
`REBREW_BENCH_PYTHON` to its configured Python 3.15 contributor interpreter.
Run the scripts on private generated fixtures, never an active user project.
Some supplemental microbenchmarks state their own invocation in their README.

The other review profiles did not establish further safe, measured changes.
Required parsing, locking and freshness checks remain. Cold storage, actual
game corpora, live Ghidra and compiler execution were outside these synthetic
measurements. The full release gates validate behavior and packaging separately.
