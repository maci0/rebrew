# Fifty independent hot-path load reviews: 6.6.0

These are fifty fresh reviews of complete callable paths, not fifty inner-loop
candidate checks. Each uses its own deterministic fixture, three load sizes or
workload shapes, at least five CPU/wall timing samples, output assertions and
hashes, and a separately instrumented cumulative-time profile. The fixed
baseline is `c232a833` (the preliminary tuning changes were already applied).
No production source was edited while collecting these baseline reviews.

The supplemental release experiment archive contains `review-01` through
`review-50`, each with `benchmark.py`, `results.json`, `profile.txt`, and
`review.md`, plus required local helpers. It includes raw samples and exact
fixture/import/cache semantics. Its README explains reproduction. These are
research artifacts, separate from the CI-verified wheel, sdist and provenance.

The table summarizes the largest workload, not all samples. Most fixtures use a
warm local OS page cache; “cold” means a fresh object/cache/process only where
specified. Synthetic layouts, compiler surrogates and omitted stages are stated
in individual reports. Shared-host contention affected some results, so chosen
production patches were checked again with alternating baseline/candidate runs.
No component timing is claimed as a whole-command or real-project speedup.

| Review | Hot path | Result | Profile/load finding |
|---|---|---|---|
| 01 | data list scan | No change | 5,000 sources: 4.015 s warm wall. Metadata/root discovery and anchors dominate; no safe narrow patch. |
| 02 | map ownership | Keep | 5,000 globals: repeated library normalization. Kept per-call normalization reuse after alternating full-pipeline checks. |
| 03 | data verification | Deferred | 5,000 rows: 112.8 ms warm wall; reuse candidate 97.3 ms but unstable and changes metadata-read timing. Deferred. |
| 04 | private placement | No change | 5,000 object placements: 101.1 ms warm wall. COFF evidence and map parsing dominate; no change. |
| 05 | data layout audit | Keep | 1,500 layout objects: 1.246 s → 0.071 s prototype; production dry-run early-out validated, keeping read errors. |
| 06 | status accounting | Deferred | 3,000 rows: 180 ms warm wall. Prefix interval prototype not production-ready; deferred. |
| 07 | todo planning | No change | 5,000 functions: 115 ms warm wall. Verification deepcopy and selection dominate; no change. |
| 08 | catalog grid | No change | 5,000 registry rows: 428 ms warm wall. Reversed/global source scans dominate; no narrow patch. |
| 09 | coverage project | No change | 3,000 functions: warm rebuild 581 ms, unchanged refresh 4 ms, fresh process 1.30 s. No change. |
| 10 | coverage documents | No change | 4,500 functions/3 targets: cold-object load 356 ms; render/history 172 ms; warm load 22 µs. TOML dominates. |
| 11 | source discovery | No change | 5,000 files: combined discovery about 63 ms. Sorting/path checks and shared-root walks dominate; no change. |
| 12 | source bindings | No change | 400 mixed source files: 132 ms warm wall. Metadata/root lookup repeats; no shortcut without freshness equivalence. |
| 13 | metadata read | No change | 5,000 rows/100 fragments: cold TOML 161 ms, disk cache 16 ms, warm read-only 0.53 ms. No change. |
| 14 | metadata write | No change | 5,000 rows/20 fragments: function bulk write 3.70 s, data 5.32 s. Parsing/copying dominate; no safe change. |
| 15 | source provenance | Deferred | 1,000 helpers: 183 ms → 137 ms purpose-index prototype. Mid-scan freshness would change; deferred. |
| 16 | rename plan | No change | 1,500 shared-target sources: rename preview 162 ms. Provider bindings/path resolution dominate; no change. |
| 17 | named inline | Keep | 360 names/30 files: occurrence-index prototype 170 ms → 83 ms. Kept indexed repeated queries after byte-boundary/freshness tests. |
| 18 | remaining strings | No change | 400 files/6,400 tokens: 30.8 ms dry run. Rendering shortcut slower; rejected. |
| 19 | cmake source selection | Deferred | 1,500 shared files/two targets: 2.70 s baseline. Purpose snapshot prototype changes mid-selection freshness; deferred. |
| 20 | source contract audit | No change | 300 independent units: 248 ms contract audit. Repeated bindings/selection dominate; no safe change. |
| 21 | include closure | No change | 4,000 headers: direct 103 ms, cold memo 143 ms, warm memo 14 ms. Path/stat checks preserve invalidation; no change. |
| 22 | compile cache | No change | 1,500 diskcache objects: persistent writes dominate. Seven samples, reopened reads and eviction checks; no safe change. |
| 23 | cmake cache | No change | 500 headers: hit 76 ms. Three guarded snapshots dominate; rechecks protect changes during staging, so retained. |
| 24 | verify cache | No change | 1,500 verification rows: fingerprint 100 ms, save 26 ms, load 35 ms. No freshness-weakening cache. |
| 25 | compile planning | No change | 400 comparisons with compiler surrogate: warm 113 ms, cold-object 259 ms. Key/header checks and temporary I/O dominate. |
| 26 | ga scoring | No change | 1,500 mixed GA candidates: 160 ms warm wall. SequenceMatcher alignment dominates; scoring unchanged. |
| 27 | mutation engine | No change | 400-statement mutation chain: 52 ms cold memo. Validation/query/parsing dominate; no safe simplification. |
| 28 | matching diff | No change | 5,000 mixed diff pairs: cold 528 ms, warm 232 ms. Register-mask detail decoding dominates; existing cache retained. |
| 29 | beam statement search | Correctness fix | 5,000 qualifier previews: 22.5 ms CPU, roughly linear. Fixed malformed extra variant for already-volatile declarations. |
| 30 | matching batch | No change | Population 64/three generations: 100 ms wall with compile surrogate. Mutation/validation dominate; no change. |
| 31 | import reader | No change | 5,000 PE32/PE32+ imports/stubs: cold-object 10–17 ms, warm 3–6 ms. No further optimization. |
| 32 | archive reader | Keep | 5,000 NUL-only archive names exposed quadratic suffix scanning: 783 ms → 10 ms prototype. Kept first-delimiter search. |
| 33 | coff reader | Keep | 1,500 relocations/3,001 symbols: 89 ms → 10 ms prototype. Kept linear ambiguity validation with adversarial cases. |
| 34 | binary loader | No change | PE/ELF loads and 5,000 repeated reads: fingerprint/path checks dominate repeats; no unsafe cache. |
| 35 | ne analysis | Keep | 256 NE segments: repeated rebuilt window sets dominate. Kept one set per comparison, with edge-equivalence tests. |
| 36 | library exact | No change | 1,500 archive bodies/200 queries: matching 123 ms. Early four-byte shortcut slower; rejected. |
| 37 | library prefix | No change | 1,700 bodies/100 unknown-size queries: 58 ms warm wall. Masks/order constrain secondary indexing; no change. |
| 38 | flirt index | No change | 5,000 FLIRT hits: 3.97 s wall. Function-size disassembly dominates; no unvalidated architecture shortcut. |
| 39 | symbol resolution | No change | 1,500 wrappers: 117 ms wall. Repeated native binary lookups dominate; freshness/error semantics prevent blind caching. |
| 40 | fingerprint similarity | No change | 2,159,428 similarity pairs: 131 ms wall with single-thread BLAS. Quadratic matrix memory remains a limit; no change. |
| 41 | binsync read | Keep | 3,000 BinSync functions: 1.151 s → 0.269 s prototype. Kept first-match identity/comment-owner indexes. |
| 42 | binsync reconcile | Deferred | 1,500 reconciliation rows: reuse-health simulation 191 ms → 98 ms, but removes a freshness observation; deferred. |
| 43 | ghidra plan | Keep | 1,000 export functions: 398 ms → 368 ms prototype. Kept exact first-VA index; tested missing-key/removal behavior. |
| 44 | cross import | Keep | 5,000 relocation bindings: 383 ms → 265 ms prototype. Kept read-only receipt metadata view after cache-isolation tests. |
| 45 | decompiler intake | Keep | 5,000 discovered functions: 821 ms → 577 ms prototype. Kept counted starts, preserving deletion/insertion/duplicates. |
| 46 | dashboard search | No change | 10,000 dashboard functions/six requests: cold 429 ms, warm 54 ms; noisy. Parsing/scan/sort dominate; no shortcut. |
| 47 | dashboard coverage | Correctness fix | 5,000 functions+globals: refresh 438 ms, warm three-route request 1 ms. Fixed snapshot-ID cache reuse; sort shortcut rejected. |
| 48 | html report | No change | 5,000-function HTML report: 1.96 s warm wall. zstd compression and graph construction dominate; no change. |
| 49 | cli startup | No change | Fresh root/status help and skills list: about 341–358 ms child CPU. Imports/Typer construction dominate; no safe remounting change. |
| 50 | config registry | Correctness fix | Config and actual dist-info refresh: found stale in-place entry-point edits. Explicit refresh now forces rediscovery; normal lookup cache retained. |

## Production remeasurement

These medians are process CPU milliseconds, measured with full pipeline output
equality and five to seven alternating baseline/candidate samples. The earlier
review figures can differ because of fixture details and host contention.

| Pipeline | Small / medium / large load | Baseline CPU ms | Production CPU ms |
|---|---|---|---|
| Layout fill dry run | 100 / 500 / 1,500 objects | 7.59 / 329.09 / 1,128.24 | 2.35 / 9.75 / 47.71 |
| Ownership enrichment | 100 / 1,000 / 5,000 globals | 1.52 / 14.55 / 71.90 | 1.25 / 12.05 / 66.00 |
| NUL archive names, two reads | 100 / 1,000 / 5,000 members | 0.54 / 33.06 / 766.75 | 0.26 / 2.28 / 12.61 |
| COFF evidence | 100 / 500 / 1,500 relocations | 0.93 / 11.29 / 86.18 | 0.43 / 2.85 / 12.33 |
| Named inlining | 1 / 30 / 300 names | 0.50 / 8.19 / 167.25 | 0.53 / 7.03 / 40.38 |
| NE comparison | 8 / 64 / 256 segments | 7.18 / 89.64 / 441.09 | 5.32 / 54.75 / 335.61 |
| Discovery | 100 / 1,000 / 5,000 functions | 10.10 / 106.73 / 721.37 | 10.29 / 98.22 / 493.92 |
| BinSync projection | 100 / 1,000 / 3,000 functions | 8.97 / 169.65 / 1,058.99 | 7.66 / 79.10 / 262.30 |
| BinSync export planning | 100 / 500 / 1,000 functions | 28.84 / 130.29 / 355.66 | 25.99 / 132.64 / 271.45 |
| Relocation catalog | 100 / 1,000 / 5,000 functions | 3.15 / 46.71 / 314.51 | 3.46 / 38.87 / 208.79 |

Small workloads sometimes regress slightly. Mixed archive delimiters cost about
0.02–0.72 ms more per two reads in the tested cases, while eliminating the NUL
quadratic case. Repeated string queries build a token-count index after the
third ASCII query and add memory proportional to distinct source words. Map and
identity indexes add memory proportional to input size and are operation-local.
Dashboard fold caches now retain a bounded set of snapshots to prevent ID reuse.
Explicit plugin refresh costs about 2.3 ms more in its benchmark because it must
rediscover metadata; normal discovery caching remains unchanged.

The preliminary changes also reduce repeated suffix classification, include
scanning, metadata validation, source-tail copying, cache-volume reads, path
resolution, short-instruction normalization, map filtering, interval accounting,
sparse string-owner counts, library matching and ASCII search folding. Their
component experiments are supplementary evidence, not part of this fifty-review
count.

Full release gates validate the combined changes after integration. Actual
compiler/image execution, live Ghidra/BinSync writes, cold storage, all possible
plugins and production-game performance remain outside these synthetic reviews.
