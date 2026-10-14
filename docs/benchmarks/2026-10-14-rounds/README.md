# Ten additional source-scan rounds (2026-10-14)

Baseline: `81a9ecbfd31c792810cc8f6eca169f36f1d127ab`, which commits the
preceding metadata performance work. Each round starts from the retained results
of the previous rounds. Round 7 was measured and reverted before round 8.

Each row combines eighteen process-CPU samples from two fresh processes per
variant, ordered before/after/after/before on CPU 0. Each process checks its
output, warms once more, measures nine times, then profiles outside the timed
region. Native pools are fixed to one thread. The same runner and output hashes
match across all four processes in every round. CPU time excludes descheduling;
frequency, caches and memory pressure can still affect it.

| Round | Workload | Before CPU ms | Candidate CPU ms | Ratio | Decision |
|---|---|---:|---:|---:|---|
| 1 | `parse_cache` | 2.911 | 0.687 | 4.23× | Retained |
| 2 | `signature_walk` | 16.977 | 13.446 | 1.26× | Retained |
| 3 | `mask_conventions` | 6.707 | 6.173 | 1.09× | Retained |
| 4 | `variable_text` | 19.380 | 19.709 | 0.98× | Retained |
| 5 | `anchor_comments` | 7.270 | 4.877 | 1.49× | Retained |
| 6 | `data_bindings` | 47.748 | 19.462 | 2.45× | Retained |
| 7 | `prototype_lines` | 1.850 | 2.199 | 0.84× | Reverted |
| 8 | `variable_lines` | 238.274 | 24.277 | 9.81× | Retained |
| 9 | `asm_tokens` | 5.589 | 3.890 | 1.44× | Retained |
| 10 | `pointer_names` | 14.378 | 10.564 | 1.36× | Retained |

1. The parse cache uses exact immutable byte keys, which are already retained with
   its trees. This removes 400 SHA-256 calls per batch while retaining per-thread
   isolation, the entry/size caps, eviction and exact-content matching.
2. Signature traversal visits named children; punctuation cannot contain a C
   definition. A deterministic test rejects punctuation traversal.
3. Literal checks skip convention/declspec regexes when no relevant token exists.
   Positive cases still run the original regexes. Separate short/large controls
   in `03-controls.json` show 2.12× for large plain C, 0.97× for large MSVC and
   0.91× for short MSVC fragments. The mixed row's small gain is informational.
4. Declaration flags decode only storage-class/declspec nodes. Profiled
   `node_text` calls fall from 14,700 to 400. CPU time is neutral; the simpler
   code avoids allocating unused text, and a regression budget checks that work.
5. Comment masking uses byte translation while retaining CR/LF, UTF-8 byte
   extents, AST-selected comments and binding errors.
6. Data bindings index exact module/address pairs, retaining ordered name checks
   for multiple views. `is_data` checks fall from 501,500 to 2,000. Newly appended
   aliases remain reusable; different names at one address remain separate views.
7. Lazy fallback line splitting adds state and showed no timing benefit. Reverted.
8. Variable inventory/filter lines use AST points instead of counting every
   preceding newline. Normalized assembly preserves line breaks in both inputs.
   This removes 6,000 prefix counts in the batch.
9. Assembly keywords compare directly as bytes. String/comment tokens, GNU asm,
   byte extents and unterminated-block handling retain their existing behavior.
10. Callback parameter walks reuse the declaration name already found.
    `_variable_name` calls fall from 12,600 to 6,300; nested callback types remain.

## Combined checks

The interleaved 18-workload cross-check (`suite-paired-*.json`) measured 1.15×
for annotation parsing, 1.14× for the 1,000-function binding tree, and 1.13× for
small binding scans. Unchanged controls range from 0.87× to 1.15×, so small ratios
are informational. The initial sequential `suite-before/after.json` reports
retain a host-load shift visible in unchanged controls; use the interleaved
reports to assess the combined change.

Guild's 100 largest C files still total 1,611,774 bytes and produce the same
binding digest `aedc20bfa674d7ec3def09f19dec3874a9199a084ab41e65ad9b2a1919bbebae`.
The interleaved scan measured 0.286 → 0.298 CPU seconds (essentially flat), with
profiled calls reduced from 891,074 to about 772,354 (13.3%). These targeted
synthetic wins therefore do not establish a faster whole-project Guild scan.
The scan is read-only; project sources, metadata and build products are untouched.

`tests/test_source_scan_hotpaths.py` supplies deterministic traversal/lookup work
budgets and correctness checks for content keys, eviction, surrogate bytes,
CRLF/Unicode comments, assembly-normalized line positions, data views and nested
callback types. Existing parser/binding/property tests cover the connected paths.
Validation results are recorded in `validation.json` after all gates finish.

## Reproduce the candidates

The `NN-candidate.patch` files preserve the exact measured changes, including the
rejected candidate. `NN-summary.json` records per-round before/after module hashes;
`manifest.json` records the final hashes. The separate formatting patch only
wraps conditions. Run the following from a contributor checkout with its venv
installed. It creates isolated source trees and writes new measurements under a
temporary directory; it does not change the checkout or the saved reports.

```bash
repo=$PWD
python="$repo/.venv/bin/python"
reports="$repo/docs/benchmarks/2026-10-14-rounds"
experiment=$(mktemp -d)
git archive 81a9ecbfd31c792810cc8f6eca169f36f1d127ab src | tar -x -C "$experiment"
for round in 01 02 03 04 05 06 07 08 09 10; do
    cp -a "$experiment/src" "$experiment/before-$round"
    (cd "$experiment" && git apply --unidiff-zero "$reports/$round-candidate.patch")
    workload=$("$python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["case"])' "$reports/$round-summary.json")
    sample=0
    for variant in before after after before; do
        source_dir="$experiment/src"
        if [ "$variant" = before ]; then source_dir="$experiment/before-$round"; fi
        PYTHONPATH="$source_dir:$repo" OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
            taskset -c 0 "$python" -m tools.bench_source_scans "$workload" \
            > "$experiment/$round-$sample-$variant.json"
        sample=$((sample + 1))
    done
    if [ "$round" = 07 ]; then
        (cd "$experiment" && git apply --unidiff-zero --reverse "$reports/$round-candidate.patch")
    fi
done
(cd "$experiment" && git apply --unidiff-zero "$reports/formatting.patch")
```

CPU 0/taskset is the Linux setup used for these reports; select an allowed CPU
on another machine. Raw reports contain all CPU/wall samples, output hashes,
runner hashes and profiled call counts. The suite reports additionally identify
Python/platform/revision; the manifest identifies the source actually loaded.
