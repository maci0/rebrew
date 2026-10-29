# Ten hotpath microbenchmarks

Ten deterministic synthetic workloads compare baseline `d598d5ec15a1` with the retained changes. Imports and fixture creation are outside the timers. Each workload checks results against generated expectations or a pinned digest; cache state and dimensions accompany every report.

The primary clock is `process_time_ns`; `perf_counter_ns` wall samples are also retained. Each script warms once, then records nine samples. Final runs were sequential in before/after/after/before order (18 CPU samples per revision per workload), with BLAS limited to one thread. [Raw reports, medians and candidate source hashes](PERFORMANCE_TEN_HOTPATHS.json) preserve the measurements.

CPU time excludes descheduling; it does not make a shared host immune to frequency changes, cache contention or garbage-collection effects. The unchanged controls varied substantially. Their ratios are not speedups, and small differences, including metadata loading, remain unconfirmed. These component timings do not establish whole-command gains.

| Workload | Input | Before CPU ms | After CPU ms | Interpretation |
|---|---|---:|---:|---|
| `depgraph_build` | 120 files, 480 functions, 2,874 edges | 132.06 | 118.84 | Retained: fewer AST walks |
| `struct_extract_recover` | 400 structs and 300 decompilations | 56.02 | 56.41 | Unchanged control |
| `archive_members` | 6,000 archive members | 44.92 | 40.19 | Unchanged control |
| `omf16_relocs` | 500 functions/object, code and relocation checks | 267.59 | 133.10 | Retained: buffer and per-thread handle reuse |
| `metadata_cold_load_validate` | 7,200 rows, four physical files | 809.35 | 781.09 | Small/unconfirmed gain; fewer copies |
| `binding_resolution_inventory` | 500 sources, 5,000 bindings | 142.80 | 99.15 | Unchanged control |
| `todo_rank` | 24,000 metadata rows, 19,173 todo items | 314.16 | 290.51 | Retained: one prover probe per collection |
| `data_inventory` | 12,000 globals, four sections | 185.51 | 92.96 | Retained: bounded type-size memo |
| `binary_similarity_aggregate` | 1,400 by 1,100 signature records | 84.16 | 47.19 | Retained: fewer matrix temporaries |
| `score_candidate_heuristic` | 30–480 instructions, 360 candidates | 840.01 | 416.09 | Retained: bounded match-run table |

## Retained changes

- Dependency graphs keep callee lists instead of reparsing generated declarations. `find_variable_roles` can collect global and per-function uses together; existing return values and filters are preserved.
- OMF decoding accumulates code in a bytearray, preserving gap fill, overlaps and record order. Printable-name checks use one compiled expression. Capstone handles are reused per thread.
- Metadata validation avoids copying every discarded fragment result, then makes one owned copy after the read. Custom backends may retain documents; callers cannot mutate those documents through cached rows. Known lowercase fields take a set lookup, with the original validation retained as fallback.
- Todo collection probes prover availability once on demand. A bounded 4,096-entry memo reuses context-free x86-32 declared type sizes; the data benchmark clears it before every sample.
- Binary similarity reuses matrix storage while retaining floating-point operation order. Count-pair gathering is limited to large matrices with enough repeated counts; small and diverse inputs retain the direct path.
- Candidate scoring keeps difflib block merging and opcode generation. A NumPy match-run table replaces its longest-match search only for dense repeated mnemonic pairs. The table is capped at 1,000,000 cells (about 7 MB of temporary arrays) and 32,767 entries per sequence; sparse, small and oversized cases use difflib. Sequence replacement invalidates the table.

## Rejected changes

Archive-header tweaks, binding-path reuse, struct offset caching and a bisected difflib walk did not establish reliable gains. Caching public mutable type-width tables risked stale results. Avoiding the final metadata copy changed custom-backend isolation. Unconditional match tables were much slower on disjoint or uneven inputs, and unconditional count gathering regressed matrices whose counts were mostly distinct. Those variants are not retained.

## Reproduction

Run from a contributor checkout with its Python 3.15 environment already installed:

```sh
for domain in analysis formats metadata workflow matcher; do
  PYTHONPATH="$PWD/src:$PWD" OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
    .venv/bin/python "tools/bench_perf10_${domain}.py" --json
done
```

To measure the baseline, keep using these same scripts and interpreter, but set `PYTHONPATH` to a detached checkout of the baseline commit (`BASELINE/src:BASELINE`). Alternate the revisions and keep raw samples. The scripts generate private temporary fixtures and do not use a real project or invoke native compilers.

## Validation and limits

Regression tests cover exact graph edges and global-use scoping, OMF bytes/relocations and threaded lookups, metadata isolation for TOML/SQLite/custom stores, prover probe counts, type-size results, bitwise matrix parity, and exhaustive/randomized difflib parity. Full-suite tests, lint, formatting, mypy, import cycles and layering were checked. The report-link check was rerun after writing this document.

Cold physical storage, real game corpora, Docker compiler execution, live Ghidra/BinSync and arbitrary plugin workloads were not benchmarked. No release was cut for this tuning pass.
