# Rebrew Performance Notes

Measurements of Rebrew hot paths, retained optimizations, and rejected experiments.

## `rebrew status` on guild-rebrew (2026-11-24)

guild-rebrew has 2,631 compiled sources and a replicated SQLite metadata store
whose functions document is 25 MB (803,420 lines, about 36,000 records).
`perf stat -e instructions:u` on `rebrew status`. "Warm" is the second of two
runs. "Cold" bypasses the parsed-document cache (`document._read_doc_cache`
and `_write_doc_cache` stubbed), as the first command after a metadata edit
pays. Output was byte-identical at every step.

| stage | warm | cold |
|---|---:|---:|
| base (`b7451389`) | 48 G | 71.5 G |
| one SQLite reader per command, cached routed store, string include walk, line TOML reader | 38 G | 46.5 G |
| reused parsed rows, field-name and include-spelling caches, one masking pass, indexed inventory | 29.0 G | 35.4 G |
| stale-closure fix, containment without exceptions, journal hash reuse | 27.11 G | 33.19 G |
| shadow probes from the first search, scalar reuse, routed library tokens | 25.39 G | 29.58 G |
| decoded journal content reuse | 24.65 G | 28.70 G |
| persistent include closures | 20.10 G | 24.36 G |
| live config and SQLite stats for library tokens | 19.50 G | 23.71 G |
| verify-cache release before final GC | 19.4 G | not measured |
| persistent PE layouts (no LIEF import) | 17.6 G | 21.7 G |

Two persistent caches are keyed by the source of the code that produces
their entries as well as the release, because a development install keeps
one release number across commits: `.rebrew/include-closures.json` (compiler
`cache.py` and `utils.py`) and the PE layouts (`formats/binary_loader.py` and
`formats/binary_model.py`). The first run after such a change rebuilds them.

What remains on a warm run: closure validation (header re-reads, shadow probes and missing-include probes,
about 1.8 G by subtraction), per-source override keys, interpreter shutdown
(about 0.42 G in the final collections and 0.31 G in module and object
teardown), and the cold-only pure-Python TOML line parse (about 1.1 s).

Rejected:

- a per-call header lookup memo, stale after a case-only rename between calls;
- deferring the LIEF import alone (status reached it), and a hand-written PE
  parser (not equivalent to LIEF);
- `os._exit` after the command, which skips exit handlers;
- `gc.freeze()` at exit, which reproduced a nanobind leak report;
- releasing the include scanner's closure through `del`, within run-to-run
  variation;
- `access()` in place of marker stats (a different permission question) and
  stat-only header reuse (weaker than the content check).

## CLI startup mounts one command (2026-11-23)

`rebrew --version` cost 2.01 G user-space instructions, against 0.06 G for
`import rebrew`: composition imported and registered all ~130 command
modules (about half of startup under cProfile), and typer converted the whole
command tree to click (another quarter). `main()` now mounts only the invoked
built-in when argv names one after root options alone, and
`rebrew.app.builtins` builds each domain sub-app on first access. Base
`22e0bd7b` against the candidate, `perf stat -r 15`, same host:

| command | instructions | CPU (task-clock) |
|---|---|---|
| `python -P -m rebrew.app.main test --help` | 2.39 G -> 0.92 G | 278 ms -> 118 ms |
| `rebrew ops --help` | 2.28 G -> 1.1 G | not measured |

The test suite starts about 155 rebrew children per run (ops-server compiles,
intake, the CLI contract tests). Two warm `-n auto` runs per tree: 2,676 G
-> 2,475 G instructions, 16,256 -> 16,273 tests. Whole-suite task-clock was
not comparable: the host's load average was 23-27 during the runs.

## Commands outside the earlier sets (2026-11-16)

A one-run probe of the read-only commands the rounds above never measured
found `binary functions` (649 G instructions), `coverage report` (366 G),
`types contracts` (300 G), `binary analyze` (286 G), `data bss` (218 G) and
`source units` (216 G). Base `8ae46626`, candidate `f0e12caf`, three runs per
side from byte-compiled trees; every run printed the same stdout. "Cold" runs
delete `.rebrew/data-scan-roles.json` first, the state after any store write.

| Command | Before | After | Change |
|---|---:|---:|---:|
| `source units --json` | 215.57 | 148.62 | -31.1% |
| `binary analyze --json` | 286.10 | 241.87 | -15.5% |
| `coverage report --json` | 333.58 | 289.28 | -13.3% |
| `data bss --json`, cold | 217.39 | 148.32 | -31.8% |
| `data list --json`, cold | 217.57 | 148.44 | -31.8% |
| `data bss --json`, warm | 86.53 | 86.53 | 0.0% |
| `types contracts --json` | 299.50 | 299.51 | 0.0% |

`binary functions` spends about 84% of its samples in rizin child processes,
so instructions do not show its change; three runs per side measured 40.7 s
against 35.8 s wall with the same CPU time and identical output.

Retained changes:

1. On x86-32 outside NE, `scan_references`, `data_references` and
   `reachable_code` decode an instruction's capstone details only when its
   operand text prints a value inside the image. Intel syntax prints every
   value above 9 as a lowercase `0x` literal (every in-image value of the
   823k instructions in guild-rebrew's PE), so the screen applies only when
   the lowest image address is at least 10 (the `mini.elf` fixture maps
   address 0). Identical references on guild-rebrew's PE and every x86
   fixture binary.
2. `reachable_code` decodes each instruction from a 15-byte window instead of
   the rest of the body.
3. `binary functions` starts `rizin aaa`, `rizin aa;aap` and the capstone
   sweep together and merges in the same order.
4. `scan_globals` checks target visibility on the source text as read; the
   rejoined lines lost the final newline and missed the anchor cache.

Not changed: `types contracts` is first-time parsing (each file's text is
parsed once), and asking rizin for less analysis would change its results.
## Source scans read each store once (2026-11-16)

`scan_globals` loaded both metadata stores once, then read them again for every
source: `_collect_scan_file_facts` called `data_rows_for_path`, and
`source_bindings` reloaded the function store for the file's rows and its first
function anchor, and the data store for the file's rows and for an anchored
declaration whose row names another file. `scan_reversed_dir` read the data
store per source and `get_globals` per annotated global. Every read stats
`rebrew-project.toml` in each ancestor directory and fingerprints the store,
which opens a SQLite database. The scans now pass one read-only snapshot down
(`function_entries`, `data_entries`, and `data_file_index` rows).

Measured on the YC server.dll target (572 sources, SQLite metadata; the
recoverage review lane's project) with baseline `c74bce11` (6.46.0) and the
change, both trees byte-compiled, under the same interpreter. Each run stages
a fresh copy of the project, as the coverage worker does, in one process per
side; the first run warms imports and the median covers the next seven. The
map is recoverage 9.0.0's `coverage_map` through `recoverage.ops.dispatch`.
Opens are `sqlite3.connect` audit events and the `os.stat`/`os.lstat` columns
count Python calls, both during one op; syscalls are `strace -f -c` of a
three-map process minus a two-map one.

| Per op | Before | After |
|---|---:|---:|
| `scan_globals` median | 331 ms | 99 ms |
| `build_catalog_data` median | 454 ms | 156 ms |
| `coverage_map` median | 718 ms | 404 ms |
| SQLite opens: scan / catalog / map | 2,300 / 2,889 / 2,935 | 13 / 32 / 78 |
| `os.stat` / `os.lstat` calls per map | 55,538 / 88,783 | 11,574 / 67,083 |
| `lstat` / `stat` / `openat` syscalls per map | 121,068 / 93,695 / 8,252 | 67,941 / 12,590 / 4,251 |

A second alternating round gave medians within 24 ms of these. The scan
result, the catalog document and the map reply (966,783 bytes, sha256
`24f387f7...`) were identical on both sides, and peak RSS was 147 and 148 MiB.
The `os.lstat` calls left are `Path.resolve()` of each source, about four per
source for the scan's fact and role cache keys and its first source read, not
store reads.

## Call scans kept by binary digest (2026-11-16)

`rebrew.call_references` scanned the whole binary (`scan_references`, then the import
table) on every call. The backend calls it for each function page's call graph:
production span metrics over 24 hours put the backend route at 225 requests, p50
476 ms and p95 2.3 s, nearly all of it this op. The op now keeps its answer by the
sha256 of the binary's bytes, 8 binaries per worker.

`.scratch/bench_call_refs.py` analyses the YC server.dll (sha256 `3cc2ce90...`, 286,720
bytes) in a fresh workspace, then times six `rebrew.call_references` calls through
`rebrew.ops.dispatch`. It ran on `origin/main` and on the change with the same
interpreter:

| Call | Before | After |
|---|---:|---:|
| first | 427 ms | 421 ms |
| repeats (median of 5) | 392 ms | 2.2 ms |

Every reply was the same 206,108 bytes (sha256 `d62b28c6...`) on both sides.
`scan_references` alone takes a median 540 ms on this binary (5,466 references).

## Third ten hot-path rounds (2026-11-15)

Baseline `23171f8d`, candidate `e1381b2b`, measured as above with both source
trees byte-compiled before the first run (a fresh tree's first run otherwise
adds about 5 G instructions to `status`). Every run of both sides printed the
same stdout.

| Workload | Before | After | Change | Spread before / after |
|---|---:|---:|---:|---:|
| `--version` | 2.00 | 2.00 | +0.0% | 0.14% / 0.12% |
| `status --json` | 53.59 | 46.89 | -12.5% | 0.11% / 0.11% |
| `todo --json` | 54.46 | 47.78 | -12.3% | 0.08% / 0.10% |
| `lint --json` | 202.17 | 167.11 | -17.3% | 0.04% / 0.01% |
| `data list --json` | 110.10 | 86.65 | -21.3% | 0.00% / 0.02% |
| `coverage catalog --json` | 164.27 | 128.41 | -21.8% | 0.07% / 0.01% |
| `source graph --format summary` | 189.74 | 141.81 | -25.3% | 0.02% / 0.05% |
| `orphans list --json` | 162.21 | 126.40 | -22.1% | 0.03% / 0.02% |
| `recommend --json` | 393.37 | 305.44 | -22.4% | 0.01% / 0.03% |
| total | 1,331.9 | 1,052.5 | -21.0% | |

Peak RSS rises from 1.13 to 1.23 GB in `lint` and from 1.46 to 1.56 GB in
`recommend`, mostly from change 2 below, which keeps trees the parse memo
would drop.

Counting real tree-sitter parses by caller showed `lint` and `data list`
parsing each source twice and `source graph` three times, as different
masked variants of the same text. Retained changes; 1-3 were measured
together against the baseline, 4-10 each against the previous commit:

1. `metadata_comments` returns before parsing when no `KEY:` text for a
   reserved key exists (5,762 of 5,779 guild sources): `lint` -6.0%,
   `data list` -9.7%.
2. `_function_trees` keeps its trees per source text in the per-thread memo.
   With 1: `lint` -9.6%, `coverage catalog` -9.7%, `source graph` -8.3%.
3. `find_extern_function_names` parses the same-length `_mask_cc` text, which
   is what `_function_trees` parsed for a source without asm, instead of
   `strip_cc`'s; a `__declspec(...)` spanning lines keeps `strip_cc`.
   Identical names on the corpus and 20,000 generated sources. With 1 and 2:
   `source graph` -18.2%, `recommend` -14.5%.
4. `_is_vendored_toolchain_tree` resolves through `resolved_path`: `todo`
   -2.6%.
5. `unresolved_still_missing` and `shadow_unchanged` recheck each distinct
   probe once (63% of `status`'s unresolved probes were repeats): `status`
   -7.1%, `coverage catalog` -2.7%.
6. `function_signatures` keeps its result per source text: `recommend`
   -1.5%.
7. `mask_msvc_syntax` keeps its result per source text: `lint` -3.8%.
8. The `find_extern_variables` walk skips a function definition whose bytes
   hold no `extern`: nothing under a definition is at file scope, so only an
   extern declaration there is reported. Identical results in both modes and
   with three function filters: `lint` -4.9%, `data list` -8.4%,
   `coverage catalog` -6.2%.
9. `toolchains_repo` finds the sibling checkout once per process;
   `REBREW_TOOLCHAINS_DIR` is still read per call: `status` -6.0%, `todo`
   -5.9%.
10. `_DefinitionPrototypes._line_signature` returns at once for a name the
    lines never spell as `name(` or `name (`: `source graph` -3.7%, `orphans
    list` -4.1%.

Rejected:

- Parsing `_mask_cc` text for `_variable_tree`: it also blanks `__declspec`,
  which `find_extern_variables` reads for `dllimport`.
- A sidecar for the source-provenance table: `lint`'s W031 check parses the
  function store anyway, so only `recommend` would gain (about 6%).
- Building the library-override memo key without `metadata_store`: the memo
  records no config identity, so a backend change would serve a stale entry.

## Ten more hot-path rounds (2026-11-15)

Baseline `dc78eac4` (after the rounds below), candidate `c7550248`, measured the same
way: 10 runs per workload and side, `instructions:u`, one guild-rebrew
snapshot, identical stdout on every run of both sides.

| Workload | Before | After | Change | Spread before / after |
|---|---:|---:|---:|---:|
| `--version` | 2.01 | 2.00 | -0.4% | 202.75% / 0.12% |
| `status --json` | 56.35 | 52.55 | -6.8% | 1.56% / 1.77% |
| `todo --json` | 57.23 | 53.41 | -6.7% | 0.13% / 0.10% |
| `lint --json` | 243.97 | 202.14 | -17.1% | 0.08% / 0.16% |
| `data list --json` | 137.07 | 110.09 | -19.7% | 0.09% / 0.15% |
| `coverage catalog --json` | 193.61 | 163.21 | -15.7% | 0.02% / 0.22% |
| `source graph --format summary` | 228.05 | 189.74 | -16.8% | 0.03% / 0.02% |
| `orphans list --json` | 191.51 | 161.13 | -15.9% | 0.02% / 0.04% |
| `recommend --json` | 551.89 | 391.32 | -29.1% | 0.05% / 0.11% |
| total | 1,661.7 | 1,325.6 | -20.2% | |

One `--version` run on the before side took three times the median; the
median is unaffected. CPU times from these runs are not reported: test suites
ran on the same host during the measurement.

cProfile charges a fixed cost per Python call, so it overstated call-heavy
helpers (`clone_plain`, the asm token grouping) and could not show cyclic GC
at all. `perf record` with `python -X perf` found GC at about 17% of `lint`'s
samples. Each candidate below was re-timed without a profiler before it was
kept.

Retained changes:

1. `_variable_tree` finds calling-convention tokens with a word regex checked
   against the tree when a source has no `_asm`, instead of listing every leaf
   token (5,779 corpus sources and 20,000 generated ones agree byte for byte).
2. `recommend` resolves `cfg.metadata_dir` once per walk, and
   `bind_compiled_source` no longer evaluates it as an unused `getattr`
   default.
3. `metadata.storage._ancestor_identities` walks `str` paths: 9 µs against
   27 µs per call, 113k calls per `recommend`.
4. `metadata_comments` keeps its C-branch result per source text in the
   bounded per-thread memo (`c_parser.recall_source_value` /
   `store_source_value`); `recommend` binds each source about five times.
5. An include lookup stats each directory once and hands the stat to the
   directory index.
6. `_has_function_declarator` searches with a stack instead of a recursive
   generator: 25% less time on 339k corpus declarators.
7. The `resolved_path` memo holds as many entries as the source-text memo
   (8,192); at 2,048 a 5.5k-file tree evicted every entry before its next pass.
8. `address_comments_for_file` resolves through `resolved_path`.
9. The `find_extern_variables` walk reads `node.type` once per node: 17% less
   time in both modes, identical results on the corpus.
10. The CLI entry point raises the young-generation GC threshold from 2,000 to
    20,000 (`app.main._GC_YOUNG_THRESHOLD`). `lint` ran 2,482/225/17
    collections and now runs 140/11/1: 12% less CPU time and 1.7% fewer
    instructions, with the same output and peak RSS (1.13 GB). Disabling GC
    measured 12.5% less CPU time and 2.3% fewer instructions, so the threshold
    keeps most of the gain.

Rejected:

- tree-sitter Queries: a `(declaration (storage_class_specifier) @s) @d`
  query over the corpus cost 11.1 G instructions against 9.1 G for the Python
  walk, with the same 15,509 matches.
- Pruning walks by grammar: `node-types.json` merges aliased node variants, so
  84 of 125 named types may contain a `declaration` and no sound pruning set
  exists.
- Stack loops for `find_c_function_definitions` and
  `find_extern_function_names`, and reading `node.type` once in the former:
  no measurable change (2.47 s against 2.47 s).
- A `TreeCursor` walk: 18% faster than `node.children` on a bare traversal,
  too little for rewriting the walks.
- A 64 MiB parse memo: 1.9% fewer `recommend` instructions for 36 MB more
  peak RSS.
- Inline scalar checks in `clone_plain`: 15% faster on the 22 MB function
  store, a fraction of a second per command.
- Faster asm token grouping: only 218 corpus sources contain `_asm`, 0.13 s in
  total.
- Caching include resolution or `realpath` across lookups: either changes the
  reported header path under bind mounts or the race checks between parallel
  workers.

## Ten profiled hot-path rounds (2026-11-15)

Baseline `ec604a1f` (6.40.1), candidate `c4f90954`. Each workload ran 10 times
per side from one guild-rebrew snapshot (5,703 C files, 14.4 MB), with the same
interpreter and the source tree chosen by `PYTHONPATH`. The metric is retired
user-space instructions, which host load does not move:

```bash
PYTHONHASHSEED=0 NO_COLOR=1 COLUMNS=120 PYTHONPATH=<rebrew>/src \
  perf stat -x, -e instructions:u,task-clock -- \
  <rebrew>/.venv/bin/python -m rebrew.app.main status --json
```

Medians in billions of instructions. Spread is (max - min) / median over the 10
runs; every run of a workload printed the same stdout (sha256), on both sides.

| Workload | Before | After | Change | Spread before / after |
|---|---:|---:|---:|---:|
| `--version` | 2.53 | 2.01 | -20.7% | 0.06% / 0.19% |
| `status --json` | 483.71 | 56.37 | -88.3% | 0.29% / 1.64% |
| `todo --json` | 484.53 | 57.25 | -88.2% | 0.27% / 0.13% |
| `lint --json` | 262.73 | 243.98 | -7.1% | 0.02% / 0.09% |
| `data list --json` | 143.30 | 137.07 | -4.3% | 0.01% / 0.08% |
| `coverage catalog --json` | 628.66 | 193.62 | -69.2% | 0.04% / 0.02% |
| `source graph --format summary` | 249.72 | 228.05 | -8.7% | 0.03% / 0.02% |
| `orphans list --json` | 626.51 | 191.54 | -69.4% | 0.04% / 0.03% |
| `recommend --json` | 1,462.48 | 551.91 | -62.3% | 0.04% / 0.36% |
| total | 4,344.2 | 1,661.8 | -61.7% | |

The after side's `status` spread comes from its first run, which also compiled
the fresh worktree's bytecode (57.2 G; the other nine are 56.3-56.4 G).

Retained changes, in profile order:

1. `compiler.cache` lists each include directory once per (device, inode,
   mtime) and looks names up in a casefolded index, instead of a `scandir` and
   NFC fold per path component per lookup (the largest profiled cost in
   `status`, `todo`, `catalog`, `orphans` and `recommend`). A directory modified within 2 s
   of the lookup is not cached (racy-git rule).
2. `mask_preprocessor_comments` copies runs between significant bytes instead
   of one byte at a time.
3. The anchored-source cache holds 32 MiB instead of 8, so guild-rebrew's 3,094
   anchored files (9.8 MB) stay resident within one command.
4. `find_c_function_definitions` and `find_extern_variables` keep their
   results per parsed source, as the tree memo does.
5. `_variable_tree` reads line numbers from `node.start_point` instead of a
   per-byte newline index.
6. `find_variable_roles` and `_msvc_asm_token_groups` read `node.type` once per
   node, and the asm grouping returns before parsing a source without `_asm`.
7. Metadata loads copy plain TOML values with `utils.clone_plain` instead of
   `copy.deepcopy`.
8. `cli.add_global_options` builds the version/verbose/quiet options once.

Equivalence beyond the identical command output: the old and new
`mask_preprocessor_comments` agree on 5,786 corpus files and 20,000 random
strings; parse trees, extern scans (both modes), function definitions,
variable roles and asm spans agree on all 5,779 corpus sources; `--help` and
the CLI schema hash identically.

Rejected: raising the parse-tree memo cap to 64 MiB left the parse count at
9,855 against 9,859, because the extra parses are of distinct inputs.
Replacing the function-definition walk with a tree-sitter Query
(`(function_definition) @f`) cost 10.8 G instructions over the corpus against
5.8 G for the Python walk, since the query still visits every node.

## Ten CPU-time microbenchmarks (2026-10-29)

[Ten synthetic hotpath workloads](PERFORMANCE_TEN_HOTPATHS.md) exercise metadata,
source analysis, formats, matching and workflow analysis. The report includes
paired CPU medians, raw CPU/wall samples, cache states, correctness checks,
rejected changes and reproduction commands.

## Independent hot-path load reviews (2026-10-28, 6.6.0)

[Fifty fresh reviews](PERFORMANCE_6_6_0.md) profile complete callable paths at
three load sizes or shapes, preserving raw CPU/wall samples and output checks.
Retained production patches remove repeated archive/symbol/identity searches,
layout regex setup and string scans. The report separates measurements from
instrumented profiles, records rejected candidates and small-load regressions,
and covers the cache freshness bugs exposed during refresh testing. The release
includes a supplemental archive of runnable experiments and raw evidence.

## Source and rename review (2026-10-28, 6.5.0)

The review traced CLI source discovery, metadata joins, global ownership,
rename planning, coverage/catalog reads, compiler cache identity, matching,
and integration readers. Expected load is a local reversing workspace with
thousands of source files and symbols. Native toolchain execution, remote
Ghidra/BinSync latency, cold storage, and all possible plugin implementations
were not benchmarked.

The retained changes remove repeated work:

- Ownership enrichment parses each map-selected source once per command.
  The cache dies with the command; the next call sees edited sources.
- Global definition/user association looks up actual file symbols instead of
  testing every global against every file. Target-local collisions retain the
  same declaration-site checks and output order.
- Address-anchor and forbidden-metadata discovery use a native Tree-sitter
  comment query. Strings remain opaque and function-body metadata comments
  remain excluded. Query cursors are per call and compiled queries per thread.
- Named-string inlining reuses external-source parses by complete content,
  including when another source changes during the scan. Comment/literal
  membership uses binary search over disjoint, sorted AST spans.
- Rename plans index canonical source identities once. Exact path matching,
  Windows separators, first-match behavior and the existing preview/freshness
  checks are preserved; indexes are local to a plan.

Measured on Python 3.15.1 with identical outputs in each paired comparison:

| Workload | Before | After | Measurement |
|---|---:|---:|---|
| Guild `data list --json`, ownership-cache change | 58.6 s | 21.9 s | Wall time, 3,758 globals |
| Anchor/comment discovery, fixed snapshot of 5,604 files | 6.334 s | 2.802 s | Wall time |
| Named inlining, 30 strings and 200 other-file functions | 16.83 ms | 2.85 ms | Median process CPU, 5 samples |
| Rename path lookup, 200 sources and 200 lookups | 70.32 ms | 0.717 ms | Median process CPU, index build included |

The first row isolates the ownership-cache change. Subsequent Guild source and
metadata edits prevented a comparable final command-wide timing. The rename
row measures path resolution within a plan, not the whole rename operation.
Synthetic fixtures are prepared outside the timed region, with one untimed
warmup. Benchmark controls and the named-inlining workload are reproducible:

```sh
uv run --frozen python -m tools.bench_source_scans named_string_reuse
uv run --frozen python -m tools.bench_source_scans include_scan
uv run --frozen python -m tools.bench_source_scans struct_scan
```

Two additional query conversions, for includes and struct discovery, increased
latency by about 1.6–1.7 times on their fixtures and were reverted. The include
and struct workloads remain controls. SIMD/NumPy and mmap were not added:
file reads accounted for 0.18 s in a 77 s profiled run, while anchor discovery
accounted for about 35 s. The retained query addresses Python AST traversal.
These profile timings include profiler overhead and are not command benchmarks.

Regression tests count ownership parses and rename identity conversions, check
updates between calls and during inlining, and preserve malformed-anchor,
comment/string, sibling-path, TU-local and cross-target cases.

## Metadata store resolution (2026-10-19)

The backend-neutral storage layer resolves a logical store per cached read,
so `metadata_store()` is on the same hot path as the document fingerprint.
The first version walked the project ancestors, re-read the config, rebuilt
the backend tuple and constructed a new store object on every call; a
whole-tree scan calls it once per source file.

Measured as process CPU time medians (Python 3.13.15, Ryzen 9 9950X, CPU 2)
on a project with `rebrew-project.toml`, 2,000 iterations:

| Path | Before | After |
|---|---:|---:|
| `metadata_store()` resolution | 39.5 ms | 9.6 ms |
| cached `load_metadata`, 4,000-row store | 34.7 ms | 21.1 ms |
| cached `load_metadata`, store in six fragments | 44.4 ms | 29.6 ms |

The after numbers beat the pre-storage-layer measurements in
"Metadata drop-in hot paths" (25.4 / 35.5 ms). The project root is memoized
per directory (misses are not cached, so a later config is still found),
built-in stores are cached per identity, a project with a config resolves the
selected store with one dict lookup keyed on the config's stat identity, and
callers that already resolved the path pass `resolved=True` to
`load_metadata_doc` so the read does not walk every component again. Plugin
backends are constructed fresh per call.

Gates: `test_store_resolution_caches_the_project_walk_and_instance` asserts
zero ancestor walks and one instance across repeated resolution;
`test_hot_load_does_not_resolve_an_already_resolved_path` asserts zero
`Path.resolve` calls on repeated cached reads. Both count calls, so they do
not move with scheduler load.

## CLI startup object graph (2026-10-19)

typer, click, rich and the registries are imported before the command runs and
stay live for the process. A command that allocates thousands of rows triggers
full collections that rescan that import graph. The umbrella entry point now
runs `gc.freeze()` once before dispatch, so the startup graph sits in the
permanent generation while everything allocated afterwards stays collectable
(watch and server modes still collect their own garbage). The freeze is not
preceded by `gc.collect()`: the collect scanned the whole import graph and cost
about 30 ms of CPU over the command, so unreachable import-time cycles are
retained once for the process lifetime, including watch and server modes. This
also retains any finalizable resources held only by those startup cycles until
process exit; it does not disable collection of later command allocations.

Measured as fresh-process CPU time (Python 3.13.15, Ryzen 9 9950X, CPU 2),
paired wrappers that differ only in the freeze call:

| Command | No freeze | Collect + freeze | Freeze only |
|---|---:|---:|---:|
| `status --json`, 5,000-function synthetic project | 0.863 s | 0.733 s | ~0.65 s |
| `--version` | 0.430 s | 0.349 s | 0.291 s |

The 5,000-row command is a synthetic project; no real project command was
measurable on this checkout.
`gc.get_freeze_count()` is the gate:
`test_startup_freeze_does_not_run_a_preliminary_collection` checks that no collect
is requested and freeze runs exactly once. `test_startup_freeze_is_one_shot`
asserts the first call moves tracked objects
to the permanent generation and a second call does not move more, so the
command's own allocations are not frozen alongside the import graph.

## Todo caller counts (2026-10-19)

`_caller_counts` reuses `.rebrew/extern-names.json`, but a warm scan used to
resolve every source path twice: once for the cache key and once inside
`rel_display_path` for the matched-file filter. A walked source path is
already real and absolute, so the key is its spelling and the display path is
a prefix slice; only a relative spelling or a shared-root file falls back to
the resolving helpers.

Measured as process CPU time medians (Python 3.13.15, Ryzen 9 9950X, CPU 2),
7,000 sources with one extern each, matched-file filter active, the tree walk
shared outside the timed call:

| Path | Before | After |
|---|---:|---:|
| warm `_caller_counts`, 7,000 files | 97.3 ms | 35.4 ms |

That is 2.75x on the warm caller-count path; including its own tree walk the
same workload measures 133.8 ms to 65.0 ms (2.06x). The recorded `todo`
sample below spent 0.183s in caller counts. Gate:
`test_warm_scan_does_not_resolve_absolute_paths` asserts zero `Path.resolve`
calls for a warm scan over an absolute `reversed_dir`; counts still identify
the same files because the walk yields one spelling per source.

## Compiled-source row binding (2026-10-19)

`compiled_source_annotations` builds one row per function for `status`. The
base containment and the display prefix depend only on the project paths, so
they are computed once per call instead of once per row. The original row
code ran `Path.is_relative_to` plus `rel_display_path` (`relative_to`/
`as_posix`) per function; a second pass replaced the remaining `Path`
construction with `os.path` string joins and `os.path.islink`, and
`validate_identity_file` no longer builds a parsed path for the common
no-`..` identity.

Measured as process CPU time medians, 5,000 rows under `src/`, project root as
the metadata base:

| Path | Original | After |
|---|---:|---:|
| `compiled_source_annotations`, 5,000 rows | 97.6 ms | 26.4 ms |

The two passes measured 97.6 to 61.9 ms, then 61.9 to 26.4 ms. The `status`
sample recorded below spent 0.118s in that build for 4,995 GOLDTL rows, so the
same shape should give back roughly 65ms there. Rows with a symlink, an
unresolved base, or a path outside `root` still go through
`bind_compiled_source`, which resolves and raises where the old code did; a
display prefix that would need normalization falls back to
`rel_display_path`. Gate: `test_plain_rows_do_not_walk_display_paths` asserts
zero `rel_display_path` calls for plain in-tree rows.

## Metadata drop-in hot paths (2026-10-19)

Drop-in fragments are read on every cached metadata load and rewritten by every
locked edit, so both paths cost what the number of fragments makes them cost.
Measured as process CPU time medians (Python 3.13.15, Ryzen 9 9950X, CPU 2).

A 4,000-row functions store, one store versus six fragments:

| Path | Before | After |
|---|---:|---:|
| fingerprint, 2,000 calls, one file | 7.54 ms | 5.43 ms |
| fingerprint, 2,000 calls, six fragments | 61.36 ms | 19.72 ms |
| cached `load_metadata`, 2,000 calls, one file | 27.33 ms | 25.42 ms |
| cached `load_metadata`, 2,000 calls, six fragments | 77.18 ms | 35.50 ms |
| one `update_field` edit, six fragments | 4,346 ms | 2,560 ms |
| one `update_field` edit, one file | 1,552 ms | 1,370 ms |

`metadata_fingerprint` walks the drop-in directory itself with `os.scandir`
and stats each file once. It used to go through `metadata_paths`, which
stats the main file and stats every fragment to answer `is_file`, then stats
all of them again. The write path no longer parses the whole collection a
second time to re-check duplicates (the caller already loaded and validated
it), and it deep-copies and renders only the members the edit touches. A
single-file store takes the unchanged direct-write fast path.

The remaining cost against a single-file store is one directory check per
cached read, because a new or removed fragment has to be visible without a
restart. Cached `load_metadata` on one file measured 11.2 µs per call before
drop-in support and 12.7 µs after; a 100-file binding scan measures
about 4-7% slower for the same reason. Paying it per read is the price of
live discovery; a project with six fragments now pays 17.8 µs per scan
instead of 38.6 µs.

Gates, not thresholds: `test_fingerprint_stats_each_input_once` asserts one
`Path.stat` for the main file and one `os.scandir` for the directory
regardless of fragment count, and
`test_edit_parses_and_dumps_only_the_owning_fragment` asserts six fragment
loads (three in the caller's load, three in the write) and two `tomlkit.dumps`
renders for an edit that changes one record. Both counts are independent of
scheduler load.

## Status, todo, and verify preparation (2026-10-18)

Measured with process CPU time (`getrusage`) on the guild-rebrew tree, one
sample each, scheduler wait excluded.

| Command | Before | After, warm store |
|---|---:|---:|
| `status` server.dll | 2.722s | 0.445s |
| `status` Europa1400Gold_TL.exe | 3.346s | 1.150s |
| `todo` server.dll | 4.173s | 1.474s |
| verify preparation, server.dll | 9.951s | 1.452s |

The function store is an 11MB TOML. The first load in a process still parses
it. Later processes read the parsed rows from `.rebrew/metadata-doc/` when
the store's fingerprint matches, and a changed store parses again. The gate
is `TestParsedDocumentCache.test_second_load_does_not_parse_again`: one
`tomllib` load, then zero, then one more after the text changes.

Verify preparation was spending 7.278s inside `build_name_to_va`, reparsing
sources whose addresses the stores already name. That call now skips the C
parse for those files. An address that is only in the source is still parsed.
The gate is `test_stored_address_is_not_parsed_again`.

A second pass stores the two results that were still re-done in every
process. `rebrew todo` writes `.rebrew/extern-names.json`, keyed by file
stamp. A source that does not contain `extern` is stored empty, with no parse.
A byte-matched caller is ignored after that lookup, so the count for a
matched file stays the same. Verify preparation writes
`.rebrew/name-map-cover.json` for files the stores already name, and a
later process stats those files. The source and header list is one
directory walk. On guild-rebrew, one warm sample moved
server `todo` from 1.474s to 0.914s, of which caller counts were 0.183s
(251 functions, 0 actions), and server verify preparation from 1.452s to
1.019s, with 10 source reads. The gates are the extern-parser call count,
the source-read count, and the one-walk source list.

A later sample on the same tree, still process CPU:

| Command | Warm sample |
|---|---:|
| `status` Europa1400Gold_TL.exe | 0.825s (4,995/4,996 covered) |
| `todo` server.dll | 0.611s (251 functions, 0 actions) |
| verify preparation, server.dll | 0.954s (316 entries, 10 source reads) |

Compiled-source rows for a plain relative path use that path directly.
A symlink, or a directory that does not resolve to itself, still resolves.
On GOLDTL that row build was 0.333s and is 0.118s in the status sample.
The verify cache writes `.rebrew/verify_cache.json` after a TOML parse;
the next process loads that document (0.045s for three status reads, where
the TOML parse alone had been 0.164s). `rebrew todo` walks the source tree
once and hands that list to the inventory and the caller count. `rebrew data`
records types and use sites in `scan_globals`. A warm scan replays those
facts from `.rebrew/data-scan-roles.json` when the source stamp, the store
fingerprint, and the target identity match, and parses again when the
source changes. The reloc name map still uses its own name cover and does
not read that role cache. The separate annotation walk skips function-prototype parses; one sample of
that walk was 3.339s and returned 664 rows. The new gates are the symlink
rejection, the verify-cache parse count, and the prototype call count.

`rebrew status` keeps one delete-safe PE layout entry per binary path under
the user cache directory (`$XDG_CACHE_HOME/rebrew/pe-layout/`, usually
`~/.cache/rebrew/pe-layout/`). It uses the same atomic sidecar writes as
the repository's other derived caches. An entry holds LIEF's section and
data-directory layouts, architecture, image base, and code bounds. The
loader checks the entry checksum, the binary's full SHA-256, the LIEF
distribution version, the Rebrew release version, the source of the PE
extractor (`formats/binary_loader.py` and `formats/binary_model.py`), and the
format hint.
If any check fails, LIEF parses the bytes used to calculate the hash.
A hit lets `rebrew status` reuse those facts across processes without
loading LIEF. The cache contains only layout facts, so binary data reads
still go through the target file.

## Metadata-backed inventories (2026-10-18)

Status/todo and verification preparation use stored function identities without
reading or parsing registered C files and library headers. Declaration consumers
keep the full source reader; source-only files still use it. Verification also
reads declarations when a missing stored symbol requires calling-convention
recovery, and cache admission still validates source and header fingerprints.

`tests/test_source_scan_hotpaths.py` gates one function-store load and zero AST
calls for both one-file and 32-file registered inventories, including a dangling
address anchor and library headers. It also checks exact paths, target filtering,
source-only fallback and the default declaration reader. Guild's 7,246-source
tree retains 25 source-only fallbacks: profiled status calls finish with no load
error, reporting 251/251 covered for SERVER and 4,995/4,996 for GOLDTL. These are
inventory checks, not new byte-comparison verdicts.

Existing fingerprint memos already avoid body rereads and include-closure walks.
New counted tests cover unchanged calls, source/header touch and content edits,
and library-override changes. An immediate paired sample of 32 real Guild sources
with includes performed 151 body reads and 32 closure walks cold, then zero of
either warm, with equal fingerprints. A separate unsnapshotted 7,246-file pass
performed one source reread and one closure walk warm; that pass does not prove
that the whole tree stayed unchanged. No additional fingerprint cache was added.

## Twenty additional hot-path rounds (2026-10-14)

Profiled the actual timed callbacks in the eighteen-workload runner, then measured
another twenty candidates in before/after/after/before order on CPU 0. Each
process records nine warmed CPU/wall samples; setup, output hashing and profiling
stay outside the timed region. Fifteen changes remain and five were rejected.
Raw profiles, reports, edge probes and candidate patches stay in the ignored
`docs/benchmarks/2026-10-14-twenty-rounds/` directory.

These are individual experiment ratios, before subsequent combined checks:

| Round | Workload | Before / candidate CPU | Decision |
|---|---|---:|---|
| 1 | `flags_segments` | 2.06× | Retained |
| 2 | `flags_empty_flush` | 1.46× | Retained |
| 3 | `flags_strip` | 1.01× | Rejected |
| 4 | `verify_fields` | 1.60× | Retained |
| 5 | `verify_vars` | 2.48× | Rejected |
| 6 | `module_keys` | 1.10× | Rejected |
| 7 | `ascii_int` | 1.49× | Retained |
| 8 | `decimal_int` | 1.00× | Rejected |
| 9 | `integer_suffix` | 1.18× | Retained |
| 10 | `grid_cells` | 1.05× | Retained |
| 11 | `status_groups` | 1.64× | Retained |
| 12 | `status_singletons` | 1.27× | Retained |
| 13 | `binding_get` | 2.00× | Retained |
| 14 | `prototype_body` | 2.18× | Retained |
| 15 | `binding_copy` | 0.99× | Retained |
| 16 | `percent_clamp` | 1.31× | Retained |
| 17 | `comment_text` | 4.35× | Retained |
| 18 | `span_clipping` | 1.45× | Retained |
| 19 | `include_specs` | 286.06× | Retained |
| 20 | `metadata_resolve` | 2.94× | Rejected |

The rejected variants either changed results (quote stripping, schema-wide
`vars()` serialization, metadata path caching), or added complexity without a
useful measured gain (target-key caching and decimal-only specialization).
The path-cache probe reads 16 after an ancestor retarget where the correct new
metadata says 32; the original resolver and its regression test read 32.

Retained changes preserve unknown flag anchors and last-wins groups, declared
cache fields and subclass shapes, binding aliases and subclass lookups, ASCII
integer validation, quoted braces, escaped comments, status priority and
non-finite percentages. The field-name cache retains one base schema; subclass
fields remain independently inspected. Binding copies avoid truth testing
arbitrary objects. Coverage cells use exact integer ceilings above 2**53.

The combined workloads preserve all twenty output hashes. Final verify-cache
reconstruction measured 1.66×; binding lookups 2.06×; printable comment handling
4.46×. Prototype trimming measured 1.91×. The no-directive scan's large ratio
(about 293×) applies to inputs with no `#`, not compiler throughput. Unchanged
controls varied substantially, so small timing ratios remain informational.
Clipping's individual CPU gain did not persist in the combined run; it remains
because median traced peak temporary memory fell from 622,752 to 330,064 bytes
(47%) and each input bound is computed once. Deep-copy timing is neutral; its
retained change fixes an unintended truth-value test and preserves copy semantics.

Regression tests in `tests/test_hotpath_work.py` enforce empty-group work budgets,
base-schema discovery, strict literals, preserved binding behavior, clipping
work/ownership, exact large ceilings, and metadata retargeting. Generated
experiments remain local; reusable benchmark tools and these tests stay tracked.

Validation: 11,792 full-suite tests passed with 36 skips; the final binding-focused
checks passed 53 tests. Full mypy, lint, cycle and layering checks passed. The
maintained verify-cache workload measured 1.20× in the paired eighteen-workload
check; other command-level gains are not established by these microbenchmarks.

## Ten additional source-scan rounds (2026-10-14)

Committed the preceding work at `81a9ecbf`, then ran ten additional, interleaved
CPU-time experiments. Nine changes remain; lazy prototype-line splitting was
reverted. Raw measurements, candidate patches and the round ledger remain local
under `docs/benchmarks/`, which Git ignores. Reusable benchmark runners and
deterministic regression tests stay in the repository.

The largest targeted changes are 9.81× for large variable inventories, 4.23× for
warmed parse-cache lookups, and 2.45× for dense data-anchor binding. Other changes
reduce signature, comment, assembly-token and callback-name work. Declaration
text decoding drops from 14,700 calls to 400 with neutral CPU timing. These are
workload-specific ratios; unchanged controls vary and no timing threshold enters
the tests.

The paired 18-workload check reports about 1.14–1.15× for the large binding tree
and annotation parsing. Guild's same 100-file scan retains its binding digest and
uses 13.3% fewer profiled calls; CPU time remains essentially flat. Deterministic
regression budgets check exact source-cache reuse/eviction, named-only traversal,
linear data lookups, declaration decoding, and preserved source coordinates.

## Metadata scan measurements (2026-10-14)

The runner now reports warmed **process CPU time**, wall time, all samples,
Python/platform information, and source revision/diff fingerprints. Fixture
creation, imports, and warmup stay outside the timed calls. Native library
thread pools are fixed to one. Historical wall-time constants are removed;
comparisons consume a saved report from the same benchmark harness instead.
`--json` emits one JSON document without a preceding terminal table.

```sh
mkdir -p docs/benchmarks
uv run --frozen python tools/bench_hotpaths.py --output docs/benchmarks/before.json
# Change the implementation, keeping benchmark workloads unchanged.
uv run --frozen python tools/bench_hotpaths.py --compare docs/benchmarks/before.json --output docs/benchmarks/after.json
```

Eighteen workloads cover metadata loading, address binding, source-purpose
reads, source-tree scans, catalog/status aggregation, verify and compile-cache
hits, registry construction, binary similarity, structural diffing, GA scoring,
and mutation application. The three metadata modules were compared against their
v3.0.0 versions, holding other source files fixed. The paired measurements below
interleave baseline/optimized/optimized/baseline processes on CPU 0; medians
combine both runs' samples. Full-suite reports retain every workload, including
unchanged controls, without attributing their timing variation to these changes.

| Workload | Before CPU / batch | After CPU / batch | Speedup |
|---|---:|---:|---:|
| `source_purposes` | 497.427 ms | 0.979 ms | 507.92× |
| `bindings_small` | 22.743 ms | 15.501 ms | 1.47× |
| `bindings_large` | 49.220 ms | 16.423 ms | 3.00× |
| `bindings_metadata_only` | 40.654 ms | 8.801 ms | 4.62× |
| `parse_tree` | 37.199 ms | 32.972 ms | 1.13× |

Binding batches scan 100 files with 200 or 2,000 data rows; metadata-only
uses the large inventory without address comments. The parse-tree batch binds
1,000 functions in one file. Source-purpose batches perform 100 reads of a
200-definition, 20-purpose document.

A read-only scan of Guild's 100 largest C files (1,611,774 bytes)
measured 0.788 → 0.311 CPU seconds
(2.53×), with identical serialized binding hashes.
Profiled work counts dropped from
1,777,712 to 889,812 function calls. Source reads fell from 190 to 100,
whole-data-map loads from 100 to zero, and signature inventories from 213 to 113.
These work counts remain comparable under scheduler load.

Three changes account for the targeted reductions:

- Bindings reuse the source text already read and extract prototypes once;
  unmatched function anchors share one function lookup map.
- Data anchors use indexed single-entry lookups instead of copying every
  unrelated data row for every source file.
- Source-purpose and assembly views share an immutable, bounded cache keyed by
  resolved path, modification and change times, size and inode. Comment
  validation prunes function bodies whose comments it already ignores.

CPU time excludes descheduling and blocked I/O, **not** CPU-frequency changes,
shared-cache pressure, memory bandwidth or thermal effects. In a controlled
same-CPU competitor experiment, wall time changed by
125.8% while CPU time changed by
14.1%. Unchanged controls still vary, so timing ratios are
informational rather than machine-independent CI thresholds. The load-independent
regression gates are operation budgets in `tests/test_metadata_hotpaths.py`:
one source read, no full data-map copy, one shared function map, no traversal
into ignored function bodies, and one document parse across unchanged source
metadata views. Tests also check atomic-edit invalidation, deletion, malformed
replacement rejection, and unchanged preview prototypes.

The following historical measurements predate the current CPU-time runner;
re-measure them on the current workload rather than comparing their absolute
wall times across machines.

## GA scoring hot loop (`score_candidate`)

Profiled on 512-byte functions with 40 reloc offsets (5000 iterations):

| Component | Share of per-call time | Verdict |
|---|---|---|
| capstone disassembly | ≈ 40 % | C library; not vectorizable. The target side is pre-computed once per function (`precompute_target` → `_pre_norm_target`/`_pre_target_mnems`); per-candidate cost is dominated by the unavoidable candidate disassembly. |
| `difflib.SequenceMatcher` | ≈ 27 % | Scoring weights are calibrated to it; swapping it changes behavior. |
| numpy byte compare / prologue / reloc mask | ≈ 30 % | Already vectorized. A numpy fancy-indexing prototype for `_normalize_with_reloc_offsets` measured *slower* (0.7×) than the slice-assignment loop: do not "vectorize" it. |

### Fast paths (added, behavior-identical)

Two shortcuts skip work without approximating, both produce exactly the
scores the full computation would:

1. **Identical bytes** (`target_bytes == candidate_bytes`): every metric is
   zero except the prologue bonus, so the candidate disassembly and the numpy
   compares are skipped entirely.  Hits often in converged GA populations,
   where many members are byte-identical copies.
2. **Mnemonic-equality** (`target_mnems == cand_mnems`): the GA's common case
   is candidates that differ from the target only in immediates/reloc slots
   (`mov eax, 0x10` vs `mov eax, 0x20`; same mnemonics).  SequenceMatcher on
   equal lists emits exactly one `equal` opcode covering everything, so the
   shortcut skips difflib's O(n) setup.

**Measured:** 5000 mixed candidates (40 % identical, 30 % mnemonic-equal,
30 % arbitrary mutations) on a 512-byte function with 40 relocs:

- before: **0.669 s**
- after: **0.380 s**; **1.76× faster** wall-clock on the scoring loop.

The `_pre_*` contract is locked by `TestPrecomputedTarget` in
`tests/test_scoring.py`; the fast paths are covered by
`TestScoreFastPaths` (exact zero metrics, mnemonic-equality reference check,
and a differing-mnemonics case that must still be penalized).

## Aligned climb scoring

`rebrew match climb --objective aligned` counts instruction pairs with
difflib's matching blocks and `autojunk` off. The stdlib index walk reads
every copy of a repeated opcode from every copy on the other side, which is
quadratic on a stream of `mov`. The climb matcher returns those same blocks.
A length-2-or-longer region is a rolling-hash search checked against the
tokens; a region with no adjacent pair is one forward scan. The gate is the
token-position counter on the 2200-instruction pair-vs-hunk case
(`TestScoreAligned.test_more_pairs_win_regardless_of_hunk_count`), which has
to stay under one quadratic pass. That count does not move with scheduler load.

## Surface reads and recompile retries

`tools/public_surface.surface_at_ref` lists the tree and reads every blob
in one `git cat-file --batch`, avoiding one `git show` process per module.
`public_surface` parses each module once and reuses that tree for constant
substitution. Substitution walks signatures, bases, and literal values, not
function bodies. The gates are `TestSurfaceWork.test_ref_is_one_cat_file_batch`
(two git commands), `TestSurfaceWork.test_each_module_is_parsed_once`, and
`TestSurfaceWork.test_substitution_ignores_function_body_size` (the same
name-visit count for a 1-statement body and a 400-statement body).

`test_failed_artifact_download_never_re_posts_the_compile` injects the
recompile client's `sleep` seam and asserts the backoff delays. One delay is
recorded per retried attempt. The test does not wait on the clock, so the
retry count does not move with scheduler load.

The packaging pointer scan reads every module and parses only those whose
text contains `docs/`. Docstrings are dropped in that same walk. The gate is
`TestUserFacingDocPointers.test_pointer_scan_skips_files_that_do_not_name_docs`:
one `ast.parse` for a file that names a doc, and zero for a file that does not.
That count does not move with scheduler load.

`test_self_jump_chain_segments_one_block_per_jump` bounds the self-jump
segmenter with process CPU time (`getrusage`), and
`test_enumerate_ne_functions_sweep_is_bounded` bounds the NE sweep with the
bytes fed to the disassembler. Neither gate reads the wall clock.

Import and class scans of the package walk statements
(`tests/stmt_walk.py`), not every expression. A 400-term arithmetic
expression has the same statement count as a 2-term one
(`test_expression_size_does_not_change_the_statement_count`). Provenance
tags, sandbox prefixes, exception classes, and the dependency import set
are parsed once per path and reused. A second call records no further
`ast.parse`. Those counts do not move with scheduler load.

## What was measured and rejected

- **Fancy-indexing reloc normalization**: 0.7× slower; kept the slice loop.
- **Replacing `SequenceMatcher`**: changes calibrated scoring; rejected.
- **Lazy CLI domain mounting**: `app.builtins` activates every domain at
  import so the umbrella can mount its groups, which imports every command
  module: 13 `activate()` calls measured ~0.17 s of a fresh `status` process
  (about 26%). The 0.29 s `--version` still imports the whole command surface.
  Deferring it needs a custom click group (Typer converts every registered
  sub-Typer before it parses arguments), which is a composition-layer change
  rather than a local edit; not attempted here.

## GA bottleneck: compilation, not scoring

Measured on smygb (512-byte function, real MSVC6 toolchain):

- one compile + byte-compare (`rebrew test`): **≈ 585 ms**
- one `score_candidate` call (reloc path, precomputed target): **≈ 0.36 ms**
  (`tools/bench_hotpaths.py`, "GA candidate scoring" row)

Scoring is ~1600× cheaper than a compile, so the GA's wall-clock is
dominated by Wine/compiler subprocesses (which the compile cache
mitigates), not by the numpy/capstone scoring path. Future perf work on
the GA should target compile throughput (cache hit rate, parallel
compiles), not `score_candidate`.

## Dashboard first paint (`bootstrap` / `/api/functions`)

*(Superseded: the dashboard reads the live project coverage view and serves an
immutable in-memory snapshot, so the per-request connections and per-row
`json.loads` this section measured no longer exist. The numbers below are kept
as the record of why the reader is snapshot-based.)*

Nested query methods each opened their own read-only SQLite connection.
Cold-start `bootstrap()` therefore connected four times (targets, known-target
check, summary, functions); `/api/functions` and `/api/summary` connected twice
(`target_known` then the query). The reader now parses each coverage document
once, caches the immutable snapshot against the document's stat, and every
route answers from that one object: the connect counts are structurally zero
rather than reduced. Gates: `TestQueryLayer.test_one_response_reads_one_snapshot`,
`test_revalidation_matches_the_get_it_stands_in_for`.

Measured 50 warmed calls on 500 synthetic functions (CPU time, `getrusage`):

| Path | before connects | after connects | CPU / 50 |
|---|---|---|---|
| `bootstrap()` | 4 | 1 | 0.047 s → 0.036 s |
| `/api/functions` | 2 | 1 | 0.050 s → 0.044 s |
| `/api/summary` | 2 | 1 | 0.008 s → 0.004 s |

`_files_display` takes the `files` tuple the reader already decoded (a JSON
string per row cost 55 % of `/api/functions` CPU on 500 rows). Row counting is
skipped when the first page is already short; a later short page (offset past
the end) still pays for it.

Measured 100 warmed `/api/functions` calls on 500 synthetic functions
(CPU time, `getrusage` / `cProfile`):

| | calls | CPU / 100 | `json.loads` |
|---|---|---|---|
| after connect reuse | 660 920 | 0.185 s | 50 000 |
| after files/COUNT skip | 361 001 | 0.067 s | 0 |

`/api/functions` now emits compact arrays under `cols` instead of per-row
dicts. 500-row JSON 58 915 → 31 978 bytes (0.54×). `json.dumps` CPU / 200:
0.033 s → 0.020 s. Gate: `TestHostValidation.test_functions_omit_unused_kind`.

`/api/globals` and `/api/history` use the same compact-array shape. 100-row
globals JSON 8053 → 4597 bytes (0.57×); gzip-5 872 → 821. Gate:
`test_functions_omit_unused_kind` (cols lists).

`/api/sections` moved to it too, on the 14-column rows. 2000-section JSON
346 091 → 88 229 bytes (0.25×); the size now comes from a join on the
`(target, name)` primary key instead of a second query plus a lookup dict.
Gates: `test_sections`, `test_api_sections_includes_count_total`.

Wire encoding: responses negotiate `zstd` then `gzip` from `Accept-Encoding`
(q-values; zstd wins ties). HTML shell and `/app.js` are compressed lazily on
first use and cached at both codecs. Measured 500-row functions JSON:
gzip-5 4728 → zstd-5 2912 bytes. Gates: `TestEncodingNegotiation`,
`test_handler_serves_precompressed_static`.

Shell HTML (zstd-19): 3677 bytes on the wire (was ~8.2 KB with inlined JS).
`/app.js` is served without its full-line comments (they stay in the source the bun harness runs). At this checkpoint, both entry assets totaled 11337 bytes zstd / 11915 gzip, inside the RFC 6928
14600-byte initial window less a 500-byte-per-response header reserve
(`_ENTRY_WIRE_BUDGET_BYTES`, 13600), so the loading chrome paints before
`/app.js` finishes. Gate:
`test_entry_assets_fit_initial_congestion_window`.

Gzip size also depends on the host's zlib version. These byte counts are a
measurement checkpoint; tests enforce the 13600-byte budget on every host.

The gzip path is the binding one: 11915 of 13600 budgeted bytes, 1685 to spare
(zstd has 2263). With the measured response headers (560 shell, 592 `/app.js`)
the two entry responses total 13067 bytes, 1533 under the 14600-byte window,
the preloaded bootstrap rides past it, as below. Any shell or client growth
has to come out of that remaining space, so trim copy before adding an asset.
`test_cold_flight_fits_the_window_against_measured_headers` is the check that
counts the real header block, so it is the one to read when the fixed-reserve
proxy is at its edge.

Every non-entry 200 answers `Server-Timing: route;dur=<ms>`, so the browser's
Network panel separates the query from the transfer and a slow route shows up
before the access log does. The entry assets omit it: their cold flight
is budgeted to the byte, and the value is a constant there. Gate:
`TestServerTiming`.

Two per-response costs came off that same window. `send_response` is overridden
to send the status line, `Date` and `X-Request-Id` only, dropping the stdlib
`Server: BaseHTTP/0.6 Python/<patch>` banner: measured header blocks 592 → 555
(shell) and 624 → 587 (`/app.js`), 13324 bytes for
the two responses with bodies instead of 13797. `disable_nagle_algorithm`
is set because headers and body leave as two writes on an unbuffered socket,
so Nagle would hold the body's first segment until the header block is
acknowledged. Gates: `TestResponseFraming`.

`<link rel="preload" href="/api/bootstrap" as="fetch"
crossorigin fetchpriority="high">` plus `/app.js` script preload lets
bootstrap overlap the deferred client download. The client `fetch()` keeps
the default `same-origin` credentials, the mode `crossorigin` (anonymous)
preloads with; any other mode misses the preload and fetches bootstrap twice. Gate: `test_index_html_bootstraps_in_one_round_trip`.

The boot guard is inline in the shell and runs on `DOMContentLoaded`, which
every deferred client precedes, so a client that never set
`globalThis.__rebrewBooted` (aborted transfer, parse error) leaves a message
and a reload prompt instead of a permanent "Loading coverage…". It was a
deferred `/boot-guard.js` asset, which cost a third request, ~640 bytes of
header reserve, and 245 gzip bytes for 424 raw ones: inline it compresses
with the shell it rides in, and the cold flight drops to two responses. The
policy still allows no inline script it has not hashed: `script-src 'self'`
plus that one script's `sha256`, never `'unsafe-inline'`. Gates:
`test_boot_guard_is_inline_and_runs_after_the_client`,
`test_boot_guard_rides_the_precompressed_shell`.

Repeat loads: the shell links `/app.js?v=<content hash>` and
`/favicon.svg?v=<content hash>`, both served
`private, max-age=31536000, immutable`, and the mark is served from
that route instead of being requested as an implicit
`/favicon.ico` (a no-store 404). A warm reload is two requests
(shell 304, bootstrap 200): the client and the mark are answered from
the browser's own cache and are not requested at all. Gates:
`test_handler_caches_only_hashed_client_urls_immutable`,
`test_index_html_links_the_served_favicon`, `test_favicon_route_serves_the_theme_mark`,
`test_favicon_hash_matches_the_served_bytes`.

The mark moved out of the shell for the cold flight, not for the request count.
A percent-encoded data URI is 443 raw bytes of near-incompressible payload
inside the one document that has to fit RFC 6928's initial window, and it cost
178 gzip bytes of the shell; linked, it is fetched off the critical path (a tab
icon is not first paint). Hashing the linked URL cost 16 gzip bytes of the
shell and buys the whole icon request back on every load after the first. The
entry assets are now 11337 zstd / 11915 gzip against the 13600 B budget, so
gzip has 1685 B of room. One shell-trimming idea is a negative result worth
recording: deduplicating near-identical JavaScript *raised* the compressed
size by 340 B even though it removed 262 raw ones, because the copies were
what gzip matched.

First page default is 100 rows (Show more still 500). On 2000 synthetic
functions, `/api/functions` CPU / 100: 500 rows 0.059 s / 32 KB → 100 rows
0.026 s / 6 KB. The bootstrap pages at its own smaller first page
(`_BOOTSTRAP_FUNCTION_LIMIT`, 40): it is preloaded onto the same cold
connection as the shell and `/app.js`, which already spend most of the entry
window before any data is counted. 40 rows measure 711 zstd / 776 gzip against
1083 / 1305 for the full 100-row page, and 60 fewer rows of `innerHTML` before
the page is interactive. Show more continues from `loadedCount` against the
payload's real `total`, so nothing stops being reachable. The preloaded body
has its own ceiling (`_BOOTSTRAP_WIRE_BUDGET_BYTES`, 1024) because no part of
the cold flight is left to absorb a growing first page. Gates:
`test_bootstrap_stays_inside_its_wire_budget`,
`test_bootstrap_paginates_past_its_first_page`.

Remaining: 100-row HTML join. Table virtualization, splitting the non-Functions
views out of `/app.js`, and cross-request pooling were not measured. The
initial-window budget does not yet count the preloaded bootstrap among the
entry assets: measured, the two entry responses fill 13067 of the 14600
window with the reserved headers, so the bootstrap's 776 B now fits beside them.

`/app.js` pays for the row render too, not only the download. `esc()` looked
up its five entities in a fresh object literal on every matched character, so
a 5000-row page allocated one per escaped cell; the table and the regex now
sit at module scope (1.1x over 35000 cells, bun). Two dead paths went with it
to stay inside the window: the object shape `historyRowHtml` still accepted
(`/api/history` answers positional arrays under `cols` and has for some time),
and the sections page's empty `tip`/`tipCapped` (it is unpaged, so the branch
that reads them is unreachable). The shell lost `-webkit-overflow-scrolling:
touch`, which only ever affected iOS Safari 12 and older while the same
stylesheet already requires Safari 15.4 for `content-visibility`; the report
page carries the same dead declaration and it is gone there too. Gate:
`test_entry_assets_fit_initial_congestion_window` is what forces the trade.

Dashboard shell gzip is 3796 bytes (the inline guard included) and
`/app.js` gzip is 8119 bytes at this measurement checkpoint (full-line comments stripped from the served copy; the source the harness runs still has them). Fixed
`mtime=0` makes those bytes a function of the content, so a restart does
not serve a different body under the same ETag. Gate:
`test_handler_serves_precompressed_static`.

## Report pages (`rebrew coverage report`)

The report is a static site (opened from disk or hosted), so the entry HTML
is the critical path. Index and strings were already paged at 250 rows.
Imports and import stubs use that budget. A Mermaid source over 32 KB
(32768 bytes) moves to `callgraph.mmd`; `graph.html` keeps the opening lines.

Measured on synthetic payloads (raw HTML / gzip-9, `mtime=0`):

| Page | before | entry page after |
|---|---|---|
| 2000 imports | 187344 / 13220 | 28614 / 3593 (8 pages) |
| 900-node call graph | 119060 / 16025 | 8026 / 2585 (`callgraph.mmd` is 101956 bytes, gzip 13064) |

A rebuild deletes owned pages and `.gz`/`.zst` sidecars it did not write,
so a static server cannot keep serving the previous body under the same
name. Gates: `TestReportPayloadShape`.

The mark is a linked `favicon.svg` beside the pages, not a data URI in every
head: 370 bytes of `rel=icon` markup become 57, and the 266-byte icon (208
gzip) is fetched once for the site and cached after that, the same trade the
dashboard shell makes with its own `/favicon.svg` route. Every page also
ships its `.gz`/`.zst` sidecars, so a static server that prefers them serves
the icon and the pages precompressed.

## Idempotency

`tools/check_idempotency.py` runs its 18 commands twice as an offline
CI step, comparing exit codes and parsed JSON after recursively removing
`timestamp` keys. JSON formatting and object-key order do not affect the
comparison; non-JSON output is compared verbatim. This check does not establish
raw byte identity or cover invocations outside that list. See [CI.md](CI.md).

The same tool runs each of its 24 mutating commands (`source register`,
`source document-unmatched`, `build link-stubs`, both `skeleton` forms, `coverage export`, `coverage import-history`, `export symbols`,
`build cmake-toolchain`, `source fix`, `export context`, both `blocker set` forms, both
`library set` forms, `coverage report`, the three `data` forms: `header`,
`set --type`, `set --section`, and the five `cfg` forms that write
`rebrew-project.toml`: `set`, `target set-compiler`, `module add`, `module set-cflags`,
`target add`) twice against their own
fresh fixture project and
content-digests the whole tree after each run, so a command that appends an
address anchor, a stub or a metadata row on every execution fails the gate.
A first run that changes nothing also fails it: exiting 0 twice over an
unchanged tree is what a mutating command looks like once it has stopped
mutating, and the digest compares alone cannot tell that from safety.
