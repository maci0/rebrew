# Rebrew Performance Notes

Measured facts about where rebrew's hot paths spend time, and what was done
(and deliberately *not* done) about it.

## Ten additional source-scan rounds (2026-10-14)

Committed the preceding work at `81a9ecbf`, then ran ten additional, interleaved
CPU-time experiments. Nine changes remain; lazy prototype-line splitting was
reverted. The [round ledger](benchmarks/2026-10-14-rounds/README.md) contains all
measurements, decisions, candidate patches, output identities and reproduction
commands.

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
uv run --frozen python tools/bench_hotpaths.py --output before.json
# Change the implementation, keeping benchmark workloads unchanged.
uv run --frozen python tools/bench_hotpaths.py --compare before.json --output after.json
```

Eighteen workloads cover metadata loading, address binding, source-purpose
reads, source-tree scans, catalog/status aggregation, verify and compile-cache
hits, registry construction, binary similarity, structural diffing, GA scoring,
and mutation application. The [recorded reports](benchmarks/2026-10-14/manifest.json)
identify the three baseline metadata modules from v3.0.0 and their optimized
replacements. Other source files were held fixed. The paired measurements below
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
[Profiled work counts](benchmarks/2026-10-14/work-counts.json) dropped from
1,777,712 to 889,812 function calls. Source reads fell from 190 to 100,
whole-data-map loads from 100 to zero, and signature inventories from 213 to 113.
These work counts remain comparable under scheduler load.

Three changes account for the targeted reductions:

- Bindings reuse the source text already read and extract prototypes once;
  unmatched function anchors share one function lookup map.
- Data anchors use indexed single-entry lookups instead of copying every
  unrelated data row for every source file.
- Source-purpose and assembly views share an immutable, bounded cache keyed by
  resolved path, modification nanoseconds, size and inode. Comment validation
  prunes function bodies whose comments it already ignores.

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

## What was measured and rejected

- **Fancy-indexing reloc normalization**: 0.7× slower; kept the slice loop.
- **Replacing `SequenceMatcher`**: changes calibrated scoring; rejected.

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

*(Superseded: the dashboard reads `db/coverage-<target>.toml` and serves a
frozen in-memory snapshot, so the per-request connections and per-row
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
0.033 s → 0.020 s. Gate: `test_functions_omit_unused_marker_type`.

`/api/globals` and `/api/history` use the same compact-array shape. 100-row
globals JSON 8053 → 4597 bytes (0.57×); gzip-5 872 → 821. Gate:
`test_functions_omit_unused_marker_type` (cols lists).

`/api/sections` moved to it too, on the 14-column rows. 2000-section JSON
346 091 → 88 229 bytes (0.25×); the size now comes from a join on the
`(target, name)` primary key instead of a second query plus a lookup dict.
Gates: `test_sections`, `test_api_sections_includes_count_total`.

Wire encoding: responses negotiate `zstd` then `gzip` from `Accept-Encoding`
(q-values; zstd wins ties). HTML shell and `/app.js` are precompressed at both
codecs at import. Measured 500-row functions JSON:
gzip-5 4728 → zstd-5 2912 bytes. Gates: `TestEncodingNegotiation`,
`test_handler_serves_precompressed_static`.

Shell HTML (zstd-19): 3564 bytes on the wire (was ~8.2 KB with inlined JS).
Both entry assets total 12690 bytes zstd / 13317 gzip, inside the RFC 6928
14600-byte initial window less a 640-byte-per-response header reserve
(`_ENTRY_WIRE_BUDGET_BYTES`, 13320), so the loading chrome paints before
`/app.js` (9131 zstd) finishes. Gate:
`test_entry_assets_fit_initial_congestion_window`.

The gzip path is the binding one: 13317 of 13320 budgeted bytes, 3 to spare
(zstd has 630). With the measured response headers (560 shell, 592 `/app.js`)
the two entry responses total 14473 bytess, 129 under the 14600-byte window;
the preloaded bootstrap rides past it, as below. Any shell or client growth
has to come out of that 1 gzip byte, so trim copy before adding an asset.
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
entry assets are now 12690 zstd / 13317 gzip against the 13320 B budget, so
gzip has 1 B of room. One shell-trimming idea is a negative result worth
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
entry assets: measured, the two entry responses fill 14465 of the 14600
window with their real headers, so folding the bootstrap's 776 B in needs the
static shell to shrink first.

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

Dashboard shell gzip is 3872 bytes (the inline guard included) and
`/app.js` gzip is 9418 bytes (same
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

Every offline `--json` command is deterministic across runs: enforced by
`tools/check_idempotency.py` (18 commands, run twice, byte-compared) as a CI
step; see `docs/CI.md`.

The same tool runs each of its 23 mutating commands (`source register`,
`source document-unmatched`, `build link-stubs`, both `skeleton` forms, `coverage build`, `export symbols`,
`build cmake-toolchain`, `source fix`, `export context`, both `blocker set` forms, both
`library set` forms, `coverage report`, the three `data` forms: `--gen-header`,
`--set-type`, `--set-section`, and the five `cfg` forms that write
`rebrew-project.toml`: `set`, `set-compiler`, `add-module`, `set-cflags`,
`add-target`) twice against their own
fresh fixture project and
content-digests the whole tree after each run, so a command that appends a
marker, a stub or a metadata row on every execution fails the gate.
A first run that changes nothing also fails it: exiting 0 twice over an
unchanged tree is what a mutating command looks like once it has stopped
mutating, and the digest compares alone cannot tell that from safety.
