# Data command JSON shapes and failure modes

`--json` prints one JSON document on **stdout** (rich tables go to stderr). Parse it
with `jq` or Python; do not parse the terminal output.

## Inventory (`--json` / `--conflicts` / `--summary`)

All three emit this inventory. `--conflicts` keeps only conflicting names in
`globals` (and recounts `summary`); `--summary` replaces `summary` with
`{"sections": [{"name", "globals", "annotated", "annotated_bytes", "declared_bytes",
"section_size", "coverage_pct"}], "conflicts"}` (`annotated_bytes` is the union
of the annotated spans clipped to the section, the same number `coverage_pct`
is taken from; `declared_bytes` is the raw sum of the declared type sizes):

```json
{"globals": {"g_name": {"name": "g_name", "type": "int *", "va": "0x10025000",
                        "section": ".bss", "declared_in": ["server/main.c"],
                        "defined_in": ["server/owner.c"], "referenced_in": ["server/main.c"],
                        "library_owners": [],
                        "annotated": true}},
 "data_annotations": [{"va": "0x10025000", "name": "g_sprite_lut", "size": 256,
                       "section": ".rdata", "note": "lookup table", "filepath": "server/main.c"}],
 "type_conflicts": [{"name": "g_count", "types": {"int": ["a.c"], "short": ["b.c"]}}],
 "summary": {"total": 42, "annotated": 10, "unannotated": 32, "data_entries": 5, "conflicts": 1, "multiple_definitions": 0, "library_owned": 0},
 "sections": {".data": {"va": "0x10022000", "size": 4096}}}
```

`defined_in` lists source storage definitions, including tentative definitions and
initialized externs. `declared_in` lists all source/header declaration sites,
including definitions. `referenced_in` lists syntactic expression references,
excluding declaration names, member names, and local shadows. Users can reference
a symbol supplied by an included header without redeclaring it in their `.c`.
These are raw source facts: macros/conditional branches are not preprocessed, and
archive ownership requires separate link evidence. An empty `defined_in` means
no source definition found, not a claim that a specific library owns the symbol.
`summary.multiple_definitions` counts globals with more than one source definition.
`library_owners` records `{library, member, symbol, linked_va, map, map_hash,
evidence}`; evidence is `link-map`, or `link-map+archive` with `archive_hash` for
COMMON data. `summary.library_owned` counts globals with an established library
owner. The default map is the configured `raw_link` image with `.map` suffix;
`--link-map PATH` selects another. Missing automatic maps are optional; explicit
unreadable maps error. A map and its hashes describe a build snapshot, not proof
that the reference bytes match. Names must match the C/link spelling; VAs, header
names, CRT prefixes, and unselected archive definitions establish no owner.


Check `summary.conflicts > 0` to decide whether `--conflicts` needs attention.
`globals` with `"annotated": false` are plain `extern` declarations with no VA;
give them `// GLOBAL: MODULE 0xVA` markers so they resolve to a section.

## `--bss --json`

`{"bss_va", "bss_size", "known_entries": [{"name", "va", "size_hint", "source_file"}],
 "gaps": [{"offset", "size", "between": [before, after]}], "coverage_pct",
 "summary": {"total_globals", "gaps", "total_gap_bytes"}}`.

A gap is uncovered inventory, not proof of missing storage. Check complete extents,
alignment, interior views, and linked library storage before using `--fix-bss`.

## `--dispatch --json`

A list of tables:
`[{"va", "section", "num_entries", "resolved", "coverage", "entries": [{"target_va",
"name", "status"}]}]`. `status` is `EXACT`/`RELOC`/`NEAR_MATCHING`/`STUB` or `""`
(unknown). Low `coverage` means the table's targets have no reversed source yet,
which makes them good next-matching candidates.

## Failure modes

`verify --data --json` includes a `data.results` row for every visible named
symbol: `{module, va, name, size, status}` plus `first_diff` on a content
mismatch. Identity is `(module, va)`; aliases keep separate verdicts and
symbols from another target are excluded. The result row also carries
`input_hash` and `definition_hash`; only an acknowledged raw-link comparison
writes them into canonical verification evidence. Incomplete reference bytes remain
`UNCHECKED`; missing or truncated built bytes are `DRIFT`.

| Symptom | Cause | Fix |
|---|---|---|
| `rebrew-project.toml not found` / config error | Running outside a project | `cd` into the project (config discovery walks up to `rebrew-project.toml`) |
| `target binary not found` / `could not be parsed (needed for --dispatch)` | Binary missing or unparseable | Fix `target_binary` in `rebrew-project.toml`; only `--dispatch` hard-requires the binary (plain scans degrade gracefully) |
| `already exists. Use --force to overwrite.` | `--gen-header` clobber guard | Pass `--force`, or `--gen-header-out` to a new path |
| `No annotated BSS globals: nothing to verify` | No `// GLOBAL:`/`extern` with a `.bss` VA | Add annotations first, then re-run `--bss` |
| Gap size looks wrong | `size_hint` is estimated from the C type (int=4, char=1, …) | Verify the declared types of the globals on either side of the gap |
| Small gaps not reported | Gaps < 4 bytes are alignment padding and intentionally ignored | Ignore; only ≥ 4-byte gaps are flagged |
