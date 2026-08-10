# Rebrew Tooling Improvement Ideas

Ideas collected during hands-on workflow testing, sorted by impact-to-effort ratio.

---

## Completed

| # | Idea | Notes |
|---|------|-------|
| 15 | Compile result cache | `compile_cache.py` — SHA-256 hash-based `.obj` caching via `diskcache`. CLI: `rebrew cache stats/clear`. 23 tests. |
| 17 | Match regression detection | `rebrew verify --compare` — compares verify results against last saved report. Exit code 1 on regressions. |
| 18 | Batch promote | `rebrew verify` — bulk compile, auto-updates STATUS/BLOCKER for all functions (always-on). Supports `--compare`, `--dry-run`. |
| 1 | CRT source cross-reference tool | `rebrew crt-match` — indexes CRT source directories, matches by name with confidence tiers, auto-writes `// SOURCE:`. 19 tests. |
| 2 | Data Sync and XREF Pipeline | `rebrew sync --pull-data` — fetches data labels from Ghidra, generates `rebrew_globals.h`. 11 tests. |
| 16 | Auto-download wibo | `wibo.py` — `download_wibo()`, `find_wibo()`, `ensure_wibo()`. CLI: `rebrew doctor --install-wibo`. 15 tests. |
| 3 | Incremental verify | `rebrew verify` uses `.rebrew/verify_cache.json`, `--full` forces rebuild. |
| 6 | XREF context in skeleton | `rebrew skeleton --xrefs` — fetches cross-references via MCP, decompiles callers. 9 tests. |
| 7 | Ghidra decompilation backend | `fetch_ghidra()` in `decompiler.py` via ReVa MCP `get-decompilation`. 12 tests. |
| 9 | Validate programPath | `ghidra_program_path` config + `_resolve_program_path()` in `sync.py`. |
| 12 | Auto-BLOCKER classification | `rebrew match --diff-only --fix-blocker` — `classify_blockers()` auto-writes metadata. 20 tests. |
| 13 | Multi-function file splitting | `rebrew split` + `rebrew merge` — split/merge with preamble preservation. 20 tests. |
| 14 | Semantic equivalence with angr | `rebrew prove` — symbolic execution + Z3 constraint solving. Optional dep. |
| — | Coverage dashboard | Sibling project `recoverage` — consumes `data_{target}.json`. |
| — | CRT auto-detection | `rebrew cfg detect-crt` — scans `tools/` for known MSVC CRT source dirs. `detect_crt_sources()` in `config.py`. |
| — | Dotted key resolution | `rebrew cfg show/set/get` — greedy longest-match resolution for TOML keys containing dots. |
| — | CLI code audit / deduplication | `normalize_name()` in `naming.py`; `disasm_bytes()` in `asm.py`; `iter_annotations()` in `cli.py`; removed `_find_block_lines` dead code; removed `_make_progress_printer` in favour of `Console(stderr=True)` pattern. All 1784 tests pass. |
| 4 | GA code layout mutations | `mutator.py` — 120 structural mutations for GA exploration. |
| 19 | Cross-function solution transfer | `solutions.py` — GA auto-saves and seeds from `.rebrew/solutions.json`. |

---

## Completed (recent additions — see CHANGELOG for details)

| # | Idea | Notes |
|---|------|-------|
| 20 | Test watch mode | `--watch` shipped on test/verify/match (shared `watch_files` helper). |
| 21 | Binary similarity search | `rebrew similar` — mnemonic-histogram + call/branch agreement scoring. |
| 22 | Deep NEAR_MATCHING analysis | `rebrew near-diag` classifies the blocking compiler choice per function. |
| 25 | Memory side-effect checking in prove | `test_prove_memory_watch.py` — watched-VA memory comparison in `prove_equivalence`. |
| — | One-shot onboarding | `rebrew intake` (toolchain detect → init → functions → document). |
| — | PDB import | `rebrew pdb-info` — S_COMPILE3 version + flags (`--write-cflags`) + names. |
| — | Function discovery | `rebrew discover-functions` — aaa→aap→capstone sweep with boundary validation. |
| — | Toolchain-version sweep | `rebrew match --sweep-toolchain` — which MSVC SP built this function. |
| — | Cross-project solutions seeding | `rebrew match --all --seed-solutions <path>` — borrow winning cflags across projects. |
| — | Library identification | `rebrew identify-library` — FLIRT + imports + CRT merged into `library_*.h`. |
| — | Intelligence dossier | `rebrew analyze` — one-shot recon (toolchain, strings, imports, dispatch, FLIRT); `--output report.md`, `--function 0xVA` drill. |
| — | In-repo binary fixtures | `tests/fixtures/` + `tools/gen_fixtures.py` — CI parse/compare/reloc coverage without wine. |
| — | JSON purity contract | `tests/test_json_purity.py` + `tools/check_idempotency.py` (16 commands, CI step). |
| — | Typed metadata facade | `metadata_model.MetadataEntry` + property round-trip tests. |
| — | Ghidra enum/typedef sync | `extract_enums_from_file`, push via CParser, merge-safe `--pull-datatypes`. |
| — | GA scoring fast paths | identical-bytes + mnemonic-equality shortcuts (1.76× measured; `docs/PERFORMANCE.md`). |
| — | Recoverage schema parity | `tests/test_recoverage_contract.py` pins the DB contract recoverage reads. |

## Open Ideas

### 23. LLM-assisted GA seed generation

**Pain**: GA mutations are currently generated using fixed deterministic rules in `mutator.py`. These might miss subtle patterns needed to nudge the compiler.

**Proposed**: Integrate an optional LLM call in `rebrew match` that looks at the `NEAR_MATCHING` assembly diff and suggests specialized C source permutations to seed the genetic algorithm.

**Impact**: High — could break through the "systemic ceiling" of register allocation issues by coming up with creative C constructs.

### 25. Memory side-effect checking in `rebrew prove` (E9 v2)

**Pain**: `rebrew prove` compares EAX (and optionally EDX) but ignores memory writes. Functions that write to global variables or through output-pointer arguments can be falsely promoted to PROVEN when their memory side effects differ between the original and the compiled version.

**Proposed**: Thread a list of "watched" virtual addresses through `prove_equivalence` and compare `state.memory.load(va, 4)` across state pairs for each watched address. The user would specify watched VAs via `prove_constraints` metadata (e.g. `watched_vas = [0x10123456]`) or via a future `--watch-va` CLI flag.

**Impact**: Medium-high — closes a correctness gap for functions with observable side effects. Prerequisite: the watched-VA list must be small (< 10) to avoid Z3 blowup.

### 24. Ghidra-CLI as alternative Ghidra transport *(done)*

`ghidra_backend = "cli"` in `rebrew-project.toml` routes sync push (apply)
and pull (functions/symbols/comments) through the `ghidra-cli` binary instead
of ReVa MCP (`src/rebrew/ghidra/cli_backend.py`). Per-op invocations are used
deliberately for push: the `batch` file format splits lines on whitespace, so
args containing spaces (plate comments, signatures) cannot be batched safely.

**Pain**: `rebrew sync` currently requires a running Ghidra instance with the ReVa MCP extension installed. ReVa is a heavyweight requirement: AI-tuned, MCP-only, brings its own dependencies, and breaks the workflow for users who want plain headless Ghidra scripting.

**Proposed**: Add a second sync backend on top of [`ghidra-cli`](https://github.com/nonsleepr/ghidra-cli) — a thin command-line wrapper around Ghidra's headless analyzer that exposes function rename, label, comment, and struct operations via stdin/stdout JSON. Selectable via `cfg.ghidra_backend = "reva" | "cli"` (default keeps ReVa for back-compat). The push/pull command set stays identical; only the transport changes. Lets users without ReVa still sync, and makes CI integration easier (no live Ghidra instance needed — ghidra-cli spawns one per call).

**Impact**: Medium-high — removes ReVa as a hard dependency and unlocks headless / CI sync. Implementation footprint is contained to `src/rebrew/ghidra/` (new `cli.py` backend alongside the existing MCP client).

---

## Observations (Reference Knowledge)

Moved to [`MATCH_TYPES.md`](MATCH_TYPES.md#observed-near-matching-patterns)
— these are byte-level reference observations, not actionable ideas.
