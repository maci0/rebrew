# CLI Reference

All 32 CLI tools are installed as entry points via `pyproject.toml`.
Every tool supports `--target / -t` to select a target from `rebrew-project.toml` and
reads defaults (binary path, reversed_dir, compiler settings) from the project config.

Run any tool with `--help` to see usage examples and context
(typer `rich_markup_mode="rich"` with epilog text).

## Entry Points

| Entry Point | Script | Description |
|-------------|--------|-------------|
| `rebrew` | `main.py` | Unified CLI entry point for all subcommands |
| `rebrew-rename` | `rename.py` | Rename a function and update all cross-references |
| `rebrew-init` | `init.py` | Scaffold a new project directory and `rebrew-project.toml` |
| `rebrew-test` | `test.py` | Compile-and-compare; auto-promotes STATUS on EXACT/RELOC; `--no-promote` to skip; `--json` output |
| `rebrew-asm` | `asm.py` | Dump disassembly (`--format hex`) or NASM (`--format nasm`) from target binary at a VA |
| `rebrew-diff` | `diff.py` | Side-by-side disassembly diff against target binary; `--fix-blocker` writes BLOCKER annotations |
| `rebrew-skeleton` | `skeleton.py` | Generate annotated `.c` skeleton from VA (with `--decomp`, `--xrefs`, `--append` for multi-function files) |
| `rebrew-catalog` | `catalog/` | Parse annotations, generate catalog + coverage JSON |
| `rebrew-sync` | `ghidra/cli.py` | Sync annotations, structs, and signatures to/from Ghidra via ReVa MCP (`--push`, `--pull`, `--apply`, `--export`) |
| `rebrew-lint` | `lint.py` | Lint annotation standards in decomp C files |
| `rebrew-extract` | `extract.py` | Batch extract and disassemble functions from binary |
| `rebrew-match` | `match.py` / `matcher/` | GA matching engine (`--fix-blocker`); `--json` structured output |
| `rebrew-ga` | `ga.py` | Batch GA runner for STUB and MATCHING functions |
| `rebrew-verify` | `verify.py` | Compile all `.c` files and verify byte match against target binary; `--diff` regression detection; `--json` structured reports |
| `rebrew-todo` | `todo.py` | Prioritized action list: what to work on next, ROI-ranked across all signals |
| `rebrew-cache` | `cache_cli.py` | Compile cache management (`stats`, `clear` subcommands) |
| `rebrew-cfg` | `cfg.py` | Read and edit `rebrew-project.toml` programmatically (see [CONFIG.md](CONFIG.md)) |
| `rebrew-split` | `split.py` | Split multi-function C files into individual files |
| `rebrew-merge` | `merge.py` | Merge single-function C files into multi-function file |
| `rebrew-prove` | `prove.py` | Prove semantic equivalence via angr symbolic execution (optional dep) |
| `rebrew-flirt` | `flirt.py` | FLIRT signature scanning (see [FLIRT_SIGNATURES.md](FLIRT_SIGNATURES.md)) |
| `rebrew-crt-match` | `crt_match.py` | CRT source cross-reference matcher (index, match, ASM detection) |
| `rebrew-data` | `data.py` | Global data scanner for .data/.rdata/.bss; `--bss` layout verification; `--dispatch` vtable detection |
| `rebrew-graph` | `depgraph.py` | Function dependency graph (mermaid, DOT, summary); `--cu-map` infers compilation unit boundaries |
| `rebrew-doctor` | `doctor.py` | Diagnostic checks for project health (config, compiler, binary, paths); `--install-wibo`; `--json` |
| `rebrew-build-db` | `build_db.py` | Build SQLite `db/coverage.db` from `data_*.json` ([schema docs](DB_FORMAT.md)) |

## Tool Flags

### `rebrew match`

| Flag | Description |
|------|-------------|
| `--cl COMMAND` | CL.EXE command (auto from config) |
| `--inc DIR` | Include dir (auto from config) |
| `--cflags FLAGS` | Compiler flags (auto from source) |
| `--symbol NAME` | Symbol to match (auto from source) |
| `--target-va HEX` | Target VA hex (auto from source) |
| `--target-size N` | Target size (auto from source) |
| `--diff-only` | Side-by-side disassembly diff (no GA) |
| `--mm` / `--mismatches-only` | With `--diff-only`, show only structural (`**`) lines + summary |
| `--rr` / `--register-aware` | With `--diff-only`, normalize register encodings and mark as `RR` |
| `--diff-format FORMAT` | Output format for diff: `terminal` (default), `json`, `csv` |
| `--fix-blocker` | With `--diff-only`, auto-write `BLOCKER`/`BLOCKER_DELTA` annotations from diff classification |
| `--seed N` | Seed RNG for reproducible GA runs |
| `--force` | Continue even if annotation linter finds errors |
| `--generations N` | Number of GA generations (default 100) |
| `--pop-size N` | GA population size (default 32) |
| `-j N` | Parallel compilation workers |
| `--out-dir DIR` | Output directory for GA results |
| `--compare-obj` / `--no-compare-obj` | Use object comparison instead of full link (default: true) |
| `--extra-seed FILE` | Extra `.c` file(s) to seed GA population from solved functions |
| `--no-seed` | Disable cross-function solution seeding |
| `--link COMMAND` | LINK.EXE command (for non-obj comparison) |
| `--lib DIR` | Lib dir (for non-obj comparison) |
| `--ldflags FLAGS` | Linker flags (for non-obj comparison) |

### `rebrew test`

| Flag | Description |
|------|-------------|
| `--all` | Batch test all reversed .c files |
| `--dir PATH` | With `--all`, restrict to this subdirectory |
| `--origin TYPE` | With `--all`, filter by origin (GAME, MSVCRT, ZLIB) |
| `--dry-run` | Preview changes without writing |
| `--no-promote` | Skip STATUS annotation update |
| `--json` | JSON structured output |

### `rebrew rename`

`rebrew rename <old_ident> <new_name>`

Atomically renames a function across the entire project.

| Flag | Description |
|------|-------------|
| `--symbol NAME` | Override symbol name (default: derived from C function definition as `_<new_name>`) |
| `--file NAME` | New filename (default: auto-rename if stem matches old name) |
| `--json` | Output results as JSON |

Behavior:

- Symbol is derived automatically from the C function definition
- Updates the C function definition name
- Replaces `extern` cross-references across all `.c` files
- Renames the file itself if the stem matches the old name

### `rebrew todo`

| Flag | Description |
|------|-------------|
| `-n N` / `--count N` | Number of items to show (default 20) |
| `-c CAT` / `--category CAT` | Filter by category (e.g. `start-function`, `fix-verify-fail`) |
| `-s` / `--stats` | Show coverage stats in the panel title |
| `--json` | Output results as JSON |

### `rebrew skeleton`

| Flag | Description |
|------|-------------|
| `--va HEX` | Function VA in hex |
| `--decomp` | Embed inline decompilation |
| `--decomp-backend BACKEND` | Decompiler backend: `r2ghidra`, `r2dec`, `ghidra`, `auto` |
| `--xrefs` | Fetch cross-references and caller decompilation from Ghidra via ReVa MCP |
| `--endpoint URL` | ReVa MCP endpoint URL (for `--xrefs` and `--decomp-backend ghidra`) |
| `--append FILE` | Append to existing multi-function file |
| `--name NAME` | Override function name |
| `--origin TYPE` | Force compiler profile/origin type (GAME, MSVCRT, ZLIB) from config |
| `-o FILE` / `--output FILE` | Output file path |
| `--force` | Overwrite existing files |
| `--list` | List uncovered functions (no file generation) |
| `--batch N` | Generate N skeletons (smallest first) |
| `--min-size N` | Minimum function size (default 10) |
| `--max-size N` | Maximum function size (default 9999) |
| `--json` | Output results as JSON (for batch/list modes) |

### `rebrew verify`

| Flag | Description |
|------|-------------|
| `--fix-status` | Auto-update `STATUS` in `rebrew-function.toml` sidecar based on compile results |
| `--diff` | Compare against last saved `db/verify_results.json`, detect regressions/improvements; exit code 1 on regression |
| `--summary` | Show EXACT/RELOC/MATCHING summary table with match percentages |
| `--json` | Structured JSON report to stdout |
| `-o FILE` / `--output FILE` | Write report to specific file |

Output prefixes for unambiguous parsing:

| Prefix | Meaning |
|--------|---------|
| `COMPILE_ERROR:` | Source failed to compile |
| `MISMATCH:` | Compiled but bytes differ |
| `MISSING_FILE:` | Source file not found |
| `EXACT MATCH` / `RELOC-NORM MATCH` | Success |

### `rebrew ga`

| Flag | Description |
|------|-------------|
| `--max-stubs N` | Max functions to process, 0=all (default 0) |
| `--generations N` | GA generations per function (default 200) |
| `--pop-size N` | GA population size (default 48) |
| `-j N` / `--jobs N` | Parallel jobs (default: from `[project].jobs`) |
| `--timeout-min N` | Per-function GA timeout in minutes (default 30) |
| `--min-size N` | Min target size to attempt |
| `--max-size N` | Max target size to attempt |
| `--filter STR` | Only process functions matching this substring |
| `--near-miss` | Target MATCHING functions instead of STUBs |
| `--threshold N` | Max byte delta for `--near-miss` mode (default 10) |
| `--dry-run` | List candidates without running GA |
| `--seed-from-solved` / `--no-seed` | Seed GA population from similar solved functions (default: on) |
| `--json` | Output results as JSON |

### `rebrew doctor`

| Flag | Description |
|------|-------------|
| `--install-wibo` | Auto-download wibo (lightweight Wine alternative for Linux) |
| `--json` | Output results as JSON |

### `rebrew data`

| Flag | Description |
|------|-------------|
| `--conflicts` | Show only type-conflict globals |
| `--summary` | Show section-level summary only |
| `--bss` | Verify .bss layout and detect gaps |
| `--dispatch` | Detect dispatch tables / vtables |
| `--fix-bss` | Auto-generate `bss_padding.c` with dummy arrays for detected gaps |
| `--json` | JSON output for all modes |

### `rebrew graph`

| Flag | Description |
|------|-------------|
| `-f FORMAT` / `--format FORMAT` | Output format: `mermaid` (default), `dot`, `summary` |
| `--cu-map` | Infer compilation unit boundaries (clusters by .text contiguity + call graph) |
| `--origin ORIGIN` | Filter to specific origin |
| `--focus NAME` | Neighbourhood of a specific function |
| `--depth N` | Depth for focus mode |
| `-o FILE` / `--output FILE` | Output file (default: stdout) |
| `--json` | Output results as JSON |

### `rebrew lint`

| Flag | Description |
|------|-------------|
| `--fix` | Auto-migrate old annotation formats |
| `--quiet` | Suppress warnings, show errors only |
| `--json` | Machine-readable JSON output |
| `--summary` | Print status/origin breakdown table |
| `--files FILE...` | Check specific files instead of full scan |

See [ANNOTATIONS.md](ANNOTATIONS.md) for the full linter code reference (E000–E017, W001–W017).

### `rebrew catalog`

| Flag | Description |
|------|-------------|
| `--json` | Generate `db/data_<target>.json` |
| `--catalog` | Generate `CATALOG.md` in reversed directory |
| `--summary` | Print summary to stdout |
| `--csv` | Generate reccmp-compatible CSV |
| `--export-ghidra` | Cache Ghidra function list |
| `--export-ghidra-labels` | Generate `ghidra_data_labels.json` from detected tables |
| `--fix-sizes` | Update `SIZE` entries in `rebrew-function.toml` sidecar to match canonical sizes |
| `--root DIR` | Project root directory (auto-detected if omitted) |

### `rebrew sync`

| Flag | Description |
|------|-------------|
| `--export` | Export Ghidra commands to `ghidra_commands.json` |
| `--summary` | Show sync summary without exporting |
| `--apply` | Apply `ghidra_commands.json` to Ghidra via ReVa MCP |
| `--push` | Export and apply in one step |
| `--create-functions` | Create functions at annotated VAs before labeling |
| `--skip-generic` / `--no-skip-generic` | Skip/include generic `func_` labels (default: skip) |
| `--sync-sizes` | Sync function sizes to Ghidra |
| `--sync-new-functions` | Create functions for newly discovered VAs |
| `--sync-structs` / `--no-sync-structs` | Push struct definitions to DTM (default: sync) |
| `--sync-signatures` / `--no-sync-signatures` | Push function prototypes (default: sync) |
| `--sync-data` / `--no-sync-data` | Push data segment labels (default: sync) |
| `--pull` | Fetch Ghidra renames and comments and update local `.c` files |
| `--accept-ghidra` | With `--pull`, accept Ghidra renames for all conflicts (updates cross-references) |
| `--accept-local` | With `--pull`, keep local names for all conflicts (adds `// GHIDRA:`) |
| `--pull-signatures` | Pull function prototypes from Ghidra and update extern declarations |
| `--pull-structs` | Pull struct definitions from Ghidra into `types.h` |
| `--pull-comments` | Pull Ghidra analysis comments into source files |
| `--pull-data` | Fetch Ghidra data labels via MCP, generate `rebrew_globals.h` with typed extern declarations |
| `--dry-run` | Preview any sync operation without applying changes |
| `--endpoint URL` | ReVa MCP endpoint URL |
| `--json` | Output results as JSON |

### `rebrew flirt`

| Flag | Description |
|------|-------------|
| `SIG_DIR` | Directory containing `.sig`/`.pat` files (positional, optional) |
| `--exe FILE` | Target PE file (default: from config) |
| `--min-size N` | Minimum function size in bytes to report (default 16) |
| `--json` | Output results as JSON |

### `rebrew crt-match`

| Flag | Description |
|------|-------------|
| `VA` | Virtual address to match (positional, optional) |
| `--all` | Match all functions with library origins (MSVCRT, ZLIB, etc.) |
| `--origin ORIGIN` | Filter by specific origin (e.g. MSVCRT) |
| `--fix-source` | Auto-write `// SOURCE:` annotations for matches |
| `--index` | Show the CRT source index (files and functions) |
| `--target NAME` | Select a target from `rebrew-project.toml` |
| `--json` | Output results as JSON |

### `rebrew extract`

| Flag / Arg | Description |
|------------|-------------|
| `COMMAND` | `list`, `extract`, or `batch N` (positional argument) |
| `--min-size N` | Minimum function size to extract (default 8) |
| `--max-size N` | Maximum function size to extract (default 50000) |
| `--json` | Output results as JSON |

### `rebrew split`

`rebrew split <source_file> [--va HEX] [--output-dir DIR] [--dry-run] [--force] [--json]`

Split a multi-function `.c` file into individual single-function files. Each output file gets the shared preamble (includes, defines, extern declarations) plus its own annotation block and function body. Filenames are derived from the C function definition name; falls back to `func_<VA>.c` when no function definition is present.

With `--va`, extract a **single function** into its own file (into a `source_c/` subdirectory) and remove it from the original. This is useful for isolating a function to iterate on independently.

| Flag | Effect |
|------|---------|
| `--va HEX` | Extract a single function by VA into `source_c/name.c` and remove from original |
| `--output-dir DIR` | Write output files to DIR (default: same directory / `source_c/` for `--va`) |
| `--dry-run` | Preview changes without writing |
| `--force` | Overwrite existing output files |
| `--json` | Structured JSON output |

### `rebrew prove`

`rebrew prove <source> [--target NAME] [--json] [--timeout N] [--loop-bound N] [--dry-run]`

Prove semantic equivalence of a MATCHING function via angr symbolic execution + Z3 constraint solving. Requires the optional `angr` dependency (`uv pip install -e ".[prove]"`).

| Flag | Description |
|------|-------------|
| `SOURCE` | C source file path or symbol name (positional, required) |
| `--target NAME` | Select a target from `rebrew-project.toml` |
| `--json` | JSON structured output |
| `--timeout N` | Seconds before giving up (default: 60) |
| `--loop-bound N` | Max loop iterations for angr's LoopSeer (default: 10) |
| `--dry-run` | Preview changes without writing |

On success, updates `STATUS` from `MATCHING` → `PROVEN`. On failure (timeout, path explosion, or Z3 finds a distinguishing input), status remains unchanged.

### `rebrew merge`

`rebrew merge <file1> <file2> ... --output FILE [--dry-run] [--force] [--delete] [--json]`

Merge multiple single-function `.c` files into one multi-function file. Preamble lines (`#include`, `extern`, `#define`) are deduplicated. Function blocks are sorted by virtual address ascending.

| Flag | Effect |
|------|--------|
| `--output FILE` | Output merged file (required) |
| `--dry-run` | Preview changes without writing |
| `--force` | Overwrite output if it already exists |
| `--delete` | Delete input files after successful merge |
| `--json` | Structured JSON output |

### `rebrew build-db`

| Flag | Description |
|------|-------------|
| `--root DIR` | Project root directory (auto-detected if omitted) |
| `--json` | Output results as JSON |

### `rebrew init`

| Flag | Description |
|------|-------------|
| `--target NAME` / `-t NAME` | Name of the initial target (default: `main`) |
| `--binary NAME` | Binary filename (default: `program.exe`) |
| `--compiler PROFILE` | Compiler profile (default: `msvc6`) |
| `--json` | Output results as JSON |

## Examples

```bash
# Disassembly
rebrew asm 0x100011f0 --size 64                   # Hex dump 64 bytes at VA
rebrew asm 0x100011f0 --format nasm               # NASM disassembly at VA
rebrew asm 0x100011f0 --target server.dll         # Use alternate target

# Skeleton generation
rebrew skeleton 0x10003da0 --decomp               # Skeleton with inline decompilation
rebrew skeleton 0x10003da0 --decomp --decomp-backend ghidra  # Ghidra via MCP
rebrew skeleton 0x10003da0 --decomp --decomp-backend r2dec   # Radare2 r2dec
rebrew skeleton 0x10003da0 --xrefs                # With caller context from Ghidra
rebrew skeleton 0x10003da0 --append getenv.c      # Append to multi-function file

# Testing (auto-promotes STATUS on EXACT/RELOC)
rebrew test src/target_name/my_func.c --json      # JSON test result
rebrew test src/target_name/my_func.c --no-promote # compile without updating STATUS

# Prioritization & action queue
rebrew todo                                        # Top 20 ROI-ranked actions
rebrew todo -c start-function                      # Only uncovered functions to start
rebrew todo -c fix-verify-fail -n 50               # All verify failures
rebrew todo --stats --json                         # Coverage stats + full JSON report

# Diff & investigation
rebrew diff src/target_name/f.c                    # Side-by-side diff
rebrew diff --mm src/target_name/f.c               # Only structural diffs
rebrew diff --fix-blocker src/target_name/f.c      # Auto-write BLOCKER annotations
rebrew diff --json src/target_name/f.c             # JSON diff
rebrew ga                                          # Batch GA on all STUBs
rebrew ga --near-miss --threshold 5                # GA on MATCHING with <=5B delta
rebrew ga --dry-run                                # List candidates only

# Verification & status
rebrew verify                                      # Verify all reversed functions
rebrew verify --diff                               # Compare against last report, detect regressions
rebrew verify --json                               # Structured JSON report
rebrew verify -o db/verify_results.json            # Write report to file
rebrew lint --fix && rebrew lint                   # Fix then re-lint
rebrew status                                      # Reversing progress overview
rebrew catalog --summary --csv                     # Catalog + CSV

# Data analysis
rebrew data                                        # Inventory globals
rebrew data --dispatch --json                      # Dispatch tables as JSON
rebrew data --bss --json                           # BSS layout as JSON
rebrew data --fix-bss                              # Auto-generate BSS padding

# Dependency graph
rebrew graph                                       # Mermaid call graph
rebrew graph --format dot --origin GAME            # DOT graph, GAME only
rebrew graph --focus FuncName --depth 2            # Neighbourhood of a function

rebrew split src/target_name/multi.c               # split all functions into individual files
rebrew split src/target_name/multi.c --dry-run      # preview split
rebrew split --va 0x10003DA0 src/target_name/multi.c  # extract one function into multi_c/
rebrew split --va 0x10003DA0 --dry-run src/target_name/multi.c  # preview extraction
rebrew merge a.c b.c -o merged.c                    # merge into one file
rebrew merge multi_c/ multi.c -o multi.c --force --delete  # merge extracted function back

# Semantic equivalence proving
rebrew prove src/target_name/calculate_physics.c     # prove MATCHING → PROVEN
rebrew prove src/target_name/calculate_physics.c --json  # JSON output
rebrew prove my_func --dry-run                        # find by symbol, preview only
rebrew prove src/target_name/func.c --timeout 120     # allow 2 min for complex functions

# FLIRT scanning
rebrew flirt                                       # Scan with default sigs
rebrew flirt sigs/ --min-size 32                   # Custom dir, skip tiny funcs
rebrew flirt --json                                # JSON output

# Compilation unit inference (via graph --cu-map)
rebrew graph --cu-map                              # Rich table of inferred TU clusters
rebrew graph --cu-map --json                       # JSON output for scripting
rebrew graph --cu-map --json | jq '.clusters | length'  # count clusters

# CRT source matching
rebrew crt-match 0x10006c00                     # match a single VA against CRT source
rebrew crt-match --all --origin MSVCRT           # match all MSVCRT functions
rebrew crt-match --fix-source --all              # auto-write // SOURCE: annotations
rebrew crt-match --index                         # show CRT source index

# Sync to/from Ghidra
rebrew sync --summary                              # Preview what would sync
rebrew sync --push                                 # Export + apply to Ghidra
rebrew sync --export                               # Export ghidra_commands.json only
rebrew sync --pull                                 # Pull renames/comments from Ghidra
rebrew sync --pull-data                            # Fetch data labels into rebrew_globals.h
```

## Internal Modules

### Matcher Engine

| Module | Purpose |
|--------|---------|
| `matcher/scoring.py` | Multi-metric fitness scoring (byte, reloc, mnemonic, structural similarity) |
| `matcher/compiler.py` | Compilation backend + `flag_sweep(tier=)` + `generate_flag_combinations(tier=)` |
| `matcher/flags.py` | `FlagSet`/`Checkbox` primitives (compatible with decomp.me) |
| `matcher/flag_data.py` | Auto-generated MSVC flags + sweep tiers (from `tools/sync_decomp_flags.py`) |
| `matcher/parsers.py` | COFF `.obj` and PE byte extraction (LIEF-based) |
| `matcher/mutator.py` | 67 C mutation operators for GA |
| `matcher/core.py` | SQLite `BuildCache` + GA checkpointing |
| `solutions.py` | Cross-function solution transfer database (`.rebrew/solutions.json`) |

### Annotation & Sync

| Module | Purpose |
|--------|---------|
| `annotation.py` | Canonical annotation parser (`parse_c_file`, `parse_c_file_multi`, `normalize_status`) |
| `lint.py` | Annotation linter (E000–E017 / W001–W017); `--fix` auto-migrates old formats |
| `ghidra/cli.py` | Sync annotations to Ghidra via ReVa MCP; skips generic `func_` labels by default |

### Binary Analysis

| Module | Purpose |
|--------|---------|
| `cu_map.py` | Compilation unit boundary inference (contiguity clustering + call-graph refinement) |

### Library Identification

| Module | Purpose |
|--------|---------|
| `flirt.py` | FLIRT signature matching (no IDA required) |
| `crt_match.py` | CRT source cross-reference matcher (index, match, ASM detection) |
| `gen_flirt_pat.py` | Generate `.pat` files from COFF `.lib` archives |

### Unified Compilation

All tools share a single compile path via `rebrew.compile`. The module reads
`base_cflags` and `timeout` from config, ensuring consistent behavior across
`rebrew test`, `rebrew verify`, and `rebrew match`.
