# CLI Reference

All 22 CLI tools are installed as entry points via `pyproject.toml`.
Every tool supports `--target / -t` to select a target from `rebrew.toml` and
reads defaults (binary path, reversed_dir, compiler settings) from the project config.

Run any tool with `--help` to see usage examples and context
(typer `rich_markup_mode="rich"` with epilog text).

## Entry Points

| Entry Point | Script | Description |
|-------------|--------|-------------|
| `rebrew` | `main.py` | Unified CLI entry point for all subcommands |
| `rebrew-init` | `init.py` | Scaffold a new project directory and `rebrew.toml` |
| `rebrew-test` | `test.py` | Quick compile-and-compare (single or multi-function files); `--json` structured output |
| `rebrew-asm` | `asm.py` | Dump disassembly from target binary at a VA; `--json` structured output |
| `rebrew-next` | `next.py` | Prioritize uncovered functions by difficulty; auto-filters unmatchable; `--json` for all modes |
| `rebrew-skeleton` | `skeleton.py` | Generate annotated `.c` skeleton from VA (with `--decomp` and `--append` for multi-function files) |
| `rebrew-catalog` | `catalog/` | Parse annotations, generate catalog + coverage JSON |
| `rebrew-sync` | `sync.py` | Sync annotations, structs, and signatures to/from Ghidra via ReVa MCP (`--push`, `--pull`, `--apply`, `--export`) |
| `rebrew-lint` | `lint.py` | Lint annotation standards in decomp C files |
| `rebrew-extract` | `extract.py` | Batch extract and disassemble functions from binary |
| `rebrew-match` | `match.py` / `matcher/` | GA matching engine (diff with `--mm`, flag-sweep with `--tier`, GA); `--diff-only --json` structured diff |
| `rebrew-ga` | `ga.py` | Batch GA runner for STUB functions and near-miss MATCHING functions |
| `rebrew-verify` | `verify.py` | Compile all `.c` files and verify byte match against target binary; `--json` structured reports |
| `rebrew-build-db` | `build_db.py` | Build SQLite `db/coverage.db` from `data_*.json` ([schema docs](DB_FORMAT.md)) |
| `rebrew-cfg` | `cfg.py` | Read and edit `rebrew.toml` programmatically (see [CONFIG.md](CONFIG.md)) |
| `rebrew-nasm` | `nasm.py` | NASM assembly extraction |
| `rebrew-flirt` | `flirt.py` | FLIRT signature scanning (see [FLIRT_SIGNATURES.md](FLIRT_SIGNATURES.md)) |
| `rebrew-status` | `status.py` | Project reversing status overview (per-target breakdowns) |
| `rebrew-data` | `data.py` | Global data scanner for .data/.rdata/.bss; `--bss` layout verification; `--dispatch` vtable detection |
| `rebrew-graph` | `depgraph.py` | Function dependency graph (mermaid, DOT, summary) |
| `rebrew-promote` | `promote.py` | Test + atomically update STATUS annotation; `--json` structured output; `--dry-run` preview |
| `rebrew-triage` | `triage.py` | Cold-start triage: coverage stats, FLIRT scan, near-miss list, recommendations; `--json` |

## Tool Flags

### `rebrew match`

| Flag | Description |
|------|-------------|
| `--diff-only` | Side-by-side disassembly diff (no GA) |
| `--mm` / `--mismatches-only` | With `--diff-only`, show only structural (`**`) lines + summary |
| `--rr` / `--register-aware` | With `--diff-only`, normalize register encodings and mark as `RR` |
| `--flag-sweep-only` | Sweep compiler flags without GA mutations |
| `--tier TIER` | Flag sweep tier: `quick` (192), `targeted` (6k), `normal` (21K), `thorough` (1M), `full` (8.3M) |
| `--seed N` | Seed RNG for reproducible GA runs |
| `--force` | Continue even if annotation linter finds errors |
| `--generations N` | Number of GA generations (default 100) |
| `--pop-size N` | GA population size (default 32) |
| `-j N` | Parallel compilation workers |
| `--out-dir DIR` | Output directory for GA results |
| `--json` | JSON structured output (with `--diff-only`) |

### `rebrew test`

| Flag | Description |
|------|-------------|
| `--json` | JSON structured output |

### `rebrew next`

| Flag | Description |
|------|-------------|
| `--stats` | Show progress statistics instead of recommendations |
| `--improving` | List MATCHING functions sorted by byte delta |
| `--unmatchable` | Show auto-detected unmatchable functions |
| `--origin ORIGIN` | Filter by origin (e.g. `GAME`, `MSVCRT`) |
| `-n N` | Number of recommendations |
| `--json` | JSON output for all modes |

### `rebrew skeleton`

| Flag | Description |
|------|-------------|
| `--decomp` | Embed inline decompilation from r2ghidra/r2dec |
| `--decomp-backend BACKEND` | Decompiler backend: `r2ghidra`, `r2dec`, `auto` |
| `--append FILE` | Append to existing multi-function file |
| `--name NAME` | Override function name |

### `rebrew verify`

| Flag | Description |
|------|-------------|
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
| `--near-miss` | Target MATCHING functions instead of STUBs |
| `--threshold N` | Only attempt functions with byte delta <= N (default 10) |
| `--dry-run` | List candidates without running GA |

### `rebrew data`

| Flag | Description |
|------|-------------|
| `--conflicts` | Show only type-conflict globals |
| `--bss` | Verify .bss layout and detect gaps |
| `--dispatch` | Detect dispatch tables / vtables |
| `--fix-bss` | Auto-generate `bss_padding.c` with dummy arrays for detected gaps |
| `--json` | JSON output for all modes |

### `rebrew graph`

| Flag | Description |
|------|-------------|
| `--format FORMAT` | Output format: `mermaid` (default), `dot`, `summary` |
| `--origin ORIGIN` | Filter to specific origin |
| `--focus NAME` | Neighbourhood of a specific function |
| `--depth N` | Depth for focus mode |

### `rebrew lint`

| Flag | Description |
|------|-------------|
| `--fix` | Auto-migrate old annotation formats |
| `--quiet` | Suppress warnings, show errors only |
| `--json` | Machine-readable JSON output |
| `--summary` | Print status/origin breakdown table |
| `--files FILE...` | Check specific files instead of full scan |

See [ANNOTATIONS.md](ANNOTATIONS.md) for the full linter code reference (E001-E017, W001-W015).

### `rebrew promote`

| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON |
| `--dry-run` | Show what would change without writing |

### `rebrew triage`

| Flag | Description |
|------|-------------|
| `-n N` | Number of recommendations to include (default 10) |
| `--json` | Output as JSON |

### `rebrew catalog`

| Flag | Description |
|------|-------------|
| `--json` | Generate `db/data_<target>.json` |
| `--catalog` | Generate `CATALOG.md` in reversed directory |
| `--summary` | Print summary to stdout |
| `--csv` | Generate reccmp-compatible CSV |
| `--export-ghidra` | Cache Ghidra function list |
| `--export-ghidra-labels` | Generate `ghidra_data_labels.json` from detected tables |
| `--fix-sizes` | Update `// SIZE:` annotations to match canonical sizes |
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
| `--endpoint URL` | ReVa MCP endpoint URL |
| `--json` | Output results as JSON |

### `rebrew status`

| Flag | Description |
|------|-------------|
| `--json` | Machine-readable JSON output |

### `rebrew flirt`

| Flag | Description |
|------|-------------|
| `SIG_DIR` | Directory containing `.sig`/`.pat` files (positional, optional) |
| `--exe FILE` | Target PE file (default: from config) |
| `--min-size N` | Minimum function size in bytes to report (default 16) |
| `--json` | Output results as JSON |

### `rebrew nasm`

| Flag | Description |
|------|-------------|
| `--exe FILE` | PE executable (default: from config) |
| `--va HEX` | Virtual address (hex) |
| `--size N` | Function size in bytes |
| `--bin FILE` | Raw `.bin` file input |
| `--label NAME` | Label name for the function |
| `-o FILE` / `--out FILE` | Output `.asm` file (default: stdout) |
| `--verify` | Assemble output and verify byte-identical round-trip |
| `--stats` | Print stats only (no ASM output) |
| `--batch` | Batch mode: extract all functions from `reversed_dir` |
| `--batch-stubs` | Batch mode: extract only STUB functions |
| `--out-dir DIR` | Output directory for batch mode |
| `--base-va HEX` | Base VA for `.bin` files (default: 0) |

### `rebrew build-db`

| Flag | Description |
|------|-------------|
| `--root DIR` | Project root directory (auto-detected if omitted) |

## Examples

```bash
# Disassembly
rebrew asm 0x100011f0 --size 64                   # Disassemble 64 bytes at VA
rebrew asm 0x100011f0 --target server.dll         # Use alternate target

# Skeleton generation
rebrew skeleton 0x10003da0 --decomp               # Skeleton with inline decompilation
rebrew skeleton 0x10003da0 --decomp --decomp-backend r2dec
rebrew skeleton 0x10003da0 --append crt_env.c     # Append to multi-function file

# Testing
rebrew test src/target_name/my_func.c --json      # JSON test result

# Prioritization
rebrew next --stats                                # Show progress statistics
rebrew next --stats --json                         # JSON progress stats
rebrew next --improving                            # MATCHING functions by byte delta
rebrew next --unmatchable                          # Show unmatchable functions
rebrew next --origin GAME -n 20                    # Top 20 GAME functions

# Matching & GA
rebrew match --diff-only src/target_name/f.c       # Side-by-side diff
rebrew match --diff-only --mm src/target_name/f.c  # Only structural diffs
rebrew match --diff-only --json src/target_name/f.c # JSON diff
rebrew ga                                          # Batch GA on all STUBs
rebrew ga --near-miss --threshold 5                # GA on MATCHING with <=5B delta
rebrew ga --dry-run                                # List candidates only

# Verification & status
rebrew verify                                      # Verify all reversed functions
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

# Promote & triage
rebrew promote src/target_name/my_func.c           # Test + update STATUS
rebrew promote src/target_name/my_func.c --json    # JSON output for agents
rebrew promote src/target_name/my_func.c --dry-run # Preview changes
rebrew triage                                      # Cold-start triage summary
rebrew triage --json -n 20                         # JSON report, top 20

# NASM extraction
rebrew nasm --va 0x10003ca0 --size 77              # Extract single function
rebrew nasm --va 0x10003ca0 --size 77 --verify     # With round-trip verification
rebrew nasm --batch --out-dir output/nasm/         # Batch extract all matched

# FLIRT scanning
rebrew flirt                                       # Scan with default sigs
rebrew flirt sigs/ --min-size 32                   # Custom dir, skip tiny funcs
rebrew flirt --json                                # JSON output

# Sync to/from Ghidra
rebrew sync --summary                              # Preview what would sync
rebrew sync --push                                 # Export + apply to Ghidra
rebrew sync --export                               # Export ghidra_commands.json only
rebrew sync --pull                                 # Pull renames/comments from Ghidra
```

## Internal Modules

### Matcher Engine

| Module | Purpose |
|--------|---------|
| `matcher/scoring.py` | Multi-metric fitness scoring (byte, reloc, mnemonic) |
| `matcher/compiler.py` | Compilation backend + `flag_sweep(tier=)` + `generate_flag_combinations(tier=)` |
| `matcher/flags.py` | `FlagSet`/`Checkbox` primitives (compatible with decomp.me) |
| `matcher/flag_data.py` | Auto-generated MSVC flags + sweep tiers (from `tools/sync_decomp_flags.py`) |
| `matcher/parsers.py` | COFF `.obj` and PE byte extraction (LIEF-based) |
| `matcher/mutator.py` | 40+ C mutation operators for GA |
| `matcher/core.py` | SQLite `BuildCache` + GA checkpointing |

### Annotation & Sync

| Module | Purpose |
|--------|---------|
| `annotation.py` | Canonical annotation parser (`parse_c_file`, `parse_c_file_multi`, `normalize_status`) |
| `lint.py` | Annotation linter (E001-E017 / W001-W015); `--fix` auto-migrates old formats |
| `sync.py` | Sync annotations to Ghidra via ReVa MCP; skips generic `func_` labels by default |

### Library Identification

| Module | Purpose |
|--------|---------|
| `flirt.py` | FLIRT signature matching (no IDA required) |
| `gen_flirt_pat.py` | Generate `.pat` files from COFF `.lib` archives |

### Unified Compilation

All tools share a single compile path via `rebrew.compile`. The module reads
`base_cflags` and `timeout` from config, ensuring consistent behavior across
`rebrew test`, `rebrew verify`, and `rebrew match`.
