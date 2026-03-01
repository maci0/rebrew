# ☕ Rebrew

**Compiler-in-the-loop decompilation workbench for binary-matching game reversing.**

Rebrew is a reusable Python tooling package for reconstructing exact C source code from compiled binaries. It provides a genetic algorithm engine, annotation pipeline, verification framework, and CLI tools.

## ✨ Features

- **Global rename** — `rebrew rename` renames a function, updates its `// SYMBOL:`, renames the file if applicable, and updates cross-references across the entire codebase.
- **Skeleton generation** — `rebrew skeleton` creates annotated `.c` stubs from VAs with optional inline decompilation (`--decomp`) via r2ghidra, r2dec, or Ghidra; `--xrefs` embeds caller context from Ghidra cross-references
- **Compile-and-compare** — `rebrew test` compiles your C and diffs it byte-by-byte against the original binary
- **GA matching engine** — `rebrew match` uses a genetic algorithm to brute-force compiler flags and mutate source code to find exact byte matches; structural similarity metric distinguishes flag-fixable vs structural differences
- **Batch GA** — `rebrew ga` runs GA across all STUB functions unattended; `--near-miss` targets MATCHING functions with small byte deltas; `--flag-sweep` sweeps compiler flags across all MATCHING functions with priority queuing
- **Annotation pipeline** — `rebrew lint` validates `// FUNCTION:`, `// STATUS:`, `// ORIGIN:` annotations across the codebase (E000–E017, W001–W017)
- **Verification** — `rebrew verify` bulk-compiles every reversed function and reports match status with a progress bar; `--fix-status` auto-updates `// STATUS:` and `// BLOCKER:` annotations; `--summary` shows a table with EXACT/RELOC/MATCHING breakdown and match percentages; `--json` emits timestamped structured reports to `db/verify_results.json`; `--diff` detects regressions against the last saved report (exit code 1 for CI)
- **Smart prioritization** — `rebrew next` recommends functions to work on, auto-filters unmatchable stubs, and shows byte-delta for near-miss MATCHING functions
- **Dependency graph** — `rebrew graph` builds call graphs from `extern` declarations in mermaid, DOT, or summary format with focus mode
- **Global data scanner** — `rebrew data` inventories `.data`/`.rdata`/`.bss` globals, detects type conflicts, finds dispatch tables / vtables (`--dispatch`), verifies BSS layout (`--bss`), and supports `// DATA:` annotations for first-class data tracking
- **Status tracking** — `rebrew status` gives a per-target breakdown of EXACT/RELOC/MATCHING/STUB counts
- **Atomic promotion** — `rebrew promote` tests a function and atomically updates its STATUS annotation; `--all` for batch promotion with `--dir` and `--origin` filters; `--dry-run` to preview
- **Cold-start triage** — `rebrew triage` combines coverage stats, FLIRT scan, near-miss list, and recommendations into a single report for agent sessions
- **Diagnostic check** — `rebrew doctor` validates project health (config, compiler, includes/libs, binary); `--install-wibo` auto-downloads wibo as a lightweight Wine alternative
- **FLIRT scanning** — `rebrew flirt` identifies known library functions via FLIRT signatures (`.sig`/`.pat`), no IDA required
- **CRT source matching** — `rebrew crt-match` cross-references binary functions against configured CRT/library source directories (MSVC6 CRT, zlib, etc.); auto-detects ASM-only functions; `--fix-source` writes `// SOURCE:` annotations; supports `--all` batch mode with `--origin` filter
- **NASM extraction** — `rebrew nasm` extracts function bytes and produces NASM-reassembleable ASM with round-trip verification
- **File splitting** — `rebrew split` breaks multi-function `.c` files into individual single-function files, preserving shared preamble (includes, defines) and generating filenames from `SYMBOL` annotations
- **File merging** — `rebrew merge` combines multiple single-function files into one multi-function file with preamble deduplication and VA-sorted function blocks
- **Multi-target** — all tools read from `rebrew-project.toml` with `--target` selection; supports maintaining multi-target `// FUNCTION:` blocks (e.g. LEGO1 vs BETA10) in the exact same C file by auto-filtering inactive targets; supports PE, ELF, Mach-O across x86, x64, ARM32/64
- **Rich CLI help** — every tool has detailed `--help` with usage examples, context, and prerequisites via Typer's `rich_markup_mode`
- **Compile cache** — disk-backed SHA-256 keyed cache avoids redundant recompilations across `rebrew match`, `rebrew ga`, and `rebrew test`; `rebrew cache stats` / `rebrew cache clear` for management
- **Agent-friendly** — bundled `agent-skills/` copied to projects on `rebrew init`

## Agent Skills
The project includes five `agent-skills` for AI coding agent integration:

| Skill | Purpose |
|-------|---------|
| `rebrew-workflow` | End-to-end reversing workflow and status tracking |
| `rebrew-matching` | GA matching engine, flag sweeps, diff analysis |
| `rebrew-data-analysis` | Global data scanning, BSS layout, dispatch tables |
| `rebrew-intake` | Binary onboarding, triage, and initial FLIRT scanning |
| `rebrew-ghidra-sync` | Ghidra ↔ Rebrew sync via ReVa MCP |

See the `src/rebrew/agent-skills/` directory for the SKILL.md files.

### ❓ What is Rebrew?

Rebrew is the engine behind binary-matching game decompilation. When you are writing C arrays, structs, and logic to perfectly match a 25-year-old compiled game binary, Rebrew orchestrates the constant cycle of compiling your C code and diffing it against the original binary to tell you how close you are to an exact match.

### 🎯 Core Principles

- **Idempotent**: Every tool can be run repeatedly with the same result. `rebrew catalog`, `rebrew verify`, `rebrew cfg`, `rebrew init` — running them twice changes nothing the second time. No destructive side effects.
- **Config-driven**: All tools read from `rebrew-project.toml` — zero manual path arguments needed.
- **Composable**: Tools are small, single-purpose, and designed to be chained by scripts or AI agents.
- **Genetic Algorithm (GA) Search Engine**: Brute-forcing compiler flags and mutating source code AST to discover the exact code changes needed to fix compiler discrepancies.

## 🚀 Quick Start & Setup

Rebrew is designed to be consumed as a dependency by a project-specific decomp repo (e.g., [guild-rebrew](../guild-rebrew/)).

### 1. Installation

```bash
uv tool install git+https://github.com/maci0/rebrew.git
```

### 2. Project Configuration (`rebrew-project.toml`)

Each decomp project provides a `rebrew-project.toml` in its root. Rebrew finds it by searching upward from the current working directory (similar to how `git` finds `.git/`).

```toml
[targets.target_name]
binary = "original/target.dll"
format = "pe"
arch = "x86_32"
reversed_dir = "src/target_name"
function_list = "src/target_name/functions.txt"
bin_dir = "bin/target_name"

[compiler]
profile = "msvc6"
command = "wine tools/MSVC600/VC98/Bin/CL.EXE"
includes = "tools/MSVC600/VC98/Include"
libs = "tools/MSVC600/VC98/Lib"
```

## 💻 Usage & Workflow

All CLI tools must be run **from within a project directory** that contains a `rebrew-project.toml` config file.

```bash
cd /path/to/your-decomp-project    # must contain rebrew-project.toml

# Project Setup
rebrew init --target mygame --binary mygame.exe --compiler msvc6 # initialize project
rebrew cfg list-targets              # list configured targets
rebrew cfg add-origin ZLIB           # add origin to default target
rebrew cfg set compiler.cflags "/O1" # set a config value

# Development
rebrew skeleton 0x10003DA0          # generate C skeleton from disassembly
rebrew skeleton 0x10003DA0 --xrefs  # skeleton with Ghidra cross-reference context
rebrew test src/target_name/f.c     # test implementation against target
rebrew next --stats                 # show overall progress statistics
rebrew next --improving             # list MATCHING functions sorted by byte delta
rebrew triage --json                # combined coverage, near-miss, and recommendations report
rebrew flirt --json                 # FLIRT scan: identify known library functions
rebrew crt-match 0x10006c00         # match a single VA against CRT source
rebrew crt-match --all --origin MSVCRT # match all MSVCRT functions
rebrew crt-match --fix-source --all  # auto-write // SOURCE: annotations
rebrew crt-match --index            # show CRT source index
rebrew lint                         # lint annotations in your source files
rebrew split src/target_name/multi.c           # split multi-function file into individual files
rebrew merge a.c b.c --output merged.c         # merge files into one multi-function file
rebrew status                       # show reversing status overview
rebrew data                         # inventory globals in .data/.rdata/.bss
rebrew data --dispatch              # detect dispatch tables / vtables
rebrew graph --format summary       # call graph stats and blockers
rebrew nasm 0x10003DA0              # extract NASM-reassembleable ASM with round-trip verify
rebrew catalog                      # regenerate the function catalog and coverage JSON
rebrew catalog --export-ghidra-labels  # generate ghidra_data_labels.json from detected tables
rebrew build-db                     # build SQLite coverage database from catalog

# Matching
rebrew match --diff-only src/target_name/f.c       # side-by-side disassembly diff
rebrew match --diff-only --mm src/target_name/f.c  # show only structural diffs (**)
rebrew match src/target_name/f.c    # run the Genetic Algorithm Engine to resolve diffs
rebrew ga                           # batch GA runner to solve all stubs
rebrew ga --near-miss --threshold 5 # batch GA on MATCHING functions with ≤5B delta
rebrew ga --flag-sweep              # batch flag sweep on all MATCHING functions
rebrew ga --flag-sweep --tier targeted --fix-cflags  # targeted sweep, auto-update CFLAGS

# Export & Sync
rebrew rename old_func new_func     # completely rename a function across the codebase
rebrew verify --fix-status          # bulk compile and auto-update STATUS/BLOCKER annotations
rebrew verify --json                # structured JSON report to stdout
rebrew verify --diff                # detect regressions against last saved report
rebrew promote --all --origin GAME  # batch promote all promotable GAME functions
rebrew split src/target_name/multi.c --dry-run  # preview split without writing
rebrew merge a.c b.c -o merged.c --delete       # merge and delete originals
rebrew extract list                 # list un-reversed candidates
rebrew extract batch 20             # extract and disassemble first 20 smallest
rebrew asm                          # quick offline disassembly
rebrew cache stats                  # show compile cache hit rate and size
rebrew doctor --install-wibo        # auto-download wibo (lightweight Wine alternative)

# Ghidra Sync via ReVa MCP
rebrew sync --push                  # export annotations and push to Ghidra
rebrew sync --pull                  # fetch Ghidra renames into local files
rebrew sync --pull --accept-ghidra  # fetch renames and automatically update cross-references
rebrew sync --pull-signatures       # fetch Ghidra decompilation to update extern prototypes
rebrew sync --pull-structs          # export Ghidra structs into types.h
rebrew sync --pull-comments         # fetch Ghidra EOL/post analysis comments into source
rebrew sync --pull-data             # fetch Ghidra data labels into rebrew_globals.h
rebrew sync --pull --dry-run        # preview pull without modifying files
```

## ⚙️ Supported Platforms

| Architecture | Binary Format | Compiler | Binary Loading | Object Parsing | GA Matching | Verification |
|:------------|:-------------|:---------|:--------------:|:--------------:|:-----------:|:------------:|
| x86 (32-bit) | PE (`.exe`/`.dll`) | MSVC 6.0 | ✅ | ✅ | ✅ | ✅ |
| x86 (32-bit) | PE | MSVC 7.x+| ✅ | ✅ | ✅ | ✅ |
| x86 (32-bit) | PE | Watcom C | ✅ | ⬜ | ✅ | ⬜ |
| x86 (32-bit) | ELF (`.so`/exec) | GCC/Clang| ✅ | ✅ | ⬜ | ⬜ |
| x86_64     | PE | MSVC     | ✅ | ✅ | ⬜ | ⬜ |
| x86_64     | ELF | GCC/Clang| ✅ | ✅ | ⬜ | ⬜ |
| x86_64     | Mach-O| Clang    | ✅ | ✅ | ⬜ | ⬜ |
| ARM32      | ELF | GCC/Clang| ✅ | ✅ | ⬜ | ⬜ |
| ARM64      | ELF | GCC/Clang| ✅ | ✅ | ⬜ | ⬜ |
| ARM64      | Mach-O| Clang    | ✅ | ✅ | ⬜ | ⬜ |

**Legend:** ✅ Supported  ⬜ Planned / Not yet implemented

## 🛠️ Development

```bash
cd rebrew/
uv sync --all-extras       # install dev dependencies
uv run pytest tests/ -v    # run tests (~1443 tests)
uv run ruff check .        # lint
uv run ruff format .       # format
python tools/sync_decomp_flags.py  # sync compiler flags from decomp.me
```

### Flag Sweep Tiers

The flag sweep uses compiler flag definitions synced from [decomp.me](https://github.com/decompme/decomp.me). The `generate_flag_combinations(tier)` function supports five effort levels: `quick` (~192 combos), `targeted` (~1.1K combos), `normal` (~21K combos), `thorough` (~1M combos), and `full` (~8.3M combos). The `msvc6` compiler profile automatically excludes incompatible MSVC 7.x+ flags.

## 🌐 Ecosystem & Related Tools

Rebrew is part of a broader decompilation ecosystem. These are the notable projects it integrates with or draws from:

### Integrated

| Tool | Role | Integration |
|------|------|-------------|
| [decomp.me](https://github.com/decompme/decomp.me) | Collaborative decompilation platform | Flag axes synced via `tools/sync_decomp_flags.py`; powers `rebrew match --flag-sweep` |
| [reccmp](https://github.com/isledecomp/reccmp) | Binary recompilation comparison framework | Annotation format compatibility; `rebrew catalog --csv` exports reccmp-compatible CSV |
| [LIEF](https://github.com/lief-project/LIEF) | Binary format parsing (PE/ELF/Mach-O) | Used for binary loading, format detection, and PE section analysis |
| [Capstone](https://github.com/capstone-engine/capstone) | Disassembly engine | Powers `rebrew asm`, byte-diff scoring, relocation masking, and mnemonic comparison |
| [ReVa](https://github.com/cyberkaida/reverse-engineering-assistant) | Ghidra MCP bridge | `rebrew sync` pushes/pulls annotations, labels, structs, and comments to Ghidra |

### Adjacent Tools

| Tool | What it does | Relevance |
|------|-------------|-----------|
| [asm-differ](https://github.com/simonlindholm/asm-differ) | Assembly diff with levenshtein alignment | Used by decomp.me for all diffs; rebrew has its own capstone-based differ |
| [objdiff](https://github.com/encounter/objdiff) | Rust GUI for object file diffing (COFF/ELF/Mach-O) | Visual companion for inspecting match differences |
| [decomp-toolkit](https://github.com/encounter/decomp-toolkit) | GameCube/Wii decompilation toolkit | DOL/REL focused; similar split/link/diff workflow concepts |
| [wibo](https://github.com/decompals/wibo) | Lightweight Win32 PE loader | Faster alternative to Wine for running MSVC CL.EXE |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | NSA's reverse engineering suite | Primary disassembler/decompiler; connected via ReVa MCP |
| [FLIRTDB](https://github.com/Maktm/FLIRTDB) | FLIRT signature database | Signatures for MSVC, Borland, MinGW used by `rebrew flirt` |

## License

MIT
