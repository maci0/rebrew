# ☕ Rebrew

**Compiler-in-the-loop decompilation workbench for binary-matching game reversing.**

Rebrew is a reusable Python tooling package for reconstructing exact C source code from compiled binaries. It provides a genetic algorithm engine, annotation pipeline, verification framework, and CLI tools.

## ✨ Features

### Core Loop

| Tool | What it does |
|------|-------------|
| `rebrew test` | Compile your C and diff it byte-by-byte against the original binary |
| `rebrew match` | GA engine — brute-force compiler flags and mutate source to find exact byte matches |
| `rebrew ga` | Batch GA across all STUBs; `--near-miss` for close matches; `--flag-sweep` for flag search |
| `rebrew verify` | Bulk compile + report match status; `--fix-status` auto-updates annotations; `--diff` for CI regression checks |
| `rebrew prove` | Symbolic equivalence via angr + Z3 — mathematically prove MATCHING functions are equivalent |

### Authoring

| Tool | What it does |
|------|-------------|
| `rebrew skeleton` | Generate annotated `.c` stubs from VAs; `--decomp` for inline decompilation; `--xrefs` for caller context |
| `rebrew rename` | Rename a function across the entire codebase (symbol, filename, cross-references) |
| `rebrew split` | Break multi-function `.c` files into individual files; `--va` to extract one function |
| `rebrew merge` | Combine single-function files into one multi-function file |
| `rebrew lint` | Validate annotation correctness (E000–E017, W001–W017) |
| `rebrew promote` | Test + atomically update STATUS; `--all` for batch promotion |

### Analysis

| Tool | What it does |
|------|-------------|
| `rebrew todo` | Prioritized action list: what to work on next |
| `rebrew next` | Smart prioritization — recommends similar functions |
| `rebrew triage` | Cold-start report: coverage stats, FLIRT scan, near-miss list, recommendations |
| `rebrew status` | Per-target breakdown of EXACT / RELOC / MATCHING / STUB counts |
| `rebrew graph` | Call graph from `extern` declarations (mermaid, DOT, summary) |
| `rebrew data` | Inventory `.data`/`.rdata`/`.bss` globals; detect dispatch tables and vtables |
| `rebrew cu-map` | Infer compilation unit boundaries from .text layout and call graph |
| `rebrew flirt` | Identify known library functions via FLIRT signatures — no IDA required |
| `rebrew crt-match` | Cross-reference functions against CRT/library source directories |

### Infrastructure

| Tool | What it does |
|------|-------------|
| `rebrew init` | Scaffold a new project with config, directories, and agent skills |
| `rebrew doctor` | Validate project health (config, compiler, binary); `--install-wibo` |
| `rebrew catalog` | Build function catalog and coverage JSON |
| `rebrew build-db` | Build SQLite coverage database from catalog |
| `rebrew cache` | Compile cache management (`stats`, `clear`) |
| `rebrew cfg` | Read/write `rebrew-project.toml` settings |
| `rebrew extract` | Batch extract function bytes and disassembly |
| `rebrew nasm` | Extract NASM-reassembleable ASM with round-trip verification |
| `rebrew asm` | Quick offline disassembly |
| `rebrew sync` | Push/pull annotations, labels, structs, and comments to Ghidra via ReVa MCP |

### Design

- **Config-driven** — all tools read from `rebrew-project.toml`, zero manual path arguments
- **Multi-target** — PE, ELF, Mach-O across x86, x64, ARM32/64 with `--target` selection
- **Idempotent** — every tool safe to re-run without side effects
- **Composable** — small single-purpose tools designed for scripting and AI agent chaining
- **Compile cache** — disk-backed SHA-256 cache avoids redundant recompilations
- **Agent-friendly** — bundled `agent-skills/` copied to projects on `rebrew init`

### Agent Skills

Five bundled skills for AI coding agent integration:

| Skill | Purpose |
|-------|---------|
| `rebrew-workflow` | End-to-end reversing workflow and status tracking |
| `rebrew-matching` | GA matching engine, flag sweeps, diff analysis |
| `rebrew-data-analysis` | Global data scanning, BSS layout, dispatch tables |
| `rebrew-intake` | Binary onboarding, triage, and initial FLIRT scanning |
| `rebrew-ghidra-sync` | Ghidra ↔ Rebrew sync via ReVa MCP |

## 🚀 Quick Start

```bash
# 1. Install
uv tool install git+https://github.com/maci0/rebrew.git

# 2. Create a project
mkdir my-decomp && cd my-decomp
rebrew init --target server --binary server.dll

# 3. Place your binary
cp /path/to/server.dll original/

# 4. Start reversing
rebrew doctor                       # verify setup
rebrew triage                       # assess scope
rebrew skeleton 0x10003DA0          # generate first stub
rebrew test src/server/func_10003da0.c  # compile and compare
```

`rebrew init` creates `rebrew-project.toml`, source/bin directories, and agent skills.
All tools find the config by searching upward from the current directory (like `git` finds `.git/`).

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
rebrew todo                         # see highest ROI action items
rebrew next --stats                 # show overall progress statistics
rebrew next --improving             # list MATCHING functions sorted by byte delta
rebrew triage --json                # combined coverage, near-miss, and recommendations report
rebrew flirt --json                 # FLIRT scan: identify known library functions
rebrew crt-match 0x10006c00         # match a single VA against CRT source
rebrew crt-match --all --origin MSVCRT # match all MSVCRT functions
rebrew crt-match --fix-source --all  # auto-write // SOURCE: annotations
rebrew crt-match --index            # show CRT source index
rebrew cu-map                       # infer compilation unit boundaries
rebrew cu-map --json                # JSON output for scripting
rebrew lint                         # lint annotations in your source files
rebrew split src/target_name/multi.c           # split multi-function file into individual files
rebrew split --va 0x10003DA0 src/target_name/multi.c  # extract one function into multi_c/
rebrew merge a.c b.c --output merged.c         # merge files into one multi-function file
rebrew merge multi_c/ multi.c -o multi.c --force --delete  # merge extracted function back
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

# Semantic Equivalence (requires angr: uv pip install -e ".[prove]")
rebrew prove src/server.dll/calculate_physics.c      # prove MATCHING function equivalent
rebrew prove src/server.dll/calculate_physics.c --json  # JSON output
rebrew prove my_func --dry-run                        # find by symbol, preview only

# Export & Sync
rebrew rename old_func new_func     # completely rename a function across the codebase
rebrew verify --fix-status          # bulk compile and auto-update STATUS/BLOCKER annotations
rebrew verify --json                # structured JSON report to stdout
rebrew verify --diff                # detect regressions against last saved report
rebrew promote --all --origin GAME  # batch promote all promotable GAME functions
rebrew split src/target_name/multi.c --dry-run  # preview split without writing
rebrew split --va 0x10003DA0 --dry-run src/target_name/multi.c  # preview single extraction
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
uv run pytest tests/ -v    # run tests (~1644 tests)
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
| [angr](https://github.com/angr/angr) | Binary analysis + symbolic execution | Powers `rebrew prove` for Z3-based semantic equivalence proving (optional dep) |
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
