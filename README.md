# ☕ Rebrew

**Compiler-in-the-loop decompilation workbench for binary-matching game reversing.**

Rebrew is a reusable Python tooling package for reconstructing exact C source code from compiled binaries. It provides a genetic algorithm engine, annotation pipeline, verification framework, and CLI tools.

## ✨ Features

- **Skeleton generation** — `rebrew-skeleton` creates annotated `.c` stubs from VAs with optional inline decompilation (`--decomp`) via r2ghidra, r2dec, or Ghidra
- **Compile-and-compare** — `rebrew-test` compiles your C and diffs it byte-by-byte against the original binary
- **GA matching engine** — `rebrew-match` uses a genetic algorithm to brute-force compiler flags and mutate source code to find exact byte matches
- **Batch GA** — `rebrew-ga` runs GA across all STUB functions unattended; `--near-miss` targets MATCHING functions with small byte deltas
- **Annotation pipeline** — `rebrew-lint` validates `// FUNCTION:`, `// STATUS:`, `// ORIGIN:` annotations across the codebase (E001–E017, W001–W015)
- **Verification** — `rebrew-verify` bulk-compiles every reversed function and reports match status with a progress bar; `--json` emits timestamped structured reports to `db/verify_results.json`
- **Smart prioritization** — `rebrew-next` recommends functions to work on, auto-filters unmatchable stubs, and shows byte-delta for near-miss MATCHING functions
- **Dependency graph** — `rebrew graph` builds call graphs from `extern` declarations in mermaid, DOT, or summary format with focus mode
- **Global data scanner** — `rebrew data` inventories `.data`/`.rdata`/`.bss` globals, detects type conflicts, finds dispatch tables / vtables (`--dispatch`), verifies BSS layout (`--bss`), and supports `// DATA:` annotations for first-class data tracking
- **Status tracking** — `rebrew status` gives a per-target breakdown of EXACT/RELOC/MATCHING/STUB counts
- **Multi-target** — all tools read from `rebrew.toml` with `--target` selection; supports PE, ELF, Mach-O across x86, x64, ARM32/64
- **Rich CLI help** — every tool has detailed `--help` with usage examples, context, and prerequisites via Typer's `rich_markup_mode`
- **Agent-friendly** — includes `agent-skills/` for AI coding agent integration

## Agent Skills
The project includes four `agent-skills` for AI coding agent integration:

| Skill | Purpose |
|-------|---------|
| `rebrew-workflow` | End-to-end reversing workflow, status tracking, Ghidra sync |
| `rebrew-matching` | GA matching engine, flag sweeps, diff analysis |
| `rebrew-data-analysis` | Global data scanning, BSS layout, dispatch tables |
| `rebrew-intake` | Binary onboarding, triage, and initial FLIRT scanning |

See the `agent-skills/` directory for the SKILL.md files.

### ❓ What is Rebrew?

Rebrew is the engine behind binary-matching game decompilation. When you are writing C arrays, structs, and logic to perfectly match a 25-year-old compiled game binary, Rebrew orchestrates the constant cycle of compiling your C code and diffing it against the original binary to tell you how close you are to an exact match.

### 🎯 Core Principles

- **Idempotent**: Every tool can be run repeatedly with the same result. `rebrew-catalog`, `rebrew-verify`, `rebrew-cfg`, `rebrew-init` — running them twice changes nothing the second time. No destructive side effects.
- **Config-driven**: All tools read from `rebrew.toml` — zero manual path arguments needed.
- **Composable**: Tools are small, single-purpose, and designed to be chained by scripts or AI agents.
- **Genetic Algorithm (GA) Search Engine**: Brute-forcing compiler flags and mutating source code AST to discover the exact code changes needed to fix compiler discrepancies.

## 🚀 Quick Start & Setup

Rebrew is designed to be consumed as a dependency by a project-specific decomp repo (e.g., [guild-rebrew](../guild-rebrew/)).

### 1. Installation

```bash
# In your decomp project's pyproject.toml:
[project]
dependencies = ["rebrew"]

[tool.uv.sources]
rebrew = { path = "../rebrew", editable = true }
```

Then from within the project directory:

```bash
uv sync
```

### 2. Project Configuration (`rebrew.toml`)

Each decomp project provides a `rebrew.toml` in its root. Rebrew finds it by searching upward from the current working directory (similar to how `git` finds `.git/`).

```toml
[targets.target_name]
binary = "original/target.dll"
format = "pe"
arch = "x86_32"
reversed_dir = "src/target_name"
function_list = "src/target_name/r2_functions.txt"
bin_dir = "bin/target_name"

[compiler]
profile = "msvc6"
command = "wine tools/MSVC600/VC98/Bin/CL.EXE"
includes = "tools/MSVC600/VC98/Include"
libs = "tools/MSVC600/VC98/Lib"
```

## 💻 Usage & Workflow

All CLI tools must be run **from within a project directory** that contains a `rebrew.toml` config file.

```bash
cd /path/to/your-decomp-project    # must contain rebrew.toml

# Initialization & Configuration
rebrew-init --target mygame --binary mygame.exe --compiler msvc6 # initialize project
rebrew-cfg list-targets              # list configured targets
rebrew-cfg add-origin ZLIB           # add origin to default target
rebrew-cfg set compiler.cflags "/O1" # set a config value

# Daily Workflow
rebrew-skeleton 0x10003DA0          # generate C skeleton from disassembly
rebrew-test src/target_name/f.c     # test implementation against target
rebrew next --stats                 # show progress (equivalent to rebrew-next)
rebrew next --improving             # list MATCHING functions sorted by byte delta
rebrew-lint                         # lint annotations in your source files
rebrew status                       # show reversing status overview
rebrew data                         # inventory globals in .data/.rdata/.bss
rebrew data --dispatch              # detect dispatch tables / vtables
rebrew graph --format summary       # call graph stats and blockers
rebrew-catalog                      # regenerate the function catalog and coverage JSON
rebrew-catalog --export-ghidra-labels  # generate ghidra_data_labels.json from detected tables
rebrew-build-db                     # build SQLite coverage database from catalog

# Solving the Matching Puzzle
rebrew-match --diff-only src/target_name/f.c       # side-by-side disassembly diff
rebrew-match --diff-only --mm src/target_name/f.c  # show only structural diffs (**)
rebrew-match src/target_name/f.c    # run the Genetic Algorithm Engine to resolve diffs
rebrew-ga                           # batch GA runner to solve all stubs
rebrew-ga --near-miss --threshold 5 # batch GA on MATCHING functions with ≤5B delta

# Advanced & Sync
rebrew-verify                       # bulk compile and verify all reversed functions
rebrew-verify --json                # structured JSON report to stdout
rebrew-verify --output report.json  # write report to specific file
rebrew-extract                        # batch extract and disassemble functions
rebrew-asm                          # quick offline disassembly
rebrew-sync --push                  # export annotations and push to Ghidra via ReVa MCP
rebrew-sync --summary               # preview what would be synced
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
uv run pytest tests/ -v    # run tests (1029 tests)
uv run ruff check .        # lint
uv run ruff format .       # format
python tools/sync_decomp_flags.py  # sync compiler flags from decomp.me
```

### Flag Sweep Tiers

The flag sweep uses compiler flag definitions synced from [decomp.me](https://github.com/decompme/decomp.me). The `generate_flag_combinations(tier)` function supports four effort levels: `quick` (~192 combos), `normal` (~21K combos), `thorough` (~1M combos), and `full` (~8.3M combos). The `msvc6` compiler profile automatically excludes incompatible MSVC 7.x+ flags.

## License

MIT
