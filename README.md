# ☕ Rebrew

**Compiler-in-the-loop decompilation workbench for binary-matching game reversing.**

Rebrew is a reusable Python tooling package for reconstructing exact C source code from compiled binaries. It provides a genetic algorithm engine, annotation pipeline, verification framework, and CLI tools.

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
rebrew-lint                         # lint annotations in your source files
rebrew-catalog                      # regenerate the function catalog and coverage JSON
rebrew-build-db                     # build SQLite coverage database from catalog

# Solving the Matching Puzzle
rebrew-match src/target_name/f.c    # run the Genetic Algorithm Engine to resolve diffs
rebrew-ga                           # batch GA runner to continuously try to solve all stubs

# Advanced & Sync
rebrew-verify                       # bulk compile and verify all reversed functions
rebrew-batch                        # batch extract and disassemble functions
rebrew-asm                          # quick offline disassembly
rebrew-sync                         # export annotations to Ghidra
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
uv run pytest tests/ -v    # run tests (201 tests)
uv run ruff check .        # lint
uv run black .             # format
python tools/sync_decomp_flags.py  # sync compiler flags from decomp.me
```

### Flag Sweep Tiers

The flag sweep uses compiler flag definitions synced from [decomp.me](https://github.com/decompme/decomp.me). The `generate_flag_combinations(tier)` function supports four effort levels: `quick` (~192 combos), `normal` (~21K combos), `thorough` (~1M combos), and `full` (~8.3M combos). The `msvc6` compiler profile automatically excludes incompatible MSVC 7.x+ flags.

## License

MIT
