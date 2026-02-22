# ☕ Rebrew

**Compiler-in-the-loop decompilation workbench for binary-matching game reversing.**

Rebrew is a reusable Python tooling package for reconstructing exact C source code from compiled binaries. It provides a genetic algorithm engine, annotation pipeline, verification framework, and CLI tools.

## Installation

Rebrew is designed to be consumed as a dependency by a project-specific decomp repo (e.g., [guild-rebrew](../guild-rebrew/)).

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

## Usage

All CLI tools must be run **from within a project directory** that contains a `rebrew.toml` config file. Rebrew finds `rebrew.toml` by searching upward from the current working directory (similar to how `git` finds `.git/`).

```bash
cd /path/to/your-decomp-project    # must contain rebrew.toml

rebrew-next --stats                 # show progress
rebrew-skeleton 0x10003DA0          # generate skeleton
rebrew-test src/server_dll/f.c      # test implementation
rebrew-verify                       # bulk verify all functions
rebrew-match ...                    # run GA engine
rebrew-catalog                      # regenerate catalog
rebrew-lint                         # lint annotations
rebrew-sync                         # export to Ghidra
rebrew-batch                        # batch extract functions
rebrew-asm                          # quick disassembly
```

## CLI Tools

| Command | Description |
|---------|-------------|
| `rebrew-next` | Show uncovered functions and progress stats |
| `rebrew-skeleton` | Auto-generate .c skeleton from a virtual address |
| `rebrew-test` | Quick compile-and-compare harness |
| `rebrew-match` | Run the genetic algorithm or diff mode |
| `rebrew-catalog` | Generate function catalog and coverage JSON |
| `rebrew-verify` | Bulk compile and verify all reversed functions |
| `rebrew-lint` | Lint annotation headers |
| `rebrew-sync` | Export annotations to Ghidra |
| `rebrew-batch` | Batch extract and disassemble functions |
| `rebrew-asm` | Quick offline disassembly |
| `rebrew-ga` | Batch GA runner for STUB functions |

## Project Configuration (`rebrew.toml`)

Each decomp project provides a `rebrew.toml` in its root:

```toml
[targets.server_dll]
binary = "original/Server/server.dll"
format = "pe"
arch = "x86_32"
reversed_dir = "src/server_dll"
function_list = "src/server_dll/r2_functions.txt"
bin_dir = "bin/server_dll"

[compiler]
profile = "msvc6"
command = "wine tools/MSVC600/VC98/Bin/CL.EXE"
includes = "tools/MSVC600/VC98/Include"
libs = "tools/MSVC600/VC98/Lib"
```

## Development

```bash
cd rebrew/
uv sync --all-extras       # install dev dependencies
uv run pytest tests/ -v    # run tests (62 tests)
uv run ruff check .        # lint
uv run black .             # format
```

## License

MIT
