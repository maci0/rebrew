# AGENTS.md — Rebrew

## Overview

**Rebrew** is a compiler-in-the-loop decompilation workbench for binary-matching
game reversing. It provides 22 CLI tools for compiling, comparing, and matching
C source against target binary functions, using MSVC6 under Wine.

This is a **pip-installable Python package** (`uv pip install -e .`). It is
installed into a workspace project (e.g. `guild-rebrew/`) that contains the
actual binaries, source files, and toolchains.

### Core Principles

- **Idempotent**: Every tool can be run repeatedly with the same result. No destructive side effects — safe to retry or re-run.
- **Config-driven**: All tools read from `rebrew.toml` — zero manual paths needed.
- **Composable**: Small, single-purpose tools designed to be chained by scripts or AI agents.

## Project Structure

```
rebrew/
├── pyproject.toml              # Package config, 22 CLI entry points
├── src/rebrew/
│   ├── __init__.py
│   ├── main.py                 # `rebrew` — umbrella CLI with subcommands
│   ├── cli.py                  # Shared: TargetOption, get_config()
│   ├── config.py               # ProjectConfig, rebrew.toml loader
│   ├── annotation.py           # Annotation parsing and manipulation
│   ├── binary_loader.py        # PE/COFF binary loading helpers
│   ├── compile.py              # Shared compile helpers (compile_to_obj, compile_and_compare)
│   │
│   ├── test.py                 # `rebrew-test` — quick compile-and-compare
│   ├── verify.py               # `rebrew-verify` — batch verify all .c files
│   ├── match.py                # `rebrew-match` — GA binary matching engine
│   ├── ga.py                   # `rebrew-ga` — batch GA runner for STUBs
│   ├── next.py                 # `rebrew-next` — find next functions to reverse
│   ├── skeleton.py             # `rebrew-skeleton` — generate C89 skeleton
│   ├── catalog.py              # `rebrew-catalog` — build function catalog + JSON
│   ├── build_db.py             # `rebrew-build-db` — build SQLite coverage DB
│   ├── asm.py                  # `rebrew-asm` — dump disassembly from binary
│   ├── lint.py                 # `rebrew-lint` — lint annotations
│   ├── sync.py                 # `rebrew-sync` — sync annotations with Ghidra via ReVa MCP
│   ├── batch.py                # `rebrew-batch` — batch extract/disassemble
│   ├── init.py                 # `rebrew-init` — initialize new project
│   ├── nasm.py                 # `rebrew-nasm` — NASM extraction
│   ├── flirt.py                # `rebrew-flirt` — FLIRT signature scanning
│   ├── cfg.py                  # `rebrew-cfg` — programmatic config editor
│   ├── status.py               # `rebrew-status` — project status overview
│   ├── data.py                 # `rebrew-data` — global data scanning
│   ├── depgraph.py             # `rebrew-graph` — dependency graph visualization
│   ├── promote.py              # `rebrew-promote` — promote function status
│   ├── triage.py               # `rebrew-triage` — triage unmatched functions
│   ├── decompiler.py           # Decompiler interface (used by skeleton.py)
│   ├── gen_flirt_pat.py        # FLIRT pattern generator
│   │
│   └── matcher/                # Core GA engine package
│       ├── __init__.py         # Public API re-exports
│       ├── compiler.py         # Wine execution, build_candidate*()
│       ├── core.py             # BuildCache (diskcache), GACheckpoint
│       ├── flags.py            # FlagSet, Checkbox, Flags primitives
│       ├── flag_data.py        # MSVC flag definitions and sweep tiers
│       ├── mutator.py          # Mutation engine, crossover
│       ├── parsers.py          # COFF/PE extraction
│       └── scoring.py          # Byte/mnemonic comparison
├── tests/                      # pytest tests (1003 tests)
└── docs/                       # WORKFLOW.md, TOOLS.md, and more
```

## CLI Tools (22 entry points)

| Command | Source | Purpose |
|---------|--------|---------|
| `rebrew` | `main.py` | Umbrella CLI with all subcommands |
| `rebrew-test` | `test.py` | Quick compile-and-compare for a .c file |
| `rebrew-verify` | `verify.py` | Batch verify all reversed files |
| `rebrew-match` | `match.py` | GA-based binary matching engine |
| `rebrew-ga` | `ga.py` | Batch GA runner for all STUB functions |
| `rebrew-next` | `next.py` | Find next functions to reverse |
| `rebrew-skeleton` | `skeleton.py` | Generate skeleton .c from VA |
| `rebrew-catalog` | `catalog.py` | Build function catalog + JSON (`--export-ghidra-labels` to generate `ghidra_data_labels.json`) |
| `rebrew-build-db` | `build_db.py` | Build SQLite coverage database (cells include `label`, `parent_function`) |
| `rebrew-asm` | `asm.py` | Dump disassembly from target binary |
| `rebrew-lint` | `lint.py` | Lint source file annotations |
| `rebrew-sync` | `sync.py` | Sync annotations to Ghidra via ReVa MCP (`--push`, `--apply`, `--export`) |
| `rebrew-batch` | `batch.py` | Batch extract and disassemble |
| `rebrew-nasm` | `nasm.py` | NASM assembly extraction |
| `rebrew-flirt` | `flirt.py` | FLIRT signature scanning |
| `rebrew-init` | `init.py` | Initialize a new rebrew project |
| `rebrew-cfg` | `cfg.py` | Read/edit `rebrew.toml` (idempotent) |
| `rebrew-status` | `status.py` | Project status overview |
| `rebrew-data` | `data.py` | Global data scanning and analysis |
| `rebrew-graph` | `depgraph.py` | Dependency graph visualization |
| `rebrew-promote` | `promote.py` | Promote function status (STUB → MATCHING → RELOC) |
| `rebrew-triage` | `triage.py` | Triage unmatched functions |


## JSON Output

Most tools support `--json` for machine-readable output (scripts, AI agents):

| Tool | `--json` Modes |
|------|---------------|
| `rebrew-test` | Single-function result, multi-function results |
| `rebrew-next` | `--stats`, recommendations, `--improving`, `--unmatchable`, `--group` |
| `rebrew-match` | `--diff-only` structured diff |
| `rebrew-asm` | Disassembly instructions |
| `rebrew-verify` | Verification report |
| `rebrew-lint` | Lint results |
| `rebrew-flirt` | FLIRT matches |
| `rebrew-status` | Status overview |
| `rebrew-catalog` | `--export-ghidra-labels` generates `ghidra_data_labels.json` from detected data labels/thunks; `--fix-sizes` updates SIZE annotations; `--sync-sizes` pushes corrected sizes to Ghidra |
| `rebrew-data` | Data scan results |

## CLI Patterns

All tools follow the same conventions:

```python
import typer
from rebrew.cli import TargetOption, get_config

app = typer.Typer(
    help="Tool description",
    rich_markup_mode="rich",
    epilog="Usage examples and context shown via --help",
)

@app.command()  # or @app.callback(invoke_without_command=True)
def main(target: Optional[str] = TargetOption):
    cfg = get_config(target=target)
    # ... use cfg.target_binary, cfg.compiler_command, etc.

def main_entry():
    app()
```

- Every tool uses `TargetOption` and `get_config()` from `rebrew.cli`
- Every tool has a `main_entry()` function registered in `pyproject.toml`
- Config comes from `rebrew.toml` in the current working directory

## Key Commands

### Testing a function

```bash
# Auto-reads VA, SIZE, SYMBOL, CFLAGS from source annotations
rebrew-test src/server.dll/game_pool_free.c

# With explicit args
rebrew-test src/server.dll/my_func.c _my_func --va 0x10003da0 --size 160
```

### Diffing against target

```bash
# Side-by-side disassembly diff (auto-reads config from rebrew.toml)
rebrew-match --diff-only src/server.dll/game_pool_free.c

# Show only structural differences (** lines)
rebrew-match --diff-only --mm src/server.dll/game_pool_free.c
```

Output markers: `==` (identical), `~~` (relocation diff), `**` (structural diff)
Use `--mm` (or `--mismatches-only`) to filter to `**` lines only.

### Running the GA

```bash
# OBJ-only mode (default, fastest)
rebrew-match src/server.dll/my_func.c --generations 200 --pop 64 -j 16

# Batch all STUBs
rebrew-ga --dry-run          # preview
rebrew-ga --generations 200  # run
```

## Configuration (rebrew.toml)

Tools auto-read `rebrew.toml` from the current directory:

```toml
[targets."server.dll"]
binary = "original/Server/server.dll"
reversed_dir = "src/server.dll"
# ...

[compiler.preset]
command = "wine tools/MSVC600/VC98/Bin/CL.EXE"
includes = "tools/MSVC600/VC98/Include"
```

This means `rebrew-test` and `rebrew-match` need zero manual paths — they read
compiler command, include dirs, target binary, and MSVC env from config.

## matcher/ Package

The core GA engine, used by `match.py` and `ga.py`:

| Module | Key Exports |
|--------|-------------|
| `compiler.py` | `build_candidate_obj_only()`, `build_candidate()`, `flag_sweep(tier=)`, `generate_flag_combinations(tier=)` |
| `core.py` | `BuildCache` (diskcache), `GACheckpoint`, `save/load_checkpoint` |
| `flags.py` | `FlagSet`, `Checkbox`, `Flags` — flag primitives (compatible with decomp.me) |
| `flag_data.py` | `COMMON_MSVC_FLAGS`, `MSVC6_FLAGS`, `MSVC_SWEEP_TIERS` — auto-generated from decomp.me |
| `mutator.py` | `mutate_code()`, `crossover()`, `compute_population_diversity()` |
| `parsers.py` | `parse_coff_symbol_bytes()`, `extract_function_from_pe()` (LIEF-based) |
| `scoring.py` | `score_candidate()`, `diff_functions()` |

### Scoring System (lower = better)

| Component | Weight | Measures |
|-----------|--------|----------|
| Length penalty | 3.0 | `abs(candidate_size - target_size)` |
| Weighted byte similarity | 1000.0 | Position-weighted, prologue 3x |
| Relocation-aware similarity | 500.0 | After masking relocatable fields |
| Mnemonic similarity | 200.0 | Via capstone disassembly |
| Prologue bonus | -100.0 | If first 20 bytes match |

---

## MSVC6 Constraints

- **C89 only**: no `for(int i=...)`, no `//` comments in strict mode, declare
  all variables at block top
- **Symbol decoration**: `_funcname` for `__cdecl`, `_funcname@N` for `__stdcall`
- **No `/GS`**, no `__declspec(noinline)` — not supported
- Wine execution: all CL.EXE/LINK.EXE calls go through Wine

## Compiler Flags by Origin

Origins and their flags are **config-driven** via `rebrew.toml`.  The table below
shows the defaults for The Guild's `server.dll`; other projects define their own.

| Origin | CL flags | Notes |
|--------|----------|-------|
| GAME | `/nologo /c /O2 /MT /Gd` | Full optimization, cdecl |
| MSVCRT | `/nologo /c /O1 /MT /Gd` | Size optimization |
| ZLIB | `/nologo /c /O2 /MT /Gd` | From zlib-1.1.3 source |

Configure per-project in `rebrew.toml`:
- `origins` — valid ORIGIN values (e.g. `["GAME", "MSVCRT", "ZLIB"]`)
- `library_origins` — origins using LIBRARY marker (default: all except first)
- `[targets.<name>.cflags_presets]` — per-origin compiler flags
- `[targets.<name>.origin_comments]` — skeleton preamble comments per origin
- `[targets.<name>.origin_todos]` — skeleton TODO text per origin

---

## Annotation Standard

Based on [reccmp annotations](https://github.com/isledecomp/reccmp/blob/master/docs/annotations.md).

### Function Header (required)

```c
// FUNCTION: server.dll 0x10003da0
// STATUS: RELOC
// ORIGIN: GAME
// SIZE: 160
// CFLAGS: /O2 /Gd
// SYMBOL: _alloc_game_object
```

**Marker types**: `FUNCTION` (game code), `LIBRARY` (third-party), `STUB` (incomplete)

**Required fields**: `STATUS`, `ORIGIN`, `SIZE`, `CFLAGS`

### STATUS Values

| Status | Meaning |
|--------|---------|
| `EXACT` | Byte-for-byte identical |
| `RELOC` | Identical after masking relocations (typical best result) |
| `MATCHING` | Close but structural diffs (add `BLOCKER` line) |
| `MATCHING_RELOC` | Very close, 1-5 byte diffs |
| `STUB` | Far off or placeholder |

### Lint Rules

Run `rebrew-lint` to check. Errors: E001-E017, Warnings: W001-W015.
Run `rebrew-lint --fix` to auto-migrate old annotation formats.

---

## Reference Sources

### MSVC6 CRT Source (Partial)

17 original CRT source files from VC++ 6.0 at `tools/MSVC600/VC98/CRT/SRC/`.
Key files: `MALLOC.C`, `FREE.C`, `SBHEAP.C` (105K), `OUTPUT.C` (88K), `HEAPINIT.C`.

CRT uses `#ifdef WINHEAP` path (server.dll) and `#ifdef _MT` (multi-threaded).

### zlib 1.1.3

Exact version in server.dll. Source at `references/zlib-1.1.3/` produces
byte-identical matches with `/O2`. Confirmed by version strings in binary.

---

## Dependencies

```
capstone>=5.0.0   # x86 disassembly
diskcache>=5.6    # Build result caching
jinja2>=3.1       # Template rendering (skeleton generation)
lief>=0.16.0      # PE/ELF/Mach-O parsing
numpy>=1.26       # Vectorized byte comparison (scoring)
pycparser>=2.21   # C parsing for AST mutations
python-flirt      # FLIRT signature matching
typer>=0.9        # CLI framework
```

## Build & Test

```bash
uv pip install -e .           # install
uv run pytest tests/ -v       # test (1003 tests)
uv run ruff check src/        # lint
```

## Code Style

- 4-space indentation, 100-char lines
- snake_case functions, PascalCase classes, `mut_` prefix for mutations
- Type hints on all function signatures
- `T | None` style (PEP 604, not `Optional[T]`)

### Strict Type Annotations

All new and modified code must include complete type annotations:

- **Function signatures**: Every parameter and return type must be annotated
- **PEP 604 unions**: Use `T | None` not `Optional[T]`; use `str | Path` not `Union[str, Path]`
- **Container types**: Use specific generics — `dict[int, str]` not bare `dict`,
  `list[tuple[int, str]]` not `list[tuple]`
- **Type aliases**: Define named aliases for complex types used in multiple places
  (e.g. `UncoveredItem = tuple[int, int, int, str, str, str, str | None]`)
- **Config parameters**: Functions accepting config objects from both `ProjectConfig`
  and `SimpleNamespace` (in tests) should type the parameter as `Any` and access
  optional fields with `getattr(cfg, "field_name", default)` for robustness
- **Local variables**: Annotate container variables when the type isn't obvious from
  the initializer (e.g. `existing: dict[int, str] = {}`)
- **Avoid `object`**: Use `Any` from `typing` when you need a catch-all type;
  `object` is too restrictive (doesn't allow attribute access)
