# AGENTS.md — Rebrew

## Overview

**Rebrew** is a compiler-in-the-loop decompilation workbench for binary-matching
game reversing. Python package (`src/rebrew/`) with CLI tools for compiling,
comparing, and matching C source against target binary functions (MSVC6 under Wine).

Installed as an editable package (`uv pip install -e .`) into a workspace project
that contains the actual binaries, source files, and toolchains.

## Build & Test Commands

```bash
# Install (editable)
uv pip install -e .
uv sync --all-extras            # with dev deps

# Run ALL tests (~1784 tests)
uv run pytest tests/ -v

# Run a SINGLE test file
uv run pytest tests/test_annotation.py -v

# Run a SINGLE test by name
uv run pytest tests/test_annotation.py -k "test_defaults" -v

# Run a SINGLE test class
uv run pytest tests/test_annotation.py::TestAnnotationDataclass -v

# Lint
uv run ruff check src/          # check only
uv run ruff check --fix src/    # auto-fix
uv run ruff format src/         # format

# Pre-commit (hooks: trailing-whitespace, ruff-check, ruff-format, pytest on push)
uv run pre-commit run --all-files

# Coverage
uv run python -m slipcover -m pytest
```

**pytest config** (`pyproject.toml`): `testpaths = ["tests"]`, `pythonpath = ["src"]`.
No conftest.py — tests use `tmp_path` fixture and inline helpers.

## Code Style

### Formatting & Linting (ruff)

- **Python 3.12+** target
- **100-char line length** (E501 ignored)
- **4-space indentation**
- Ruff rules: `["E", "F", "W", "I", "UP", "B", "SIM"]`
- Ignored: `E501` (line length), `B008` (function call in default arg — typer pattern), `B904` (raise from)

### Naming

- `snake_case` for functions and variables
- `PascalCase` for classes and dataclasses
- `UPPER_CASE` for module-level constants
- `_private` prefix for internal functions/constants (e.g. `_ARCH_PRESETS`, `_find_root`)
- `mut_` prefix for mutation functions in `matcher/mutator.py`
- **One canonical name per function** — no backward-compat aliases, no shims, no legacy names

### Type Annotations (strict)

- **Every function signature** must have parameter and return type annotations
- **PEP 604 unions**: `T | None` not `Optional[T]`; `str | Path` not `Union[str, Path]`
- **Specific generics**: `dict[int, str]` not bare `dict`; `list[tuple[int, str]]` not `list[tuple]`
- **Named aliases** for complex types: `UncoveredItem = tuple[int, int, int, str, str, str, str | None, float]`
- **Config params**: Type as `ProjectConfig` (from `rebrew.config`), use `getattr(cfg, "field", default)` for defensive access
- **`Any` over `object`**: `object` is too restrictive (no attribute access)

### Imports

Standard ordering (enforced by ruff `I`):
1. `from __future__ import annotations` (when needed for forward refs)
2. Standard library (`os`, `re`, `sys`, `pathlib`, etc.)
3. Third-party (`typer`, `rich`, `lief`, `capstone`, `numpy`, etc.)
4. Local (`from rebrew.config import ...`, `from rebrew.cli import ...`)

Blank line between each group. Specific imports preferred over star imports.

### Error Handling

- **CLI tools**: Use `error_exit(msg, json_mode=json_output)` from `rebrew.cli` (prints + raises `typer.Exit(code=1)`)
- **Library code**: Raise specific exceptions (`ValueError`, `FileNotFoundError`, `KeyError`, `RuntimeError`)
- **No bare `except:`** or `except Exception` without re-raise
- **JSON output**: Use `json_print(data)` from `rebrew.cli` for `--json` mode
- **VA parsing**: Use `parse_va(s)` from `rebrew.cli` for hex/int address strings
- **Exit codes**: Use `EXIT_OK` (0), `EXIT_MISMATCH` (1), `EXIT_ERROR` (2) from `rebrew.cli` for consistent process exit codes

### Docstrings

- Module-level docstring on every file (brief description + architecture notes)
- Class/function docstrings use reStructuredText-ish style (see `compile.py`, `config.py`)
- Section separators: `# ---------------------------------------------------------------------------`

### Dependencies — Use What We Import

If a library is already imported, use its built-in capabilities. Never hand-roll
functionality that exists in an imported dependency.

Key libraries and what they provide:

- **LIEF** (`lief`): Binary format detection (`lief.is_pe()`, `lief.is_elf()`, `lief.is_macho()`),
  format/arch identification via parsed headers (`header.machine`, `header.machine_type`,
  `header.cpu_type`), PE/ELF/Mach-O parsing. Never use manual `struct.unpack` on binary
  headers when LIEF can do it.
- **httpx** (`httpx`): HTTP client for Ghidra/ReVa MCP communication (`ghidra/cli.py`,
  `skeleton.py`, `decompiler.py`). Use `httpx.Client` for connection-pooled requests.
  Never use `urllib.request` for MCP endpoints.
- **Typer** (`typer`): CLI framework. Use `Console(stderr=True)` from Rich for
  user-facing output; rich markup (`[green]`, `[bold]`, etc.) for styled messages.
  Keep raw `print()` only for data output meant for piping (e.g. disassembly, NASM source).
- **pathlib** (`Path`): Path manipulation. Use `Path` methods over `os.path.*`.
- **tempfile** (`TemporaryDirectory`): Use context-managed `TemporaryDirectory` over
  `tempfile.mkdtemp()` + manual `shutil.rmtree()`.
- **angr** (`angr`, optional): Symbolic execution engine for `prove.py`. Optional
  dependency (`[project.optional-dependencies].prove`). Import guarded with a clear
  error message. Uses `claripy` for Z3 constraint solving.
- **tree-sitter** (`tree_sitter`, `tree_sitter_c`): C AST parser for structural
  extraction of function definitions, extern declarations, and extern variables.
  Used by `c_parser.py` — never hand-roll regex parsers for C structure when
  tree-sitter can do it.

## Project Structure

```
src/rebrew/
├── main.py              # Umbrella CLI (`rebrew` command)
├── merge.py             # Merge single-function C files into multi-function file
├── cli.py               # Shared: TargetOption, require_config(), iter_sources(),
│                        #   iter_library_headers(), iter_annotations(), error_exit(),
│                        #   json_print(), parse_va(), source_glob(), target_marker(),
│                        #   EXIT_OK, EXIT_MISMATCH, EXIT_ERROR, NEAR_MATCH_THRESHOLD,
│                        #   classify_match_status(), is_matched(), rel_display_path()
├── config.py            # ProjectConfig dataclass, rebrew-project.toml loader
├── annotation.py        # Annotation parsing (dataclass + comment parsers + library header parser)
├── c_parser.py          # Shared tree-sitter C parsing (function defs, extern decls, extern vars)
├── compile.py           # Shared compile helpers (compile_to_obj, compile_and_compare → CompareResult, classify_compare_result)
├── naming.py            # Shared naming/difficulty/origin helpers (next, skeleton, triage)
├── binary_loader.py     # PE/COFF/ELF/Mach-O binary loading + format detection (via LIEF)
├── extract.py           # Batch extract and disassemble functions
├── decompiler.py        # Pluggable decompiler backend (r2ghidra, r2dec, Ghidra headless)
├── gen_flirt_pat.py     # Generate FLIRT .pat files from MSVC6 COFF .lib archives
├── signature_parser.py  # Extract function signatures from C source via tree-sitter
├── split.py             # Split multi-function C files into individual files
├── struct_parser.py     # Extract struct/typedef definitions from C source via tree-sitter
├── utils.py             # Shared utilities (Wine stderr filtering, path helpers)
├── wibo.py              # Auto-download + verify wibo (lightweight Wine alternative)
├── compile_cache.py     # Disk-backed compile result cache (diskcache, SHA-256 keyed)
├── metadata.py          # Per-directory rebrew-function.toml metadata loader/writer; update_source_status is the canonical STATUS writer
├── crt_match.py         # CRT source cross-reference matcher (index, match, ASM detection)
├── cache_cli.py         # `rebrew cache stats` / `rebrew cache clear` CLI
├── prove.py             # Symbolic equivalence prover via angr (optional dep)
├── cu_map.py            # Compilation unit boundary inference (contiguity + call graph)
├── todo.py              # Prioritized action list: what to work on next
├── match.py             # GA engine — single file or batch (--all); absorbs old ga.py
├── [tool].py            # Each CLI tool (test, verify, diff, lint, etc.)
├── catalog/             # Function catalog package (see catalog/AGENTS.md)
│   ├── __init__.py      # Re-exports all public names
│   ├── loaders.py       # Ghidra JSON + text function list parsers, DLL bytes, library header scanning
│   ├── registry.py      # build_function_registry, canonical size resolution
│   ├── grid.py          # Coverage grid / data JSON generation
│   ├── export.py        # Catalog + reccmp CSV generation
│   ├── sections.py      # PE section helpers, shared x86 utils (trim_trailing_padding, has_back_jumps)
│   └── cli.py           # Typer CLI app
├── matcher/             # Core GA engine (see matcher/AGENTS.md)
│   ├── __init__.py      # Re-exports: build_candidate, score_candidate, mutate_code, ...
│   ├── core.py          # Data types: Score, BuildResult, BuildCache, GACheckpoint
│   ├── compiler.py      # MSVC6 compilation + flag sweep (Wine/wibo subprocess)
│   ├── scoring.py       # Byte-level scoring, structural similarity (capstone + numpy)
│   ├── mutator.py       # 120 C source mutation operators for GA exploration
│   ├── parsers.py       # Object file parsing (COFF/ELF/Mach-O via LIEF)
│   ├── flags.py         # FlagSet/Checkbox primitives (decomp.me compatible)
│   └── flag_data.py     # Auto-synced MSVC flag definitions
└── agent-skills/        # AI agent workflow skills (SKILL.md per skill)
    ├── rebrew-intake/   # Binary onboarding, FLIRT scan, catalog, triage
    ├── rebrew-workflow/  # End-to-end reversing loop
    ├── rebrew-matching/ # Deep binary matching, GA engine, flag sweeps
    ├── rebrew-data-analysis/  # Global data, BSS layout, dispatch tables
    └── rebrew-ghidra-sync/ # Ghidra ↔ Rebrew sync via ReVa MCP
tests/
├── test_[module].py     # Unit tests, one file per module
```

### CLI Tool Pattern

Every single-command tool follows this structure:

```python
import typer
from rich.console import Console
from rebrew.cli import TargetOption, require_config

console = Console(stderr=True)

app = typer.Typer(help="Tool description", rich_markup_mode="rich")

@app.callback(invoke_without_command=True)
def main(target: str | None = TargetOption) -> None:
    cfg = require_config(target=target)
    # ... implementation

def main_entry() -> None:
    """Run the Typer CLI application."""
    app()

if __name__ == "__main__":
    main_entry()
```

- Uses `@app.callback(invoke_without_command=True)` so the function works both
  as a standalone entry point (`rebrew-<cmd>`) and as a flat subcommand when
  registered via `app.command()` in `main.py`.
- `TargetOption` + `require_config()` from `rebrew.cli` — never build config manually. Use `load_config()` from `rebrew.config` only when optional config loading is intentional (e.g. `lint.py`, `doctor.py` diagnostics).
- `main_entry()` registered in `pyproject.toml` `[project.scripts]`.
- Most tools support `--json` for machine-readable output. Always use `--json` when executing these CLI tools yourself to receive structured output.
- The multi-command modules are `cfg.py` (subcommands: `list-targets`, `show`, `add-target`, `remove-target`, `add-module`, `remove-module`, `set`, `set-cflags`, `raw`, `path`, `detect-crt`) and `cache_cli.py` (subcommands: `stats`, `clear`), both registered via `add_typer()` in `main.py`.

### CLI Conventions

All CLI tools follow these conventions for a consistent user experience:

- **Parameter ordering**: `--json` always comes before `--target`, both as the last two options
- **`--json` help text**: Always `"Output results as JSON"` (exact string)
- **`--dry-run` help text**: Always `"Preview changes without writing"` for file-modifying tools
- **Rich output to stderr**: Use `console = Console(stderr=True)` with `console.print()` for all user-facing output; Rich markup (`[green]`, `[bold]`, `[red]`, etc.) for styled messages. Keep raw `print()` only for data output meant for piping (disassembly, NASM source, hex dumps).
- **`main_entry()` docstring**: Always `"""Run the Typer CLI application."""`
- **`if __name__` guard**: Every CLI module ends with `if __name__ == "__main__": main_entry()`
- **Error handling in JSON mode**: Pass `json_mode=json_output` to `error_exit()` so errors are JSON-formatted when `--json` is active

### Test Patterns

- No conftest.py — each test file is self-contained
- Use `tmp_path` (pytest built-in) for temp directories
- Class-based grouping: `class TestFeatureName:` with `def test_specific(self) -> None:`
- Helper functions prefixed with `_` (e.g. `_make_project(tmp_path, toml)`)
- Tests type-annotated with `-> None` return
- Mock config via `SimpleNamespace` — type config params as `Any` in production code

### Key Architectural Rules

- **Config-driven**: All tools read `rebrew-project.toml` — never hardcode paths
- **Idempotent**: Every tool safe to re-run without side effects
- **Source discovery**: Always use `iter_sources(directory, cfg)` from `cli.py`; use `iter_library_headers(directory)` for `library_*.h` files
- **Batch annotation loading**: Always use `iter_annotations(sources, target=...)` from `cli.py` — it wraps `parse_c_file_multi` with silent error handling and returns `[(path, [Annotation])]` pairs
- **Source glob**: Use `source_glob(cfg)` — respects `cfg.source_ext` (`.c`, `.cpp`)
- **No wheel reinvention**: If an imported library provides the functionality, use it
- **No backward compat**: One canonical name per function — no aliases, no shims, no legacy wrappers
- **Metadata for volatile metadata**: Volatile fields (STATUS, CFLAGS, BLOCKER, NOTE, GHIDRA) live in `rebrew-function.toml` per-directory metadata, managed via `rebrew.metadata`. **Never manually edit `rebrew-function.toml`**
- **Status promotion via metadata only**: Call `update_source_status(metadata_dir, new_status, module, va)` from `rebrew.metadata` to promote STATUS (pass `cfg.metadata_dir` as the first argument). Both `rebrew test` and `rebrew verify` always call this function. **Never write STATUS inline into `.c` files.**
- **Compile result type**: `compile_and_compare` and `verify_entry` return `CompareResult` from `rebrew.compile`. Consume `.matched`, `.status`, `.delta`, `.match_percent` — never unpack as a tuple.
