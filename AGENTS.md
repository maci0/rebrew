# AGENTS.md — Rebrew

## Overview

**Rebrew** is a compiler-in-the-loop decompilation workbench for binary-matching
game reversing. Python package (`src/rebrew/`) with 22 CLI tools for compiling,
comparing, and matching C source against target binary functions (MSVC6 under Wine).

Installed as an editable package (`uv pip install -e .`) into a workspace project
that contains the actual binaries, source files, and toolchains.

## Build & Test Commands

```bash
# Install (editable)
uv pip install -e .
uv sync --all-extras            # with dev deps

# Run ALL tests (~1029 tests)
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

### Type Annotations (strict)

- **Every function signature** must have parameter and return type annotations
- **PEP 604 unions**: `T | None` not `Optional[T]`; `str | Path` not `Union[str, Path]`
- **Specific generics**: `dict[int, str]` not bare `dict`; `list[tuple[int, str]]` not `list[tuple]`
- **Named aliases** for complex types: `UncoveredItem = tuple[int, int, int, str, str, str, str | None]`
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

- **CLI tools**: Use `raise typer.Exit(code=1)` for user-facing errors. Print message with `rich.Console` first.
- **Library code**: Raise specific exceptions (`ValueError`, `FileNotFoundError`, `KeyError`, `RuntimeError`)
- **No bare `except:`** or `except Exception` without re-raise
- Pattern: print error → `raise typer.Exit(code=1)`

### Docstrings

- Module-level docstring on every file (brief description + architecture notes)
- Class/function docstrings use reStructuredText-ish style (see `compile.py`, `config.py`)
- Section separators: `# ---------------------------------------------------------------------------`

## Project Structure

```
src/rebrew/
├── main.py              # Umbrella CLI (`rebrew` command)
├── cli.py               # Shared: TargetOption, get_config(), iter_sources()
├── config.py            # ProjectConfig dataclass, rebrew.toml loader
├── annotation.py        # Annotation parsing (dataclass + regex parsers)
├── compile.py           # Shared compile helpers (compile_to_obj)
├── naming.py            # Shared naming/difficulty/origin helpers (next, skeleton, triage, ga)
├── binary_loader.py     # PE/COFF/ELF/Mach-O binary loading
├── extract.py           # Batch extract and disassemble functions
├── [tool].py            # Each CLI tool (test, verify, match, lint, etc.)
├── catalog/             # Function catalog package
│   ├── __init__.py      # Re-exports all public names
│   ├── loaders.py       # Ghidra/r2 function list parsers, DLL byte extraction
│   ├── registry.py      # build_function_registry, canonical size resolution
│   ├── grid.py          # Coverage grid / data JSON generation
│   ├── export.py        # Catalog + reccmp CSV generation
│   ├── sections.py      # PE section helpers (text size, globals)
│   └── cli.py           # Typer CLI app
└── matcher/             # Core GA engine (compiler, scoring, mutation, flags)
tests/
├── test_[module].py     # Unit tests, one file per module
```

### CLI Tool Pattern

Every tool follows this structure:

```python
import typer
from rebrew.cli import TargetOption, get_config

app = typer.Typer(help="Tool description", rich_markup_mode="rich")

@app.command()
def main(target: str | None = TargetOption) -> None:
    cfg = get_config(target=target)
    # ... implementation

def main_entry() -> None:
    app()
```

- `TargetOption` + `get_config()` from `rebrew.cli` — never build config manually
- `main_entry()` registered in `pyproject.toml` `[project.scripts]`
- Most tools support `--json` for machine-readable output. Always use `--json` when executing these CLI tools yourself to receive structured output.

### Test Patterns

- No conftest.py — each test file is self-contained
- Use `tmp_path` (pytest built-in) for temp directories
- Class-based grouping: `class TestFeatureName:` with `def test_specific(self) -> None:`
- Helper functions prefixed with `_` (e.g. `_make_project(tmp_path, toml)`)
- Tests type-annotated with `-> None` return
- Mock config via `SimpleNamespace` — type config params as `Any` in production code

### Key Architectural Rules

- **Config-driven**: All tools read `rebrew.toml` — never hardcode paths
- **Idempotent**: Every tool safe to re-run without side effects
- **Source discovery**: Always use `iter_sources(directory, cfg)` from `cli.py`
- **Source glob**: Use `source_glob(cfg)` — respects `cfg.source_ext` (`.c`, `.cpp`)
