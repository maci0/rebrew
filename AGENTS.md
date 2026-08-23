# AGENTS.md — Rebrew

## Overview

**Rebrew** is a compiler-in-the-loop decompilation workbench for binary-matching game reversing. Python package (`src/rebrew/`) with CLI tools to compile, compare, and match C source against target binary functions (every Windows/DOS toolchain runs through its docker image; MinGW GCC via `gcc-pe` for non-MSVC PE/x86_32 targets).

Install editable (`uv pip install -e .`) inside a workspace containing binaries, sources, and toolchains.

## Compiler Profiles

- **`msvc6`** (default): MSVC 6.0 — runs ONLY through its docker image `rebrew/msvc:6.0-win32` (the image wraps wine; the host never calls CL.EXE directly). MSVC flags (`/I`, `/Fo`, `/c`). C89.
  Execution is **docker-only for every Windows/DOS toolchain** (all `msvc*`, `borlandc55`, `watcom`, `tc16`/20, `msvc1.52`/15/10, `delphi16`): the image encapsulates the runtime (wine / DOSBox) and there is no host wine/wibo/dosbox fallback.  A missing image is a hard error — run `rebrew toolchain build <name>` (or `rebrew toolchain pull <name>`).  The docker build source (Dockerfiles, wrappers, the shared `base`) lives in the sibling **rebrew-toolchains** checkout (overridable via `REBREW_TOOLCHAINS_DIR`); `rebrew toolchain build`/`vendor` read it from there — rebrew no longer vendors build files in-repo.
  The 16-bit media tarballs are user-supplied next to their Dockerfile in that checkout; the vendored host trees (assemble via `rebrew toolchain vendor`) land in `<family>/<version>-<arch>/source` there too.
- **`gcc-pe`**: `i686-w64-mingw32-gcc` — POSIX flags (`-I`, `-o`, `-c`), a native Linux binary (no wine), PATH-resolved toolchain, empty `includes`/`libs` allowed. For MinGW GCC / Zig-built PE/x86_32 targets (`.buildid` section, `0f 1f` GNU nops, call-based `___chkstk_ms` probe, few/no CRT imports).
  See `docs/TOOLCHAIN.md` for the codegen-version caveat: byte-exact matching requires the author's exact GCC version; old builds usually match only structurally (document semantic decomp + blocker).
- **`gcc` / `clang`**: ELF/x86_64 targets.
- **`borlandc55`**: Borland C++ 5.5 free tools (bcc32) — image `rebrew/borland:5.5-win32` (wine inside the image). For Borland-built PE/x86_32 targets (family `borlandc`).
- **`watcom16`**: Open Watcom 2.0 `wcc` (16-bit DOS, native Linux binary — no image, runs directly). Same snapshot as `watcom`. For 16-bit DOS/Watcom targets (family `watcom`).
- **`tc16`**: Turbo C++ 3.1 `TCC.EXE` (16-bit DOS) — image `rebrew/borland:3.1-win16` (DOSBox inside the image). Classic DOS-game compiler. 16-bit OMF via `rebrew.matcher.omf16`.
- **`msvc1.52` / `delphi16`**: 16-bit targets — images `rebrew/msvc:1.52-win16`, `rebrew/delphi:1.0-win16` (DOSBox inside the image).

All images build reproducibly (pinned sources, sha256-verified downloads or 16-bit media tarballs in the rebrew-toolchains checkout; shared `rebrew/base` with pinned Debian digest) and `rebrew toolchain smoke` gates byte-reproducible objects for every image-backed toolchain — see `docs/TOOLCHAIN.md`.

**CMake builds** (projects that link via CMake instead of the rebrew compile
pipeline) run the image's tools through the `rebrew-cmake-{cl,link,lib}`
console scripts: they translate CMake's invocations into `docker run` calls
(same-path-mounted project root, shared flock-initialized wineprefix,
`INCLUDE`/`LIB` from the image's own tree).  Generate a project's toolchain
file with `rebrew cmake-toolchain --toolchain msvc6 --out cmake/` and pass
`--toolchain cmake/toolchain-msvc6-docker.cmake` to `cmake -B build`.

**Per-library toolchain/flags overrides** (`rebrew-library.toml` at a library
root, managed by `rebrew library set/show/rm`): a source subtree whose
functions were all built with one compiler + flags declares them once — every
function under it compiles with that docker image + flags instead of
per-function metadata.  Resolution (most specific first): per-function
`TOOLCHAIN`/`CFLAGS` (`rebrew-function.toml`) → nearest `rebrew-library.toml`
(walk-up) → project default.  Known shipped libraries (e.g. `msvcrt-static` =
MSVC static CRT, `/MT /O2 /Gd`) fill missing fields via presets.  See
`docs/TOOLCHAIN.md`.

## Build & Test Commands

```bash
# Install (editable)
uv pip install -e .
uv sync --all-extras            # with dev deps

# Run all tests (~4850)
uv run pytest tests/ -v

# Single file
uv run pytest tests/test_annotation.py -v

# Single test by name
uv run pytest tests/test_annotation.py -k "test_defaults" -v

# Single class
uv run pytest tests/test_annotation.py::TestAnnotationDataclass -v

# Lint
uv run ruff check src/          # check only
uv run ruff check --fix src/    # auto-fix
uv run ruff format src/         # format

# Pre-commit (trailing-whitespace, ruff-check, ruff-format, pytest on push)
uv run pre-commit run --all-files

# Coverage
uv run python -m slipcover -m pytest
```

**pytest config** (`pyproject.toml`): `testpaths = ["tests"]`, `pythonpath = ["src", "."]` (`"."` exposes `tools/` as namespace).
No conftest.py — tests use `tmp_path` + inline helpers.

## Code Style

### Formatting & Linting (ruff)

- **Python 3.12+**
- **100-char lines** (E501 ignored)
- **4-space indent**
- Ruff rules: `["E", "F", "W", "I", "UP", "B", "SIM"]`
- Ignored: `E501` (line length), `B008` (function call in default arg — typer pattern), `B904` (raise without from)

### Naming

- `snake_case` for functions/variables
- `PascalCase` for classes/dataclasses
- `UPPER_CASE` for module constants
- `_private` prefix for internals (e.g. `_ARCH_PRESETS`, `_find_root`)
- `mut_` prefix for mutations in `matcher/mutator.py`
- **One name per function** — no aliases/shims/legacy names

### Type Annotations (strict)

- **All signatures** require param + return annotations
- **PEP 604 unions**: `T | None` not `Optional[T]`; `str | Path` not `Union[str, Path]`
- **Specific generics**: `dict[int, str]` not bare `dict`; `list[tuple[int, str]]` not `list[tuple]`
- **Named aliases** for complex types: `RelocInput = list[int] | dict[int, str] | Sequence[CoffRelocRecord] | None`
- **Config params**: type as `ProjectConfig` (`rebrew.config`); use `getattr(cfg, "field", default)` defensively
- **`Any` over `object`**: `object` blocks attribute access

### Imports

Order enforced by ruff `I`:
1. `from __future__ import annotations` (for forward refs)
2. Standard library (`os`, `re`, `sys`, `pathlib`, etc.)
3. Third-party (`typer`, `rich`, `lief`, `capstone`, `numpy`, etc.)
4. Local (`from rebrew.config import ...`, `from rebrew.cli import ...`)

Blank line between groups. Prefer specific imports over `*`.

### Error Handling

- **CLI**: `error_exit(msg, json_mode=json_output)` from `rebrew.cli` (prints + raises `typer.Exit(code=1)`)
- **Library**: raise specific exceptions (`ValueError`, `FileNotFoundError`, `KeyError`, `RuntimeError`)
- **No bare `except:`** or `except Exception` without re-raise
- **JSON output**: `json_print(data)` from `rebrew.cli` for `--json` mode
- **VA parsing**: `parse_va(s)` from `rebrew.cli` for hex/int addresses
- **Exit codes**: `EXIT_OK` (0), `EXIT_MISMATCH` (1), `EXIT_ERROR` (2) from `rebrew.cli`

### Docstrings

- Every file needs a module docstring (brief + architecture)
- Class/function docstrings: reStructuredText-ish (see `compile.py`, `config.py`)
- Section separators: `# ---------------------------------------------------------------------------`

### Dependencies — Use What We Import

If already imported, use its API — don't reimplement.

Key libraries:

- **LIEF** (`lief`): format detection (`lief.is_pe/elf/macho`), header-based format/arch (`header.machine`, `header.machine_type`, `header.cpu_type`), PE/ELF/Mach-O parsing. Never `struct.unpack` headers manually.
- **httpx** (`httpx`): HTTP for Ghidra/ReVa MCP (`ghidra/cli.py`, `skeleton.py`, `decompiler.py`). Use `httpx.Client` (pooled); never `urllib.request` for MCP.
- **Typer** (`typer`): CLI framework. Use `Console(stderr=True)` (Rich) + markup (`[green]`, `[bold]`, etc.); raw `print()` only for piped data (disassembly, NASM).
- **pathlib** (`Path`): use `Path` methods, not `os.path.*`.
- **tempfile** (`TemporaryDirectory`): context-managed `TemporaryDirectory`, not `mkdtemp()` + `shutil.rmtree()`.
- **angr** (`angr`, optional, `[prove]`): symbolic execution for `prove.py`; guarded import with clear error; uses `claripy`/Z3.
- **tree-sitter** (`tree_sitter`, `tree_sitter_c`): C AST for function defs, extern decls/vars (`c_parser.py`). Never regex-parse C structure.

## Project Structure

```
src/rebrew/
├── main.py              # Umbrella CLI (`rebrew`)
├── merge.py             # Merge single-function C files into one
├── cli.py               # Shared: TargetOption, require_config(), iter_annotations(),
│                        #   error_exit(), json_print(), parse_va(),
│                        #   EXIT_OK, EXIT_MISMATCH, EXIT_ERROR, STATUS_COLORS
├── sources.py           # Source discovery: source_exts(), source_glob(), target_marker(),
│                        #   iter_sources(), iter_library_headers() (pure pathlib/config logic)
├── config.py            # ProjectConfig dataclass, rebrew-project.toml loader
├── annotation.py        # Annotation parsing (dataclass + comment parsers + library header parser); MIN_VALID_VA / min_valid_va_for VA floor
├── c_parser.py          # tree-sitter C parsing (function defs, extern decls/vars)
├── compile.py           # Compile helpers (compile_to_obj, compile_and_compare → CompareResult,
│                        #   classify_compare_result, classify_match_status, is_matched,
│                        #   NEAR_MATCH_THRESHOLD)
├── naming.py            # Naming/difficulty/origin helpers (next, skeleton, triage)
├── binary_loader.py     # PE/COFF/ELF/Mach-O loading + format detection (via LIEF)
├── extract.py           # Batch extract + disassemble functions
├── decompiler.py        # Pluggable decompiler backend (r2ghidra, r2dec, ghidra, kuna) — kuna also seeds the GA (--kuna-seed)
├── cfg_ged.py           # CFG structural similarity (basic-block graph edit distance; feeds near-diag)
├── gen_flirt_pat.py     # Generate FLIRT .pat from MSVC6 COFF .lib archives
├── signature_parser.py  # Extract function signatures from C (tree-sitter)
├── split.py             # Split multi-function C files into singles
├── struct_parser.py     # Extract struct/typedef defs from C (tree-sitter)
├── utils.py             # Shared utilities (atomic_write_text, rel_display_path)
├── analysis.py          # Recon primitives: iter_strings, scan_references (Xref/Insn/StringEntry), string_refs
├── analyze.py           # One-shot dossier (toolchain, strings, imports, dispatch, FLIRT, NEAR_MATCHING blockers)
├── pe_headers.py        # PE header helpers (image base, section math)
├── ne_loader.py         # NE (New Executable) loader — 16-bit Windows 3.x format detection + parsing
├── headless.py          # Headless X server management for wine compiler invocations
├── wibo.py              # Auto-download + verify wibo (lightweight Wine alternative)
├── compile_cache.py     # Disk-backed compile cache (diskcache, SHA-256 keyed)
├── metadata.py          # Per-directory rebrew-function.toml loader/writer; update_source_status is canonical STATUS writer; is_status_sticky / should_promote_status promotion rules
├── metadata_model.py    # Typed metadata schema helpers (file-only vs metadata-only routing)
├── data_metadata.py     # Per-directory data metadata (global/BSS annotations)
├── crt_match.py         # CRT cross-reference matcher (index, match, ASM detection)
├── cache_cli.py         # `rebrew cache stats` / `rebrew cache clear` CLI
├── prove.py             # Symbolic equivalence prover via angr (optional)
├── delphi16.py          # Delphi 1.0 (16-bit) compile support — DOSBox sandbox + NE parse
├── msvc16.py            # MSVC 1.52 (16-bit) compile support — DOSBox + OMF object
├── tc16.py              # Turbo C 2.0/C++ 3.1 (16-bit) compile support — DOSBox + tiny-model output
├── lzexe.py             # LZEXE 0.90/0.91 DOS unpacker core (CLI in lzexe_cli.py)
├── library.py           # rebrew-library.toml per-library overrides + `rebrew library` CLI group
├── dosbox.py            # Shared headless DOSBox runner (mount sandbox as C:, FAT-uppercase reads)
├── toolchain.py         # Toolchain abstraction: spec registry, docker-only runner (images for Windows/DOS, native for Linux compilers)
├── toolchain_cli.py     # `rebrew toolchain` CLI (list/status/detect/pull/build)
├── cu_map.py            # Compilation-unit boundary inference (contiguity + call graph)
├── todo.py              # Prioritized action list
├── similar.py           # Find structurally similar functions
├── binary_similarity.py # Whole-binary structural similarity vs another binary (versions/DLL+EXE)
├── match.py             # GA engine — single or batch (--all); absorbs old ga.py
│
├── # --- CLI tools (each exports app, main, main_entry) ---
├── test.py              # Compile, byte-compare, auto-update STATUS
├── verify.py            # Bulk verification (incremental, cached)
├── diff.py              # Compile and diff against target
├── asm.py               # Disassemble (hex/NASM); --imports/--strings/--hints annotate IAT, strings, codegen patterns (post-decrement, SEH, CRT magic, switch dispatch incl. byte-compressed, IAT forwarder, EH-ctor, esp-disp8); detect_function_pattern + calling_convention
├── switch.py            # `rebrew switch` — decode jump-table switches (case → handler; --all recon)
├── skeleton.py          # Generate skeleton C files (convention-aware stubs; --batch --skip-fragments; stale-size warnings)
├── fixup.py             # `rebrew fix` — DecBench-style compilability fixup for decompiler output
├── struct_recover.py    # `rebrew recover-structs` — struct typedefs from decompiler offset evidence
├── document_unmatched.py# STUB skeletons + blockers for remaining functions (`rebrew document-unmatched`)
├── postlink.py          # `rebrew postlink` — normalize built-binary layout onto the reference
├── cmake_tc.py          # `rebrew cmake-toolchain` + rebrew-cmake-{cl,link,lib} — CMake
│                        # bridge: run the toolchain image's tools via docker from CMake
├── cross_import.py      # `rebrew cross-import` — import functions matched in another target
├── lzexe_cli.py         # `rebrew unpack-lzexe` — unpack LZEXE 0.90/0.91 DOS executables
├── binsync_import.py    # Import a BinSync state dir into rebrew metadata
├── binsync_diff.py      # Read-only BinSync divergence report
├── lint.py              # Lint C annotations + corpus consistency (W028: markers vs function list)
├── llm_seed.py          # LLM alternative-implementation seeding for GA (--llm-seed)
├── near_diag.py         # Classify why NEAR_MATCHING doesn't byte-match (register/equiv/reloc/structural + EFFECTIVE)
├── stack_cmp.py         # Compare compiled function's stack frame vs target (reccmp stackcmp, no PDB)
├── rename.py            # `rebrew rename` CLI (typer app + argument resolution)
├── rename_ops.py        # Cross-reference rename engine (shared by rename CLI, sync pull, binsync import)
├── init.py              # Initialize new project
├── imports.py           # List PE imports + detect jmp [iat] stubs
├── exports.py           # Verify recompiled binary export table vs target (verexp equivalent)
├── pdb_info.py          # PDB metadata (S_COMPILE3 compiler + command line)
├── identify_library.py  # Library-function backends (CRT/ZLIB marking)
├── intake.py            # One-shot binary onboarding (FLIRT scan, catalog, triage)
├── discover.py          # Function enumeration (rizin aaa→aap→capstone linear sweep)
├── strings.py           # Extract printable strings from data sections + xrefs
├── xrefs.py             # Cross-reference explorer for an address
├── describe.py          # Per-function dossier (callers, callees, strings, imports)
├── report.py            # Static HTML site (index, strings, imports, call graph)
├── doctor.py            # Project health diagnostics
├── status.py            # Reversing progress overview
├── toolchain_detect.py  # Compiler/version detection (diec → PDB → heuristics)
├── dashboard.py         # Read-only web dashboard over db/coverage.db
├── data.py              # Global data scanner (.data/.rdata/.bss); --annotate inserts
│                        # // GLOBAL: markers; --layout-audit/--fill-data placement
├── data_layout.py       # Shared .data placement model (audit, pad emission, ownership)
├── depgraph.py          # Function dependency graph
├── flirt.py             # FLIRT signature scanning (project flirt_sigs/ merged
│                        # with the sibling rebrew-flirt-sigs checkout)
├── build_db.py          # Build SQLite coverage DB from data JSON
├── binsync_export.py    # Export annotations to BinSync state dir
├── round_trip.py        # Splice matched functions back into PE, verify byte equality
├── resource.py          # PE resource comparison
├── cfg.py               # Multi-command: list-targets, show, add-target, set, set-cflags, etc.
├── skills.py            # Skill discovery CLI: list, show (multi-command)
├── solutions_db.py      # GA solutions DB (cross-function cflags seeding)
│
├── catalog/             # Function catalog (see catalog/AGENTS.md)
│   ├── __init__.py      # Re-exports all public names
│   ├── models.py        # Types (FunctionEntry, etc.)
│   ├── loaders.py       # Ghidra JSON + text list parsers, DLL bytes, library header scanning
│   ├── registry.py      # build_function_registry, canonical size resolution
│   ├── grid.py          # Coverage grid / data JSON
│   ├── export.py        # Catalog + reccmp CSV
│   ├── sections.py      # PE section helpers, x86 utils (trim_trailing_padding, has_back_jumps)
│   └── cli.py           # Typer CLI app
├── matcher/             # Core GA engine (see matcher/AGENTS.md)
│   ├── __init__.py      # Re-exports: build_candidate, score_candidate, mutate_code, ...
│   ├── core.py          # Types: Score, BuildResult, BuildCache, GACheckpoint
│   ├── compiler.py      # MSVC6 compilation + flag sweep (docker images)
│   ├── scoring.py       # Byte scoring, structural similarity (capstone + numpy)
│   ├── mutator.py       # 119 C mutation operators for GA
│   ├── omf16.py         # Minimal 16-bit OMF parser (MSVC 1.52 dialect — code + reloc slots for the 16-bit path)
│   ├── ast_engine.py    # tree-sitter AST mutation helpers
│   ├── parsers.py       # Object parsing (COFF/ELF/Mach-O via LIEF)
│   ├── flags.py         # FlagSet/Checkbox primitives (decomp.me compatible)
│   ├── flag_data.py     # Auto-synced MSVC flag defs
│   └── solutions.py     # GA solution transfer DB (cross-function cflags seeding)
├── ghidra/              # Ghidra sync (ReVa MCP)
│   ├── __init__.py      # Re-exports public API
│   ├── models.py        # Types (PullResult, PullChange, etc.)
│   ├── client.py        # MCP HTTP (httpx)
│   ├── commands.py      # Sync builders (push, pull, rename, size-sync)
│   └── cli.py           # Typer CLI (`rebrew sync`)
├── core/                # Matching + toolchain utilities
│   ├── __init__.py      # Re-exports: smart_reloc_compare, msvc_env_from_config
│   ├── matching.py      # smart_reloc_compare (relocation-aware byte compare)
│   └── toolchain.py     # msvc_env_from_config (MSVC env setup)
└── agent-skills/        # AI workflow skills (SKILL.md per skill)
    ├── rebrew-intake/   # Binary onboarding, FLIRT scan, catalog, triage
    ├── rebrew-workflow/  # End-to-end reversing loop
    ├── rebrew-matching/ # Deep binary matching, GA, flag sweeps
    ├── rebrew-data-analysis/  # Global data, BSS layout, dispatch tables
    └── rebrew-ghidra-sync/ # Ghidra ↔ Rebrew sync via ReVa MCP
tests/
├── test_[module].py     # Unit tests, one per module
```

The docker-image build source (Dockerfiles, wrappers, `base/`, the 16-bit
media tarballs) is **not in this repo** — it lives in the sibling
**`rebrew-toolchains`** checkout (github.com/maci0/rebrew-toolchains,
overridable via `REBREW_TOOLCHAINS_DIR`).  `rebrew toolchain build`/
`vendor`/`update` read it from there; `rebrew.toolchain._toolchains_repo()`
resolves it (a missing checkout is an actionable error).

`agent-skills/` is the single source of truth for AI workflow skills
(packaged; served by `rebrew skills list/show` — `src/rebrew/skills.py`).
`rebrew init` renders it into a project's `.agents/skills/`, substituting
`<target>` with the target name (`init._copy_agent_skills`).  This repo's own
`.agents/skills/` is one such rendered copy (target `bench`) — edit
`agent-skills/`, then re-render; `tests/test_skills_sync.py` pins the copy and
`tools/validate_skill_commands.py` gates stale CLI flags in SKILL.md files.

### CLI Tool Pattern

Single-command tools follow this pattern:

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

- `@app.callback(invoke_without_command=True)` — works as standalone entry (`rebrew-<cmd>`) and flat subcommand via `app.command()` in `main.py`.
- `TargetOption` + `require_config()` from `rebrew.cli` — never build config manually. Use `load_config()` from `rebrew.config` only for optional loads (e.g. `lint.py`, `doctor.py`).
- `main_entry()` registered in `pyproject.toml` `[project.scripts]`.
- Most tools support `--json`; always use it for structured output when invoking them yourself.
- Multi-command modules (registered via `add_typer()` in `main.py`'s `_MULTI_COMMANDS`): `extract.py` (`list`, `show`, `batch`), `cfg.py` (`list-targets`, `show`, `add-target`, `remove-target`, `add-module`, `remove-module`, `set`, `set-cflags`, `raw`, `path`, `detect-crt`), `cache_cli.py` (`stats`, `clear`), `skills.py` (`list`, `show`), `resource.py`, `library.py`, `toolchain_cli.py` (`list`, `status`, `detect`, `pull`, `build`, `vendor`, `smoke`, `update`, `check-updates`).

### CLI Conventions

All tools follow these for consistency:

- **Param order**: `--json` before `--target`, both last
- **`--json` help**: always `"Output results as JSON"` (exact)
- **`--dry-run` help**: always `"Preview changes without writing"` (file-modifying tools)
- **Output**: `console.print()` via `Console(stderr=True)` + Rich markup (`[green]`, `[bold]`, etc.); raw `print()` only for piped data (disassembly, NASM, hex dumps)
- **`main_entry()` docstring**: always `"""Run the Typer CLI application."""`
- **`if __name__` guard**: every CLI module ends with `if __name__ == "__main__": main_entry()`
- **JSON errors**: pass `json_mode=json_output` to `error_exit()` for JSON-formatted errors under `--json`

### Adding a New GA Mutation

Mutations live in [`src/rebrew/matcher/mutator.py`](src/rebrew/matcher/mutator.py). All `mut_` prefix (see Naming); operate via tree-sitter AST queries — never regex.

Numeric constants need explicit operators: GA can't fix wrong offsets/magics/sizes without a tweak (`mut_tweak_integer_literal` covers small ±deltas; add targeted ops if search plateaus).

1. **Write** in `mutator.py`:
   ```python
   def mut_my_transform(s: str, rng: random.Random) -> str | None:
       """One-line docstring."""
       # tree-sitter query to find matches
       # return modified source or None if no match
   ```

2. **Register** in `ALL_MUTATIONS` (bottom of file)

3. **Test** in `tests/test_mutator_p*.py`

4. **Document** — add row to category table in [`docs/GA_MUTATIONS.md`](docs/GA_MUTATIONS.md)

### Test Patterns

- No conftest.py — each file self-contained
- `tmp_path` (pytest builtin) for temp dirs
- Grouped by class: `class TestFeatureName:` with `def test_specific(self) -> None:`
- Helpers prefixed `_` (e.g. `_make_project(tmp_path, toml)`)
- Tests annotated `-> None`
- Mock config via `SimpleNamespace`; type config params as `Any`

### Key Architectural Rules

- **Config-driven**: all tools read `rebrew-project.toml` — never hardcode paths
- **ADRs**: record decisions (new formats/profiles/backends, contract changes, trade-offs) in `docs/adr/NNN-short-title.md` (Nygard: Status/Context/Decision/Consequences), listed in `docs/adr/README.md`; keep current. Small fixes → `CHANGELOG.md`, not an ADR. Statuses are `Accepted` / `Amended by NNN` / `Superseded by NNN` — a decision still being made is an RFC, not a proposed ADR.
- **Idempotent**: every tool safe to re-run
- **Source discovery**: `iter_sources(directory, cfg)` from `sources.py`; `iter_library_headers(directory)` for `library_*.h`
- **Batch annotations**: `iter_annotations(sources, target=...)` from `cli.py` — wraps `parse_c_file_multi` with silent errors → `[(path, [Annotation])]`
- **Source glob**: `source_glob(cfg)` from `sources.py` — respects `cfg.source_ext` (`.c`, `.cpp`)
- **Don't reimplement**: if an imported library provides it, use it
- **No backward compat**: one name per function — no aliases/shims/wrappers
- **Volatile metadata**: fields `STATUS`, `CFLAGS`, `BLOCKER`, `NOTE`, `GHIDRA` live in per-directory `rebrew-function.toml` via `rebrew.metadata` — never edit manually (STATUS via `update_source_status`/`update_statuses_batch`; BLOCKER via `update_field`/`remove_field` through `rebrew blocker set/clear` or the auto-writers `rebrew diff --fix-blocker`/`near-diag --fix-blocker`/`document-unmatched`)
- **STATUS promotion**: only via `rebrew.metadata` writers — `update_source_status(metadata_dir, new_status, module, va)` (single; `rebrew test`) or `update_statuses_batch(metadata_dir, updates)` (batch; `rebrew verify`) — never write `STATUS` in `.c` files. BLOCKER likewise only via `update_field`/`remove_field` (see above).
- **Compile result**: `compile_and_compare` (`rebrew.compile`) / `verify_entry` (`rebrew.verify`) → `CompareResult`; use `.matched`, `.status`, `.delta`, `.match_percent` — never tuple-unpack.
