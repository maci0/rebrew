# AGENTS.md — Rebrew

## Overview

**Rebrew** is a compiler-in-the-loop decompilation workbench for binary-matching game reversing. Python package (`src/rebrew/`) with CLI tools to compile, compare, and match C source against target binary functions.

Install editable (`uv pip install -e .`) inside a workspace containing binaries, sources, and toolchains. Contributor/dev install: `make setup` (or `uv sync --frozen --all-extras --group similarity`) — needs sibling `../resembl` at the `RESEMBL_REF` pin (see `Makefile` / CI) and **nasm** on `PATH` for the test suite. `make help` lists targets.

## Compiler Profiles

Names are `"<image-family>-<version>"` (lowercase, version dots kept), e.g. `msvc-6.0`, `gcc-14.2.0`, `mingw-16.2.0`. Append a target suffix only when one family+version spans more than one target (`watcom-2.0-win32` / `watcom-2.0-win16`). See ADR 017; old names are gone, not aliased.

**Docker-only for every shipped toolchain** (`msvc-*`, `borland-*`, `watcom-*`, `delphi-1.0`, `gcc-*`, `clang-*`, `mingw-*`): the image wraps wine / DOSBox / a native Linux compiler. No host wine/wibo/dosbox fallback. Missing image → hard error; run `rebrew toolchain build <name>` or `rebrew toolchain pull <name>`.

Docker build source lives in the sibling **rebrew-toolchains** checkout (`REBREW_TOOLCHAINS_DIR` override). Resolve via `rebrew.toolchain_paths.toolchains_repo()`; commands that need it call `rebrew.toolchain.require_toolchains_repo()`. Details, pins, and smoke gates: `docs/TOOLCHAIN.md`.

| Profile | Image | Notes |
|---------|-------|-------|
| `msvc-6.0` (default) | `rebrew/msvc:6.0-win32` | MSVC flags; C89 |
| `msvc-6.0-sp5-pp` | `rebrew/msvc:6.0-sp5-pp-win32` | Processor Pack (`c2.dll` 13.00.9044); MMX/SSE intrinsics; no `/arch` |
| `mingw-16.2.0` / `mingw-14.2.0` | `rebrew/mingw:*-win32` | PE/x86_32 MinGW; POSIX flags |
| `gcc-14.2.0` / `gcc-12.3.0` | `rebrew/gcc:*-linux-x64` | ELF/x86_64 |
| `clang-18.1.8` / `clang-16.0.4` | `rebrew/clang:*-linux-x64` | ELF/x86_64 |
| `borland-5.5` | `rebrew/borland:5.5-win32` | PE/x86_32 |
| `watcom-2.0-win16` / `watcom-2.0-win32` | `rebrew/watcom:2.0-*` | Watcom |
| `borland-3.1` / `borland-2.0` / `msvc-1.52` / `delphi-1.0` | `rebrew/*:*-win16` | 16-bit (DOSBox); OMF via `rebrew.omf16` where applicable |

**CMake**: `rebrew cmake-toolchain --toolchain msvc-6.0 --output cmake/` then `cmake -B build --toolchain cmake/toolchain-msvc-6.0-docker.cmake`. Bridge scripts: `rebrew-cmake-{cl,link,lib}`.

**Library overrides** (`rebrew-libraries.toml`, `rebrew library set/show/rm`): resolve most-specific-first — per-function `TOOLCHAIN`/`CFLAGS` → nearest `rebrew-libraries.toml` (walk-up) → project default. Presets fill missing fields (e.g. `msvcrt-static` = `/MT /O2 /Gd`).

## Build & Test Commands

```bash
make setup                                # frozen sync + pre-commit; checks uv + ../resembl
make test-one T=tests/test_annotation.py  # single-file edit-test loop
make lint                                 # ruff check src/ tests/ tools/
make format                               # ruff format src/ tests/ tools/
make all                                  # local mirror of CI lint + test gates (+ import cycles)
make check                                # pre-commit hook parity (before a PR: make all && make check)
make gen-fixtures                         # regenerate tests/fixtures/ after editing the generator
# or: uv sync --frozen --all-extras --group similarity

uv run --frozen pytest tests/ -v --tb=short # needs nasm
uv run --frozen pytest tests/test_annotation.py -v # or ::TestClass / -k name
uv run --frozen pre-commit run --all-files
uv run --frozen python -m slipcover --fail-under 80 -m pytest
```

**pytest** (`pyproject.toml`): `testpaths = ["tests"]`, `pythonpath = ["src", "."]` (`.` exposes `tools/`). No `conftest.py` — use `tmp_path` + inline helpers.

## Code Style

- **Python 3.13+**, 4-space indent, 100-char lines (E501 ignored)
- Ruff select/ignore: `[tool.ruff.lint]` in `pyproject.toml` (do not weaken the gate)
- Naming: `snake_case` / `PascalCase` / `UPPER_CASE`; `_private`; `mut_` for GA mutations; **one name per function** (no aliases/shims)
- Types: annotate all signatures; `T | None` not `Optional`; specific generics; config params as `ProjectConfig` (`getattr` defensively); prefer `Any` over bare `object`
- Imports: stdlib → third-party → local (ruff `I`); blank line between groups
- CLI errors: `error_exit(..., json_mode=...)` from `rebrew.cli`; library code raises specific exceptions; no bare `except`
- JSON / VA / exits: `json_print`, `parse_va`, `EXIT_OK`/`EXIT_MISMATCH`/`EXIT_ERROR` from `rebrew.cli`
- Docstrings on every module; section separators `# ---...---`
- Use imported libs' APIs: LIEF for binary formats (never hand-unpack headers), httpx for MCP (never `urllib.request`), Typer + `Console(stderr=True)`, `pathlib.Path`, `TemporaryDirectory`, tree-sitter for C structure (never regex), angr only behind `[prove]`

## Layout

```
src/rebrew/          # package; discover modules there — do not rely on an inline inventory
├── matcher/         # GA engine — see matcher/AGENTS.md (128 mut_* operators)
├── catalog/         # function registry + coverage grid — see catalog/AGENTS.md
├── ghidra/          # BinSync-primary field sync + MCP structural ops
├── binsync/         # declib BinSync state I/O
└── agent-skills/    # packaged skill source of truth (rebrew skills list/show)
tests/               # pytest; typically test_<module>.py
```

Dockerfiles / wrappers / 16-bit media: sibling **rebrew-toolchains** (not vendored here). `rebrew init` renders `agent-skills/` into a project's `.agents/skills/` (`init._copy_agent_skills`); this repo's `.agents/skills/` is a rendered copy (target `bench`). Edit `src/rebrew/agent-skills/`, re-render; `tests/test_skills_sync.py` and `tools/validate_skill_commands.py` gate drift.

## CLI Conventions

Single-command tools: `@app.callback(invoke_without_command=True)` + `main_entry()` in `[project.scripts]`; `TargetOption` + `require_config()` from `rebrew.cli` (use `load_config()` only for optional loads). Param order: `--json` before `--target`, both last. Help strings exact: `--json` → `"Output results as JSON"`; `--dry-run` → `"Preview changes without writing"`. Output via `Console(stderr=True)`; raw `print()` only for piped data. `main_entry` docstring always `"""Run the Typer CLI application."""`. JSON errors: `error_exit(..., json_mode=json_output)`.

Multi-command (`is_group=True` in `builtins.py`): `blocker`, `orphans`, `types`, `extract`, `cfg`, `cache`, `skills`, `resource`, `library`, `toolchain`, `binsync`.

## Adding a GA Mutation

Operators live under `src/rebrew/matcher/mutations/` (`mut_*`, tree-sitter only — never regex). Register in the packaged list assembled by `mutator.py` → `ALL_MUTATIONS`. Test in `tests/test_mutator_p*.py`. Document in `docs/GA_MUTATIONS.md`. Entry-point group `rebrew.mutations` can add operators without editing host source; duplicate name → skipped with warning (packaged ops kept).

Numeric constants need explicit operators (`mut_tweak_integer_literal` covers small ±deltas).

## Test Patterns

No `conftest.py`. Group by class; helpers `_`-prefixed; annotate tests `-> None`; mock config with `SimpleNamespace`; type config params as `Any`.

## Key Architectural Rules

- **Config-driven**: read `rebrew-project.toml` — never hardcode paths
- **ADRs**: settled decisions in `docs/adr/NNN-short-title.md` (Nygard; listed in `docs/adr/README.md`). Statuses: `Accepted` / `Amended by NNN` / `Superseded by NNN`. An unmade decision is an **RFC**, not a “proposed ADR”. Small fixes → `CHANGELOG.md`
- **Idempotent**: every tool safe to re-run
- **Source discovery**: `iter_sources` / `iter_library_headers` / `source_glob` from `sources.py`; batch annotations via `iter_annotations` in `cli.py`
- **Don't reimplement**: if an imported library provides it, use it
- **Declarative registration**: toolchains, decompiler backends, CLI commands, mutations, flag sets, library presets, detectors, loaders, MSVC version tables, cache backends, discoverers via `rebrew.registry` entry-point groups (+ `REBREW_TOOLCHAIN_OVERLAY_DIR` / `REBREW_SKILLS_DIR`). Conflict policy: toolchains → `RegistryError` on duplicate; tuning groups (`flag_sets`, `library_presets`, `msvc_versions`) extend/override; other plugin groups skip broken/duplicate with a warning. `refresh_all()` for long-lived processes. Adding a component must not require editing host source
- **CLI composition**: umbrella app is a component graph (`plugin.py` + `builtins.py`); see ADR 014
- **No backward compat**: one name per function — no aliases/shims/wrappers
- **Volatile metadata**: `STATUS`, `SIZE`, `CFLAGS`, `BLOCKER`, `BLOCKER_DELTA`, `NOTE`, `GHIDRA`, `LOCALS`, `COMMENTS` live only in `rebrew-functions.toml` via `rebrew.metadata` — never hand-edit. STATUS via `update_source_status` / `update_statuses_batch`; BLOCKER via `update_field` / `remove_field` (`rebrew blocker` or auto-writers). Written **mode 0444** (`atomic_write_locked`); same lock for `rebrew-data.toml` and declib binsync artifacts
- **STATUS is earned**: `rebrew verify` promotes/demotes from byte comparison; never write `STATUS` in `.c` files. Stale hand-claimed `PROVEN` is demoted with a `metadata: warning`
- **Compile result**: `CompareResult` — use `.matched`, `.status`, `.delta`, `.match_percent`; never tuple-unpack
- **Compile backends**: local docker image by default; `[compiler] recompile_url` / `REBREW_RECOMPILE_URL` → `rebrew.recompile_client`. Cache id pins the backend. Only a plugin toolchain without `image` runs as a host binary. See ADR 015
