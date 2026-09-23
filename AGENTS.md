# AGENTS.md: Rebrew

## Overview

**Rebrew** is a compiler-in-the-loop decompilation workbench for binary-matching game reversing. Python package (`src/rebrew/`) with CLI tools to compile, compare, and match C source against target binary functions.

Install editable (`uv pip install -e .`) inside a workspace containing binaries, sources, and toolchains. Contributor install: `make setup`; needs sibling `../resembl` at the `Makefile` `RESEMBL_REF` pin and **nasm** on `PATH` for the test suite. `make help` lists targets.

## Compiler Profiles

Names are `"<image-family>-<version>"` (lowercase, version dots kept), e.g. `msvc-6.0`, `gcc-14.2.0`, `mingw-16.2.0`. Append a target suffix only when one family+version spans more than one target (`watcom-2.0-win32` / `watcom-2.0-win16`). See ADR 017; old names are gone, not aliased. Default profile: `msvc-6.0`.

**Docker-only for every shipped toolchain** (`msvc-*`, `borland-*`, `watcom-*`, `delphi-1.0`, `ido-*`, `gcc-*`, `clang-*`, `mingw-*`): the image wraps wine / DOSBox / a native Linux compiler. No host wine/wibo/dosbox fallback. Missing image → hard error; run `rebrew toolchain build <name>` or `rebrew toolchain pull <name>`. Inventory and image tags: `rebrew toolchain list` (pins/smoke: `docs/TOOLCHAIN.md`).

Docker build source lives in the sibling **rebrew-toolchains** checkout (`REBREW_TOOLCHAINS_DIR` override). Resolve via `rebrew.toolchain_paths.toolchains_repo()`; commands that need it call `rebrew.toolchain.require_toolchains_repo()`.

**CMake**: `rebrew cmake-toolchain --toolchain msvc-6.0 --output cmake/` then `cmake -B build --toolchain cmake/toolchain-msvc-6.0-docker.cmake`. Bridge scripts: `rebrew-cmake-{cl,link,lib}`.

**Library overrides** (`rebrew-libraries.toml`, `rebrew library set/show/rm`): resolve most-specific-first (per-function `TOOLCHAIN`/`CFLAGS` → nearest `rebrew-libraries.toml` (walk-up) → project default). Presets fill missing fields (e.g. `msvcrt-static` = `/O2 /Gd /MT`).

## Build & Test Commands

```bash
make test-one T=tests/test_annotation.py  # edit-test loop; T takes a node id (::TestClass)
make test                                 # full suite (needs nasm)
make lint / make format / make mypy
make gen-fixtures                         # regenerate tests/fixtures/ after editing the generator
make all && make check && make build      # before a PR: CI gates + pre-commit + reproducible build
uv run --frozen python -m slipcover --fail-under 80 -m pytest  # coverage floor; ratchet up, never down
```

Bare `uv run pytest` matches `make test` (`pyproject.toml` pytest config loads `tests/pytest_ansi_env.py`; `.` on `pythonpath` exposes `tools/`).

## Code Style

- **Python 3.13+**; ruff/mypy gates in `pyproject.toml`; do not weaken them
- Types: `T | None` not `Optional`; config as `ProjectConfig` (`getattr` defensively); prefer `Any` over bare `object`
- CLI: `error_exit(..., json_mode=...)`, `json_print`, `parse_va`, `EXIT_*` from `rebrew.cli`; `Console(stderr=True)`; library code raises specific exceptions; no bare `except`
- Docstrings on every module; section separators `# ---...---`
- Use imported libs' APIs: LIEF (never hand-unpack headers), httpx for MCP (never `urllib.request`), tree-sitter for C AST (no new regex C parsers; legacy mutation regex stays), angr only behind `[prove]`

## Layout

```
src/rebrew/          # package; discover modules there; do not rely on an inline inventory
├── matcher/         # GA engine: src/rebrew/matcher/AGENTS.md
├── catalog/         # function registry + coverage grid: src/rebrew/catalog/AGENTS.md
├── ghidra/          # BinSync-primary field sync + MCP structural ops
├── binsync/         # declib BinSync state I/O
└── agent-skills/    # packaged skill source of truth (rebrew skills list/show)
tests/               # pytest; typically test_<module>.py
```

Dockerfiles / wrappers / 16-bit media: sibling **rebrew-toolchains** (not vendored here). `rebrew init` renders `agent-skills/` into a project's `.agents/skills/`; this repo's `.agents/skills/` is a rendered copy (target `bench`). Edit `src/rebrew/agent-skills/`, re-render; `tests/test_skills_sync.py` and `tools/validate_skill_commands.py` gate drift.

## CLI Conventions

Single-command tools: `@app.callback(invoke_without_command=True)` + `main_entry()` in `[project.scripts]`; `TargetOption` + `require_config()` from `rebrew.cli` (use `rebrew.config.load_config` only for optional loads; not re-exported from `cli`). Param order: `--json` before `--target`, both last. Help strings exact: `--json` → `"Output results as JSON"`; `--dry-run` → `"Preview changes without writing"`. Output via `Console(stderr=True)`; raw `print()` only for piped data. `main_entry` docstring always `"""Run the Typer CLI application."""`; its body is `run_standalone(main)` (single-command) or `run_cli(app)` (group), never a bare `app()` (that loses the 141/130/2 exit contract). JSON errors: `error_exit(..., json_mode=json_output)`.

Multi-command groups: `is_group=True` in `builtins.py`.

## Adding a GA Mutation

Name it `mut_*`; see `src/rebrew/matcher/AGENTS.md` and `docs/GA_MUTATIONS.md`. Test in `tests/test_mutator_p*.py`. Numeric constants need explicit ops (`mut_tweak_integer_literal` covers small ±deltas).

## Test Patterns

No `conftest.py`: use `tmp_path` + inline helpers. Group by class; helpers `_`-prefixed; annotate tests `-> None`; mock config with `SimpleNamespace`; type config params as `Any`.

## Key Architectural Rules

- **Config-driven**: read `rebrew-project.toml`; never hardcode paths
- **ADRs**: settled decisions in `docs/adr/NNN-short-title.md` (Nygard; listed in `docs/adr/README.md`). Statuses: `Accepted` / `Amended by NNN` / `Superseded by NNN`. An unmade decision is an **RFC**, not a “proposed ADR”. Small fixes → `CHANGELOG.md`
- **Idempotent**: every tool safe to re-run
- **Source discovery**: `iter_sources` / `iter_library_headers` / `source_glob` from `sources.py`; batch annotations via `iter_annotations` in `annotation.py`
- **Declarative registration**: toolchains, decompiler backends, CLI commands, mutations, flag sets, library presets, detectors, loaders, MSVC version tables, cache backends, discoverers via `rebrew.registry` entry-point groups (+ `REBREW_TOOLCHAIN_OVERLAY_DIR` / `REBREW_SKILLS_DIR`). Conflict policy: toolchains → `RegistryError` on duplicate; CLI plugin name clashes → warn+skip; tuning groups (`flag_sets`, `library_presets`, `msvc_versions`) extend/override; other optional groups skip broken/duplicate with a warning. `refresh_all()` for long-lived processes. Adding a component must not require editing host source
- **CLI composition**: umbrella app is a component graph (`plugin.py` + `builtins.py`); see ADR 014
- **No backward compat**: one name per function, no aliases/shims/wrappers
- **Volatile metadata** (`METADATA_FIELDS` in `rebrew.metadata`): live in `rebrew-functions.toml`; never hand-edit the TOML. Most fields are metadata-only (`STATUS`, `TOOLCHAIN`, `BLOCKER`, …); `SIZE`/`CFLAGS` are co-read (`.c` + TOML override). STATUS via `update_source_status` / `update_statuses_batch`; BLOCKER via `update_field` / `remove_field` (`rebrew blocker` or auto-writers). Written **mode 0444** (`atomic_write_locked`); same lock for `rebrew-data.toml` and declib binsync artifacts
- **STATUS is earned**: `rebrew test` / `rebrew verify` promote/demote from byte comparison; never write `STATUS` in `.c` files. Stale hand-claimed `PROVEN` is demoted with a `metadata: warning`
- **Compile result**: `CompareResult`; use `.matched`, `.status`, `.delta`, `.match_percent`; never tuple-unpack
- **Compile backends**: local docker image by default; `[compiler] recompile_url` / `REBREW_RECOMPILE_URL` → `rebrew.recompile_client`. Cache id pins the backend. Only a plugin toolchain without `image` runs as a host binary. See ADR 015
