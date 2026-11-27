# AGENTS.md: toolchain_cli/

Host-side CLI (`rebrew toolchain`) and helpers for toolchain discovery, vendoring, Docker builds, smoke verification, and upstream pin checks.

## Modules

| Module | Role |
|--------|------|
| `__init__.py` | `rebrew toolchain` Typer `app`, commands, `main_entry()`, and `external_ranges()` |
| `vendor.py` | Pinned download host/URL validation, safe tar extraction, wrapper flattening, and vendor-tree probing |
| `smoke.py` | `SMOKE_GOLDEN` table, target inspection, container smoke execution, masked SHA-256 hashing, and `docker_build()` |
| `updates.py` | Codeload URL pattern matching, `STATUS_*` constants, GitHub auth headers, and `live_commit_sha()` |

Externals (the only packages this one may import): `cli`, `compiler.temp_dirs`, `compiler.toolchain`, `compiler.toolchain_data`, `config`, `formats.coff`, `toolchain_detect`, `utils`, `wibo`. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- Typer `app` and `main_entry()` live only in `__init__.py`; `vendor.py`, `smoke.py`, and `updates.py` remain non-CLI helper modules and never import `__init__.py`.
- Cross-module helpers are public in `vendor.py`, `smoke.py`, and `updates.py`; `__init__.py` binds local `_`-aliases only for test/caller compatibility.
