# AGENTS.md: doctor/

Diagnostic project-health checks and `rebrew doctor` CLI.

## Modules

| Module | Role |
|--------|------|
| `__init__.py` | `rebrew doctor` Typer CLI (`app`, `main`, `main_entry()`), public re-exports, and compatibility `_`-aliases |
| `checks.py` | `CheckResult`, `DoctorReport`, `LibIndexUnavailable`, and core project/config/binary/toolchain/cache/runner/source/metadata/external-lib/backup checks |
| `integrations.py` | Optional tools, decompiler, FLIRT, Ghidra, BinSync, CRT, and optimization-level checks, plus `run_doctor` and `render_doctor` |

Externals (the only packages this one may import): `binsync.git`, `binsync.serial`, `catalog`, `cli`, `compiler.cache`, `compiler.compile`, `compiler.toolchain`, `config`, `decompiler`, `errors`, `formats.binary_loader`, `ghidra`, `library.flirt`, `library.match`, `matching.prove`, `metadata.bindings`, `metadata.sqlite`, `metadata.storage`, `source.discovery`, `toolchain_cli`, `toolchain_detect`, `utils`, `wibo`.

## Contracts

- Helper submodules (`checks.py`, `integrations.py`) stay library-only: no `app = typer.Typer`, no `main_entry()`, and never import `__init__.py`.
- Cross-module imports never target `_`-prefixed names; `__init__.py` binds local `_`-aliases to public submodule symbols for test compatibility.
