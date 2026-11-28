# AGENTS.md: cross_import/

Cross-target function matching, shared-tree promotion, source import, and byte-level preview (`rebrew source import-related`).

## Modules

| Module | Role |
|--------|------|
| `__init__.py` | CLI surface (`app`, `main`, `main_entry`), package re-exports, and wrappers injecting the command-module callables (`compare.similar`, `verify.cli`, `source.split`) the library submodules may not import |
| `matching.py` | Pure structural matching, signature extraction, target byte / disasm / preview helpers |
| `importer.py` | Shared promotion, copy/shared import, anchor rewriting, and verification helpers |

Externals (the only packages this one may import): `binary.analysis`, `c_syntax.parser`, `catalog`, `catalog.loaders`, `cli`, `compare.coff_reloc`, `compare.similar`, `compiler.cache`, `compiler.compile`, `compiler.overrides`, `config`, `formats.binary_loader`, `formats.relocations`, `matcher.scoring`, `metadata.anchors`, `metadata.binding_history`, `metadata.bindings`, `metadata.coordinated`, `metadata.data`, `metadata.functions`, `source.discovery`, `source.layout`, `source.split`, `utils`, `verify.cli`, `workspace.status`.

## Contracts

- Library submodules (`matching.py`, `importer.py`) stay free of CLI `app`/`main_entry` imports and never import `__init__.py`.
