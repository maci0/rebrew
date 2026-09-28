# AGENTS.md: binsync/

declib BinSync state I/O: the artifact layer a `rebrew binsync` push/pull moves through.

## Modules

| Module | Role |
|--------|------|
| `state.py` | Shared readers/indexes over a state dir (`importer` and `diff` both build on these) |
| `serial.py` | declib wrapper for the artifact dump/load layer |
| `export.py` | rebrew annotations → BinSync state dir (`rebrew binsync-export`) |
| `importer.py` | BinSync state dir → rebrew metadata (`rebrew binsync-import`) |
| `diff.py` | Read-only divergence report between rebrew and a state dir (`rebrew binsync-diff`) |
| `overlay.py` | Map a related target's BinSync names across VAs onto matched functions (`rebrew binsync-overlay`) |
| `init.py` | Create the git envelope a state dir needs (`rebrew binsync-init`) |
| `git.py` | Sandboxed git invocations against that envelope |
| `cli.py` | `rebrew binsync` umbrella: `push` / `pull` / `summary` (defined here) plus `init` / `diff` / `overlay` mounted as subcommands |

Externals (the only top-level packages this one may import): `annotation`, `binary_loader`, `catalog`, `cli`, `config`, `c_parser`, `cross_import`, `data_metadata`, `data_scan`, `metadata`, `naming`, `rename_ops`, `sources`, `struct_parser`, `types`, `utils`. `declib` is imported only here, behind the `[binsync]` extra.

## Contracts

- **The package exports no public names.** `__init__` is a module docstring plus an empty `__all__`; import submodules by name (`rebrew.binsync.export`, …).
- **`cli.py` orchestrates, it does not re-implement.** `push` / `pull` / `summary` call `export.export_state` / `importer.import_state` / `importer.resolve_state_dir`, the same functions the flat `rebrew binsync-export` / `-import` commands call; `init` / `diff` / `overlay` are mounted as subcommands, while `export` / `importer` keep their own flat commands because their option sets differ. A change to export/import/diff behavior lands in its own module, never in the umbrella.
- **State readers are shared, not re-derived.** `importer.py` and `diff.py` read through `state.py`; a new reader extends `state.py` instead of opening the dir a second way. The same rule covers the `dict[str, object]` an `export_state` / `import_state` call returns: `export.py` and `importer.py` narrow it through `result_count` / `result_rows` / `result_paths`, never a `cast`.
- **Git runs through `git.py` only.** Every invocation goes through `run_git`, which passes an argv list from `git_argv` (no shell), neutralizes the repo-local settings that execute a program (`core.fsmonitor`, `core.hooksPath`, `core.sshCommand`, `gpg.program`, `protocol.ext.allow`), and kills the whole process group on timeout so an `ssh` transport does not outlive the call. A new git call bypasses that helper only if it can name why. `run_git`'s default `timeout` (`_GIT_TIMEOUT`) is sized for a local probe; an invocation that contacts a remote (`push`, `pull`, `fetch`) passes `GIT_NETWORK_TIMEOUT`.
