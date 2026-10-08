# AGENTS.md: binsync/

declib BinSync state I/O: the artifact layer a `rebrew binsync` push/pull moves through.

## Modules

| Module | Role |
|--------|------|
| `state.py` | Shared readers, native field schema, reconciliation baseline, and provenance/freshness facts used by push/pull/diff |
| `serial.py` | declib wrapper for the artifact dump/load layer |
| `export.py` | rebrew annotations → BinSync state dir (`rebrew binsync export`) |
| `importer.py` | BinSync state dir → rebrew metadata (`rebrew binsync import`) |
| `diff.py` | Read-only divergence report between rebrew and a state dir (`rebrew binsync diff`) |
| `overlay.py` | Map a related target's BinSync names across VAs onto matched functions (`rebrew binsync overlay`) |
| `init.py` | Create the git envelope a state dir needs (`rebrew binsync init`) |
| `repo.py` | The BinSync repo behind a state dir: the validated rebrew user, checkout of its own branch, other users' branches as detached snapshots |
| `git.py` | Sandboxed git invocations against that envelope |
| `cli.py` | `rebrew binsync` umbrella: `push` / `pull` / `summary` (defined here) plus `init` / `diff` / `overlay` mounted as subcommands |

Externals (the only top-level packages this one may import): `annotation`, `binary_loader`, `catalog`, `cli`, `config`, `c_parser`, `cross_import`, `data_metadata`, `data_scan`, `metadata`, `naming`, `rename_ops`, `sources`, `struct_parser`, `types`, `utils`, `verify_hash`. `declib` is imported only here, behind the `[binsync]` extra.

## Contracts

- **The package exports no public names.** `__init__` is a module docstring plus an empty `__all__`; import submodules by name (`rebrew.binsync.export`, …).
- **`cli.py` orchestrates, it does not re-implement.** `push` / `pull` / `summary` call `export.export_state` / `importer.import_state` / `importer.resolve_state_dir`, the same functions the flat `rebrew binsync export` / `-import` commands call; `init` / `diff` / `overlay` are mounted as subcommands, while `export` / `importer` keep their own flat commands because their option sets differ. A change to export/import/diff behavior lands in its own module, never in the umbrella.
- **State readers are shared, not re-derived.** `importer.py` and `diff.py` read through `state.py`; a new reader extends `state.py` instead of opening the dir a second way. The same rule covers the `dict[str, object]` an `export_state` / `import_state` call returns: `export.py` and `importer.py` narrow it through `result_count` / `result_rows` / `result_paths`, never a `cast`.
- **One user, its own branch.** `repo.resolve_user` is the only source of the user rebrew writes as (`metadata.toml` `user` and branch `binsync/<user>` are the same validated name). A real export into a BinSync repo first calls `repo.checkout_user_branch`; nothing writes another user's branch. Pull reads other users' branches through `repo.peer_snapshot` and `importer.import_from_repo`, each against its own baseline seeded by `state.seed_peer_baseline`.
- **Renames go through `rename_ops`.** Pulled function, global and struct member renames plan and apply through `rebrew.rename_ops`; a refused plan is a `skipped_details` row with its reason, never a partial write.
- **State files stay writable.** `serial.write_state_text` writes 0644: BinSync's `State.dump` rewrites the same files.
- **Git runs through `git.py` only.** Every invocation goes through `run_git`, which passes an argv list from `git_argv` (no shell), neutralizes the repo-local settings that execute a program (`core.fsmonitor`, `core.hooksPath`, `core.sshCommand`, `gpg.program`, `protocol.ext.allow`), and kills the whole process group on timeout so an `ssh` transport does not outlive the call. A new git call bypasses that helper only if it can name why. `run_git`'s default `timeout` (`_GIT_TIMEOUT`) is sized for a local probe; an invocation that contacts a remote (`push`, `pull`, `fetch`) passes `GIT_NETWORK_TIMEOUT`.

- **One field schema, one reconciliation policy.** `SYNC_FIELD_RULES` defines
  native field direction/ownership. `state.py` owns baseline and freshness
  helpers; callers reuse them. The baseline advances only equal fields after
  successful writes, never previews or failed applications. Remote removals
  require explicit resolution; push must not silently resurrect them.
- **Canonical source and provenance.** Prototype imports update the C signature
  through `c_parser`; type edits use `struct_parser`. No PROTOTYPE comments.
  Accepted function/global fields store origins through the metadata APIs;
  comparison evidence stays private. Batch related fields into one store write.
  Atomicity is per file, not a multi-file transaction. The user contract lives
  in [BINSYNC_INTEGRATION.md](../../../docs/BINSYNC_INTEGRATION.md).
