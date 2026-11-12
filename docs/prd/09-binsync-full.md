# PRD 09: Full BinSync Integration

- **Status**: Partial (umbrella + declib I/O shipped; divergent git merge remains open)
- **Date**: 2026-05 (updated 2026-09)
- **Owner**: rebrew team

> `rebrew sync push` / `pull --state-dir D` share the same declib state I/O
> and conflict rules. `rebrew binsync` adds Git-backed collaboration. BinSync
> repos fetch and reconcile peer branches individually; plain state repos use
> `git pull --ff-only`. Divergent Git-history merging remains out of scope.

**Feature name:** Bidirectional BinSync ↔ Rebrew Sync (git-backed state, declib format)
**One-line value:** Turn rebrew into a first-class BinSync peer so reverse-engineering knowledge round-trips losslessly between IDA Pro, Binary Ninja, Ghidra, and rebrew's C source; collaborators on different decompilers share names, types, comments, and stack vars without conversion friction.

## Problem It Solves

Rebrew exchanges native names, sizes, prototypes, globals with C types,
struct layouts, enums, typedefs, stack variables, and per-instruction comments
through declib (`rebrew[binsync]`, `declib>=4.5.0,<5`). Struct members use
byte-offset keys in `structs/<name>.toml`; incomplete or ambiguous layouts
are omitted, preserving existing remote artifacts. No placeholder is emitted
for a `struct` metadata name without a scanned definition.

`rebrew binsync export` / `import` exchange raw state; `diff` reports
divergence read-only (exit 1). The `push` / `pull` / `summary` / `init` /
`overlay` operations add collaboration and related-target transfer. Divergent
upstream Git-history merging remains the open requirement. See
[BINSYNC_INTEGRATION.md](../BINSYNC_INTEGRATION.md) for reconciliation,
provenance and per-file atomicity.

## Users

- **Solo reverser** who wants to share annotations with a team member working in IDA Pro without manual conversion.
- **Team** collaborating on a binary where one person prefers source-level work (rebrew) and others use decompiler GUIs: git-backed BinSync state is the canonical merge point.
- **AI agent** running CI-style sync between rebrew's annotations and a published BinSync repo.
- **Switchers**: someone starting a project in IDA + BinSync who wants to migrate to rebrew without losing names/types/comments.

## Goals

- One umbrella command (`rebrew binsync`) with explicit `push`, `pull`,
  `summary`, `init` subcommands. Mirrors `rebrew sync push`'s shape for
  muscle-memory. (Shipped; umbrella plus flat commands coexist; `diff`
  and `overlay` also ship under the umbrella.)
- True bidirectional sync via git: `rebrew binsync pull` fetches peer branches before reading (plain repos use `git pull --ff-only`); `push` does `git commit` + optional `git push` after writing. (Shipped: export/`push` commit, peer-branch fetch/import (plain repos: `git pull --ff-only`) unless `--no-git`, `push --git-push`. Open: divergent upstream merge as the primary path.)
- Real declib-compatible struct fields, enums, typedefs. (Shipped via declib artifacts.)
- Annotation surface for stack vars / local vars (see "Annotation Surface" below). (Shipped: `LOCALS` metadata ↔ `Function.stack_vars`.)
- Conflict detection on pull: when both rebrew and BinSync have meaningful (non-generic) names for the same VA, report and let the user pick via `--accept-binsync` / `--accept-local` (same pattern as `rebrew sync push`). (Shipped on umbrella `pull` and flat `binsync import`.)
- Per-instruction comments, both directions. (Shipped: dedicated `comments` metadata ↔ BinSync Comment artifacts.)
- Declib as an optional dependency (under `[project.optional-dependencies].binsync`, `declib>=4.5.0,<5`) so users who don't need this feature aren't forced to install it. (Shipped; this PRD originally named the layer `libbs`.)

## Non-Goals

- **Patch tracking**: BinSync supports binary patches. Rebrew has no patch concept and adding one is a different feature; skip in v1.
- **Custom GUI**: rebrew is CLI-first; no graphical conflict resolver. Conflicts surface as JSON / Rich tables and accept-flags.
- **Real-time collaboration** (live cursor / presence). BinSync's git substrate gives push/pull semantics, not realtime, and that's enough.
- **Replacing `rebrew sync push`**: `rebrew sync push` is now BinSync-primary for field sync (sharing the BinSync state directory format, with ReVa MCP for structural ops); `rebrew binsync` is the cross-decompiler portability umbrella.

## Functional Requirements

**Status (2026-09):** the `rebrew binsync` umbrella ships (`push` / `pull` /
`summary` / `init` / `diff` / `overlay`) alongside the flat
`binsync export` / `binsync import` / `binsync diff` / `binsync init` /
`binsync overlay` commands.  Conflict accept-flags
(`--accept-binsync` / `--accept-local`) ship on pull/import.  Declib
serialization ships (`rebrew[binsync]`), including structs with fields,
enums, typedefs, `LOCALS`, and per-instruction `COMMENTS`.  Still open:
divergent git merge as the default sync substrate (export/`push` local
commit, peer-branch fetch/import (plain repos: `git pull --ff-only`) unless `--no-git`, and `push --git-push`
are the git steps today).

### F1: `rebrew binsync` umbrella

Shipped subcommands:

```bash
rebrew binsync push <state-dir>      # write local annotations into BinSync state + git commit
rebrew binsync pull <state-dir>      # fetch peer branches + apply BinSync state
rebrew binsync summary <state-dir>   # preview what would push / pull (read-only)
rebrew binsync init <state-dir>      # initialise a fresh BinSync state directory
rebrew binsync diff <state-dir>      # per-VA diff: where do rebrew + BinSync disagree?
rebrew binsync overlay ...           # overlay a related target's BinSync data
```

Flat commands remain as peers (not only aliases): `binsync export`,
`binsync import`, `binsync diff`, `binsync init`, `binsync overlay`.

Shared flags: `--target`, `--json`; `--module FILTER` on every subcommand except `init`; `--dry-run` on the writing subcommands (`push`, `pull`, `init`, `overlay`; `summary` and `diff` are read-only).

### F2: `push` writes via declib

All artifact writing goes through declib serializers (struct field, enum,
typedef, function header, stack frame). Artifact TOML is not serialized by hand.
Rebrew's `[rebrew:note]` synthetic comment stays: it is orthogonal, and
BinSync clients ignore it (the write-only `[rebrew] STATUS=… CFLAGS=…`
comment was removed; see `rebrew/binsync/export.py`). *(This PRD originally
named the layer `libbs`; the shipped dependency is `declib>=4.5.0,<5`.)*

`push` adds an auto-commit step after writing: `git -C <state-dir> add -A && git commit -m "rebrew binsync export: <target> @ <utc>"` (the message the shipped `binsync export --git` already writes). With `--git-push`, also `git push`. With `--no-git`, skip git entirely. `--no-git` is an umbrella `push` / `pull` flag only: the flat `binsync export` has the opposite default, no commit unless you pass its opt-in `--git`.

### F3: `pull` reads via declib, applies to rebrew metadata

For each function in the BinSync state:

- **Name** → if generic per `rebrew.binsync.importer.is_meaningful` (`func_<hex>`, `FUN_`, `DAT_`, `switchdata`, `thunk_`, `g_<hex>`), skip. If meaningful and rebrew already has a meaningful different name, report CONFLICT. Else update the managed function identity and C declaration through the rename owner, including bound cross-references. Optional ADDRESS anchors retain the same module/VA.
- **Prototype** → update the C function declaration via the prototype-rewrite path in `rebrew.binsync.importer` (the `--pull-signatures` flag it replaced is removed).
- **Stack frame / locals** → write to a new `[locals]` block in `rebrew-functions.toml`. See F4.
- **Per-instruction comments** → store native-address-keyed comment fields in dedicated function metadata. No ANALYSIS state is written into C source.
- **Struct / enum / typedef** → write unknown type definitions into `binsync_types.h` in `reversed_dir` (see F5).
- **Global variable** → write `name`/`size`/`type` into `rebrew-data.toml` (canonical data metadata file).

`pull` fetches `binsync/*` from `--remote` (default `origin`) and imports
every peer against its own baseline without changing the state working tree.
A plain state repo uses `git pull --ff-only` instead. `--no-git` skips network
steps; dry runs also skip them. Git failures abort with the state directory
and failure reason.

### F4: Annotation surface: locals + stack vars

Shipped: `[locals]` in `rebrew-functions.toml` (offset-keyed
`{name, type, size}`), round-tripped via declib `Function.stack_vars`:

```toml
["SERVER.0x10008880"]
status = "EXACT"
[SERVER.0x10008880.locals]
"-4" = { name = "ret_val",   type = "int" }
"-8" = { name = "tmp",       type = "char *" }
"8"  = { name = "arg_count", type = "size_t" }
```

Keys are the stringified stack offsets from BinSync's `Function.stack_vars`
(`"-4"`, `"8"`), not register-relative names.

Informational at v1: rebrew doesn't lint local-var names against the C
source or use them for matching. Optional future: validate against
tree-sitter-extracted locals (W020+).

### F5: Annotation surface: enums + typedefs

Shipped: tree-sitter extraction of `enum` / standalone `typedef` from
headers and sources; `binsync push`/`export` emit `enums.toml` /
`typedefs.toml` via declib; pull/import write unknown definitions into
`binsync_types.h`. Remote-only changes to one unambiguous existing definition
apply; concurrent changes conflict. Related-target overlays preserve known names.

### F6: Conflict resolution

Pull surfaces conflicts in the same shape as `rebrew sync pull`:

```
  CONFLICT 0x10008880: local='BitReverse' vs binsync='ReverseBits'
```

Resolution flags:

- `--accept-binsync`: accept all BinSync values; rewrite local files + metadata.
- `--accept-local`: keep local fields; retain alternate function names as
  GHIDRA metadata. No source rewrite.
- Interactive resolution (per-conflict prompt) is deferred to v2.

### F7: Offline fallback

`binsync pull --no-git` reads the state directory as-is without pulling. Useful in CI where the state-dir is a checked-out artifact, or for users with credentials issues.

### F8: `declib` dependency

Shipped in `pyproject.toml`:

```toml
[project.optional-dependencies]
binsync = ["declib>=4.5.0,<5"]
```

Every BinSync state command (flat and umbrella) goes through
`rebrew.binsync.serial`; missing declib raises an explicit
"install rebrew[binsync]" error. *(This PRD originally named the layer
`libbs>=2.0`.)*

## CLI Surface

Shipped today (flat commands):

```bash
rebrew binsync export <outdir>                   # write BinSync state dir (functions/, global_vars.toml, structs/)
rebrew binsync export <outdir> --git             # also stage + git commit the state dir
rebrew binsync export <outdir> --clean           # drop orphan function TOMLs
rebrew binsync export <outdir> --module SERVER   # one module only
rebrew binsync import <state-dir>                # apply names/prototypes/globals back to rebrew
rebrew binsync import <state-dir> --accept-binsync   # accept BinSync on all conflicts
rebrew binsync import <state-dir> --accept-local     # keep local, record provenance
rebrew binsync import <state-dir> --module SERVER    # one module only
rebrew binsync import <state-dir> --create-missing   # STUB files for BinSync functions with no local annotation
rebrew binsync diff <state-dir>                  # read-only divergence report (exit 1 on divergence)
```

Common flags on all three: `--target NAME`, `--json`; `--dry-run` on
export/import (`binsync diff` is read-only and needs no dry-run).

Shipped (umbrella; flat commands above remain peers):

```bash
rebrew binsync init <state-dir>                  # git init + skeleton
rebrew binsync summary <state-dir>               # dry-run preview
rebrew binsync push <state-dir>                  # write + git commit
rebrew binsync push <state-dir> --git-push       # write + commit + push
rebrew binsync push <state-dir> --no-git         # write only (no commit; flat binsync export never commits without --git)
rebrew binsync pull <state-dir>                  # fetch peers + apply
rebrew binsync pull <state-dir> --accept-binsync # accept all conflicts
rebrew binsync pull <state-dir> --accept-local   # keep local on all conflicts
rebrew binsync pull <state-dir> --no-git         # skip Git network steps
rebrew binsync pull <state-dir> --module MSVCRT  # restrict to one module
rebrew binsync diff <state-dir>                  # show divergences without writing
rebrew binsync overlay <state-dir>               # overlay a related target's BinSync data
```

Common flags across all: `--target NAME`, `--json`; `--dry-run` everywhere except the read-only `summary` and `diff`.
The existing `binsync export` stays a peer of the umbrella: `binsync push --no-git` is the write-only path, and `binsync export` itself never commits unless given `--git`. Every `state-dir` is a local directory; no command accepts a remote URL in place of that directory (see Story 2).

## User Stories

### Story 1: Solo reverser switches between rebrew + IDA Pro

A reverser uses rebrew as their primary workspace. Once a function is `EXACT`, they want to inspect it in IDA Pro with proper names.

```bash
rebrew binsync push ./binsync_state              # export + commit
# (in IDA Pro: load binsync_state directory via the BinSync plugin)
# (analyst adds local variable name "loop_counter" in IDA)
rebrew binsync pull ./binsync_state              # pulls "loop_counter" into rebrew-functions.toml [locals] block
```

### Story 2: Team collaboration via shared git repo

Two reversers share a binary. One uses rebrew, one uses Binary Ninja. They share a `binsync-state` git repo with push access for both.

```bash
# Reverser A (rebrew), after cloning the team repo:
rebrew binsync pull ./binsync-state               # fetch peer branches + apply
# ... reverses some functions in rebrew ...
rebrew binsync push ./binsync-state --git-push    # commit and push to origin

# Reverser B (Binary Ninja):
# (BinSync plugin pulls + pushes the same git repo)
```

Every `state-dir` above is a local checkout. No BinSync command accepts a remote URL as its state-directory argument: `pull` / `diff` / `import` abort with "State directory
not found" when the path is not an existing directory, and `push` would create
a local directory with that name. Clone the team repo yourself (or share a
checked-out artifact); `--git-push` pushes the branches of the local clone it
is given. Merging divergent upstream history is the open item listed in
"Known Limitations / Open Questions" below.

### Story 3: Migrating an IDA project to rebrew

Someone with an IDA Pro + BinSync project decides to migrate to rebrew.

```bash
rebrew init --target legacy --binary original/legacy.dll --toolchain msvc-6.0
rebrew binsync init ./binsync_state                   # initialises a state dir if migrating from scratch
# OR if they already have one from IDA:
rebrew binsync pull /path/to/ida_binsync_state        # imports names, types, locals, comments
rebrew status                                          # rebrew now knows what IDA knew
```

### Story 4: CI conflict detector

A nightly CI run cross-checks local rebrew state against the shared BinSync repo.

```bash
rebrew binsync diff ./binsync-state --json > diff.json
# CI parses diff.json; fails if any CONFLICT entries exist; opens a ticket.
```

## Success Metrics

- A function reversed in rebrew, pushed to BinSync, pulled into IDA Pro, then re-renamed in IDA Pro, pushed back from IDA Pro, pulled into rebrew: round-trips losslessly. Same for stack vars, structs, enums.
- A 100-function project with all four artifact types (names, prototypes, locals, structs) pushes in <5s on a warm git tree; pulls in <5s after a `git pull` no-op.
- Conflict report on pull lists every divergent VA + field with one-line provenance. JSON parseable.
- Declib-format outputs validate via declib's own loaders (a
  BinSync/IDA/Ghidra/Binary Ninja state dir rebrew wrote must parse, and
  rebrew must parse theirs).

## Known Limitations / Open Questions

- **Patch tracking is out of scope.** If rebrew ever grows a patch annotation type, revisit.
- **declib version pinning.** v1 pins `declib>=4.5.0,<5` (the `binsync` extra); the upper bound excludes an unreviewed major.
  When declib evolves, rebrew may need migration code on `pull` for old
  state dirs. *(This PRD originally named the pin `libbs>=2.0`.)*
- **Per-instruction comments.** Native addresses remain dedicated metadata
  keys. C line mapping is unavailable; no inline ANALYSIS representation is
  emitted or parsed.
- **Locals annotation discipline.** Without lint validation against
  tree-sitter-extracted locals, the `[locals]` block can drift from the
  actual C source. Cheap mitigation: pass through. Future: W020.
- **Multi-target state directories.** Per-target by default; multi-target
  uses `--target` and separate state dirs (BinSync expects one binary per
  state directory).

## Implementation Phasing

| Phase | Scope | Effort | Status |
|-------|-------|--------|--------|
| **P1**: Foundation | Optional `declib` dep; rewrite struct export via declib | ~1 day | Shipped |
| **P2**: Bidirectional core | `binsync push`/`pull`/`summary`/`diff` (+ git commit / ff-only) | ~2 days | Shipped |
| **P3**: Type-system depth | Struct fields, enum + typedef export/import | ~1 day | Shipped |
| **P4**: Locals | `[locals]` ↔ `Function.stack_vars` | ~1.5 days | Shipped |
| **P5**: Conflict + comments | Accept-flags; per-instruction comments round-trip | ~1 day | Shipped |
| **P6**: Polish | `binsync init`, `--module`, JSON, docs | ~1 day | Shipped |

Estimated v1 scope: ~7 days, with independently shippable phases.

Status: P1–P6 core shipped (umbrella + declib I/O + structs/enums/typedefs +
`LOCALS`/`COMMENTS` + conflict flags + `binsync diff`/`--clean`). Remaining:
divergent Git-history merging (peer reconciliation, plain-repo ff-only,
local commit and `--git-push` are shipped).

## Related

- [`rebrew binsync export` / `binsync import` / `binsync diff`](../BINSYNC_INTEGRATION.md): the bridge shipping today; raw state exchange and Git-aware synchronization retain distinct semantics.
- [`rebrew sync push`](07-ghidra-sync.md): Ghidra ReVa sync; complementary, not replaced.
- [BinSync](https://github.com/binsync/binsync): the upstream plugin.
- [declib](https://github.com/binsync/declib): BinSync's artifact layer (this PRD originally named it `libbs`).
- `ghidra_backend = "cli"` ([CONFIG.md](../CONFIG.md)): the shipped ghidra-cli alternative to the ReVa MCP transport (orthogonal to BinSync).
