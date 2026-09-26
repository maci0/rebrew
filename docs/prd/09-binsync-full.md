# PRD 09 — Full BinSync Integration

- **Status**: Partial (umbrella + declib I/O shipped; divergent git merge remains open)
- **Date**: 2026-05 (updated 2026-09)
- **Owner**: rebrew team

> **Correction (2026-09):** `rebrew sync --push/--pull --state-dir` now uses
> the same BinSync state (conflicts via `--accept-binsync` / `--accept-local`),
> and the `rebrew binsync` umbrella (`push`/`pull`/`summary`/`init`/`diff`/
> `overlay`) ships alongside the flat commands. State I/O is **declib**
> (the `binsync` extra) — stack vars, per-instruction comments, enums, and
> typedefs round-trip. What remains: divergent git merge as the default
> sync substrate (today: export `--git` commit, pull `--ff-only`, push
> `--git-push`). PRDs are historical records; shipped-status lines below
> track the CHANGELOG.

**Feature name:** Bidirectional BinSync ↔ Rebrew Sync (git-backed state, declib format)
**One-line value:** Turn rebrew into a first-class BinSync peer so reverse-engineering knowledge round-trips losslessly between IDA Pro, Binary Ninja, Ghidra, and rebrew's C source — collaborators on different decompilers share names, types, comments, and stack vars without conversion friction.

## Problem It Solves

Today rebrew ships the one-way half as flat commands: `rebrew binsync-export`
writes names + sizes + globals (with real C types) + structs (with fields) to a
BinSync state directory; `rebrew binsync-import` applies BinSync names /
prototypes / global labels back into rebrew metadata; `rebrew binsync-diff`
reports divergences read-only (exit 1 on any, for CI). Gaps that remain
(or recently closed):

- **Umbrella — resolved.** `rebrew binsync` now ships `push` / `pull` /
  `summary` / `init` / `diff` / `overlay` alongside the flat commands.
  Git-backed upstream merge (pull from remote + push upstream as the
  default substrate) is still open; export's `--git` and pull's optional
  fast-forward are the git steps today.
- **Static snapshot, no full git merge.** BinSync's substrate is git.
  Export's `--git` flag commits locally; pull can fast-forward — there is
  still no full awareness of upstream divergent changes as the primary
  sync path.
- **Struct fields — resolved.** `structs/<name>.toml` is now emitted with real
  `[fields.<name>]` entries (types parsed from `*.h` headers / sources via
  tree-sitter; the raw `definition` is preserved). Placeholders remain only for
  `STRUCT:` names with no scanned definition.
- **Enums, typedefs, stack vars, per-instruction comments — resolved.**
  Export/import/overlay round-trip `enums.toml`, `typedefs.toml`, `LOCALS`
  (stack vars), and `COMMENTS` via declib artifacts (see CHANGELOG /
  [BINSYNC_INTEGRATION.md](../BINSYNC_INTEGRATION.md)).
- **Hand-rolled TOML — resolved.** State I/O goes through declib
  (`rebrew[binsync]` → `declib>=4.5`); the earlier `libbs` name in this PRD
  refers to that same upstream artifact layer.

PRD 09's remaining open loop is divergent git merge as the default
substrate (ff-only pull + local commit / optional `--git-push` ship today).

## Users

- **Solo reverser** who wants to share annotations with a team member working in IDA Pro without manual conversion.
- **Team** collaborating on a binary where one person prefers source-level work (rebrew) and others use decompiler GUIs — git-backed BinSync state is the canonical merge point.
- **AI agent** running CI-style sync between rebrew's annotations and a published BinSync repo.
- **Switchers**: someone starting a project in IDA + BinSync who wants to migrate to rebrew without losing names/types/comments.

## Goals

- One umbrella command (`rebrew binsync`) with explicit `push`, `pull`,
  `summary`, `init` subcommands. Mirrors `rebrew sync`'s shape for
  muscle-memory. (Shipped — umbrella plus flat commands coexist; `diff`
  and `overlay` also ship under the umbrella.)
- True bidirectional sync via git: `rebrew binsync pull` does `git pull` on the state directory before reading; `push` does `git commit` + optional `git push` after writing. (Shipped: export/`push` commit, pull `--ff-only`, `--git-push`. Open: divergent upstream merge as the primary path.)
- Real declib-compatible struct fields, enums, typedefs. (Shipped via declib artifacts.)
- Annotation surface for stack vars / local vars (see "Annotation Surface" below). (Shipped: `LOCALS` metadata ↔ `Function.stack_vars`.)
- Conflict detection on pull: when both rebrew and BinSync have meaningful (non-generic) names for the same VA, report and let the user pick via `--accept-binsync` / `--accept-local` (same pattern as `rebrew sync`). (Shipped on umbrella `pull` and flat `binsync-import`.)
- Per-instruction comments — both directions. (Shipped: `COMMENTS` metadata + `// ANALYSIS @ 0xADDR:` source markers.)
- Declib as an optional dependency (under `[project.optional-dependencies].binsync`, `declib>=4.5`) so users who don't need this feature aren't forced to install it. (Shipped; this PRD originally named the layer `libbs`.)

## Non-Goals

- **Patch tracking** — BinSync supports binary patches. Rebrew has no patch concept and adding one is a different feature; skip in v1.
- **Custom GUI** — rebrew is CLI-first; no graphical conflict resolver. Conflicts surface as JSON / Rich tables and accept-flags.
- **Real-time collaboration** (live cursor / presence). BinSync's git substrate gives push/pull semantics, not realtime, and that's enough.
- **Replacing `rebrew sync`** — `rebrew sync` is now BinSync-primary for field sync (sharing the BinSync state directory format, with ReVa MCP for structural ops); `rebrew binsync` is the cross-decompiler portability umbrella.

## Functional Requirements

**Status (2026-09):** the `rebrew binsync` umbrella ships (`push` / `pull` /
`summary` / `init` / `diff` / `overlay`) alongside the flat
`binsync-export` / `binsync-import` / `binsync-diff` / `binsync-init` /
`binsync-overlay` commands.  Conflict accept-flags
(`--accept-binsync` / `--accept-local`) ship on pull/import.  Declib
serialization ships (`rebrew[binsync]`), including structs with fields,
enums, typedefs, `LOCALS`, and per-instruction `COMMENTS`.  Still open:
divergent git merge as the default sync substrate (export/`push` local
commit, pull `--ff-only`, and `--git-push` are the git steps today).

### F1 — `rebrew binsync` umbrella

Shipped subcommands:

```bash
rebrew binsync push <state-dir>      # write local annotations into BinSync state + git commit
rebrew binsync pull <state-dir>      # optional git fast-forward + apply BinSync state
rebrew binsync summary <state-dir>   # preview what would push / pull (read-only)
rebrew binsync init <state-dir>      # initialise a fresh BinSync state directory
rebrew binsync diff <state-dir>      # per-VA diff: where do rebrew + BinSync disagree?
rebrew binsync overlay ...           # overlay a related target's BinSync data
```

Flat commands remain as peers (not only aliases): `binsync-export`,
`binsync-import`, `binsync-diff`, `binsync-init`, `binsync-overlay`.

Shared flags: `--target`, `--json`; `--module FILTER` on every subcommand except `init`; `--dry-run` on the writing subcommands (`push`, `pull`, `init`, `overlay`; `summary` and `diff` are read-only).

### F2 — `push` writes via declib

All artifact writing goes through declib serializers (struct field, enum,
typedef, function header, stack frame). No more hand-rolled TOML for these.
Rebrew's `[rebrew:note]` synthetic comment stays: it is orthogonal, and
BinSync clients ignore it (the write-only `[rebrew] STATUS=… CFLAGS=…`
comment was removed; see `rebrew/binsync/export.py`). *(This PRD originally
named the layer `libbs`; the shipped dependency is `declib>=4.5`.)*

`push` adds an auto-commit step after writing: `git -C <state-dir> add -A && git commit -m "rebrew push: <target> @ <utc>"`. With `--git-push`, also `git push`. With `--no-git`, skip git entirely (current `binsync-export` behaviour).

### F3 — `pull` reads via declib, applies to rebrew metadata

For each function in the BinSync state:

- **Name** → if generic (FUN_/SUB_/sub_), skip. If meaningful and rebrew already has a meaningful different name, report CONFLICT. Else update `ann.name` (writes `// FUNCTION: <module> 0x<va>` doesn't change; symbol declaration in `.c` does change, plus cross-references like `rebrew rename` does today).
- **Prototype** → update the C function declaration via the prototype-rewrite path in `rebrew.binsync.importer` (the `--pull-signatures` flag it replaced is removed).
- **Stack frame / locals** → write to a new `[locals]` block in `rebrew-functions.toml`. See F4.
- **Per-instruction comments** → write as `// ANALYSIS:` style markers in the C body (the shape the removed `rebrew sync --pull-comments` flag wrote).
- **Struct / enum / typedef** → write unknown type definitions into `binsync_types.h` in `reversed_dir` (see F5).
- **Global variable** → write `name`/`size`/`type` into `rebrew-data.toml` (canonical data metadata file).

`pull` does `git pull` on the state directory first unless `--no-git`. On merge conflicts (in git itself), abort with a helpful error pointing the user at the state dir.

### F4 — Annotation surface: locals + stack vars

Shipped: `[locals]` in `rebrew-functions.toml` (offset-keyed
`{name, type, size}`), round-tripped via declib `Function.stack_vars`:

```toml
["SERVER.0x10008880"]
status = "EXACT"
[SERVER.0x10008880.locals]
ebp_minus_4  = { name = "ret_val",   type = "int" }
ebp_minus_8  = { name = "tmp",       type = "char *" }
esp_plus_0   = { name = "arg_count", type = "size_t" }
```

Informational at v1 — rebrew doesn't lint local-var names against the C
source or use them for matching. Optional future: validate against
tree-sitter-extracted locals (W020+).

### F5 — Annotation surface: enums + typedefs

Shipped: tree-sitter extraction of `enum` / standalone `typedef` from
headers and sources; `binsync push`/`export` emit `enums.toml` /
`typedefs.toml` via declib; pull/import write unknown definitions into
`binsync_types.h` without overwriting known names.

### F6 — Conflict resolution

Pull surfaces conflicts in the same shape as `rebrew sync --pull`:

```
CONFLICT: SERVER.0x10008880 — local "BitReverse" vs BinSync "ReverseBits"
CONFLICT: SERVER.0x10010000 (struct NPSTATE.field_0) — local "id" int vs BinSync "type_id" uint32_t
```

Resolution flags:

- `--accept-binsync` — accept all BinSync values; rewrite local files + metadata.
- `--accept-local` — record BinSync values as `[ghidra]`-style provenance metadata but keep local; no source rewrite.
- Interactive resolution (per-conflict prompt) is deferred to v2.

### F7 — Offline fallback

`binsync pull --no-git` reads the state directory as-is without pulling. Useful in CI where the state-dir is a checked-out artifact, or for users with credentials issues.

### F8 — `declib` dependency

Shipped in `pyproject.toml`:

```toml
[project.optional-dependencies]
binsync = ["declib>=4.5.0"]
```

Every BinSync state command (flat and umbrella) goes through
`rebrew.binsync.serial`; missing declib raises an actionable
"install rebrew[binsync]" error. *(This PRD originally named the layer
`libbs>=2.0`.)*

## CLI Surface

Shipped today (flat commands):

```bash
rebrew binsync-export <outdir>                   # write BinSync state dir (functions/, global_vars.toml, structs/)
rebrew binsync-export <outdir> --git             # also stage + git commit the state dir
rebrew binsync-export <outdir> --clean           # drop orphan function TOMLs
rebrew binsync-export <outdir> --module SERVER   # one module only
rebrew binsync-import <state-dir>                # apply names/prototypes/globals back to rebrew
rebrew binsync-import <state-dir> --accept-binsync   # accept BinSync on all conflicts
rebrew binsync-import <state-dir> --accept-local     # keep local, record provenance
rebrew binsync-import <state-dir> --module SERVER    # one module only
rebrew binsync-import <state-dir> --create-missing   # STUB files for catalog-known functions
rebrew binsync-diff <state-dir>                  # read-only divergence report (exit 1 on divergence)
```

Common flags on all three: `--target NAME`, `--json`; `--dry-run` on
export/import (`binsync-diff` is read-only and needs no dry-run).

Shipped (umbrella; flat commands above remain peers):

```bash
rebrew binsync init <state-dir>                  # git init + skeleton
rebrew binsync summary <state-dir>               # dry-run preview
rebrew binsync push <state-dir>                  # write + git commit
rebrew binsync push <state-dir> --git-push       # write + commit + push
rebrew binsync push <state-dir> --no-git         # write only (binsync-export behaviour)
rebrew binsync pull <state-dir>                  # git pull + apply
rebrew binsync pull <state-dir> --accept-binsync # accept all conflicts
rebrew binsync pull <state-dir> --accept-local   # keep local on all conflicts
rebrew binsync pull <state-dir> --no-git         # skip git pull
rebrew binsync pull <state-dir> --module MSVCRT  # restrict to one module
rebrew binsync diff <state-dir>                  # show divergences without writing
rebrew binsync overlay <state-dir>               # overlay a related target's BinSync data
```

Common flags across all: `--target NAME`, `--json`; `--dry-run` everywhere except the read-only `summary` and `diff`.
The existing `binsync-export` stays as a peer of `binsync push --no-git`.

## User Stories

### Story 1 — Solo reverser switches between rebrew + IDA Pro

A reverser uses rebrew as their primary workspace. Once a function is `EXACT`, they want to inspect it in IDA Pro with proper names.

```bash
rebrew binsync push ./binsync_state              # export + commit
# (in IDA Pro: load binsync_state directory via the BinSync plugin)
# (analyst adds local variable name "loop_counter" in IDA)
rebrew binsync pull ./binsync_state              # pulls "loop_counter" into rebrew-functions.toml [locals] block
```

### Story 2 — Team collaboration via shared git repo

Two reversers share a binary. One uses rebrew, one uses Binary Ninja. They share a `binsync-state` git repo with push access for both.

```bash
# Reverser A (rebrew):
rebrew binsync pull git@team:binsync-state.git    # fetch latest team work
# ... reverses some functions in rebrew ...
rebrew binsync push git@team:binsync-state.git --git-push   # push back

# Reverser B (Binary Ninja):
# (BinSync plugin pulls + pushes the same git repo)
```

### Story 3 — Migrating an IDA project to rebrew

Someone with an IDA Pro + BinSync project decides to migrate to rebrew.

```bash
rebrew init --target legacy --binary original/legacy.dll --toolchain msvc-6.0
rebrew binsync init ./binsync_state                   # initialises a state dir if migrating from scratch
# OR if they already have one from IDA:
rebrew binsync pull /path/to/ida_binsync_state        # imports names, types, locals, comments
rebrew status                                          # rebrew now knows what IDA knew
```

### Story 4 — CI conflict detector

A nightly CI run cross-checks local rebrew state against the shared BinSync repo.

```bash
rebrew binsync diff git@team:binsync-state.git --json > diff.json
# CI parses diff.json; fails if any CONFLICT entries exist; opens a ticket.
```

## Success Metrics

- A function reversed in rebrew, pushed to BinSync, pulled into IDA Pro, then re-renamed in IDA Pro, pushed back from IDA Pro, pulled into rebrew — round-trips losslessly. Same for stack vars, structs, enums.
- A 100-function project with all four artifact types (names, prototypes, locals, structs) pushes in <5s on a warm git tree; pulls in <5s after a `git pull` no-op.
- Conflict report on pull lists every divergent VA + field with one-line provenance. JSON parseable.
- Declib-format outputs validate via declib's own loaders (a
  BinSync/IDA/Ghidra/Binary Ninja state dir rebrew wrote must parse, and
  rebrew must parse theirs).

## Known Limitations / Open Questions

- **Patch tracking is out of scope.** If rebrew ever grows a patch annotation type, revisit.
- **declib version pinning.** v1 pins `declib>=4.5` (the `binsync` extra).
  When declib evolves, rebrew may need migration code on `pull` for old
  state dirs. *(This PRD originally named the pin `libbs>=2.0`.)*
- **Per-instruction comments.** Source markers are
  `// ANALYSIS @ 0xADDR: text` in a trailing block; comments outside any
  known function range stay metadata-only. Address↔line alignment can
  drift for inlined/reordered code.
- **Locals annotation discipline.** Without lint validation against
  tree-sitter-extracted locals, the `[locals]` block can drift from the
  actual C source. Cheap mitigation: pass through. Future: W020.
- **Multi-target state directories.** Per-target by default; multi-target
  uses `--target` and separate state dirs (BinSync expects one binary per
  state directory).

## Implementation Phasing

| Phase | Scope | Effort | Status |
|-------|-------|--------|--------|
| **P1** — Foundation | Optional `declib` dep; rewrite struct export via declib | ~1 day | Shipped |
| **P2** — Bidirectional core | `binsync push`/`pull`/`summary`/`diff` (+ git commit / ff-only) | ~2 days | Shipped |
| **P3** — Type-system depth | Struct fields, enum + typedef export/import | ~1 day | Shipped |
| **P4** — Locals | `[locals]` ↔ `Function.stack_vars` | ~1.5 days | Shipped |
| **P5** — Conflict + comments | Accept-flags; per-instruction comments round-trip | ~1 day | Shipped |
| **P6** — Polish | `binsync init`, `--module`, JSON, docs | ~1 day | Shipped |

Open beyond this table: divergent git merge as the default substrate
(ff-only + local commit / `--git-push` ship today).

Total v1 scope was ~7 days of focused work; each phase shipped
independently.

Status: P1–P6 core shipped (umbrella + declib I/O + structs/enums/typedefs +
`LOCALS`/`COMMENTS` + conflict flags + `binsync-diff`/`--clean`). Remaining:
divergent git merge as the default sync substrate (ff-only + local commit /
`--git-push` ship today).

## Related

- [`rebrew binsync-export` / `binsync-import` / `binsync-diff`](../BINSYNC_INTEGRATION.md) — the bridge shipping today; flat commands remain peers of the umbrella.
- [`rebrew sync`](07-ghidra-sync.md) — Ghidra ReVa sync; complementary, not replaced.
- [BinSync](https://github.com/binsync/binsync) — the upstream plugin.
- [declib](https://github.com/binsync/declib) — BinSync's artifact layer (this PRD originally named it `libbs`).
- `ghidra_backend = "cli"` ([CONFIG.md](../CONFIG.md)): the shipped ghidra-cli alternative to the ReVa MCP transport (orthogonal to BinSync).
