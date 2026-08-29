# PRD 09 — Full BinSync Integration

**Feature name:** Bidirectional BinSync ↔ Rebrew Sync (git-backed state, libbs format)
**One-line value:** Turn rebrew into a first-class BinSync peer so reverse-engineering knowledge round-trips losslessly between IDA Pro, Binary Ninja, Ghidra, and rebrew's C source — collaborators on different decompilers share names, types, comments, and stack vars without conversion friction.

## Problem It Solves

Today rebrew ships the one-way half as flat commands: `rebrew binsync-export`
writes names + sizes + globals (with real C types) + structs (with fields) to a
BinSync state directory; `rebrew binsync-import` applies BinSync names /
prototypes / global labels back into rebrew metadata; `rebrew binsync-diff`
reports divergences read-only (exit 1 on any, for CI). The full bidirectional
workflows are still out of reach:

- **Round-trip via flat commands, not git-backed sync.** Symbol renames a
  collaborator does in IDA/BN/Ghidra can now flow back via `rebrew
  binsync-import`, but there is still no `rebrew binsync` umbrella: push, pull,
  merge, and conflict resolution against a shared git repo are out of reach.
- **Static snapshot, no git merge.** BinSync's substrate is git. Export's
  `--git` flag only commits locally — no pull, no push, no awareness of
  upstream changes.
- **Struct fields — resolved.** `structs/<name>.toml` is now emitted with real
  `[fields.<name>]` entries (types parsed from `*.h` headers / sources via
  tree-sitter; the raw `definition` is preserved). Placeholders remain only for
  `STRUCT:` names with no scanned definition. (Resolved — was an empty
  `# (libbs-compatible struct field entries)` comment that BinSync clients
  skipped.)
- **No enum, typedef, stack-var, or local-var concept.** Rebrew's annotation
  surface stops at functions + globals + structs. BinSync covers enums,
  typedefs, stack frames (named local vars + types), and per-instruction
  comments; none of those are exported/imported today.
- **`libbs` library not used.** Rebrew hand-rolls the TOML serialization, so
  any format evolution upstream (libbs is BinSync's format crate) breaks
  silently.

PRD 09 closes the loop: a `rebrew binsync` umbrella with `push` / `pull` / `summary` modes, optional git auto-commit, full libbs serialization, and new annotation surfaces for enums, typedefs, and locals.

## Users

- **Solo reverser** who wants to share annotations with a team member working in IDA Pro without manual conversion.
- **Team** collaborating on a binary where one person prefers source-level work (rebrew) and others use decompiler GUIs — git-backed BinSync state is the canonical merge point.
- **AI agent** running CI-style sync between rebrew's annotations and a published BinSync repo.
- **Switchers**: someone starting a project in IDA + BinSync who wants to migrate to rebrew without losing names/types/comments.

## Goals

- One umbrella command (`rebrew binsync`) with explicit `push`, `pull`, `summary`, `init` subcommands. Mirrors `rebrew sync`'s shape for muscle-memory. (Not yet shipped — today the pieces live in flat `binsync-export` / `binsync-import` / `binsync-diff`.)
- True bidirectional sync via git: `rebrew binsync pull` does `git pull` on the state directory before reading; `push` does `git commit` + optional `git push` after writing. (Export's `--git` commit is the only git step shipped so far.)
- Real `libbs`-compatible struct fields, enums, typedefs. (Struct fields ship today via hand-rolled TOML; enums/typedefs and libbs remain.)
- New annotation surface for stack vars / local vars (see "Annotation Surface" below).
- Conflict detection on pull: when both rebrew and BinSync have meaningful (non-generic) names for the same VA, report and let the user pick via `--accept-binsync` / `--accept-local` (same pattern as `rebrew sync`). (The conflict detection + accept-flags half ships in `binsync-import`; the umbrella shape remains.)
- Per-instruction comments — both directions.
- `libbs` as an optional dependency (under `[project.optional-dependencies].binsync`) so users who don't need this feature aren't forced to install it.

## Non-Goals

- **Patch tracking** — BinSync supports binary patches. Rebrew has no patch concept and adding one is a different feature; skip in v1.
- **Custom GUI** — rebrew is CLI-first; no graphical conflict resolver. Conflicts surface as JSON / Rich tables and accept-flags.
- **Real-time collaboration** (live cursor / presence). BinSync's git substrate gives push/pull semantics, not realtime, and that's enough.
- **Replacing `rebrew sync`** — Ghidra sync via ReVa MCP stays the primary path for users on Ghidra. BinSync sync is the cross-decompiler portability path.

## Functional Requirements

**Status (2026-08):** the one-way half of this design ships as three flat
commands — `rebrew binsync-export` (the push-write: state dir + optional
`--git` commit), `rebrew binsync-import` (the pull-apply: names / prototypes /
globals with `--accept-binsync` / `--accept-local` and `--create-missing`),
and `rebrew binsync-diff` (read-only divergence report, exit 1 on divergence).
None use `libbs`; git pull, stack vars, enums, typedefs, and per-instruction
comments are not covered. The umbrella below is the remaining target.

### F1 — `rebrew binsync` umbrella

Five subcommands:

```bash
rebrew binsync push <state-dir>      # write local annotations into BinSync state + git commit
rebrew binsync pull <state-dir>      # git pull + read BinSync state into local metadata
rebrew binsync summary <state-dir>   # preview what would push / pull (read-only)
rebrew binsync init <state-dir>      # initialise a fresh BinSync state directory (git init + skeleton)
rebrew binsync diff <state-dir>      # per-VA diff: where do rebrew + BinSync disagree?
```

Shipped today as flat commands: `binsync-export` (≈ `push --no-git`, plus the
`--git` commit), `binsync-import` (≈ `pull` minus the git pull), and
`binsync-diff` (≈ the planned `diff` subcommand, read-only).

Plus the existing `rebrew binsync-export` stays as a back-compat alias for `binsync push --no-git`.

Shared flags: `--target`, `--json`, `--dry-run`, `--module FILTER` (mirroring `rebrew sync --module`).

### F2 — `push` writes via `libbs`

All artifact writing goes through the `libbs` package's serializers (struct field, enum, typedef, function header, stack frame). No more hand-rolled TOML for these. Rebrew's existing `[rebrew]` / `[rebrew:note]` synthetic comments stay — they're orthogonal and BinSync-clients ignore them.

`push` adds an auto-commit step after writing: `git -C <state-dir> add -A && git commit -m "rebrew push: <target> @ <utc>"`. With `--git-push`, also `git push`. With `--no-git`, skip git entirely (current `binsync-export` behaviour).

### F3 — `pull` reads via `libbs`, applies to rebrew metadata

For each function in the BinSync state:

- **Name** → if generic (FUN_/SUB_/sub_), skip. If meaningful and rebrew already has a meaningful different name, report CONFLICT. Else update `ann.name` (writes `// FUNCTION: <module> 0x<va>` doesn't change; symbol declaration in `.c` does change, plus cross-references like `rebrew rename` does today).
- **Prototype** → update the C function declaration via `rebrew sync --pull-signatures`'s existing prototype-rewrite path.
- **Stack frame / locals** → write to a new `[locals]` block in `rebrew-functions.toml`. See F4.
- **Per-instruction comments** → write as `// ANALYSIS:` style markers in the C body (matches existing `rebrew sync --pull-comments` shape).
- **Struct** → write field-by-field into `types.h` (or per-module `types_<module>.h` per E16).
- **Enum / typedef** → write into `types.h` (or `enums.h` if the user wants split).
- **Global variable** → write `name`/`size`/`type` into `rebrew-data.toml` (canonical data metadata file).

`pull` does `git pull` on the state directory first unless `--no-git`. On merge conflicts (in git itself), abort with a helpful error pointing the user at the state dir.

### F4 — New annotation surface: locals + stack vars

Today rebrew has no local-variable annotation concept. To round-trip with BinSync, add the smallest possible surface:

- A new `[locals]` block in `rebrew-functions.toml`:
  ```toml
  ["SERVER.0x10008880"]
  status = "EXACT"
  [SERVER.0x10008880.locals]
  ebp_minus_4  = { name = "ret_val",   type = "int" }
  ebp_minus_8  = { name = "tmp",       type = "char *" }
  esp_plus_0   = { name = "arg_count", type = "size_t" }
  ```
- The metadata is informational only at v1 — rebrew doesn't lint local-var names against the C source or use them for matching. Pure pass-through field for BinSync round-trip.
- Optional future enhancement: validate against tree-sitter-extracted local declarations in the C source and surface mismatches as lint warnings (W020+).

### F5 — New annotation surface: enums + typedefs

Today rebrew extracts struct definitions from C source via tree-sitter (`struct_parser.py`). Extend the same path:

- Parse `enum FOO { A = 1, B, C };` and `typedef int my_int_t;` declarations from `types.h` (or any header under `cfg.reversed_dir`).
- Emit them in `rebrew binsync push` via libbs's enum/typedef serializers.
- Pull writes new enums/typedefs into `types.h` (append or overwrite — `--types-out PATH` from E16 applies).

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

### F8 — `libbs` dependency

Add to `pyproject.toml`:

```toml
[project.optional-dependencies]
binsync = ["libbs>=2.0"]
```

`rebrew binsync` raises a clear error if libbs isn't installed, with the install command (`uv pip install -e ".[binsync]"`). Existing `binsync-export` continues to work without libbs (back-compat), only the new `binsync push/pull` modes require it.

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

Planned (PRD target — umbrella not yet shipped):

```bash
rebrew binsync init <state-dir>                  # git init + skeleton
rebrew binsync summary <state-dir>               # dry-run preview
rebrew binsync push <state-dir>                  # write + git commit
rebrew binsync push <state-dir> --git-push       # write + commit + push
rebrew binsync push <state-dir> --no-git         # write only (current binsync-export behaviour)
rebrew binsync pull <state-dir>                  # git pull + apply
rebrew binsync pull <state-dir> --accept-binsync # accept all conflicts
rebrew binsync pull <state-dir> --accept-local   # keep local on all conflicts
rebrew binsync pull <state-dir> --no-git         # skip git pull
rebrew binsync pull <state-dir> --module MSVCRT  # restrict to one module
rebrew binsync diff <state-dir>                  # show divergences without writing
```

Common flags across all (planned): `--target NAME`, `--json`, `--dry-run`.
The existing `binsync-export` stays as a back-compat alias for
`binsync push --no-git`.

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
rebrew init --target legacy --binary original/legacy.dll --compiler msvc6
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
- libbs-format outputs validate via libbs's own loader (`libbs.api.State(...)` should accept the rebrew-written state directory and return a fully-populated `State` object).

## Known Limitations / Open Questions

- **Patch tracking is out of scope.** If rebrew ever grows a patch annotation type, revisit.
- **libbs version pinning.** v1 pins `libbs>=2.0` (current as of 2026-05). When libbs evolves, rebrew may need migration code on `pull` for old state dirs.
- **Per-instruction comments.** Today rebrew has `// ANALYSIS:` for Ghidra's EOL/POST. The mapping from BinSync's per-address comments to source-line annotation is straightforward but needs care for inlined / reordered code where instruction addresses don't align with source lines. v1: pull writes comments as `// ANALYSIS: @ 0x<addr> — <text>` and accepts that they may end up on a sibling line.
- **Locals annotation discipline.** Without lint validation against tree-sitter-extracted locals, the `[locals]` block can drift from the actual C source. Cheap mitigation: in v1, just pass through. v2: add W020 ("local name in metadata doesn't match any local in the C function body").
- **Multi-target state directories.** Today `rebrew binsync-export` is per-target. The new umbrella stays per-target by default; multi-target is doable by passing `--target` and using separate state dirs, since BinSync expects one binary per state directory.

## Implementation Phasing

| Phase | Scope | Effort |
|-------|-------|--------|
| **P1** — Foundation | Add `libbs` optional dep; rewrite struct export via libbs; replace existing `binsync-export` internals (no behavioural change for users yet). | ~1 day |
| **P2** — Bidirectional core | `binsync push` (with optional git commit), `binsync pull` (with git pull + name/prototype application), `binsync summary`, `binsync diff`. Function + struct names only — no locals, no enums. | ~2 days |
| **P3** — Type-system depth | Real struct field serialization, enum export + import, typedef export + import. | ~1 day |
| **P4** — Locals | New `[locals]` block in `rebrew-functions.toml`. Pull writes; push reads. No source-level validation yet. | ~1.5 days |
| **P5** — Conflict + comments | Conflict detection on pull; `--accept-binsync` / `--accept-local`; per-instruction comments round-trip. | ~1 day |
| **P6** — Polish | `binsync init`, `--module` filter, JSON-mode improvements, retry on network failures, docs + skill updates. | ~1 day |

Total v1 scope: ~7 days of focused work. Each phase ships independently and is useful on its own.

Status: parts of P1–P3 (struct export with real fields — hand-rolled TOML,
libbs itself not shipped), P2 (name/prototype/global import + conflict flags),
and P6 (read-only `binsync-diff`, `--clean`) have already landed in the flat
commands; the remaining work is the git-backed umbrella, libbs, enums/typedefs,
locals, and per-instruction comments.

## Related

- [`rebrew binsync-export` / `binsync-import` / `binsync-diff`](../BINSYNC_INTEGRATION.md) — the one-way bridge shipping today; `binsync-export` becomes the back-compat alias under the umbrella.
- [`rebrew sync`](07-ghidra-sync.md) — Ghidra ReVa sync; complementary, not replaced.
- [BinSync](https://github.com/binsync/binsync) — the upstream plugin.
- [libbs](https://github.com/binsync/libbs) — the serialization library this PRD depends on.
- IDEAS.md entry #24 — ghidra-cli alternative (orthogonal; addresses ReVa-MCP dependency).
