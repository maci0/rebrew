# BinSync Integration

`rebrew binsync-export`, `rebrew binsync-import`, and `rebrew binsync-diff`
provide a bidirectional bridge between rebrew and any BinSync-aware decompiler
plugin (IDA Pro, Binary Ninja, Ghidra via BinSync). The export now carries real
global types and struct fields; the import closes the loop for names,
prototypes, and global labels; `binsync-diff` reports divergence read-only.

> BinSync state I/O goes through [declib](https://github.com/binsync/declib), BinSync's
> artifact layer (the `declib>=4.5` dependency of the `binsync` extra). Install it with
> `uv sync --extra binsync`. Stack vars, per-instruction comments, enums, and typedefs
> all round-trip; the `rebrew binsync` push/pull umbrella is still planned
> ([prd/09-binsync-full.md](prd/09-binsync-full.md)).

---

## Init: `rebrew binsync-init <state-dir>`

Creates the git envelope upstream BinSync's `Client` requires. rebrew writes
BinSync-format files, but upstream resolves the state root from a git repo
whose `binsync/__root__` branch root commit carries `.gitignore` (`.git/*`)
and `binary_hash` (the target binary's MD5), plus a `binsync/<user>` branch
created from that root. Without it, `_get_or_init_binsync_repo` raises "not a
BinSync repo".

```bash
rebrew binsync-init ./binsync_state
rebrew binsync-init ./binsync_state --user alice
rebrew binsync-init ./binsync_state --dry-run
```

`--user` defaults to `git config user.name` (else `rebrew`). The root commit
adds only `.gitignore` and `binary_hash` (never `-A`), so files already present
in the state directory stay untracked. Running against a state directory that
already has a `binsync/__root__` branch errors.

---

## Umbrella — `rebrew binsync <push|pull|summary|init|diff|overlay>`

`rebrew binsync` is a multi-command group that orchestrates the same
functions as the flat commands and adds git automation:

```bash
rebrew binsync init ./binsync_state          # build the git envelope (same as binsync-init)
rebrew binsync push ./binsync_state          # export + git commit
rebrew binsync push ./binsync_state --git-push --remote origin
rebrew binsync pull ./binsync_state          # git pull --ff-only + import
rebrew binsync pull ./binsync_state --no-git --accept-binsync
rebrew binsync summary ./binsync_state       # read-only preview of both directions
rebrew binsync diff ./binsync_state          # same as binsync-diff
rebrew binsync overlay ./binsync_state       # same as binsync-overlay
```

- **`push`** runs `binsync-export`, staging and committing the state directory
  (`--no-git` skips the commit). `--git-push` pushes both `binsync/__root__` and
  the current branch to `--remote` (default `origin`).
- **`pull`** fast-forwards the state directory's git repo (`--no-git` skips it;
  a non-fast-forward points you at resolving the repo by hand), then runs
  `binsync-import`. Unresolved conflicts exit `1`, like the flat import.
- **`summary`** calls export and import in dry-run mode and reports the counts
  each direction would change. It writes nothing and never touches git.

The flat `rebrew binsync-init/export/import/diff/overlay` commands remain for
scripting and back-compat; the umbrella is a thin layer over the same code.

---

## Export — `rebrew binsync-export <outdir>`

Writes a [BinSync](https://github.com/binsync/binsync) state directory from the
project's annotations and metadata:

```
<outdir>/
    metadata.toml        -- user + version (declib State.parse requires it)
    functions/
        <hex>.toml       -- one declib Function artifact per function
    structs/
        <name>.toml      -- one declib Struct artifact per struct (name sanitized)
    comments.toml        -- Comment.dumps_many, keyed by hex addr
    global_vars.toml     -- GlobalVariable.dumps_many, keyed by hex addr
    enums.toml           -- Enum.dumps_many, keyed by name
    typedefs.toml        -- Typedef.dumps_many, keyed by name
    binary_hash          -- target binary MD5 (rebrew-added)
    manifest.toml        -- rebrew freshness facts (ignored by declib)
```

Export merges two sources: reversed annotations (`scan_reversed_dir`, the
authoritative names/sizes/prototypes) plus the **project file / catalog**
(`src/<target>/functions.txt` + `function_structure.json` → `build_function_registry`,
canonical sizes) for functions that have not yet been reversed.  This keeps
BinSync in sync with your binary's full function list and offsets, not just the
reversed subset.  Catalog-only functions are exported with no `STATUS`/`CFLAGS`
and no `GHIDRA` comment; import surfaces them as `proposed_missing` until created
with `--create-missing`.

### What Gets Exported

| Rebrew field | declib artifact | Location |
|---|---|---|
| `va` + `name`/`symbol` | `Function.addr` / `Function.name` | `functions/<hex>.toml` |
| `size` | `Function.size` | `functions/<hex>.toml` |
| `prototype` | `Function.header.type` | `functions/<hex>.toml` |
| `locals` metadata | `Function.stack_vars` (`StackVariable`) | `functions/<hex>.toml` |
| `note` | `Comment` at `va + 1` (`func_addr=va`) | `comments.toml` |
| `ghidra` | `Comment` at `va + 2` (only when different) | `comments.toml` |
| `comments` metadata | `Comment` per instruction addr | `comments.toml` |
| DATA/GLOBAL entries | `GlobalVariable.addr/name/type/size` | `global_vars.toml` (hex-addr keys) |
| Struct definitions | `Struct` members keyed by byte offset | `structs/<name>.toml` |
| Enum definitions | `Enum.name` + `Enum.members` values | `enums.toml` (`[<name>.members]`) |
| Standalone typedefs | `Typedef.name` + `Typedef.type` | `typedefs.toml` |
| Target binary MD5 | Binary identity binding | `binary_hash` (omitted when the target binary is unavailable) |
| Export manifest | Freshness facts | `manifest.toml` (`exported_at`, `content_hash`, `target`, `binary_hash`, optional `commit`) |

### Rebrew Metadata Comment Format

`STATUS`/`CFLAGS` are verify-earned and never exported.  Notes, the
Ghidra-synced name, and per-instruction comments all travel as declib
`Comment` artifacts in `comments.toml`, keyed by address and tagged with the
owning function's `func_addr`:

```toml
# comments.toml
[0x10008881]
addr = 0x10008881
func_addr = 0x10008880
comment = "[rebrew:note] Matches original exactly"
decompiled = false
```

(`va + 1` for the note, `va + 2` for a differing Ghidra name; the comment
prefix distinguishes provenance from a real instruction comment.)

### Function TOML Layout

```toml
# functions/10008880.toml
addr = 0x10008880
size = 0x1f
name = "_BitReverse@4"

[header]
name = "_BitReverse@4"
addr = 0x10008880
type = "int __cdecl BitReverse(int x)"

[header.args]

[stack_vars.-0x4]
offset = -4
name = "ret"
type = "int"
size = 0x4
addr = 0x10008880
```

### Global Variables

DATA and GLOBAL annotations are written as declib `GlobalVariable` artifacts
with their real C types (resolved from `extern` declarations + data metadata;
`char` fallback).  Section is not part of declib's `GlobalVariable`; import and
overlay derive the section from the binary by address:

```toml
[0x10008000]
addr = 0x10008000
name = "g_szNotepad"
type = "char[64]"
size = 0x40
```

### Structs

Struct definitions are collected from `*.h` headers and source files via
tree-sitter and emitted with field-level detail.  Headers are scanned in the
target's `reversed_dir` and, when configured, the project-shared tree
(`[project].shared_dir`, default `src/shared`), so a type declared once for
every target exports for each of them:

```toml
# structs/Point.toml
name = "Point"
size = 0x28

[members.0x0]
name = "x"
offset = 0x0
type = "int"
size = 0x4

[members.0x4]
name = "y"
offset = 0x4
type = "int"
size = 0x4

[members.0x8]
name = "name"
offset = 0x8
type = "char[32]"
size = 0x20
```

If `STRUCT:` annotations name a struct that isn't defined in any scanned header,
a minimal placeholder (no members) is still emitted.

### Enums and typedefs

Enums and standalone typedefs are name-keyed like structs and collected from
the same header/shared/source scan via tree-sitter.  Each is a **single**
file (matching upstream BinSync, which dumps many enums/typedefs per file);
an empty collection writes nothing:

```toml
# enums.toml
[E]
name = "E"

[E.members]
A = 0x0
B = 0x5
C = 0x6
```

```toml
# typedefs.toml
[uint32_t]
name = "uint32_t"
type = "unsigned int"
```

Bare enum members auto-increment from the previous value (starting at 0).
declib carries no enum/typedef body text, so import synthesizes the
declaration from the name + members/type.  `binsync-import` writes unknown
enum/typedef definitions into the local `binsync_types.h` (known names are
never overwritten), and `binsync-overlay` imports them from a related target's
state directory the same way.

---

## Import — `rebrew binsync-import <state-dir>`

Reads a BinSync state directory (own export or one produced by another tool)
and applies changes back into rebrew metadata/source:

- **Names** — declib `Function.name` → rebrew symbols
  (via `rebrew rename` cross-reference rewriting). Generic→meaningful is applied
  directly; meaningful↔meaningful raises a conflict.
- **Prototypes** — declib `Function.header.type` → `// PROTOTYPE:` inline
  annotations in the local `.c` files (PROTOTYPE is a file-only key, not
  metadata).  Comparison is whitespace-normalized (formatting-only differences
  are not divergence); a differing local prototype raises a conflict like a
  name — `--accept-binsync` overwrites.
- **Globals** — declib `GlobalVariable` records → `rebrew-data.toml` names,
  plus differing `type`/`size` written back (section comes from the binary).
- **Notes / comments** — declib `Comment` artifacts in `comments.toml`:
  `[rebrew:note]`/`[rebrew:ghidra]` prefixes become rebrew `note`/`ghidra`
  metadata; every other comment lands in the function's `comments` metadata
  keyed by hex address. A comment whose address falls inside the owning
  function's range also gets a human-editable source marker (see below).
- **Locals** — declib `Function.stack_vars` → the function's `locals` metadata
  (`[<module>.<va>.locals]`, offset-keyed `{name, type, size}`).
- **Structs / enums / typedefs** — declib `Struct`, `Enum`, and `Typedef`
  records unknown locally land in `binsync_types.h`; known names are never
  overwritten, and unparseable synthesized definitions import as comments, never
  as compile-breaking typedefs.

### Per-address comment markers

Per-instruction comments have a line-comment representation, anchored by
address (rebrew has no source line table, so the block is placed at the END of
the owning `.c` file and never touches a function body):

```c
// ANALYSIS @ 0x401010: some note
```

- **Import/pull** writes or updates one marker per comment whose address is
  inside a local function's range, in a single trailing block sorted by
  address, separated from the code by one blank line. Re-import updates the
  existing line in place (idempotent, no duplicates). A comment outside every
  known function's range stays in the `comments` metadata only.
- **Export/push** collects comments from BOTH the metadata `comments` field and
  a scan of the project sources for the marker pattern, merged by address. A
  source marker wins over the metadata entry for the same address, so an edit
  made in source flows out to `comments.toml`. `func_addr` is derived from the
  owning function's VA.
- **Overlay** shifts each transferred comment address by the matched pair's VA
  delta and writes the marker in the destination file too.

The metadata `comments` field remains the lossless store (it survives even for
addresses with no source marker).

Conflict resolution mirrors `rebrew sync`:

```
CONFLICT 0x10001000: local=_OldName vs binsync=_NewName
```

- `--accept-binsync` — accept BinSync name (rewrites local files).
- `--accept-local` — keep local, record BinSync name as `GHIDRA` provenance.

`--module FILTER` restricts to one module; `--dry-run`/`--json` work as elsewhere.  For BinSync
functions with no local annotation but present in the catalog, import proposes a new STUB
(`proposed_missing`); pass `--create-missing` to materialize it (see `--create-missing` in the flag table).

### Examples

```bash
# Preview what would be imported
rebrew binsync-import ./binsync_state --dry-run

# Accept all BinSync renames
rebrew binsync-import ./binsync_state --accept-binsync

# Accept only one module
rebrew binsync-import ./binsync_state --module SERVER --accept-binsync

# Machine-readable summary
rebrew binsync-import ./binsync_state --dry-run --json | jq .
```

---

## Overlay — `rebrew binsync-overlay <state-dir>`

Transfers BinSync names, prototypes, and notes from a **related target** onto
structurally-matched functions of the target the command runs against. Two
binaries in one project (a DLL+EXE pair sharing a static lib, or two versions)
hold the same code at different VAs; this command pairs them by structural
signature (no compilation needed) and overlays the fields the source target
already knows.

The source target comes from `--from`, or from the `target` key in the state
`manifest.toml` when `--from` is omitted. The destination is the command's
`--target` (the project default when omitted).

- **Names**: applied when the local name is generic or empty; a meaningful
  local name that differs is a conflict.
- **Prototypes**: applied when the local prototype is empty; a differing
  non-empty local prototype is a conflict (whitespace-normalized compare).
- **Notes**: a differing non-empty remote note is written to the `note`
  metadata field.
- **Structs, enums, typedefs**: unknown definitions from the state import into
  the destination's `binsync_types.h` as in `binsync-import`; known names are
  never overwritten.
- **Globals** (opt-in via `--fields global`): a source global is matched to
  the destination by exact content, not by address. Its bytes are searched in
  the destination's same-named section and mapped only when they occur exactly
  once; a duplicate or a missing section is skipped, never guessed. The matched
  destination VA takes the source name plus `type`/`size`/`section`.

`--fields name,prototype,note` restricts which fields run (add `global` to
include content-matched globals). `--module NAME` restricts the destination to
one module.

Default conflict behavior matches `binsync-import`: a conflict is reported,
nothing is written, and the command exits `1`. Pass `--accept-binsync` to take
the remote value, or `--accept-local` to keep the local value and record the
remote one as `GHIDRA` provenance.

```bash
# Preview what would move from v1's state onto this target
rebrew binsync-overlay ../v1/state --dry-run

# Source target from the manifest; accept BinSync names on conflicts
rebrew binsync-overlay ../v1/state --accept-binsync

# Only names and prototypes, machine-readable
rebrew binsync-overlay ./state --fields name,prototype --json | jq .

# Include content-matched globals
rebrew binsync-overlay ./state --fields global
```

---

## Diff — `rebrew binsync-diff <state-dir>`

Read-only divergence report between the local project (reversed annotations +
catalog) and a BinSync state directory. Never writes; exits `1` when any
divergence exists (CI-friendly). Same filtering semantics as
`binsync-import --dry-run`.

- **Names** — generic-vs-meaningful and meaningful↔meaningful conflicts
- **Prototypes** — BinSync `[header].type` vs local prototype (whitespace-normalized)
- **Globals** — `global_vars.toml` labels missing or renamed locally
- **New in BinSync** — catalog-known functions present in BinSync but not yet
  reversed locally (the same population import surfaces as `proposed_missing`)
- **Freshness** — `manifest.toml` facts surfaced in `--json` (`exported_at`, `content_hash`)

```bash
rebrew binsync-diff ./binsync_state            # divergences (exit 1 if any)
rebrew binsync-diff ./state --json | jq .      # machine-readable report
rebrew binsync-diff ./state --module SERVER    # one module only
```

---

## Common Flags

`binsync-export`, `binsync-import`, and `binsync-diff` share the standard
rebrew surface (`binsync-diff` is read-only: no `--dry-run` or `--accept-*`;
it exits `1` on divergence). `binsync-overlay` adds `--from` and `--fields`,
and supports the same `--target`/`--module`/`--dry-run`/`--json` flags:

| Flag | Effect |
|---|---|
| `--target NAME` | Operate on a specific target |
| `--module NAME` | Only this module (export filters, import/diff skip) |
| `--dry-run` | Preview without writing |
| `--json` | Machine-readable output |
| `--git` (export only) | Stage + `git commit` the state directory after writing |
| `--clean` (export only) | Delete orphan `functions/<hex>.toml` no longer in the catalog/annotations |
| `--create-missing` (import only) | Create STUB files for catalog-known BinSync functions with no local annotation |

### Export Examples

```bash
# Export to a directory
rebrew binsync-export ./binsync_state

# Export one module only
rebrew binsync-export ./binsync_state --module SERVER

# Export + git commit the state
rebrew binsync-export ./binsync_state --git

# Export for a specific target (multi-target project)
rebrew binsync-export ./binsync_state --target server

# Preview without writing (dry-run)
rebrew binsync-export ./binsync_state --dry-run

# Machine-readable summary
rebrew binsync-export ./binsync_state --json
```

---

## Coverage by Status

| Status | Name | Prototype | Metadata comment |
|--------|------|-----------|-----------------|
| EXACT / RELOC / PROVEN | ✅ | ✅ (if annotated) | ✅ |
| NEAR_MATCHING | ✅ | ✅ (if annotated) | ✅ |
| STUB | ✅ | ✅ (if annotated) | ✅ |
| LIBRARY | ✅ | ✅ (if annotated) | ✅ |
| (no STATUS) | ✅ | ✅ (if annotated) | omitted |

The metadata-comment column is notes and differing Ghidra names only —
`STATUS`/`CFLAGS` are verify-earned and never leave the project.

---

## Limitations (remaining)

- **Comments outside a function range** — a per-instruction comment whose
  address falls outside every known function's range has no source marker
  (rebrew has nowhere to anchor it); it stays in the metadata `comments` store
  and still round-trips through `comments.toml`.
- **Marker placement** — the `// ANALYSIS @ 0xADDR: text` block is file-level
  (one trailing block per `.c`), not mapped to a source line; rebrew has no
  line table, so the address is the only anchor.

---

## Related

- [`rebrew sync`](GHIDRA_SYNC.md) — bidirectional Ghidra sync via ReVa MCP
- [`rebrew catalog`](CLI.md#rebrew-catalog) — function registry and coverage grid
- [BinSync GitHub](https://github.com/binsync/binsync)
- [declib](https://github.com/binsync/declib)
