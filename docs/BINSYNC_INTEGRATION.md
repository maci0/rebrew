# BinSync Integration Proposal

Evaluation of integrating [BinSync](https://github.com/binsync/binsync) into the
rebrew decompilation workbench for collaborative reverse engineering.

---

## What is BinSync?

BinSync is a Git-based decompiler collaboration tool that synchronizes reverse
engineering artifacts across multiple decompilers (IDA Pro, Binary Ninja, Ghidra,
angr-management). Built by mahaloz, the angr team, and SEFCOM at ASU.

### Core Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  IDA Pro     │     │  Ghidra     │     │  Binary Ninja│
│  Plugin      │     │  Plugin     │     │  Plugin      │
└──────┬───────┘     └──────┬──────┘     └──────┬───────┘
       │                    │                    │
       └────────────┬───────┘────────────────────┘
                    │
              ┌─────▼──────┐
              │ Controller  │  (orchestrator)
              ├─────────────┤
              │   Client    │  (git operations)
              ├─────────────┤
              │   State     │  (TOML artifact store)
              └─────┬───────┘
                    │
              ┌─────▼──────┐
              │  Git Repo   │  (local or remote)
              │  per-user   │
              │  branches   │
              └─────────────┘
```

### Data Model (via libbs)

BinSync tracks these Reverse Engineering Artifacts (REAs):

| Artifact | Key | Storage |
|----------|-----|---------|
| Functions | address (int) | `functions/<hex_addr>.toml` (one file per function) |
| Stack Variables | within Function | embedded in function TOML |
| Comments | address (int) | `comments.toml` (single file) |
| Structs | name (str) | `structs/<name>.toml` (one file per struct) |
| Enums | name (str) | `enums.toml` (single file) |
| Global Variables | address (int) | `global_vars.toml` (single file) |
| Typedefs | name (str) | `typedefs.toml` (single file) |
| Patches | offset (int) | `patches.toml` (single file) |

All artifacts serialize to TOML with hex-encoded addresses (`%08x.toml`).

### Git Branching Model

- Each user operates on their own branch: `binsync/<username>`
- Shared root branch: `binsync/__root__`
- Changes auto-push to user branch, manual merge to root
- Conflict resolution via Git's native merge tooling

### Supported Decompilers

| Platform | Min Version | Limitations |
|----------|-------------|-------------|
| IDA Pro | >= 8.4 | Full support |
| Binary Ninja | >= 2.4 | Full support |
| Ghidra | >= 12.0 (PyGhidra) | No enum push, no auto-push comments |
| angr-management | >= 9.0 | No global vars, structs, or enums |

Requires Python >= 3.10 and Git.

---

## Current State: rebrew's Ghidra Integration

Rebrew already has a mature Ghidra sync via ReVa MCP (`rebrew sync`):

| Capability | rebrew sync | BinSync |
|------------|:-----------:|:-------:|
| Function labels/renames | push + pull | push + pull |
| Function signatures/prototypes | push + pull | push + pull |
| Struct definitions | push + pull | push + pull |
| Comments (EOL/analysis) | push + pull | push + pull |
| Stack variables | -- | push + pull |
| Enums | -- | push + pull (partial) |
| Global variables/data labels | push + pull | push + pull |
| Annotation metadata (STATUS, SIZE, CFLAGS) | push + pull | -- |
| Match verification (byte comparison) | yes | -- |
| Multi-target support | yes | -- |
| Conflict detection | yes | git-native |
| Real-time auto-sync | -- | yes |
| Cross-decompiler (IDA, BinNinja) | -- | yes |
| Git-versioned history | -- | yes |

---

## Integration Options

### Option A: Use BinSync as Transport Layer (Replace ReVa MCP)

Replace the current ReVa MCP HTTP transport with BinSync's Git-based sync.

**How it would work:**
1. `rebrew sync --push` writes rebrew annotations to BinSync's TOML format in a
   Git repo
2. BinSync's decompiler plugins pick up changes automatically
3. `rebrew sync --pull` reads BinSync State from the Git repo
4. Rebrew-specific fields (STATUS, SIZE, CFLAGS) stored as comments or
   in a custom artifact extension

**Effort:** High — requires rewriting sync.py's transport layer, mapping rebrew's
annotation model to BinSync's State model, handling bidirectional conflict
resolution differently.

### Option B: BinSync as Additional Sync Target (Alongside ReVa)

Keep ReVa MCP for Ghidra, add BinSync as an optional sync target for IDA/BinNinja.

**How it would work:**
1. New `rebrew sync --binsync-push` / `--binsync-pull` commands
2. Map rebrew Annotations to BinSync Functions + Comments
3. Rebrew-specific metadata stored as structured comments (e.g.
   `[rebrew] STATUS=EXACT SIZE=120 CFLAGS=/O2`)
4. BinSync repo lives alongside `rebrew-project.toml` (or configured path)

**Effort:** Medium — new sync backend, but existing ReVa sync untouched.

### Option C: Read-Only BinSync Import (One-Way)

Import BinSync State into rebrew annotations. No push back.

**How it would work:**
1. New `rebrew import-binsync <repo-path>` command
2. Reads BinSync's `functions/*.toml` and `structs/*.toml`
3. Creates skeleton `.c` files or updates existing annotations with names, types,
   comments from BinSync
4. One-time or periodic import — no ongoing sync

**Effort:** Low — read BinSync TOML files, map to rebrew Annotations.

### Option D: libbs as Decompiler Abstraction (Replace/Supplement binary_loader)

Use [libbs](https://github.com/binsync/libbs) (BinSync's underlying library)
as a decompiler interface for skeleton generation and type import.

**How it would work:**
1. `rebrew skeleton --backend binsync` uses libbs to decompile via any supported
   decompiler (not just Ghidra)
2. `rebrew sync` uses libbs's `DecompilerInterface` instead of ReVa MCP HTTP calls
3. Struct/type import via libbs's cross-decompiler type system

**Effort:** Medium-High — libbs dependency, new decompiler backend, but gains
IDA/BinNinja support "for free".

---

## Pros

### Cross-Decompiler Support
- **IDA Pro and Binary Ninja access** — rebrew currently only supports Ghidra.
  BinSync would enable teams using IDA or BinNinja to contribute function names,
  types, and comments back to the rebrew project.

### Git-Native Versioning
- **Full history of analysis changes** — every rename, retype, comment is a Git
  commit. Rollback, blame, and diff are free.
- **Offline-capable** — no live Ghidra/ReVa server required for sync.
- **Branch-per-analyst** — natural isolation for concurrent work.

### Proven Collaboration Model
- **Multi-user workflow** — BinSync was designed for CTF teams and research labs
  with multiple analysts working simultaneously.
- **Auto-sync** — changes propagate automatically without manual push/pull cycles.

### Complementary Data
- **Stack variables** — BinSync tracks local variable names and types, which
  rebrew currently doesn't import from Ghidra.
- **Enums and typedefs** — additional type information that could enrich skeleton
  generation.

### Active Ecosystem
- Maintained by the angr team (rebrew already uses angr for `rebrew prove`).
- Python-native — same language as rebrew, easy integration.
- libbs provides a clean decompiler-agnostic API.

---

## Cons

### Impedance Mismatch — Different Data Models

BinSync's model is **decompiler-centric** (functions, variables, types):
```toml
# BinSync: functions/10008880.toml
[info]
name = "bit_reverse"
addr = 268469376
size = 31

[header]
type = "int __cdecl bit_reverse(int x)"
```

Rebrew's model is **matching-centric** (marker + sidecar metadata):
```c
// FUNCTION: SERVER 0x10008880

int __cdecl bit_reverse(int x) { ... }  // symbol derived from C definition
```
```toml
# rebrew-functions.toml sidecar (found via walk-up, managed by CLI tools)
["0x10008880"]
status = "EXACT"
size = 31
cflags = "/O2 /Gd"
```

Rebrew-specific fields (`STATUS`, `CFLAGS`, `BLOCKER`, `SOURCE`) have no BinSync equivalent. They'd need to be stored as structured comments or custom
extensions, which is fragile and non-standard.

### Redundancy with Existing Ghidra Sync

`rebrew sync` already handles the Ghidra workflow comprehensively:
- Push/pull labels, signatures, structs, comments, data labels
- Conflict detection with `--accept-ghidra` / `--accept-local`
- Annotation-aware (preserves STATUS, CFLAGS, etc.)

Adding BinSync creates a **second sync system** to maintain, with different
semantics and edge cases.

### Ghidra Support is Weakest

BinSync's Ghidra plugin (PyGhidra mode, >= 12.0) has the most limitations:
- No enum push
- No auto-push comments
- PyGhidra dependency adds complexity

Since Ghidra is rebrew's primary decompiler, BinSync's strongest value
(IDA/BinNinja) isn't where most rebrew users work.

### Per-User Branches Don't Map to Decomp Matching

BinSync assumes multiple analysts working on **different functions simultaneously**.
Decomp matching is typically **one function at a time**, iterated until byte-exact.
The branch-per-user model adds overhead without clear benefit for solo or small-team
binary matching projects.

### Additional Dependencies

- `binsync` + `libbs` + `toml` + Git operations
- Version pinning concerns (libbs >= 2.15.6, Python >= 3.10)
- BinSync's 60 open issues suggest ongoing stability work

### No Compile/Verify Integration

BinSync knows nothing about:
- Compiler flags, compilation, byte matching
- MSVC6 toolchain under Wine
- The GA engine, flag sweeps, or symbolic proving
- reccmp annotation compatibility

All of rebrew's core value proposition is invisible to BinSync.

### Address Normalization Issues

BinSync normalizes addresses relative to the binary base. Rebrew uses absolute VAs
from the original binary. This mismatch requires careful translation and could cause
subtle bugs when the same binary is loaded at different bases in different decompilers.

---

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Data model mismatch loses rebrew metadata | High | Store rebrew fields as structured comments; accept lossy round-trip |
| Two sync systems to maintain | Medium | Clear documentation on when to use each |
| BinSync Ghidra plugin conflicts with ReVa | Medium | Test both running simultaneously |
| Address normalization bugs | Medium | Centralize VA translation in one module |
| Dependency churn (libbs API changes) | Low | Pin versions, isolate behind interface |
| User confusion (push to which system?) | Low | Clear CLI UX: `--binsync` flag |

---

## Recommendation

**Start with Option C (read-only import)**, then evaluate Option B if cross-decompiler
demand materializes.

### Rationale

1. **Low effort, high signal** — importing BinSync State (function names, types,
   comments) into rebrew annotations is straightforward and immediately useful for
   teams that use IDA/BinNinja for initial analysis.

2. **No disruption** — existing ReVa/Ghidra workflow is untouched. BinSync becomes
   an optional input source, not a replacement.

3. **Validates the model** — if the import proves valuable, upgrading to bidirectional
   sync (Option B) is a natural next step with real usage data.

4. **Avoids premature commitment** — BinSync's data model and rebrew's annotation
   model serve different purposes. Forcing bidirectional sync before understanding
   the mapping is risky.

### Proposed Implementation (Option C)

```
rebrew import-binsync <repo-path> [--dry-run] [--json]
```

1. Read `functions/*.toml` from BinSync repo
2. For each function with a VA in our registry:
   - Update the C function name if we have a `func_XXXXXXXX` placeholder
   - Import prototype if available
   - Import comments as NOTE annotations
3. Read `structs/*.toml` and append to `types.h`
4. Report: N functions updated, M structs imported, K conflicts skipped

### Future Path (Option B, if needed)

```
rebrew sync --binsync-push [--binsync-repo <path>]
rebrew sync --binsync-pull [--binsync-repo <path>]
```

Map rebrew annotations to BinSync State:
- `Annotation.symbol` ↔ `Function.name`
- `Annotation.prototype` ↔ `Function.header.type`
- `Annotation.note` ↔ `Comment.comment`
- `STATUS`, `CFLAGS` → stored as `[rebrew]` prefixed comment at function VA (from sidecar)

---

## References

- [BinSync GitHub](https://github.com/binsync/binsync)
- [libbs (decompiler abstraction)](https://github.com/binsync/libbs)
- [BinSync docs](https://binsync.net/)
- [Current rebrew Ghidra sync](GHIDRA_SYNC.md)
