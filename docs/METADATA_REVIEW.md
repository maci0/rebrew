# Metadata & Sync Review — reccmp / rebrew / BinSync / Ghidra

Status: implemented (R1–R4 landed in the R1 sweep commit).  Scope: the per-function /
data / struct / library metadata layers, the two Ghidra-sync mechanisms, and
how rebrew's stores interleave with the reccmp and BinSync formats.  The
canonical store map lives in [METADATA.md](METADATA.md); this document is the
*redundancy audit* on top of it.

## 1. The landscape (verified against code)

| Layer | Store | Owns (canonical) |
|---|---|---|
| `.c` markers | `// FUNCTION: MODULE 0xVA` (+ LIBRARY/STUB/GLOBAL/DATA), `// SYMBOL:`, `// PROTOTYPE:` | Function **identity**, symbol, prototype — reccmp-compatible |
| Function metadata | `rebrew-functions.toml` (keys `MODULE.0xVA`) | STATUS, CFLAGS, TOOLCHAIN, BLOCKER/DELTA, NOTE, GHIDRA, SKIP, GLOBALS, SOURCE, PROVE_CONSTRAINTS |
| Data/globals | `rebrew-data.toml` | GLOBAL/DATA name, size, section, note |
| Library overrides | `rebrew-libraries.toml` (walk-up) | Per-library toolchain/flags |
| Structs | `.h` headers (canonical C) + recovered typedefs | Struct definitions |
| Registry (derived) | `function_structure.json`, `ghidra_data_labels.json`, `functions.txt` | Sizes/boundaries/names provenance |
| **BinSync interchange** | `functions/*.toml`, `global_vars.toml`, `structs/*.toml` | Names, prototypes, sizes, comments, globals, structs — git-versioned shared state |
| **Ghidra sync (ReVa MCP)** | live RPC + `.rebrew/ghidra_sync_state.json` | push: labels/comments/bookmarks/structs/functions/prototypes; pull: renames, NOTE/GHIDRA, PROTOTYPE, structs, params, data |

Multi-binary is already sound: keys are module-prefixed (`"server.dll.0xVA"`,
`"client.exe.0xVA"`) in **one** `rebrew-functions.toml` per metadata root;
targets share the metadata dir with separate `reversed_dir`s.

## 2. Redundancy inventory

### R1 — Two complete Ghidra-sync implementations (the headline)
`ghidra/commands.py` implements a full field-level sync over ReVa MCP
(create-label / set-comment / set-bookmark / parse-c-structure /
create-function / set-function-prototype push; rename / NOTE / GHIDRA /
PROTOTYPE / structs / params / data pull) **and** `binsync_export/import/diff`
implements the same field set (names→renames, comments→NOTE, prototypes,
structs, globals) over the BinSync state dir.  Two code paths map the same
facts to the same destinations; only the transport differs.  A pushed-op hash
cache (`.rebrew/ghidra_sync_state.json`) exists solely for the MCP path.

**Recommendation: make the BinSync state dir the single interchange for
field-level Ghidra sync** — `rebrew sync push` = binsync-export, `rebrew sync
pull` = binsync-import.  Keep ReVa MCP **only** for the operations the BinSync
Ghidra plugin cannot express: `create-function`, bookmarks, and live data
pulls.  This deletes roughly half of `ghidra/commands.py`, the MCP sync-state
cache, and one of the two name/comment/prototype mappings.  The Ghidra-side
counterpart is BinSync's own plugin — rebrew stops maintaining a second
client for fields the plugin already covers.

### R2 — Write-only `[rebrew] STATUS=… CFLAGS=…` shim in BinSync exports
`binsync_export._rebrew_comment()` embeds rebrew-only STATUS/CFLAGS as a
`[rebrew]` comment inside the state TOMLs, but **nothing reads it back** —
`binsync_import` handles names/prototypes/globals/structs only.  The data is
duplicated from `rebrew-functions.toml` into the shared state with no
consumer.  It also *cannot* be restored: STATUS is verify-earned (0444-locked,
unbacked claims demoted), so importing a status from a shared state would
violate the earned-status rule.

**Recommendation: drop the `[rebrew] STATUS/CFLAGS` comment from BinSync
exports** (keep the state clean-BinSync; optionally keep a non-authoritative
`note`).  BinSync compatibility is unaffected — BinSync ignores the comment
today.

### R3 — `SIZE`: reccmp-compatibility tension
`SIZE` is in `METADATA_FIELDS`, so lint `W019` flags inline `// SIZE:` as
deprecated — but reccmp's annotation format reads `// SIZE:` from the `.c`,
and rebrew's own fixtures still carry it inline.  Migrating SIZE to TOML
silently breaks reccmp's size hints (it falls back to the function list/PDB).

**Recommendation: keep `// SIZE:` inline as the reccmp-native place.**  SIZE
is a compile contract (stable, identity-adjacent), not volatile like STATUS —
it does not belong in the "migrate to TOML" set.  Either remove `SIZE` from
the W019-migrated set or special-case it (warn only when TOML and inline
disagree).  This removes the "two homes for SIZE" ambiguity.

### R4 — Globals have three homes (two of them Ghidra-originated)
`rebrew-data.toml` (canonical) ← `ghidra_data_labels.json` (Ghidra export,
input for the registry) ← BinSync `global_vars.toml` (interchange), plus
derived `rebrew_globals.h` and grid/DB copies.  The two Ghidra-originated
copies are the redundancy.  With R1 (BinSync-primary), `ghidra_data_labels.json`
shrinks to a pure registry input and the interchange copy is the BinSync one.

### R5 — Structs have no rebrew-canonical store (by design, and fine)
Struct knowledge lives in: `.h` headers (canonical C), the Ghidra program
(parse-c-structure push), BinSync `structs/*.toml` (interchange), and
recovered typedefs (`struct_recover` output).  Rebrew already treats BinSync
as the struct interchange — this supports R1 rather than resisting it.

### Verified-consistent (not redundancies)
- **PROTOTYPE** is inline-only (`// PROTOTYPE:`), not in `METADATA_FIELDS`;
  both writers (ghidra pull, binsync-import) route through the same
  `update_annotation_key` → single home.  No change.
- **Name** has one canonical home (the `.c` marker); registry `list_name` /
  `ghidra_name` are provenance columns, BinSync `info.name` is interchange.
- **STATUS** precedence (metadata > verify-cache measured result > snapshot)
  is the earned-status machinery, documented in METADATA.md.
- **CFLAGS/TOOLCHAIN** resolution chain (per-function → per-library →
  project) is a single resolver.
- Derived stores (`CATALOG.md`, `db/data_<target>.json`, `coverage.db`) are
  documented build outputs, not competing truths.

## 3. Target architecture (after the changes)

- **Canonical (rebrew-owned):** `.c` markers (identity + SYMBOL + PROTOTYPE +
  SIZE, all reccmp-compatible) · `rebrew-functions.toml` (volatile per-
  function) · `rebrew-data.toml` (globals) · `.h` headers (structs).
- **Interchange (team/Ghidra):** the BinSync state dir — the single place
  names, comments, prototypes, structs, and globals cross the boundary.
- **Ghidra structural ops (MCP only):** `create-function`, bookmarks, live
  data pulls — what BinSync's plugin does not express.
- **Removed:** the `[rebrew] STATUS/CFLAGS` shim, the MCP field-level sync
  machinery + its sync-state cache, the SIZE migration ambiguity.

## 4. Compatibility guarantees

- **reccmp:** `// FUNCTION: MODULE 0xVA` + `// SIZE:` stay inline; STATUS/
  CFLAGS/etc. remain TOML-only (reccmp does not read them).
- **BinSync:** the state-dir format is untouched (functions/global_vars/
  structs TOMLs); only the write-only `[rebrew]` comment is dropped.

## 5. Sequencing (if adopted)

1. **R3** — SIZE inline decision (small, unblocks lint clarity).
2. **R2** — drop the `[rebrew]` shim (small, removes dead data).
3. **R1** — BinSync-primary sync, phased: (a) `rebrew sync pull` = binsync-
   import, (b) `rebrew sync push` = binsync-export, (c) delete the MCP
   field-level code paths + sync-state cache, keeping create-function/
   bookmarks on MCP.
4. **R4** — fold `ghidra_data_labels.json` into the registry-input role.
