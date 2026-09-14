# Metadata & Sync Review — reccmp / rebrew / BinSync / Ghidra

Status: implemented (R1–R4 all landed).  Scope: the per-function /
data / struct / library metadata layers, the two Ghidra-sync mechanisms, and
how rebrew's stores interleave with the reccmp and BinSync formats.  The
canonical store map lives in [METADATA.md](METADATA.md); this document is the
*redundancy audit* on top of it.  Recommendations below are struck through
as landed; the surviving text is the as-built record.

## 1. The landscape (verified against code)

| Layer | Store | Owns (canonical) |
|---|---|---|
| `.c` markers | `// FUNCTION: MODULE 0xVA` (+ LIBRARY/STUB/GLOBAL/DATA), `// SIZE:` (reccmp-native compile contract, co-read) | Function **identity** — reccmp-compatible |
| Function metadata | `rebrew-functions.toml` (keys `MODULE.0xVA`) | STATUS, SIZE, CFLAGS, TOOLCHAIN, BLOCKER/DELTA, NOTE, GHIDRA, ANALYSIS, SKIP, GLOBALS, LOCALS, COMMENTS, SOURCE, PROVE_CONSTRAINTS |
| Data/globals | `rebrew-data.toml` | GLOBAL/DATA name, type, size, section, note, status |
| Library overrides | `rebrew-libraries.toml` (walk-up) | Per-library toolchain/flags |
| Structs | `.h` headers (canonical C) + recovered typedefs | Struct definitions |
| Registry (derived) | `function_structure.json`, `ghidra_data_labels.json` | Sizes/boundaries/names provenance |
| **BinSync interchange** | `functions/*.toml`, `global_vars.toml`, `structs/*.toml` | Names, prototypes, sizes, comments, globals, structs — git-versioned shared state |
| **Ghidra sync (ReVa MCP)** | structural ops only: `create-function`, bookmarks, live data pulls | (field-level sync removed — BinSync-primary) |

Multi-binary is already sound: keys are module-prefixed (`"server.dll.0xVA"`,
`"client.exe.0xVA"`) in **one** `rebrew-functions.toml` per metadata root;
targets share the metadata dir with separate `reversed_dir`s.

## 2. Redundancy inventory (all landed — historical record)

### R1 — Two complete Ghidra-sync implementations (landed)

`ghidra/commands.py` *used to* implement a full field-level sync over ReVa
MCP (create-label / set-comment / set-bookmark / parse-c-structure /
create-function / set-function-prototype push; rename / NOTE / GHIDRA /
PROTOTYPE / structs / params / data pull) alongside the BinSync state-dir
path.  Landed: BinSync is now the single interchange for field-level sync;
ReVa MCP keeps only `create-function`, bookmarks, and live data pulls
(`ghidra/commands.py` holds just those), and the sync-state cache is gone.

### R2 — Write-only `[rebrew] STATUS=… CFLAGS=…` shim in BinSync exports (landed)

`binsync.export._rebrew_comment()` *used to* embed rebrew-only STATUS/CFLAGS
as a `[rebrew]` comment inside the state TOMLs with no reader.  Landed:
dropped — the state is clean BinSync (STATUS stays verify-earned in
`rebrew-functions.toml`).

### R3 — `SIZE`: reccmp-compatibility tension (landed)

`SIZE` *used to* sit in the W019-migrated set while reccmp reads `// SIZE:`
from the `.c`.  Landed: `// SIZE:`/`// CFLAGS:` stay inline as the
reccmp-native contract (an external build reads the file directly) and the
TOML value is an override — W019 warns only on inline↔metadata disagreement.

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
- **Name** has one canonical home (the `.c` marker); registry `list_name` /
  `ghidra_name` are provenance columns, BinSync `info.name` is interchange.
- **STATUS** precedence (metadata > verify-cache measured result > snapshot)
  is the earned-status machinery, documented in METADATA.md.
- **CFLAGS/TOOLCHAIN** resolution chain (per-function → per-library →
  project) is a single resolver.
- Derived stores (`db/data_<target>.json`, `coverage.db`) are
  documented build outputs, not competing truths.

## 3. Target architecture (as built)

- **Canonical (rebrew-owned):** `.c` markers (identity: `// FUNCTION: MODULE
  0xVA`, plus co-read `// SIZE:`/`// CFLAGS:`) · `rebrew-functions.toml`
  (volatile per-function) · `rebrew-data.toml` (globals) · `.h` headers
  (structs).
- **Interchange (team/Ghidra):** the BinSync state dir — the single place
  names, comments, prototypes, structs, and globals cross the boundary.
- **Ghidra structural ops (MCP only):** `create-function`, bookmarks, live
  data pulls — what BinSync's plugin does not express.
- **Removed:** the `[rebrew] STATUS/CFLAGS` shim, the MCP field-level sync
  machinery + its sync-state cache, the SIZE migration ambiguity,
  `functions.txt`, `CATALOG.md` generation.

## 4. Compatibility guarantees

- **reccmp:** `// FUNCTION: MODULE 0xVA` + `// SIZE:` stay inline; STATUS/
  BLOCKER/etc. remain TOML-only (reccmp does not read them); SIZE/CFLAGS
  are co-read (external builds read the `.c` directly).
- **BinSync:** the state-dir format is untouched (functions/global_vars/
  structs TOMLs); only the write-only `[rebrew]` comment is dropped.

## 5. Sequencing (landed, in this order)

1. **R3** — SIZE inline decision (small, unblocks lint clarity).
2. **R2** — drop the `[rebrew]` shim (small, removes dead data).
3. **R1** — BinSync-primary sync: `rebrew sync pull` = binsync-
   import, `rebrew sync push` = binsync-export; MCP field-level code paths
   + sync-state cache deleted, keeping create-function/
   bookmarks on MCP.
4. **R4** — `ghidra_data_labels.json` folded into the registry-input role.
