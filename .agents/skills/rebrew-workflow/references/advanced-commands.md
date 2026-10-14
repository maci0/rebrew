# Advanced / linkage commands

Manual inspection and linkage tools outside the main reverse loop. Run
`rebrew <cmd> --help` for options; structured output uses `--json`.

| Command | Purpose |
|---------|---------|
| `rebrew binary function` | Per-function recon dossier: callers, callees, strings, imports. |
| `rebrew diagnose config` | Explain why a function compiles with its toolchain and flags (resolution trace). |
| `rebrew diagnose stack` | Compare the compiled function's stack frame against the target binary. |
| `rebrew binary pdb show` | Extract compiler version, flags, and function names from a sibling PDB. |
| `rebrew types recover` | Recover struct definitions from decompiler output (offset evidence to typedefs). |
| `rebrew source document-unmatched` | Document unmatched functions as STUB skeletons plus blockers. Writes one `.c` + BLOCKER per unmatched function: preview with `--dry-run` and check that the file count fits the authorized scope. `--backfill-blockers` adds a BLOCKER to existing STUBs. |
| `rebrew similarity binary` | Whole-binary structural similarity against another binary (versions, DLL+EXE). |
| `rebrew source import-related` | Import matched functions from another target (same code, different VAs). `--shared` records the destination `MODULE.0xVA` row on the shared file in `src/shared` (one file, one row per target) instead of copying; prefer it when targets share one codebase. |
| `rebrew build check-exports` | Verify the recompiled binary's export table matches the original target. |
| `rebrew build order-sources` | Order source files by their first function's original VA (position-aligned `.text`). |
| `rebrew build calibrate-bss` | Calibrate a BSS tail pad so the raw link's `.data` VirtualSize matches the reference. |
| `rebrew library inspect` | List a `.lib`'s members: sections (size, alignment, COMDAT), defined, COMMON and undefined symbols, short imports; `--refs`/`--defines SYMBOL` find who pulls or supplies a symbol when reproducing link order. |
| `rebrew build symbol-stubs` | Generate a stub TU for unresolved linker symbols (LNK2001/LNK2019). |
| `rebrew build link-stubs` | Generate a `link_stubs.c`-style BSS placeholder TU from the data metadata. |
| `rebrew source inline-strings` | Inline string-literal globals (`s_<hint>_<0xADDR>`) from the reference binary; `--named` inlines a file's own `char s_x[] = "..."` pool. |
| `rebrew build sweep-link-flags` | Sweep LINK options to reproduce the reference PE header (find stamp-only fields). |
| `rebrew build cmake-toolchain` | Write a CMake toolchain file that drives a docker toolchain via `rebrew build driver`. |
| `rebrew build cmake-flags` | Write per-file CFLAGS from `rebrew-functions.toml` as a CMake include. |
| `rebrew build cmake-sources` | Write the target's metadata-selected source list as a CMake include. |
| `rebrew source register` | Register optional ADDRESS anchors above C declarations in format-2 stores; `--dry-run` previews. Sources and headers are scanned. |
| `rebrew build check` | Verify `build/` still matches what CMake generated (catches a hand-edited `build.make`). |
| `rebrew binsync init` | Create the BinSync state repository. |
| `rebrew binsync diff` | Report field divergence and provenance freshness. |
| `rebrew binsync overlay` | Import a related target's field evidence. Preview with `--dry-run`. |
| `rebrew binsync push` | Export fields with Git commit and push support. Field sync: rebrew-ghidra-sync. |
| `rebrew binsync pull` | Pull Git state and reconcile its fields. Preview with `--dry-run`. |
| `rebrew binsync export` | Export local state; Git actions are opt-in. |
| `rebrew binsync import` | Reconcile local state without pulling Git. |
| `rebrew dev refactor` | Analyze Python files under `--repository` and suggest contributor refactoring opportunities. |
| `rebrew recommend` | Deterministic advice lanes (TU layout, hygiene, next action); `--apply` fixes safe lanes. |
| `rebrew binary analyze` | One-shot intelligence dossier for a target binary (layout, strings, imports, coverage, FLIRT). |
| `rebrew decompile` | Decompile a function VA (`--decompiler`: auto, r2ghidra, r2dec, ghidra, kuna, m2c; default kuna). |
| `rebrew source fix` | Make raw decompiler output compilable (DecBench-style fixup). |
| `rebrew diagnose drift` | Localize where compiled bytes drift from reference, from branch targets. |
| `rebrew binary switches` | Decode jump-table switch dispatches in a function (case → handler map). |
| `rebrew match solutions` | Query the GA solutions database (`.rebrew/ga_runs.jsonl` wins + run history). |
| `rebrew build residue` | Measure linked byte-identity residue after postlink fixers. |
| `rebrew binary xrefs` | Show cross-references (callers/callees) to/from a target address. |
| `rebrew cache` | Manage the compile result cache (`rebrew cache stats` to inspect; `clear` prompts before deleting, `--force` skips the prompt). |
| `rebrew binary imports list` | List import-table symbols (PE IAT/ELF/NE) and detect import stubs. |
| `rebrew binary imports mark` | Record detected import stubs as library identifications. Preview with `--dry-run`. |
| `rebrew binary strings` | Extract strings from binary with cross-references (`--xref`, `--section`). |
| `rebrew library identify` | Batch identify library functions (FLIRT + imports + CRT) into `library_<module>.h`. |
| `rebrew source import-splat` | Seed a project from a splat YAML config (names, layout, and dedicated metadata); dry run unless `--apply`. |
| `rebrew binary resource compare/extract` | Byte-compare two PE `.rsrc` sections (`compare` exits 1 on drift) or dump the raw bytes. |


## Compile a library function from project sources

`rebrew library bind-source VA SOURCE --symbol NATIVE_SYMBOL --dry-run`
previews binding an identified library declaration to a project translation
unit, which makes the provider built from source. Remove `--dry-run` to accept
the identity through the locked writer, then verify the function normally. A
unique member of a configured external archive is the statically linked
provider. Origin and provider stay separate; a declaration with neither stays
unresolved.

## Reproduce a vendored library tree

`rebrew library vendor MANIFEST...` checks pinned pristine files plus ordered
patches. Use `--apply` only to regenerate the declared output trees after editing
patches. All manifests stage before any writes. Paths are root-relative, patch
paths are manifest-relative, and GNU patch is required when patches are listed.
Keep the manifest, checksum list, pristine sources and reviewed patches as inputs;
do not edit the generated source tree or patch a stock archive. The archive URL
and SHA-256 document provenance; the command verifies the unpacked file pins.

## Artifact previews and machine output

- `binary functions [BINARY]` uses the configured target when the path is omitted;
  an explicit binary takes precedence and works outside a project. PDB operations
  still take the binary beside the PDB.
- `binary extract show VA --dry-run` plans the size and output path without
  parsing or extracting bytes. Its explicit address has no batch size filters.
- `binary asm show VA --dry-run` and `binary asm batch --dry-run` write no source
  or metadata and do not run NASM verification. A written `--inline-c` artifact
  also records function metadata. NASM `show --output FILE --json` writes FILE
  and reports it; batch JSON emits one summary with planned/written file paths.
- `coverage serve --print-url --json` probes the dashboard URL without starting
  a server. JSON without `--print-url` is an error.
- `cfg raw --format toml` and `--json` are mutually exclusive.
- `build symbol-stubs` defaults to `src/symbol_stubs.c`; `build link-stubs`
  defaults to `src/link_stubs.c`.
