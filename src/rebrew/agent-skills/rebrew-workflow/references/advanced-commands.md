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
| `rebrew source import-related` | Import matched functions from another target (same code, different VAs). `--shared` stacks the marker onto the shared file in `src/shared` (one file, one marker per target) instead of copying; prefer it when targets share one codebase. |
| `rebrew build check-exports` | Verify the recompiled binary's export table matches the original target. |
| `rebrew build order-sources` | Order source files by their first function's original VA (position-aligned `.text`). |
| `rebrew build calibrate-bss` | Calibrate a BSS tail pad so the raw link's `.data` VirtualSize matches the reference. |
| `rebrew build symbol-stubs` | Generate a stub TU for unresolved linker symbols (LNK2001/LNK2019). |
| `rebrew build link-stubs` | Generate a `link_stubs.c`-style BSS placeholder TU from the data metadata. |
| `rebrew source inline-strings` | Inline string-literal globals (`s_<hint>_<0xADDR>`) from the reference binary. |
| `rebrew build sweep-link-flags` | Sweep LINK options to reproduce the reference PE header (find stamp-only fields). |
| `rebrew build cmake-toolchain` | Write a CMake toolchain file that drives a docker toolchain via `rebrew build driver`. |
| `rebrew build cmake-flags` | Write per-file CFLAGS from `rebrew-functions.toml` as a CMake include. |
| `rebrew build cmake-sources` | Write the target's marker-selected source list as a CMake include. |
| `rebrew source migrate-markers` | ADR 023: move inline markers into `rebrew-functions.toml` and strip the `.c` to pure C (idempotent, `--dry-run` previews). |
| `rebrew build check` | Verify `build/` still matches what CMake generated (catches a hand-edited `build.make`). |
| `rebrew binsync init/diff/overlay/push/pull` | BinSync state repo: create, divergence report, overlay a related target's names, git-backed export/import. Field sync: rebrew-ghidra-sync. |
| `rebrew binsync init` / `binsync-diff` / `binsync-overlay` | Same commands as `rebrew binsync init/diff/overlay`; prefer the group form. |
| `rebrew binsync export` / `binsync-import` | Low-level state export/import; prefer `rebrew sync push / rebrew sync pull --state-dir`. |
| `rebrew dev refactor` | Analyse the source tree and suggest refactoring opportunities. |
| `rebrew recommend` | Deterministic advice lanes (TU layout, hygiene, next action); `--apply` fixes safe lanes. |
| `rebrew binary analyze` | One-shot intelligence dossier for a target binary (layout, strings, imports, coverage, FLIRT). |
| `rebrew decompile` | Decompile a function VA (`--decompiler`: auto, r2ghidra, r2dec, ghidra, kuna, m2c; default kuna). |
| `rebrew source fix` | Make raw decompiler output compilable (DecBench-style fixup). |
| `rebrew diagnose drift` | Localise where compiled bytes drift from reference, from branch targets. |
| `rebrew binary switches` | Decode jump-table switch dispatches in a function (case → handler map). |
| `rebrew match solutions` | Query the GA solutions database (`.rebrew/ga_runs.jsonl` wins + run history). |
| `rebrew build residue` | Measure linked byte-identity residue after postlink fixers. |
| `rebrew binary xrefs` | Show cross-references (callers/callees) to/from a target address. |
| `rebrew cache` | Manage the compile result cache (`rebrew cache stats` to inspect; `clear` prompts before deleting, `--force` skips the prompt). |
| `rebrew binary imports list` | List import-table symbols (PE IAT/ELF/NE) and detect/mark import stubs (`--mark`). |
| `rebrew binary strings` | Extract strings from binary with cross-references (`--xref`, `--section`). |
| `rebrew library identify` | Batch identify library functions (FLIRT + imports + CRT) into `library_<module>.h`. |
| `rebrew source import-splat` | Seed a project from a splat YAML config (names, layout, annotations); dry run unless `--write`. |
| `rebrew binary resource compare/extract` | Byte-compare two PE `.rsrc` sections (`compare` exits 1 on drift) or dump the raw bytes. |


## Compile a library function from project sources

`rebrew library bind-source VA SOURCE --symbol NATIVE_SYMBOL --dry-run`
previews binding an identified library declaration to an existing project
C/C++ translation unit. Remove `--dry-run` to accept the identity through the
locked writer, then verify the function normally. Library ancestry and the
actual code provider remain separate; a declaration alone never proves a
prebuilt archive member owns the bytes.
