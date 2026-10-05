# Verify / lint / interchange (progress tools)

## Core

```bash
rebrew doctor                           # toolchain/config health (run first on breakage)
rebrew verify --summary                 # summary table with match %
rebrew verify --json                    # bulk compile + diff all reversed functions
rebrew verify --jobs 8 --output report.json       # parallel compile, save report
rebrew verify --compare --json          # regressions vs last baseline
rebrew verify --watch                   # re-verify on every file change
rebrew verify --full --json             # ignore cache
rebrew lint src/test/<file>.c       # lint one file (files are POSITIONAL)
rebrew lint --json                      # annotation correctness
rebrew lint --fix                       # migrate inline metadata; drop W029-redundant cflags
rebrew lint --fix --dry-run
rebrew lint --summary
rebrew lint --quiet                     # errors only
rebrew orphans list # metadata rows whose source file is missing
rebrew orphans prune --dry-run # preview prune (EXACT/RELOC/PROVEN held back)
rebrew verify --prune-orphans --dry-run # preview the same prune inside a verify pass
rebrew verify --prune-orphans           # deletes orphan blocks; --dry-run / --no-promote only counts
rebrew orphans drop 0x<VA> --dry-run # preview one VA's block (functions + data)
rebrew orphans drop 0x<VA> # delete only when this removal is explicitly authorized; no undo
rebrew types check # struct layouts vs decompiler evidence
rebrew types apply <file> --param N --type T
rebrew verify --data --built build/test
rebrew verify --whole-binary --built build/test
rebrew verify --text --built build/test
rebrew build check-text-placement --built build/test
rebrew build check-data-placement --built build/test
```

`rebrew verify` syncs STATUS (SKIP preserved, PROVEN replaced by the byte result).
EXACT/RELOC clears BLOCKER unless the source still has `__asm`, `_asm`, or `__emit`
(kept; lint W020). Exit 1 if any function fails. `passed` counts EXACT/RELOC only.
`rebrew lint` exit 1 on errors. Link-only files use `// SUPPORT: <MODULE> <reason>`.

`verify --data` reports comparisons but suppresses all stored data verdict and
evidence writes unless `--raw-link` acknowledges the built image, or configured
`raw_link` selects it. Existing stored verdicts remain unchanged without that
acknowledgment. Compare the raw link to avoid counting postlink-copied bytes.

## Coverage / interchange

```bash
rebrew coverage build                          # write db/coverage-test.toml (one per target)
rebrew export symbols --output symbol_addrs.csv
rebrew export context --output ctx.c
rebrew coverage report --decomp-dev report.json
rebrew export decompme <file>.c --dry-run     # payload summary, no upload
rebrew export decompme <file>.c                # uploads the function + context to decomp.me; prints claim URL
```

`decompme` sends the function body, its context, and the target object bytes to a
third-party site. Run it only when the user asks for a decomp.me scratch, and
`--dry-run` first if they have not said where the source may go.

`rebrew verify --compare` uses `.rebrew/verify_baseline.toml` (exit 1 on
regression). First run warns and skips the diff.

`db/coverage-test.toml` is the progress document the dashboards and the
sibling `recovery` UI read: functions with their `updated_by` / `updated_at`
stamp, globals, `verify_results` rows and the `history` change log. It is
gitignored build output: regenerate it with `rebrew coverage build`, never edit it,
and delete any older `db/coverage.db`, `db/data_test.json` or `db/*.csv`
(`rebrew lint` reports them, W032). The canonical provenance lives in the
TOML stores: `UPDATED_BY` / `UPDATED_AT` describe ordinary changes, `ORIGINS`
records accepted external fields, and `VERIFICATION` records comparison inputs
and measurement time. The coverage document does not mirror those nested
provenance tables. Deleting derived coverage/cache files does not delete them.

## Library origin and the build provider

`LIBRARY` records origin. It does not choose how the bytes are supplied.

- Built from source: the row's `file` is a project `.c`, including a vendored
  body outside `reversed_dir`, or `rebrew library bind-source` names one.
  Verify compiles and compares it. Those verdicts stay out of the game
  progress count.
- Statically linked: a unique native symbol in a configured external archive
  appears in the raw link map. The header declaration is not compiled.
- Unresolved: a declaration with neither. A name, a VA, or an archive name
  alone is not a provider.

When a source identity and a map entry both exist, the source wins.
`--nolib` drops every library-origin row, source-built and statically linked.
A header with no source binding is skipped as a declaration. Never count an
identified-only header's default EXACT as a source verification.

Bind a header to source with
`rebrew library bind-source 0x<VA> references/library/file.c --symbol _native`.
The writer records the source and native symbol. Sources may live outside
`reversed_dir`.
