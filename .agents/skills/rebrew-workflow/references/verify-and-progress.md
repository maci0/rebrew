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
rebrew lint src/bench/<file>.c       # lint one file (files are POSITIONAL)
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
rebrew verify --data --built build/bench
rebrew verify --whole-binary --built build/bench
rebrew verify --text --built build/bench
rebrew build check-text-placement --built build/bench
rebrew build check-data-placement --built build/bench
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
rebrew coverage build                          # write db/coverage-bench.toml (one per target)
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

`db/coverage-bench.toml` is the progress document the dashboards and the
sibling `recovery` UI read: functions with their `updated_by` / `updated_at`
stamp, globals, `verify_results` rows and the `history` change log. It is
gitignored build output: regenerate it with `rebrew coverage build`, never edit it,
and delete any older `db/coverage.db`, `db/data_bench.json` or `db/*.csv`
(`rebrew lint` reports them, W032). The canonical provenance lives in the
TOML stores: `UPDATED_BY` / `UPDATED_AT` describe ordinary changes, `ORIGINS`
records accepted external fields, and `VERIFICATION` records comparison inputs
and measurement time. The coverage document does not mirror those nested
provenance tables. Deleting derived coverage/cache files does not delete them.

## Compiled and prebuilt library providers

Separate library origin from build provider. A `LIBRARY` row identifies
library-derived code, not necessarily a prebuilt archive. Vendored or adapted
library bodies compiled by the project belong in the verification batch, even
when their source lives outside `reversed_dir`. Bind an identified header entry
with `rebrew library bind-source 0x<VA> references/library/file.c --symbol _native`;
this records the source/native-symbol identity through the managed metadata API.
`rebrew verify` and `rebrew test --all` then compile and compare it normally.
Never count an identified-only header's default EXACT as a source verification.
Prebuilt archive providers require a configured external archive and unique
native-symbol link-map evidence, and stay outside the
compile batch; unmatched providers remain unresolved. `--nolib` explicitly scopes
verification to game code. Compiled-library results do not count as game reversing.
