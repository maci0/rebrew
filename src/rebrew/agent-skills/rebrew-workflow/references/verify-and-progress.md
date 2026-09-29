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
rebrew lint src/<target>/<file>.c       # lint one file (files are POSITIONAL)
rebrew lint --json                      # annotation correctness
rebrew lint --fix                       # migrate inline metadata; drop W029-redundant cflags
rebrew lint --fix --dry-run
rebrew lint --summary
rebrew lint --quiet                     # errors only
rebrew orphans                          # metadata blocks with no source marker
rebrew orphans --prune --dry-run        # preview prune (EXACT/RELOC/PROVEN held back)
rebrew verify --prune-orphans --dry-run # preview the same prune inside a verify pass
rebrew verify --prune-orphans           # deletes orphan blocks; --dry-run / --no-promote only counts
rebrew orphans drop 0x<VA> --dry-run    # preview one VA's block (functions + data)
rebrew orphans drop 0x<VA>              # delete it; no undo, confirm with the user first
rebrew types                            # struct layouts vs decompiler evidence
rebrew types apply-type <file> --param N --type T
rebrew verify --data --built build/<target>
rebrew verify --whole-binary --built build/<target>
rebrew verify --text --built build/<target>
rebrew text-audit --built build/<target>
rebrew verify-placement --built build/<target>
```

`rebrew verify` syncs STATUS (SKIP preserved, PROVEN replaced by the byte result).
EXACT/RELOC clears BLOCKER unless the source still has `__asm`, `_asm`, or `__emit`
(kept; lint W020). Exit 1 if any function fails. `passed` counts EXACT/RELOC only.
`rebrew lint` exit 1 on errors. Link-only files use `// SUPPORT: <MODULE> <reason>`.

`verify --data` suppresses DRIFT status write-backs unless `--raw-link` says the
built binary is a raw link; without it `rebrew todo --category data-drift` stays empty.

## Coverage / interchange

```bash
rebrew build-db                          # write db/coverage-<target>.toml (one per target)
rebrew symbol-addrs --output symbol_addrs.csv
rebrew context --output ctx.c
rebrew report --decomp-dev report.json
rebrew decompme <file>.c --dry-run     # payload summary, no upload
rebrew decompme <file>.c                # uploads the function + context to decomp.me; prints claim URL
```

`decompme` sends the function body, its context, and the target object bytes to a
third-party site. Run it only when the user asks for a decomp.me scratch, and
`--dry-run` first if they have not said where the source may go.

`rebrew verify --compare` uses `.rebrew/verify_baseline.toml` (exit 1 on
regression). First run warns and skips the diff.

`db/coverage-<target>.toml` is the progress document the dashboards and the
sibling `recovery` UI read: functions with their `updated_by` / `updated_at`
stamp, globals, `verify_results` rows and the `history` change log. It is
gitignored build output: regenerate it with `rebrew build-db`, never edit it,
and delete any older `db/coverage.db`, `db/data_<target>.json` or `db/*.csv`
(`rebrew lint` reports them, W032). The canonical provenance lives in the
TOML stores: `UPDATED_BY` / `UPDATED_AT` are written by the tool that made the
change, in `rebrew-functions.toml` and `rebrew-data.toml` alike.
