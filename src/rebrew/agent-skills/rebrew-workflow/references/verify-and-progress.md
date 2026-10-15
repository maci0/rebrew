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
rebrew lint --fix                       # drop W029-redundant cflags; source metadata tags are errors
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
rebrew verify --data --built build/<target>
rebrew verify --whole-binary --built build/<target>
rebrew verify --text --built build/<target>
rebrew build check-text-placement --built build/<target>
rebrew build check-data-placement --built build/<target>
```

`rebrew verify` syncs STATUS (SKIP preserved, PROVEN replaced by the byte result).
EXACT/RELOC clears BLOCKER unless the source still has `__asm`, `_asm`, or `__emit`
(kept; lint W020). Exit 1 if any function fails. `passed` counts EXACT/RELOC only.

After a link that is byte-identical to the reference (`cmp` equal, or
`verify --whole-binary` match on the raw link), run
`rebrew verify --text --raw-link --built <raw link>`: every RELOC function the
image places at its VA with identical bytes becomes linked EXACT, and
`text.linked.kept_reloc` names the rest with a reason. Without the raw-link
acknowledgement it counts them and writes nothing. A rebuilt image with
different bytes returns them to RELOC on the next verify; re-run the promotion.
`rebrew lint` exits 1 on errors. Record link-only file purposes with
`rebrew source register <file> --support "<reason>"`; the purpose lives in
`rebrew-source.toml`.

`verify --data` reports comparisons but suppresses all stored data verdict and
evidence writes unless `--raw-link` acknowledges the built image, or configured
`raw_link` selects it. Existing stored verdicts remain unchanged without that
acknowledgment. Compare the raw link to avoid counting postlink-copied bytes.

## Coverage / interchange

```bash
rebrew coverage export --output snapshots/                          # optional portable snapshots for offline use
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

Local dashboards read canonical project metadata, inventory and binaries directly.
Run `rebrew coverage serve` or `recoverage serve` inside the project; there is no
`db_dir` setting or prerequisite export. Optional portable snapshots are generated
with `rebrew coverage export --output snapshots/`; serve them with
`rebrew coverage serve --snapshots snapshots/` or set
`RECOVERAGE_SNAPSHOTS` for Recoverage. Comparison writers record durable status
transitions in function metadata. Preview and run
`rebrew coverage import-history --snapshots db/ --dry-run` before retiring older
exports, then repeat without `--dry-run`. Keep inventory JSON if configured there.
Ordinary edit stamps, external origins and verification evidence remain separate
canonical facts; deleting derived views never deletes them.

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
`--skip-libraries` drops every library-origin row, source-built and statically linked.
A header with no source binding is skipped as a declaration. Never count an
identified-only header's default EXACT as a source verification.

Bind a header to source with
`rebrew library bind-source 0x<VA> references/library/file.c --symbol _native`.
The writer records the source and native symbol. Sources may live outside
`reversed_dir`.

`STATUS_HISTORY` is comparison evidence: accepted verdict transitions record it
atomically. Generic metadata setters cannot edit it. Import older portable events
with `coverage import-history` before retiring exports; automatic source cleanup
preserves identities carrying this history.

For a shared source, `rebrew test FILE --source-targets --json` or
`rebrew verify FILE --source-targets --json` preflights exact bindings and runs
only eligible targets, with explicit skip reasons. FILE must be an existing
current-directory-relative or absolute path, including with `verify --root`.
Malformed target inputs fail independently; an entirely unbound scope fails.
Use `--all-targets` when an absent binding should itself be an error.
