# CLI migration: domains and explicit operations

The October 2026 CLI reorganization is a breaking change with no old-path aliases.
[ADR 028](adr/028-cli-domains-and-explicit-operations.md) records the decision;
[CLI.md](CLI.md) documents the current command surface.

## Route mapping

Unlisted daily commands retain their root paths. Build protocol callers must
regenerate their files; appending command words to an executable pathname is
incorrect. Entries that now have explicit operations are expanded below.

| Previous route (after `rebrew`) | Current route |
| --- | --- |
| `rename` | `rebrew source rename` |
| `migrate-markers` | `rebrew source migrate-markers` |
| `fix` | `rebrew source fix` |
| `recover-structs` | `rebrew types recover` |
| `postlink` | `rebrew build postlink` |
| `stack-cmp` | `rebrew diagnose stack` |
| `asm` | `rebrew binary asm show` |
| `switch` | `rebrew binary switches` |
| `gen-layout` | `rebrew build layout` |
| `cmake-toolchain` | `rebrew build cmake-toolchain` |
| `cmake-driver` | `rebrew build driver` |
| `objdiff-build` | `rebrew build objdiff-driver` |
| `cmake-flags` | `rebrew build cmake-flags` |
| `cmake-sources` | `rebrew build cmake-sources` |
| `build-check` | `rebrew build check` |
| `order-sources` | `rebrew build order-sources` |
| `calibrate-bss` | `rebrew build calibrate-bss` |
| `gen-link-stubs` | `rebrew build link-stubs` |
| `gen-stubs` | `rebrew build symbol-stubs` |
| `inline-strings` | `rebrew source inline-strings` |
| `verify-placement` | `rebrew build check-data-placement` |
| `text-audit` | `rebrew build check-text-placement` |
| `link-sweep` | `rebrew build sweep-link-flags` |
| `link-order` | `rebrew build link-order` |
| `document-unmatched` | `rebrew source document-unmatched` |
| `pdb-info` | `rebrew binary pdb show` |
| `discover-functions` | `rebrew binary functions` |
| `graph` | `rebrew source graph` |
| `unpack-lzexe` | `rebrew binary unpack-lzexe` |
| `crt-match` | `rebrew library crt-match` |
| `lib-match` | `rebrew library match` |
| `imports` | `rebrew binary imports list` |
| `fingerprints` | `rebrew binary fingerprints` |
| `pe-info` | `rebrew binary pe` |
| `crypto-scan` | `rebrew binary crypto` |
| `security-scan` | `rebrew source security` |
| `verify-exports` | `rebrew build check-exports` |
| `strings` | `rebrew binary strings` |
| `xrefs` | `rebrew binary xrefs` |
| `drift` | `rebrew diagnose drift` |
| `describe` | `rebrew binary function` |
| `analyze` | `rebrew binary analyze` |
| `report` | `rebrew coverage report` |
| `diagnose` | `rebrew diagnose config` |
| `flirt` | `rebrew library scan-signatures` |
| `identify-library` | `rebrew library identify` |
| `gen-flirt-pat` | `rebrew library signatures` |
| `split` | `rebrew source split` |
| `merge` | `rebrew source merge` |
| `solutions` | `rebrew match solutions` |
| `round-trip` | `rebrew build round-trip` |
| `build-db` | `rebrew coverage build` |
| `dashboard` | `rebrew coverage serve` |
| `binsync-export` | `rebrew binsync export` |
| `binsync-import` | `rebrew binsync import` |
| `binsync-diff` | `rebrew binsync diff` |
| `binsync-init` | `rebrew binsync init` |
| `binsync-overlay` | `rebrew binsync overlay` |
| `catalog` | `rebrew coverage catalog` |
| `similar` | `rebrew similarity function` |
| `binary-similarity` | `rebrew similarity binary` |
| `merge-sweep` | `rebrew match partitions` |
| `climb` | `rebrew match climb` |
| `qual-sweep` | `rebrew match qualifiers` |
| `cross-import` | `rebrew source import-related` |
| `probe` | `rebrew diagnose probe` |
| `residue` | `rebrew build residue` |
| `near-diag` | `rebrew diagnose near` |
| `gap-trace` | `rebrew diagnose gap` |
| `refactor` | `rebrew dev refactor` |
| `symbol-addrs` | `rebrew export symbols` |
| `context` | `rebrew export context` |
| `objdiff` | `rebrew export objdiff` |
| `decompme` | `rebrew export decompme` |
| `layout-map` | `rebrew build layout-map` |
| `import-splat` | `rebrew source import-splat` |
| `types` | `rebrew types check` |
| `types apply-type` | `rebrew types apply` |
| `extract` | `rebrew binary extract` |
| `extract list` | `rebrew binary extract list` |
| `extract show` | `rebrew binary extract show` |
| `extract batch` | `rebrew binary extract batch` |
| `cfg list-targets` | `rebrew cfg target list` |
| `cfg add-target` | `rebrew cfg target add` |
| `cfg remove-target` | `rebrew cfg target remove` |
| `cfg add-module` | `rebrew cfg module add` |
| `cfg remove-module` | `rebrew cfg module remove` |
| `cfg set-cflags` | `rebrew cfg module set-cflags` |
| `cfg set-compiler` | `rebrew cfg target set-compiler` |
| `cfg detect-crt` | `rebrew cfg detect-crt show` |
| `resource` | `rebrew binary resource` |
| `resource compare` | `rebrew binary resource compare` |
| `resource extract` | `rebrew binary resource extract` |
| `library rm` | `rebrew library remove` |
| `data` | `rebrew data list` |
| `match` | `rebrew match run` |
| `orphans` | `rebrew orphans list` |

## Operations selected by former mode flags

| Previous invocation | Current invocation |
| --- | --- |
| `match SOURCE` | `match run SOURCE` |
| `match --all` | `match batch` |
| `match --all-targets` | `match batch --all-targets` |
| `match --all --flag-sweep` | `match batch --algorithm flags` |
| `match --all --flag-sweep-then-ga` | `match batch --algorithm flags-then-ga` |
| `match SOURCE --flag-sweep-only` | `match flags SOURCE` |
| `match SOURCE --flag-sweep-toolchains` | `match toolchains SOURCE` |
| `match SOURCE --flag-sweep-toolchains --flag-sweep-only` | `match toolchains SOURCE --flags` |
| `match --ga-history` | `match history` |
| `data` | `data list` |
| `data --set-FIELD VA=VALUE` | `data set --FIELD VA=VALUE` |
| `data --dispatch` / `--bss` / `--fix-bss` | `data dispatch` / `bss` / `fix-bss` |
| `data --gen-header` / `--annotate` | `data header` / `annotate` |
| `data --layout-audit` / `--fill-data` / `--own` | `data layout audit` / `fill` / `own` |
| `data --fix-ownership` / `--converge` | `data layout fix-ownership` / `converge` |
| `sync --push` / `--pull` / `--summary` / `--watch` | `sync push` / `pull` / `summary` / `watch` |
| `sync --create-functions` / `--bookmarks` / `--pull-data` | `sync create-functions` / `bookmarks` / `pull-data` |
| `sync --pull --create-functions` | `sync pull --create-functions` |
| `doctor --install-wibo` | `toolchain install-wibo` |
| `flirt --init` / `--init-matched` | `library init-signatures` / `library init-signatures --matched-only` |
| `imports --mark` | `binary imports mark` |
| `pdb-info BINARY --write-cflags` | `binary pdb import-cflags BINARY` |
| `asm --all --format nasm` | `binary asm batch` |
| `asm --batch-stubs` | `binary asm batch --stubs` |
| `orphans --prune` | `orphans prune` |
| `types` / `types apply-type` | `types check` / `types apply` |
| `cfg list-targets` / `add-target` / `remove-target` / `set-compiler` | `cfg target list` / `add` / `remove` / `set-compiler` |
| `cfg add-module` / `remove-module` / `set-cflags` | `cfg module add` / `remove` / `set-cflags` |
| `cfg detect-crt --write` | `cfg detect-crt apply` |
| `cfg detect-crt` | `cfg detect-crt show` |

## Options and generated artifacts

- `skeleton --decomp-backend` becomes `--decompiler`; provider defaults remain unchanged.
- Match/split/ASM output directories use `--output/-o`; data header output is a file.
- Match profile sweeps use `--toolchains` and `--exclude-toolchains`.
  `match flags` and `match toolchains` compile and have no `--dry-run` option.
  `match batch --dry-run` previews selection; `match run --seed-llm --dry-run`
  previews the LLM request.
- Todo and both similarity operations use `--limit`. Zero displays no rows;
  `source import-related --limit 0` means unlimited imports, and
  `match batch --max-stubs 0` means unlimited selected functions.
- `dev refactor --repository PATH` scans Python without requiring project config.
- Run `rebrew init --refresh-agents`, then `rebrew init --check` in each workspace.
  Canonical guidance comes from packaged skills and templates; preserve locally
  customized obsolete skills when the refresh reports them.
- Regenerate CMake files with `rebrew build cmake-toolchain --toolchain PROFILE
  --output cmake/`, retain the companion rules file, and reconfigure CMake.
  Compiler/linker/archive calls use `rebrew build driver MODE -- ARG...`.
- Regenerate objdiff files with `rebrew export objdiff`; `custom_args` starts with
  `build`, `objdiff-driver`, and the target name.
- Recoverage's in-process generator and coverage document format are unchanged.
  CLI generation is now `rebrew coverage build`.

Historical changelog and ADR examples describe their releases; current guidance
uses the routes above.
