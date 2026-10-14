# Source addresses and metadata

All Rebrew state lives in dedicated metadata files. C source may carry optional
address anchors immediately above a function definition, variable declaration,
or data constant:

```c
/* ADDRESS: SERVER 0x10001000 */
/* ADDRESS: CLIENT 0x00402000 */
int tick(void) { return 1; }

/* ADDRESS: SERVER 0x10025000 */
extern const unsigned char lookup[256];
```

Each anchor identifies exactly the next C declaration. Stack one line per target
when targets share the declaration. Blank lines and comments may intervene;
preprocessor directives and other code may not. Multiple declarators on one line
are ambiguous and rejected. An extern is a declaration, never a storage owner.
Generated C uses C89-safe block comments. Strings and function-body comments do
not establish identities.

`rebrew source register [SOURCE] --dry-run` previews identities recovered from
these addresses; run without `--dry-run` to record them. It validates the complete
selection before writes and preserves existing metadata fields. With no SOURCE,
it scans configured sources and headers. `--support "reason"` with one source
records its target-scoped support purpose in `rebrew-source.toml`.

Sources without addresses remain supported through stored `file`, `symbol`,
`name`, and `kind` identities. Library inventories without a C declaration are
metadata-only. No fake definitions or storage are needed for inventory rows.

## Managed stores

Function and data stores require `format = 2`, then qualified `MODULE.0xVA`
tables. `rebrew-source.toml` requires format 2 and the `definitions` and `files`
tables. No older schema or inline metadata blocks are read, including during
registration. `kind` is the sole identity field for classification.

Illustrative managed output (use the CLI or locked owner APIs to edit):

```toml
format = 2

["SERVER.0x10001000"]
file = "src/tick.c"
name = "tick"
symbol = "_tick"
kind = "FUNCTION"
size = 16
status = "STUB"
```

`rebrew-functions.toml` owns identity, size, flags, toolchain, blockers, notes,
external origins, verification evidence, STRUCT/CALLERS information, and
`source = "naked"` for generated assembly reconstructions. `rebrew-data.toml`
owns data identity, type, extent, section, storage relationships and data
verification. `rebrew-source.toml` owns assembly evidence for definitions without
a native address and target-scoped file purposes. File paths are relative to
`cfg.metadata_dir`; pass that directory to readers and writers.

Never hand-edit these stores. Writers use their owning metadata APIs, locks,
atomic replacement and mode 0444. STATUS is earned only by comparison through
`rebrew test` / `rebrew verify`; an address or registration is no match evidence.
`PROVEN` is not a byte match. Library origin and actual linked provider remain
separate; a signature candidate is not a verified provider.

Function and data verification have separate denominators. Data aliases are
views into one backing allocation, externs are users or declarations, and BSS
is not initialized file data. Preserve canonical provenance and stored comparison
inputs when moving or renaming identities.

See [metadata ownership](METADATA.md) and [ADR 030](adr/030-address-only-source.md).

## Lint reference

`--fix` repairs redundant flags and resolvable data sections. It never imports
source comments or rewrites obsolete blocks.

| Code | Meaning |
|------|---------|
| E000 | Cannot read file   File permissions, encoding issues |
| E001 | No source binding, invalid address or empty file; a support file requires a stored purpose. |
| E002 | Address is invalid or outside the supported native range. |
| E004 | Stored function status is outside the known vocabulary. |
| E008 | Stored size is not an integer. |
| E012 | Binding module belongs to no configured target or declared library module. |
| E013 | Duplicate address ownership across definitions or files. |
| E015 | Stored classification conflicts with the configured module classification. |
| E017 | STUB classification conflicts with stored comparison state. |
| E023 | Whole-function naked asm   `__declspec(naked)` + `__asm`/`__emit` body beyond 1-2 padding bytes (`nop` / `0x90` / `0xCC`). Only 1-2 alignment nops are allowed as minor padding; a whole-function naked dump must be decompiled to C |
| E024 | Source contains a metadata tag; put all state in the dedicated stores. No fix or migration parser reads these blocks. |
| W003 | A bound or support file contains no implementation. |
| W005 | An unfinished function lacks a stored blocker explanation. |
| W006 | A declared library module lacks source provenance in function metadata. |
| W015 | Hex address digits use inconsistent case. |
| W016 | A data identity lacks its native section; --fix can resolve it from the binary. |
| W018 | Missing CFLAGS with no config fallback   No CFLAGS in metadata **and** no `[compiler].cflags` default in project config: compile may use wrong flags |
| W020 | Undocumented assembly   Names each definition using `__asm`/`_emit`, using only its selected-target metadata. Its own `BLOCKER`, or current file/symbol/target evidence recorded by `rebrew source document-assembly`, documents original-assembly provenance and suppresses only that definition's warning. Another function's status, blocker or naked body does not affect it. Foreign-only target files/definitions are excluded. Naked assembly is handled by **E023**. Non-stub statuses appear in the warning, but a byte match alone does not establish original assembly provenance |
| W021 | Duplicate global   Conflicting addresses for one module/name, or initialized definitions in more than one file; same-address extern references are allowed |
| W022 | Zero-init `.bss` global   File-scope `= 0` initializer on a `.bss`-style global |
| W023 | Default function name   Function named `fcn`/`fn`/`fun`/... (pedantic only): rename it; a descriptive name is what the call graph and reports key on |
| W024 | Function naming convention   Function name does not match project naming convention (`lint_naming_convention` in config) |
| W025 | Opening brace style   Opening brace style does not match project configuration (`lint_brace_style` in config) |
| W026 | Line indent style   Line indent style does not match project configuration (`lint_indent_style` in config) |
| W027 | Line too long   Line exceeds `lint_max_line_length` characters |
| W028 | Stale bound VA   FUNCTION/STUB binding VA has no function in the current discovery inventory (`function_structure.json`, removed/shifted) or points inside another function's span (moved/merged): review the binding or refresh with `rebrew binary functions`; LIBRARY/DATA/GLOBAL bindings excluded |
| W029 | Redundant cflags   Per-function `cflags` in `rebrew-functions.toml` or `compiler.cflags_presets.<MODULE>` that only repeat the inherited value (`resolve_cflags` ladder: function → module preset → project `compiler.cflags`); flagged by `rebrew lint` (project-level `check_redundant_cflags` moved from `rebrew doctor`). `rebrew lint --fix` drops the redundant field; the fallback chain already supplies the same flags |
| W030 | Function addresses for one target do not follow C definition order. |
| W031 | Metadata store problem   A `rebrew-functions.toml` / `rebrew-data.toml` entry a reader will not honour: an unknown field, a STATUS outside the vocabulary, half an `updated_by`/`updated_at` pair, an unknown provenance tag, a stray top-level key, or a missing / foreign `format` stamp. Also reports malformed `rebrew-source.toml`, unknown target modules and evidence bound to a changed, missing or ambiguous definition; clear the record or review and record evidence again |
| W032 | Coverage store hygiene   An artifact from a store rebrew no longer writes: `db/coverage.db` (SQLite), `db/data_<target>.json` (catalog grid), `db/*.csv`, or a `db/coverage-<target>.toml` the dashboards cannot serve: unreadable to the loader (foreign `version`, malformed TOML) or one whose `target` key disagrees with its filename, so that target answers with another's data. Re-run `rebrew coverage build` and delete the old artifacts |
| W033 | Agent scaffold drift   `AGENTS.md`, `PRINCIPLES.md` or `.agents/skills/**` no longer matches the installed rebrew's packaged sources, so an agent follows workflow instructions for a version that is not running. Warn-only; fix with `rebrew init --refresh-agents` (it writes only differing files and prunes a skill the packaged tree no longer ships). `AGENTS.md`'s own comparison is profile-rendered: `rebrew init --refresh-agents --check` reports it in full |
| W034 | `file` identity is not joinable   A stored `file` in `rebrew-functions.toml` is absolute or contains a `..` segment, so `verify`/`rename`/BinSync would join it to a path outside the checkout. Writers refuse it (`rebrew.metadata.functions.validate_identity_file`); this reports rows written before the gate |
| W035 | Module belongs to no target   A metadata row's `module` matches no project binding, target binding, or declared library module, so `status`, `todo` and the dashboards (all of which filter by module) cannot show it. Typical after a target rename left rows behind |
| W036 | Stray metadata store   A `rebrew-data.toml` / `rebrew-functions.toml` outside the directories the readers use (`metadata_dir`, `reversed_dir`, `shared_dir`). The readers resolve a store by directory with no fallback, so a second copy is not a backup: pointed at its directory it answers with its own smaller entry set, and is invisible otherwise. Warn-only; delete the copy that no command is pointed at |
| W037 | Data row disagrees with its definition   A `rebrew-data.toml` row of the active target whose `file` names this source, where the file-scope definition of its `name` has a different byte size than the row's `size` or the extent of its `type` (guild-rebrew `g_gap_10034644`: the row said `char[44]` after a generator shrank the definition to 36 bytes). `extern` declarations are users and are ignored, except for `storage_kind = "span"` rows, whose owning file may hold only an extern inventory view; a definition still wins. A tiled allocation (guild-rebrew `g_slot_table`: a short leading definition plus separately defined interior names and pads, each an `alias` row in the same file whose `backing` names the allocation) is measured as the leading definition plus the backed definitions that follow it contiguously; a backed row with no definition there is a view and is ignored, and a hole before the next piece is reported by address. Only byte sizes are compared, so `[0x104]` against `[260]` or a typedef against its expansion is silent. Skipped, not guessed: no definition in the file, conflicting definitions (`#if` branches), and any size `data_symbol_size` cannot compute (struct/union/unknown typedef, unsized array, non-x86_32). The message names both values and the fix: `rebrew data set --type '0xVA=TYPE'` / `--size 0xVA=BYTES` |
| W038 | Overlapping data rows   Two named `rebrew-data.toml` rows of one module whose `[va, va + size)` extents intersect (size from `size`, else a computable `type`). An `alias` row with a `backing` is a view and is excluded; rows that only touch end-to-start do not overlap. Two storage owners cannot share a byte, so one extent is stale (W037 often names it) or a view is not recorded as one (`rebrew data set --storage-kind 0xVA=alias --backing 0xVA=GLOBAL`). `rebrew status` otherwise shows only the discounted byte count |
