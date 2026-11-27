# Source addresses and metadata

Function and data records live in dedicated metadata stores. C source may carry optional
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
By default, generated C uses C89-safe block comments. See
[address comment settings](CONFIG.md#address-comment-syntax) for other styles.
Strings and function-body comments do not establish identities.

`rebrew source register [SOURCE] --dry-run` previews identities recovered from
these addresses; run without `--dry-run` to record them. It validates the complete
selection before writes and preserves existing metadata fields. With no SOURCE,
it scans configured sources and headers. `--support "reason"` with one source
records its target-scoped support purpose in `rebrew-functions.toml` under `[source.files]`.

Sources without addresses remain supported through stored `file`, `symbol`,
`name`, and `kind` identities. Library inventories without a C declaration are
metadata-only. No fake definitions or storage are needed for inventory rows.

## Managed stores

Functions require `format = 3`; data requires `format = 2`. Both retain qualified
`MODULE.0xVA` tables. The function store also holds `[source.definitions]` and
`[source.files]` for addressless evidence and target-scoped purposes. Ordinary
readers reject older schemas and inline metadata blocks, including during
registration. Explicitly preview `rebrew source consolidate --dry-run --json`,
then apply with the returned `--expected-digest` to fold format-2 function/source
stores into the current function store. `kind` is the sole identity field for classification.

Illustrative managed output (use the CLI or locked owner APIs to edit):

```toml
format = 3

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
verification. The function store owns assembly evidence for definitions without
a native address (`source.definitions.FILE.SYMBOL.MODULE`) and target-scoped file
purposes (`source.files.FILE.MODULE`). These records never invent a native VA.
Source identity paths are relative to `cfg.metadata_dir`; pass that directory
to readers and writers. Compiled LIBRARY providers use the project root, as
specified in the [source contract](METADATA.md#current-source-contract).
Configured source directories must remain inside the metadata root; see the
[configuration rule](CONFIG.md#what-the-config-loader-provides).

Never hand-edit these stores. Writers use their owning metadata APIs, locks,
and backend persistence. See [metadata storage](METADATA.md#storage-api-and-backend-selection) for backend and permission rules. Byte-match STATUS is earned only by comparison through
`rebrew test` / `rebrew verify`; an address or registration is no match evidence.
`prove` writes semantic `PROVEN`, and scaffold writers may create `STUB`.
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
| E000 | Cannot read file: file permissions or encoding. |
| E001 | No source binding, invalid address or empty file; a support file requires a stored purpose. |
| E002 | Address is invalid or outside the supported native range. |
| E004 | Stored function status is outside the known vocabulary. |
| E008 | Stored size is not an integer. |
| E012 | Binding module belongs to no configured target or declared library module. |
| E013 | Duplicate address ownership across definitions or files. |
| E015 | Stored classification conflicts with the configured module classification. |
| E017 | STUB classification conflicts with stored comparison state. |
| E023 | Whole-function naked asm: `__declspec(naked)` + `__asm`/`__emit` body beyond 1-2 padding bytes (`nop` / `0x90` / `0xCC`). Only 1-2 alignment nops are allowed as minor padding; a whole-function naked dump must be decompiled to C unless its original assembly is documented with `rebrew source document-assembly` (that definition is exempt) |
| E024 | Source contains a metadata tag; put all state in the dedicated stores. No fix or migration parser reads these blocks. |
| W003 | A bound or support file contains no implementation. |
| W005 | An unfinished function lacks a stored blocker explanation. |
| W006 | A declared library module lacks source provenance in function metadata. |
| W015 | Hex address digits use inconsistent case. |
| W016 | A data identity lacks its native section. `--fix` can resolve it from the binary. |
| W018 | Missing CFLAGS with no config fallback. No CFLAGS in metadata **and** no `[compiler].cflags` default in project config: compile may use wrong flags |
| W020 | Inline assembly lacks original-source evidence for this definition and target. See [assembly warnings](#assembly-warnings). |
| W021 | Duplicate global. Conflicting addresses for one module/name, or initialized definitions in more than one file; same-address extern references are allowed |
| W022 | Zero-init `.bss` global: file-scope `= 0` initializer on a `.bss`-style global |
| W023 | Default function name. Function named with a placeholder (`fcn`, `FUN_<hex>`, `sub_<hex>`, `fcn_<hex>`, ...; `rebrew.workspace.names.is_placeholder_name`; pedantic only): rename it; a descriptive name is what the call graph and reports key on |
| W024 | Function name does not match project naming convention (`lint_naming_convention` in config) |
| W025 | Opening brace style does not match project configuration (`lint_brace_style` in config) |
| W026 | Line indent style does not match project configuration (`lint_indent_style` in config) |
| W027 | Line exceeds `lint_max_line_length` characters |
| W028 | A FUNCTION or STUB binding is absent from the inventory or points inside another function's span. Review it or run `rebrew binary functions --output <inventory>`. Earned EXACT and RELOC bindings are exempt. |
| W029 | Redundant cflags. Per-function `cflags` in `rebrew-functions.toml` or `compiler.cflags_presets.<MODULE>` that only repeat the inherited value (`resolve_cflags` ladder: function → module preset → project `compiler.cflags`). `rebrew lint --fix` drops the redundant field; the fallback chain already supplies the same flags |
| W030 | Function addresses for one target do not follow C definition order. |
| W031 | A metadata store contains an unsupported format or field, malformed provenance or evidence, or evidence bound to a changed, missing, or ambiguous definition. |
| W033 | Generated agent instructions or skills have drifted. See [refreshing the scaffold](#refreshing-the-scaffold). |
| W034 | A stored `file` is absolute, drive-qualified, or contains a `..` segment. Writers reject these values. An unreadable store also triggers W034 because lint cannot check its identities. |
| W035 | Module belongs to no target. A metadata row's `module` matches no project binding, target binding, or declared library module, so `status`, `todo` and the dashboards (all of which filter by module) cannot show it. Typical after a target rename left rows behind |
| W036 | Stray metadata store. A `rebrew-data.toml` / `rebrew-functions.toml` outside the directories the readers use (`metadata_dir`, `reversed_dir`, `shared_dir`). The readers resolve a store by directory with no fallback, so a second copy is not a backup: pointed at its directory it answers with its own smaller entry set, and is invisible otherwise. Warn-only; delete the copy that no command is pointed at |
| W037 | A data row's size or type extent disagrees with its definition. See [data extent warnings](#data-extent-warnings). |
| W038 | Overlapping data rows. Two named `rebrew-data.toml` rows of one module whose `[va, va + size)` extents intersect (size from `size`, else a computable `type`). An `alias` row with a `backing` is a view and is excluded; rows that only touch end-to-start do not overlap. Two storage owners cannot share a byte, so one extent is stale (W037 often names it) or a view is not recorded as one (`rebrew data set --storage-kind 0xVA=alias --backing 0xVA=GLOBAL`). `rebrew status` otherwise shows only the discounted byte count |

### Assembly warnings

W020 checks each selected-target definition using `__asm` or `_emit`. It accepts
a blocker on that definition or current evidence from `rebrew source
document-assembly`. A byte match alone does not document provenance. E023
handles whole-function naked assembly.

### Refreshing the scaffold

`rebrew init --refresh-agents --check` previews W033 fixes. Apply with
`rebrew init --refresh-agents`. It refreshes generated files and removes
unchanged retired skills recorded in the scaffold manifest. Locally modified
retired files are reported and kept.

### Data extent warnings

W037 checks byte sizes it can compute for the selected target. For a `span`
row, it measures the extern declaration when the file has no definition.
For a tiled allocation, the check adds contiguous same-file definitions whose alias rows
name the allocation as `backing`. A gap before the next tile is reported if
it starts within the stored extent. Ambiguous or uncomputable extents are
skipped. Review the definition before correcting metadata with `rebrew data
set --type '0xVA=TYPE'` or `rebrew data set --size 0xVA=BYTES`.
