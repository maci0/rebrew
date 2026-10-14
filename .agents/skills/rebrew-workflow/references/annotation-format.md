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

See the project AGENTS.md and the metadata owner API documentation.
