# DATA annotations (`rebrew-data.toml`)

DATA metadata lives in a **`rebrew-data.toml`** beside `rebrew-functions.toml` at
`cfg.metadata_dir`: one level above the source tree (the project root when
sources live under `src/`) when a store sits there, otherwise the outermost store found
walking up to the project root, so one store covers every target. The loader does
no walk-up of its own (it reads `directory / rebrew-data.toml` plus direct
`rebrew-data.d/*.toml` fragments), so library code must pass `cfg.metadata_dir`
rather than the `.c` file's directory.
New writers emit a declaration with an ADDRESS anchor and record the row.
All identity and state belong in format-2 `rebrew-data.toml`. Register existing
address-bound declarations with `rebrew source register --dry-run`, then apply.
Metadata-only rows without anchors remain valid. Older inline blocks and schemas
are rejected. Extern declarations never establish storage ownership.

| Field | Purpose |
|-------|---------|
| `file` | Source path relative to the metadata root. `rebrew source register` records it |
| `kind` | `GLOBAL`, `DATA`, `VTABLE`, or `STRING`. A row without it is read as `DATA` |
| `name` | Preferred variable label; overrides C stem; imported from BinSync state |
| `type` | Declared type `data header` uses when the source has none; set with `rebrew data set --type 0xVA=TYPE` |
| `size` | Size in bytes |
| `section` | PE section (`.data`, `.rdata`, `.bss`) |
| `note` | Local analysis description; native BinSync globals do not carry notes |
| `status` | Data verdict written by `rebrew verify --data`: `EXACT` (bytes and placement agree), `VERIFIED` (bytes agree, placement unproven), `DISPLACED` (linked provider is away from its reference VA), `DRIFT` (bytes differ or are missing), `UNCHECKED` (not compared). `rebrew status` counts every verdict; `rebrew todo --category data-drift` lists `DRIFT` and `DISPLACED` |

`rebrew data set` accepts multiple fields atomically. Preview with `--dry-run --json`; apply the same
request with `--expected-digest HASH` from `input_digest`. Definition, identity and placement edits
clear the current verdict while retaining verification evidence; notes and unchanged values preserve it.
`data list --all-targets` uses each target's own link map. A row `data set` creates has no `kind` and
reads as `DATA`. `rebrew data move 0xOLD 0xNEW` re-addresses a row with all its fields, drops its
verdict, keeps its `verification` record, and refuses an occupied address. Registration preserves
existing fields and verdicts. `origins` and `verification` are nested tables for external source
facts and comparison evidence; ordinary edit stamps remain separate. Writers
store `size` as a non-negative integer and descriptive fields as strings; lint W031 uses the same
validation. Duplicate spellings of one `(module, VA)` count once; W031 reports them and granular
writers refuse ambiguous updates.

Verification needs a known complete extent. Without `size`, only supported
x86_32 types and complete constant arrays are inferred; unresolved types or
bounds and other architectures need explicit `size`. A matching prefix of
an unknown-sized symbol cannot earn `VERIFIED`.

> [!CAUTION]
> **Never manually edit `rebrew-data.toml`.** `rebrew data set`, `rebrew data annotate`,
> and `rebrew sync pull --state-dir <dir>` write it. `rebrew data list` does not write
> metadata; `rebrew data fix-bss` writes the gap rows it generates.
> Entries are keyed `"MODULE.0xVA"` (qualified, same scheme as `rebrew-functions.toml`).
