# File organization and dependency graph

One-function-per-file is the default. Split when a file mixes CFLAGS, merge
when functions share a translation unit (file statics or file-scope globals).
Every writer here accepts `--dry-run` except `layout-map` and `graph`, which
only read: preview the mutating ones first.

## Review every target before moving source

`rebrew source organize review a.c b.c --destination merged.c --json` reads all
configured targets. Review provider participation, original compiler/header
contexts, storage/namespace collisions, static header instances and native order
cycles. A header guard can collapse separate per-TU statics after a merge. Preserve
source comments, ADDRESS anchors, file-scope state and preprocessor boundaries;
do not choose one target's order when another contradicts it. `--shared` models
body-sharing candidates; it does not establish common storage ownership.

Preserve each pre-change raw link, make the reviewed source change, and rebuild
every affected target. `rebrew source organize check old.dll build/raw.dll --json`
compares independent complete PE images, full code/data bytes and placement.
Unsupported formats, incomplete tables/spans and changed inputs fail explicitly.
Object matches and a common order do not prove raw-link agreement. This check earns
no source STATUS and does not establish reference equality: verify functions and
data as well. The review is read-only and never automatically reorders definitions.

## Split / merge / rename

```bash
rebrew source split src/<target>/multi.c [--dry-run] [--va 0x...]
rebrew source merge a.c b.c --output merged.c
rebrew match partitions --dry-run
rebrew build link-order --check
rebrew build layout-map
rebrew source rename old_func new_func [--dry-run]
rebrew source rename SERVER.0x10003da0 new_func [--all-modules] [--dry-run]
rebrew source rename g_old g_new --data [--dry-run]
rebrew source rename OldType NewType --type [--dry-run]
rebrew source rename Struct.old_member new_member --field [--dry-run]
rebrew recommend --json                   # all lanes: TU layout + hygiene + next action
```

- `rebrew source split --va <va>` moves one function out of a multi-function file.
  Definitions are resolved from canonical function rows and C syntax. File-scope storage stays
  in the original file. A static dependency is refused. A non-terminal stdin
  is refused, and `--json` requires `--force`. Pass `--force` to skip the
  prompt. A piped answer does not approve. `--dry-run` writes nothing.
- `rebrew source merge` combines C definitions from their function rows.
  Definitions move to the output and every row that names an input moves
  with them. `--shared` keeps one copy when the bodies match and refuses
  bodies that differ. Reconstruction source stays scoped to its metadata identity. A non-terminal stdin is refused, and `--json` requires `--force`. Pass `--force` to skip the prompt. A piped answer does not approve.
  `--dry-run` writes nothing.
- `rebrew source import-related --shared` records the destination identity on
  the shared definition (`--promote` moves the file first). Optional address
  anchors follow their declarations; metadata carries every other field.
- `rebrew source rename` rewrites whole identifiers only: never inside string
  literals, inside comments only with `--comments`. Read the `--dry-run` list
  (`file:line:column role` plus row changes) before writing.
  Reviewed assembly provenance follows definitions and file moves. Only records
  current before the mechanical rename receive refreshed hashes; stale evidence
  stays stale. Reverify byte matches after renaming.
- `rebrew source rename PLACEHOLDER MODULE.0xVA --dry-run` previews binding
  unbound calls to an existing external definition or header-owned `LIBRARY`
  identity, including compiled library sources bound outside `reversed_dir`.
  Apply the reviewed binding without `--dry-run`; the destination
  identity/verdict stays unchanged. Verify library providers separately against
  the configured archive and raw link; binding requires no replacement C body.
- A definition shared by several modules' rows renames only with
  `--all-modules`; a per-target twin keeps its name unless `--all-modules`
  is given. `rebrew source rename --all-modules` renames module rows. It is
  not `--all`. Pick one twin by `MODULE.0xVA`. A name with no row in the active
  target renames the source symbol and the other modules' rows bound to it.
- `--data` renames a global's rows, definition, `extern` declarations and
  uses (`rebrew data set --name` changes only the row). `--type` renames a tag
  or typedef and the `type` strings of data rows and function `locals`.
  `--field STRUCT.MEMBER` resolves each access to its struct and refuses,
  with `file:line`, accesses it cannot resolve while another struct has a
  member of that name.
- After a rename run `rebrew test --all`; after `--data` or `--type` also run
  `rebrew verify --data`, since a changed name or type clears the row's verdict.

## Dependency graph

```bash
rebrew source graph --format summary           # stats, leaf functions, top blockers
rebrew source graph --focus <Func> --depth 2   # neighbourhood of a specific function
rebrew source graph                            # full mermaid call graph
rebrew source graph --cu-map --json            # infer compilation unit boundaries
```

`--cu-map` clusters functions into inferred translation units from gap
analysis plus call-graph signals; high-confidence clusters are the merge
candidates. `rebrew-intake` runs the same pass during onboarding.


For a proved-wrong native identity, preview `rebrew source binding retire VA
--reason TEXT --dry-run --json`. An optional `--counterpart VA` records an existing
same-target counterpart without changing its verdict. Rebind with `rebrew source
binding rebind VA SOURCE --name NAME --reason TEXT --dry-run --json`. Repeat a
reviewed request with `--expected-digest HASH`. History and native sizes survive;
references are reported, not rewritten, and the replacement earns a fresh verdict.
Former-only TUs stay inactive. Historical address comments do not reactivate them.

For selected stale discovery extents, preview `rebrew binary repair-extents
0xVA=SIZE --reason TEXT --dry-run --json`, then guard apply with the preview digest.
Use complete native boundary evidence; the command does not promote a match or
replace unrelated inventory rows.
