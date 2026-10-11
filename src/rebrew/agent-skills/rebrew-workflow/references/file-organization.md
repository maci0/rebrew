# File organization and dependency graph

One-function-per-file is the default. Split when a file mixes CFLAGS, merge
when functions share a translation unit (file statics or file-scope globals).
Every writer here accepts `--dry-run` except `layout-map` and `graph`, which
only read: preview the mutating ones first.

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
  A migrated file is resolved from its function row. File-scope storage stays
  in the original file. A static dependency is refused. Pass `--force` when
  the run is not interactive. `--dry-run` writes nothing.
- `rebrew source merge` combines migrated files from their function rows.
  Definitions move to the output and every row that names an input moves
  with them. `--shared` keeps one copy when the bodies match and refuses
  bodies that differ. A file-level `// SOURCE: naked` is not copied onto
  a second function. Pass `--force` when the run is not interactive.
  `--dry-run` writes nothing.
- `rebrew source merge --shared` on an unmigrated file still stacks marker
  blocks and refuses divergent bodies.
- `rebrew source import-related --shared` records the destination row on that shared file
  (`--promote` moves the file first). `rebrew source split --va` still splits an unmigrated stacked marker.
- `rebrew source rename` rewrites whole identifiers only: never inside string
  literals, inside comments only with `--comments`. Read the `--dry-run` list
  (`file:line:column role` plus row changes) before writing.
  Reviewed assembly provenance follows definitions and file moves. Only records
  current before the mechanical rename receive refreshed hashes; stale evidence
  stays stale. Reverify byte matches after renaming.
- `rebrew source rename PLACEHOLDER MODULE.0xVA --dry-run` previews binding
  unbound calls to an existing external definition or header-owned `LIBRARY`
  identity. Apply the reviewed binding without `--dry-run`; the destination
  identity/verdict stays unchanged. Verify library providers separately against
  the configured archive and raw link; binding requires no replacement C body.
- A definition shared by several modules' rows renames only with
  `--all-modules`; a per-target twin keeps its name unless `--all-modules`
  is given. Pick one twin by `MODULE.0xVA`. A name with no row in the active
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
