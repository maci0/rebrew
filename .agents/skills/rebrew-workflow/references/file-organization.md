# File organization and dependency graph

One-function-per-file is the default. Split when a file mixes CFLAGS, merge
when functions share a translation unit (file statics or file-scope globals).
Every writer here accepts `--dry-run` except `layout-map` and `graph`, which
only read: preview the mutating ones first.

## Split / merge / rename

```bash
rebrew source split src/bench/multi.c [--dry-run] [--va 0x...]
rebrew source merge a.c b.c --output merged.c
rebrew match partitions --dry-run
rebrew build link-order --check
rebrew build layout-map
rebrew source rename old_func new_func [--dry-run]
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
