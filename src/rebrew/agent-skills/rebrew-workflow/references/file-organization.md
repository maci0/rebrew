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
rebrew recommend --json                   # all lanes: TU layout + hygiene + next action
```

- `split --va <va>` moves one annotated function out of a multi-function file.
- `merge --shared` collapses per-target twin copies into one stacked
  `src/shared` file; it refuses divergent bodies.
- `cross-import --shared` stacks one matched function at a time from another
  target (`--promote` moves the file first); `split --va` matches any stacked
  marker.

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
