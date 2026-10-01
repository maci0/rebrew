# Defensive patterns

Bug classes that actually bit this repo, stated as the rule preventing
recurrence. Adapted from the DeepSeek Harness `defensive-patterns.md`;
every entry below names the rebrew incident. Read before writing
lifecycle, subprocess, container-staging, or cache-key code.

## Symlinks do not survive the container mount

Absolute symlinks inside a bind-mounted workdir resolve against the
*container's* filesystem, where the host target is missing: `[ -f ]`
fails and the wrapper reports "no readable source file". Batch staging
copies the tree (`shutil.copyfile`) instead of linking it. Same rule for
`write_bytes` overlays: unlink first, or the write follows the link into
the source tree.

## One bad file must not void the batch

CL compiles each TU independently, so siblings of a broken file still
emit objects, but a batch helper returning `({}, err)` on nonzero exit
throws all of them away. Collect what was emitted first, then report the
error; the caller falls back per file for the rest. (ADR-021 policy.)

## Dicts keyed by path silently drop shared files

Several functions can share one `.c` file. A `staged[path] = entry` map
keeps only the last entry per path; the rest never get objects. Map
path → *list* of entries and fan out.

## Cache keys must match on both paths

The batch writes cache entries keyed on each file's *own* flags; the
single-file path keys on its resolved flags. Any field present on one
path and absent on the other (unioned `/I` dirs, `extra_include_dirs`)
means every run recompiles everything on both paths: warm runs as slow
as cold ones. When adding a key input, grep both writers.

## Lazy imports must not break mocks or narrowing

Function-local `import lief` defeats `monkeypatch.setattr("rebrew.<mod>.lief…")`
(the local binding ignores the patched global) and dissolves mypy
narrowing. Pattern: module `__getattr__` for the lazy import (keeps the
attribute patchable) + local alias via `globals().get("lief") or _lief()`
(mock wins, real import on demand). And: LIEF 1.0 stubs type `parse`/`at`
results Optional; dereference needs an explicit `None` guard, not faith.

## Silent `continue` hides whole groups

A grouping loop with bare `continue` on `< 2 members` / `spec is None`
can drop 250 files without a log line. Every skip path logs at debug
with the group key and counts; batch debuggability is a feature, not
verbosity.

## Test the real entry path

Testing a module's app alone misses registration in `builtins.py`: the
module works while `rebrew <cmd>` fails (the `residue` incident,
[ADDING_A_COMMAND.md](ADDING_A_COMMAND.md)). Test the mounted command through
the umbrella. `test_docs_hygiene.py::test_every_component_main_has_callback_decorator`
checks module wiring, and the packaging gate allows only `rebrew` plus four
external build hooks, so separate executable names cannot mask a missing mount.

## Uncommitted work poisons `git add -A` releases

A release commit made with `git add -A` swept 7 unrelated files (version
docs, dep floors, another feature's `db.py`) under a batch-perf message.
Stage by path for releases; review `git diff --cached` before committing.
