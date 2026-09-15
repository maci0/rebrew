# 018 — Single-file verify scope and baseline

## Status

Accepted

## Context

`rebrew verify` scopes by module (`--origin`) and subdirectory (`--dir`),
but not by file — and `--compare` baselines the whole run. CI on a large
project cannot gate one file ("this PR touches `foo.c`, verify just it
against its last-known report") without verifying everything and eyeballing
the diff. The batch pipeline (`run_batch` → report → baseline → gate)
already filters by origin/dir; file scope is the same filter one level
narrower, and the baseline is a keyed JSON document that already supports
per-entry comparison.

## Decision

- `rebrew verify <file.c> --compare` restricts the run to one source file
  (exact path match after `resolve_source_arg`) and compares only that
  file's entries against the baseline. Entries for other files are neither
  verified nor reported — the gate answers "did *this file* regress".
- The baseline stays whole-project (`verify_baseline.json` unchanged);
  comparison filters to the scoped entries. No per-file baseline files.
- Exit codes unchanged: 0 clean, 1 regression/mismatch, 2 error.

## Consequences

- CI can gate per-file: `rebrew verify src/x/foo.c --compare` fails the PR
  only when `foo.c` regresses, regardless of unrelated tree state.
- `--origin`/`--dir` keep working; file scope composes (file must be under
  the dir when both given, else empty set → explicit error, not silent pass).
- An empty scope (path matches no annotations) errors instead of reporting
  "0/0 passed" — a silent green gate is worse than a loud one.
