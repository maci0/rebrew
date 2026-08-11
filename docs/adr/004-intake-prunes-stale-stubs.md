# ADR-004: Intake re-discovery prunes only exact auto-stubs

- **Status**: Accepted
- **Date**: 2026-08

## Context

`rebrew intake` re-runs on an existing project (re-discovery) when the
function list changes — a rizin update, an NE enumeration fix, a discovery
backend swap.  Before this change, stubs from the previous discovery were
left behind: a broken first enumeration produced 233 `fcn_0000XXXX.c`
stubs, the fixed re-run produced 137 `fcn_0001XXXX.c` stubs, and both
coexisted, inflating `rebrew status` totals (348 "functions" in a
137-function target) and cluttering the source tree.

## Decision

On re-discovery, intake prunes stale stubs after documenting the new list:

- A file is pruned only when its content **exactly matches the auto-stub
  pattern** (`// STUB: <marker> 0x<va>` + `void fcn_<va>(void) { ... }`)
  and its VA is absent from the new function list.  Any edited, renamed,
  or user-written source survives untouched.
- The metadata entry for a pruned VA is deleted together with the file
  (new `delete_metadata_entry` in `rebrew.metadata`), so a progressed
  function — whose source was renamed/edited and therefore not pruned —
  never loses metadata.
- Pruning runs only when the project already existed (a fresh onboarding
  has nothing stale) and reports the count as an intake note.

## Consequences

- `rebrew status`/`todo`/`verify` counts reflect the actual function list;
  stale phantom functions no longer accumulate across discovery changes.
- The auto-stub regex is the safety boundary: it cannot touch a file the
  user has meaningfully changed, which is the invariant that makes
  destructive cleanup safe on re-discovery.
- Discovery changes (NE fixes, rizin upgrades) can now be applied by
  simply re-running intake, which is what makes the corpus-onboarding
  workflow idempotent.
