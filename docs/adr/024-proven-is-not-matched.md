# ADR-024: PROVEN is not matched and not sticky

- **Status**: Accepted. Amends [ADR-009](009-cross-target-import.md)
  (cross-import: a PROVEN source is not a donor, a PROVEN destination is
  importable).
- **Date**: 2026-09

## Context

`rebrew prove` writes STATUS `PROVEN` when angr/Z3 shows a function
semantically equivalent to the target while its compiled bytes still differ.
Rebrew counted PROVEN with EXACT and RELOC in `MATCHED_STATUSES`, so status,
todo, report, catalog, build-db and verify's `passed` all treated it as done
work.  `rebrew verify` also overlaid metadata PROVEN onto its byte results
(turning a NEAR_MATCHING compile into a pass), and the promotion gate refused
to demote PROVEN except to EXACT/RELOC.  A byte-identical goal read those
numbers as progress that the linked binary does not have, and `rebrew todo`
hid PROVEN functions that still needed work.

## Decision

- "Matched" means byte-identical: `MATCHED_STATUSES = ("EXACT", "RELOC")`.
  PROVEN is excluded from every matched count, byte coverage figure,
  library-identified count, blocker clearing and verify's `passed`.
- PROVEN is not sticky.  `should_promote_status` gives it no protection;
  the verify overlay, `is_status_sticky`, `is_stale_proven` and
  `PROVEN_COMPATIBLE_STATUSES` are removed.  The next `rebrew test` /
  `rebrew verify` records the byte result over PROVEN.  SKIP stays parked.
- `rebrew prove` still writes PROVEN (blocker kept).  Status and todo read a
  metadata PROVEN over a cached verdict, since prove compiles after it.
- PROVEN is shown on its own: a status row and bucket, `rebrew todo`
  improve-match items, never a `rebrew prove` item again.
- Sites that protect earned work rather than claim a match name PROVEN
  explicitly: orphan hold-back (`orphans.EARNED_STATUSES`), lint E017 (STUB
  marker on a proven function), W028 and the `--fix-sizes` guard (prove
  compiled and compared at the annotated VA and size).
  Amended: W028 no longer names PROVEN. It skips byte-matched markers and
  markers whose annotated neighbour tiles a merged inventory entry.

## Consequences

- Verify's `passed` and `rebrew status`'s headline drop by the number of
  PROVEN functions; a project gate pinned to the old `passed` count needs a
  new baseline.
- The first verify after upgrading demotes every PROVEN function whose bytes
  do not match to its byte verdict; re-running `rebrew prove` restores PROVEN
  until the next verify.
- PROVEN stays live work in `rebrew todo` until it byte-matches.
