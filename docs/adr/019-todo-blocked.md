# 019 — Todo blocked category

## Status

Accepted

## Context

Functions carrying a `BLOCKER` (structural mismatch, GA ceiling, naked body,
non-target) surface inside `improve-match` mixed with plain near-misses —
their mutations list is parsed from the blocker text, but there is no way to
list *just* the blocked set ("what is stuck and why"). Triage on a large
project needs the blocked view first: it names the work that flag sweeps and
plain iteration cannot unstick.

## Decision

- New `blocked` category in `rebrew todo` (`-c blocked`): every function
  with non-empty `BLOCKER` text, regardless of verify status. The item keeps
  its score/cmd; `desc` leads with the blocker class
  (`STRUCTURAL`/`GA_CEILING`/naked/non-target) so the list scans.
- Blocked items stay in their existing categories too (a STRUCTURAL
  near-miss is both `improve-match` and `blocked`) — the category is a lens,
  not a move. Counts in the header reflect this (an item can appear under
  two categories; the total stays deduplicated).
- `todo --json` exposes the same items (no schema change — `category` is
  already per-item... see consequence).

## Consequences

- Per-item `category` is single-valued today; a blocked improve-match item
  reports one of the two. The `-c blocked` filter matches on blocker
  presence, not the category field, so JSON consumers filter the same way
  (`items[?blocker]`). A future multi-category schema is out of scope.
- Zero new writers: the category derives from existing BLOCKER text at
  read time. No migration, no backfill.
