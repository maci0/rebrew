# ADR-025: Remove the todo blocked lens

- **Status**: Accepted. Supersedes [ADR-019](019-todo-blocked.md).
- **Date**: 2026-09

## Context

ADR-019 added `rebrew todo -c blocked`, and `rebrew status` reported
"N blocked" (JSON `unresolved_blockers`): unmatched functions with BLOCKER
text.  In use, the word says nothing: every unmatched function is blocked
until someone unblocks it, and one with no BLOCKER note (a 5-byte near-miss
nobody has written up) is not less stuck than one with a note.  The lens was
also not a category: `-c blocked` sat beside the categories the table's `Cat`
column shows, matched on a different field, and in the guild-rebrew case
listed 4 of 5 unmatched functions under a heading that implied the fifth was
unblocked.

## Decision

- Remove the `blocked` lens from `rebrew todo`, the blocked count from
  `rebrew status` (terminal line and JSON `unresolved_blockers`), and the
  "blocked" wording for NEAR_MATCHING in `rebrew analyze`.
- A row keeps its BLOCKER text in the description (`— Blocked: <text>`) and
  in JSON (`blocker`), so the note is still visible where the work is.
- `todo -c` accepts only real categories and fails on anything else,
  `blocked` included, instead of filtering to an empty list.

## Consequences

- Consumers of `status --json` `unresolved_blockers` or `todo -c blocked`
  break loudly; JSON consumers that want noted rows filter `items[?blocker]`.
- No metadata change: BLOCKER stays a field, written by the same tools.
