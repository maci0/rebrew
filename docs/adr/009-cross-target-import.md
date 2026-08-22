# ADR-009: Cross-target function import (`rebrew cross-import`)

- **Status**: Accepted
- **Date**: 2026-08

## Context

A single rebrew project can contain multiple targets (`[targets.*]` in
`rebrew-project.toml`, each with its own binary and `reversed_dir`), but
until now nothing connected them: each target's functions were reversed in
isolation.  Two common scenarios make that wasteful:

1. **Binary versions** — v1.0 and v1.1 of the same game share most code,
   but every VA differs between builds.  Reversing v1.1 means redoing every
   function already matched in v1.0.
2. **A DLL + EXE pair** — two binaries that ship together and share code
   (a static-lib blob linked into both, or the EXE duplicating library
   functions).  The shared functions are the same code at different VAs.

The existing `rebrew similar` command already computes structural
signatures (mnemonic histogram + call/branch agreement) for one target;
what was missing is the cross-target workflow: find the same code in
another target and reuse the already-matched source.

## Decision

Add a `rebrew cross-import` command.  The target the command runs against
is the **destination**; `--from TARGET` names the **source**.  For each
destination function whose metadata STATUS is not EXACT/RELOC/PROVEN, the
best-matching source function is imported when the match is unambiguous:

- **Matching is structural and compile-free**: both sides are
  signature-compared from their **target-binary bytes** (the source side
  restricted to functions already matched in the source target).  No
  toolchain is needed to find the matches — this also works where the
  docker image is absent.
- **Threshold**: the best score must be ≥ `--min-score` (default **95**)
  and beat the runner-up by ≥ `--min-gap` (default 5).  The high default
  is deliberate and measured: structural signatures are prologue-heavy, so
  a genuinely different function with a shared prologue/epilogue scores in
  the high 80s–low 90s against a sibling (92.9 on the two-PE fixture),
  while identical code scores 100 (or ~99.x for reloc-only differences).
  A wrong match below the threshold is reported as skipped, never forced.
- **Import**: the source `.c` marker line is rewritten to the destination
  module + VA and its `SIZE` to the destination's canonical size, the file
  is written into the destination's `reversed_dir` (replacing the
  destination function's existing file when it has one), then the function
  is compiled + verified against the destination binary through the shared
  `verify_entry` + `apply_status_updates` flow.  The verification is the
  final arbiter: an import that fails to verify keeps its source but is not
  promoted.
- `--dry-run` previews; `--json` emits structured results; `--va`/`--limit`
  restrict scope.

## Consequences

- **Positive**: matched functions propagate across versions/DLL-EXE pairs
  with one command; the verify step guarantees a wrong match cannot be
  silently promoted; matching needs no toolchain, so the command works on
  any project.
- **Negative**: structural matching can still misfire on near-identical
  sibling functions — the high default threshold and the runner-up gap
  bound this, and the verify step catches what slips through, but a
  `--min-score` lower than ~90 is a documented footgun.  The import is
  one-way (source → destination); bi-directional sync and diffing across
  targets are future work.  Only functions already matched in the source
  target are eligible — deliberately, since their sources are trusted to
  reproduce.
- **Contract notes**: imports rewrite the `.c` marker (module/VA/SIZE);
  the per-target config schema, metadata format, and STATUS semantics are
  unchanged.  The destination's existing annotation file is overwritten
  when present — users should review with `--dry-run` first.
