# Retained coverage input envelopes from released versions

Each `vX.Y.Z/<case>/` holds a tiny project (`project/`, no user data) and the
coverage input envelope plus digest (`envelope.json`) that release produced for
it: `plan_coverage_readset` rows with `origin` assigned, and
`coverage_input_digest`. Built by running the tagged code from a git worktree
(`git worktree add <dir> vX.Y.Z`, `PYTHONPATH=<dir>/src`) on the project; the
`without_shared` case has no `src/shared`, `with_shared` has `src/shared/common.h`.

`tests/test_coverage_input_compat.py` verifies every fixture under the current
code. A deliberate change to the readset contract must add a migration note to
the CHANGELOG and regenerate or add fixtures in the same commit; never edit a
committed envelope to make the test pass.
