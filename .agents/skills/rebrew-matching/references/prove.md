# Prove (symbolic equivalence): details

Use when STATUS is NEAR_MATCHING or SIZE_MISMATCH and structural diffs (register alloc, reorder,
loop layout) block EXACT/RELOC. Classify first, then prove.

```bash
rebrew diagnose near src/test/<file>.c --json    # classify: register/equivalent/reloc/structural
rebrew diagnose near src/test/<file>.c --fix-blocker
rebrew diagnose near --all --fix-blocker --json
rebrew prove src/test/<file>.c --json
rebrew prove src/test/<file>.c --dry-run --json
rebrew prove src/test/<file>.c --timeout 120 --json
rebrew prove src/test/<file>.c --loop-bound 50
rebrew prove my_func --start-offset 0 --end-offset 48
rebrew prove --all --json
rebrew prove my_func --check-edx --json
rebrew prove my_func --watch-va 0x10123456 --json
```

**Register-gap functions are prime PROVEN candidates.** `REGISTER (N% of delta)`
means bytes differ only by register allocation: prove EAX equivalence and promote
without fighting the bytes. `rebrew prove --all` first; "no terminal states" on a
loop → retry with `--loop-bound 50 --timeout 120`.

`rebrew diagnose near --json` → `categories` + `verdict`. Invalid relocs surface as `structural`.
`--fix-blocker` writes each verdict as BLOCKER (including suggested GA mutations).

How it works: extract target bytes + compile source → angr symbolic exec both →
parse C calling convention → hook external call relocs with `ReturnUnconstrained` →
LoopSeer-bounded exec → Z3 compare EAX (optional EDX).

**64-bit / EDX**: `long long` / `__int64` / `int64_t` / `uint64_t` use EDX:EAX.
`--check-edx` forces EDX; return types derived from the C signature auto-enable it.

Requirements: STATUS NEAR_MATCHING or SIZE_MISMATCH and the `[prove]` extra (angr). If `rebrew prove`
fails to import angr, the extra must be installed in the environment running
Rebrew. Install it when dependency setup is authorized; otherwise report this
requirement and continue work that does not need proving:
`uv tool install --reinstall 'rebrew[prove] @ git+https://github.com/maci0/rebrew.git'`
From a checkout, install the extra into that same tool environment:
`uv tool install --reinstall --editable '/path/to/rebrew[prove]'`.

Limitations: float-heavy may not prove; raise `--timeout` / `--loop-bound` for
loops. A proof is bounded by modeled calls, inputs, and loop limits; inspect
those assumptions before treating it as semantic evidence. `--watch-va` is **decimal unless `0x`-prefixed**
(unlike most rebrew tools). Keep watched set small (<10).
`prove_constraints.watched_vas` metadata is the durable form.
