# Reccmp Adaptations

Rebrew reimplements reccmp's toolset natively (see [ECOSYSTEM.md](ECOSYSTEM.md)).
Beyond the tool equivalents, four adaptations from the reccmp source are
**carried in the tree** (MIT License, © reccmp contributors — attribution
kept beside each): three modules plus the jump-swap check inside
`near_diag`. They close capability gaps where rebrew had no equivalent,
without adding a reccmp dependency.

| Module | Adapted from | What it adds |
|---|---|---|
| `pinned_diff.py` | `compare/pinned_sequences.py` | difflib-compatible matcher seeded with known line pins |
| `near_diag.py` (`jump_swap_ok`) | `compare/asm/fixes.py` | mirrored-jump check for a swapped `cmp` operand order |
| `vtordisp.py` | `analysis/vtordisp.py` | multiple-inheritance thunk (vtordisp) detection |
| `float_const.py` | `analysis/float_const.py` | float-constant pool discovery from code references |

---

## pinned_diff — pinned sequence matching

`SequenceMatcherWithPins(a, b, pinned_lines)` diffs two string sequences
where some `(a_index, b_index)` associations are known. Each pin bounds an
independent island diffed with a plain `SequenceMatcher`, so one big
mismatch cannot scramble the alignment of surrounding known-good spans.

```python
from rebrew.pinned_diff import SequenceMatcherWithPins

m = SequenceMatcherWithPins(target_mnemonics, compiled_mnemonics,
                            pinned_lines=[(4, 4), (12, 11)])
for op in m.get_opcodes():   # DiffOpcode(tag, a_start, a_end, b_start, b_end, a, b)
    ...
```

- Invalid (out-of-range) pins are dropped; non-monotonic pins raise
  `ValueError`.
- `ratio()` is the size-weighted mean of the island ratios.
- The module-level `get_grouped_opcodes(opcodes, n)` trims long `equal` runs
  to *n* lines of context, difflib-style, for renderers.

**near-diag integration.** `align_and_classify` computes `_auto_pins`:
instructions whose raw encoding is byte-identical AND unique on both sides
are pins — reliable landmarks register/encoding churn elsewhere cannot have
produced. The pin-partitioned opcodes then feed the same per-pair
classifier as before (`match` / `register` / `encoding` / `equivalent` /
`reloc` / `structural`).

## near_diag jump_swap — instruction equivalences

`jump_swap_ok(a, b)` checks two `"mnemonic operands"` lines: both are
conditional jumps compatible with a flipped `cmp` operand order
(`ja`↔`jb`, `jg`↔`jl`, `je`↔`je`, …). reccmp's whole-pattern fixes
(`patch_cmp_jmp`, `patch_mov_cmp_jmp`, `patch_mov_commutative`,
`patch_fld_fmul`) are not ported: no command consumes their orig-line
index sets.

**near-diag integration.** `classify_pair` treats a mirrored conditional
jump pair with the same displacement as `equivalent` — the compiler
flipped the `cmp` operand order, not the control flow. This must be checked
before the same-mnemonic branch because `ja`/`jb` differ by mnemonic.

## vtordisp — MI thunk detection

MSVC multiple-inheritance thunks adjust `this` (`sub ecx, imm8`) and jump
to the base implementation. Three shapes: `{disp, 0}` (8 bytes),
`{disp, +addend}` (14), `{disp, -addend}` (11).

```python
from rebrew.vtordisp import find_vtordisps

for t in find_vtordisps(code, base_addr):
    t.disp, t.addend   # MSVC spells this thunk "vtordisp{16, 0}"
    t.func_addr        # resolved jump target
```

Byte-pattern scan (no disassembly) — thunks are 8-14 byte islands the
linker may place between functions. Exposed in the `rebrew analyze` dossier
as the `vtordisp` section (VA, target, disp, addend, size).

## float_const — float constant pool

x87 instructions with an absolute memory operand (`D8`-`DF` opcode space,
`mod=00` forms) can reference constants instead of variables. Capstone
(x86-32) walks each code region, so a copy of those bytes inside another
instruction's immediate is not a reference. A pointer is kept when it lands
in a read-only data region and (optionally) sits at a relocation site.

```python
from rebrew.float_const import find_float_consts

consts = find_float_consts(
    code_regions,        # [(va, bytes)] per executable section
    const_regions,       # [(start_va, end_va)] read-only spans
    read_at,             # (va, size) -> bytes over the image
    reloc_sites=None,    # optional set of reloc VAs — filters immediates
)
# -> FloatConstant(address, size=4|8, value)
```

Complements `rebrew inline-strings` (strings, not floats) for data
annotation. Exposed in the `rebrew analyze` dossier as `float_consts`.

---

## Verification

`tests/test_reccmp_adaptations.py` covers every module: pin partitioning
and error cases, all three vtordisp shapes, float discovery filters
(writable-data rejection, dedup), and the near-diag wiring (jump-swap →
`equivalent`, pins keeping anchor alignment).
