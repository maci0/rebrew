# Reccmp Adaptations

Rebrew reimplements reccmp's toolset natively (see [ECOSYSTEM.md](ECOSYSTEM.md)).
Beyond the tool equivalents, six modules are **adapted from the reccmp
source** (MIT License, © reccmp contributors — attribution kept in each
module docstring). They close capability gaps where rebrew had no
equivalent, without adding a reccmp dependency.

| Module | Adapted from | What it adds |
|---|---|---|
| `pinned_diff.py` | `compare/pinned_sequences.py` | difflib-compatible matcher seeded with known line pins |
| `asm_equiv.py` | `compare/asm/fixes.py` | instruction-equivalence patterns (swapped cmp/jump, mov+commutative, fld/fmul) |
| `vtordisp.py` | `analysis/vtordisp.py` | multiple-inheritance thunk (vtordisp) detection |
| `float_const.py` | `analysis/float_const.py` | float-constant pool discovery from code references |
| `demangle.py` | `cvdump/demangler.py` | MSVC symbol helpers (string consts, vtable names) |
| `pdb_cvdump.py` | `cvdump/runner.py` + `parser.py` | MSVC PDB reading via the WDK `cvdump.exe` tool |

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
- `get_grouped_opcodes()` trims long `equal` runs to *n* lines of context,
  difflib-style, for renderers.

**near-diag integration.** `align_and_classify` computes `_auto_pins`:
instructions whose raw encoding is byte-identical AND unique on both sides
are pins — reliable landmarks register/encoding churn elsewhere cannot have
produced. The pin-partitioned opcodes then feed the same per-pair
classifier as before (`match` / `register` / `encoding` / `equivalent` /
`reloc` / `structural`).

## asm_equiv — instruction equivalences

Text-level checks on `"mnemonic operands"` lines, adapted from reccmp's
diff-fix heuristics:

- `jump_swap_ok(a, b)` — both are conditional jumps compatible with a
  flipped `cmp` operand order (`ja`↔`jb`, `jg`↔`jl`, `je`↔`je`, …).
- `is_operand_swap(a, b)` — same instruction with operands exchanged
  (character-multiset check; robust against templates/string literals).
- `get_patched_jump(a, b)` — `b`'s jump with `a`'s condition mnemonic
  (keeps `b`'s displacement so a real displacement difference survives).
- `patch_cmp_jmp` / `patch_mov_cmp_jmp` / `patch_mov_commutative` /
  `patch_fld_fmul` — whole-pattern detectors returning the set of orig-line
  indices each pattern explains, or an empty set. `PATCHERS` is the
  registry; a text-diff renderer can apply each to aligned mismatch
  islands before classifying the remainder.

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

for t in find_vtordisps(code_bytes, base_va):
    t.name_hint        # "vtordisp{16, 0}" — MSVC's spelling, for stub naming
    t.func_addr        # resolved jump target
```

Byte-pattern scan (no disassembly) — thunks are 8-14 byte islands the
linker may place between functions. Exposed in the `rebrew analyze` dossier
as the `vtordisp` section (VA, target, disp, addend, size).

## float_const — float constant pool

x87 instructions with an absolute memory operand (`D8`-`DF` opcode space,
`mod=00` forms) can reference constants instead of variables. A pointer is
kept when it lands in a read-only data region and (optionally) sits at a
relocation site.

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

## demangle — MSVC symbol helpers

Scoped subset needing no demangler dependency:

- `parse_encoded_number("BC@")` → `0x12` — MSVC encoded lengths
  (`A`-`P` = hex digits `0`-`F`); raises `InvalidEncodedNumberError`.
- `demangle_string_const(symbol)` → `StringConstInfo(length, is_utf16)` —
  decodes width/length from `??_C@_…` string-constant names (text itself
  is read from the binary at the symbol's address).
- `demangle_vtable(symbol)` — class name from a `??_7` vtable symbol,
  self-contained parser: simple and one-level template cases, no backrefs
  or virtual inheritance (same ceiling as reccmp's parked implementation).
- `msvc_demangle` / `get_function_arg_string` / `get_vtordisp_name` — use
  `pydemumble` when installed; otherwise a decoration-strip fallback that
  covers plain-C symbols. `pydemumble` is intentionally NOT a rebrew
  dependency.

## pdb_cvdump — PDB access via cvdump.exe

MSVC 6-era PDBs cannot be read by `llvm-pdbutil`; the WDK's `cvdump.exe`
(run under wine on Linux) still parses them. rebrew ships the runner plus a
parser for the sections it consumes:

- `LINES` — per-source-file line→address pairs (function extents)
- `PUBLICS` — mangled public symbols (functions, strings, vtables)
- `SECTION CONTRIBUTIONS` — per-module symbol sizes (data sizing)
- `MODULES` — object/library files linked into the binary

```python
from rebrew.pdb_cvdump import Cvdump, cvdump_available

if cvdump_available():            # REBREW_CVDUMP env override, then PATH
    parser = Cvdump(pdb_path).publics().modules().section_contributions().run()
    parser.publics      # [PublicsEntry]
    parser.sizerefs     # [SizeRefEntry]
    parser.modules      # [ModuleEntry]
    parser.lines        # {Path: [LineValue]}
```

Full type-leaf (`TYPES`/`SYMBOLS`) import is deliberately deferred — until
then, struct layouts come from the Ghidra/BinSync path.

---

## Verification

`tests/test_reccmp_adaptations.py` covers every module: pin partitioning
and error cases, each patcher pattern (positive + negative), all three
vtordisp shapes, float discovery filters (writable-data rejection, dedup),
demangle round trips, cvdump section parsing against sample output, and the
near-diag wiring (jump-swap → `equivalent`, pins keeping anchor alignment).
