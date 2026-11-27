# Function Status Reference

Rebrew stores accepted function verdicts under `MODULE.0xVA` keys in managed
metadata. See [metadata formats](METADATA_FORMAT.md) for identity and writers,
and [status accounting](CLI.md#rebrew-status) for byte and function counts.

## Status Overview

The matched columns refer to byte-match credit.

| Status | Byte match | Set by | Counts in coverage |
|--------|-----------|--------|-------------------|
| No stored verdict | n/a | Coverage presents this as `UNKNOWN` | No |
| `STUB` | Placeholder or comparison below threshold | `intake`, `source document-unmatched`, `test`, or `verify` | No |
| `NEAR_MATCHING` | ≥60% | `rebrew test` / `rebrew verify` | No matched-function credit |
| `RELOC` | 100% (masked) | `rebrew test` / `rebrew verify` | Yes |
| `EXACT` | 100% (raw object, or raw linked image) | `rebrew test` / `rebrew verify`; linked EXACT via `rebrew verify --text --raw-link` | Yes |
| `PROVEN` | Semantic (bytes differ) | `rebrew prove` | No (shown separately) |
| `SKIP` | N/A | Parked in managed metadata | No byte-match credit |

Reports can also contain `SIZE_MISMATCH`, `COMPILE_ERROR`, `EXTRACT_ERROR`,
`MISSING_SIZE`, `MISSING_FILE`, or `INVALID_VA`. The metadata writer applies
[verdict protection](METADATA.md#who-owns-which-fact) before persisting a
result. If a remote compile gives no verdict or the compiler is unavailable
for selection, Rebrew reports `NOT_RUN` and keeps the stored verdict.

---

## No stored verdict

Catalog functions without a stored verdict appear as `UNKNOWN` in coverage.
That includes undocumented functions without a source file. `rebrew todo`
surfaces them as action items. `UNDOCUMENTED` is invalid in managed metadata.

```bash
rebrew todo --json          # find next undocumented function to start
rebrew skeleton 0x10008880  # generate the source and record its identity
```

---

## STUB

`intake` and `source document-unmatched` seed `STUB` for generated placeholders. `test` and `verify`
return it for comparable bodies below 60% similarity, including regressions.
A body of at most 8 bytes also returns `STUB` when the target is at least
12 bytes and more than twice as large. The metadata writer preserves a
stored `STUB` against `SIZE_MISMATCH` and `MISSING_SIZE`.

```toml
["SERVER.0x10008880"]
status = "STUB"
size = 163
blocker = "needs complete rewrite from scratch, 199B target vs 163B compiled"
```

A persistent STUB can indicate an unfinished body, a missing CRT helper,
a wrong calling convention, or a different algorithm.

---

## NEAR_MATCHING

The compiled output is ≥ 60% byte-similar to the target. That percentage does
not prove equivalent behavior. It can have structural differences
that persist after relocation masking: different register allocation, different loop
structure, different branch ordering.

`rebrew diagnose near --fix-blocker` auto-classifies the difference type and writes it to the metadata:

```toml
["SERVER.0x10008880"]
status = "NEAR_MATCHING"
size = 130
blocker = "register allocation (esi/edi swap)"
blocker_delta = 7
```

Common blockers: register allocation, loop peeling, branch inversion, code block
reordering, stack frame choice, operand swaps, small byte deltas.

**Next steps**: Iterate code structure, or run `rebrew match run` (GA engine) to explore
permutations. For near-miss cases (small delta), try `rebrew match batch --near-miss`.
Strong candidates for `rebrew prove` when the delta is very small.

---

## RELOC

Identical after masking accepted relocatable bytes (`call rel32`, `jmp rel32`,
`mov eax,[abs32]`, etc.). This establishes byte agreement outside those operand
slots. The relocation policy can accept an uncatalogued symbol without resolving
its target, so RELOC alone does not prove callee/global bindings or semantic
equivalence. The linker fills these operands; [linked EXACT](#linked-exact)
checks the function's raw linked bytes without masking.

```
Target:  50 e8 f0 83 00 00 8b f8 83 c4 04 a1 80 58 03 10
Output:  50 e8 00 00 00 00 8b f8 83 c4 04 a1 00 00 00 00
         == == ~~ ~~ ~~ ~~ == == == == == == ~~ ~~ ~~ ~~
```

This is the **typical best result** for functions that call other functions or reference
globals. Counts as complete in the project coverage metrics.

```toml
["SERVER.0x10008880"]
status = "RELOC"
size = 42
```

---

## EXACT

Byte-for-byte identical. Every single byte in the compiled `.obj` matches the target
bytes extracted from the target binary.

```
Target:  53 8b 5c 24 08 56 57 8b 43 10 50 e8 f0 83 00 00
Output:  53 8b 5c 24 08 56 57 8b 43 10 50 e8 f0 83 00 00
         == == == == == == == == == == == == == == == ==
```

Rare in practice for functions with external calls (since call offsets are
linker-dependent). Common for leaf functions with no calls or global refs.

### Linked EXACT

A RELOC function also earns EXACT when its bytes in the raw link equal the
reference bytes with no masking: the linker resolved every relocation to the
reference value. `rebrew verify --text --raw-link` records it when the built
image places the function at its reference VA. The linked bytes are identical,
so it is a byte match like any other EXACT. The `verification` table carries
`linked_image` and `linked_image_hash`; a later object compare of RELOC keeps
EXACT only while the compile inputs and the image hash are unchanged. See
[linked EXACT](CLI.md#rebrew-verify).

```toml
["SERVER.0x10008880"]
status = "EXACT"
size = 31
```

---

## PROVEN

Equivalence verified by `rebrew prove` using angr symbolic execution and Z3
constraint solving, within the proof's assumptions and checked observations.
The compiled bytes differ structurally (register allocation, instruction
reordering or loop unrolling). The proof applies to the configured argument
constraints, modeled external calls and explored paths; execution has loop and
time limits. It compares selected return registers and watched memory locations,
not every possible side effect. A timeout or incomplete exploration does not
establish equivalence.

Used when a function is stuck on NEAR_MATCHING due to compiler jitter that can't be
resolved by flag sweeps or code restructuring. Single-function proof also admits
SIZE_MISMATCH and a STUB with a nonempty BLOCKER or nonzero BLOCKER_DELTA;
a cached NEAR_MATCHING/SIZE_MISMATCH verdict can satisfy that admission check.
Batch `--all` selects stored NEAR_MATCHING/SIZE_MISMATCH entries with known sizes.
See [the proof command](CLI.md#rebrew-prove) for its options and assumptions.

```toml
["SERVER.0x10008880"]
status = "PROVEN"
size = 142
```

```bash
rebrew prove src/target/calculate_physics.c   # runs angr + Z3, ~15-60s
```

Not a byte match: excluded from matched counts and byte coverage, and kept
on `rebrew todo` as improve-match work.  The next `rebrew test` / `rebrew
verify` records the byte result over PROVEN.

---

## SKIP

Intentionally excluded from matching. Used for functions that are known to be
unmatchable or irrelevant to the decompilation effort:

| Reason | Examples |
|--------|---------|
| IAT thunks | `jmp [__imp_GetProcAddress]`: compiler-generated, no source |
| SEH helpers | `__except_handler3`, `__local_unwind2`: MSVC runtime internals |
| ASM builtins | `_memcpy_rep`, `_strlen_sse2`: hand-written assembly |
| Import stubs | Trampolines to DLL imports with no game logic |
| Padding / alignment | Dead bytes between functions, never executed |
| Linker-generated | `__security_cookie_check`, `__SEH_prolog` |

To park a reviewed function, import `update_source_status` from
`rebrew.metadata.functions` and call
`update_source_status(cfg, "SKIP", module, va, clear_blockers=False)`.
It returns `True` when it writes the row and `False` when it leaves it alone.
Test and verify preserve the parked status by default. A non-library SKIP span
counts as unmatched in [executable-byte accounting](CLI.md#rebrew-status).

```bash
rebrew todo --json    # find parking candidates
```

---

## How rebrew test Classifies Results

After compiling and extracting the candidate symbol, Rebrew compares it
against the original function. An accepted match is `EXACT` if no relocation
mask is needed and `RELOC` if relocation bytes are masked. Different lengths
usually produce `SIZE_MISMATCH`, with the stub exception described above.
For remaining mismatches, positional byte agreement of 60% or more produces
`NEAR_MATCHING`. A lower percentage produces `STUB`. Instruction similarity is
a separate diagnostic score.

## Relocation Masking Details

`test` and `verify` mask by the compiled object's relocation records
(`smart_reloc_compare` in `src/rebrew/compare/coff_reloc.py`): a DIR32 slot is accepted
when the target holds `symbol_va + addend`, a REL32 slot when it holds
`symbol_va + addend - pc` (masked without the absolute check when the section VA
is unknown), and a DIR32 into the import address table is masked without name
validation. In normal agreement mode an uncatalogued symbol is masked, and a
DIR32 whose value matches no other catalogued symbol is tolerated; an ambiguous
symbol is rejected. `strict=True` (proof mode) rejects every other slot that
does not equal its resolved symbol, uncatalogued ones included;
`check_known_bindings=True` rejects a conflicting mapped operand but keeps the
tolerant rule for uncatalogued symbols. The IAT exception applies in every mode.
With no relocation records the comparator falls back to zero-span detection
(`00 00 00 00` runs in the object aligned with non-zero target bytes).

The GA's candidate scoring uses a separate opcode heuristic, the normalizer
`_zero_reloc_fields` (driven by `_normalize_and_mnems_x86_32` in
`src/rebrew/matcher/scoring.py`), which zeros these fields without relocation
records. Byte offsets start at the opcode, after any legacy prefixes.

| Pattern | Opcode | Bytes zeroed | Why |
|---------|--------|-------------|-----|
| `call rel32` | `E8` | bytes 1-4 | Offset from the next instruction |
| `jmp rel32` | `E9` | bytes 1-4 | Offset from the next instruction |
| Accumulator `mov` to or from `[moffs32]` | `A0`–`A3` | bytes 1-4 | Absolute address of a global variable |
| `cmp [abs32], imm8` | `83 3D` | bytes 2-5 | Address of global in comparison |
| Conditional jumps near | `0F 8x` | bytes 2-5 | 32-bit relative offsets in Jcc instructions |
| `push imm32` | `68` | bytes 1-4 | Only when value looks like an address (> 0x10000000) |
| `mov reg, imm32` | `B8`-`BF` | bytes 1-4 | Only when the value exceeds `0x10000000` |
| `mov reg, [abs32]` | `8B 05/0D/15/1D/25/2D/35/3D` | bytes 2-5 | Global variable loads |
| `mov [abs32], reg` | `89 05/0D/15/1D/25/2D/35/3D` | bytes 2-5 | Global variable stores |
| `call/jmp dword ptr [abs32]` | `FF 15/25` | bytes 2-5 | Indirect call/jump through an absolute memory slot |

For other instructions six or more bytes long, the heuristic also masks a
32-bit memory displacement with an absolute value above `0x10000`.

For both, identical bytes after masking mean the code agrees outside the masked
fields, not a proof that only addresses differ (the GA heuristic masks any
large `mov` immediate). Only the comparator's verdict earns RELOC.

---

## Observed NEAR_MATCHING Patterns

These examples record what blocked byte matching in the Guild project with
MSVC 6 and `/O2 /Gd`. The sizes and counts apply to that project.

### Close NEAR_MATCHING analysis (0-3B delta)

There, GA mutations (100 gen, pop 64) did not improve close NEAR_MATCHING functions; the remaining deltas were compiler-internal decisions the tried mutations did not influence.

Common uncontrollable blocker categories:
1. **Register allocation**: ebx vs edi, eax vs ecx swaps (most common)
2. **Loop rotation**: compiler peels first iteration or uses jge+jmp vs jl
3. **Instruction folding**: lea+mov to single mov with SIB, saves 2B
4. **Zero-extend patterns**: xor+mov dl vs bare mov dl for byte params
5. **Stack frame choice**: push ecx vs sub esp,8 for locals
6. **Comparison direction swap**: cmp eax,ecx/jae vs cmp ecx,eax/jbe

### Register allocation as systemic ceiling

Register allocation was the primary blocker for that project's remaining game functions. With `/O2 /Gd` (`/O2` implies frame-pointer omission), the compiler may use ebp as a callee-save register, but only if there's enough register pressure. If C source doesn't create enough demand, the compiler won't allocate ebp, producing fewer push/pop instructions and different register assignments throughout.

### Worked example: Guild CRT dependencies

In that project, unreversed helpers held back work on the CRT functions that
depend on them (a caller can still byte-match with an unreversed callee, since
the comparison checks the caller's bytes and relocations):
- `memmove` (hand-written ASM) blocks `fread`, `fwrite`
- SEH functions block `_stricmp`, `_strnicmp`
- `strcat` (hand-written ASM) blocks downstream functions
- `FreeHeapBlockWithRuntimeLock` (SEH) blocks ~33 other functions


### Worked example: Guild STUBs

- Remaining GAME STUBs range from 355B to 6000B+. Even small ones (under 400B) face register pressure challenges with `/O2 /Gd`.
- MSVCRT STUBs range from 11B to 1825B. Many small ones (85-200B) may be achievable using reference CRT source.
- Verifying string literals via hex dump is critical: Ghidra often gets string references wrong.
- Dead assignments in STUBs are common: Ghidra generates reads for values the target code never uses.
- Entity records are 65 bytes: MSVC6 decomposes `*65` as `shl eax, 6; add eax, base; add eax, index`.
- CRT `_mbctype` access: `_mbctype[(unsigned char)c + 1] & 4` compiles to `test byte ptr [reg + 0x11766321], 4`; the +1 offset is baked into the immediate address.

## Color roles

Status words and terminal output follow the shared
[Relumea brand palette](https://github.com/relumea/ai.relumea.brand/blob/36c575575f9186181664f73e320680af9c828246/docs/brand/BRAND.md#cli-standard).
EXACT is emerald, RELOC cyan teal, PROVEN forest green (mint fills), NEAR_MATCHING steel blue,
STUB neutral gray and SIZE_MISMATCH failure brick. LIBRARY is mulberry origin
attribution, not a byte-verification result. LIVE is activity only; it does
not become a stored verification verdict. Colors never change classification
or accounting, and labels remain present when color is disabled.
