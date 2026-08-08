# GA Mutation Engine Reference

The Genetic Algorithm (GA) matching engine uses **121 C source mutation operators** to
explore the MSVC6 code generation space.  Each mutation transforms syntactically valid
C89 source into a semantically plausible variant, compiles it with MSVC6 (via Wine/wibo),
and scores the resulting binary against the target function's bytes.

All mutations live in [`mutator.py`](../src/rebrew/matcher/mutator.py) and are driven
by [tree-sitter](https://tree-sitter.github.io/) AST queries — never regex.

---

## How The GA Works

```
Source (.c) ──→ mutate_code(source, rng)
                  ├─ Pick random mutation from ALL_MUTATIONS (121 operators)
                  ├─ Apply AST-level transform to source text
                  ├─ Validate syntax (fast_syntax_check)
                  └─ Return (mutated_source, mutation_name) or None
                        │
                        ▼
                  build_candidate(source, ...)
                  ├─ SHA-256 hash → check compile cache
                  ├─ Run CL.EXE via Wine/wibo (60s timeout)
                  ├─ parse_obj_symbol_bytes() → extract function bytes + relocs
                  └─ Return BuildResult {ok, obj_bytes, reloc_offsets}
                        │
                        ▼
                  score_candidate(candidate_bytes, target_bytes, relocs)
                  ├─ Normalize relocations and register diffs
                  ├─ Byte-level + mnemonic-level similarity
                  └─ Return Score (lower = better, 0 = perfect)
                        │
                        ▼
                  [Repeat: mutate → compile → score for N generations]
```

### Key mechanics

- **Population**: Pool of candidates (default 64) evolved over generations
- **Selection**: Tournament selection — fittest survive, weakest are replaced
- **Mutation**: One random mutation per child (30% chance of 2–3 chained mutations)
- **Crossover**: Line-level crossover between two parents
- **Stagnation**: GA stops after 40 generations without improvement
- **Caching**: SQLite-backed `BuildCache` prevents recompiling identical source

---

## Mutation Categories

Mutations are grouped by the code generation aspect they target.

### 1. Commutative & Logic Rewriting

These mutations exploit the fact that MSVC6's code generation is
**not** commutative — swapping operand order changes register allocation
and instruction selection.

| Mutation | Transform | MSVC6 Rationale |
|----------|-----------|-----------------|
| `mut_swap_eq_operands` | `a == b` → `b == a` | Changes which value the `cmp` instruction uses as source vs destination |
| `mut_swap_ne_operands` | `a != b` → `b != a` | Same as `==` for inequality comparisons |
| `mut_swap_or_operands` | `a \|\| b` → `b \|\| a` | Changes short-circuit evaluation order — affects branch layout and fall-through |
| `mut_swap_and_operands` | `a && b` → `b && a` | Same as `\|\|` — different short-circuit order means different jump targets |
| `mut_reassociate_add` | `(a + b) + c` → `a + (b + c)` | Reassociation changes intermediate register lifetimes |
| `mut_demorgan` | `!(a && b)` ↔ `(!a \|\| !b)` | De Morgan's law — produces different branch structure in the compiled output |
| `mut_commute_float_operands` | `a * b` → `b * a` (float context) | MSVC6 float operations are **not** commutative at the codegen level due to x87 FPU stack ordering |
| `mut_commute_bit_or` | `a \| b` → `b \| a` | Swapping bitwise OR operands changes temporary register allocation order (left-to-right eval) |
| `mut_commute_bit_and` | `a & b` → `b & a` | Same as `\|` — different register gets the first operand computation |
| `mut_commute_bit_xor` | `a ^ b` → `b ^ a` | Same as `\|` and `&` — XOR operand order affects scratch register assignment |
| `mut_commute_add_general` | `(w >> 8) + (w << 8)` → `(w << 8) + (w >> 8)` | Generalized `+` swap for arbitrary sub-expressions — discovered via **SwapBytes** |
| `mut_commute_mul_general` | `(a + 1) * (b + 2)` → `(b + 2) * (a + 1)` | Generalized `*` swap for complex expressions beyond simple identifiers |

### 2. Comparison & Boolean

Small changes to comparison idioms that produce different instruction
sequences (e.g. `test` vs `cmp`, `setz` vs `setnz`).

| Mutation | Transform | MSVC6 Rationale |
|----------|-----------|-----------------|
| `mut_flip_eq_zero` | `x == 0` ↔ `!x` | `cmp eax, 0` vs `test eax, eax` — different encodings, different byte sizes |
| `mut_flip_lt_ge` | `a < b` ↔ `!(a >= b)` | Negated comparisons invert the jump condition (`jl` vs `jge`), changing branch layout |
| `mut_comparison_boundary` | `a < b` ↔ `a <= b - 1` | Boundary adjustment changes the immediate operand in `cmp` instructions |
| `mut_toggle_bool_not` | `!!x` → `x` | Double-negation removal — removes an unnecessary `test`/`setnz` sequence |
| `mut_negate_condition` | `if (a > b)` → `if (!(a > b))` | Wrapping in negation swaps the if/else fall-through direction |

### 3. Control Flow

Structural changes to branches and gotos that affect MSVC6's basic block
layout and jump threading.

| Mutation | Transform | MSVC6 Rationale |
|----------|-----------|-----------------|
| `mut_swap_if_else` | Swap if/else bodies, negate condition | Reverses fall-through direction — the "likely" path changes |
| `mut_reorder_elseif` | Swap two branches in else-if chain | Changes comparison order, affecting branch prediction hints |
| `mut_extract_else_body` | `if (a) { X } else { Y }` → `if (!a) { Y; return; } X` | Converts to early-exit (guard clause) pattern — eliminates a branch entirely |
| `mut_guard_clause` | Full if/else → negated guard + fall-through | Changes which path is the "common" (no-jump) path |
| `mut_hoist_return` | `return expr;` → `ret = expr; goto end;` | Accumulate return value in a variable + single return point — changes stack usage |
| `mut_sink_return` | `ret = expr; goto end;` → `return expr;` | Inverse — direct returns reduce register pressure |
| `mut_return_to_goto` | `return 0;` → `goto ret_false;` | Explicit goto to a label — changes basic block structure |
| `mut_goto_to_return` | `goto ret_false;` → `return 0;` | Inverse — direct return instead of goto |
| `mut_while_to_goto_loop` | `while (cond) { body }` → label + explicit `if/goto` | Completely different loop structure — no loop back-edge, just forward jumps |

### 4. Loop Transforms

Different loop forms produce different prolog/test/branch patterns.
MSVC6 generates measurably different code for `while` vs `do-while` vs
`for` vs loops with/without `break`.

| Mutation | Transform | MSVC6 Rationale |
|----------|-----------|-----------------|
| `mut_for_to_while` | `for(init; cond; inc)` → `init; while(cond) { body; inc; }` | `for` and `while` generate different loop header placement |
| `mut_while_to_for` | `while(cond) { body }` → `for(; cond;) { body }` | Inverse — `for` form may inline the update |
| `mut_while_to_dowhile` | `while(c)` → `if(c) do { } while(c)` | Do-while puts the condition at the bottom — loop body is the fall-through path |
| `mut_dowhile_to_while` | `do { } while(c)` → `while(c) { }` | Inverse — condition moves to top, changing branch direction |
| `mut_duplicate_loop_body` | Loop body × 2 (manual unrolling) | Reduces loop overhead but changes code size — different instruction cache behavior |
| `mut_invert_loop_direction` | `for(i=0; i<n; i++)` → `for(i=n-1; i>=0; i--)` | Reversed iteration changes comparison and the `dec`/`jns` vs `inc`/`jl` pattern |
| `mut_remove_loop_break` | Remove `break;` from loop body | Discovered via **HandleCommDlgError**: removing `break` matches MSVC6's fall-through branch layout |
| `mut_add_loop_break` | Insert `break;` at end of loop body | Inverse — adding `break` creates an explicit loop exit branch |

### 5. Ternary & Branch Folding

The ternary operator (`? :`) produces fundamentally different code than
`if/else` in MSVC6 — it uses `sbb` tricks and conditional moves instead
of branches.

| Mutation | Transform | MSVC6 Rationale |
|----------|-----------|-----------------|
| `mut_if_to_ternary` | `if (c) x = a; else x = b;` → `x = c ? a : b;` | Ternary uses branchless `sbb`/`cmov` patterns instead of jump-based if/else |
| `mut_ternary_to_if` | `x = c ? a : b;` → `if (c) x = a; else x = b;` | Inverse — branch-based may be preferred for complex expressions |
| `mut_if_false_to_bitand` | `if (!e) v = FALSE;` → `v &= e;` | Bitwise AND avoids a branch entirely — single `and` instruction |
| `mut_bitand_to_if_false` | `v &= e;` → `if (!e) v = 0;` | Inverse — explicit branch may match target's codegen |
| `mut_if_else_call_to_ternary_arg` | `if (c) F(a, X); else F(a, Y);` → `F(a, c ? X : Y);` | Discovered via **NpPrintDlgProc**: collapsing into ternary arg reduces AST use-count, stopping MSVC6 from enregistering `hwnd` into ESI |
| `mut_ternary_arg_to_if_else_call` | `F(a, c ? X : Y);` → `if (c) F(a, X); else F(a, Y);` | Inverse — split back out when ternary produces worse register allocation |

### 6. Cast & Type Manipulation

Type changes affect register width, sign extension, and zero extension
in MSVC6's codegen.

| Mutation | Transform | MSVC6 Rationale |
|----------|-----------|-----------------|
| `mut_add_cast` | Wrap expression in `(BOOL)` or `(int)` | Explicit casts force `movsx`/`movzx` or `test`+`setnz` sequences |
| `mut_remove_cast` | Strip `(TYPE)` cast | Removing a cast lets the compiler choose its own widening strategy |
| `mut_toggle_signedness` | `int` ↔ `unsigned int` | Changes sign-extension (`movsx` vs `movzx`) and comparison instructions (`jl` vs `jb`) |
| `mut_toggle_char_signedness` | `char` ↔ `unsigned char` | Byte-width sign-extension differences in MSVC6 |
| `mut_change_return_type` | `int` ↔ `BOOL` ↔ `void` etc. | Return type affects whether `eax` is explicitly set on all paths |
| `mut_widen_local_type` | `short` ↔ `int`, `BYTE` ↔ `DWORD` | Type width changes affect register sizing and memory access patterns |
| `mut_retype_local_equiv` | `int` → `DWORD` → `long` → `char*` (cycle) | Same-size type cycling influences MSVC6's internal register weighting heuristics |

### 7. Variable Layout & Declaration Order

MSVC6 allocates stack slots in **declaration order** — swapping declarations
changes which variable gets which `[ebp-N]` offset.

| Mutation | Transform | MSVC6 Rationale |
|----------|-----------|-----------------|
| `mut_swap_adjacent_declarations` | Swap two adjacent `TYPE var;` lines | Different stack offset assignments change `mov [ebp-X]` encoding sizes |
| `mut_reorder_declarations` | Swap any two declarations in compound body | Broader reordering for larger stack frame permutations |
| `mut_split_declaration_init` | `int x = 5;` → `int x; x = 5;` | Split init moves the assignment later  — changes register pressure at declaration point |
| `mut_merge_declaration_init` | `int x; x = 5;` → `int x = 5;` | Inverse — merged init may allow immediate folding |
| `mut_swap_adjacent_stmts` | Swap two adjacent assignment statements | Statement reordering changes register lifetimes and available registers |

### 8. Expression Rewriting

Algebraically equivalent rewrites that produce different instruction
sequences.

| Mutation | Transform | MSVC6 Rationale |
|----------|-----------|-----------------|
| `mut_compound_assign_toggle` | `x = x + n` ↔ `x += n` | Compound assignment may use `add [mem], imm` vs `mov reg, [mem]; add reg, imm; mov [mem], reg` |
| `mut_postpre_increment` | `i++` ↔ `++i` / `i--` ↔ `--i` | Post-increment may need a temp register to preserve the old value |
| `mut_xor_zero_toggle` | `x = 0` ↔ `x ^= x` | `xor eax, eax` (2 bytes) vs `mov eax, 0` (5 bytes) — different instruction encodings |
| `mut_zero_to_bitand` | `x = 0` ↔ `x &= 0` | `and [mem], 0` vs `mov [mem], 0` — triggers different instruction form when register is known zero |
| `mut_add_redundant_parens` | `x` → `(x)` | Redundant parens should be no-ops but can change AST structure in edge cases |
| `mut_fold_constant_add` | `a + 1 + 1` → `a + 2` | Constant folding reduces instruction count |
| `mut_unfold_constant_add` | `a + 4` → `a + 1 + 1 + 1 + 1` | Unfolding may produce different `inc`/`add` sequences |
| `mut_combine_ptr_arith` | `*(p + i * 4)` → `p[i]` | Combined pointer arithmetic uses `lea` addressing modes |
| `mut_split_ptr_arith` | `p[i]` → `*(p + i)` | Split forces manual offset calculation |

### 9. Pointer & Array Access

Different pointer/array idioms map to different x86 addressing modes
(`[base + index*scale + disp]`).

| Mutation | Transform | MSVC6 Rationale |
|----------|-----------|-----------------|
| `mut_change_array_index_order` | `a[i][j]` ↔ `a[j][i]` | Row-major vs column-major — completely different offset calculations |
| `mut_struct_vs_ptr_access` | `s.field` ↔ `s->field` | Dot vs arrow — changes whether an address or value is in the register |
| `mut_array_to_ptr_arith` | `p[i]` → `*(p + i)` | Array syntax uses scaled indexing; pointer arithmetic may use `lea` + `mov` |
| `mut_ptr_arith_to_array` | `*(p + i)` → `p[i]` | Inverse — array form uses built-in scaling |
| `mut_decouple_index_math` | `a[i*4+j]` → `tmp = i*4+j; a[tmp]` | Breaking `lea` folding by computing the index in a separate register |

### 10. Calling Convention & Parameters

Function call mechanics directly affect prologue/epilogue code and
parameter passing.

| Mutation | Transform | MSVC6 Rationale |
|----------|-----------|-----------------|
| `mut_toggle_calling_convention` | Add/remove `__cdecl`/`__stdcall`/`__fastcall` | `__stdcall` callee-cleans (uses `ret N`); `__cdecl` caller-cleans (uses `add esp, N`) |
| `mut_change_param_order` | Swap two parameter declarations | Changes which parameter is at which stack offset (`[ebp+8]`, `[ebp+C]`, ...) |
| `mut_pointer_to_int_param` | `void* p` → `int p` | Changes parameter width and sign-extension behavior |
| `mut_int_to_pointer_param` | `int p` → `char* p` | Inverse — pointer type enables dereference optimization |
| `mut_register_param` | Add `register` to function parameter | Discovered via **HandleSetupFlag**: `register LPCWSTR lpCmdLine` forces param into ESI, suppressing `push ebp` frame entirely |
| `mut_unregister_param` | Remove `register` from function parameter | Inverse — let the compiler decide register allocation for the parameter |

### 11. Stack Frame Manipulation (MSVC6-specific)

MSVC6 has specific thresholds for stack frame decisions — adding or
removing stack variables can push past these thresholds.

| Mutation | Transform | MSVC6 Rationale |
|----------|-----------|-----------------|
| `mut_inject_dummy_var` | Insert unused `int __dummy_N;` | Grows the stack frame past 4/8/16-byte alignment thresholds, changing prologue code |
| `mut_inject_dummy_array` | Insert unused `char __pad_N[K];` | Larger padding — pushes past bigger alignment boundaries |
| `mut_scope_variable` | Move declaration into `{ }` nested block | Variables in nested scopes may share stack slots (MSVC6 reuses space) |
| `mut_inject_block_register` | Wrap loop/stmts in `{ register int _reg_N; ... }` | C89 block-scoped register delays allocation, rotating ESI/EDI/EBX assignment |

### 12. Register Pressure (MSVC6-specific)

MSVC6's register allocator has specific, exploitable behaviors around
`volatile` and `register` keywords.

| Mutation | Transform | MSVC6 Rationale |
|----------|-----------|-----------------|
| `mut_toggle_volatile` | Add/remove `volatile` on local | `volatile` forces stack spills — the variable is always loaded/stored through memory |
| `mut_add_register_keyword` | Add `register` to local variable | Hints to use ESI/EDI/EBX — MSVC6 respects this hint strongly |
| `mut_remove_register_keyword` | Remove `register` from local | Let compiler choose — may use stack instead |
| `mut_swap_register_keywords` | Swap `register` between two locals | Changes ESI vs EDI assignment — different register encoding sizes |
| `mut_add_volatile_intermediate` | `a = expr;` → `volatile tmp = expr; a = tmp;` | Forces an intermediate stack spill, breaking register chains |
| `mut_reorder_register_vars` | Reorder `register` variable declarations | MSVC6 assigns ESI, EDI, EBX strictly in declaration order |
| `mut_inject_dummy_registers` | Inject 1–3 dummy `register int` locals | Consumes volatile registers (eax/ecx/edx) so real variables land in ESI/EDI/EBX, changing the prologue/epilogue push/pop sequence and code layout |

### 13. Zero-Extension Patterns (MSVC6-specific)

Specific tricks for byte-width zero-extension that MSVC6 uses.

| Mutation | Transform | MSVC6 Rationale |
|----------|-----------|-----------------|
| `mut_preinit_byte_load` | `int val = 0; val = *p;` before byte loads | Triggers `xor reg, reg` before `mov al, [mem]` — pre-clearing the full register |
| `mut_cast_to_bitmask` | `(BYTE)x` → `x & 0xFF` | Explicit bitmask vs cast — may produce `and eax, 0FFh` instead of `movzx` |

### 14. Branch Merging (MSVC6-specific)

Moving code between if/else branches and surrounding context changes
how MSVC6 merges or splits return paths.

| Mutation | Transform | MSVC6 Rationale |
|----------|-----------|-----------------|
| `mut_hoist_common_tail` | Move identical last statement out of both if/else branches | Discovered via **GetPrinterDC**: hoisting `MessageBoxW` let the compiler merge return paths into a single epilogue |
| `mut_sink_common_tail` | Move post-if/else statement into both branches | Inverse — duplicating into branches may improve instruction cache locality |

### 15. Temporary Variables & Aliasing

Introducing or removing temporaries changes the register allocator's
view of value lifetimes.

| Mutation | Transform | MSVC6 Rationale |
|----------|-----------|-----------------|
| `mut_introduce_temp_for_call` | `f(g(x))` → `tmp = g(x); f(tmp);` | Separating the call forces the return value into a specific register before the outer call |
| `mut_remove_temp_var` | `tmp = expr; var = tmp;` → `var = expr;` | Removing the temp reduces register pressure — one fewer live variable |
| `mut_introduce_local_alias` | `var = id;` → `alias = id; var = alias;` | Extra alias adds a register copy that may spill to stack |
| `mut_extract_condition_to_var` | `if (complex)` → `int cond = complex; if (cond)` | Forces the condition into a variable — may change branch vs `test` patterns |

### 16. Accumulator & Return Patterns

Different ways to structure "check and return" patterns.

| Mutation | Transform | MSVC6 Rationale |
|----------|-----------|-----------------|
| `mut_early_return_to_accum` | `if (!e) return 0;` → `ret &= e;` | Replaces branches with bitwise AND accumulation — branchless validation chains |
| `mut_accum_to_early_return` | `ret &= e;` → `if (!e) return 0;` | Inverse — early return may be faster for common failure cases |

### 17. Switch/Case Transforms

MSVC6 generates very different code for `switch` statements depending on
case density, ordering, and structure.

| Mutation | Transform | MSVC6 Rationale |
|----------|-----------|-----------------|
| `mut_reorder_switch_cases` | Swap two `case` clauses | Case ordering affects jump table layout and branch prediction |
| `mut_switch_to_if_chain` | `switch (x) { case A: ... }` → `if (x == A) { ... }` | If-chain avoids jump table overhead for sparse switches |
| `mut_if_chain_to_switch` | `if (x == A) ... else if (x == B)` → `switch (x) { ... }` | Inverse — switch enables jump table optimization |
| `mut_split_switch` | Split switch into two nested switches by range | Reduces jump table size — may use binary search instead |
| `mut_move_switch_default` | Move `default:` to top or bottom | Changes fall-through behavior and default path optimization |
| `mut_switch_add_explicit_default` | Add `default: break;` if missing | Explicit default may change jump table generation |
| `mut_switch_break_to_return` | `case X: ...; break;` → `case X: ...; return;` | Direct return avoids the break-to-end jump |

### 18. Condition Splitting & Merging

Structural transforms on compound boolean conditions.

| Mutation | Transform | MSVC6 Rationale |
|----------|-----------|-----------------|
| `mut_split_and_condition` | `if (a && b)` → `if (a) { if (b) }` | Splits lazy AND into nested ifs — different short-circuit behavior |
| `mut_split_or_condition` | `if (a \|\| b)` → `if (a) { ... } else if (b) { ... }` | Splits lazy OR into else-if chain |
| `mut_merge_nested_ifs` | `if (a) { if (b) }` → `if (a && b)` | Inverse of split — merges back into compound condition |

### 19. Miscellaneous

| Mutation | Transform | MSVC6 Rationale |
|----------|-----------|-----------------|
| `mut_insert_noop_block` | Insert `if (0) {}` before a statement | Dead code that MSVC6 may not fully eliminate — changes basic block boundaries |
| `mut_loop_condition_extraction` | Extract loop condition to a temp variable | Forces the condition evaluation outside the loop header |
| `mut_wrap_in_else` | `if (c) { X } Y;` → `if (c) { X } else { Y; }` | Wrapping the fall-through in an explicit else changes branch structure |
| `mut_toggle_dllimport` | Add/remove `__declspec(dllimport)` on extern | Essential for Win32 API calls — produces direct IAT jumps vs thunks |
| `mut_memcpy_to_loop` | `memcpy(d, s, N)` → explicit byte-copy loop | Inline loop vs library call — completely different codegen |
| `mut_loop_to_memcpy` | Explicit byte-copy loop → `memcpy()` | Inverse — library call may be more compact |

### 20. MSVC6 Codegen Quirks (Phase 6)

Targeted mutations for specific MSVC6 code generation behaviors: De Morgan branch
inversion, stack frame padding, and argument evaluation order.

| Mutation | Transform | MSVC6 Rationale |
|----------|-----------|-----------------|
| `mut_invert_if_else` | `if (a == b) { X } else { Y }` → `if (a != b) { Y } else { X }` | Negates the comparison operator and swaps bodies. Changes `je`/`jne` branch direction, affecting fall-through path and instruction cache behavior |
| `mut_dummy_stack_vars` | Insert `volatile int __pad_N = 0;` at function top | Grows stack frame past MSVC6 alignment thresholds (4/8/12/16/20/24/32/48/64 bytes), changing prologue strategy between `push ecx`/`push edx` and `sub esp, N` |
| `mut_extract_complex_args` | `F(g(x), a+b)` → `tmp1 = g(x); F(tmp1, a+b);` | Extracting nested calls and complex expressions from function arguments changes C evaluation order, which MSVC6 respects strictly — affects which value is in which register at the `push` sequence |

> Note: `mut_pragma_optimize`/`mut_pragma_optimize_remove` and `mut_loop_convert`
> were removed — `mutate_code` operates on the function body only (never the
> preamble, so the pragma pair could not fire), and `mut_loop_convert` duplicated
> `mut_while_to_dowhile`/`mut_for_to_while`/`mut_while_to_for` while its
> do-while → while branch silently changed semantics.

---

## Discovery Origins

Many mutations were discovered through manual decompilation of real MSVC6
binaries.  The table below traces each discovery to the function that
inspired it.

| Function | Problem | Mutation | Result |
|----------|---------|----------|--------|
| **HandleSetupFlag** | `push ebp` frame not suppressed | `mut_register_param` — `register LPCWSTR` forced param into ESI | Frame omission → EXACT |
| **HandleCommDlgError** | Wrong branch layout in loop | `mut_remove_loop_break` — removed `break` to match fall-through | 0 structural diffs → EXACT |
| **NpPrintDlgProc** | `hwnd` enregistered into ESI | `mut_if_else_call_to_ternary_arg` — ternary arg reduced AST use-count | Register allocation fixed → EXACT |
| **GetPrinterDC** | Return paths not merged | `mut_hoist_common_tail` — hoisted `MessageBoxW` out of branches | Compiler merged returns → NEAR_MATCH |
| **SwapBytes** | Register allocation wrong for `(w >> 8) + (w << 8)` | `mut_commute_add_general` — swapped to `(w << 8) + (w >> 8)` to match eval order | Correct register assignment → EXACT |

---

## Mutation Selection

By default, `mutate_code()` picks uniformly at random from `ALL_MUTATIONS`.
You can bias selection via the `mutation_weights` parameter:

```python
weights = {"mut_swap_if_else": 3.0, "mut_for_to_while": 2.0}
mutated, name = mutate_code(source, rng, mutation_weights=weights)
```

### Multi-Mutation

Children have a 35% chance of undergoing 2–3 **chained mutations** in a
single generation step.  This enables larger jumps in the search space
that single mutations cannot reach.  (Bumped from 30% after expanding
to 121 operators.)

---

## Adding A New Mutation

See contributor guidelines in [`AGENTS.md`](../AGENTS.md#adding-a-new-ga-mutation)
(a.k.a. `CLAUDE.md`).


> Consolidation note (2026-08-08): `mut_commute_simple_add`/`mut_commute_simple_mul`
> (identifier-only subsets of `mut_commute_add_general`/`mut_commute_mul_general`),
> `mut_extract_args_to_temps` (subset of `mut_extract_complex_args`), and
> `mut_split_cmp_chain`/`mut_merge_cmp_chain`/`mut_flatten_nested_if` (duplicates
> of the Phase-3 `mut_split_and_condition`/`mut_merge_nested_ifs`) were removed —
> they double/triple-weighted identical transforms in the GA.  Use the survivor
> in each family.
