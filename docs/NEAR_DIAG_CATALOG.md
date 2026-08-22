# near-diag symptom index

Generated from the verdict registry (`rebrew near-diag --catalog`).  When a function is NEAR_MATCHING, the verdict names the dominant delta category; the row below gives the actionable suggestion and the GA mutation operators most likely to close the gap.

| Symptom (verdict category) | What it means / what to do | GA mutations to try |
|---|---|---|
| `register` | Register allocation differs — try reordering expressions, swapping loop counters, or splitting/merging statements.  Register gaps are usually PROVEN-able: run 'rebrew prove' to establish semantic equivalence without byte changes. | `mut_reorder_register_vars`, `mut_swap_register_keywords`, `mut_add_register_keyword`, `mut_toggle_volatile`, `mut_hoist_repeated_deref`, `mut_inject_dummy_var`, `mut_inject_dummy_array`, `mut_scope_variable`, `mut_reorder_declarations`, `mut_swap_adjacent_stmts` |
| `equivalent` | Instruction selection differs — try alternative C constructs (e.g. pointer arithmetic vs indexing, cast-based masking). | `mut_array_to_ptr_arith`, `mut_ptr_arith_to_array`, `mut_change_array_index_order`, `mut_struct_vs_ptr_access`, `mut_add_cast`, `mut_remove_cast`, `mut_toggle_signedness`, `mut_if_false_to_bitand`, `mut_fold_constant_add`, `mut_unfold_constant_add`, `mut_combine_ptr_arith`, `mut_decouple_index_math` |
| `structural` | Control flow / block layout differs — try restructuring loops or if/else; may need a compiler-pattern workaround. | `mut_swap_if_else`, `mut_guard_clause`, `mut_hoist_return`, `mut_sink_return`, `mut_return_to_goto`, `mut_while_to_dowhile`, `mut_dowhile_to_while`, `mut_for_to_while`, `mut_while_to_for`, `mut_invert_loop_direction`, `mut_duplicate_loop_body`, `mut_hoist_common_tail`, `mut_sink_common_tail`, `mut_invert_if_else`, `mut_if_to_ternary`, `mut_ternary_to_if` |
| `reloc` | Difference is confined to relocation sites — the match is RELOC-level. | — (no mutation helps) |
| `effective` | Same instructions, different registers (not byte-identical) — `rebrew prove` for PROVEN, or register-nudging C tweaks | `mut_reorder_register_vars`, `mut_swap_register_keywords`, `mut_add_register_keyword`, `mut_toggle_volatile`, `mut_hoist_repeated_deref`, `mut_inject_dummy_var`, `mut_inject_dummy_array`, `mut_scope_variable`, `mut_reorder_declarations`, `mut_swap_adjacent_stmts` |
| `match` | Bytes are identical — nothing to fix | — |
