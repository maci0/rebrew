# AGENTS.md: compare/

Binary/function comparison, relocations, near-match diagnosis, drift, and stack analysis.

## Modules

| Module | Role |
|--------|------|
| `alignment.py` | Instruction alignment shared by comparison reports and statement search. |
| `coff_reloc.py` | Core matching and relocation handling logic. |
| `diff.py` | diff.py – Compile and diff a reversed function against the target binary. |
| `drift.py` | Localise byte drift between compiled and reference code from branch targets. |
| `drift_cli.py` | ``rebrew diagnose drift`` -- localise byte drift from branch targets, without disassembling. |
| `gap_trace.py` | gap_trace.py — where does a function lose (or gain) length vs the reference? |
| `instruction_clones.py` | instruction_clones: exact duplicate structure over instruction streams. |
| `instruction_diff.py` | Instruction-level comparison of a function's target bytes and its rebuilt bytes. |
| `near_analysis.py` | near_analysis.py — classify WHY a NEAR_MATCHING function does not match. |
| `near_diag.py` | near_diag.py — the ``rebrew diagnose near`` command. |
| `pinned_diff.py` | pinned_diff.py — SequenceMatcher with known line pins. |
| `reloc_diff.py` | reloc_diff.py: compare PE base relocation sites between the reference and a build. |
| `similar.py` | Binary similarity search — rank functions by structural similarity. |
| `stack_analysis.py` | stack_analysis.py — compare the stack frame of a compiled function against the target. |
| `stack_cmp.py` | stack_cmp.py — the ``rebrew diagnose stack`` command. |

Externals (the only packages this one may import): `binary.analysis`, `binary.asm`, `binary.cfg_ged`, `binary.similarity`, `catalog`, `cli`, `compiler.compile`, `compiler.overrides`, `compiler.temp_dirs`, `config`, `data.ownership`, `data.scan`, `errors`, `formats.binary_loader`, `formats.binary_model`, `formats.relocations`, `formats.xtensa`, `function_providers`, `matcher`, `matcher.parsers`, `matcher.scoring`, `matching.semantics`, `matching.sweep`, `metadata.bindings`, `metadata.data`, `metadata.functions`, `metadata.native_identity`, `source.discovery`, `source.rename_ops`, `utils`, `workspace.status`. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- Library modules remain free of CLI `app`/`main_entry` imports (`tools/check_layering.py`).
- `apply_coff_relocations`, `smart_reloc_compare` and `relocation_binding_evidence` link MIPS ELF `R_MIPS_26`/`HI16`/`LO16` through one helper, `_mips_linked_word`, in the record's byte order, and compare every bit outside the relocated field. A record against the function's own section (`local_offset`, a `jal` to a static function) binds to `section_va + local_offset`, never to a catalog name.
