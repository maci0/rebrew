# AGENTS.md: matching/

Matching CLI orchestration, flag sweeps, GA search, LLM seeding, round-trip checks, and proving.

## Modules

| Module | Role |
|--------|------|
| `batch.py` | match_batch.py — batch stub/near-miss discovery and source updates. |
| `cli.py` | Genetic Algorithm engine for binary matching — single-function and batch modes. |
| `climb.py` | climb -- deterministic single-statement hill-climb over one function body. |
| `ga.py` | match_ga.py — the genetic-algorithm matching engine. |
| `llm_seed.py` | llm_seed.py — optional LLM-assisted GA seed generation. |
| `probe.py` | probe.py — measure ONE function after editing its source. |
| `prove.py` | prove.py — Symbolic equivalence prover for rebrew. |
| `prove_simprocs.py` | prove_simprocs.py — Win32 SimProcedure models for the equivalence prover. |
| `qual_sweep.py` | qual_sweep.py — sweep declaration qualifiers/types for one function. |
| `round_trip.py` | ``rebrew build round-trip`` — splice matched function bytes back into the target PE. |
| `run.py` | match_run.py — the batch GA and flag-sweep run drivers. |
| `semantics.py` | match_semantics.py — shared effective-match classification. |
| `solutions_db.py` | solutions_db.py — query the GA solutions database and run history. |
| `sweep.py` | match_sweep.py — build-parameter resolution and compiler/flag sweeps. |

Externals (the only packages this one may import): `binary.analysis`, `binary.sections`, `c_syntax.parser`, `call_progress`, `catalog`, `cli`, `compare.alignment`, `compare.coff_reloc`, `compare.near_analysis`, `compiler`, `compiler.cache`, `compiler.compile`, `compiler.overrides`, `compiler.temp_dirs`, `compiler.toolchain`, `config`, `decompiler`, `errors`, `flag_data`, `formats.binary_loader`, `formats.binary_model`, `formats.import_table`, `formats.pe_headers`, `limits`, `matcher`, `matcher.core`, `matcher.mutator`, `matcher.parsers`, `matcher.scoring`, `metadata.bindings`, `metadata.data`, `metadata.functions`, `metadata.storage`, `present`, `source.c_rename`, `source.discovery`, `source.rename_ops`, `status_style`, `utils`, `verify.cache`, `verify.hash`, `workspace.config`, `workspace.status`. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- Library modules remain free of CLI `app`/`main_entry` imports (`tools/check_layering.py`).
