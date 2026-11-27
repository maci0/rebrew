# AGENTS.md: binary/

Binary analysis, disassembly, CFG construction, discovery, and PE/PDB/NE inspection.

## Modules

| Module | Role |
|--------|------|
| `analysis.py` | Shared binary-analysis primitives for recon and visualization tools. |
| `analyze.py` | analyze.py — one-shot intelligence dossier for a target binary. |
| `asm.py` | asm.py – Disassemble and export function bytes from the target binary. |
| `cfg.py` | rebrew cfg: Programmatic editor for rebrew-project.toml. |
| `cfg_ged.py` | cfg_ged.py — control-flow-graph structural similarity (DecBench GED-inspired). |
| `crypto_scan.py` | crypto_scan.py: Name-and-constant crypto detector for a target binary. |
| `describe.py` | describe.py - Per-function recon dossier (callers, callees, strings, globals, imports). |
| `discover.py` | rebrew binary functions — function enumeration for a target binary. |
| `extract.py` | extract.py - Extract and disassemble functions from the target binary. |
| `fingerprints.py` | fingerprints.py: Content fingerprint bundle for a target binary. |
| `forms.py` | Inspect and verify Delphi 1 form streams in NE images or standalone form data. |
| `gate.py` | binary_gate.py - Whole-binary parity primitives for the CI gate. |
| `imports.py` | imports.py — ``rebrew binary imports list``: list import-table symbols and mark import stubs. |
| `inventory_repair.py` | Review and repair selected native function inventory extents. |
| `jump_table.py` | jump_table.py — recognise a jump-table switch dispatch in decoded x86. |
| `lzexe.py` | lzexe_cli.py — Unpack LZEXE 0.90/0.91 compressed DOS executables. |
| `ne_compare.py` | Compare physical NE bytes independently of relocation and content inventories. |
| `pdb_export.py` | rebrew export pdb: write a synthetic PDB for the original target binary. |
| `pdb_info.py` | rebrew binary pdb show — extract compiler version, flags, and function names from a PDB. |
| `pe_info.py` | pe_info.py — read-only PE metadata dump via LIEF. |
| `resource.py` | ``rebrew binary resource`` — PE resource (``.rsrc``) comparison for byte-identical work. |
| `score.py` | bin-score — same-offset byte agreement between the reference and a build. |
| `sections.py` | sections.py - Binary section and globals helpers. |
| `similarity.py` | binary_similarity.py — whole-binary structural similarity between two binaries. |
| `strings.py` | strings.py — Extract printable strings from a binary, with cross-references. |
| `switch.py` | switch.py — jump-table switch dispatch decoding. |
| `xrefs.py` | xrefs.py — Cross-reference explorer: who references a given address. |

Externals (the only packages this one may import): `buildsys.layout_meta`, `c_syntax.float_const`, `c_syntax.parser`, `c_syntax.vtordisp`, `catalog`, `catalog.inventory`, `cli`, `compare.similar`, `compiler.cache`, `compiler.toolchain`, `compiler.xtensa`, `config`, `data.layout`, `data.ownership`, `data.scan`, `errors`, `formats.binary_loader`, `formats.binary_model`, `formats.dfm`, `formats.import_table`, `formats.lzexe`, `formats.ne_analysis`, `formats.ne_loader`, `formats.pdb`, `formats.pe_headers`, `formats.pe_symbols`, `init_profiles`, `library.flirt`, `library.identify`, `metadata.anchors`, `metadata.binding_history`, `metadata.bindings`, `metadata.data`, `metadata.functions`, `metadata.storage`, `naming`, `registry`, `source.discovery`, `source.rename_ops`, `status_style`, `symbol_addrs`, `toolchain_detect`, `utils`. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- Library modules remain free of CLI `app`/`main_entry` imports (`tools/check_layering.py`).
