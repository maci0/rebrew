# AGENTS.md: data/

Global and static data analysis, layout convergence, BSS calibration, ownership attribution, and data metadata verification.

## Modules

| Module | Role |
|--------|------|
| `cli.py` | `rebrew data` CLI group (list, scan, set, annotate, verify, layout, placement) |
| `scan.py` | Global/data section scanner and role/name cover caches |
| `layout.py` | TU `.data`/`.bss` layout auditing and padding convergence |
| `annotate.py` | Emit canonical `extern` declarations and data annotations |
| `ownership.py` | Archive-member and link-map global storage ownership attribution |
| `pair.py` | Pair and reconcile data definitions across targets |
| `placement.py` | Verify data symbol placement and section bounds |
| `render.py` | Render data tables and summaries |
| `verify.py` | Verify initialized data bytes against the target binary |
| `tu_check.py` | Translation-unit data consistency checks |
| `calibrate_bss.py` | Calibrate `.bss` layout padding offsets |

Externals (the only packages this one may import): `buildsys.layout_meta`, `c_parser`, `cast_rewrite`, `catalog`, `cli`, `config`, `errors`, `formats.archives`, `formats.binary_loader`, `formats.coff`, `formats.ne_loader`, `formats.pe_headers`, `metadata.anchors`, `metadata.binding_history`, `metadata.bindings`, `metadata.coordinated`, `metadata.data`, `metadata.functions`, `metadata.storage`, `object_evidence`, `present`, `sections`, `source.discovery`, `source.rename_ops`, `status_style`, `utils`, `workspace`. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- Follow the root `AGENTS.md` Global ownership rules: one storage owner per global, separate game and runtime declarations, interior addresses recorded as views with `--backing`.
