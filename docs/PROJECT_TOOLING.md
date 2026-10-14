# Project tooling consolidation

This audit covers Guild, Holidaydecomp, and the 44 projects in
`rebrew-test-projects`. The canonical local checkouts are the sibling
`rebrew`, `recoverage`, and `recompile-toolchains` repositories under
`relumea/repos`. Project-specific reconstruction facts and independent
acceptance checks stay with their projects. Reusable operations belong here.

## Audit and migration ledger

| Operation | Evidence | Disposition |
| --- | --- | --- |
| Select a target's linked image | Guild status compared both clients with `build/server.dll` | Fixed; no cross-target fallback |
| Check known data operand bindings | Guild's normalized shared-import checks accepted a contradictory known global | Implemented target `check_known_bindings`; diagnostics keep unresolved/IAT scopes explicit |
| Rename one shared definition | Guild's client wrapper rename also selected an independent server twin with `--all-modules` | Implemented `source rename --shared-definition` with independent-twin regressions |
| Recover source-unit evidence | Guild's native source-path strings identify units more precisely than inferred CU clusters | Implemented `source units`; bounded owners, conflicts and unattributed references stay separate |
| Find prior address-keyed findings | Guild `scripts/whathas.py` | Implemented `source findings`; Guild callers migrated and script retired |
| Build a Pascal program and its map | Holiday `tools/dcc16.py`, `with_rebrew.sh`, compiler compatibility probes and shims | Implemented `build delphi`; Holiday compiler callers migrated and shims/driver retired; full EXE parity proven |
| Compare NE segments and content overlap | Holiday `tools/ne_compare.py` | Implemented `binary ne-compare` and validated `formats.ne_analysis`; Holiday callers migrated; approximate gap experiment retained |
| Decode and encode Delphi form streams | Holiday `tools/dfm_extract.py` | Implemented `formats.dfm` and `binary forms`; all 23 Holiday streams/text reproduce exactly; local output policy retained |
| Discover and analyze Delphi procedures | Holiday `tools/decompile.py` | Lifted physical segments/fixup inventories; project decompiler consumes them; curated body/discovery semantics remain local |
| Inspect DCU string candidates | Holiday `tools/dcu_symbols.py` | Exploratory string heuristic, not a proven DCU symbol parser; retain and label scope |
| Generate recovered Pascal units, data, strings and tables | Holiday `gen_*`, `lift.py`, `place_global.py` | Retain target-specific source reconstruction and curated evidence |
| Run reachability, arity and switch experiments | Holiday `reach_*`, `arity_probe.py`, `switch_sweep.py`, `byte_match.py` | Migrate compiler/parser dependencies; retain experiment policy and measured receipts |
| Audit generated documents and reconstruction | Holiday `audit_*`, `converge.py`, `verify.sh`, `progress.sh` | Retain project-specific acceptance and generation orchestration |
| Generate linker game anchors | Guild `scripts/gen_game_includes.py` | Implemented `build anchors`; exact 251-function/34-data response-file parity; old generator retired |
| Force native import ordering | Guild `scripts/gen_import_includes.py` | Retained local load-order recipe, migrated to LIEF/config, fixed ordinal handling; response-file bytes unchanged |
| Emit exact BSS layout | Guild `scripts/gen_bss_layout.py` | Audit against existing data/header/layout tools; preserve game/CRT allocation ownership |
| Read native link/archive timestamps | Guild `scripts/native_timestamps.py` | CMake consumes `binary pe` JSON; independent configure passes; old parser retired |
| Gate and summarize project objectives | Guild `gate.sh`, `verify_objective.py`, `update_state_table.py`, `wine_load_check.sh` | Retain independent acceptance and project-specific orchestration |
| Bind installed packages and checkout paths | Editable installs and legacy tool links in all projects | Verified canonical editable origins; installed canonical Recoverage+Rebrew; repaired Docker settings and removed 23 obsolete links across 44 projects |
| Keep workflow guidance current | AGENTS template, packaged skills, generated project copies | Updated packaged source/template and regenerated all 46 projects; every scaffold check passes with local rules preserved |

## Existing Guild proposals

`IDEAS-GUILD.md` records historical evidence as well as outstanding proposals.
Verify current code and tests before treating an unchecked box as missing.
CMake pins, target defines, strict relocation comparison, library callee
resolution, source split, source-only assembly provenance, type bindings, and
staged include search already have upstream implementations. Their remaining
local scripts should be retired only after callers and supported replacements
are checked. Historical scratch receipts remain evidence.

Do not generalize hardcoded addresses, copied reference bytes, inferred
ownership, or compiler-specific accidents into default policy. A feature must
preserve the distinction between a byte comparison, relocation-masked source
agreement, native operand proof, and a linked provider.

## Validation and scope

An independent Guild CMake configure/build produces all 286,720 reference bytes
exactly. The final Holiday Docker build/map preserves its existing 482,560-byte
program exactly, and all 23 form streams/text reproduce exactly. Native import
anchors are unchanged after the LIEF/ordinal repair. Six installed/project
interpreters import the canonical Rebrew checkout; both Recoverage interpreters
import the canonical sibling. All 46 generated scaffolds pass drift checks.

Holiday's parent project passes 416 Python tests; its broader `make check` fails
at the unrelated GELD.HIS web smoke assertion (251×251 versus expected 128×192).
No game-data repair is included in this tooling consolidation. Historical
content-overlap receipts retain the former counter's scope; current reports
count complete matching-window spans, including the tail, once per byte.

The project-only BSS generator truncates overlapping metadata rows into a
server-specific storage recipe. Existing ownership/span APIs are the supported
general model; this algorithm is not lifted and its emitted storage is not
changed here. Stock CRT objects remain the storage owners where established.

Rebrew validation passes 11,891 tests (42 optional/integration skips) at 88%
coverage, plus lint, types, cycles/layering, CLI contracts and fixture drift.
Wheel/sdist equivalence, isolated wheel smoke, distribution provenance and the
116-component SBOM pass. Release validation rebuilds both distributions from a clean HEAD at a different
path, timezone and file mode before the verified CI artifacts are published.
