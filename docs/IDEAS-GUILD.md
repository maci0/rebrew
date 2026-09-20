# Rebrew ideas — features the guild-rebrew effort needed but lacked

Sourced from the 100% byte-identical `server.dll` campaign (MSVC6, x86-32).
Each entry: observed pain, proposed feature, evidence pointer in guild-rebrew.
Status `open` unless noted. Promote to ROADMAP when scoped.

## Measure truth, not proxies

- [ ] **Link-residue as first-class metric (`rebrew residue --json`).**
  Pain: object metrics (`matched`, `aligned`) pointed the wrong way ≥6 times;
  only `scripts/linktest.sh` + `split_link.sh` + `postlink_residual.py` told
  the truth, all out-of-tree. Feature: built-in command that relinks, applies
  postlink, prints per-function linked delta. Evidence: measure-traps §1–2.
- [ ] **Relocation-ceiling report (`rebrew test --show-ceiling`).**
  Pain: `matched` shortfall that is pure accounting (one-sided HIGHLOW,
  per-call REL32) looks like codegen work. Feature: compute ceiling from
  reference HIGHLOW count per window, show `matched / matched-reloc /
  ceiling` side by side; flag windows at ceiling as done. Evidence:
  measure-traps §3 (`cm_ExProdObjekt` 980/980, PCQ 624/624 at ceiling).
- [ ] **Gap-curve view built in (`gaptrace` in-tree).**
  Pain: residue number ≠ error size; only curve shape discriminates cascade
  vs frame-value vs distributed. Feature: promote `scripts/gaptrace.py` to
  `rebrew gaptrace <VA>` with no size argument (derives window itself).
  Evidence: measure-traps §4.
- [ ] **Two-ruler readout (`--ruler probe|test`).**
  Pain: probe reports padded COMDAT span, test reports real body; same object,
  different numbers, endless confusion. Feature: every size/match number
  labelled with its ruler; warn when comparing across rulers. Evidence:
  measure-traps §8.
- [ ] **COMDAT composition band check (`rebrew test --composition`).**
  Pain: wrong "real body must equal reference" rule discarded good candidates
  for rounds; true constraint is padded-COMDAT neutrality (or real-length
  binding when tables follow code). Feature: report real body, padded span,
  table-follows flag, and pass/fail per branch. Evidence: measure-traps §7.

## Allocate and steer

- [ ] **Slot-map probe generator (`rebrew slotmap <VA>`).**
  Pain: slot transpositions are colourer ties; only the sentinel-initial
  probe reads the map, hand-built each time. Feature: auto-generate the
  probe TU, compile, report reference-vs-object slot assignment per local.
  Evidence: codegen-walls §1, allocator Finding 60.
- [ ] **Volatile fixed-point sweep (`rebrew match --volatile-sweep`).**
  Pain: volatile is per-variable fixed point, per-site wall; manual sweeps
  (1/8/17 sites) cost rounds. Feature: systematic per-variable qualify/
  dequalify sweep with link-residue ranking, respecting composition band.
  Evidence: codegen-walls §3.
- [ ] **Epilogue-merge detector.**
  Pain: reference keeps N epilogues, `/O2` folds to one; 8 spellings tried,
  all inert — recognised late as compiler wall. Feature: detect "N ref rets
  vs 1 obj ret with byte-identical bodies" in diff output, label as wall,
  stop the loop early. Evidence: codegen-walls §2, shapes §74.
- [ ] **Strength-reduction use-site hint.**
  Pain: `add R,R` vs `lea R,[R+R]` follows value uses, not spelling; probed
  blind. Feature: when diff shows add/lea mismatch, point at the value's
  use sites, not the emission site. Evidence: codegen-walls §4.

## Data round support

- [ ] **`rebrew data` composition awareness.**
  Pain: data edits move `.text` cost unpredictably (AcceptConnections:
  local 0 diffs, gate `.text` +180 via COMDAT literal emission). Feature:
  data verify that also reports `.text` delta of the change, warning when a
  data-only edit churns code. Evidence: goal.md data-round notes (518/520).
- [ ] **Shared-type lift assistant.**
  Pain: manual promotion from `types.h` (Ghidra-pulled) to `rebrew_types.h` /
  `game_structs.h`, duplicate-definition LNK4006 as signal. Feature: flag
  identical layouts across TUs, propose lift target header, detect dupes
  pre-link. Evidence: goal.md types section.
- [ ] **String-to-owner attribution with push verification.**
  Pain: RevEng attribution wrong twice; manual `asm | grep push` confirmation
  each time. Feature: `rebrew strings --verify-push` — attribute `"<name>():
  ..."` strings, confirm each by disassembling the owner for the literal
  push, report unverified ones. Evidence: naming_conventions.md attested
  table method.

## Workflow safety

- [ ] **Serialized link-test queue.**
  Pain: agents cannot link-test (measurement serialised); object-metric
  ranking mispredicts; coordinator bottleneck. Feature: `rebrew linktest
  --queue` accepting candidate files, running one at a time, reporting
  deltas. Evidence: workflow-traps §1.
- [ ] **Agent file-ownership guard.**
  Pain: fan-out without ownership check broke two rounds. Feature: `rebrew
  agents --claim <files>` / pre-launch collision check, or at minimum a
  documented protocol in `rebrew-workflow` skill. Evidence: workflow-traps
  §1.
- [ ] **`src/` glob guard for probes.**
  Pain: probe dropped in `src/` compiled via GLOB_RECURSE, moved every
  symbol. Partially fixed (leading-`_` exclusion). Feature: refuse to test
  files matching probe patterns inside `src/`, or keep all probes in
  `.scratch/` by construction. Evidence: workflow-traps §1.
- [ ] **Named-paths commit helper.**
  Pain: `git add -A` swept unmeasured edits once. Feature: `rebrew commit
  --measured` staging only link-tested files. Evidence: workflow-traps §1.

- [ ] **`test`/`verify` must honour the CMake per-file toolchain pin.**
  Pain: `CMakeLists.txt` pins three files to `/REBREW_TOOLCHAIN:msvc-6.0-sp5-pp`
  and the real link applies it (confirmed in `build.make`), but `rebrew test`
  and `rebrew verify` compile those files with the project default (sp6) and
  never read the pin. So every per-function number for a pinned file in
  `rebrew-functions.toml` and in `verify` output describes a compile that does
  not ship: `gm_FindNextFilteredEntity` reads `obj 342`, SIZE_MISMATCH,
  delta 186 under verify, against `obj 346` (the reference's exact size),
  `match` 171/346 when compiled the way the link does. The whole-tree residue
  is unaffected (measured on the shipped bytes), but per-function claims are
  not. Feature: parse the `set_source_files_properties(... COMPILE_OPTIONS
  "/REBREW_TOOLCHAIN:...")` entries, or record the producing toolchain on the
  metadata entry so a stale number is detectable. Evidence: guild-rebrew
  `docs/TODO.md` round 842.

- [ ] **`test`/`verify` must read the CMake per-file flags, not just the metadata.**
  Pain: `CMakeLists.txt` sets per-file options for pinned files
  (`set_source_files_properties(... COMPILE_OPTIONS ...)`) and the real link honours
  them, but `rebrew test`/`verify` compile with the metadata's `cflags` only. For
  `ls_LoadBuildingEntityState` (`0x100128f0`) `build.make` shows
  `/O2 /Gd /Oa /Ow /REBREW_TOOLCHAIN:msvc-6.0-sp5-pp` while the metadata carries **no
  `cflags` field at all**, so every `test`/`verify` figure for that file describes a
  compile the build never performs. Round 842 found the same for the toolchain pin;
  round 877 confirmed it extends to the flags.
  **Worse, "fixing" it by persisting the flags breaks the build.** Running
  `rebrew test <file> --cflags "/O2 /Gd /Oa /Ow"` writes the field into
  `rebrew-functions.toml` (the tool owns that file and does this itself), after which
  `scripts/gate.sh` goes FAIL with **`fatal error C1001: INTERNAL COMPILER ERROR`**
  plus a C1083. The identical flag pair appended to the identical defaults compiles
  fine through the CMake path, so the two paths do not construct the same command
  line and only one works. That is a trap for anyone following the documented rule
  that the metadata is the source of truth for flags.
  Feature: have `test`/`verify` read the CMake per-file options (or refuse and say
  so), and make `--cflags` on a CMake-pinned file a loud error rather than a silent
  metadata write. Evidence: guild-rebrew `docs/measure-traps.md` §6e,
  `docs/TODO.md` rounds 842 / 877.

## Build hygiene

- [ ] **`postlink_residual.py` should refuse a build whose split state is stale
  instead of printing a number.** Pain: `cmake --build` deletes the deliverable
  and leaves `build/split_poc/` from the previous run, so residue reads 58,614
  or 116,814 when the truth is 8,634 -- a 13x error that looks like a
  catastrophic regression and survives a `git checkout` of the sources.
  `split_link.sh` already computes the tell, `exactly at their reference VA: N`,
  and `linktest.sh` already refuses to measure when it is 0, but
  `postlink_residual.py` has no such guard. Feature: have it compare the build
  artifact's mtime against the newest source, and if the artifact is missing or
  older, exit non-zero with "residue not measured" rather than printing a
  number. Evidence: guild-rebrew round 889, `docs/measure-traps.md` section 9.
- [ ] **`gate.sh` should print the split-alignment count next to the residue.**
  Pain: the residue line and the composition-collapse signal are produced by
  different tools, so a collapsed run reads as a normal regression line.
  Evidence: guild-rebrew round 889 -- the false readings above were only
  diagnosed after `linktest.sh` printed the collapse warning.

## Data

- [ ] **`lint --fix` W016 writes `section` but not `name`, so `verify --data`
  then reports the marker as unattributed.**
  Pain: a `DATA:` marker gains `section = ".data"` in `src/rebrew-data.toml`
  and stays `unknown` forever after. `scan_globals` needs `name` (or `type`)
  to attribute a marker -- the next source line is a *definition*, which
  tree-sitter returns only when it parses as a declaration-with-initialiser,
  so `char s_x[] = "..."` under the marker is not always picked up. The
  resulting warning reads like a source defect ("has no declaration on the
  following line") and sends the reader to the wrong file. Feature: W016's
  `--fix` should write `name`/`type`/`size` from the binary's data-symbol map
  the way `import-splat`'s `_write_data` does (`splat_config.py`), or the
  warning should name the missing *metadata* field explicitly.
  Evidence: guild-rebrew `src/rebrew-data.toml` `0x1002944c` / `0x100294a4`
  (section only, from TODO round 559), `docs/measure-traps.md` §9, round 882.

- [x] **`todo`'s `start-data` lane should exclude link-produced data.**
  Pain: a fresh project opens with the lane dominated by `__imp__*` IAT
  slots, which are linker output and can never be attributed to a source
  symbol no matter how much naming is done, so the lane can never empty and
  its size stops meaning "data work remaining". Feature: tag metadata
  entries whose VA falls in a linker-owned section (`.idata`) as
  `status = "SYNTHETIC"` (written by `verify --data`), and have
  `_collect_start_data` skip them. Evidence: guild-rebrew `rebrew todo` --
  224 of 226 remaining items are `start-data`, 18 of them `__imp__*`;
  IAT bytes confirmed identical to the reference at
  `0x10024000..0x10024044`; `docs/measure-traps.md` section 9, round 883.
  Applied (round 1078): `_collect_start_data` skips `__imp_` names,
  `section = ".idata"`, `section = ".bss"`, and any symbol whose extent runs
  past its section's `raw_size`. The lane went from 123 items to 0 on
  guild-rebrew, leaving only its 2 real `.text` carriers. Measured there:
  207 UNCHECKED entries, all 207 un-clearable, and all 207 independently
  confirmed already byte-correct (5 with file bytes identical, 111 in the
  zero-fill tail, 84 import slots, 7 sizeless).

- [x] **`verify --data` reports a pass over a subset and does not say so.**
  Pain: `rebrew verify --data` printed "data: 122 matched, 0 mismatched,
  0 missing" while the metadata held 329 symbols -- it had compared 122, or
  37%, and reported no coverage figure, so the summary read as "all data
  verified". Everything it cannot compare is invisible by design:
  `section_symbol_bytes` skips any symbol running past its section's
  `raw_size` (the zero-fill tail, no file bytes) and any symbol outside
  `.data`/`.rdata`. Those VAs never enter `ref_sizes`, so they can never be
  written back as VERIFIED, and they are exactly the entries that pile up in
  the `start-data` lane. Feature: report the denominator -- "122 of 329
  symbols compared (207 not comparable: N in the zero-fill tail, M outside
  .data/.rdata)" -- and either mark non-comparable entries with a distinct
  terminal status (`SYNTHETIC` / `NO_FILE_BYTES`) or list them as such, so
  the lane and the summary agree. Evidence: guild-rebrew round 1078 --
  `verify --data --json`'s `data` block carries `matched`/`mismatched`/
  `missing` but no total and no per-symbol list; `ref_sizes` was measured at
  exactly 122 across both images.
  Applied (round 1079, commit `3f7cefea`): the report now carries `total`,
  `compared`, `not_comparable` and `coverage`; the human summary prints
  "(122 of 329 symbols compared, 37%)" plus a line naming why the rest are
  not comparable, and `--json` passes all four fields through.

- [ ] **`function_extent_from_disasm` stops at the first `jmp`, so it cannot
  bound a function that branches internally.**
  Pain: the walk is conservative by design -- it stops at `ret`/`jmp`/`int3` --
  and that is correct for a thunk, but a large `switch`-heavy function ends on
  an inner `jmp` long before its real epilogue. On guild-rebrew,
  `CrashDumpUnhandledExceptionFilter` (`0x10002770`) is 2115 bytes and returns
  with `ret 4` at `0x10002e99`, but the walk stops at `0x10002a56` -- 742 bytes
  in, 35% of the function -- so callers that prefer the walk over the declared
  size (added in round 1084 to stop the dump swallowing `0x09` padding) cannot
  use it here and still over-report 724 instructions against the real 673.
  Feature: when the walk ends on `jmp`, follow the branch target and continue,
  or fall back to "keep walking until a `ret` in the same basic-block region",
  and return the extent with a distinct kind (`jmp-tail` vs `jmp-inner`) so
  callers can decide. A cheaper option: report both bounds and let the caller
  choose the smaller *credible* one.
  Evidence: guild-rebrew `docs/measure-traps.md` section 52, round 1084.
  **Attempted and reverted (round 1085).** A worklist walk that follows a
  forward `jmp` target and keeps going fixes this carrier (742 -> 1836) but
  breaks the contract the other five callers depend on, in three ways measured
  with the suite: a thunk that legitimately IS a tail jump is now followed out
  of the function (10 -> 3988), an unterminated buffer returns 4 instead of
  `None` because "walked some bytes" was conflated with "found an end", and the
  MIPS/16-bit walkers inherit both. It also overshoots this very function: the
  real epilogue is `ret 4` at `0x10002e99` (extent 1835) and the walk reported
  1836, having decoded a jump table as code. The distinguishing signal a fix
  needs is "is this `jmp` a tail call or an intra-function branch", which is
  exactly what the current conservative walk refuses to guess at -- and the six
  callers were written against that refusal. Fixing it means auditing all six
  and deciding the answer per caller, not changing the shared walker.

## Knowledge capture

- [ ] **Jev as a typed decision layer over `todo` / `near-diag` (out of tree).**
  Pain: agents pick the wrong next tool, reread 167 MSVC6 shapes, and spend
  codegen-LLM budget on library leftovers, stale blockers, and inverted
  briefs. Feature: a guild-rebrew script that sends `todo --json` +
  `near-diag --json` + blocker prose to TypeSafe Jev (Choice / Score /
  Noul) and confidence-gates the next command — no C generation, no
  rebrew package change. Keep only if it beats `todo` on a labeled
  NEAR_MATCHING slice. Evidence: [JEV.md](JEV.md); workflow-traps §1
  (inverted `volatile` brief); shapes / allocator catalogs.
- [ ] **Finding router (`rebrew note --finding`).**
  Pain: one finding, one home (shapes / allocator / codegen-walls /
  measure-traps / workflow-traps / TODO) enforced by discipline only.
  Feature: prompt for category on note capture, append with call-site and
  delta template, lint for missing evidence fields. Evidence: goal.md
  codegen section.

- **Build-tree integrity check belongs in rebrew, not in every consumer.**
  Pain: `build/` is gitignored, so a hand-edited `build.make` (or `flags.make`)
  is invisible to `git status`, to `rebrew lint`, to `rebrew verify --full`, and
  to `cmake --build`, while silently redefining what any consumer's measurement
  means. `rebrew postlink` and `rebrew cmake-flags` both read that tree. A round
  sweeping per-file toolchain pins hit this and left a tree reporting 58% residue
  with a 290,816-byte deliverable against the correct 286,720 / 8628.
  Feature: `rebrew build-check` (and a `rebrew doctor` clause) comparing
  `build.make`'s compile lines against CMake's own `flags.make` records —
  already prototyped in-tree as `scripts/build_tree_check.py`, ~60 lines.
  Evidence: guild-rebrew `docs/workflow-traps.md` §20.

- **Post-link failure messages should report the measurement, not one hypothesis.**
  Pain: `postlink._fix_imports` refused a build with "built .rdata prefix size
  does not match the reference — check the debug directory: builds with /debug
  carry an extra 0x1c-byte directory". The real discrepancy was +64 bytes with
  `DataDirectory[6] == 0` in both images. The message cost a wrong lead on a
  check every composition round hits.
  Feature: state *measured* vs *expected*, and give the test that separates the
  candidate causes (`== 0x1c` means /debug; anything else means the section
  length itself). Applied — see the diff to `src/rebrew/postlink.py`.
  Evidence: guild-rebrew `docs/workflow-traps.md` §21.

- **`rebrew verify`'s denominator should not be the annotation count alone.**
  Pain: `function_structure.json` (the discoverer's partition) is coarser than the
  annotations — 543 entries against 283 annotated functions — and its entry sizes
  are gaps to the *next inventory entry*. Reading a size divergence as "missing
  functions" produced a four-round false lead in guild-rebrew, including a
  proposed tool fix for a defect that does not exist.
  Feature: have `verify` report the annotation count beside the inventory count,
  and label a size divergence as an inventory-coarseness fact rather than a
  coverage gap.
  Evidence: guild-rebrew `docs/workflow-traps.md` §17.

- **`verify --data` should refuse to write statuses when `--built` is not the postlinked deliverable.**
  Pain: running `rebrew verify --data --built build/split_poc.dll` (the raw link) to escape the
  "tautological" warning flipped 30 symbols' `status` from `VERIFIED` to `DRIFT` in the tool-owned
  `rebrew-data.toml`. The raw link's `.data` divergence is postlink-supplied (AMBIGUOUS-by-design), so the
  statuses it wrote were wrong and persistent; recovery needed `git checkout` plus a deliverable re-run.
  Feature: detect a raw-link artifact (e.g. `.data` differing above a threshold it can already measure, or
  an explicit `--raw-link` ack write-gate) and suppress both the status write-back and the DRIFT flips —
  report `mismatched` only.
  Evidence: guild-rebrew `docs/measure-traps.md` §56, round 1102.
