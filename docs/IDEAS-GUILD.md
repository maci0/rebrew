# Rebrew ideas: features the guild-rebrew effort needed but lacked

Sourced from the 100% byte-identical `server.dll` campaign (MSVC6, x86-32).
Each entry: observed pain, proposed feature, evidence pointer in guild-rebrew.
This is a proposal/evidence ledger, not a command manual: example commands and
flags may be unshipped. Status `open` unless noted; observations describe the
campaign at the time recorded. Use [CLI.md](CLI.md) for shipped behavior and
promote scoped proposals to [ROADMAP.md](ROADMAP.md).

## October 2026 consolidation audit

The historical proposals below retain their campaign evidence. Current reusable
operations and project migrations are tracked in [PROJECT_TOOLING.md](PROJECT_TOOLING.md).

Implemented here: target-correct linked-image selection; configured
`check_known_bindings` with resolved/conflicting/unresolved operand diagnostics;
`source rename --shared-definition`; `source units` with authenticated body
extents and explicit unattributed references; `source findings`; `build anchors`;
and separate COFF/export timestamps in `binary pe`. These replace Guild's
notebook lookup, game-anchor generator and timestamp parser.

Existing supported replacements include `build residue` (measure an existing
link and postlink it in memory), `diagnose gap`, `diagnose near`, `diagnose probe`
(separate COMDAT/body rulers), qualifier/climb experiments, data verification,
managed type bindings, scoped AST renames, source split/merge, library adoption
and native-callee resolution. Their scopes are described in CLI.md; they do not
implicitly relink candidate projects or prove complete operands/providers.

Retain the following as evidence-dependent research, rather than default policy:
slot-coloring sentinel generation; linked volatile sweeps and composition-band
ranking; broad optimization-flag inference; allocator/use-site advice; whole-member
text/data graph identity for tiny math dispatch wrappers; and linker reservation
models derived from one MSVC campaign. Their current receipts establish a local
case, not a cross-project algorithm. The math-member proposal still explicitly
lacks complete data/provider verification. Existing public object/archive APIs
remain appropriate for those proof experiments.

Do not add an automatic commit helper, agent scheduler, live-sync loop, or
external finding router for this consolidation. Explicit file ownership, named
paths, existing metadata writers and project checks cover the demonstrated
workflow failures without an additional authority or storage system.

## Measure truth, not proxies

- [ ] **Link-residue as first-class metric (`rebrew build residue --json`).**
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
- [ ] **Volatile fixed-point sweep (`rebrew match run --volatile-sweep`).**
  Pain: volatile is per-variable fixed point, per-site wall; manual sweeps
  (1/8/17 sites) cost rounds. Feature: systematic per-variable qualify/
  dequalify sweep with link-residue ranking, respecting composition band.
  Evidence: codegen-walls §3.
- [ ] **Epilogue-merge detector.**
  Pain: reference keeps N epilogues, `/O2` folds to one; 8 spellings tried,
  all inert; recognised late as compiler wall. Feature: detect "N ref rets
  vs 1 obj ret with byte-identical bodies" in diff output, label as wall,
  stop the loop early. Evidence: codegen-walls §2, shapes §74.
- [ ] **Strength-reduction use-site hint.**
  Pain: `add R,R` vs `lea R,[R+R]` follows value uses, not spelling; probed
  blind. Feature: when diff shows add/lea mismatch, point at the value's
  use sites, not the emission site. Evidence: codegen-walls §4.

## Data round support

- [ ] **`rebrew data list` composition awareness.**
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
  each time. Feature: `rebrew binary strings --verify-push`; attribute `"<name>():
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
  Noul) and confidence-gates the next command; no C generation, no
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
  means. `rebrew build postlink` and `rebrew build cmake-flags` both read that tree. A round
  sweeping per-file toolchain pins hit this and left a tree reporting 58% residue
  with a 290,816-byte deliverable against the correct 286,720 / 8628.
  Feature: `rebrew build check` (and a `rebrew doctor` clause) comparing
  `build.make`'s compile lines against CMake's own `flags.make` records;
  shipped as `src/rebrew/build_check.py`.
  Evidence: guild-rebrew `docs/workflow-traps.md` §20.

- **Post-link failure messages should report the measurement, not one hypothesis.**
  Pain: `postlink._fix_imports` refused a build with "built .rdata prefix size
  does not match the reference; check the debug directory: builds with /debug
  carry an extra 0x1c-byte directory". The real discrepancy was +64 bytes with
  `DataDirectory[6] == 0` in both images. The message cost a wrong lead on a
  check every composition round hits.
  Feature: state *measured* vs *expected*, and give the test that separates the
  candidate causes (`== 0x1c` means /debug; anything else means the section
  length itself). Applied: see the diff to `src/rebrew/postlink.py`.
  Evidence: guild-rebrew `docs/workflow-traps.md` §21.

- **`rebrew verify`'s denominator should not be the annotation count alone.**
  Pain: `function_structure.json` (the discoverer's partition) is coarser than the
  annotations (543 entries against 283 annotated functions) and its entry sizes
  are gaps to the *next inventory entry*. Reading a size divergence as "missing
  functions" produced a four-round false lead in guild-rebrew, including a
  proposed tool fix for a defect that does not exist.
  Feature: have `verify` report the annotation count beside the inventory count,
  and label a size divergence as an inventory-coarseness fact rather than a
  coverage gap.
  Evidence: guild-rebrew `docs/workflow-traps.md` §17.

- **Data verdict write acknowledgment (shipped).**
  Current behavior: `verify --data` reports comparisons but suppresses stored
  verdict/evidence writes unless `--raw-link` or configured `raw_link` acknowledges
  the image. See [CLI.md](CLI.md#rebrew-verify). Original observation:
  Pain: running `rebrew verify --data --built build/split_poc.dll` (the raw link) to escape the
  "tautological" warning flipped 30 symbols' `status` from `VERIFIED` to `DRIFT` in the tool-owned
  `rebrew-data.toml`. The raw link's `.data` divergence is postlink-supplied (AMBIGUOUS-by-design), so the
  statuses it wrote were wrong and persistent; recovery needed `git checkout` plus a deliverable re-run.
  Feature: detect a raw-link artifact (e.g. `.data` differing above a threshold it can already measure, or
  an explicit `--raw-link` ack write-gate) and suppress both the status write-back and the DRIFT flips:
  report `mismatched` only.
  Evidence: guild-rebrew `docs/measure-traps.md` §56, round 1102.

- **`rebrew prove` should stub import thunks instead of failing with "No terminal states reached".**
  Pain: any function that calls an import thunk (GetTickCount, Sleep and friends via
  `call dword ptr [0x10024xxxx]`) cannot reach a terminal state in angr, because the thunk slot has
  no resolvable target in the loaded image. Measured in guild-rebrew on `ServerMainThread`
  (0x100093a0, 2434 B, 55 calls, 9 indirect): full function and every slice return "No terminal
  states reached" at timeouts 60/600/900 and loop-bounds 1/2, while the call-free control
  0x1001bdd0 proves in seconds and a 162-byte single-call function fails the same way despite
  being 15x smaller. The blocker is the harness, not the C.
  Feature: seed each import-thunk address with an unconstrained stub (return-symbolic or
  skip-and-continue) so calls through `[0x10024xxx]` do not dead-end the CFG; expose a
  `--stub-thunks` flag so runs that need real semantics can opt out.
  Evidence: guild-rebrew `src/server.dll/DieGildeAddOnServer/server_c/ServerMainThread.c` header,
  "PROVEN is NOT reachable for this function" block (rounds 6-9 probes).

- **`rebrew orphans prune` deletes metadata for block-comment `/* DATA: SERVER 0x... */` markers.**
  Pain: pruned 260 lines from `rebrew-data.toml` + 3 GOLDTL function entries, orphaning live source
  DATA markers (vfs4.c `0x1002944c..0x100294a0` range form, vfs_OpenStream.c `0x100294a4`) and
  tripping W016 ("DATA marker missing // SECTION") + W022. The orphan detector appears to match only
  the `// DATA:` line form, so a `/* DATA: ... */` block marker does not register as a live
  annotation and its metadata looks orphaned. Measured in guild-rebrew round 1282 (had to
  `git checkout` both TOMLs to recover).
  Feature: parse `/* DATA: ... */` and range `0x..0x` markers as live annotations before pruning;
  report (not delete) any entry whose marker form the detector did not recognize.
  Evidence: guild-rebrew `src/Develop/Units/vfs/vfs4.c` line 17 range marker.

- **`rebrew data list` needs a `--set-size` (data extent correction).**
  Pain: a stale `size` on a data symbol cannot be corrected by any CLI; `--set-type` writes only
  `type` (and preserves existing `size`), `annotation.py` only ever grows size, and `--fix-bss`
  writes sizes only for new gaps. When a range marker overstates an extent (`0x1002944c..0x100294a0`
  = 84 parsed onto a 4-byte `char s_rb[4]`), the extent gate fails and the only fix is calling
  `rebrew.data_metadata.set_data_field(dir, va, "size", n, module)` by hand.
  Feature: `rebrew data set --size 0xVA=N` (mirror `--set-type`) so extent corrections go through
  the sanctioned atomic writer.
  Evidence: guild-rebrew `src/rebrew-data.toml` s_rb_1002944c size 84 vs binary 4 (round 1282).

## Optimization level

- [ ] **Byte heuristics for opt flags other than MSVC `/O1` and `/O2`.**
  Pain: `detect_toolchain` seeds project `cflags` from wrapper-call counts, and that vote only
  separates `/O1` from `/O2` (three sites, two-to-one, else `mixed` or empty). `/Od`, `/Os`,
  `/Ot`, `/Og`, and `/Ox` stay on the flag sweep, and so do GCC/Clang/MinGW `-O`, Watcom
  `-od`/`-os`/`-ot`/`-ox`, Borland `-O`, and IDO `-O`.
  Feature: extend the codegen corpus (`docs/codegen/`, today `/O1` and `/O2` for MSVC) with the
  missing flag rows, then add a detector only for a pattern the matrix actually separates. No
  signature database covers this: Detect It Easy, RetDec, capa, IDA FLIRT, and Ghidra's Rich
  header name the compiler, not the flag. GCC/Clang classifiers (o-glassesX, Pizzolotto) emit a
  coarse `-O` class and are not an MSVC `cflags` source. When the record exists, read the command
  line instead: PDB `LF_BUILDINFO` argument 4, or GCC/Clang `.GCC.command.line` /
  `DW_AT_producer`. `S_COMPILE3` has no `/O` bits, and a VC 6 PDB was not shown to carry
  `LF_BUILDINFO`.
  Hold these until a compile shows them: do not score `/Ox` as `/O2` (`/Ox` is `/Ob2 /Oi /Ot /Oy`
  and drops `/GF` and `/Gy`); `/Os` and `/Ot` alone leave codegen debug-like; a missing GCC frame
  pointer means "not `-O0`" and does not separate `-O1`/`-O2`/`-O3`; a missing Watcom stack check
  means `-s` or `-ox`, not `-os` versus `-ot`; ReC98's Borland rules apply only once the compiler
  is Turbo C++ 4.0J; an IDO loop that did not unroll is not a lower `-O`. The verdict stays per
  function, and two styles clearing the bar stays `mixed`.
  Evidence: the guild-rebrew "Compiler opt level heuristics" report (not in this repo).

## Calling-convention evidence

- [ ] **Infer caller-cleaned stack arguments before generating skeleton signatures.**
  Pain: correcting local ECX definition tracking identifies server `m_pool_free`
  as cdecl, but a cdecl skeleton still defaults to `int f(void)` despite two
  observed arguments. A plain `ret` does not establish zero stack arguments.
  Feature: track ESP bias through saves and local allocation, report supported
  incoming stack slots, and corroborate arity with caller pushes/cleanup. Keep
  unknown counts and types explicit; do not manufacture a `self` parameter.
  Evidence: guild-rebrew `docs/msvc6-c-shapes.md` section 257, callee
  `0x10006e30` and callers `0x10008e2a` / `0x10009220` with `add esp,8`.

## Relocation evidence in shared-client checks

- [ ] **Expose unresolved relocation targets separately from validated RELOC slots.**
  Pain: the shared GOLD/TL `fcn_00401180` source calls the numeric GOLD symbol
  `fcn_00430bd0`; TL's original helper calls `vfs_ReadData` at `0x004306b0`.
  Both ordinary checks report RELOC because an uncatalogued REL32 target is
  deliberately masked in `coff_reloc._validate_rel32`. Those checks establish
  instruction agreement but do not establish the destination callee binding.
  Feature: report masked-unresolved and validated counts separately, with an
  optional strict catalog/linked-address check for shared-source promotion.
  Evidence: guild-rebrew `src/GOLD.fcn_00401180.c`, original helpers at
  `0x00401180`, `.scratch/goal-client-loop/test-gold-helper.json`,
  `.scratch/goal-client-loop/test-tl-return-in-loop.json`, and the target-scoped
  TL annotation in `src/Develop/Units/vfs/GOLDTL.vfs_ReadData.c`.


## References inside mixed-target translation units

- [ ] **Bind rename references to their annotated function/data owner inside a shared file.**
  Pain: target-aware rename can isolate independent same-name target functions,
  but a file containing both targets may place an unrelated reference in a
  common prototype, table initializer, or a different target's function body.
  Whole-file text replacement cannot decide which binding is meant. It now
  fails before writing rather than renaming both symbols.
  Feature: use C AST reference spans and target-scoped function/data identities,
  with explicit treatment of common declarations; keep unresolved references
  visible instead of inferring ownership from a filename or proximity.
  Evidence: guild-rebrew TL `0x00406510` rename dry run names `command7.c` and
  `alchemistry_logic3.c`; `.scratch/goal-rename/project-builder-preview.json`.
  `tests/test_rename.py::TestRenameTargetIsolation` covers the safe boundary.


## Skeleton append should offer reference-VA insertion

Pain: todo recommends `skeleton <VA> --append <neighbor.c>`, which appends a
lower-VA function after its higher-VA neighbor. W030 then reports that source
order disagrees with reference linker order. Literal append works as named;
the missing feature is ordered insertion with declarations left above both
functions. Proposed `--insert-by-va` (or a todo recommendation that requests
it), respecting each target's shared marker order and rejecting conflicting
multi-target order. Evidence: guild `.scratch/goal-character/lint-final.json`,
three W030 hits for TL 0x40df00, 0x40e110 and 0x405540. Source definitions are
reordered directly as ordinary source-tree repair; no warning is suppressed.


## Retire an erroneously reversed game body after a stock-library match

Pain: library identify deliberately never touches annotated functions; a later
whole-body archive hit therefore leaves an erroneous Game C implementation
and its failed verification history in the tree. Correcting classification
requires a manual source/header move, with separate accounting checks.
Proposed library adopt/retire command: accept an exact archive-match receipt,
preview incoming references and source/header changes, retain provenance and
failed prior measurements as history, retire the local body and annotate library
origin through locked writers. Do not infer a prebuilt build provider from an
archive hit alone, manufacture EXACT, or patch the archive.
Evidence: guild-rebrew GOLD0x5e3d3d, stock ___sbh_find_block in sbheap.obj;
.scratch/goal-crt-retirement/retirement.json and
.scratch/goal-shared-sound/gold-crt-recheck.json.

## Explicit related-import donor for evidenced structural twins (2026-10-04)

Pain: source import-related can restrict a destination (--va) but cannot name an
evidenced donor. TL mouse4117c0 and keyboard4117f0 share the same42-byte structural
shape. Native GUID/CreateDevice output proof identifies Gold410710 and410740, but
default gap refuses both and gap0 chooses the same source for both. Lowering a
threshold cannot communicate the proven identity.
Proposal: --source-va filters the EXACT/RELOC donor set before ordinary score/gap
matching and verification; invalid/unmatched donor addresses must be errors. Keep
thresholds, library exclusion, preview, and verification unchanged.
Evidence: guild-rebrew .scratch/goal-input-types/ambiguous-donors.json, bindings.json;
.scratch/goal-forward-ret/input-guid-cross-build.json and gold-input-init-asm.json.

### Consolidate an already-matched related destination

Pain: import-related --shared only considers unmatched destination functions. Native-proven TL420b70/Gold4247e0 reset has duplicate existing implementations; Gold EXACT37 is excluded before source-va matching, so normal import refuses with no unmatched functions. Proposed feature: explicit --consolidate-matched, preview both source owners and native binding proof, verify the shared replacement in both targets, and retire the superseded file atomically while preserving managed VA metadata/history. Existing unmatched import default should remain conservative. Evidence: guild-rebrew/.scratch/goal-net-stats/import-dryrun.json, native-bindings.json, before-GOLD.fcn_004247e0.c.

### Report native comparison scope in library-match output

Pain: library match --va chooses managed SIZE or a32-byte prefix, not the existing native inventory span. Un-sized LIBRARY markers for TL66080a/Gold5eaad6 therefore produce both strlwr/strupr candidates, while complete native308/158-byte comparisons uniquely identify strupr.obj (strlwr has7/4 fixed mismatches). Current JSON does not expose compared byte count or prefix-vs-complete provenance. Proposed --size and explicit compared_bytes/comparison_scope fields, with previewed inventory-size fallback. Keep prefix hits visibly provisional; report whole-body only after proving the extent. Evidence guild-rebrew/.scratch/goal-vfs-casefold/full-runtime-attribution.json and .scratch/goal-net-stats/next-helper*-library.json.

### 2026-10-04 — Native bindings for declaration-only game callees across targets

Pain: shared TL442c00/442cb0 and Gold4471b0/447260 callers refer to fcn_00450a00, but its body exists only for TL450a00. Gold calls a different native body at453890. FUNCTION parsing deliberately skips prototypes; the declaration alone cannot supply a target-scoped function binding. Unknown REL32 fallback can therefore mask a wrong or unmapped legacy callee name (TL40ec60 currently names Gold453890 while actually calling TL450a00). Adding a fake DATA owner or an empty C definition would misrepresent the tree. Proposed feature: a declaration-only native function binding, stored target-scoped through a supported CLI/API and attached to a canonical prototype, resolved for call validation/link planning without adding a reversed-function body or storage owner. Preview collisions and preserve distinction between build-specific bodies, DLL imports, and data. Evidence: guild-rebrew/.scratch/goal-client-call-api/jobs.json and helper-import-preview.json; .scratch/goal-small-extents/next-tl-40ec60-native.json; src/GOLDTL.fcn_00450a00.c and shared442c00/442cb0 callers. Independently bind native call operands until available; do not claim an unchanged Gold helper import.

### Batch function-extent reconciliation from native boundaries and padding

Pain: TL full gate57178 reports322 shorter SIZE_MISMATCH bodies with zero common-prefix differences;309 have native terminal ret/tailjmp and exclusively NOP tails. These discovery/alignment sizes make already recovered bodies appear unfinished. Existing `test --fix-sizes`, `verify --fix-sizes`, and catalog backfill address size repair; they do not provide the joint strict CFG, complete relocation/literal binding, negative-control, library-exclusion evidence preview described here. Proposed CLI preview/apply operation combining conservative native CFG/end evidence, retained padding/layout accounting, complete object/native binding validation, library exclusion, and target-scoped locked SIZE updates; never shorten solely from object length or a masked prefix score. Surface ambiguous branches/data separately and verify every affected/shared build. Evidence guild-rebrew/.scratch/goal-small-client-helpers/{zero-diff-candidates,native-extent-screen}.json. Current supported metadata APIs can apply individually evidenced repairs; no game-code padding or raw assembly workaround.


Additional evidence (2026-10-11): TL `ahm_SlotClearMatch` at `0x4ee9c0`
and GOLD at `0x4ecbc0` both have 110 reachable bytes plus two alignment NOPs,
but managed SIZE112 makes the unchanged shared C appear mismatched. Complete
CFG, both call operands, numeric native helper identities, library exclusion
and wrong-target controls prove all 220 code bytes. The canonical client
callee names are still unbound, so operand evidence must remain explicit.
Evidence: `guild-rebrew/.scratch/goal20/ahm-slot-clear-extent/native-proof.json`.
This also exercises the declaration-only native function binding proposal above.

## Metadata-backed source split / extraction after marker migration

Landed: `rebrew source split` reads the function row when the file has no marker block. It slices that C definition, leaves file-scope storage in the original, refuses a static or preprocessor-wrapped dependency, and retargets every row that shares the definition. `--dry-run` writes nothing, and a failed retarget restores the source.

Observed 2026-10-04: `rebrew source split src/Develop/DieGildeAddOn/game/spiel622.c --va 0x1001a0d0 --dry-run --target server.dll --json` reported `No function block found` although the managed SERVER identity resolved to the existing gm_RandomMod definition. The CLI at that point only extracted inline marker blocks.

The landed path resolves the selected module and VA through the function store, identifies the C definition, and retargets every row that shares it. File-scope storage stays in the original. A static dependency or a definition inside a preprocessor conditional is refused. `--dry-run` writes nothing, and a failed retarget restores the source. The command does not write a marker line.

Evidence: guild-rebrew/.scratch/goal-random-helper/{split-server-preview.json,split-server-preview.log}. The marker path remains for unmigrated sources.

### Preserve library ancestry when marker inventories overlap C-source identities

A migrated library inventory and an existing FUNCTION C body can share a
(module, VA). Header and source migration currently overwrite the single
marker_type/name identity in order-dependent ways: two Gold runtime wrappers
(5deaf3,5e3a71) remained compiled but disappeared from library accounting and
acquired header hint display names. Preserve library ancestry separately from
the provider decision, keep the actual C provider symbol/name, and normalize
compiled-library paths to the established project-root contract. Exercise
both migration orders, minimal config roots, existing explicit bindings,
and migrated catalog/verification views; dry runs and repeated runs must not
change identities. Do not infer archive ownership from names or repair it by
reversing CRT code. Evidence: guild-rebrew/.scratch/goal-migration-revalidation/
full-native-rejected-comparison.json and after-native-all.json (15645 CLOSED2;
48 intended Gold byte gains remain unaccepted until classification is repaired).

### Lint explicit compiled-library paths after marker migration

Pain: library source bindings are project-root relative, but markerless lint checks only metadata-root-relative paths. Gold src/GOLD.fcn_005deaf3.c and src/GOLD.fcn_005e3a71.c resolve as actual compiled providers yet each receives E001 in every target after ancestry recovery. Proposed fix: let the shared metadata-backed-file predicate resolve explicit LIBRARY bindings against cfg.root with exact paths, without blessing unrelated files or changing ordinary function/data path rules. Evidence: guild-rebrew/.scratch/goal-migration-revalidation/lint-ancestry-all.json and gold-library-actual-provider-check.json.

### Scope migrated compiled-library bodies in CMake source selection

Pain: project-root LIBRARY bindings are discovered by verification/lint but parse_c_file_multi's metadata-relative lookup cannot see them. cmake-sources classifies the pure-C body as unannotated and includes it in every target. After Gold ancestry recovery, server wrongly selected GOLD.fcn_005deaf3.c and GOLD.fcn_005e3a71.c; the raw link fails on foreign _fcn_005e899f. Proposed fix: incorporate actual bound-library file identities for every module before the unannotated fallback, using the public library-source binder and exact resolved paths; retain ordinary helpers and per-target/shared ownership. Evidence guild-rebrew/.scratch/goal-random-helper/server-link/build.log and regenerated build/rebrew-sources-server.cmake. No source filtering workaround or library patch.


### Keep verified inline jump tables out of instruction-only diff summaries

Pain: GOLDTL0x004c3a50 has a348-byte code region plus103 four-byte inline
jump-table entries (760-byte recorded extent). `rebrew diff --json` reports
207 structural instructions after decoding pointer data as x86 code, although
the typed byte comparison isolates eight differing code bytes: independent
MOV/LEA setup instructions emitted in reverse order. Every native table
target agrees with the candidate COFF label value plus addend and function
base; the dispatch operand names the same table. This differs from the older
function-end walker proposal: the extent is already correct.

Proposed feature: expose proven code/table ranges and classify inline pointer
entries as typed relocations in structured diff output. Require COFF symbol,
relocation, dispatch, and bounded entry evidence; preserve comparison of the
entire recorded extent and every table target. Do not remove table bytes or
mask unknown storage to lower structural scores.

Evidence: guild-rebrew/.scratch/goal-tl-training/4c3a50-diff.json,
command-table-audit.log, command-table-differences.json (zero differing
table targets), and probe-command.json (eight code-byte differences in the
baseline). No upstream implementation change or verdict promotion.


## Strict mapped DIR32 proof alongside tolerant source agreement (2026-10-04)

Implemented in the comparison API (2026-10-11): `smart_reloc_compare(..., strict=True)` requires exact mapped DIR32/REL32 operands, rejects unbound/unsupported/out-of-extent claims through `invalid_relocs`, disables symbol-free masks, and retains explicit IAT policy. Compiler-local labels are supplied from their owning COFF section, so switch-table and branch targets can be proved without catalog sentinels. Existing callers retain their documented tolerant agreement; this API change does not silently promote their results to strict proofs. Native switch evidence: `guild-rebrew/.scratch/goal20/entity-class-extent/`.

Pain: the current catalog-limited DIR32 contract masks a mapped-symbol mismatch when the derived native address is absent from the catalog. This can give a RELOC result to a cross-imported body with the wrong table and array bound. Gold 0x004d0a30 compiled from the TL 768-record scan: fixed bytes and all six relocation spans aligned, but native Gold scans 32 records at 0x00930600, while the selected slot-table binding is 0x00770b80. Its two table operands implied different bases (0x00930600 and 0x008cf580) under the incorrect 768-record addend. Neither implied base was catalogued, so the wrong body passed.

Proposed feature: an explicit strict operand-proof mode, distinct from the current tolerant agreement contract, that requires every supplied mapped DIR32 identity to satisfy native_word == bound_va + COFF_addend, even when the competing native address is not catalogued. Report unbound references separately so a fully bound proof cannot silently claim them. Preserve explicit IAT policy and compiler-local jump-table resolution; compare complete code/table extents. Include a regression where the wrong actual address is deliberately absent from the catalog, a wrong array-end addend, and positive compiler-local/IAT controls. Do not silently change the documented tolerant contract without reviewing existing callers and fixtures.

Evidence: guild-rebrew/.scratch/goal-tl-callee-identities/{resolver-binding-conflicts-before,Gold-list-audit,Gold-list-applied}.json. The game repair uses its genuine target-specific C body (32 records, correct array), binds all six operands independently, and rejects every wrong-plus-four control with a correct-native-address sentinel. This is source/data proof and does not establish whole-file equality.

## Translation-unit consolidation (2026-10-06)

- [ ] **`source merge` should keep data pieces in source order.**
  Pain: the merge emits every storage piece before every function. A tentative
  definition ahead of its first use changes how the compiler treats the object
  in the functions that follow, and `#pragma optimize` / `#pragma intrinsic`
  lines that sat beside one function end up in the shared preamble, where they
  apply to every function. Feature: keep pragma lines attached to the piece
  they precede and leave data where its input put it. Evidence: guild
  `game/spiel.c` (gm_AllocGebaeude, gm_CalculateProductionValue, intrinsic
  placement).
- [ ] **Report codegen that depends on the translation unit.**
  Pain: a function that matches alone can stop matching once its callee is
  defined earlier in the same file (VC6 uses the callee; the reference does
  not). The merge reports every function as fine until `test` runs per
  function. Feature: after a merge, re-test each moved function and list the
  ones that changed status. Evidence: guild `gm_Open` (calling
  `gm_InitObjektHersteller` through a pointer restores the bytes).
- [ ] **`build order-sources --exclude` matches a basename.**
  Pain: `--exclude gzio.c` meant the zlib reference file and also dropped a
  game file named `gzio.c` in another directory. Feature: match the path.
- [ ] **`migrate-markers` refuses a file for a comment that looks like a marker.**
  Pain: `/* DATA: SERVER 0x1002944c..0x100294a0` inside a block comment counts
  as a marker line, so the file is skipped as `unrecorded-markers` with no line
  number. Feature: name the line, and ignore marker text inside comments.
- [ ] **Generated CMake should depend on the real store path.**
  Pain: `CMAKE_CONFIGURE_DEPENDS` named `src/rebrew-functions.toml` after the
  store moved to the project root, so a row change did not re-run the source
  selection. Feature: emit the path from the loaded config.
- [ ] **`/OPT:REF` reorders COMDATs, `/OPT:NOREF` keeps dead library code.**
  Pain: a position-aligned raw link needs every game function kept and every
  unreferenced library function dropped. Feature: generate the `/INCLUDE`
  list for all game rows in VA order (guild `layout/server.dll/game-includes.rsp`).
- [ ] **Reclassify a reversed function as stock library code.**
  Pain: a decompiled copy of a stock source (guild `gz_stream.c`, zlib 1.1.3
  `gzio.c` with game names) turned out to compile byte for byte from the stock
  file, but `library bind-source` refuses its FUNCTION rows ("No library
  declaration"), so renaming the symbols (`_vfs_GetByte` to `_get_byte`) and
  setting `marker_type = "LIBRARY"` and the new `file` took a script over
  `rebrew.metadata.record_migrated_markers`. Feature: `library bind-source
  --adopt` (or `library adopt <va> <source> --symbol`) that converts a FUNCTION
  row in place, for every module that shares the file. Evidence: guild
  round 18, `.scratch/r18/rebind_zlib.py`.
- [ ] **Count the relocation records discarded code contributes.**
  Pain: LINK reserves `.reloc` space for every input DIR32 record, discarded
  COMDATs included, so closing the reservation means counting DIR32 per object
  and per discarded COMDAT from the `/VERBOSE` log; no command does it.
  Feature: `rebrew binary relocs --reservation` reporting kept, discarded and
  import-thunk records per input against the reference's `12 * N`. Evidence:
  guild `.scratch/measure/dir32_count.py`, `discarded_dir32.py`.
  Current evidence (2026-10-11): guild-rebrew/.scratch/goal21/server-header-fix/
  current-input-census.json counts5,506 actual records vs5,535 reference-required;
  all3,499 runtime sites/types match. Census archive hashes match the pinned
  Docker libraries. Report this as discarded-input debt, not missing runtime fixups.

## Assembly provenance for definitions without a target VA (2026-10-09)

Pain: correcting W020 to use each definition's own target metadata exposes
assembly in unannotated helpers and discarded shared-TU functions. A helper
has no standalone target address at which to store a BLOCKER. A blocker on a
different function previously hid it, which also hid genuinely undocumented
assembly elsewhere in that file. A containing source file alone does not
establish that the definition contributes bytes to the selected target.

Implemented: `rebrew source document-assembly` manages provenance identified by
file and C symbol, separate from target-VA identity and byte-verification
rows. It records the target and current definition hash without fabricating
a VA or STATUS. W020 reports the affected C symbol and accepts only current
evidence for that file, symbol and target; W031 reports invalid/stale records.
Compiler/map reachability remains future work: a review record does not prove
that the helper participates in a target, and file membership or an unrelated
blocker never establishes that fact.

Evidence: guild-rebrew/.scratch/goal20/asm-context-audit.json and
names-integration-lint-{server,goldtl,gold}-scoped.json. SERVER findings are
vfs_AddFile and vfs_fwrite; neither has an identity row or appears in the
existing raw server map. GOLDTL also has fill helpers without standalone
identities. Existing block-fill evidence lives in docs/msvc6-allocator.md
(Finding 19); source comments and historical matches are evidence to review,
not fresh verification or permission to suppress a whole file.

## Explicit binding of unbound function references (2026-10-10)

Pain: TL 0x406510's restored animation builder has an unrelated health-command
name, while its callers use unbound `fcn_00406510`. Renaming either spelling to
the other's existing name rightly refuses the duplicate; neither rename order
can connect them. An ordinary rename must continue protecting independent
definitions, including the server's real health handler.

Implemented: `source rename PLACEHOLDER MODULE.0xVA` explicitly binds source
references to a unique existing external function. It does not change the
destination definition, managed identity or verification. Definitions, bound
identities, variables, statics, types, macros and ambiguous destinations refuse
before writes. Existing syntax-aware plans, dry runs and rollback apply.
Evidence: guild-rebrew/.scratch/goal20/animation-{rename,reference}-preview.json
and upstream `TestFunctionReferenceBinding`.

## Alignment padding biases cross-target signature scores (2026-10-10)

Pain: GOLD 0x405970 is the same 75-byte animation builder as TL 0x406510,
except for the allocator call and callback pointer relocations. Discovery gives
GOLD an 80-byte span containing five trailing NOPs, while the verified TL donor
owns 75 bytes. The default shared-import preview rejects it: full-span score
94.393546, actual-body score 100. Lowering the threshold hides the extent issue.

Implemented: the shared cross-import/BinSync signature helper uses the existing
bounded extent walker on the supplied bytes. Only a real return covering observed
forward targets followed entirely by NOP/int3 padding shortens the signature.
Reachable NOPs, multiple-return blocks, tail calls and unresolved extents keep
their bodies; int3 is no longer classified as a real return. The original
inventory span still reaches full-body compile verification and its existing
verified size retry. Default score/gap gates are unchanged.
Evidence: guild-rebrew/.scratch/goal20/animation-builder-original-evidence.json,
`animation_builder_evidence.py`, and `animation-gold-import-preview.json`.
Callback import preview at GOLD 0x405870 / TL 0x406410 independently passes
the default structural gate (98.087576); no GOLD row or verdict was written at
that checkpoint. Regression coverage: `TestPaddedSignatures` and
`TestMergedInventoryEntry.test_padded_signature_passes_default_gate_then_verifies_the_body`.

## Select an attested cross-target donor explicitly (2026-10-10)

Pain: after the extent repair, GOLD's builder 0x405970 and caller 0x40c870
both score 100 against their TL counterparts (0x406510 / 0x40d790), but the
automatic importer correctly refuses: unrelated histogram siblings score
96.325483 / 96.275310, inside the default five-point gap. Original instruction
and compiled-body evidence establish the intended pairs; lowering the global
gap would also admit genuinely ambiguous automatic matches.

Resolution: the CLI already supports `--source-va`, but its CLI reference omitted
the option. Document and use that selector with `--va` for a reviewed pair;
the donor's EXACT/RELOC requirement, score/gap gates and complete byte verification
still apply to the selected pool. Automatic selection keeps its runner-up gap.
Reuse the existing shared import path and locked writers rather than hand-editing
rows or copying C. No new option or matching algorithm is needed.
Evidence: guild-rebrew/.scratch/goal20/padded-signature-evidence.json and
`padded-{builder,caller}-gold-preview.json`; no imports were applied.

## Preserve requested identity in single-function diagnostics (2026-10-10)

Pain: `diagnose probe 0x499a50 --target Europa1400Gold_TL.exe` resolves the shared
alchemistry source, then silently measures its first function, TL47ddf0,
_ahm_ResetEntityState, yielding66/66 instead of checking the requested wrong-body
identity. Shared cli.select_annotation discards the positional VA. Explicit
`--va` absent from the file also pairs a new reference with the first symbol/size.
The same helper feeds diagnose gap and match qualifiers, which can edit C.

Resolution: select the active target's annotation at either positional VA or
`--va`; missing entries error before measurement/editing. Preserve direct-file
and decorated-symbol selection without a VA. Fix the shared helper, with inline
and managed/overlapping-target regressions and an actual probe CLI flow check;
no caller-specific workaround or new option. Evidence:
guild-rebrew/.scratch/goal20/ahm-chain-current-probe.json and
probe-selection-regressions-before.log. Separately, TL499a50 itself is falsely
bound to the chain processor; its native four-argument125-byte body is unlike
the true130-byte dispatcher at TL4c4d30/GOLD4c43c0/SERVER1000ca00. That source
identity cleanup must follow trustworthy diagnostics and native evidence.

### 2026-10-11: symbol rename leaves linker response references stale

Pain: renaming shared lb_SearchRecordTable to inferred plt_FindPlantInfo updates
four C sources and all three identity rows, but not the tracked
layout/server.dll/game-includes.rsp /INCLUDE:_lb_SearchRecordTable anchor.
The next raw link fails LNK2001/LNK1120 although all98 compiled function
measurements and whole-section relocation locations remain unchanged.

Resolution: include target-scoped linker response references in the existing
rename plan, preview and rollback path. Preserve native decoration, independent
target twins, paths and public export names. Explicit reference binding to an
existing identity must also repair a leftover linker anchor. No game alias,
manual managed-store edit, new CLI option or weakened gate. Evidence:
guild-rebrew/.scratch/goal20/plant-server-gate.log (failed) and
plant-callers-byte-preservation.json. Implement upstream before completing
the plant checkpoint and rerunning its raw-link gate.

## Shared import identity and measurement repair (2026-10-11)

Pain: importing SERVER10016f80 onto GOLDTL503e80 verifies the shared iterator
at341 bytes but leaves the previous gm_AddObjekt name beside its new
_gm_FindNextFilteredEntity symbol. The next GOLD501030 import inherits that
wrong name. Both341-byte records retain reference_size352 and the padded
reference hash from the rejected first comparison. The source flag helper
also selects another function's /DREBREW_ALLOW_NAKED flag from the same file.

Repair the shared import paths: choose flags by source module and VA, replace
the identity name after verification, and retain the successful retry's
comparison inputs. Keep marker migration's existing-name protection and
failed-retry evidence unchanged. No game source workaround or relaxed match
threshold. Evidence: guild-rebrew/.scratch/goal20/stat-iterator-{tl,gold}-import.json,
stat-shared-iterator-audit.json and stat-import-regressions-before-corrected.log.

Further replay checks reproduce a stale destination override surviving an
inherited flag selection, and a failed managed move between definitions in
one file overwriting the old verdict. Persist flags only after an accepted
measurement and recognize the managed destination symbol when previewing
or rejecting a move. This removes provisional store writes and their
rollback code. Evidence: shared-import-fields-reproduction.json and
stat-import-additional-before.log in the same guild-rebrew scratch directory.

## Shared-import source retirement must honor remaining owners (2026-10-11)

Pain: the numeric slot helper guild-rebrew/src/GOLDTL.fcn_0050dac0.c owns both
GOLDTL50dac0 and GOLD50a640. `import_shared_function(..., dst_file=...)` unlinks
the entire old file after moving one identity, orphaning the other target.
It would also delete other functions and globals in a larger source file.
Preserve files with remaining managed or inline function/data identities, other
function definitions or storage. Remove only the superseded inline claim,
preserving other claims and line numbers. Retire a single-body stub when its
last owner moves. Reuse the annotation lexer and C storage-role inventory;
do not work around this with duplicated game code or manual store edits.

The cleanup also must use migration's existing file-borne comment policy:
SOURCE stays only when naked, while STRUCT/CALLERS stay in the source. A
follow-up regression catches ordinary SOURCE metadata incorrectly surviving
the retired claim; share the policy instead of cloning its rules.

## Preserve the original include search for a source in its workdir (2026-10-11)

Pain: a guild-rebrew helper call-order probe wrote its C candidate directly
in compile_to_obj's workdir. MSVC failed to find a valid parent-relative header:
the source runs at /work, but the original source directory was omitted when
it equaled the host workdir. Always retain an authorized original-path include
search in this case; the /work alias has different ancestors. Evidence:
guild-rebrew/.scratch/goal20/stat-helper-order-probe-variants.log and
compiler-source-in-workdir-before-corrected.log. The MSVC regression fails first;
the GCC case is a passing control. No game header or include-path workaround.

## Find definitions after an assembly prelude (2026-10-11)

Pain: the guild-rebrew statistic formatter preservation check omitted every
function after server.c's assembly fill. The shared definition finder stripped
calling conventions but fed inline assembly to the C grammar, which swallowed
later functions into the earlier body. Use the existing same-length MSVC syntax
mask before walking definitions. LF/CRLF fill regressions fail first; multiline
attributes also demonstrate shifted following line numbers. This fixes every
caller, including retirement, without a game-side parser workaround. Evidence:
guild-rebrew/.scratch/goal20/function-discovery-after-asm-before.log.

## Reject unsupported provenance at the common stamp (2026-10-11)

Pain: a guild-rebrew formatter identity note passed an unsupported tool tag
to update_field. The public field writer accepted it although the batch writer
refused the same input, and all-target lint then reported W031 against the
managed store. Validate against the existing provenance vocabulary in the
shared stamper, before changing an open entry. Five failing regressions cover
fresh and existing stores through single and grouped writes, plus the open
entry itself; no new tag or lint exception is needed. Evidence:
guild-rebrew/.scratch/goal20/provenance-field-writer-before.log.

## Validate recorded native data spellings (2026-10-11)

Pain: the shared name-to-VA catalog ignored data link_symbol even though the
locked writer and ownership tools preserve it. A scalar year field shares
an address with a packed calendar view in the client; recording its verified
COFF spelling could not validate the shared formatter without replacing the
analysis label or inventing another allocation. Include the exact native
spelling in the common marker-scoped catalog alongside the label. Four
regressions fail first and cover test/verify catalog construction, another
target's conflicting spelling, compiler-literal spellings, symbol resolution,
and rejecting a wrong known target. Existing unknown-address policy remains.
Evidence: guild-rebrew/.scratch/goal20/native-data-catalog-final-before.log.

## Retire a fully superseded multi-body source unit (2026-10-11)

Pain: the shared importer deliberately retires only single-body sources. A
two-body office-query unit remains after all three target claims move to the
verified shared server.c definitions. Its conservative guard correctly avoids
deleting unannotated helpers, but completing this source consolidation requires
an explicit operator audit: every former claim, every definition, data and source
provenance ownership, remaining callers, and all native bytes/operands of both
old bodies and their shared replacements. An unowned leftover can also become
an unintended input to the unannotated-source build fallback.

Proposed feature: a previewable retirement operation accepting explicit complete
replacement evidence for every definition. Reject helpers, storage, remaining
claims/references, stale measurements or incomplete mappings. Keep the current
automatic single-body guard; do not generalize its definition-count condition.
Evidence: guild-rebrew/.scratch/goal20/retire_office_query_duplicates.py and
office-query-duplicate-retirement/receipt.json. This is a missing workflow
feature, not a reason to relax the existing import safety check.

## Nested compiler batches with single-file input parity (2026-10-11)

Nested sources currently fall back to individual compiles. VC6 emits an
861-byte `gm_Open` when invoked with `spiel.c`, but 859 bytes with
`Develop/DieGildeAddOn/game/spiel.c`, even with identical preprocessed C.
Adding the missing include paths or a basename `#line` does not restore parity.
Caching the nested batch object under the single-file key poisoned verification.

Proposed feature: batch nested units only when compiler-visible basenames,
include order and header resolution equal the single-file path, for example by
grouping sources by their original directory. Prove complete body and operand
parity before sharing object-cache keys; preserve the individual fallback.
Evidence: guild-rebrew/.scratch/goal20/pool-first-next-gm-open-cache/receipt.json,
pool-first-next-gm-open-batch/receipt.json and its empty preprocessed.diff.

## Distinguish library template hits from operand-supported identities (2026-10-11)

Pain: GOLD's 12-byte seed setter at 0x5de77a matches LIBCMT's
`___set_app_type` template. Stock LIBC reports both that template and `_srand`.
The setter writes the same native word at 0x62e108 that the independently
matched LIBC `_rand` reads; this supports the random binding, while a unique
template hit in the configured archive alone does not prove its identity.

Proposed feature: expose template-only scope and unresolved operand ownership
in library match results, and optionally compare typed data operands against
independently established native allocations and companion archive members.
Keep ambiguous candidates visible and require raw-link evidence before claiming
a configured storage provider. Do not infer a complete CRT selection from one
function or replace stock runtime bodies to satisfy a template.
Evidence: guild-rebrew/.scratch/goal20/random-unit-probe/GOLD-srand-provider.json,
GOLD-srand-libc-provider.json and runtime-providers.json. GOLD's `_rand` origin
was already recorded in guild-rebrew/.scratch/goal-crt-retirement/.

## Acknowledge the selected shared definition without renaming independent twins (2026-10-11)

Pain: GOLDTL40ce80/GOLD40bf60 share a sound wrapper falsely named
cm_ChkSetGebBesitzer; SERVER1000cfe0 independently defines the attested command
validator. Identity-selected CLI rename refuses the shared client rows without
--all-modules, whose preview also renames the unrelated SERVER definition,
its dispatch table and linker include. Neither preview is the intended repair.
The existing source-definition library entry point can preserve the independent
server twin while renaming both client rows. Expose acknowledgement limited to
rows bound to the selected definition, retaining --all-modules' current meaning
and the refusal of ambiguous references. Preview must name every included row
and excluded independent twin; test a shared two-client definition plus server
validator, attributed users and linker references.
Evidence: guild-rebrew .scratch/goal20/sound-wrapper-rename-preview.json,
sound-wrapper-rename-all-preview.json and sound-wrapper/rename-preview.json.

## Native source-unit evidence for organization (2026-10-11)

Pain: source graph --cu-map groups the TL inventory's6,335 functions into only
three broad clusters; that does not establish original unit ownership for3,871
loose root C files. A local read-only scan finds complete native source-path
strings and direct instruction operands referring to them:37 functions across
both clients, including TL420840 in Units/Msx/msx.c and GOLD438780 in
Units/d3/d3_d3d.c. Expose this evidence through a source-unit inventory command:
target, original path, string VA, function VA/extent, instruction VA, managed
source and all shared bindings. Keep direct evidence separate from inferred
caller/global clusters, refuse conflicts, and do not move or merge implicitly.
Use verified body extents so a merged discovery range cannot attribute the next
function's path. Evidence: guild-rebrew/.scratch/goal20/native-unit-map/
{direct-path-evidence,root-candidates}.json and source-cu-map.json.

## Configured target defines in CMake (2026-10-11)

Resolved: build cmake-flags now emits selected target defines as source
COMPILE_DEFINITIONS and reports them in JSON. Three regressions and native
CMake property checks pass; full11,582 passed/51 skipped.

Pain: compile_to_obj applies targets.<name>.defines, but build cmake-flags
emits only metadata code-generation flags and drops configured target defines.
A shared implementation can therefore pass test/verify under its server/client
branch while the configured CMake link compiles a different branch. The
recursive object-list repair requires a genuine SERVER-only empty cleanup
versus the existing54-byte client cleanup; inventing compiler-sensitive game
workarounds would preserve the wrong program. Fix: emit target defines as
CMake COMPILE_DEFINITIONS for each annotated or explicitly listed source,
separately from metadata-only reconstruction guards. Verify selected-target
isolation and CMake's preservation of quoted values, backslashes and literal
semicolons. Evidence: guild-rebrew .scratch/goal20/recursive-object-list-{asm,
server-asm,gold-asm,diff}.json and tests/test_cmake_flags.py target-defines cases.


### Known-global conflicts in normalized cross-imports

A normalized DIR32 comparison deliberately permits a known symbol to resolve to an
uncatalogued native address. This hid a real existing source pairing error: imported
GOLD423b30 uses music-path buffer14611a0, but the existing g_14cc360 row names
GOLDf8aae0 from an unrelated copier. The import reported RELOC; a strict native
operand audit exposed the conflict. TL420760 belongs with GOLD4243d0, not GOLD478860.
Offer a known-binding check for cross-import/test/verify that rejects disagreements
for resolved names while permitting genuinely unresolved operands, and report the
conflicting source/data identities so the canonical declarations can be repaired.
This is hardening beyond the documented generous masking, not a change to its current
agreement-only contract. Evidence: guild-rebrew/.scratch/goal20/msx-start-volume/
start-GOLD-operand-audit.json and src/GOLD.fcn_00478860.c before the split.


## Managed type identities and compiler/native extent evidence (2026-10-11)

Pain: the character scene-node and dummy views live in C, but there is no local
managed type identity linking their per-target compiler sizes and native evidence
to the declaration. BinSync struct artifacts are synchronization interchange,
not a target-scoped source binding. `types check` merges declarations by name
and scans unpreprocessed source; it cannot establish complete heap allocation
extents. W007 was retired because a file-level SIZE comment validates nothing.
Requested repair: a supported locked type metadata writer/CLI with durable
identity, target, C definition, partial/complete extent, compiler layout evidence
and source/context fingerprints; stale claims must be surfaced, not silently
trusted. Native construction/allocation evidence must remain separate from the
size of an accessed C view. Human requests both metadata checks and full native
character layout recovery. Source: guild-rebrew/src/Develop/DieGildeAddOn/game/character.c;
prior proofs in .scratch/goal20/character-shared-pairs/; current work in
.scratch/goal20/type-identity-layouts/. Preserve the existing idea notes.

Implemented locally as main980a49b6: managed rebrew-types.toml, compiler-gated types bind, stale binding checks and conditional-layout parsing guard. Guild D3 native byte extents and target bindings are closed in .scratch/goal20/type-identity-layouts/scope-final.json. Unknown field semantics remain byte regions; no BinSync publication or client relink claimed.

### Rename must preserve source-only assembly provenance (2026-10-11)

Pain: source rename rewrites a reviewed definition and its callers, but leaves rebrew-source.toml under the old definition name with stale hashes in callers whose fill macros did not change. Guild allocator rename m_AllocTracked -> m_alloc affects three target identities and current m_PoolAlloc provenance. Proposed fix: move definition/file identities and refresh only provenance that was current before the mechanical rename; preserve stale evidence, target separation and locked/atomic writes. Evidence: guild-rebrew/.scratch/goal21/allocator-name/preview.json and rebrew rename_ops.apply_rename_plan.


## Resolve ambiguous stock-library wrappers through native callees

Pain: full relocation-masked matching leaves fread/fwrite wrappers ambiguous. A legacy TL header called 0x64ed28 fread; its native callee at0x64ed57 uniquely matches __fwrite_lk. Naming it correctly currently needs an ignored project experiment using archive/COFF APIs, following the same pattern as the earlier sprintf/swprintf proof.
Proposal: extend library match with conservative candidate resolution from native relocation edges. Retain ambiguity for aliases, cycles, out-of-image targets, unresolved data or non-unique callees; return the evidence behind a unique name and keep origin separate from actual linked provider. No automatic store writes or archive edits.
Evidence: guild-rebrew/.scratch/goal21/shared-vfs-freedirs/fwrite-wrapper-proof.json (47 bytes, three rejected shifted bindings, uniquely matched downstream body); fwrite-stock.json contains both original candidates. Public parse_archive, COFF relocation APIs and lib_match already provide the mechanics. Add synthetic wrapper/alias/cycle/unsupported-relocation regressions before implementation.

## Staged matching candidates retain source-relative headers (2026-10-14)

Resolved: climb preview at TL4033e0 failed to compile after character.c moved
to its canonical unit because staging lost local ch_motion.h and parent-relative
Units/d3 headers. Qualifier candidates used the same staging pattern. Both
now pass the original parent through compile_and_compare extra_include_dirs,
reusing the object compiler mounts and include-aware cache key. Evidence:
guild-rebrew/.scratch/goal22/tooling/climb-{before,after}.json; four failing-before
regressions cover both climb objectives, qualifier candidates and API forwarding.

### Member-level matching for dispatch-backed math intrinsics

Pain: TL64d4fa's __CIfmod entry appears as40 native bytes but COFF splits it
into a10-byte thunk plus30-byte local fFMOD implementation. The thunk has only
two fixed bytes, so the existing half-fixed-byte guard correctly rejects it.
library match returns a miss even though all50 bytes of stock87fmod.obj's
_fmod/__CIfmod/fFMOD text, all six operands and rejecting controls agree.
Proposed feature: report whole-member text/data graph candidates, including
local-label implementation blocks and dispatch-table references; retain the
current tiny-wrapper guard and separate raw-link provider evidence.
Evidence: guild-rebrew .scratch/goal22/reconstruction/solar-stock-fmod-text-proof.json
and solar-stock-fmod-member-proof.json. Full80-byte dispatch data,16 pointers,
458-byte support text and44-byte support data now match with rejecting controls;
raw client link-map provider evidence remains pending.


Additional initialization-component case (2026-10-14): the standalone
__cinit45-byte entry has only17 fixed bytes after seven operands, so the
half-fixed-byte guard correctly misses it even with --resolve-callees.
Its two direct calls reach private STATIC __initterm26 in the same crt0dat.obj;
that helper is not an archive external and must not become a game-callable
extern. Both clients match the complete71-byte text component, all seven
operands and six rejecting symbol controls each. This supports component
matching with private callee edges while retaining the wrapper guard.
Evidence: guild-rebrew/.scratch/goal22/reconstruction/crt-init-stock-native-proof.json.
Actual selected client archive/link-map evidence remains unverified; compatible
stock bytes do not choose between CRT archive variants.


### Audit stale source names against managed function identities

Pain: restored legacy C can keep an inline identity and old function name while
its managed row names a canonical shared definition. Batch verification chooses
the legacy body (and sometimes a separate target copy) and lint reports clean,
so the canonical source reconstruction recorded in metadata is not exercised.

Proposed: expose this drift in the existing lint/catalog report, distinguishing
managed definition identity from the effective compiled source symbol. Account
for intentional target macros, aliases and library providers before warning;
show the conflicting file/symbol and the existing rename/rehome repair command.
Do not silently rewrite identity, promote a status or accept only masked bytes.

Evidence: guild-rebrew .scratch/goal23/pool-unification/reset-source-preview.json,
full-corpus-final.json in goal22/spiel-unification (TL4737c0/Gold476c60), and
upstream stale-row rename regression tests. Managed ResetDisplayCounters and
CountDisplayCounters pointed at C still defining their old fcn names; separate
Gold bodies masked the unexercised shared implementation.

## Ranked unassigned .text ranges with status reconciliation

The TL status report leaves 97,581 bytes in `no function`, but no CLI reports
the corresponding ranked ranges. `binary extract list` lists known functions
without source; `binary functions` reruns discovery and does not reconcile its
candidates against the status gap complement. The coverage grid also absorbs
heuristic tails/tables, so its cells are not an exact substitute for status spans.

Expose a read-only JSON gap report using the same span selection, clipping and
edge-fill rules as status. Return start/end, measured byte count, neighboring
identities and classification evidence; make counts reconcile with padding and
`no function`. Keep inferred function/table/thunk classifications explicit and
require reviewed evidence before inventory or extent changes.

Evidence: guild-rebrew TL contains 420 nonempty unassigned ranges totaling
97,581 bytes. The largest starts at 0x00571870 (3,815 bytes), with a 0x724-byte
stack allocation and ordinary direct calls; 0x00660ace starts a mixed range
with three six-byte indirect jump stubs. Replay `rebrew status --target
Europa1400Gold_TL.exe --json` and `rebrew binary asm show 0x571870 --size 96
--target Europa1400Gold_TL.exe --json`. Project-only composition and exact
reconciliation receipt: `.scratch/goal23/pool-unification/inspect-text-gaps.py`
and `text-gaps.json`; no new project inventory/parser or status edits.

## Structured decompiler failures for native callback seeds

After repairing Rizin project persistence, the native TL production callback
0x00571870 still produces no pseudo-C: stderr reports `Ghidra Decompiler Error:
Symbol var_1h extends beyond the end of the address space`. The current function
variable inventory has no var_1h, so its origin is unresolved; do not delete
project types or invent a seed to hide it. Rizin successfully reloads a
32,878,102-byte database and the correct binary before this separate plugin
failure.

Expose a structured backend failure trace (backend, stage, command result and
diagnostic) alongside seed availability, and make optional fallback attempts
reviewable. Preserve accepted external type provenance and ordinary byte
verification; failed/error text must never become a C body. This is a diagnostic
capability gap, not evidence that this external plugin failure is repaired.

Project receipts: `.scratch/goal23/production-callback/rizin-live-project.json`,
`rizin-variables.json`, `rizin-decomp-without-var1.log` and the complete native
callback/switch-table inspection. Both blind variable-removal probes failed;
no game source, accepted types or inventory was changed by them.

## Separate full decompiler bodies from the GA seed character budget

Kuna 1.160 successfully decompiles TL he_RunProduktion at0x00571870 in
default, reliable and aggressive modes (21,684/21,685/22,166 characters).
Each output parses without recovery as one C function. Nevertheless,
`skeleton --decomp --decomp-body --decompiler kuna --dry-run` rejects it
because `valid_c_source` shares the 8,000-character GA seed budget; its
warning instead mentions function identity, directives or assembly.

Give complete decompiler skeleton bodies a separately defined size policy
and report the actual rejection reason. Keep the GA population budget and
structural C gate, identity checks, directive/assembly rejection and ordinary
compile/byte verification intact. This does not make pseudo-types or inferred
float/pointer casts trustworthy: source still needs native review and C89
reconstruction. User requested Kuna alongside other available backends.

Replay `rebrew skeleton 0x571870 --target Europa1400Gold_TL.exe --name
he_RunProduktion --decomp --decomp-body --decompiler kuna --dry-run --json`.
Receipts: guild-rebrew `.scratch/goal23/production-callback/kuna-review.json`,
`kuna-{reliable,aggressive}-seed.c` and `kuna-skeleton-preview.json`.

## Audit C return contracts even when object bytes match

The production callback at TL0x00571870 consumes EAX from packet wrappers
0x004c51f0 and0x004c5250, storing their returned queue ID in its state.
Existing shared C defines those wrappers as void and declares their queue
callee0x004c4330 as void, although the actual queue definition returns int.
MSVC preserves EAX across the wrapper epilogue, so their complete bodies can
byte-match while the C return contract is wrong. Existing caller0x00573a80
already declares the wrapper int and stores its result.

Add a target-scoped audit comparing definition-owned prototypes with referring
declarations, distinguishing opaque pointee views from return/value-width
contradictions. Report concrete declaration/definition sites and caller return
uses; byte-match status must not imply that the C contract is coherent. Do not
automatically infer original parameter types from narrowed packet field stores.
Existing source graph and types commands do not expose this contract audit.

Evidence: guild-rebrew `.scratch/goal24/production/callee-interface.json`,
`src/GOLDTL.fcn_004c4330.c`, `src/GOLDTL.fcn_004c51f0.c`,
`src/GOLDTL.fcn_004c5250.c`, and native callback instructions
0x005725c7..0x005725cf. Project repair must validate complete helper bodies,
existing callers and typed operands independently of the byte-match totals.


## Verify compiler literal values and distinguish reviewed library bindings

With `check_known_bindings=true`, guild-rebrew's all-target corpus correctly
rejects named data operands that reference the wrong offsets. Anonymous compiler
literals remain UNRESOLVED, however: replacing a double literal 1.0 with2.0 can
retain the same function bytes after relocation masking while changing behavior.
The shared transfer template had incorrectly grouped Gold0x004b6b10,
0x004b6d30 and0x004b6ef0: their native coefficients are respectively
(1.0,0.01),(2.0,0.01),(2.0,1/120). Those are distinct native formulas, even
though relocation-masked bodies have the same shape. Function RELOC does not
verify the referred literal bytes.

Expose an opt-in literal-content audit using the compiled COFF/LIEF sections,
typed relocations and complete native pool bytes. Report the literal symbol,
object value, native VA/value and rejecting mismatched-value evidence. Preserve
multiple equal-value pools and separate value agreement from raw-link placement
and storage ownership. Do not silently turn arbitrary data into compiler literals.
Replay `rebrew test src/GOLDTL.fcn_004b6f00.c --target Europa1400Gold.exe --json`
in guild-rebrew; inspect UNRESOLVED __real@ bindings and the native pools at
0x005eb8a8(1.0),0x005eb928(2.0),0x005ece60(0.01),0x005edbc0(1/120).

The binding resolver intentionally excludes LIBRARY rows because unreviewed
FLIRT/Ghidra names have been swapped. Add explicit trust/evidence for reviewed
native library identities so known callee operands can be checked without
promoting attribution guesses to providers. Header-owned TL __ftol at0x0064d228
and strlen at0x00654120 currently remain unresolved in these comparisons;
source/runtime member byte evidence should establish the binding, while a raw
map still establishes the linked provider. Preserve uncertainty for unreviewed
library names. Evidence: guild-rebrew `.scratch/goal26/production/corpus.json`,
`transfer-{tl,gold}.json`, `strict-binding-4ec780.json` and repaired native
literal values. Project-specific operand validation belongs in ignored scratch;
reusable value/trust policy should live upstream.

## Reorder existing definitions with all-target constraints

Pain: function-order lint now locates metadata-only definitions accurately.
A project with shared server/client source can consequently reveal ordering
inversions that were hidden by absent ADDRESS anchors. `build order-sources`
orders translation units, not definitions within one unit, and a single-target
VA sort can violate another target's native order.

Proposed capability: preview a metadata-driven definition reorder, retaining
attached comments, address anchors, file-scope declarations and preprocessor
boundaries. Check all target orders, show cycles explicitly, and require an
evidenced source-unit split when no common order exists. Do not duplicate shared
bodies or suppress W030 to manufacture a clean lint result.

Replay: guild-rebrew `rebrew lint --all-targets --json` with address-only source
bindings. `.scratch/goal27/lint-order-fixed.json` exposes 62 W030 findings in 11
units; a read-only graph using `find_c_function_definitions` and `load_metadata`
finds conflicting target orders in command.c, alchemistry_logic.c,
friedhof_logic.c, spiel.c and loadsave.c. Those cycles need reviewed source
organization rather than an automatic one-target sort.

## Resolve blocker commands through managed names and symbols

Pain: `blocker set cm_ExecCommand ... --target Europa1400Gold_TL.exe` cannot
resolve the function even though its managed row names `cm_ExecCommand` and
binds `_cm_ExecCommand` to `GOLDTL.cm_ExecCommand.c`. The command's existing
symbol route resolves file stems; bare managed names are not file stems.
The same problem occurs for `d3_LoadObjectAnim`. Address selection succeeds.

Proposed capability: resolve managed names and native symbols under the selected
target, retain shared-definition binding, and reject ambiguous names with the
candidate identities. Keep explicit VA/file selection available. Evidence:
guild `.scratch/goal27/blocker-command.json` and `blocker-animation.json` now
contain the successful address-selected writes; the failed name-selected commands
returned code 2 with "Cannot resolve function" before those writes.

## Select eligible targets for a source-file comparison

Pain: `test FILE --all-targets` tests every client definition in a shared client
unit but also reports a symbol-resolution error for server.dll, which has no
binding in that file. This makes the combined exit code unsuitable for checking
that file's actual target contexts.

Proposed capability: an explicit option to select only targets bound to the
requested source file, with skipped target reasons in JSON. Preserve the strict
meaning of an explicit target selection. Replay in guild-rebrew:
`rebrew test src/Develop/Units/Msx/msx.c --all-targets --json`. Both clients have
eleven RELOC results, while server.dll returns code 2 because it has no identity.
Receipts: `.scratch/goal27/order-msx-test.json`; the same occurs for character.c
and server_stats.c. `verify FILE --all-targets` has the same eligibility problem:
an absent server binding correctly rejects the empty scope. Add explicit eligible
target selection to both commands; preserve their ordinary empty-scope rejection.

## Validate translation-unit effects before splitting native source

Pain: a definition-only split can preserve all object matches while breaking the
raw image. Extracting guild cm_ExProdObjekt from attested command.c preserves its
993-byte server RELOC body, but moves literals and changes link layout: .text grows
16 bytes, 30,085 raw file bytes differ, and 32 data rows drift. Restoring the same
body to its original translation-unit position restores all 286,720 file bytes
and 652 data comparisons. Source-order cycles are not evidence for a separate TU.

Proposed capability: a rearrangement preview that keeps original TU composition
explicit, checks all target orders and raw-link consequences, and distinguishes
definition fragments from their compilation provider. Do not invent padding or
data owners to recover the link. Evidence: guild .scratch/goal28/server.dll,
gate-current.log, restore-command.json and gate-restored.log; existing all-target
definition-order proposal above supplies the conflicting-order examples.

## Use native operand evidence to scope a symbol rename

Pain: distinct functions share one placeholder name in the same target. Target
membership alone cannot attribute references. TL4dfba0 calls TL4937d0, but the
placeholder fcn_005049c0 also names TL5079f0/Gold5049c0. Gold5a5ec0's self pointer
and Gold5a60b0's callback instead collide with the independent Gold5af2f0 wrapper.
Rename correctly refuses these ambiguous files and existing destination names.

Proposed capability: an explicit, address-evidenced reference selection, including
function-pointer operands, within a rename transaction. Reject a contradictory
native target and preserve independent definitions. Existing CLI composition
works by assigning a temporary caller placeholder, renaming the selected body,
then binding that placeholder to MODULE.0xVA; avoid exposing intermediate names.
Evidence: guild .scratch/goal28/rename-*-preview.json, rename-*-isolated-preview.json
and bind-*-preview.json. Both inferred final names preserve independent twins.

## Symbolize evidenced views before a raw client link exists

Pain: source symbolize requires a raw link map. It cannot help repair a client
whose incorrect raw addresses currently prevent that link. Two shared guild
providers use TL addresses even for Gold; canonical declarations and native
operand/data evidence already identify the correct views in both images.

Proposed capability: a bounded preview mode using reviewed native operand and
managed data-view evidence, without inferring a storage owner or linked provider.
Keep unresolved aliases explicit and require complete-body checks afterward.
Replay: source symbolize src/GOLDTL.fcn_40ec60.c --target Europa1400Gold.exe
--dry-run --json returns no raw_link. The manual canonical VECTOR3/net-header
repairs validate all eight Gold data operands; receipts are guild
.scratch/goal28/symbolize-*-preview.json and *-gold-test.json.

## Expose per-library comparison outcomes in batch JSON

Pain: Guild's all-target batch reports fourteen of fifteen compiled Gold library
functions passing, but its `libraries` entries contain provider/file/symbol facts
without comparison status, byte delta, bindings or error details. Library results
are correctly separated from game progress, but finding the failed comparison
requires another managed-store query. The current failure is Gold5e3a71,
SIZE_MISMATCH; it is not a game compile error.

Proposed capability: separate address-keyed library comparison rows with the same
measurement diagnostics as game rows, retaining the distinction between origin,
compiled provider and raw-link provider evidence. Preserve summary reconciliation
and avoid treating unresolved archive providers as tested or passed.
Replay: `rebrew test --all --all-targets --jobs 4 --json` in guild-rebrew;
receipt `.scratch/goal29/corpus-current.json`, Gold's `summary`/`libraries` fields.

## Preview atomic multi-field declaration-view edits from the CLI

Pain: reconciling seven Guild lighting declaration views needs kind, section,
access size, alias role and evidence notes together. `data set` correctly rejects
multiple setter kinds in one call, so the CLI cannot preview that atomic change.
The public `metadata.data.set_data_fields_batch` already performs the validated,
locked composition; Guild uses it instead of a separate metadata writer.

Proposed capability: a bounded batch input for non-verdict data fields, with
dry-run and atomic validation of the entire patch. Keep status/verification
exclusive to the verifier; never infer allocation ownership from declarations.
Replay: `data set --storage-kind 0x6b86d4=alias --size 0x6b86d4=4 --dry-run --json`
rejects multiple setters. Guild receipts:
`.scratch/goal31/lighting-data-tl-views-preview.json` and
`lighting-data-view-updates.json`.
