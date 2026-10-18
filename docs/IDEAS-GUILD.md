# Rebrew ideas: features the guild-rebrew effort needed but lacked

Sourced from the 100% byte-identical `server.dll` campaign (MSVC6, x86-32).
Each entry: observed pain, proposed feature, evidence pointer in guild-rebrew.
This is a proposal/evidence ledger, not a command manual: example commands and
flags may be unshipped. Status `open` unless noted; observations describe the
campaign at the time recorded. Use [CLI.md](CLI.md) for shipped behavior and
promote scoped proposals to [ROADMAP.md](ROADMAP.md).

## Source evidence consolidation — implemented in 5.0

The separate `rebrew-source.toml` repeated the metadata ownership boundary for
61 Guild assembly receipts and 14 support purposes. Fold these addressless
file/symbol/module records into `[source]` in format-3 `rebrew-functions.toml`,
sharing its lock and atomic writes without inventing VAs or duplicating comments.
Replay: `rebrew source consolidate --dry-run --json`, review its digest/counts,
then apply with `--expected-digest`. Data remains format 2; verdicts and stale
source hashes survive unchanged.

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

- [ ] **All-target data inventory and conflict reports.**
  `data list` accepts only one `--target`, so checking shared-source data
  conflicts across three targets requires three separate invocations. Add
  `data list --all-targets --json` with target-keyed inventories, conflict and
  multiple-definition summaries, and failure isolation. Replay in guild-rebrew:
  `uv run --frozen rebrew data list --all-targets --json` currently rejects the
  option; `.scratch/goal38/data-{server,tl,gold}-final.json` holds the individual
  reports. This is a batch capability gap; per-target inventories work.

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

- [ ] **Pre-link provider audit for target-selected translation units.**
  Guild's TL audit compiled all 4,840 selected TUs, then found 46 duplicate
  definitions and 3,005 unresolved symbols, including `_WinMain@16`. A TU
  with a valid target binding can still emit other targets' or superseded
  definitions. Extend the existing source/provider and object inventories to
  report these whole-link conflicts before linking, separating functions,
  storage owners, import libraries and unresolved native aliases. Do not choose
  duplicate bodies, invent storage, or suppress errors with `/FORCE:MULTIPLE`.
  Replay/evidence in guild-rebrew: `.scratch/text-accounting-20261016/` contains
  `duplicate-definitions.json`, `duplicate-provider-review.json`, and
  `link-probe/link.log`. The diagnostic probe explicitly omits the absent
  `LUA50.lib`; it is not a successful or verified build.

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
  is invisible to `git status`, to `rebrew lint`, to `rebrew verify --no-cache`, and
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

Follow-up: provide an evidence-backed, atomic edit of selected inventory extents
without replacing the entire discovery catalog. `binary functions --output`
regenerates all rows; `source register` owns managed source sizes, not the
inventory. A stale discovery extent can therefore block CU recommendations
even when the source's complete native size is already correct.

Guild TL0x4186c0 is a five-byte external tail jump followed by eleven NOPs;
its old47-byte inventory span included the following function. TL0x571720
ends with a return at0x57186e and one NOP before the production callback;
its verified335-byte body was recorded as4160 bytes. Curated repairs using
the existing atomic emitter preserve all6337 identities and unblock
`rebrew recommend --target Europa1400Gold_TL.exe --json`. Require reviewed
complete-body/next-entry evidence, preserve names and unrelated rows, and
report the changed bytes separately from source verification. Do not truncate
at an early return or blindly replace a curated inventory with a new scan.
Receipts: guild-rebrew `.scratch/goal37/inventory-*-repair.json`, native assembly
and `tl-discovered.json`; the full new scan has7503 rows and was not installed.

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

Implemented: `types contracts` audits target-scoped source/include contexts,
including return/value, ABI, unmarked globals and context-specific typedefs.
`types reconcile --dry-run` previews one reviewed canonical-header signature,
caller argument conversions and all affected targets while preserving parameter
names, bodies and metadata verdicts. Unsupported/uncertain cases require explicit
source repair. The motivating project evidence follows.

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

Repair follow-up: allow a reviewed signature to move into an existing subsystem
header, remove conflicting per-file prototypes, add the selected header to its
users and preview caller argument conversions through the MSVC-aware AST.
`types apply` edits one definition parameter; `source rename` preserves caller
types. Neither performs this reconciliation. Preserve target-specific provider
bindings and compiler-sensitive declaration order, and list every affected
target/source context for verification. Guild renderer wrapper TL442be0 /
Gold447190 needed one byte return and one D3_OBJECT pointer contract across
31 contexts; replay `.scratch/goal39/canonical_calls.py` and inspect
`scope-audit-current.json`, `wrapper-native-proof.json` and six type receipts.


Global-declaration follow-up: report incompatible unmarked users separately
from the marked reference description. The current data scanner deliberately
prefers marked types, so `data list --conflicts` can report zero while one
extern object is declared as both `int` and `char*` in active translation units.
Preserve reference/stand-in and incomplete-array policies, but expose a
source-contract diagnostic with declaration sites and target participation;
zero inventory conflicts must not imply compatible C declarations.

Evidence: guild-rebrew main3122f9dd, `g_6b8014` at TL0x006b8014 /
Gold0x00fc2dec; `.scratch/goal43/camera-declarations.txt` contains41 source
files,34 integer and seven pointer declarations. The native setter at
TL0x00439c60 / Gold0x0043cbe0 stores an art-3 object pointer. Replay
`rebrew data list --conflicts --target Europa1400Gold_TL.exe --json`
and compare `src/GOLDTL.fcn_00439b30.c` with
`src/GOLDTL.fcn_00439c60.c`. Include raw-address users and affected pointer
parameter/transport fields in the reviewed repair closure; declaration repair
must not hide stale integer interfaces behind pointer-to-integer casts.

## Verify compiler literal values and distinguish reviewed library bindings

Implemented: `data audit-literals` compares complete operand-selected compiler
constants; `library review-native` establishes explicit binary-bound exact native
names after strict full-object/operand/literal proof. Provider attribution remains
separate. Unknown literal extents and unsupported objects/fixups fail explicitly.
The original project evidence and motivation follow.

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

Implemented preflight: `source organize review` reports all-target definition
orders and cycles with original provider/TU/storage context; it does not rewrite
one target's order into shared source. `source organize check` compares independent
complete PE raw builds, including initialized data and placement. Actual automatic
definition reordering and ownership/outlier inference remain distinct proposals.

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

Follow-up: monotonic definition order also misses an isolated first definition
far outside its inferred native unit. In guild-rebrew, ahm_ResetEntityState
is first in alchemistry_logic.c at TL0x47ddf0 / Gold0x47e930, while the other
client alchemy functions form a much later run. W030 alone cannot identify
this kind of binding or placement uncertainty. Source ownership remains
unproven; a prefix and a sorted file are insufficient evidence.

Reuse the existing `cu_map` / `recommend` cluster evidence in an optional
all-target lint audit, showing target-specific outliers and the evidence behind
them. Respect COMDAT, explicit order policies and genuine cross-target unit
differences; do not automatically split a source or treat every gap as an error.
Replay `rebrew recommend --target Europa1400Gold_TL.exe --json` alongside
`rebrew lint --all-targets --json`; compare native source-unit evidence and the
single shared chain dispatcher at SERVER0x1000ca00 / TL0x4c4d30 / Gold0x4c43c0.

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

## Compare modeled call inputs in semantic checks

Pain: Guild TL 0x00412d30 returns a simple success value but builds two 88-byte
object-animation records and passes twelve bytes of options by value. A proof
that stubs the callee and compares only EAX plus watched globals can miss wrong
position inputs. The documented current prover scope does not compare call
arguments or the pointed-to records, so it cannot validate this reconstruction.

Proposed capability: optional, explicit call contracts that compare call count,
order, typed scalar/by-value arguments and bounded pointed-to memory snapshots.
Keep unknown callees and unspecified effects explicit. Compare shared symbolic
inputs where possible; concrete fixtures remain bounded evidence and must not
earn exhaustive or byte-match claims. Include wrong-argument rejecting controls.

Evidence: Guild `.scratch/goal32/compare-transition-traces.py` uses the existing
COFF/relocation APIs and angr for this one native function. Its 96 concrete
cases compare complete call inputs, records, returns and three globals; a wrong
position control rejects. Replay with the Guild pinned environment:
`uv run --frozen python .scratch/goal32/compare-transition-traces.py`.
Receipt: `.scratch/goal32/transition-trace-proof.json`.

## Retire an incorrect target binding without losing native inventory or history

Pain: three legacy Guild TL bindings passed coarse structural similarity but
identified unrelated routines as cm_ExDestroyBuilding, gm_AllocGebaeude and
InitNewDynastyEntity. Native argument use, calls, constants and allocation labels
establish the real counterparts; two already have matched numeric implementations.
The current source CLI has no detach/rebind operation. The public locked
clear_identity_fields and record_function_identity APIs can perform the repair,
but callers must compose its history, collision and related-reference checks.

Proposed capability: preview and atomically retire a proved-wrong source binding,
with its reason and optional evidenced counterpart. Keep the native inventory,
extent and historical comparison receipts; make historical verdicts distinguishable
from current source claims. Adopting an existing counterpart must preserve its
verdict and refuse drifting duplicate definitions or guessed call bindings.

Evidence: Guild `.scratch/goal34/identity-retirement.json` and native Kuna/dossier
receipts. Coarse related-import scores were95–97 for the false identities; replay
`rebrew source import-related --from server.dll --source-va 0x1000f680
--target Europa1400Gold_TL.exe --dry-run --candidates-only --json` and inspect the
reported TL0x57c7b0 against its one-argument daily-update body.

## Use the shared signature database in library identification

`library identify` currently scans only `<project>/flirt_sigs` independently by
file, while `library scan-signatures` merges that directory with the configured
shared recondb database and applies architecture selection. The difference is
not visible in identify's JSON summary. A project with millions of configured
signatures can therefore run identify without using its shared DirectX/CRT
signatures. Reuse a common signature-source resolver, retain per-file provenance
and cross-file ambiguity, and report the actual directories/counts. Preserve
whole-body/callee validation and keep ambiguous short signatures as candidates;
never improve coverage by blindly assigning the first plausible library name.

Evidence: guild-rebrew `.scratch/goal43/library-identify-audit.json` reports790
candidates (mostly generic short patterns/import thunks) from local signatures;
`library scan-signatures` loads7,102,296 signatures from project plus shared
recondb. Existing TL accounting already credits1,008 D3DX8 functions and455
other library functions; references/dxsdk8/lib/d3dx8.lib is configured. Replay
`rebrew library identify --dry-run --json --target Europa1400Gold_TL.exe`
and `rebrew library scan-signatures --show-ambiguous --json --target
Europa1400Gold_TL.exe`. The full scan and direct archive comparison remain the
supported read-only audit; this request concerns discovery/composition parity.


## Implemented evidence workflow updates (Rebrew 4.1.0)

Local coverage views now read canonical inputs directly; portable coverage is an
explicit export. `test FILE --source-targets` and `verify FILE --source-targets`
select eligible target contexts with explicit skips and isolated errors. Data
inventories accept `--all-targets`; `data set` applies multi-field/row patches
atomically with strict previews and reviewed-input digests. Complete decompiler
bodies no longer inherit GA seed size limits.

Reviewed identity retirement/replacement is `source binding retire` / `rebind`.
Native sizes and previous measurements survive in managed history; counterparts
retain their valid verdicts, and replacements earn fresh ones. Old ADDRESS
comments cannot resurrect a retired claim. Ordinary registration and delayed
comparison writes cannot reactivate one; former-only TUs are inactive.

Selected native inventory repairs use `binary repair-extents`, retaining unrelated
rows and evidence while validating full executable spans and input digests. This
closes the selected extent-edit workflow above; it does not implement automatic
CFG-boundary inference or earn a source comparison verdict. Compiler literal
audits and reviewed native library identities are implemented. Declaration
contracts/header reconciliation and link-aware organization preflight/raw checks
are implemented. Automatic source reordering remains a separate proposal.

## Resolve references between independent same-named functions (2026-10-15)

Problem: imported target-local placeholders can give unrelated definitions the
same C symbol in one reconstructed target. The strict native-name resolver
correctly refuses a conflicting binding, but a reviewed rename cannot currently
identify which definition an otherwise ambiguous caller uses. Existing
`source rename PLACEHOLDER MODULE.0xVA` deliberately handles unbound names only;
`--all-modules` would rename both independent definitions and retain the collision.

Concrete case: guild-rebrew has `fcn_0047dd60` for TL47d220/Gold47dd60 (a32-byte
kind predicate) and TL47dd60/Gold47e8a0 (a137-byte entity-link helper). Previewing
`rebrew source rename GOLD.0x0047dd60 gm_IsEntityKind2To5 --shared-definition
--dry-run --json` refuses the shared caller `src/GOLDTL.fcn_0047de50.c` as
ambiguous, without writes. Its native call must be checked against the137-byte
helper in each target before selecting that owner. Client verification currently
stops at `ambiguous native function name: _fcn_0047dd60`; other same-symbol groups
also require review. Receipts: guild-rebrew/.scratch/goal45/rename-kind-preview.json
and the two kind-native disassemblies. No ambiguous caller was renamed or hidden.

Proposed capability: accept explicit, reviewed reference ownership for selected
caller definitions or physical call/declaration sites, keyed by target identity.
Preview both selected and excluded references, require current-input digests,
reject contradictory cross-target ownership, and apply through existing syntax
and metadata writers atomically. Keep distinct bodies, native extents and verdict
history; affected definitions and callers must earn fresh comparisons. Do not
pick the first definition, weaken global validation, treat a byte match as a
declaration contract, or invent forwarding aliases to escape the collision.

Coordination update: main 319071e0 removes the target-wide catalog abort. Conflicting
callee spellings now fail only operands using them and report AMBIGUOUS in both
comparison modes; unrelated functions can still be tested. The concrete caller
at TL0x0047de50 calls the 137-byte TL0x0047dd60 helper; that caller source has no
Gold binding. Caller-ownership input for independent-bound-name rename remains
a separate open capability. The initial library-accounting suspicion was merged
native extents in the project, handled by reviewed `binary repair-extents`, not a
separate upstream library-accounting defect. No Guild caller/source edits were
made during this coordination.


## Expose the complete unstarted-function lane for byte-focused triage (2026-10-15)

Problem: `todo --category start-function --limit 3000 --json` still returns only
50 candidates. `_collect_new_functions` stops at 50 entries while traversing the
native inventory, before the global ROI sort and final display limit. On
Guild TL all 50 entries are below 0x41a000, while the target has 1,225 game
functions without source. Larger bodies elsewhere never enter this selection.
This is a candidate-discovery limit, not evidence of incorrect coverage accounting.

Replay from guild-rebrew: `uv run --frozen rebrew todo --target
Europa1400Gold_TL.exe --category start-function --limit 3000 --json`.
Receipt: guild-rebrew/.scratch/goal46/todo-start.json (total_items/count both 50).
`rebrew binary extract list --min-size 1024 --max-size 8192 --json` provides a
separate inventory path; its candidates still need library and boundary review.

Proposed capability: rank or page the complete eligible lane, and make any
performance budget explicit in JSON/help rather than silently discarding later
addresses. Support selection by potential new matched bytes as well as effort.
Keep existing filters for libraries, interior/pseudo-functions, IAT thunks and
other non-targets; a later large function or high-value candidate must remain
reachable when more than 50 lower-address entries precede it. Source placement
still requires evidence, and selecting a candidate earns no comparison verdict.

## Complete Docker SDK contexts for source-contract reconciliation (2026-10-15)

Problem: the shipped Docker-only MSVC workflow can compile the project, while
`types reconcile` refuses a selected function because host include-closure scans
cannot resolve CRT/SDK headers inside the pinned image. The guard correctly
keeps uncertain contexts explicit, but the supported workflow has no complete
context to review. Guild's office-helper preview reports incomplete contexts
including stdio.h, stdlib.h, windows.h and sys/types.h in unrelated translation
units. Do not remove the guard or infer declarations from equal x86 widths.

Replay from guild-rebrew: `rebrew types reconcile fcn_004e8240
src/Develop/DieGildeAddOn/game/aemter.h --prototype 'int __cdecl
fcn_004e8240(unsigned char, unsigned char*, unsigned char*, int, int);'
--dry-run --json`. Earlier preview
receipt: `.scratch/goal46/office-message-reconcile-preview.json`; full unknown
contexts: `contracts-office-helper-all.json`. Follow-up all-caller measurements
in `.scratch/goal47` support an unsigned-char ID with integer flags: an integer
ID preserves the helper's 129 bytes but grows two TL callers from 414/65 to
430/67 bytes. Restoring the unsigned-char ID preserves both callers. DWORD
forwarding alone does not establish the C parameter width; the earlier rejection
of that ID type from push width alone was too strong.

Goal69 replay (2026-10-16), from guild-rebrew:
`uv run --frozen rebrew types reconcile fcn_00451840
src/client_scene_transform.h --prototype 'int __cdecl
fcn_00451840(float* a, float* b, float range);' --dry-run --json` also refuses
incomplete contexts. The full contract audit reports `findings: []`, alongside
122 SERVER, 915 GOLDTL and 625 GOLD unknown-context records; unrelated Docker
SDK include closures still prevent the writer from establishing the
complete affected source set. Receipt: `.scratch/goal69/bounds-contracts.json`.
Keep the incomplete-context guard. Explicit source repair and preservation checks
with each target's pinned compiler remain necessary; an empty findings list is
not a complete-context verdict or permission to rewrite uncertain sources.

Goal80 replay (2026-10-17): `types contracts --name fcn_00448360 --target
Europa1400Gold_TL.exe --json`, the Gold `fcn_0044be60` counterpart, and TL
`fcn_005222a0` all observe one consistent declaration key and no findings, but
exit1 with921 TL/639 Gold unknown contexts (include closure and C parsing).
Receipts: guild-rebrew `.scratch/goal80-scene/contracts-summary.json` and the
three full audit files. Fourteen scoped pinned-compiler comparisons and complete
object-preservation checks remain separate evidence; they do not close the
unpreprocessed corpus. The savegame receiver's explicit legacy `int f` still
crosses into the now pointer-typed scene bridge; signature-key agreement and a
recorded argument identifier are not argument-value/type-flow proof. Keep that
limit and the incomplete-context guard visible in any compiler-context workflow.

Goal82 replay (2026-10-17): `uv run --frozen rebrew types reconcile
CloseVfsStream src/Develop/Units/vfs/vfs.h --prototype 'int __cdecl
CloseVfsStream(void* stream);' --dry-run --json` still refuses incomplete
contexts. No source writes occur. The explicit stream repair instead captures
all 87 affected compile contexts / 140 bound definitions, including complete
server objects and discarded code/data. Receipt:
`.scratch/goal82-vfs/close-reconcile-preview.json`; preservation scope:
`.scratch/goal82-vfs/preservation-scope.json`. This does not close the SDK gap.

Proposed capability: obtain complete target-specific declaration/include
contexts from the pinned compiler image, with image/source/flag hashes and
missing or conditional inputs reported explicitly. Preserve per-target header
ownership and declaration order, enumerate every affected caller, and fail
closed on unresolved contexts. No reconciliation operation should earn a byte
verdict; validate source edits separately with the target compiler and raw link.

## Audit managed type layouts across all configured targets (2026-10-15)

Problem: `rebrew types check --all-targets --json` exits2 because the option is
not supported, although `types contracts` already supports it. Guild's shared
`amt.office_slot` layout has separate SERVER/GOLDTL/GOLD bindings and pinned
compilers. A default-target success does not check either client binding.
Replay/error: guild-rebrew/.scratch/goal48/types-check-all-targets-cli.stderr.

Proposed capability: add the existing all-target dispatch/output convention to
`types check`, including `--compile`, with independent per-target results and
explicit skips when no managed layouts participate. Preserve stale-input and
compiler-failure diagnostics, and never report unexecuted targets as checked.
Current composition uses the public `check_types` API once per configuration;
guild's three positive sizeof/offset binds and wrong-offset compiler rejection
remain separate evidence. Receipt: `.scratch/goal48/types-all-targets.json`.


## Add reviewed native entries when splitting coalesced discovery (2026-10-15)

Problem: `binary repair-extents` safely repairs existing starts but explicitly
rejects starts absent from the native inventory. A reviewed split can therefore
shorten the first function while leaving the second native function absent.
`source register` can bind a reconstructed body there and earn a comparison,
but source identity and native discovery inventory remain separate facts.
Rerunning whole-binary discovery is not a selective, history-preserving repair.

Guild Gold example: discovery recorded0x00504e00 with size120. Complete native
instructions and compiled C prove a29-byte integer wrapper ending in a tail
jump at0x00504e18, three NOPs, then a distinct88-byte paired wrapper at0x00504e20
ending with RET0x00504e77. The former already had a29-byte RELOC source binding;
the latter now has its own shared-source identity. The reviewed existing extent
repair120→29 preserves history. Native inventory still lacks0x00504e20.

Proposed capability: preview/apply selected reviewed native-entry insertions or
splits through the inventory owner, with current binary/inventory digests,
complete executable-span validation, explicit overlap/neighbor handling and
provenance/history. Preserve unrelated rows and all source verdicts; adding a
native boundary must not award a byte match or infer source/library ownership.
Keep heuristic discovery separate from acceptance of explicit native evidence.

Replay in guild-rebrew: `rebrew binary repair-extents 0x504e20=88 --reason
reviewed-split --target Europa1400Gold.exe --dry-run --json` currently rejects
`selected addresses are absent from inventory: [5262880]`. Evidence:
`.scratch/goal49/skill-wrappers-gold-native.json`, `wrapper-proof.json`,
`wrapper-extent-{preview,applied}.json` and `missing-native-entry-preview.stderr`.
The five complete wrapper/caller bodies agree across321 bytes, with18 rejecting
symbol controls and separate complete literal audits. Unknown operand bases
remain comparison hypotheses; this request does not bless linked providers.


## Explain two-stage MSVC switch selectors (2026-10-15)

Problem: `binary switches` finds physical dispatch tables but does not trace an
8-bit selector lookup back to its bounded input. Its cases0..5/0..2 and null
bounds describe table slots, not the original input values. Preserve that
uncertainty explicitly and expose the lookup/bias when native instructions
prove them; do not present physical slots as recovered source-case values.

Guild TL allocator502fe0 has two complete examples. At0x50319a, EDI is type minus0xb8;
the unsigned bound0xa6 precede zeroing EAX, loading AL from0x50360c+EDI and dispatching
through0x5035f4+EAX*4. Inputs0xb8,0x12c,0x12d,0x134/0x135/0x136,0x15e reach the five
nondefault handlers. The second uses type minus0x174, unsigned bound0xf2, lookup0x5036c0
and dispatch0x5036b4. Nondefaults are0x174/0x176 and0x24b/0x256/0x266. Six/three dispatch
slots are not those semantic input values. The nearby separately handled0x160
case must stay separate. Native map bytes and input/reference hashes are in
guild-rebrew/.scratch/goal50/switch-maps.json; CLI output is switches-cli-tl.json.

Proposed capability: report physical slots separately from bounded selector
inputs, recover supported byte-map/bias chains through existing loaders and
instruction analysis, and retain unresolved/unsupported chains explicitly.
Validate the complete lookup and target tables, range bounds, target addresses
and file-backed extents; do not decode lookup bytes as instructions or infer
source names. Cover rejecting changed-selector/bounds/table controls in tests.
Replay: `rebrew binary switches 0x502fe0 --window 2016 --json --target
Europa1400Gold_TL.exe` in guild-rebrew. Kuna also loses the indirect arms in this
case, so preserving the distinction materially helps ordinary-C reconstruction.

## Bound FLIRT progress output for large databases (2026-10-15)

Problem: `_parse_sig_files` prints one `Loaded ... signatures from ...` line per
file through the shared console, including JSON scans. Guild's 7,102,296-pattern
merged database makes this diagnostic stream dominate a single-address scan;
the machine-readable result can be only a zero-match summary. This obscures real
warnings and makes remote tool output unnecessarily expensive. Valid JSON on
stdout remains useful; the issue is the unbounded per-file progress on stderr.

Proposed capability: emit a bounded aggregate loading/progress summary normally,
make per-file successful loads available at debug verbosity, and preserve parse
warnings and failures. Respect CLI verbosity without coupling library parsing
to terminal rendering. Keep signature selection and match results unchanged.
Replay in guild-rebrew: `rebrew library scan-signatures --va 0x403880 --target
Europa1400Gold_TL.exe --json > result.json 2> progress.log`; compare stderr size
and verify the same signature count and zero matches. The native constructor is
separately identified by `ch_CreateMesh()` diagnostics, not by a signature miss.

## Review reference ownership when renaming independent same-target definitions (2026-10-15)

Problem: guild has two independent source definitions named
`gm_ResetAllEntities`, each with TL and Gold identities. The table walkers differ:
TL4297c0 walks 128 records at stride0xc98; TL5012b0 clears the logical entity
table and has the server counterpart. The existing city loader TL5392a0 calls
TL5012b0, but the shared spelling is ambiguous and correctly fails comparison.
`source rename GOLDTL.0x004297c0 fcn_004297c0 --shared-definition --dry-run --json`
correctly refuses to guess ownership of entity.h, loadsave.c, server.c and the
city loader. Module-only reference selection cannot distinguish two providers
present in the same target; renaming both would preserve the ambiguity.

Proposed capability: preview an explicit, reviewed reference-ownership plan for
a selected definition and its related-target identities. Use complete native
call operands and source context where available; allow a guarded review of
retained declarations/callers separately from rewritten ones. Keep unresolved
references explicit, preserve the other definition and its users, snapshot exact
source/store inputs, and apply through the existing rollback and metadata
writers. Test changed-input, wrong-callee, common-header and same-target controls.
Do not resolve this by a global text replacement or by weakening known bindings.

Replay in guild-rebrew: the rename command above with
`--target Europa1400Gold_TL.exe`; `rebrew test 0x5392a0 --no-promote --json
--target Europa1400Gold_TL.exe` reports `_gm_ResetAllEntities` as AMBIGUOUS at
operand +0x88. Receipts: `.scratch/goal52/reset-name-preview.json`,
`external-5392a0-test.json` and `external-5392a0-diff-fixed.json`. The repaired
diff diagnostic reports XX and exit1; this separate ownership capability remains
open. Neither native walker nor its byte-match history should be retired.

Implemented for reviewed file-level ownership through `source rename
--shared-definition --reference-owner FILE=MODULE.0xVA`, with a preview/apply digest.
The plan snapshots source/header inventory and bytes, metadata/configuration,
target images and linker inputs. Unassigned ambiguous files, unavailable owners,
changed inputs and ambiguous same-target linker symbols still refuse. Native
callee proof and subsequent comparisons remain project acceptance evidence;
files containing references to both owners require a finer repair.

## Review internal archive entry points within a complete function (2026-10-16)

Problem: stock VC6 LIBC strstr.obj jumps to `___from_strstr_to_strchr`, an
exported entry six bytes inside strchr. Both labels are marked as COFF functions.
Guild Gold's complete 128-byte strstr at 0x5de800 resolves that operand to
0x5df106; the complete 188-byte strchr at 0x5df100 equals its stock member.
`object_function` correctly refuses to cross the next function-marked symbol
without an explicit relationship, so selecting `_strchr` with the complete
188-byte extent currently refuses at the internal label. A separate fake
function/allocation or a guessed resolver alias would hide the relationship.

Proposed capability: preview and apply an explicit reviewed internal-entry
relationship, with a covering function, offset, exact archive/member hashes,
complete native/object extents and operand proof. Let strict native review use
that receipt without treating the entry as an independent body or double-counting
its bytes. Preserve current fail-closed behavior for unreviewed adjacent labels,
overlaps, changed inputs and ambiguous archive candidates. Keep native identity,
library origin and actual raw-map provider evidence separate.

Replay/evidence: guild-rebrew/.scratch/goal55/strstr-native-library-proof.json
checks all 128+188 bytes and rejects a +1 internal-entry operand. The unmodified
members are extracted through `formats.archives.parse_archive` from the pinned
Processor Pack LIBC.LIB. `library match --stock-lib LIBC.LIB --va 0x5de800
--resolve-callees --json --target Europa1400Gold.exe` reports the strstr member
but leaves its callee resolution unresolved. No resolver trust or byte verdict
was granted. The old 138-byte discovery extent also includes a separate 10-byte
stub; its reviewed native correction is independent of this capability.

## Distinguish logical callbacks sharing an indistinguishable native body (2026-10-16)

Problem: Guild's character command registration names PreloadSitMesh. TL points
to 0x40dac0, a three-byte return-zero body. Gold's corresponding registration
points to 0x49dee0, already identified as Lua default_panic. The registration
recipes otherwise agree. Identical tiny bodies cannot establish original source
ownership, a Lua provider for a game callback, or whether the linker folded
separate logical definitions. Replacing the library identity or creating a second
physical function would claim more than the native bytes show.

Proposed capability: represent reviewed logical callback/source relationships
separately from physical native identity, keeping folding/provider hypotheses
explicit until independent source or raw-map evidence resolves them. Permit an
acknowledged shared physical extent without double-counting bytes or silently
binding every identical stub to the same source name. Snapshot recipes, complete
native bodies and existing identity/history; refuse conflicting or changed inputs.
This is separate from internal entry-point offsets within one function.

Evidence: guild-rebrew/.scratch/goal56/kuna-gold-registration.json and
native-gold-registration.json show the PreloadSitMesh operand at Gold49dee0;
the TL native-40e1a0.json registration points to40dac0. native-40dac0.json shows
the complete three executable bytes before alignment. No Gold game identity,
library retirement or linked-provider claim should be inferred from this equality.

## Admit selected native functions omitted by discovery (2026-10-16)

Problem: Guild's TL40dac0 is a three-byte callback referenced by the character
command registrar. Complete source comparison is EXACT, but lint correctly emits
W028 because discovery's default minimum size of eight omitted the native entry.
A fresh `binary functions --min-size 1` scan finds the entry, but replacing the
whole reviewed inventory would discard unrelated extents/history. Existing
repair-extents refuses absent addresses; source registration deliberately does
not establish native inventory.

Proposed capability: explicit selected admission with executable-span and overlap
checks, reviewed reason, input/operation digest, unchanged metadata/verdicts and
one locked atomic publication. Preserve every unrelated row and its order; never
turn admission into an automatic byte match. Replay: guild's
`.scratch/goal56/native-40dac0.json`, stub-production-tl.json, lint-first.json and
discovered-min1.json. The separate Gold shared-body ownership remains unresolved.

Implemented through `binary repair-extents --add-missing`. Default missing-address
refusal remains. Admission rejects retained overlapping extents, permits a reviewed
predecessor shrink in the same batch, and records absence as old_size:null.
Preview/apply binds updates, reason and policy alongside the full binary/inventory.

## Resolve callback typedef parameters in source contracts (2026-10-16)

Problem: ordinary `typedef int (__cdecl* EVENT_CHECK)(char* event)` parameters
remain `unresolved context-specific typedef` in `types contracts`. The resolver
rejects every alias containing `(`. Substituting its abstract type as a word
would instead create invalid C, and nested callback parameter names currently
survive `prototype_type_key`, producing false differences against inline forms.

Proposed capability: compose supported callback parameter declarators through the
existing C AST, normalize nested parameter names, preserve callback ABI/return/
argument differences and per-TU meanings, and retain conditional, ambiguous or
unsupported uses as unknown. Do not erase callbacks to `void*` or bless a verdict.
Replay: in guild-rebrew, `rebrew types contracts --name fcn_004e7160 --all-targets
--json`; `src/Develop/DieGildeAddOn/game/event_callbacks.h` is the canonical
header. Native callback storage and full-EAX consumer evidence, complete paired
objects and rejecting controls are in `.scratch/goal57/native-proof.json`.

Implemented for ordinary named callback parameters: AST declarator composition,
chained/per-TU aliases and nested parameter-name normalization. Conditional,
qualified, object and other unsupported callback uses remain explicitly unknown;
this does not establish their compatibility or any native byte verdict.

Regression coverage also preserves pointer/function declarators when a typedef's
return/base type is a named record; replacing the entire type with its tag had
lost those declarators. Anonymous records remain unresolved.

Guild replay (2026-10-16): `uv run --frozen rebrew types contracts --name
g_1052c60 --all-targets --json`. Its canonical `src/client_timer.h` declares
`typedef struct { TIMER_CALLBACK funktion; unsigned int periode; int pausiert; }
TIMER_CALLBACK_SLOT;` and an extern array of 32 slots. Both target compilers
confirm sizeof12/offsets0,4,8; complete native controls match every bound operand.
The auditor intentionally returns `unresolved context-specific typedef` for the
anonymous record in eleven TL and six Gold contexts. This is an unsupported
identity form, not evidence of a declaration conflict or a compiler failure.

Proposed capability: preserve anonymous record identity from its canonical
definition and actual per-TU include context using the existing C AST. Recognize
the same physical definition through a shared header without equating unrelated
anonymous records by typedef spelling or layout alone. Keep conditional,
ambiguous and incompatible declarations explicit. Add same-header acceptance and
independent-record rejection tests; do not invent source tags, erase the type or
promote byte/data verdicts to bypass this gap. Guild receipts are retained in
`.scratch/goal61/timer-proof.json` and `contracts-current-all.json`.

## Bind non-record typedefs with compiler evidence (2026-10-16)

Guild's event runner establishes a first-slot callback contract represented by
`typedef void (__cdecl* EVENT_RUN)(char* event);`. The registry stores this
four-byte value at the beginning of records with a 20-byte native stride.
`types contracts` understands the callable typedef, but `types bind` accepts only
parseable struct definitions and cannot retain an identity for this declaration.

Replay in guild-rebrew:

```sh
uv run --frozen rebrew types bind event.run_callback \
  src/Develop/DieGildeAddOn/game/event_callbacks.h EVENT_RUN \
  --size 4 --native-size 20 --extent stride \
  --evidence 'First callback field, one event pointer, registry stride20; not an allocation' \
  --dry-run --json --target Europa1400Gold_TL.exe
```

Current rejection: `'EVENT_RUN' has no unique parseable struct definition`.
Source inspection confirms the limitation is in `type_metadata`'s record-only
lookup, rather than a target compiler failure. Do not introduce a wrapper struct
or manually write a type row merely to satisfy that lookup.

Proposed capability: select a unique scalar/pointer/callback typedef through the
existing C AST and source-context machinery, compiler-check `sizeof`, retain its
canonical ABI and input fingerprints through the locked type writer, and recheck
it after source/header/target changes. Reject field-offset requests for non-record
types. Keep C value size separate from enclosing native record stride, complete
allocation extent and ownership. Existing record binding/checking must retain its
current validation. Guild currently checks this callback width with a C89 compiler
assertion and audits its signatures; these do not create a managed type identity.

## Audit source contracts across reviewed native data aliases (2026-10-16)

Problem: per-name contracts can each be clean while two source names describe
one native object with incompatible types. Guild's current-universe slot is
TL `0x67a370` / Gold `0x5fb5b0`. The canonical `g_67a370` view is declared `int`
at 108 physical sites; four additional Gold declarations use `char* g_5fb5b0`.
Native iterator operand proofs bind both Gold views to `0x5fb5b0`. No source
storage owner is proven. The separate name audits report no conflict within
either name; that does not establish one compatible global contract. Fourteen
raw-address-only files add further users. Direct 129 files expand through
headers to 241 target bindings.

Replay from guild-rebrew: `uv run --frozen rebrew types contracts --name
g_67a370 --all-targets --json`, then the same command with `g_5fb5b0`. Current
receipts and public-AST participation are in `.scratch/goal69/universe-pointer/
{REPORT.md,contracts-tl-name.json,contracts-gold-name.json,participation.json,
scope.json}`; the native aliases are supported by the complete 288-byte iterator
operand proofs in `.scratch/goal69/iterator-contract`. Native debug formatters
also pass the selected record to `%s`. Incomplete SDK contexts remain explicit.

Proposed capability: extend the existing contracts audit to compare declarations
in a target data-identity/native-alias class, using explicit managed bindings
and current reviewed operand evidence. Report incompatible int/pointer views
and unresolved aliases without inferring addresses solely from numeric names,
automatically merging symbols, inventing backing allocations/storage owners or
earning comparison verdicts. Preserve unknown/include/target contexts and the
separate distinction between C linkage names and proven native destinations.

## Verify import-archive version evidence before linking (2026-10-16)

Problem: matching imported API names alone accepted the wrong Miles archive for
Guild TL. The local `MSS-6.0/mss32.lib` supplies 51/51 required names but matches
0/51 reference PE import hints. A directory labeled MSS-6.1 actually contains a
7.2g runtime. The Guild backup runtime identifies 6.1c and agrees with all 51
hints, but the exact original SDK archive has not been recovered. The project
now explicitly blocks the client link instead of substituting a compatible SDK.

Proposed capability: extend public archive inspection to expose full COFF import
members' hint/name/DLL evidence as it already does for short import members, and
compare the emitted import interface against a selected reference PE. Keep
interface agreement, SDK provenance and complete archive identity distinct.
After reviewing an archive, pin its hash and reject changed inputs before link.
Never infer exact original archive identity solely from a subset of names/hints.

Evidence in guild-rebrew: `references/mss-6.1c/README.md` and
`.scratch/text-accounting-20261016/{miles-version-requirement.json,
all-miles-library-fingerprints.json,re3-miles-fingerprint.json}`. Replay the
blocked client build with `cmake --build build-goldtl-audit --target
europa1400gold_tl`. Existing loaders used by the audit: LIEF PE imports/exports,
`formats.archives.parse_archive`, `formats.coff.load_coff` and
`lib_inspect.inspect_archive`; no alternative binary parser is needed.

## Verify a reviewed set of source files in one invocation (2026-10-17)

Problem: a canonical placement-header change in Guild affects nine C files and
fourteen target bindings spread across `src/`. `test` and `verify` accept one
source file or a directory/all scan, but cannot accept this explicit file set.
Separate `test FILE --source-targets --json` processes repeat corpus/configuration
work; during this replay several were still live after six minutes with roughly
1.3 GB resident each. This observation is not a diagnosed performance bug.

Proposed capability: repeatable explicit file selection for existing batch
verification, sharing one project scan per target while retaining every binding,
target skip/error, compiler input hash, known-binding check and locked verdict
write. Do not select only filename-derived modules or broaden the verification
scope to the entire corpus silently.

Evidence: guild-rebrew `.scratch/goal75-placement/{scope-before.json,
scope-extra.json,preserve.py,preserve-extra.py}` records the complete source set
and the fourteen preserved objects. Replay the present limitation with
`uv run --frozen rebrew test src/GOLDTL.fcn_00598550.c --source-targets --json`
and equivalent invocations for the remaining files; `rebrew test --help` and
`rebrew verify --help` expose only one positional file and directory filters.
The scratch compiler proofs are independent change-preservation evidence, not a
replacement verification/metadata store.

Follow-up (Guild Goal79): `.scratch/goal79-gui/verify-scope.py` composes the public
`read_source_bindings`, `run_verification` and `apply_status_updates` APIs for
four Gold and two T&L bindings. Each target shares its normal symbol catalog,
known-binding checks, compiler input evidence and one locked batch verdict write.
This is a scoped scratch replay, not a new verifier. The same reviewed file set
still cannot be expressed through one CLI invocation; expose that selection in
the existing batch command rather than requiring each project to compose it.

## Review a copied source body's replacement by a library identity (2026-10-17)

Problem: Guild Gold5de784 is a copied naked assembly `rand` body. Pristine
Processor Pack LIBC rand.obj matches all30 bytes and both `_holdrand` operands,
with rejecting controls. `source binding rebind` requires a C definition, so it
cannot select an inventory-only library header. The public binding-history
writer supports this composition, but its whole-store expected digest repeatedly
rejects while unrelated function comparisons/imports update the large store.
The source/header/archive/native inputs and selected row need a guarded review;
unrelated rows should not require reviewing the native proof again.

Proposed capability: compose existing strict library evidence and binding-history
writers into one reviewed source-to-library replacement, preserving the old
source verdict only in history. Guard the selected identity and every reviewed
source/binary/object/binding dependency, while allowing unrelated atomic writes.
Keep classification and native symbol trust separate from an actually selected
raw-link archive provider. Do not infer a provider or carry the old C EXACT to
the replacement library row.

Evidence/replay: guild-rebrew `.scratch/goal76-assembly/{rand-proof.json,
rand-rebind.py,rand-rebind-preview.json}`. Two executions of `uv run --frozen
python .scratch/goal76-assembly/rand-rebind.py` rejected with `function metadata
changed while reading; retry`; neither applied a rebind or removed the source.
The current safety rejection is expected under its documented whole-store guard;
this requests a more precise composition, not removing that guard.

Follow-up: once the concurrent comparison writers finished, the same guarded
public API replacement succeeded. The copied source was removed and the sole
caller migrated through `source rename` to SDK `rand`, preserving all30 caller
bytes/fixups. Receipts: `.scratch/goal76-assembly/rand-rebind-apply.json` and
`.scratch/goal77-assembly/rand-caller-proof.json`. Strict `library review-native`
still rejects the private seed's unresolved project binding; no public seed
declaration or guessed backing allocation was added to bypass that rejection.

## Reference binding must distinguish disabled physical definitions (2026-10-17)

Problem: Guild's TL receiver calls `fcn_00522e30`, whose managed destination is
`GOLDTL.0x00522e30` / `ls_LoadEntities` in `loadsave.c`. A second physical copy
inside `#if 0` in `GOLDTL.loadsave2.c` made `source rename` reject the destination
as ambiguous. Conversely, a selected definition present only inside `#if 0`
was incorrectly accepted as the external provider.

Fixed upstream: preserve physical AST definition facts and mark definitions
proven inactive under literal-zero `#if`/`#elif` bodies. The reference-binding
provider guard excludes only those facts. Unknown conditions, malformed syntax,
live `#else`/`#elif` branches and static/variable collisions keep the existing
rejection. No preprocessor guess or project-local renamer is introduced.

Replay: in guild-rebrew, `uv run --frozen rebrew source rename fcn_00522e30
GOLDTL.0x00522e30 --dry-run --json`. The preview now selects two references in
one caller, no metadata edits or source moves. Regression tests in
`TestSelectedFunctionAliases` cover disabled copies, nested conditions, disabled
selected owners and live/unknown alternatives. Before the fix, four cases
failed; after it, both rename test files pass all 203 tests. The full suite also passes: 12,454 passed, 36 skipped. Receipts
and the reviewed caller COFF baseline are in `.scratch/goal81-vfs/`.


## Prototype replacement must mask preceding MSVC assembly (2026-10-17)

Problem: `replace_function_prototype` could not find `vfs_OpenStream` in Guild's
valid `vfs.c`, even though the shared ParsedSource walker found it. A preceding
MSVC assembly copy loop made the raw C grammar swallow later definitions into
an error node. The prototype editor masked calling conventions but not assembly.

Fixed upstream: use the existing same-length `mask_msvc_syntax` before walking
prototype definitions. Replacements still splice only the reviewed signature
into the original bytes. Regressions cover a preceding assembly block, a
single-line statement, labeled assembly, UTF-8 comments and an unchanged assembly
body in the selected definition. The pre-fix regression receipt is
Guild `.scratch/goal82-vfs/upstream-regression-before.log`; project replay uses
`replace_function_prototype` on `src/Develop/Units/vfs/vfs.c`, selecting
`vfs_OpenStream`. No project-local parser or literal-edit fallback is added.


## Function rename treated unrelated `main` tokens as references (2026-10-17)

Problem: `rebrew source rename GOLD.0x0053cf50 WinMain` in guild-rebrew refused
before any write. The scan treated every whole-word `main` as a cross-target
reference, so a comment in `server.c`, the script string `"main"`, and a local
variable named `main` were ambiguous beside the independent `minigzip` `main`
and the other client's definition. Real direct calls, function-pointer and
address uses, and MSVC assembly operands have to move with the selected
definition. A header declaration, a macro body, or a call built into both
providers must still refuse. `--all-modules` is the wrong repair: it would
rename every provider.

Fixed upstream: function hits and rewrites use the existing declarator, scope,
and occurrence classifiers. Comments, literals, and shadowed variable or
parameter bindings are not references. Macro bodies and unsplit tokens,
including assembly operands at their original offsets, stay references because
their target is unknown. Provider ambiguity is unchanged. A new name already
used by another target's own file is not a duplicate; a use in the selected
target or in an unscoped header still refuses. `source register`
then refreshes a stored decoration when it is the same C name and the parsed
prototype implies a different one, so `int __stdcall main(void *, void *, char *, int)`
becomes `_main@16` and a later rename keeps `@16`.

Replay: `tests/test_rename.py::TestRenameTargetIsolation::test_unrelated_main_tokens_do_not_block_real_users`
and `test_unknown_and_cross_target_main_references_still_refuse`. Guild replay,
after this fix, is `uv run --frozen rebrew source rename GOLD.0x0053cf50 WinMain
--target Europa1400Gold.exe --dry-run --json` and the same command for
`GOLDTL.0x00544c50` on `Europa1400Gold_TL.exe`.

## Hex/CFG disassembly output ignored the requested file (2026-10-17)

Problem: `rebrew binary asm show 0x41c830 --target Europa1400Gold.exe
--output native.asm` printed its hex view and silently left the requested file
absent. Both hex and CFG dispatch omitted the shared output/preview arguments;
only NASM honored them. Replayed with an explicit 8-byte slice in Guild
`.scratch/goal82-vfs/asm-output-repro-*`: no file, 57 stdout bytes.

Fixed upstream: pass output/preview into both inspection modes, reuse their
existing rendered views and the atomic text writer. JSON files contain the same
payload as stdout; text files contain the listing without terminal colors.
Dry runs preserve existing or absent destinations, and failed writes emit a
structured CLI error without partial JSON stdout. Regression matrix before:
10 failed/8 passed; after:18 passed. Full suite and replay receipts live in
Guild `.scratch/goal82-vfs/`.


## Target context for documented-address findings (2026-10-17)

Request: a multi-target client workflow tried `rebrew source findings 0x41c830
--target Europa1400Gold.exe`; the command rejects `--target`. The current API
is intentionally root-scoped: choosing a binary does not establish ownership
of plain Markdown mentions, and `--doc` already selects reviewed documents.
A future target-aware lookup needs explicit module/address evidence in document
findings and must retain mixed/unattributed mentions, rather than silently
filtering by a selected binary. This is a capability request, not a broken
existing target option. No local target-filtering search was introduced.

## Bind partial interface views without claiming allocation extents (2026-10-17)

Request: Guild's Gold dialog uses the first three IUnknown vtable slots of
IDirectDraw4 and the first four IDirect3D3 slots. Its private declarations are
prefix views, not complete SDK interfaces or native allocations. `rebrew types
bind --help` currently requires `--native-size` and permits only allocation or
stride extents. Binding a 4-byte interface pointer shell or a 12/16-byte vtable
prefix as a complete allocation would overstate the evidence.

Support an explicit partial-view contract with compiler-checked member offsets
and a minimum accessed extent, retaining unknown complete extent and backing
owner. It must remain distinct from allocation/stride coverage and full SDK ABI
verification. Replay context: Guild `src/GOLD.fcn_0041c830.c`, `DD_VTABLE`,
`D3D_VTABLE`, and the private interface structs. Real DD_DEVICE/DD_DRIVER record
strides are separately compiler-checked at 0x338/0x214; no false interface extent
was bound to bypass the missing view capability.

## Distinguish static references from indexed-base and bound candidates (2026-10-17)

Request: Guild town reader0x524040 has `mov eax,[eax*4+0x14a5320]` and a
cursor comparison against0x868058. Exact-address xrefs report neither: the first
is an indexed memory base, while the second is an immediate used as a bound.
Treating either as an unconditional access to that exact address would also
overstate the evidence. Replay: `rebrew binary xrefs 0x14a5320 --target
Europa1400Gold_TL.exe --json`, versus full1478-byte disassembly of0x524040.
The base has one classified address load in txt_OpenText; its scaled town use
is separately visible at0x5245bf. The compare at0x524218 is not one of the20
actual dword accesses to0x868058.

Expose separate candidate roles for indexed displacements and address-like
bounds, preserving base/index/scale and unknown accessed extent. Retain exact
static-reference counts and numeric-constant ambiguity. Evidence/replay using
existing instruction APIs is in Guild
`.scratch/goal82-grok-towns/data-followup/REPORT.md` and `insns.py`; no second
permanent xref implementation was added locally.

Goal83 update: image-valued x86 `cmp` immediates now have the separate `cmp`
kind in the shared scanner and CLI, including the immediate side of
`cmp [absolute], immediate` without losing its `cmp_mem` reference. These are
possible pointer comparisons; an in-image numeric constant is still ambiguous.
Guild TL `0x1042024` previously had zero CLI references despite two comparisons,
and `0x1042340` had 7 instead of 36 static candidates. Regression tests cover
32/64-bit comparisons, scalar exclusion, both operand addresses, target/kind
filters, and all three shared scanning entry points. Indexed displacement roles
and register-relative dataflow remain open; this does not infer accessed extents.

## Surface matched assembly bodies in todo without relying on source metadata (2026-10-17)

Problem: `todo` only emits `naked-reconstruction` for matched functions whose
metadata says `source = "naked"`. Guild Gold `0x4ce1b0` is catalog EXACT but its
entire body is `_emit` assembly without that field. The repaired E023 lint finds
65 unsupported bodies, while todo's actionable assembly category misses such
rows. Replay: `rebrew todo --all-targets --category naked-reconstruction --json`
and `rebrew lint --all-targets --json` in Guild; inspect
`src/GOLD.fcn_004ce1b0.c`.

Proposed capability: reuse the shared MSVC assembly-span classification when
selecting actionable bodies, preserving metadata provenance and byte verdicts.
Do not manufacture source attribution or weaken EXACT to compensate. This is a
discovery gap; no change to the todo selection has been applied.

## Goal83: whole-function assembly lint coverage (implemented)

- Problem: E023 counted only lines repeating `__asm`/`_emit`, so a naked
  `__asm {` followed by bare `push`/`mov`/`ret` lines produced no error.
  Guild's Gold resource thunk at `0x45d9e0` and node release at `0x476850`
  exposed the missing accounting; byte agreement did not establish C recovery.
- Capability: reuse the compiler-extension token scan for complete MSVC assembly
  spans, then classify their instructions. Preserve the one/two padding-byte
  allowance and ignore C tails, labels, C comments and assembly comments.
  Both `_asm` and `__asm` block spellings are recognized.
- Regression: `uv run --frozen pytest -q tests/test_lint.py::TestE023NakedAsm`;
  seven new block cases failed before the repair, and two follow-up edge cases
  rejected an initial line-based patch. Production reproductions and full-suite
  receipts are in Guild `.scratch/goal83-upstream-lint/`. No lint policy or
  project gate was weakened.

## Goal83: absolute COFF archive definitions (implemented)

- Problem: inspecting stock LIBCMT `exsup.obj` reported `__except_list` as
  `section:None` and omitted its absolute value zero. It is an absolute COFF
  symbol, not an allocation or an unresolved section. Replay in Guild:
  `rebrew library inspect LIBCMT.LIB --defines __except_list --target
  Europa1400Gold_TL.exe --json`.
- Repair: retain the value for IMAGE_SYM_ABSOLUTE definitions; both full member
  output and `--defines` explicitly label it absolute. This changes inspection
  only; no resolver binding, global storage, native identity or library provider
  is inferred from a coincident value.
- Regression: zero and nonzero absolute-symbol fixtures fail before the repair;
  `tests/test_lib_inspect.py` now checks JSON member data, inverted definitions,
  terminal output, and that these are neither COMMON nor undefined symbols.
  Guild keeps before snapshots and test receipts in
  `.scratch/goal83-upstream-absolute/`.

## Qualify source-binding counterparts by target/module (2026-10-17)

Guild's TL string-reader source claim at `GOLDTL.0x4011a0` points at a file
with no definition, while `GOLD.0x4011a0` is a separate existing counterpart.
`source binding retire --counterpart GOLD.0x004011a0` rejects that key as an
invalid hex VA; the option only identifies another VA in the selected target.
The retirement safely proceeds without a counterpart option and leaves Gold
untouched, but the explicit relationship cannot be represented by this command.

Accept a target-qualified counterpart identity and verify that its complete
binding/verdict is preserved across the guarded mutation. Keep same-VA identities
in different modules distinct. Replay and the non-mutating rejected command are
recorded in Guild `.scratch/goal83-stream-primitives/`; no cross-target rebind or
provider merge was attempted as a workaround.

## Bind a placeholder to one target's independent same-name provider (2026-10-17)

Guild's `vfs_ReadData` has separate SERVER and TL source definitions. TL
`fcn_004306b0` is an unbound placeholder for the selected `GOLDTL.0x4306b0`
identity. `source rename fcn_004306b0 GOLDTL.0x004306b0 --target
Europa1400Gold_TL.exe --dry-run --json` rejects the binding because its lexical
destination search finds more than one external definition. The selected row
already identifies the TL source file; the SERVER provider must stay independent.
Likewise, renaming Gold's separate `GOLD.0x430bd0` to the reviewed canonical
name is rejected by the existing-name collision guard. These are conservative
refusals, and no source or provider was changed.

Add a reviewed target/provider-aware plan that selects definitions from complete
managed identity and compiler contexts, enumerates every rewritten caller in
every target, and rejects mixed or unknown owners. Require a guarded digest and
preserve independent source providers and verdicts; do not relax the generic
duplicate-symbol guard or equate providers based on their shared spelling.
The concrete preview commands and refusal observations are recorded in Guild
`.scratch/goal83-stream-primitives/binding-preview-observations.md`.

## Goal83: scope CMake flag resolution to the build inputs (implemented)

Guild requested one Gold source with `build cmake-flags --sources-file
.scratch/goal83-miles-candidates/gold-one-source.txt --target
Europa1400Gold.exe`. The command examined every bound TU instead, emitted
thousands of unrelated entries, and rejected the request because unselected
`zufall.c` has conflicting flags. An empty source list had the same problem.
`--sources-file` now scopes both checks and output to its resolved paths,
preserving the build's path spelling and unannotated-input defaults. Without
the option, every annotated TU is still checked and conflicting flags still fail.
The two new regression cases fail before the repair. Replay and suite receipts
are in Guild `.scratch/goal83-miles-candidates/`.

## Compare CMake compile context with pinned verification (2026-10-17)

Guild's Gold helper has identical 144-byte object `.text` under its old CMake
composition and pinned verification, but different default-library directives:
the project's generic client loop selects /MT and plain SP5, while Gold's
configured context is Processor Pack SP5 with /ML. The repaired per-file flag
include correctly emits /O2 /Gd and REBREW_GOLD; those do not override the
caller's runtime or compiler-image selection. This is a project composition
error, not a source byte-match failure. The client-only CMake branch is being
corrected and actual generated-rule verification is pending.

Extend build-context checks to compare actual generated CL arguments with the
selected verification context: image/profile, runtime/base flags, target macros
and header roots, separately from CMake's build.make/flags.make agreement.
Report conflicts rather than silently replacing caller flags. Keep separate
targets and per-file overrides explicit. Native probe and driver receipts:
Guild `.scratch/goal83-gold-cmake-context/REPORT.md`.

## Shared source root in contract/organization contexts (2026-10-17)

Concrete bug: `source organize review` on Guild's nested
`src/Develop/DieGildeAddOn/game/GOLDTL.fcn_0040df40.c` reports the existing
`Develop/DieGildeAddOn/game/ch_script.h` missing. Compilation implicitly adds
`shared_dir` when the TU lies within it; the contract scan rebuilt the explicit
flags and omitted that root. Receipt: Guild
`.scratch/goal83-gold-flag-getters/organization-review.json`.

Implemented the shared fix in `source_contracts.contract_contexts`: use the
compiler's effective flag composition before extracting include directories.
A nested-source regression fails before the fix; its no-shared-root control
retains the unresolved include. This closes local header discovery and
fingerprinting only. It does not provide Docker SDK headers, preprocess
conditional declarations or establish source organization/raw-link safety.

## Repeated header extraction in source-contract audits (2026-10-18)

Guild's named `types contracts --name fcn_0046c1c0 --all-targets --json` audit
walked the declarations of a shared header once for every including unit.
The global-declaration lookup additionally walked the entire AST for every
global in each context. This is CPU work, independent of compiler execution
backends and object caches. Preserve separate per-TU typedef meanings and
unknown contexts; deduplicate physical extraction, not semantic contexts.

Implemented physical-file function/global extraction once, reusing the parsed
AST and a declaration-line index, then expanding immutable function sites into
each real context. A regression fails before the fix (two extractions for two
includers), checks once-per-file extraction and preserves function/global
contexts, contradictions and calls with full or name-scoped audits. Existing
typedef/linkage/input-change guards remain. Both-warm alternating runs on a
201-declaration header included by 12 units measured median 0.594s to 0.028s,
with complete reports equal; this fixture is not a whole-project speed claim.
Evidence/replay: Guild `.scratch/goal99-gui-center/benchmark-contracts.py`,
`contract-benchmark.json`, and upstream `tests/test_source_contracts.py`.

## Multi-target CMake compile throughput with a shared Wine prefix (2026-10-17)

Guild's first isolated full client builds select 4,840 TL and 4,482 Gold source
files. Each actual generated recipe goes through the pinned compiler driver.
The PP Wine-prefix lock serializes the two client builds even at two jobs each;
Gold reached about 164 objects near 2% after the initial run, with no compiler
error. Evidence: Guild `.scratch/goal83-gold-build-baseline/REPORT.md` and
`.scratch/goal83-tl-build-baseline/REPORT.md`. Keep prefix isolation and locks;
do not remove them to claim parallelism.

Proposed capability: reproducible batch compilation or safe isolated compiler
workers for generated CMake builds, preserving exact argv, runtime, target
macros, include roots, diagnostics and COFF bytes. Validate throughput and
complete-object equivalence against actual generated rules, rather than
reusing single-file cache entries from a different compile context. This is
build performance evidence, not a game/provider byte-match claim.

The generated Docker toolchain also calls `cmake_tc.driver_main` through
`_docker_run` unconditionally. Setting `compiler.execution_backend = "unshare"`
selects that backend for test/verify, not these CMake recipes. A backend-aware
CMake toolchain needs explicit target context so per-target overrides survive,
plus compile/link object-equivalence checks before reusing build caches. The
2026-10-17 Gold follow-up build confirms actual Docker invocations despite the
verification backend setting; this is a separate generated-toolchain capability,
not evidence that image-only `verify --data` invokes a compiler.

The 2026-10-18 API review also rules out replacing `_docker_run` with a bare
`run_toolchain(..., execution_backend="unshare")`: unshare binds `workdir`
read-write at `/work`, sets that as cwd, and makes additional `mounts`
read-only. Generated CMake commands need their actual build cwd, readable
project inputs, and writable `/Fo`, `/OUT`, `/MAP` and response-file paths,
which can be elsewhere under the project root. Preserve the clock wrapper,
include/library environment, last toolchain-pin precedence and immutable
image admission too. Extend the supported execution context before switching
generated recipes; compare real CL/LIB/LINK outputs and relative-path cases.
Replay surfaces: `cmake_tc._docker_run`, `compiler.toolchain.run_toolchain`,
`compiler.unshare._profile`, and Guild
`.scratch/goal94-slot-cleanup/{gold,tl}-build-restored.log`. Existing active
Docker recipes must retain their dispatch until a reviewed reconfigure.

2026-10-18 resolution: project-level backend dispatch and the required native
same-path execution context are implemented below. Existing builds were stopped
before this bridge change. Per-target backend identity and cross-context compile
cache reuse remain separate open capabilities.

Guild's server gate also exposed the danger of source-wide CMake pin greps:
adding a correct client-only PP branch made its legacy grep label that pin as
a server override. The project gate now scans only generated server compile,
flags and link rules; its before-failing case plus wrong-server-pin controls
pass. Native server codegen and entire raw bytes remain unchanged. A reusable
upstream context audit should scope by generated target, retain later-pin
precedence and report runtime/default-library directives separately. Do not
infer every target's compiler from all literal strings in CMakeLists.txt.

## Shared source flags in a combined CMake build (2026-10-17)

Concrete bug: two `build cmake-flags` tables use source-wide CMake properties.
When two build targets compile the same file, the last included table replaces
the other target's flags and definitions. An isolated fixture reproduces both
targets receiving `/O2` and `BUILD_B`, losing A's `/O1` and `BUILD_A`. Guild's
isolated client baseline builds do not combine targets and are unaffected.
Replay: Guild `.scratch/goal83-multitarget-cmake/replay.py`.

Implemented `--cmake-target <build-target-name>` to emit appended source
properties conditional on the actual consuming CMake target. The Rebrew
configuration target and CMake build target are separate arguments. Includes
require that build target to exist, and invalid target names are rejected before
writing. Actual CMake regression configurations check both inclusion orders,
quoted/semicolon definitions and an unrelated third target; the old unscoped
mode remains available for existing single-target builds. Guild adoption is
staged until its running client baselines finish so their inputs stay frozen.

## Replace one FUNCTION claim with a header LIBRARY identity (2026-10-17)

Problem: ten Gold VAs (`0x5dea38`, `0x5dea49`, `0x5dea5a`, `0x5dedd8`,
`0x5dedf8`, `0x5defef`, `0x5e5157`, `0x5e4fe7`, `0x5e5269`, `0x5e533f`) have
whole-span matches in pinned PP `LIBC`, but their rows are `kind = FUNCTION`
on `src/GOLD.fcn_*.c` with symbols `_fcn_*`. `rebrew source binding rebind`
keeps the current kind and requires a C definition, so it cannot point the row
at a comment-only `library_*.h`. `record_function_rows` refuses a retired row
(`retired source bindings require an explicit reviewed rebind`). The rand
follow-up below already uses `metadata.binding_history.change_source_binding`
for one replacement; there is still no CLI that sets `kind = LIBRARY`,
preserves `size` and history, and clears the old game-byte verdict.

A second consequence: `build_name_to_va` skips `LIBRARY` annotations and admits
a library symbol only from a `native_identity` receipt. Reclassifying the
private callee `_doexit` does not put `_doexit` in the resolver, so
`library review-native` of the `_exit` wrapper still reports an unresolved
operand. Do not treat that as a failed byte compare. Data and import operands
of the callee remain a separate proof, and they are not ownership.

Proposed capability: one reviewed CLI transition from a current FUNCTION claim
to an existing header LIBRARY name/symbol. Guard the selected row, native
extent, history, and the header path. Preserve size. Clear status. Do not
require a C definition, do not rewrite other rows, and do not infer a raw-link
provider. State in the command help that a LIBRARY row without
`native_identity` is not a resolved callee.

Replay the CLI refusal from Guild:

```
uv run --frozen rebrew library review-native 0x5dea38 \
  .scratch/goal83-client-crt-providers/members/crt0dat.obj \
  --symbol _exit --reason "17-byte PP LIBC crt0dat.obj _exit" \
  --dry-run --json --target Europa1400Gold.exe
```

It exits 2 with `select a library metadata row with a complete positive SIZE`
while the row is FUNCTION and size 17. `rebrew source binding rebind --help`
has no kind argument. Evidence and the scratch selection copy are
`.scratch/goal83-client-crt-providers/`.

### Reviewed reuse of equivalent CMake compile inputs (2026-10-17)

Guild's target-scoped flag adoption changes per-source `COMPILE_FLAGS` from
`/O2 /Gd` to ` /O2 /Gd`. Adding client stub/zlib sources also changes comments
in `flags.make`. CMake makes every object depend on that file, so an otherwise
incremental client link starts recompiling more than 4,400 objects. A scratch
comparison found all 8,895 retained flag/define entries equal after argument
tokenization, with no changed effective arguments. Changed sources and newly
added inputs still need compilation.

Proposed capability: let build inspection export and compare complete normalized
compile commands plus dependency/input hashes, and produce an auditable reuse
plan for unchanged objects after CMake regeneration. Never reuse an object when
the compiler profile, argv, source or header inputs differ. Keep this separate
from byte-match or provider claims.

Evidence: Guild `.scratch/goal84-client-build/gold-flags-before.make` and
`gold-normalized-flag-proof.json`; replay `cmake --build
.scratch/goal83-gold-build-baseline/build --target europa1400gold --parallel 1`
after target-scoped flag regeneration. The reviewed scratch optimization invokes
the generated target makefile with `-o CMakeFiles/europa1400gold.dir/flags.make`
only after proving equivalent retained arguments; ordinary source/dependency
timestamps and new-object builds remain active.

### Stub parameter-name collisions — fixed (2026-10-17)

Gold's generated `fcn_004524e0` used `f` for an unnamed sixth parameter even
though its third parameter was already named `f`, producing MSVC C2040. The
same problem affects names declared later in a signature. `ensure_param_names`
now reserves identifiers from the complete parameter list and allocates an
unused suffixed name. Three regressions fail on the old implementation and
pass with the fix: `pytest tests/test_gen_stubs.py -k
generated_names_do_not_collide`. Native replay: generate the Gold scaffold
from Guild `.scratch/goal84-client-build/gold-stub-input.log` and compile
`stubs/gold/symbol_stubs.c` with the PP `/ML` profile.

### Naked assembly guard bypass in lint (2026-10-17)

Concrete failure: a `REBREW_ALLOW_NAKED` source token or metadata compile flag
suppressed E023 for an entire file, including an unrelated naked byte dump.
This is a compilation choice, not evidence that the original source used assembly.
Fixed in `lint.py`: neither source guards nor compiler flags exempt whole-function
reconstructions. Three regression cases cover metadata flags, a fenced body and
an unrelated guard; the existing minor-padding checks still apply.
Replay: `uv run --frozen pytest tests/test_lint.py -k E023`.

A future reviewed exception for a genuinely original naked routine should use
current definition-hashed, target-scoped `source document-assembly` evidence,
never a global build switch or merely a failed C matching search. Current
reviewed inline assembly already uses those receipts. Do not infer padding or
original source absence from a linked gap: compilation, selected link inputs,
archive-member extraction and linker-discarded contributions are separate facts.

### Imported IAT slots reported as missing built bytes (2026-10-17)

Gold and TL `verify --data` printed MISSING for
`__imp__LeaveCriticalSection@4` and `__imp__EnterCriticalSection@4`, although
both APIs were in each built PE and map. Metadata already correctly identifies
these as `storage_kind = import`, not C storage or static library bodies.
`parse_link_map` correctly excludes DLL records for ownership, but the data
placement caller reused that filtered result and lost their linked addresses.
Fixed with an opt-in import-inclusive map view for placement; ownership callers
keep the excluding default. The byte compare remains at reference VAs, while
terminal diagnostics name a known displaced slot and both addresses. It does
not treat import-name agreement as byte equality or credit native placement.
Replay: `uv run --frozen pytest tests/test_data_verify.py tests/test_data_ownership.py tests/test_verify_extended.py`.

### Image-only verify unnecessarily compiled the entire project (2026-10-17)

`rebrew verify --data` always called `run_batch`, walking thousands of sources,
validating each function's inputs/cache and compiling misses even though the
requested result only needs an existing binary, data metadata and the link map.
It also initialized the compiler runner before reading the image. A faster
runner cannot eliminate that unrelated work, and a built CMake object is not
silently interchangeable with a separately fingerprinted verification object.

Fixed upstream: `--data` / `--whole-binary` select image-only verification unless
`--functions`, `--text`, or a function source/scope is explicitly selected.
A data-only run never calls `run_batch` or the runner preflight, never clears
function caches, and never replaces the whole-function `--compare` baseline.
JSON records `functions_checked = false`. Bare `verify` and text promotion
retain their function checks; `--data --functions` requests the old combined run.
Regression tests fail if the function pipeline, unshare preflight or function
cache/baseline writer is reached by a data-only check.

### Known-binding policy disabled warm verify result caches (2026-10-17)

`prepare_entries` skipped `load_verify_cache` whenever `check_known_bindings`
was true. All Guild targets enable that safety check, so every annotation
entered object extraction/comparison again even when the object cache hit.
The compile cache itself is healthy: the CLI reports 69,890 entries (~200 MiB).
Filesystem blob count is not cache-entry count because small objects live in
SQLite; no hit-rate estimate should be inferred from that blob count.

Fixed: load the result cache and admit a row only if its recorded relocation
bindings still resolve to their recorded addresses in the current catalog.
The public COFF API `binding_evidence_current` shares the operand resolver;
source/compiler/header/context/binary identity checks remain necessary. Legacy
or incomplete evidence misses, and changed, newly resolved or disappeared
symbols miss. Unchanged cached conflicts remain failures, not passes. Tests
exercise a warm hit and rejecting catalog controls; no global metadata hash
is used, so writing STATUS does not invalidate every function.

### Oversized MSVC batches fell back to per-file containers (2026-10-17)

A 4,002-file cohort produced a 36,030-character command, beyond Wine's
32,767-character CreateProcess limit. `compile_batch_objs` now moves overflow
source arguments into a response file, using MS C-runtime quoting and leaving
a readable source on argv because the pinned image wrapper requires one.
If flags themselves overflow, a separate flags response file preserves their
position before that source; no source/flag reordering is assumed harmless.
Small MSVC and POSIX batches retain their argv. Response-file write errors
remain explicit, with no compiler invocation against an absent file.

Mocked stress regressions cover large cohorts, quoting, leading @ filenames,
flag ordering and write failure. A bounded two-source PP probe produces
identical objects through direct argv and the response-file path. No library
was patched and no full client rebuild was used to claim this result.

### Retired providers block reference binding (2026-10-17)

After rebinding Gold's lookup to the shared client C translation unit,
`source rename fcn_005a8600 GOLD.0x005a8600 --dry-run --json` still rejected
the old, explicitly retired definition. Source selection already excludes
that historical-only translation unit, but reference binding scanned it as
an active provider. Ignore historical-only source files in this operation;
preserve headers and files retained by any function, data or support binding.
Do not rewrite the retired text. Regression tests exercise preview/apply and
a file retained by another target: `pytest tests/test_rename.py -k
reference_binding_leaves_retired_sources_unchanged`.

### Private static data placement through selected COFF operands (2026-10-17)

Guild's zlib `inflate_trees_fixed` matches 46 native bytes and references four
private static objects totalling 4,360 bytes on both clients. Those objects
also match the current raw builds, but MSVC's maps list the public helper and
omit `_fixed_bl`, `_fixed_bd`, `_fixed_tl` and `_fixed_td`. Image-only data
verification correctly finds no named placement and reports drift at the
reference addresses; it cannot show the actual displaced private objects.

A bounded experiment uses the existing COFF/map/PE APIs: require a unique
selected public helper, compare its complete encoding with all COFF operands
applied, derive the private DIR32 targets, check their source-defined extents
and complete payloads, and reject shifted data. Evidence and replay:
Guild `.scratch/goal90-fixed-trees/prove-raw-data.py` and `raw-data-proof.json`.

Proposed capability: an admitted source-object/link-input manifest can supply
these scoped private symbols to placement analysis. Preserve source/TU and
compile-input identity; reject conflicting sites, ambiguous providers, changed
encodings and missing objects. Do not scan for equal bytes, create public
replacement globals, fabricate map rows or start compilation from image-only
verification. The local proof does not record a data-verification verdict or
establish native placement/original archive selection.

### Relative metadata roots reused another project's path (2026-10-17)

Final-suite onboarding reruns redocumented two existing stubs when earlier
in-process commands had cached `load_metadata(Path("."))` under a different
working directory. `_resolved_metadata_path` keyed its memo by the raw directory
spelling, so a chdir could keep reading that previous project's store. This is
a correctness bug, not a reason to disable metadata caching.

Fixed by making the memo key absolute before the expensive, still-memoized
symlink resolution. Two deterministic regressions create different stores and
switch working directories using both `.` and a relative subdirectory. Both
read the previous project's value before the fix and the current one after it.
Replay: `uv run --frozen pytest tests/test_metadata_hotpaths.py tests/test_onboarding.py`.

## Extend comparison scaffolds from actual COFF references (2026-10-18)

Selecting an existing shared source provider can introduce a few undefined data
symbols after the saved unresolved-link log. `build symbol-stubs` accepts linker
logs but no explicit COFF/symbol input or preserving append. Regenerating the
whole existing scaffold can alter unrelated inferred signatures; inventing new
LNK2001 lines would falsify evidence. A reusable explicit-symbol/COFF input and
reviewed preserving refresh could consume real references and declarations while
keeping known library providers excluded. Current bounded use composes public
`generate_stubs` and `collect_extern_info` to append four generated definitions;
no custom parser or canonical owner store. Evidence and replay:
`guild-rebrew/stubs/gold/source-closure.json`, `stubs/README.md`, and
`.scratch/goal91-sound-wrapper/callee-proof.json`. These remain comparison
placeholders, never recovered allocations.

## Select a reviewed set of source files in one verify batch (2026-10-18)

A shared-signature/provider repair spans seven files and13 bound client contexts.
CLI verify accepts one file or a whole directory; repeatedly invoking it pays a
full catalog scan per file. A repeatable selected-file option could scope cached
results, size audits and STATUS writes through the same batch pipeline, rejecting
empty or mistyped selections. Current bounded composition reuses public
prepare_entries, run_verification and apply_status_updates with exact expected VA
sets; it writes no parallel status store. Evidence/replay: guild-rebrew
`.scratch/goal93-shared-sound-control/verify-selected.py`. Keep unrelated cache
rows and library-provider filtering intact in any eventual CLI extension.

## Phase comparison-stub retirement with provider reconfiguration (2026-10-18)

Rebinding three Gold identities to existing shared C definitions changes the next
configured source list, but the active frozen Make tree still needs its three
comparison definitions. Removing those stubs immediately breaks the pending
link; retaining them after reconfigure creates duplicate providers. A preview
could compare selected COFF public definitions against comparison definitions,
then stage digest-guarded retirement together with an explicit configure/build
transition. Source or metadata presence alone must not establish an emitted
provider. Never mutate the inputs of a live build automatically.

Concrete evidence: guild-rebrew `.scratch/goal100-video-lookups/scaffold-cutover.json`,
`selection.json` and `baseline.json`; shared lookup/release C providers replace
Gold comparison names fcn_0041f5f0, fcn_0041f9b0 and fcn_0041f9d0. The current
manual phased operation uses the public C AST and hash guards, without adding a
second verifier or provider store.

The same phased preview should cover newly introduced COFF data references.
Goal105's recovered Gold initializer needs g_10405e0; its six writes require24
bytes in a comparison scaffold, while the native allocation extent and owner
remain unknown. Composition through public generate_stubs and the C AST stages
that explicit comparison capacity alongside Goal100's three omissions without
editing the live input. Keep comparison capacity separate from managed native
size/ownership. Replay: guild-rebrew `.scratch/goal105-color-init/stage-scaffold.py`.

## Honor sibling maps and missing text-placement failures (2026-10-18)

Problem: `rebrew build check-text-placement --built <isolated client.exe>`
ignored the nonempty sibling MSVC map and looked for objects under the default
project build directory, then fell back to PE exports. Guild's nonexporting
clients reported Gold4558 and TL4988 functions missing and exited 0. The maps
actually identify Gold4557 and TL4988 expected functions, all displaced.
`verify --text` already preferred maps, but also allowed missing functions to
pass its gate when no function was misplaced.

Fixed: sibling maps take precedence in the standalone command. Both placement
paths share parsed function-name conversion, preserving decorations and excluding
data rows. A present empty map remains authoritative. Missing expected functions
now fail both gates, including all-missing output. No layout, artifact bytes or
metadata verdict is inferred from the map change. The existing no-map object
walk remains an estimate; this repair does not prove linker retention from
compilation alone.

Evidence: guild-rebrew `.scratch/goal106-client-cutover/{UPSTREAM-GAP.md,
gold-before-text.json,tl-before-text.json}` and Goal107 regression/replay logs.
Seven assertions fail before the fix. Regression coverage includes a nonexporting
PE plus a sibling map in another directory, authoritative empty/drifted maps,
no-map all-missing failure, decorated names and verify's missing-function gate.
Final review also reproduced a corrupt image hidden by a valid map. Image
validation still precedes map lookup; that regression is covered separately.
Replay: `rebrew build check-text-placement --built .scratch/goal106-client-cutover/completed-before-configure/Europa1400Gold_TL.exe --json --target Europa1400Gold_TL.exe`.


### CMake ignored the selected native unshare runtime (2026-10-18)

Guild already selected `compiler.execution_backend = "unshare"`, but the
CMake CL/LINK/LIB bridge always launched Docker and serialized on its shared
Wine prefix. The project setting now dispatches all three tools through the
existing immutable-image native runner, retaining absolute source paths,
nested build cwd, rewritten response files, image INCLUDE/LIB and clock pinning.
The native helper accepts one same-path writable project mount while rejecting
runtime mount overlap; external include mounts remain read-only. Failure never
falls back to Docker. Explicit Docker/Podman selection also reaches prefix
initialization and timeout cleanup. Existing generated toolchains still work.

CMake carries profile pins, not Rebrew target identities. A future target-scoped
backend capability must carry that identity in generated compile/link rules;
this change honors the project-level setting and does not guess a target from
an ambiguous shared profile. Object-cache reuse is a separate capability.
Replay: `uv run --frozen pytest tests/test_cmake_tc.py tests/test_unshare.py`.
Project smoke evidence: Guild `.scratch/goal109-unshare-runtime/`.


### Native unshare repeated Wine first-time setup on every compile (2026-10-18)

The admitted MSVC images have an empty `/opt/wineprefix`. A private overlay is
correct for isolation, but it repeated wineboot/registry setup for every CL,
LINK and LIB invocation. Guild full builds exposed dozens of concurrent
`InstallHinfSection` processes and poor throughput. The old rootfs extractor
also replaced archive timestamps with extraction time.

Fixed: timestamp-preserving extraction and a versioned image cache with a Wine
prefix initialized once through the native namespace helper. Initialization
uses the existing writable `/work` mount and waits for wineserver shutdown;
the runtime-state bind guard remains unchanged. Each compiler still receives
its own writable overlay, and seed preparation rejects paths escaping the
owned prepared image. Old image-cache directories remain intact for active
runs. Failed preparation is not published and there is no Docker fallback.
The cached prefix is runtime setup, not a patched compiler or archive.

Regression coverage checks timestamp fidelity, native seed argv, failure
cleanup and an escaping symlink. Existing native isolation and explicit
one-second timeout/descendant tests remain. Normal success-fixture timeout is
20s: a traced static probe exited immediately, but host namespace teardown
waited more than 5s in `exit_group` under concurrent Wine loads.
Replay: `uv run --frozen pytest tests/test_unshare.py tests/test_cmake_tc.py`.
Guild `.scratch/goal110-full-runs/compile-equivalence.json` checks complete
Gold `/ML` and TL `/MT` COFF equality across Docker and the seeded native runner.


### Generated runtime guidance still claimed Docker-only execution (2026-10-18)

The MSVC init constraints and workflow skill still said Docker-only after native
unshare support, and the packaged principles still named retired external build
hooks. Its inventory note also hard-coded a path despite configured overrides.
Update the packaged owners, regenerate checked-in skills, and refresh
projects rather than patching generated copies. Compiler profiles still identify
immutable image filesystems; the configured supported backend selects execution.
Replay: `uv run --frozen pytest tests/test_init.py tests/test_skills_sync.py`, then
`rebrew init --refresh-agents` and `rebrew init --check` in the project.


### Verify no-cache help overstated compiler cache bypass (2026-10-18)

The flag bypasses saved verification verdicts in `prepare_entries`;
`run_verification` still obtains the compiler-object cache. Help and generated
guidance incorrectly promised recompiling every function. Clarify the two layers
without changing execution or clearing caches. A CLI contract regression rejects
the old wording and requires both cache layers to be explicit. Replay:
`uv run --frozen pytest tests/test_cli_contract.py -k no_cache_help_distinguishes`.


### README status graphic from canonical reports (2026-10-18)

Guild's retired progress renderer queried an obsolete coverage database and counted
PROVEN as a byte match. The current CLI has canonical multi-target status JSON
but no README SVG export (`coverage --help` and `coverage report --help`).
A reusable renderer should consume that report, separate EXACT/RELOC C and naked
assembly counts, exclude library/PROVEN verdicts from C recovery, and show raw-file
agreement separately with a snapshot date. Guild now uses only CLI JSON in its
small presentation script; it performs no metadata parsing or verification.
Replay: `rebrew status --all-targets --json | python3 scripts/progress_svg.py`.


### Consider consolidating source provenance stores (2026-10-18)

The Guild user questioned the extra `rebrew-source.toml` beside function/data/type
stores. Its current 61 target-scoped assembly records include addressless helpers,
and its support-file records include headers; moving everything onto VA-keyed
function rows would lose those identities. Consider whether a unified schema or
a coordinated file/definition section in an existing store can reduce maintenance
without duplicating evidence. Any migration must preserve hashes, target scopes,
rename behavior, support purposes, locked atomic writes and stale-evidence lint.
Current readers: `metadata/source_provenance.py`; inspect Guild source metadata
with `rebrew source document-assembly --help`. Implemented in 5.0 by format-3 function `[source]` sections and digest-guarded `source consolidate`.


### Preserve accepted toolchain inputs when upstream removes archives (2026-10-18)

`recompile-toolchains/base-dosemu/Dockerfile` pins two fd35 Debian packages
whose Launchpad files now return 404. Native smoke failed before this dependency
refresh (run `38723898730`) and still fails in run `39102305256`; changing the
version or hash would change the accepted native inputs, not repair availability.
Keep a durable content-addressed mirror for admitted inputs, verifying the
original hashes before recording another URL. Cache extraction may recover the
accepted bytes; rebuilding a similarly named package is not equivalent.

The missing files are `libfdldr35` (librarian `876268288`, SHA-256
`a250e93e6d323d208a7cc2a998bcd03e9510831bf670d2da94eb5f2b6820f49d`) and
`libfdpp35` (`876268289`,
`1baec8711043c75d1e29a4f260e926cb7343c9cc484f8c053970e0e0a7000a2a`), version
`1.11-10003-1714-6fc57bc+202609081621~ubuntu24.04.1`. Launchpad publications
`249343552` and `249343554` record removal on 2026-09-27. Replay the Dockerfile's
URLs with `curl -fIL`, then run `make smoke` in the toolchain repository.
The MSVC server walkthrough uses its separate base image.


### Generated project rules require editable tooling (2026-10-18)

Rebrew 5.0's `AGENTS.md.template` says to use editable canonical Rebrew/Recoverage
checkouts, contradicting normal project environments pinned to released wheels.
Refreshing instructions across 45 projects retained that generated requirement;
the projects must not acquire sibling development checkouts just to run tooling.
Default generated guidance to released packages in the project's pinned
environment and reserve editable checkouts for explicit tooling development.
The generated-output regression rejects the old requirement. Replay:
`make test-one T=tests/test_init.py::TestInit::test_creates_agents_md`.


### LIEF enum diagnostics for valid GNU SFrame ELF headers (2026-10-18)

Public Rebrew 5.1.0 with LIEF 1.0.0 loads a modern GNU-built `/bin/true`
successfully but emits two `RuntimeWarning`s from `_load_elf` in
`src/rebrew/formats/binary_loader.py`. The values are legitimate
`PT_GNU_SFRAME` (`1685382484`, `0x6474e554`) and `SHT_GNU_SFRAME`
(`1879048180`, `0x6ffffff4`), both recognized by the host's `readelf`;
`/usr/include/elf.h` also defines `PT_GNU_SFRAME`. LIEF's enum bindings omit these names; reading
`Segment.type` or `Section.type` returns the exact integer while warning that
it "is not a valid TYPE." The image base, sections and code region still load;
strict warnings-as-errors can instead make the binding raise `SystemError`
with the `RuntimeWarning` as its cause.

LIEF 1.0.0 is the latest published stable release in
[PyPI metadata](https://pypi.org/pypi/lief/json) at this observation. Its
[public ELF API](https://lief.re/doc/latest/formats/elf/python.html) exposes
no integer `raw_type` accessor for segments or sections. `TYPE.from_value`
warns and rejects these integers, and `lief.to_json` renders their type as
`UNKNOWN`, losing the numeric identity. Preserve the existing raw values;
do not add a parallel ELF parser, global warning filter or patched native
library to silence the diagnostics. An upstream LIEF enum addition, together
with a public raw integer accessor for future unknown types, would allow
Rebrew to classify headers without misleading warnings. When available in a
published dependency, cover both GNU SFrame types and another unknown numeric
type, preserve `PT_LOAD` selection and zero file size for `SHT_NOBITS`, and
assert that unrelated warnings remain visible.

Replay on an ELF containing GNU SFrame headers (`/bin/true` on the observed host;
SHA-256 `1573301c316fd6297e2352441a9fb42eca9c32f97b3bb7ae1d45d3362811234d`):

```sh
readelf -lW /bin/true
readelf -SW /bin/true
uv run --frozen python -W always::RuntimeWarning -c \
  'from rebrew.formats.binary_loader import load_binary; print(load_binary("/bin/true").format)'
```


### Lint help described both stores as format 2 — fixed (2026-10-18)

Public Rebrew 5.1.0's `lint --help` still said all identity/state used format-2
metadata after function metadata moved to format 3. The help now distinguishes
format-3 function metadata from format-2 data metadata. A rendered umbrella CLI
help regression checks both descriptions against the writers' schema constants;
the schemas and runtime behavior are unchanged. Replay:
`make test-one T=tests/test_cli_help_copy.py::TestHelpCopy::test_lint_help_names_current_function_and_data_formats`.


### Todo suggested unsupported unshare linked comparison — fixed on main (2026-10-18)

Released Rebrew 5.1.0 suggests `test --linked` for RELOC and postlink work even
when the selected target uses `execution_backend = "unshare"`; the compiler
explicitly rejects that linked runner. Main now preserves those work rows but
suggests `verify --text --raw-link` only when the configured raw image exists,
with an explicit quoted `--built` path and selected `--target`. Without that
image the row explains the prerequisite and carries no command. Docker and
Podman suggestions stay unchanged. This does not implement unshare linked
comparison or claim the raw image is identical; verification must establish it.
The 5.1.0 artifacts remain unchanged. Replay:
`make test-one T=tests/test_todo.py::TestCollectAllIntegration`.

### Generated principles described all metadata as format 2 (2026-10-18)

The packaged `PRINCIPLES.md` still claimed that identity and state use format-2
metadata after function/source metadata moved to format 3. A project with the
correct version-neutral wording therefore received W033, and refreshing would
restore the false instruction. The template now refers to managed metadata
without conflating the two formats. A scaffold-refresh regression test rejects
the stale claim; existing drift checks remain unchanged. Replay:
`make test-one T=tests/test_init.py::TestRefreshAgents::test_refresh_writes_skills_and_principles`.

### Source fixtures could overwrite an ancestor project catalog (2026-10-19)

`write_source` preferred a discovered project over its pytest fixture boundary.
With a custom `--basetemp` beneath a real project, lint fixtures changed real
function identities and could retain unrelated earned verdicts. The fixture
helper now respects the session temporary root and rejects projects above its
fixture boundary, while accepting projects created inside it. Regression tests
cover default/custom temporary paths and an inner fixture project. Affected
catalog rows were restored from their prior records through the locked owner;
no replacement verdict was earned. Replay:
`make test-one T=tests/test_source_fixture_writes.py`.
### Temporary layout probes conflict with unshare's private /tmp (2026-10-19)

`rebrew types bind d3.animation-options ... --target Europa1400Gold_TL.exe`
failed with `unsupported/invalid extra mount overlaps runtime mount`. The
generated probe was compiled in place under `/tmp/rebrew-types-*`, making the
compiler request a same-path source mount beneath the runner's private `/tmp`.
Keep the generated source and object workdir separate; its absolute project
header remains served by the existing project mount. Preserve the runner's
mount restrictions. The type-probe regression checks this boundary, and the
real replay validates sizeof 12 and offsets 0/1/2/9 in both client profiles.
### Paging property model accepted non-API numeric syntax (2026-10-19)

The full suite found `raw='1\x85'`: Python `int` accepts the C1 whitespace,
while dashboard paging deliberately accepts only ASCII decimal syntax and
ASCII surrounding whitespace. Keep that API boundary and align the independent
integer model with its documented grammar, pinning C1 whitespace, plus signs,
underscores and Unicode digits as rejected examples. A long leading-zero
prefix then exposed a real bug: 100 zeros followed by 1 incorrectly clamped to
the page maximum. Strip leading zeros before the bounded integer conversion;
preserve fallback/clamping behavior for genuinely large or negative values.

## Ghidra MCP analysis and headless BinSync relay (2026-10-19)

Problem: Rebrew 5.1.0 accepts only `ghidra_backend = "reva" | "cli"`;
bethington/ghidra-mcp exposes a different live-analysis API. A BinSync export
is not itself an import into Ghidra, and a headless MCP process must not be
assumed to run the GUI BinSync integration. Users need a documented, tested
path without creating a competing metadata writer.

Proposed capability: document the separate analysis connection first; if a
structural adapter is needed, add an explicit backend with program/hash guards
and fixture tests for function creation, bookmarks and data-label queries.
Keep field exchange BinSync-primary. Document or implement a tested headless
state relay separately; never treat it as implicit in `sync push`.

Evidence: installed `config.py` restricts `ghidra_backend` to `reva`/`cli`.
Replay `rebrew sync --help` and `rebrew doctor --target Europa1400Gold_TL.exe
--json`; the Guild client has neither a program path nor a state directory.
The community Dockerfile at commit `181935f64a2a754c468420503ef7b57bbe27f64b`
checks out MCP `main`, pins Ghidra 12.1.3 and expects a locally built bridge
image. Do not transplant it as a reproducible supported deployment. Upstream
reference: https://github.com/bethington/ghidra-mcp .

Follow-up trial: both MCP 6.0.0 and REA 6.7.0 need a reviewed entry seed for
TL 0x4b6f00; both return 216 bytes after seeding, but their pseudocode drops the
x87 expression around __ftol. Preserve native ABI/operand checks. Rebrew's
BinSync preview also reports 159 ambiguous private struct names (first header/
source wins) and truncates D3_ANIMATION_OPTIONS before its bitfields despite a
managed, compiled 12-byte binding. Before a bulk headless relay, offer a
reviewed target/context-safe export using canonical type bindings and explicit
unresolved/ambiguous types; do not silently promote partial/first-wins layouts.
Reports: Guild .scratch/ghidra-mcp-trial and .scratch/rea-trial.

### Doctor reported Docker instead of the configured backend (2026-10-19)

The live Guild trial selected unshare but `doctor` reported a Docker runner
without checking namespace admission. All image checks also ignored an explicit
Podman override and inspected the default runtime's image store. Reuse the
configured frontend for image checks, label the selected runner, and run the
existing unshare namespace probe before reporting readiness. No host Wine
fallback is introduced. Replay `pytest tests/test_doctor.py::TestConfiguredRunner`.
