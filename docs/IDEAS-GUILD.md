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
