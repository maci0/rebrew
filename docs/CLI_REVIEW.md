# CLI surface review

Review the complete CLI for simpler discovery, consistent options, and clear
operation boundaries. The original 2026-10-03 baseline had: **103 top-level
entries, 150 routes including the root and groups, and 139 distinct callbacks**.
All 150 help and 150 version invocations returned exit 0. Third-party extension APIs remain
subject to the existing [component registration contract](CLI.md#component-registration-plugins).

The recommendations are implemented in the current worktree: **33 root entries
and 196 routes including groups and the root**. The accepted decision is
[ADR 028](adr/028-cli-domains-and-explicit-operations.md); see
[CLI_MIGRATION.md](CLI_MIGRATION.md) for old-to-new routes and mode flags, and
[CLI.md](CLI.md) for the current API. The complete route review below records
the original baseline and its disposition. Validation results are recorded
in the verification section below.

- [Review method and limits](#review-method-and-limits)
- [Priority changes](#priority-changes)
- [Implemented organization](#implemented-organization)
- [Option and behavior contracts](#option-and-behavior-contracts)
- [Complete route review](#complete-route-review)
- [Verification and migration gates](#verification-and-migration-gates)

## Review method and limits

Enumerated the composed Typer/Click command tree recursively, inspected each
route's arguments, options, defaults, help, callback signature, and routing calls,
and traced the overlapping/mode-heavy operations through their source owners.
Callback identity was checked after unwrapping the shared global-option wrapper.
This matters: filenames/line numbers on a wrapper are not reliable evidence that
two commands share an implementation.

The review evaluates the public surface and logical structure. Help success does
not prove compilation, remote services, mutation safety, or the output of every
command against a real project. No project mutation, upload, Git push, image
build, or toolchain download was run to collect the inventory. Existing focused
CLI and owner tests provide the behavioral evidence described below.

## Priority changes

| Priority | Finding | Recommended change | Evidence / constraints |
|---|---|---|---|
| 1 | The root has 103 entries across broad panels. | Keep the daily workflow near the root and put specialized operations under domain groups. | Every route has a destination/disposition in the table below; moving a name alone is not a reason to merge implementations. |
| 1 | BinSync exposes flat and grouped routes for the same callbacks. | Remove the flat init/diff/overlay routes; move raw export/import under binsync. | Init/diff/overlay are exact callback duplicates. Push/pull have different Git defaults and options from raw export/import, so preserve both operation types. |
| 1 | data combines inventory, metadata writes, declarations, BSS, and linked layout repair. | Separate list/set/dispatch/bss/header/layout operations. | Its callback has 31 non-global options and dispatches distinct storage owners. Preserve provenance, locked writers, raw-link evidence, and preview paths. |
| 1 | match combines single GA, batch GA, flag/profile search, and run history. | Use named run/batch/flags/toolchains/history operations and put climb/qualifiers/partitions beside them. | Its callback has 50 non-global options. A --toolchain spelling currently selects a comma-separated sweep, unlike test's single profile override. |
| 1 | Build-tool protocol adapters now live under the ordinary CLI. | Preserve their argument boundaries and generated callers when changing the layout. | [ADR 027](adr/027-build-hooks-under-umbrella.md) records the single-executable migration and required regeneration. Compiler flags after -- must remain raw argv; an executable plus arguments is not one executable name containing spaces. |
| 2 | Project selection, function selection, and artifact selection use similar words for different things. | Specify common contracts, then use shared selectors where the semantics match. | Do not equate a raw .bin comparison slice with an original executable, or a library-list root positional with project --root selection. |
| 2 | diagnose explains configuration while near-diag/drift/gap-trace/stack-cmp explain byte mismatches. | Group them under diagnose with descriptive operation names. | Keep distinct analyses and reports; share selection/compilation plumbing rather than build a new diagnostic framework. |
| 2 | Several readers hide writes behind mode flags. | Prefer explicit action names when restructuring these families. | imports --mark, pdb-info --write-cflags, orphans --prune, cfg detect-crt --write, and types' default check need clear operation boundaries. Do not add blanket confirmation prompts. |
| 2 | decompile/recover-structs use --decompiler; skeleton uses --decomp-backend. | Choose one backend-option spelling in a documented breaking release. | Default backends differ intentionally; a spelling cleanup must not silently change those defaults. |
| 3 | refactor scans Python files but requires a reversing-project config. | Move it to a contributor-only surface or remove it if there is no project-facing use. | It is not a C-source refactoring operation; do not rename it as though it were. |

Implemented in this review: qualifier sweeps now offer **--jobs/-j**, and the
shared option contract checks include **group callbacks and nested commands**.
The old enumeration omitted orphans' default action and types' default check.
Cross-target imports now reject negative --limit values, and batch extraction
rejects negative COUNT/--start before creating output artifacts. Zero keeps
its existing meaning; these checks use the shared non-negative validator.

## Implemented organization

Keep init, intake, doctor, status, todo, recommend, skeleton, decompile, lint,
test, verify, diff, and prove directly discoverable. Existing small groups such
as cache, skills, blocker, toolchain, and cfg are already coherent.

| Family | Responsibility | Deliberate separation |
|---|---|---|
| match | GA, deterministic searches, flag/profile sweeps, history | Search algorithm versus batch selection versus read-only history. |
| data | Global inventory, metadata edits, type/header output, layout work | Declarations/users are not storage owners; views are not extra allocations. |
| source | Rename, split/merge, sanitization, source imports, source analysis | Metadata identity and compiler-sensitive declaration ordering survive transformations. |
| binary | Binary/function inspection, discovery, extraction, format resources | Optional project fallback versus standalone input; inspection versus artifact output. |
| diagnose | Configuration explanation and mismatch localization | Configuration resolution, measurement, stack shape, region drift, and length-gap analysis remain distinct. |
| build | CMake exports/drivers, link layout, stubs, postlinking, artifact checks | Build-tool protocol adapters do not consume ordinary workflow flags after their forwarding boundary. |
| library | Override declarations, archive/CRT identification, signatures | Override configuration, source matching, archive bytes, and FLIRT evidence have different owners. |
| coverage | Catalog validation, coverage documents, static reports, serving | Validation, persistence, export, and a read-only HTTP server remain different actions. |
| similarity | Function and whole-binary structural comparisons | Comparison suggestions do not imply accepted field or source imports. |
| export | C context/symbol artifacts, objdiff configuration, decomp.me upload | Local artifact generation versus remote emission; upload provenance is retained. |
| binsync | Raw state artifacts and Git-aware synchronization | Export/import versus push/pull; neither preview nor failure advances reconciliation baselines. |

Do not create a generic dispatcher, new plugin framework, or aliases for every
old spelling. Reuse the existing component and Typer composition mechanisms.
Any adopted renames are breaking changes: update commands, skills, examples,
generators, tests, and migration notes together.

## Option and behavior contracts

- Keep --json before --target in callback signatures, with the shared target
  option and documented all-target behavior. Global version/verbosity flags
  should work at every depth; raw build argv after -- remains raw argv.
- Keep --output/-o for a destination path and --jobs/-j for parallelism.
  Specify whether an output is a file or directory. Unify --out-dir only after
  checking how each command uses the destination; it is not an input filter.
- Prefer a common --limit for displayed/imported result caps when renaming a
  family, but retain --depth for graph traversal. State each command's zero
  behavior explicitly: zero-as-unlimited is not the same as zero rows.
- Standardize whole-binary overrides separately from raw-byte inputs.
  asm --bin and test --target-bin are raw blobs; they should not be relabeled
  as interchangeable original executable paths.
- Standardize source/function reference selection through existing helpers
  where possible. VA selection in a multi-function C file differs from a
  standalone VA in a binary and from a data allocation identity.
- Use --toolchain for one compiler profile and a plural, explicitly scoped
  selector for a profile search: `match toolchains --toolchains` selects
  profiles. The conflicting sweep aliases are removed.
- Keep explicit preview semantics. import-splat and toolchain update already
  preview by default, whereas source transformations generally require
  --dry-run for preview. Name a writing action instead of assuming every
  command must adopt the same default or another confirmation prompt.
- Preserve exit 0/1/2/130/141 and JSON/stdout separation. Read-only inspection
  does not manufacture STATUS; only byte-comparison owners record byte status.
  prove's semantic evidence remains separate from an EXACT/RELOC byte match.
- Keep test for immediate compile/comparison, verify for incremental/CI gates,
  and prove for semantic equivalence. Document that test --all reuses verify's
  engine but forces recompilation. Their different behavior is useful.
- Prefer shared compilation and selection below the CLI for probe/diff/drift/
  gap/near analysis; a single enormous command is not required to share code.

## Complete route review

Every route in the baseline runtime tree appears once below. The dispositions
record the implemented paths, without compatibility aliases. Groups without a callback are
still reviewed as discovery/ownership boundaries.

| Baseline route (after `rebrew`) | Implemented disposition | Reason / preserved distinction | Source owner |
|---|---|---|---|
| `rebrew` | Keep one executable | Use workflow groups to reduce the 103-entry landing page; keep third-party registration on the component graph. | [main.py](../src/rebrew/main.py) |
| `rename` | source rename | Keep rename propagation and canonical metadata writes; do not reduce it to text substitution. | [rename.py](../src/rebrew/rename.py) |
| `test` | Keep test | Immediate compile/comparison and earned STATUS recording; keep raw-byte and linked comparison inputs distinct. | [test.py](../src/rebrew/test.py) |
| `verify` | Keep verify | Incremental project/CI verification and regression baselines; separate advanced linked/data scopes in help. | [verify.py](../src/rebrew/verify.py) |
| `skeleton` | Keep skeleton | The normal source-creation entry; retain append, batch, and optional decompilation distinctions. | [skeleton.py](../src/rebrew/skeleton.py) |
| `sync` | Keep sync; split its operations | Expose named field-sync and MCP structural operations; preserve their different state and transport owners. | [cli.py](../src/rebrew/ghidra/cli.py) |
| `lint` | Keep lint | A daily validation command; keep explicit fixing separate from the default check. | [lint.py](../src/rebrew/lint.py) |
| `migrate-markers` | source migrate-markers | An explicit format migration; keep dry-run and locked metadata APIs. | [migrate_markers.py](../src/rebrew/migrate_markers.py) |
| `fix` | source fix | Decompiler-output sanitization is different from lint fixing; make the output file clear. | [fixup.py](../src/rebrew/fixup.py) |
| `recover-structs` | types recover | Type recovery belongs with type checking/application; keep inference separate from source writes. | [struct_recover.py](../src/rebrew/struct_recover.py) |
| `decompile` | Keep decompile | Useful daily operation; use the same backend-option spelling as skeleton and type recovery. | [name_decomp.py](../src/rebrew/name_decomp.py) |
| `match` | match run / batch / flags / toolchains / history | Split mutually scoped algorithms and reporting from the 50-option command; retain shared matcher primitives. | [match.py](../src/rebrew/match.py) |
| `diff` | Keep diff | Readable byte/disassembly comparison; do not merge its output with STATUS recording. | [diff.py](../src/rebrew/diff.py) |
| `postlink` | build postlink | Mutates a built artifact; retain distinct reference/output paths and dry-run. | [postlink.py](../src/rebrew/postlink.py) |
| `stack-cmp` | diagnose stack | A specialized byte-mismatch explanation, rather than another top-level workflow. | [stack_cmp.py](../src/rebrew/stack_cmp.py) |
| `asm` | binary asm | Keep hex/NASM/CFG output formats; move batch extraction modes behind named operations. | [asm.py](../src/rebrew/asm.py) |
| `switch` | binary switches | Jump-table decoding is binary inspection; preserve its VA/window and all-functions scopes. | [switch.py](../src/rebrew/switch.py) |
| `init` | Keep init | Project creation and idempotent scaffold refresh/check remain one cohesive lifecycle command; optional runner setup is available as toolchain install-wibo. | [init.py](../src/rebrew/init.py) |
| `intake` | Keep intake | The onboarding orchestrator adds value over manually chaining init, detection, discovery, and documentation. | [intake.py](../src/rebrew/intake.py) |
| `gen-layout` | build layout | Linker layout generation belongs with build reconstruction; preserve reference-derived ownership evidence. | [gen_layout.py](../src/rebrew/gen_layout.py) |
| `cmake-toolchain` | build cmake-toolchain | Generate configuration for CMake; do not conflate this with the raw compiler driver. | [cmake_tc.py](../src/rebrew/cmake_tc.py) |
| `cmake-driver` | build driver | Build-tool protocol adapter; preserve the mode argument and -- forwarding boundary. | [cmake_tc.py](../src/rebrew/cmake_tc.py) |
| `objdiff-build` | build objdiff-driver | Build-tool protocol adapter; keep it out of the ordinary reversing quick path. | [objdiff_project.py](../src/rebrew/objdiff_project.py) |
| `cmake-flags` | build cmake-flags | Per-file flag export differs from source-list export; retain separate output artifacts. | [cmake_flags.py](../src/rebrew/cmake_flags.py) |
| `cmake-sources` | build cmake-sources | Target-filtered source selection; preserve target scoping and external-library inputs. | [cmake_sources.py](../src/rebrew/cmake_sources.py) |
| `build-check` | build check | Checks generated-build drift; distinguish this from verifying reversed machine code. | [build_check.py](../src/rebrew/build_check.py) |
| `order-sources` | build order-sources | Produces VA ordering; link-order applies/checks that ordering in CMake, so keep both operations. | [order_sources.py](../src/rebrew/order_sources.py) |
| `calibrate-bss` | build calibrate-bss | Compile/link calibration is a write operation; preserve explicit raw-link and pad constraints. | [calibrate_bss.py](../src/rebrew/calibrate_bss.py) |
| `gen-link-stubs` | build link-stubs | Data/BSS placeholders differ from unresolved-symbol stubs; make storage ownership restrictions visible. | [gen_link_stubs.py](../src/rebrew/gen_link_stubs.py) |
| `gen-stubs` | build symbol-stubs | Resolves linker failures; keep library exclusion and generated-storage safety. | [gen_stubs.py](../src/rebrew/gen_stubs.py) |
| `inline-strings` | source inline-strings | Source rewriting with a reference binary; unify source selection before renaming options. | [inline_strings.py](../src/rebrew/inline_strings.py) |
| `verify-placement` | build check-data-placement | Checks addresses and ownership, not initialized-data byte equality; retain the distinction. | [verify_placement.py](../src/rebrew/verify_placement.py) |
| `text-audit` | build check-text-placement | Address/layout check; make the relationship to verify --text clear. | [text_audit.py](../src/rebrew/text_audit.py) |
| `link-sweep` | build sweep-link-flags | Linker-option search is separate from compiler/source search; retain raw command forwarding. | [link_sweep.py](../src/rebrew/link_sweep.py) |
| `link-order` | build link-order | An explicit CMake check/apply operation; keep its difference from order-sources output. | [link_order.py](../src/rebrew/link_order.py) |
| `document-unmatched` | source document-unmatched | Creates skeletons and blocker evidence; do not hand-set earned byte-match status. | [document_unmatched.py](../src/rebrew/document_unmatched.py) |
| `pdb-info` | binary pdb show / import-cflags | Inspect compiler evidence separately from importing it into configuration. | [pdb_info.py](../src/rebrew/pdb_info.py) |
| `discover-functions` | binary functions | Standalone binary discovery remains useful outside a configured project. | [discover.py](../src/rebrew/discover.py) |
| `data` | data list / set / dispatch / bss / header / layout | Split inventory, metadata edits, generated declarations, and layout repair; preserve one storage owner per allocation. | [data.py](../src/rebrew/data.py) |
| `graph` | source graph | Project/source dependency analysis; keep optional binary/dispatch edges and CU-map output explicit. | [depgraph.py](../src/rebrew/depgraph.py) |
| `status` | Keep status | Fast progress/accounting view; its different denominators must remain visible. | [status.py](../src/rebrew/status.py) |
| `todo` | Keep todo | Prioritized per-function work; keep it distinct from project-level recommend. | [todo.py](../src/rebrew/todo.py) |
| `unpack-lzexe` | binary unpack-lzexe | Standalone binary transformation; state the output path and overwrite behavior. | [lzexe_cli.py](../src/rebrew/lzexe_cli.py) |
| `crt-match` | library crt-match | Source cross-reference matching is different evidence from archive-byte or FLIRT matching. | [crt_match.py](../src/rebrew/crt_match.py) |
| `lib-match` | library match | Archive byte comparison; retain configured versus verified stock-library provenance. | [lib_match.py](../src/rebrew/lib_match.py) |
| `imports` | binary imports | Inspection by default; separate optional stub marking from import-table display. | [imports.py](../src/rebrew/imports.py) |
| `fingerprints` | binary fingerprints | Standalone fingerprints are useful; project target is only an optional input fallback. | [fingerprints.py](../src/rebrew/fingerprints.py) |
| `pe-info` | binary pe | Format-specific inspection is intentionally PE-only; do not hide that behind generic binary-info. | [pe_info.py](../src/rebrew/pe_info.py) |
| `crypto-scan` | binary crypto | Binary constants/imports scan; separate it from source security scanning. | [crypto_scan.py](../src/rebrew/crypto_scan.py) |
| `security-scan` | source security | C-source scanning; its input is a directory, unlike binary crypto inspection. | [security_scan.py](../src/rebrew/security_scan.py) |
| `verify-exports` | build check-exports | Built/reference export-table comparison; retain mismatch exit 1. | [verify_exports.py](../src/rebrew/verify_exports.py) |
| `strings` | binary strings | Standalone extraction with optional xrefs; keep VA and string-filter semantics explicit. | [strings.py](../src/rebrew/strings.py) |
| `xrefs` | binary xrefs | Address references and calls-from are different directions; keep their selection readable. | [xrefs.py](../src/rebrew/xrefs.py) |
| `drift` | diagnose drift | Branch/region drift localization; share compilation/selection plumbing rather than collapse its analysis. | [drift_cli.py](../src/rebrew/drift_cli.py) |
| `describe` | binary function | Project-backed function dossier; analyze --function uses the same dossier builder; document configured-project versus standalone inputs. | [describe.py](../src/rebrew/describe.py) |
| `analyze` | binary analyze | Whole-binary dossier; its per-function mode delegates to the shared describe dossier builder. | [analyze.py](../src/rebrew/analyze.py) |
| `report` | coverage report | Static HTML output differs from serving existing coverage snapshots. | [report.py](../src/rebrew/report.py) |
| `diagnose` | diagnose config | Explains toolchain/flag resolution; does not diagnose the machine-code mismatch itself. | [diagnose.py](../src/rebrew/diagnose.py) |
| `flirt` | library scan-signatures | Signature scanning differs from writing identified library headers; initialization uses library init-signatures. | [flirt.py](../src/rebrew/flirt.py) |
| `identify-library` | library identify | Aggregates identification evidence and can write headers; retain dry-run and provenance. | [identify_library.py](../src/rebrew/identify_library.py) |
| `gen-flirt-pat` | library signatures | Signature production from archives is separate from signature scanning. | [gen_flirt_pat.py](../src/rebrew/gen_flirt_pat.py) |
| `doctor` | Keep doctor | Project readiness checks; optional runner installation lives under toolchain install-wibo. | [doctor.py](../src/rebrew/doctor.py) |
| `split` | source split | Preserve metadata identities and source preimages; document its overwrite/backup behavior. | [split.py](../src/rebrew/split.py) |
| `merge` | source merge | Preserve explicit input deletion and declaration-order controls; not just the inverse of textual split. | [merge.py](../src/rebrew/merge.py) |
| `prove` | Keep prove | Semantic equivalence is not earned byte equality; keep PROVEN distinct and non-sticky. | [prove.py](../src/rebrew/prove.py) |
| `solutions` | match solutions | Read-only matcher history/solutions discovery belongs with matching, not binary inspection. | [solutions_db.py](../src/rebrew/solutions_db.py) |
| `round-trip` | build round-trip | Splicing compiled bytes into a target is an artifact operation; preserve its byte-equality gate. | [round_trip.py](../src/rebrew/round_trip.py) |
| `build-db` | coverage build | Coverage document generation; name the artifact rather than imply a generic database. | [build_db.py](../src/rebrew/build_db.py) |
| `dashboard` | coverage serve | Read-only serving of coverage artifacts; keep host/port security and shutdown ownership. | [dashboard.py](../src/rebrew/dashboard.py) |
| `binsync-export` | binsync export | Keep raw export options --git/--clean; push has different Git defaults and cannot replace it unchanged. | [export.py](../src/rebrew/binsync/export.py) |
| `binsync-import` | binsync import | Keep local import independent of git pull; share the existing importer owner. | [importer.py](../src/rebrew/binsync/importer.py) |
| `binsync-diff` | Remove flat route; keep binsync diff | Exact callback duplicate of the grouped route. | [diff.py](../src/rebrew/binsync/diff.py) |
| `binsync-init` | Remove flat route; keep binsync init | Exact callback duplicate of the grouped route. | [init.py](../src/rebrew/binsync/init.py) |
| `binsync-overlay` | Remove flat route; keep binsync overlay | Exact callback duplicate of the grouped route. | [overlay.py](../src/rebrew/binsync/overlay.py) |
| `catalog` | coverage catalog | Annotation/catalog validation differs from rendering coverage documents; keep the artifact boundary clear. | [cli.py](../src/rebrew/catalog/cli.py) |
| `similar` | similarity function | Single-function/submatch/cluster search; separate output modes and retain score semantics. | [similar.py](../src/rebrew/similar.py) |
| `binary-similarity` | similarity binary | Whole-binary comparison needs its own paired input and inventory selection. | [binary_similarity.py](../src/rebrew/binary_similarity.py) |
| `merge-sweep` | match partitions | Translation-unit partition search is distinct from source merge; keep rollback and compile-budget controls. | [merge_sweep.py](../src/rebrew/merge_sweep.py) |
| `climb` | match climb | Deterministic statement search differs from GA; use common function selection and compiler overrides. | [climb.py](../src/rebrew/climb.py) |
| `qual-sweep` | match qualifiers | Qualifier search remains a separate algorithm; -j now matches every other --jobs option. | [qual_sweep.py](../src/rebrew/qual_sweep.py) |
| `cross-import` | source import-related | Imports actual source across targets; keep it distinct from BinSync field overlays. Negative limits now fail with exit 2. | [cross_import.py](../src/rebrew/cross_import.py) |
| `probe` | diagnose probe | Measurement without metadata writes; reuse compilation logic with test --no-promote while preserving evidence inputs. | [probe.py](../src/rebrew/probe.py) |
| `residue` | build residue | Linked whole-artifact residue/baseline measurement; not the same as one-function diff. | [residue.py](../src/rebrew/residue.py) |
| `near-diag` | diagnose near | Byte mismatch classification and optional blocker writes; keep them separate from compiler-resolution diagnose. | [near_diag.py](../src/rebrew/near_diag.py) |
| `gap-trace` | diagnose gap | Instruction-stream length-gap tracing; keep its distinct output and shared selection/compile primitives. | [gap_trace.py](../src/rebrew/gap_trace.py) |
| `recommend` | Keep recommend | Project-level layout/hygiene advice complements per-function todo; make optional application explicit. | [recommend.py](../src/rebrew/recommend.py) |
| `refactor` | dev refactor | Scans Python under --repository without requiring a reversing project config. | [refactor.py](../src/rebrew/refactor.py) |
| `symbol-addrs` | export symbols | Splat symbol/reference export; distinguish address symbols from C context declarations. | [symbol_addrs.py](../src/rebrew/symbol_addrs.py) |
| `context` | export context | Universal C declaration export; distinguish this from --context input on comparison commands. | [context.py](../src/rebrew/context.py) |
| `objdiff` | export objdiff | Writes reference objects and GUI config; generation differs from the build protocol callback. | [objdiff_project.py](../src/rebrew/objdiff_project.py) |
| `decompme` | export decompme | Remote upload and upload provenance; retain explicit dry-run and network boundary. | [decompme.py](../src/rebrew/decompme.py) |
| `layout-map` | build layout-map | Reference layout measurements; do not merge read-only inventory with gen-layout scaffolding. | [layout_map.py](../src/rebrew/layout_map.py) |
| `import-splat` | source import-splat | Preview is the default and --write opts in; preserve that explicit contract during any naming change. | [splat_config.py](../src/rebrew/splat_config.py) |
| `blocker` | Keep blocker | A cohesive metadata group; keep its set/clear/show model. | [blocker.py](../src/rebrew/blocker.py) |
| `blocker set` | Keep blocker set | Sets blocker evidence only; preserve validated blocker and delta shapes. | [blocker.py](../src/rebrew/blocker.py) |
| `blocker clear` | Keep blocker clear | Removes BLOCKER and BLOCKER_DELTA together through metadata APIs. | [blocker.py](../src/rebrew/blocker.py) |
| `blocker show` | Keep blocker show | Read-only lookup; retain the common function-reference selector. | [blocker.py](../src/rebrew/blocker.py) |
| `orphans` | orphans list / prune | Replace a writing mode on the group callback with an explicit prune operation; keep earned-status protection. | [orphans.py](../src/rebrew/orphans.py) |
| `orphans drop` | Keep orphans drop | Single-identity deletion is distinct from bulk pruning; preserve canonical metadata writers. | [orphans.py](../src/rebrew/orphans.py) |
| `types` | types check | Make the group default layout check an explicit action; retain evidence-based layout findings. | [types_cli.py](../src/rebrew/types_cli.py) |
| `types apply-type` | types apply | The parent already establishes the type domain; keep source-signature rewriting and dry-run. | [types_cli.py](../src/rebrew/types_cli.py) |
| `extract` | binary extract | Keep candidate discovery and byte extraction together; avoid duplicating asm show/batch behavior without comparing artifacts. | [extract.py](../src/rebrew/extract.py) |
| `extract list` | binary extract list | Lists uncovered candidates with extent bounds; preserve no-project --binary use. | [extract.py](../src/rebrew/extract.py) |
| `extract show` | binary extract show | Displays one selected candidate; compare overlap with asm before consolidating formats. | [extract.py](../src/rebrew/extract.py) |
| `extract batch` | binary extract batch | Writes selected function artifacts; negative count/start now fail before artifact creation. Keep extent filters explicit. | [extract.py](../src/rebrew/extract.py) |
| `cfg` | Keep cfg | Already a coherent config owner; nested target/module operations are more useful than a cosmetic cfg rename. | [cfg.py](../src/rebrew/cfg.py) |
| `cfg list-targets` | cfg target list | Groups target lifecycle verbs; retain project-default target information. | [cfg.py](../src/rebrew/cfg.py) |
| `cfg show` | Keep cfg show | Raw declared values with optional dotted-key selection; do not merge with effective resolution. | [cfg.py](../src/rebrew/cfg.py) |
| `cfg effective` | Keep cfg effective | Resolved environment/default values and validation errors are distinct from the raw TOML. | [cfg.py](../src/rebrew/cfg.py) |
| `cfg raw` | Keep cfg raw | Machine-readable full document export; retain secret redaction and explicit format. | [cfg.py](../src/rebrew/cfg.py) |
| `cfg path` | Keep cfg path | Pipeable project-config location; does not require semantic config validity. | [cfg.py](../src/rebrew/cfg.py) |
| `cfg add-target` | cfg target add | Retain validated binary/arch/format fields and overwrite protection. | [cfg.py](../src/rebrew/cfg.py) |
| `cfg remove-target` | cfg target remove | Retain default-target handling and protection against accidental live-target deletion. | [cfg.py](../src/rebrew/cfg.py) |
| `cfg set` | Keep cfg set | Generic scalar editing must retain field validation; special compiler setters carry stronger profile semantics. | [cfg.py](../src/rebrew/cfg.py) |
| `cfg add-module` | cfg module add | Target-scoped module/origin edits belong together. | [cfg.py](../src/rebrew/cfg.py) |
| `cfg remove-module` | cfg module remove | Retain protected-last-module and idempotence behavior. | [cfg.py](../src/rebrew/cfg.py) |
| `cfg set-cflags` | cfg module set-cflags | Compiler-sensitive module presets; do not reduce validation to unrestricted dotted-key writes. | [cfg.py](../src/rebrew/cfg.py) |
| `cfg set-compiler` | cfg target set-compiler | Retain profile validation/default generation; generic cfg set is not equivalent. | [cfg.py](../src/rebrew/cfg.py) |
| `cfg detect-crt` | cfg detect-crt; explicit apply operation | Read detection is useful; make --write provenance changes visible and preserve dry-run. | [cfg.py](../src/rebrew/cfg.py) |
| `cache` | Keep cache | A small cohesive resource-management group. | [cache_cli.py](../src/rebrew/cache_cli.py) |
| `cache stats` | Keep cache stats | Read cache statistics and close handles; no need to require dry-run on a read. | [cache_cli.py](../src/rebrew/cache_cli.py) |
| `cache clear` | Keep cache clear | Explicit destructive verb; retain confirmation/--force and backend cleanup. | [cache_cli.py](../src/rebrew/cache_cli.py) |
| `skills` | Keep skills | Package/user skill discovery is a distinct environment task. | [skills.py](../src/rebrew/skills.py) |
| `skills list` | Keep skills list | Show merged skills and origin; preserve the user override precedence. | [skills.py](../src/rebrew/skills.py) |
| `skills show` | Keep skills show | Pipeable skill text/JSON; preserve path confinement and raw-output semantics. | [skills.py](../src/rebrew/skills.py) |
| `resource` | binary resource | PE resource inspection/extraction belongs with binary formats, not the matching quick path. | [resource.py](../src/rebrew/resource.py) |
| `resource compare` | binary resource compare | Resource byte equality is distinct from initialized-data/function equality; keep exit 1 on differences. | [resource.py](../src/rebrew/resource.py) |
| `resource extract` | binary resource extract | Writes raw section bytes; make its artifact output distinct from function extraction. | [resource.py](../src/rebrew/resource.py) |
| `library` | Keep library; add identification operations | Current overrides are cohesive; add match/identify/signature operations with distinct verbs. | [library.py](../src/rebrew/library.py) |
| `library show` | Keep library show | Nearest effective override differs from listing all declaration files. | [library.py](../src/rebrew/library.py) |
| `library list` | Keep library list | Enumerates override declaration files; clarify the root positional is not --root target selection. | [library.py](../src/rebrew/library.py) |
| `library set` | Keep library set | Retain preset validation and canonical cache invalidation. | [library.py](../src/rebrew/library.py) |
| `library rm` | library remove | Align with cfg remove verbs; a rename must be a breaking change without a compatibility alias. | [library.py](../src/rebrew/library.py) |
| `toolchain` | Keep toolchain | Already groups provider lifecycle and compiler evidence appropriately. | [toolchain_cli.py](../src/rebrew/toolchain_cli.py) |
| `toolchain list` | Keep toolchain list | Known profile inventory differs from readiness for one profile. | [toolchain_cli.py](../src/rebrew/toolchain_cli.py) |
| `toolchain status` | Keep toolchain status | Profile resolution/readiness; keep image, plugin-host, and vendor provenance distinct. | [toolchain_cli.py](../src/rebrew/toolchain_cli.py) |
| `toolchain detect` | Keep toolchain detect | Compiler evidence and profile alignment; preserve standalone binary inspection. | [toolchain_cli.py](../src/rebrew/toolchain_cli.py) |
| `toolchain pull` | Keep toolchain pull | Image acquisition is distinct from source builds; keep pinned identity and backend caches coherent. | [toolchain_cli.py](../src/rebrew/toolchain_cli.py) |
| `toolchain vendor` | Keep toolchain vendor; clarify audience | Assembles pinned source media; does not enable a host fallback for shipped profiles. | [toolchain_cli.py](../src/rebrew/toolchain_cli.py) |
| `toolchain smoke` | Keep toolchain smoke | Compiler reproducibility gate; preserve measured fixtures and expected hashes. | [toolchain_cli.py](../src/rebrew/toolchain_cli.py) |
| `toolchain build` | Keep toolchain build | Build images from the sibling source owner, not arbitrary project paths. | [toolchain_cli.py](../src/rebrew/toolchain_cli.py) |
| `toolchain check-updates` | Keep toolchain check-updates | A read-only drift report is separate from accepting/rebuilding an upstream change. | [toolchain_cli.py](../src/rebrew/toolchain_cli.py) |
| `toolchain update` | Keep toolchain update | Preview by default; preserve explicit --apply and smoke/provenance validation. | [toolchain_cli.py](../src/rebrew/toolchain_cli.py) |
| `binsync` | Keep binsync; absorb flat routes | Use one namespace while retaining raw artifact operations separately from Git orchestration. | [cli.py](../src/rebrew/binsync/cli.py) |
| `binsync init` | Keep binsync init | Canonical grouped initialization; remove only its exact flat route duplicate. | [init.py](../src/rebrew/binsync/init.py) |
| `binsync diff` | Keep binsync diff | Canonical read-only comparison; preserve divergence exit behavior. | [diff.py](../src/rebrew/binsync/diff.py) |
| `binsync overlay` | Keep binsync overlay | Cross-target field provenance differs from source import; preserve matching confidence/conflict rules. | [overlay.py](../src/rebrew/binsync/overlay.py) |
| `binsync push` | Keep binsync push | Local export plus Git commit and optional remote push; preserve raw-export options in a separate export command. | [cli.py](../src/rebrew/binsync/cli.py) |
| `binsync pull` | Keep binsync pull | Fast-forward Git orchestration plus field import; retain a no-Git local-import operation. | [cli.py](../src/rebrew/binsync/cli.py) |
| `binsync summary` | Keep binsync summary | Read-only preview of both directions; neither Git transport nor baseline advancement belongs here. | [cli.py](../src/rebrew/binsync/cli.py) |

## Verification and migration gates

[ADR 028](adr/028-cli-domains-and-explicit-operations.md) records the accepted
layout. The migration reuses the component registry and implementation owners;
old routes and mode flags are removed without aliases. The CLI reference,
packaged and rendered skills, project templates, generated CMake/objdiff callers,
plugin guidance, and operation tests use the current routes.

Validation exercises all **196 help and version routes**, checks global options
and example flags at every depth, and tests metadata writers, earned STATUS,
Git reconciliation, and compiler argument forwarding through their owners.
Ruff, mypy, import-cycle and layering checks cover the changed repository.
On 2026-10-03, the full Rebrew suite passed **10,835 tests**, with **32 skips**
chiefly for unavailable toolchain trees or Docker images. The full run used an
isolated snapshot so concurrent checkout edits could not change the source
during collection or execution. A further **373 focused tests** passed against
the live checkout's subsequent source/cache changes, including the coverage
document contract; the quality checks also passed on that checkout.
The documentation validator resolves nested commands from the composed runtime
tree and checks the options cited in current guides and skills: **1,625 unique
command/option combinations** pass. A separate documentation gate requires
every nested built-in route to appear in the CLI reference.

The wheel and source distribution build successfully; rebuilding from the source
distribution reproduces all **259 wheel files byte for byte**. All **196 help and
version routes** also pass from the wheel installed in an isolated environment,
including the new signature setup, runner setup, and library source binding
operations. The October 4 follow-up also checks required arguments in help
examples, exact option names in command-table descriptions, and preview
semantics. Compiler flag/profile sweeps expose only supported execution options;
batch and LLM request previews retain `--dry-run`.

All **45 discovered sibling Rebrew workspaces** were refreshed using the public
scaffold commands and checked for drift. Four existing generated toolchain files
were regenerated, and both Guild CMake build directories were configured with
the new compiler-driver paths. Durable metadata was unchanged by those refresh
operations.

Recoverage consumes the same coverage schema and direct Rebrew Python APIs.
Its backend suite, frontend type and lint checks, and ten browser interactions
run against the changed checkout and regenerated assets. A separate integration
check regenerates a coverage document twice through Rebrew, then serves the
result through both dashboards and the function/data APIs. The backend suite
passes **2,254 tests** with two platform-specific skips; all **10 browser tests** pass.
Read-only HTTP checks also serve both dashboards and the stats, functions, and
data APIs for all **three real Guild targets**. Positive and negative server
smoke checks and the compressed-page budget pass. These checks were repeated
after the follow-up documentation and help corrections.

Reportal now imports the same TOML documents through the shared reader rather
than removed SQLite workspace helpers. Its regeneration uses the public writer,
all target documents are checked before import writes, and its fixtures cover
malformed input, configured directories and repeated imports. A real binary
fixture generates coverage, imports twice without duplicates, and serves its
functions through the Reportal API. Contributor, CI and container dependency
pins agree with the supported Rebrew release.

Reportal's full `make check` passes **10,528 tests** with **92.95% coverage**,
including its packaging and browser smoke checks. The final UI audit covers
**116 route renders** with zero violations. Its focused compatibility and
regression checks also pass **387 tests** against the current checkout.

Commands for repeating the checks:

```bash
make test
make lint
make format-check
make mypy
make cycles-check
make layering-check
make gen-skills-check
make build sdist-check smoke-wheel
uv run --frozen python tools/validate_skill_commands.py --docs
```

In the sibling Recoverage checkout, run `make test`, `make test-browser`,
`make lint format-check type-check`, `make web-lint typecheck-web`, and
`make smoke smoke-fail payload-budget`. Rebuild edited frontend sources with
`make web-build` before these checks.

In the sibling Reportal checkout, run `make check` for its complete validation.

For a consumer workspace, follow [the migration guide](CLI_MIGRATION.md) to
refresh agents and skills and regenerate any CMake or objdiff configuration.
Default mutation policies, earned STATUS, and coverage schema remain unchanged.
