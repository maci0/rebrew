<p align="center">
  <img src="https://raw.githubusercontent.com/maci0/rebrew/main/docs/mascot.png" alt="Rebrew mascot" width="256" />
</p>

# Rebrew

**Compiler-in-the-loop decompilation workbench for binary-matching game reversing.**

Rebrew is a reusable Python tooling package for reconstructing exact C source code from compiled binaries. It provides a genetic algorithm engine, source metadata pipeline, verification framework, and CLI tools.

## Features

### Core Loop

| Tool | What it does |
|------|-------------|
| `rebrew test` | Compile your C and diff it byte-by-byte against the original binary |
| `rebrew match` | GA engine — single file or batch (`--all`); brute-force compiler flags and mutate source to find exact byte matches |
| `rebrew climb` | Deterministic hill-climb over adjacent statements in one function body — the complement to `match` when the residual is statement order |
| `rebrew verify` | Bulk compile + report match status; always auto-updates metadata; `--compare` for CI regression checks; `--watch` re-verifies on every change |
| `rebrew prove` | Symbolic equivalence via angr + Z3 — mathematically prove NEAR_MATCHING functions are equivalent |
| `rebrew near-diag` | Classify *why* a NEAR_MATCHING function misses: register allocation, equivalent instruction selection, relocation masking, or structural layout |
| `rebrew probe` | Measure one function against the reference without writing metadata |
| `rebrew qual-sweep` | Sweep declaration qualifiers over one function, keeping winners |
| `rebrew gap-trace` | Trace length-gap drift between object and reference instruction streams |
| `rebrew residue` | Section diffs plus per-function attribution of remaining `.text` bytes |

### Authoring

| Tool | What it does |
|------|-------------|
| `rebrew skeleton` | Generate annotated `.c` stubs from VAs; `--decomp` for inline decompilation; `--xrefs` for caller context |
| `rebrew rename` | Rename a function across the entire codebase (symbol, filename, cross-references) |
| `rebrew split` | Break multi-function `.c` files into individual files; `--va` to extract one function |
| `rebrew merge` | Combine single-function files into one multi-function file |
| `rebrew lint` | Validate source marker correctness (10 E-codes, 19 W-codes incl. W019 inline-metadata and W020 asm-dump warnings; see ANNOTATIONS.md for the emitted set) |

### Analysis

| Tool | What it does |
|------|-------------|
| `rebrew todo` | Prioritized action list: what to work on next |
| `rebrew status` | Per-target breakdown of EXACT / RELOC / NEAR_MATCHING / STUB counts |
| `rebrew graph` | Call graph from `extern` declarations (mermaid, DOT, summary) |
| `rebrew data` | Inventory `.data`/`.rdata`/`.bss` globals; detect dispatch tables and vtables |
| `rebrew flirt` | Identify known library functions via FLIRT signatures — no IDA required |
| `rebrew crt-match` | Cross-reference functions against CRT/library source directories |
| `rebrew similar` | Rank binary functions by structural similarity to a solved function — find which STUBs share its source family |
| `rebrew fingerprints` | File hashes, imphash, MSVC Rich-header hash, and per-section entropy for a binary |
| `rebrew pe-info` | PE metadata dump: identity, sections with protection flags, DllCharacteristics security flags, Authenticode, debug/PDB, and Rich header |
| `rebrew crypto-scan` | Detect crypto constant tables (AES/SHA/MD5), crypto imports, and crypto-named functions |
| `rebrew security-scan` | Scan C sources for unsafe API use: unbounded copies, non-literal format strings, command execution, unchecked `memcpy`, weak randomness, non-literal `alloca` |

### Infrastructure

| Tool | What it does |
|------|-------------|
| `rebrew init` | Scaffold a new project with config, directories, and agent skills |
| `rebrew doctor` | Validate project health (config, toolchain image, binary) |
| `rebrew catalog` | Build function catalog and coverage JSON |
| `rebrew build-db` | Build SQLite coverage database from catalog |
| `rebrew cache` | Compile cache management (`stats`, `clear`) |
| `rebrew cfg` | Read/write `rebrew-project.toml` settings |
| `rebrew extract` | Batch extract function bytes and disassembly |
| `rebrew binsync` | Umbrella for BinSync sync: `push` (export + git commit, optional `--git-push`), `pull` (git fast-forward + import), `summary`, plus `init`/`diff`/`overlay` |
| `rebrew binsync-export` | Export source markers and metadata to BinSync state directory (IDA/BinNinja import; real types + struct fields, `--module`, `--git`) |
| `rebrew binsync-import` | Import a BinSync state directory into rebrew metadata (names + prototypes + globals, `--accept-binsync`/`--accept-local`, `--module`) |
| `rebrew round-trip` | Splice matched functions back into the target PE and verify byte equality |
| `rebrew asm` | Quick offline disassembly |
| `rebrew skills` | List/show the bundled agent skills |
| `rebrew sync` | Sync with Ghidra: BinSync state dir field sync + MCP structural ops |

### Onboarding & Intelligence

| Tool | What it does |
|------|-------------|
| `rebrew intake` | One-shot binary onboarding: init + toolchain detect + functions + document-unmatched in a single command |
| `rebrew analyze` | One-shot intelligence dossier for a binary — layout, toolchain, strings, imports, dispatch tables, FLIRT matches. Works standalone outside a project |
| `rebrew discover-functions` | Function enumeration (rizin aaa/aap + capstone sweep + `.eh_frame` / `.pdata` unwind tables) with validated boundaries and sizes |
| `rebrew document-unmatched` | Write STUB skeletons + blockers for every function in the list that isn't documented yet (re-discovery workflow; idempotent) |
| `rebrew identify-library` | Identify library functions (FLIRT + imports + CRT) into `library_*.h`; `--build-sigs` generates the sigs from the toolchain `.lib` files first |
| `rebrew pdb-info` | Extract compiler version, flags (S_COMPILE3), and function names from a PDB |

### Design

- **Config-driven** — all tools read from `rebrew-project.toml`, zero manual path arguments
- **Multi-target** — PE, ELF, Mach-O, and 16-bit Windows NE across x86-16, x86, x64, ARM32/64 with `--target` selection
- **Idempotent** — every tool safe to re-run without side effects
- **Composable** — small single-purpose tools designed for scripting and AI agent chaining
- **Compile cache** — disk-backed SHA-256 cache avoids redundant recompilations
- **Agent-friendly** — bundled `agent-skills/` copied to projects on `rebrew init`

### Agent Skills

Six bundled skills for AI coding agent integration:

| Skill | Purpose |
|-------|---------|
| `rebrew-init` | Scaffold a new project from a bare directory + binary |
| `rebrew-workflow` | End-to-end reversing workflow and status tracking |
| `rebrew-matching` | GA matching engine, flag sweeps, diff analysis |
| `rebrew-data-analysis` | Global data scanning, BSS layout, dispatch tables |
| `rebrew-intake` | Binary onboarding, triage, and initial FLIRT scanning |
| `rebrew-ghidra-sync` | Ghidra ↔ Rebrew sync via ReVa MCP |

## Quick Start

> **Host requirements:** Linux x86_64 with Docker. Every Windows/DOS compiler
> profile executes inside its toolchain image (wine/DOSBox live in the image;
> there is no host wine path) — build or pull it with
> `rebrew toolchain build <name>` (see [docs/TOOLCHAIN.md](https://github.com/maci0/rebrew/blob/main/docs/TOOLCHAIN.md)).
> Shipped compiler images are `*-linux-x64` / `*-win32` / `*-win16`; CI runs on
> `ubuntu-24.04` (x86_64). Analysis-only commands (`asm`, `analyze`, `flirt`,
> `catalog`, …) are pure Python 3.13+ and avoid host-OS assumptions in path and
> text I/O, but are only CI-validated on Linux x86_64.

```bash
# 1. Install
uv tool install git+https://github.com/maci0/rebrew.git

# 2. Create a project
mkdir my-decomp && cd my-decomp
rebrew init --target server --binary server.dll

# 3. Place your binary
cp /path/to/server.dll original/

# 4. Start reversing
rebrew doctor                       # verify setup
rebrew todo -c start-function       # find easiest uncovered functions
rebrew skeleton 0x10003DA0          # generate first stub
rebrew test src/server/func_10003da0.c  # compile and compare
```

`rebrew init` creates `rebrew-project.toml`, source/bin directories, and agent skills.
All tools find the config by searching upward from the current directory (like `git` finds `.git/`).

## Library usage

Install as a dependency (`uv add git+https://github.com/maci0/rebrew.git` or
`pip install` from the same URL). Import submodules directly — the top-level
package only exports `__version__`:

```python
from rebrew.config import load_config
from rebrew.errors import RebrewError
from rebrew.sources import iter_sources
from rebrew.toolchain import ToolchainError, get_toolchain

cfg = load_config()  # walks up for rebrew-project.toml
for path in iter_sources(cfg.reversed_dir, cfg):
    print(path)

try:
    get_toolchain(cfg.compiler_profile)  # e.g. "msvc-6.0"
except ToolchainError as exc:
    # Branch on exc.kind / exc.name / exc.retryable — not message substrings.
    raise

# Byte-level matching uses the same entry as the CLI:
#   from rebrew.compile import CompareResult, compile_and_compare
#   result = compile_and_compare(cfg, source_path, symbol, target_bytes, cflags)
#   result.matched / result.status / result.match_percent / result.message
```

Remote compile transport, registry plugins, workspace helpers, and the GA
matcher follow the same pattern (`rebrew.recompile_client`, `rebrew.registry`,
`rebrew.plugin`, `rebrew.workspace`, `rebrew.matcher`). Catch the specific type
(`ConfigError`, `RecompileError`, `McpError`, `ToolchainError`, `RegistryError`, ...) when the
recovery differs per failure, and `RebrewError` when it does not:

```python
try:
    result = compile_and_compare(cfg, source_path, symbol, target_bytes, cflags)
except RebrewError as exc:
    if exc.retryable:
        ...  # transient docker/daemon blip or transport hiccup
    raise
```

Every rebrew error type inherits `RebrewError` alongside its original
`RuntimeError`/`ValueError` base, so a new error type in a later release lands
in that handler instead of escaping it.

## Usage & Workflow

All CLI tools must be run **from within a project directory** that contains a `rebrew-project.toml` config file.

```bash
cd /path/to/your-decomp-project    # must contain rebrew-project.toml

# Project Setup
rebrew init --target mygame --binary mygame.exe --toolchain msvc-6.0 # initialize project
rebrew cfg list-targets              # list configured targets
rebrew cfg set-cflags ZLIB "/O3"        # set cflags for origin
rebrew cfg set compiler.cflags "/O1" # set a config value
rebrew cfg show targets.main.arch     # read a value (supports dotted target names)
rebrew cfg raw                       # dump config as JSON
rebrew cfg path                      # print config file path
rebrew cfg detect-crt --write        # auto-detect MSVC CRT source directories

# Development
rebrew skeleton 0x10003DA0          # generate C skeleton from disassembly
rebrew skeleton 0x10003DA0 --xrefs  # skeleton with Ghidra cross-reference context
rebrew test src/target_name/f.c     # test implementation against target
rebrew todo                         # see highest ROI action items
rebrew todo --stats                 # show overall progress statistics
rebrew todo -c fix-delta --json     # tiny byte diffs (quick wins, sorted by ROI)
rebrew todo -c extract-error        # symbols missing from .obj (marker/impl issue)
rebrew flirt --json                 # FLIRT scan: identify known library functions
rebrew crt-match 0x10006c00         # match a single VA against CRT source
rebrew crt-match --all                     # match all library functions
rebrew crt-match --fix-source --all  # auto-write // SOURCE: markers
rebrew crt-match --index            # show CRT source index
rebrew graph --cu-map               # infer compilation unit boundaries
rebrew graph --cu-map --json        # JSON output for scripting
rebrew lint                         # lint source markers in your files
rebrew split src/target_name/multi.c           # split multi-function file into individual files
rebrew split --va 0x10003DA0 src/target_name/multi.c  # extract one function into multi_c/
rebrew merge a.c b.c --output merged.c         # merge files into one multi-function file
rebrew merge multi_c/ multi.c -o multi.c --force --delete  # merge extracted function back
rebrew catalog                      # regenerate the function catalog and coverage JSON
rebrew catalog --data-json          # write db/data_<target>.json
rebrew catalog --export-ghidra-labels  # generate ghidra_data_labels.json from detected tables
rebrew build-db                     # build SQLite coverage database from catalog
rebrew binsync-export ./binsync_out # export source markers and metadata to BinSync state directory
rebrew binsync-import ./binsync_out --dry-run # import names + prototypes + globals from a BinSync state (dry-run)

# Matching
rebrew diff src/target_name/f.c                     # side-by-side disassembly diff
rebrew diff --mismatches-only src/target_name/f.c  # show only structural diffs (**)
rebrew match src/target_name/f.c    # run the Genetic Algorithm Engine to resolve diffs
rebrew match --all                          # batch GA on all STUB functions
rebrew match --all --improve                # batch GA on all NEAR_MATCHING functions
rebrew match --all --near-miss --threshold 5 # batch GA on NEAR_MATCHING with ≤5B delta
rebrew match --all --flag-sweep             # batch flag sweep on all NEAR_MATCHING functions
rebrew match --all --flag-sweep --fix-cflags  # targeted sweep, auto-update CFLAGS

# Semantic Equivalence (requires angr: uv tool install --reinstall 'rebrew[prove] @ git+https://github.com/maci0/rebrew.git')
rebrew prove src/server.dll/calculate_physics.c      # prove NEAR_MATCHING function equivalent
rebrew prove src/server.dll/calculate_physics.c --json  # JSON output
rebrew prove my_func --dry-run                        # find by symbol, preview only

# Export & Sync
rebrew verify                       # bulk compile and auto-update STATUS/BLOCKER metadata
rebrew verify --json                # structured JSON report to stdout
rebrew verify --compare             # detect regressions against last saved report
rebrew split src/target_name/multi.c --dry-run  # preview split without writing
rebrew split --va 0x10003DA0 --dry-run src/target_name/multi.c  # preview single extraction
rebrew merge a.c b.c -o merged.c --delete       # merge and delete originals
rebrew extract list                 # list un-reversed candidates
rebrew extract batch 20             # extract and disassemble first 20 smallest
rebrew asm                          # quick offline disassembly
rebrew cache stats                  # show compile cache hit rate and size
rebrew doctor                       # validate config, toolchain image, and binary

# Ghidra Sync via BinSync state dir + ReVa MCP
rebrew sync --push                  # export source markers and metadata to the state dir
rebrew sync --pull                  # import the state dir into rebrew
rebrew sync --pull --accept-binsync # accept BinSync names on pull conflicts
rebrew sync --pull-data             # pull Ghidra data labels into rebrew_globals.h (MCP)
rebrew sync --create-functions      # create functions in Ghidra (MCP)
rebrew sync --bookmarks             # set status bookmarks in Ghidra (MCP)
rebrew sync --pull --dry-run        # preview pull without modifying files
```

## Match Statuses

Every annotated function carries a `STATUS`. Status is *earned*, never
claimed: `rebrew verify` / `rebrew test` derive it from the real byte
comparison of the compiled `.c` against the target binary, and write it
through the metadata writer. A hand-claimed status is demoted to the actual
byte result with a `metadata:` warning.

| Status | Meaning | How it is earned |
|---|---|---|
| `EXACT` | Compiled bytes identical to the target | `rebrew verify` — every non-relocation byte matches |
| `RELOC` | Identical except relocation slots | `rebrew verify` — all non-reloc bytes match and the reloc slots (linker-filled symbol addresses) validate against the catalog |
| `PROVEN` | Semantically equivalent despite structurally different bytes | `rebrew prove` (symbolic equivalence via angr/Z3). Not a byte match and not protected: the next `rebrew test` / `rebrew verify` records the byte result (`NEAR_MATCHING`, `EXACT`, …) over it |
| `NEAR_MATCHING` | Close but not byte-identical — at least 60 % of bytes match | `rebrew verify` — typically register allocation, instruction scheduling, or a flag variant; try `rebrew match --flag-sweep` |
| `STUB` | Below the 60 % near-match threshold — the skeleton was never implemented, or control flow diverges | `rebrew verify`, or manual classification for known-unimplemented code |
| `SKIP` | Intentionally not worked on (data, out of scope) | manual classification |
| `SIZE_MISMATCH` | Compiles, but the object length differs from the target | `rebrew verify` |
| `COMPILE_ERROR` | The C does not compile under the function's toolchain and flags | `rebrew verify` |
| `EXTRACT_ERROR` | The compiled object or the target bytes could not be extracted | `rebrew verify` |
| `MISSING_SIZE` / `MISSING_FILE` | Target function size unknown / target binary missing | `rebrew verify` |
| `INVALID_VA` | Annotation VA sits below the architecture's code floor | `rebrew verify` (annotation problem) |

Typical progress runs `STUB` → `NEAR_MATCHING` → `EXACT` / `RELOC`, with
`PROVEN` for code that is semantically correct but structurally different.
Only `EXACT` and `RELOC` count as matched; `PROVEN` functions stay on
`rebrew todo` as improve-match work (`rebrew status` summarizes the rest).  Source-marker mechanics live in
[docs/ANNOTATIONS.md](https://github.com/maci0/rebrew/blob/main/docs/ANNOTATIONS.md).

## Supported Platforms

| Architecture | Binary Format | Compiler | Binary Loading | Object Parsing | GA Matching | Verification |
|:------------|:-------------|:---------|:--------------:|:--------------:|:-----------:|:------------:|
| x86 (16-bit) | NE (Windows 3.x) | Borland Delphi 1.0 / Turbo Pascal | ✅ | ⬜ | ⬜ | ⬜ |
| x86 (16-bit) | NE (Windows 3.x) | MSVC 16-bit (C 7.0 / VC 1.x) | ✅ | ⬜ | ⬜ | ⬜ |
| x86 (32-bit) | PE (`.exe`/`.dll`) | MSVC 5.0 / 6.0 | ✅ | ✅ | ✅ | ✅ |
| x86 (32-bit) | PE | MSVC 7.x+ | ✅ | ✅ | ✅ | ✅ |
| x86 (32-bit) | PE | MinGW GCC / Zig (`mingw-16.2.0` profile) | ✅ | ✅ | ✅ | ✅ |
| x86 (32-bit) | PE | Watcom C | ✅ | ✅ (OMF→COFF via objconv) | ✅ | ⬜ |
| x86 (32-bit) | ELF (`.so`/exec) | GCC/Clang| ✅ | ✅ | ⬜ | ⬜ |
| x86_64     | PE | MSVC     | ✅ | ✅ | ⬜ | ⬜ |
| x86_64     | ELF | GCC/Clang| ✅ | ✅ | ⬜ | ⬜ |
| x86_64     | Mach-O| Clang    | ✅ | ✅ | ⬜ | ⬜ |
| ARM32      | ELF | GCC/Clang| ✅ | ✅ | ⬜ | ⬜ |
| ARM64      | ELF | GCC/Clang| ✅ | ✅ | ⬜ | ⬜ |
| ARM64      | Mach-O| Clang    | ✅ | ✅ | ⬜ | ⬜ |

**Legend:** ✅ Supported  ⬜ Planned / Not yet implemented

16-bit NE targets are parsed, enumerated, and analyzed natively (intake,
analyze, asm, describe, data, report — see `docs/TOOLCHAIN.md`); byte
matching and verification short-circuit with a notice because no 16-bit
compiler profile exists yet (ADR-001).

**Toolchain detection:** `rebrew intake`/`analyze` auto-detect the compiler
family and version — DIE (`diec`) signatures first, then PDB records, then
structural heuristics (strings, imports, codegen style, section layout).
16-bit NE family comes from the Borland segment-marker convention
(`delphi` vs MSVC-style markerless segments).  When diec misses a compiler
record, the Microsoft Linker version still pins the MSVC era.

**Compiler profiles:** `msvc-6.0` is the default — every profile (all `msvc*`
from 1.0 through 11.0, `borland-5.5`, `borland-3.1`/`borland-2.0`, `watcom-2.0-win32`/`watcom-2.0-win16`,
`delphi-1.0`, `gcc-14.2.0`/`gcc-12.3.0`, `clang-18.1.8`/`clang-16.0.4`, `mingw-16.2.0`/`mingw-14.2.0`,
`ido-5.3`/`ido-7.1`) compiles
inside a per-toolchain **docker image** (wine/DOSBox/a native Linux compiler
live in the image; there is no host wine/wibo path).  `mingw-16.2.0` targets MinGW
GCC / Zig PE builds, `gcc-14.2.0`/`clang-18.1.8` cover ELF/x86_64, and `watcom-2.0-win16` is the
16-bit DOS Watcom profile.  Service-pack variants
(`msvc-6.0-sp1`–`msvc-6.0-sp6`, `msvc-7.0-sp1`, …) cover the pin-specific
codegen differences.  Profile selection happens automatically on
`rebrew intake` from the detected family; the full list is
`rebrew toolchain list`.

## Development

Clean clone needs **uv**, **Python 3.13+** (`.python-version`), **nasm** on
`PATH`, and a sibling [`resembl`](https://github.com/maci0/resembl) checkout at
`../resembl` (tag `v2.0.0`, matching CI `RESEMBL_REF` / `uv.lock`; `make setup`
also requires `HEAD` to be the `RESEMBL_SHA` commit CI's `resembl-sha` pins).  See
[`CONTRIBUTING.md`](https://github.com/maci0/rebrew/blob/main/CONTRIBUTING.md); `make help` lists targets.
Run the following from the directory that will hold both checkouts:

```bash
git clone https://github.com/maci0/rebrew.git
git clone --depth 1 --branch v2.0.0 https://github.com/maci0/resembl.git
cd rebrew/
make setup                 # uv sync --frozen --all-extras --group similarity + pre-commit hooks
make test-one T=tests/test_annotation.py   # single-file edit-test loop
make test                  # full suite (needs nasm)
make lint                  # ruff check (same as CI)
make format                # ruff format (writes)
make all                   # local mirror of CI lint + test + cli-contract
make check                 # pre-commit hook parity (before a PR)
make build                 # sdist + wheel + dist/rebrew.buildinfo (CI package job)
make clean                 # remove build/dist artifacts and caches
```

Flag-axis refresh from decomp.me (maintainer, needs network):
`uv run --frozen python tools/sync_decomp_flags.py`.

### Flag Sweep Tiers

The flag sweep uses compiler flag definitions synced from [decomp.me](https://github.com/decompme/decomp.me). The `generate_flag_combinations(tier)` function supports five effort levels: `quick` (192 combos), `targeted` (~1.2K combos), `normal` (~5.4K combos), `thorough` (~258K combos), and `full` (~6.2M combos; stride-sampled down to a 100K memory bound). The `msvc-6.0` compiler profile automatically excludes incompatible MSVC 7.x+ flags. See [docs/FLAG_SWEEP_TIERS.md](https://github.com/maci0/rebrew/blob/main/docs/FLAG_SWEEP_TIERS.md).

## Ecosystem & Related Tools

Projects rebrew integrates with or draws from:

### Integrated

| Tool | Role | Integration |
|------|------|-------------|
| [decomp.me](https://github.com/decompme/decomp.me) | Collaborative decompilation platform | Flag axes synced via `tools/sync_decomp_flags.py`; powers `rebrew match --flag-sweep` |
| [reccmp](https://github.com/isledecomp/reccmp) | Binary recompilation comparison framework | Source marker format compatibility; `rebrew catalog --csv` exports reccmp-compatible CSV |
| [LIEF](https://github.com/lief-project/LIEF) | Binary format parsing (PE/ELF/Mach-O) | Used for binary loading, format detection, and PE section analysis |
| [Capstone](https://github.com/capstone-engine/capstone) | Disassembly engine | Powers `rebrew asm`, byte-diff scoring, relocation masking, and mnemonic comparison |
| [angr](https://github.com/angr/angr) | Binary analysis + symbolic execution | Powers `rebrew prove` for Z3-based semantic equivalence proving (optional dep) |
| [declib](https://github.com/binsync/declib) | BinSync artifact layer | BinSync state export/import/diff/overlay (`binsync` extra, `declib>=4.5`) |
| [ReVa](https://github.com/cyberkaida/reverse-engineering-assistant) | Ghidra MCP bridge | `rebrew sync` structural ops (create-functions, bookmarks, pull-data); field sync is BinSync-primary |

### Adjacent Tools

| Tool | What it does | Relevance |
|------|-------------|-----------|
| [asm-differ](https://github.com/simonlindholm/asm-differ) | Assembly diff with levenshtein alignment | Used by decomp.me for all diffs; rebrew has its own capstone-based differ |
| [decomp-permuter](https://github.com/simonlindholm/decomp-permuter) | Source-level permutation finder for matching decompilation | Complementary to `rebrew match`'s GA: explores semantic-preserving C rewrites (variable types, statement order, parenthesisation) until the compiler emits identical assembly. Candidate for integration as an alternative mutation engine or seed source for the GA. |
| [objdiff](https://github.com/encounter/objdiff) | Rust GUI for object file diffing (COFF/ELF/Mach-O) | Visual companion for inspecting match differences |
| [decomp-toolkit](https://github.com/encounter/decomp-toolkit) | GameCube/Wii decompilation toolkit | DOL/REL focused; similar split/link/diff workflow concepts |
| [wibo](https://github.com/decompals/wibo) | Lightweight Win32 PE loader | Faster alternative to Wine for running MSVC CL.EXE |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | NSA's reverse engineering suite | Primary disassembler/decompiler; connected via ReVa MCP |
| [FLIRTDB](https://github.com/Maktm/FLIRTDB) | FLIRT signature database | Signatures for MSVC, Borland, MinGW used by `rebrew flirt` |

## Companion Projects

| Project | What it is |
|---------|-----------|
| [recompile.online](https://github.com/maci0/recompile) | Compiler-as-a-service API over the rebrew toolchain zoo — submit C + a toolchain id, get the compiled artifact (separate workspace: `../recompile`) |
| [recoverage](https://github.com/maci0/recoverage) | Coverage database / dashboard over `rebrew build-db` output |

## License

MIT. See [LICENSE](https://github.com/maci0/rebrew/blob/main/LICENSE).

Optional installs use separate grants, named in [NOTICE](https://github.com/maci0/rebrew/blob/main/NOTICE): the
`similarity` group (`resembl`, GPLv3), the `m2c` group (GPL-3.0-only), and
the `prove` extra (`pyvex` ships LibVEX under GPL-2.0-or-later).
