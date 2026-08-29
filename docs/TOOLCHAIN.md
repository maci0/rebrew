# Toolchain & Environment

External tools that rebrew integrates with or builds on top of.

---

## MSVC6 Toolchain (Compile Backend)

Executed only through the docker image `rebrew/msvc:6.0-win32` (the image
wraps wine; the host never calls CL.EXE directly — execution is docker-only
for every Windows/DOS toolchain).  The tools inside the image:

| Tool | Purpose |
|------|---------|
| `CL.EXE` | C/C++ compiler (primary compilation tool) |
| `LINK.EXE` | Linker |
| `LIB.EXE` | Library manager (extract .obj from .lib archives) |
| `DUMPBIN.EXE` | Binary dumper (see below) |
| `EDITBIN.EXE` | Binary editor (modify PE headers, base addresses) |

---

## MinGW GCC (gcc-pe profile, for PE/x86_32 targets)

Some PE/x86_32 binaries are built with MinGW GCC instead of MSVC (identifiable
by a `.buildid` section, GNU-style multi-byte `0f 1f` nops, and a call-based
stack probe `mov eax, N; call ___chkstk_ms`).  For these, use the `gcc-pe`
compiler profile:

```toml
[compiler]
profile = "gcc-pe"
command = "i686-w64-mingw32-gcc"
includes = ""            # mingw ships its own headers
libs = ""
cflags = "-O2 -march=pentium4"
base_cflags = ""         # -c is added by rebrew for posix-style profiles
```

`rebrew init --compiler gcc-pe` creates this configuration.  The compile
pipeline is profile-aware: `-I/-c/-o` flag style, no Wine runner, and PATH
resolution of the bare toolchain name.

**Caveat — codegen-version sensitivity:** byte-exact matching requires the
author's *exact* GCC version.  Modern GCC (e.g. 16.x) differs from older GCC
(4.x–7.x) in argument passing (accumulate-outgoing-args), stack probing
(chkstk convention), and scheduling, so old MinGW-built binaries usually
match only *structurally* (use `rebrew diff` structural ratio) — document the
semantic decomp and blocker the byte delta rather than forcing a pass.

**ELF/x86_64 targets:** `gcc` and `clang` are first-class native PATH specs
(no image, posix flags, `.o` objects) — the same profile-aware pipeline as
`gcc-pe`, resolving the bare `gcc`/`clang` binary from PATH.  Both carry a
minimal posix flag-sweep axis set (`flag_data.GCC_FLAGS`), so
`rebrew match --flag-sweep` emits flags these compilers accept rather than
the MSVC fallback.

**Analysis note:** rizin's `aaa` mis-merges functions on this toolchain —
use `aa; aap` (function-prelude analysis) for the function list.  Ghidra
headless gives correct boundaries but is slow on loaded machines.

---

## Delphi 1.0 (16-bit NE compile backend — research; Borland ABI unmatchable)

The vendored `rebrew-toolchains/delphi/1.0-win16` toolchain (DCC.EXE, DOS
DPMI app run under DOSBox headless) compiles 16-bit Windows 3.x NE
executables; the `rebrew.delphi16.compile_ne` wrapper makes it invocable
from Python and parses the output with the native NE loader.  Note: 16-bit
*matching* is implemented in rebrew via the `msvc1.52` profile (DOSBox
CL.EXE → OMF objects) — but **Delphi's Borland ABI has no matchable rebrew
profile**, so Delphi functions are documented as blockers and this
toolchain is for research (compile + NE parse).  See
`rebrew-toolchains/delphi/1.0-win16/source/README.md` for the recipe and
the RTM.EXE / non-tmpfs requirements, and the NE section below for the
analysis-side support matrix.

---

## Per-library overrides (rebrew-libraries.toml)

Most codebases are one codebase: all functions were built with the same
compiler and flags.  Per-function `TOOLCHAIN`/`CFLAGS` metadata (the
`rebrew-functions.toml` escape hatch for rare mixed builds) stays, but the
right abstraction for "some parts of the codebase were built with other
flags" is a **per-library** override: a `rebrew-libraries.toml` at a library
root directory (e.g. `references/zlib/`, a shipped runtime, or any source
subtree) applies to every function under it.  `rebrew library` manages it:

```bash
rebrew library set refs/zlib --preset msvcrt-static   # known shipped lib
rebrew library set refs/zlib --toolchain msvc6 --cflags "/O2 /Gd /MT"
rebrew library show refs/zlib/f                       # effective override (walk-up)
rebrew library rm refs/zlib
```

```toml
# refs/zlib/rebrew-libraries.toml
library = "msvcrt-static"   # optional: known-library preset fills missing fields
toolchain = "msvc600sp6"     # optional: compiler profile (docker image)
cflags = "/O2 /Gd /MT"       # optional: compiler flags
```

Resolution (most specific first): per-function `TOOLCHAIN`/`CFLAGS` → the
nearest `rebrew-libraries.toml` walking up from the function's directory →
project defaults.  **Known-library presets** cover the shipped runtimes
rebrew knows the build settings for — e.g. `msvcrt-static` expands to
`msvc6` + `/O2 /Gd /MT` (the MSVC static CRT), `msvcrt-dynamic` to
`/MD`, `msvc16-runtime` / `borland-runtime` / `watcom-runtime` for the
16-bit and Borland/Watcom runtimes.  `rebrew toolchain` docker-only
execution applies unchanged: the override selects the image.


## Toolchain standardization (docker-first)

`rebrew toolchain` (see [CLI.md](CLI.md)) manages compiler toolchains
through a uniform abstraction (`rebrew.toolchain`), modeled on Godbolt's
Compiler Explorer convention: **one container image per toolchain-version**,
with the compiler behind a wrapper inside the image, so the host invocation
is always `docker run <image> <compiler> <args>`.  Execution is
**docker-only for every Windows/DOS toolchain** — the images encapsulate the
runtime (wine / DOSBox) and there is no host wine/wibo/dosbox fallback; a
missing image is a hard error (run `rebrew toolchain build <name>`).
Native-Linux toolchains without an image (gcc-pe, watcom16 `wcc`) exec
their vendored/PATH binary directly.  The docker build source (Dockerfiles,
wrappers, the shared `base`) lives in the standalone **rebrew-toolchains**
checkout — the sibling repo (overridable via `REBREW_TOOLCHAINS_DIR`) —
and `rebrew toolchain build`/`vendor` read it from there; rebrew no
longer vendors build files in-repo.

Current toolchains (`rebrew toolchain list`): `msvc6` (image
`rebrew/msvc:6.0-win32` built+verified — MSVC 6.0 under wine in a
container, from the sha256-pinned archaic-msvc `msvc600` tarball,
CL.EXE 12.00.8168), `delphi16`
(DOSBox; image `rebrew/delphi:1.0-win16` built+verified — a
containerized Delphi 1.0 compile produces a genuine NE 6.01 executable),
`gcc-pe` (native MinGW), `watcom` (native Open Watcom 2.0 — installed at
`rebrew-toolchains/watcom/2.0-win32`; image `rebrew/watcom:2.0-win32` built and verified —
the docker-first compile produces the same object + relocs as the host
path), `msvc1.52` (16-bit, DOSBox via `rebrew.msvc16`; image
`rebrew/msvc:1.52-win16` built+verified — containerized CL.EXE
produces a genuine 16-bit OMF object; the `cl16` wrapper takes the source
as its single argument and adds `/nologo /c` itself), `borlandc55`
(Borland C++ 5.5 free command-line tools under wine; image
`rebrew/borland:5.5-win32` built+verified — bcc32 emits OMF objects that
parse via objconv; vendored from the archive.org `BorlandC55` item),
`watcom16` (Open Watcom 2.0 `wcc`, 16-bit DOS, native — same snapshot as
`watcom`), `tc16` (Turbo C++ 3.1, 16-bit DOS under DOSBox via
`rebrew.tc16`; image `rebrew/borland:3.1-win16` — TCC.EXE produces
Borland 16-bit OMF that parses via `rebrew.matcher.omf16`; vendored
from the archive.org `turboc3.1_202112` item — the classic
DOS-game compiler, e.g. id Software's early titles; verified:
`compile_and_compare` returns EXACT against a TCC-built object),
`tc20` (Turbo C 2.0, 16-bit DOS under DOSBox via the same `rebrew.tc16`
module with `version="2.0"`; tree `rebrew-toolchains/borland/2.0-win16` assembled
from the archive.org `turboc20` floppies; image
`rebrew/borland:2.0-win16`, in the smoke gate — the 1988/89 compiler that
diec reports as "Borland C/C++ 1991"; C89-strict: rejects `//` comments,
so skeletons use `/* */` markers), and the **complete MSVC 1.0–11.0
line** (below: 30 docker profiles from `msvc10` to `msvc1100`,
every version and every preserved service pack, each packaged as a
sha256-pinned docker image `rebrew/msvc:<version>-<arch>` plus a
host tree vendored into the rebrew-toolchains checkout as the
byte-identical build source; the 4.0/4.2/5.0 trees are archaic-msvc /
itsmattkc snapshots, pinned sha256 sources shared with `rebrew toolchain vendor`),
and `ido5.3`/`ido7.1` (SGI IDO reimplementations — MIPS-II big-endian, N64;
native-Linux images `rebrew/ido:5.3-linux`/`rebrew/ido:7.1-linux` built+verified
from the sha256-pinned decompals/ido-static-recomp v1.2 release assets — the
recomp `cc` runs natively, no wine; in the smoke gate, objects byte-identical
across runs).

**Every registry toolchain with a pinned source has a verified
containerized path** (the images above + gcc-pe native) — the
docker-only standardization is complete for the whole matrix; there is
no host wine/dosbox execution path in the compile pipeline anymore (only
the standalone `rebrew.msvc16`/`rebrew.tc16`/`rebrew.delphi16` research
modules run their DOSBox sandbox directly).  `rebrew toolchain smoke`
gates byte-reproducibility for every image-backed MSVC profile with a
golden object hash.

**Source drift is tracked** (`rebrew toolchain check-updates`): every
GitHub-codeload pin (archaic-msvc, archaic-toolchains, itsmattkc)
records the branch commit it was taken from, and the checker compares
the live commit sha via the GitHub API (no download) — a changed
upstream repo (e.g. a preservation fix) is reported as `DRIFTED`
before any build fails.  `rebrew toolchain update <name> --apply`
re-pins (sha256 + commit), re-vendors the host tree, rebuilds the
docker image and regenerates the smoke golden (verified stable across
two compiles).  The image swap is transactional: a failed build/pull
restores the previously registered image under the tag, and a failed
`update --apply` restores the previous source pin — the pin never stays
ahead of the image.  The Open Watcom `Last-CI-build` release tag is a
moving target, so it is re-downloaded and re-hashed; decomp.me /
archive.org assets and pinned tarballs (16-bit media in the
rebrew-toolchains checkout) are immutable and reported as
static.  Runs on a schedule (or ad-hoc) with `GH_TOKEN` set for
generous API limits.

> **Headless by construction:** every Windows/DOS compile runs inside a
> docker container — wine runs headless inside the image (no desktop
> window, no `DISPLAY` needed on the host), so the old host-side Xvfb /
> xvfb-run / wibo dance is gone.  The images set `WINEDEBUG=-all` and a
> fixed wine prefix; nothing wine-related runs on the host.
>
> **wine is the default runtime.**  The shared wrapper (`base/wrapper-common.sh`)
> selects the PE runtime per run via `REBREW_RUNNER`, defaulting to **wine**
> (`${REBREW_RUNNER:-wine}`) — the most compatible option.  `wibo` is opt-in
> (`REBREW_RUNNER=wibo`) and faster for plain console tools, but **fails on
> some tools**, so rebrew never steers projects toward it: `rebrew doctor`
> reports a present wibo binary as informational only, and
> `rebrew doctor --install-wibo` downloads it but leaves a docker-backed
> project's `runner` config untouched (the config runner is obsolete for
> images anyway).

**Image layout convention** (Godbolt-style): Dockerfiles live at
`<family>/<version>-<arch>/Dockerfile` under the rebrew-toolchains
checkout and produce `rebrew/<family>:<version>-<arch>` — the
top-level directory is the **unversioned compiler family** (`msvc/`,
`delphi/`, `watcom/`) and the version + target architecture live in the
subdirectory and image tag, so `msvc/6.0-win32/`,
`msvc/1.52-win16/`, or a future `msvc/6.0-windows-x86/` coexist
without ambiguity.  (The old
`msvc6/6.0-linux-x64` / `msvc152/1.52-linux-x64` / `delphi16/1.0-linux-x64`
names were ambiguous — `msvc152` read as "MSVC 152" and `delphi16` as
"Delphi 16" — and are retired.)

**Shared base image**: every toolchain Dockerfile inherits
`FROM rebrew/base:1.0` (`base/` in the rebrew-toolchains checkout), which
carries the OS + wine + wine32 + dosbox + download tooling and the common
env (`WINEDEBUG=-all`, `WINEPREFIX=/opt/wineprefix`,
`SDL_VIDEODRIVER=dummy`).  `rebrew toolchain build` builds the base
automatically when the toolchain's Dockerfile references it.  Each
toolchain image only adds its compiler + an entrypoint wrapper; the
vendored tree lives at the top level of the version dir (so the host and
the image share one layout).

**Common wrapper helpers**: `base/wrapper-common.sh` (rebrew-toolchains
checkout) provides the shared entrypoint machinery — `rebrew_pick_source`
(locates the readable source among MSVC-style flags-first argv),
`rebrew_dosbox_run` (headless DOSBox sandbox), `rebrew_copy_back`
(artifact copy-back) — and each wrapper (`cl`, `cl16`, `dcc`) sources it
instead of re-implementing the sandbox logic.

**Image entry convention:** every image's `ENTRYPOINT` *is* the compiler
wrapper (`cl`, `cl16`, `cl15`, `cl10`, `dcc`, `wcc386` — all current
specs), so images are invoked without an explicit command
(`image_binary=None`); the wrapper itself dispatches to the real
compiler (via `rebrew_run` for the wine images, DOSBox for the 16-bit
ones).  This mirrors Godbolt's "image = toolchain + wrapper" model.

Notes:

- **Watcom** (`wcc386`) emits **OMF** objects — converted to COFF via the
  vendored **objconv** (tools/objconv) and parsed by LIEF transparently;
  32-bit OMF byte-matching is enabled.  A project configured with
  `profile = "watcom"` compiles through the toolchain runner in
  `rebrew compile` (`-fo=`/`-I` flag shape, docker image or vendored
  host binary), so `rebrew test`/`verify` work for Watcom targets.
  objconv crashes on 16-bit OMF — `rebrew.matcher.omf16` now decodes the
  MSVC 1.52 dialect in both flavors (unoptimized: code from 0xA0 records,
  publics from MODEND; **/O-optimized: code from 0xC2 records, publics
  from 0x96/0xCA name lists** — the GA flag sweep emits this), so 16-bit
  function bytes + reloc slots extract through
  `parse_obj_symbol_and_relocs` (e8/e9 rel16 slots) — see
  [OMF_NOTES.md](OMF_NOTES.md).  When the `omf16` decoder cannot extract
  code, the parse falls through to the objconv→COFF path; the vendored
  `tools/objconv/objconv` should be the fixed build from the objconv fork
  (16-bit OMF relocation methods + COMDAT→COFF-section support — see the
  fork's `PR-16BIT-OMF.md`), which converts what the stock build rejects.
  `profile = "watcom16"` (native `wcc`, 16-bit DOS) routes through the
  same toolchain runner with the wcc flag shape (`-fo=`/`-I`/`-zq`, no
  `-c` — wcc16 rejects it with E1073); its objects parse via the omf16
  decoder too, so 16-bit DOS/Watcom targets get compile+compare support
  (verified: `compile_and_compare` returns RELOC 100% against a wcc-built
  object — the chkstk call reloc slot masks correctly).
- **MSVC 1.52** (`rebrew-toolchains/msvc/1.52-win16`, from archive.org `en_vc152_202512`) is a
  Phar Lap TNT DOS-extender binary — runs headless under DOSBox via the
  shared `rebrew.dosbox` runner; produces 16-bit OMF objects.
- **Borland C++ (bcc32)**: the `turbo-c-v-4.5` CD was fully surveyed —
  its 207 `.PAK` files are **Quantum** archives (extractable with
  `rebrew-toolchains/delphi/1.0-win16/source/pak_extract.py`), the `.CA1`/`.CA2` containers hold an
  embedded Quantum stream at offset 5 (`[count u32][DS\0Z …]`; TCW.CA1 =
  the TCW IDE + DLLs), but **the CD carries no compiler binary** (no
  BCC32/BCC/TLINK anywhere — it is the Windows-IDE-only release).  The
  compiler needs the actual **Borland C++ 4.5/5.0 floppy set** (different
  archive.org item), not this CD — extraction deferred pending that source.
- **Symantec C++ / Zortech C++ / Intel C++**: detected (family hints) but
  no byte-matching profile.

### Reproducible, self-contained builds

Every toolchain image builds **reproducibly from a clean checkout with only
docker** — no host files:

- **Base** (`base/` in the rebrew-toolchains checkout, `rebrew/base:1.0`)
  pins the debian digest, so apt resolves the same snapshot on every build.
- **Downloads are sha256-verified** (msvc6 tarball, watcom snapshot — the
  moving `Last-CI-build` tag is pinned by the checksum — and the Borland
  InstallShield payload).  A changed source fails the build loudly.
- **Pinned 16-bit tarballs** (`msvc152.tar.xz`, `delphi10.tar.xz`, …) are
  used for msvc1.52/15/10, tc16/tc20 and delphi — the archive.org en_vc152
  RAR SFX extracts corrupt files under both 7z and unar, and the Delphi
  RTL units have no public tarball.  The verified trees sit next to their
  Dockerfile in the rebrew-toolchains checkout (user-supplied media,
  gitignored there — see its README); rebrew no longer commits them.
- Extraction tolerates 7z's warning exits but **verifies the compiler
  binary exists**, so a bad extraction fails loudly.
- All images carry **OCI provenance labels** (source/license/title).

`rebrew toolchain smoke` is the **byte-reproducibility gate**: it compiles
a fixed source in each image with deterministic inputs (fixed work dir +
fixed source mtime — OMF/COFF objects embed the source path and
modification time) and verifies the object sha256 against golden bytes.
Every COFF object's TimeDateStamp (build time) is masked, plus the Turbo C
2.0 / 3.1 per-run COMENT ticks; all 36 smoke-gated toolchains pass —
every image-backed MSVC profile from `msvc10` to `msvc1100` plus
borlandc55, watcom, watcom16, tc16, tc20 and delphi16 — and the image and
host runs gate the same goldens (the container always sees the source at
`/work`; host-only watcom16 runs from the same fixed workdir).  gcc-pe is
not gated: it is a PATH tool, not a vendored tree.  When a pinned source
is bumped (new tarball/snapshot), `rebrew toolchain smoke --print-goldens`
regenerates the masked hashes WITHOUT comparing — run it twice, confirm
the hashes are stable, then paste them into `_SMOKE_GOLDEN`.

`rebrew toolchain vendor <name>` assembles the **host tree** from the same
pinned source the image builds from (16-bit media tarball or sha256-verified
download), extracting into `<family>/<version>-<arch>/source` under the
rebrew-toolchains checkout, so host trees and containers are
byte-identical.  Two layout rules apply during assembly:

- **MSVC 6.0 keeps the `VC98/` master layout** — the pinned `msvc600`
  source (archaic-msvc) already ships the classic `VC98/` wrapper
  (`VC98/Bin/CL.EXE`, matching the canonical config paths and every legacy
  `tools/MSVC600/VC98/...` reference), so `vendor` applies no wrap; the
  decomp.me mirrors (flat `Bin/Include`, no `Lib`) are compile-only —
  `rebrew doctor` warns about the missing lib path, which is expected and
  harmless for `/c` object builds.
- **The vendored tree backs the host-side 16-bit path** — outside the
  docker flow, `rebrew.tc16`/`rebrew.msvc16`/`rebrew.delphi16` symlink
  `source/BIN|INCLUDE|LIB` into a DOSBox sandbox (research/tests; the
  docker images build from the same tarball, byte-identical).

### Toolchain Detection (doctor alignment check)

`rebrew doctor` runs a "Toolchain alignment" check that guesses what
actually built the target and warns when the configured `[compiler] profile`
cannot byte-match it.  The detector is also exposed directly:
`rebrew toolchain detect <binary>` (works standalone, outside any project —
handy for "what built this exe?" before onboarding a new binary).  With a
project present it additionally reports whether the configured profile can
byte-match the detection (`--json` machine-readable).  Detection is layered,
best-first:

1. **Detect It Easy** (`diec -j --heuristicscan`) — the strongest signatures
   for MSVC (per-version, e.g. `12.00.9782` = MSVC 6.0), Borland/Delphi,
   linkers.  Used when `diec` is on PATH or vendored at `tools/diec/diec`
   (fetch the Linux `die_3.10_Ubuntu_24.04_amd64.deb` from the
   horsicq/Detect-It-Easy "Beta" release, `ar x` + `tar -xf` it, and vendor
   the matching `libQt5Core`/`libQt5Script`/`libicu74` `.so` files into
   `tools/diec/lib/` — the `.so`-only pair from a single distro release
   works; mixing distros aborts the QtScript engine).
2. **PE metadata** (Rich header / linker version / CRT imports) — the
   strongest **per-version** MSVC fingerprint, no external tool: LINK.EXE's
   Rich header records the compiler front/back-end build, which combined
   with the optional-header linker version pins the exact compiler (e.g.
   linker 6.0 + C1 9782 = `12.00.9782` = `msvc600sp6`; the VC 6.0 SP
   builds are distinct C1 builds: 8168 RTM, 8447 SP3, 8966 SP5, 9782 SP6).
   VC 2.0-4.2 linkers write no Rich header — the linker version alone
   names the version (2.50 -> VC 2.0, 3.0 -> 4.0, 3.10 -> 4.1, 4.20 ->
   4.2; a bare 2.x is ambiguous with MinGW).  The msvcpX.dll import
   (msvcp60/70/71/80/90/100) is a secondary binder.  The detector then
   suggests the **version-exact** rebrew profile (`suggested_profiles`,
   e.g. `msvc600sp6`) and `profile_matches_detection` flags a configured
   profile that cannot byte-match (different MSVC version = different
   codegen) before the first compile.
3. **PDB** (`llvm-pdbutil`) — when a sibling `.pdb` exists: the `S_COMPILE3`
   record carries the compiler version and, for MSVC PDBs, the exact
   compiler flags (auto-surfaced in the doctor report).  A `.zig-cache`
   module path identifies Zig builds.
4. **Structural heuristics** — `.buildid` section, GNU `0f 1f` nops vs
   MSVC alignment nops / int3 padding, imports, Delphi RTL strings, and
   GCC-arg-passing era (pre-8 push style vs modern accumulate style).
5. **MSVC optimization fingerprint** — wrapper-call codegen in `.text`
   identifies the optimization level the binary was built with: `/O2`
   (load-first `mov eax,[esp+4]; push eax` + `add esp,N`) vs `/O1`
   (push-[mem] `push dword [esp+4]` + `pop ecx`), or `mixed` when both
   styles appear (per-file /O overrides — common in MS products, e.g.
   Win2K's mspaint).  `/O1` vs `/O2` change wrapper codegen, so compiling
   with the wrong level silently breaks byte-matching at every wrapper
   call site.  The fingerprint feeds `rebrew analyze` (Optimization
   line), `rebrew init` (seeds the compiler cflags), and a `rebrew
   doctor` "Optimization level" check that warns on mismatch and points
   mixed builds at per-function flag sweeps.

   **Pre-6.0 constant-caching fingerprint** — a second codegen signal separates
   the MSVC compiler era.  MSVC 4.x/5.0 hoist a small loop-invariant constant
   into a callee-saved register and store it via that register (mov ebx,imm32
   then mov [mem],ebx); MSVC 6.0 folds the constant and emits mov [mem],imm32
   immediates instead.  `toolchain_detect.py` counts store-via-reg sites and
   appends "(pre-6.0 constant-caching codegen; compiler may be MSVC 4.x/5.0)"
   to the version hint when the signal is strong — even when DIE names the
   era 12.00 (MSVC 6.0), because the compiler and the CRT/linker eras are
   independent fingerprints.  This was the missing signal for the Europa 1400
   server (guild-rebrew): its player-init loop caches 1000 in ebx, which
   neither vendored 6.0 compiler (SP0 12.00.8168 or SP6 12.00.8804) produces
   — only MSVC 4.2/5.0 codegen does, so per-function matching of such loops
   needs the pre-6.0 toolchain (msvc5/msvc420), not msvc6.

   **Codegen fingerprint catalog** — the full set of byte-level fingerprints
   the detector uses (VC 7.0+ `lea esp,[esp]` loop-alignment nops, rep
   movs/stos string-op inlining, magic-number division, SSE2 vs x87 FPU,
   `rep ret` GCC idiom, stack-probe symbol names `__chkstk` /
   `___chkstk_ms` / `__aNchkstk` / `__CHK`, 16-bit MZ entry-code scan) is
   documented per compiler version — with verified byte patterns,
   cross-version deltas and "100% unique" markers — in
   [codegen/](codegen/README.md).  Add new fingerprints to the per-version
   file there first, then wire them into `toolchain_detect.py`.


### Per-Function Toolchain Override

A target built with a **mix** of MSVC versions (e.g. the Europa 1400 server:
mostly 6.0 code, with scattered 4.2/5.0-compiled files) cannot be byte-
matched by any single compiler.  `rebrew test`/`verify`/`diff`/`match` all
honor a per-function toolchain:

- `rebrew test <va> --toolchain msvc5` compiles that one function with
  MSVC 5.0 (the `rebrew/msvc:5.0-win32` image) and **persists** the choice
  to `rebrew-functions.toml` (the `toolchain` field, same lifecycle as
  `cflags`), so `verify` and batch `test --all` recompile with the same
  compiler that produced the match.
- The metadata value is read through the normal annotation pipeline
  (`merge_into_annotation` overlays it onto the parsed function), so any
  tool that compiles a function — test, verify, diff, prove, match, the
  GA, flag sweeps — transparently uses the overridden compiler.
- CLI `--toolchain`/`--cflags` still take precedence over the metadata
  value; the override fills the fallback chain (per-function metadata →
  nearest `rebrew-libraries.toml` → project defaults).
- The compile cache keys on the toolchain image id + flags + include-dir
  closure, so functions compiled under different toolchains never share
  cache entries.
- **Execution is docker-only (ADR-008).**  The override selects a
  different *image*, not a patched wine environment: an msvc5 override
  runs `rebrew/msvc:5.0-win32`, whose compiler loads its own matching
  C1.DLL/C2.DLL by construction.  The old host-wine machinery that had to
  retarget `WINEPATH`/`INCLUDE`/`LIB`/`PATH` per override
  (`vendored_msvc_env`) is gone.

Pick the toolchain with `rebrew test --toolchain <name> --json` on each
function and compare match counts; the vendored names are the registry
ids (`msvc5`, `msvc420`, `msvc6`, …) from `rebrew toolchain list`.  The
pre-6.0 constant-caching fingerprint above is the quick triage signal: a
function whose loop hoists a small constant into ebx/esi/edi was built
with MSVC 4.x/5.0, not 6.0.

The check fails when the detected family has no compatible profile
(Delphi: document blockers) and passes with a warning for families that may
only match structurally (Zig under `gcc-pe`).  The check is **arch-aware**:
a 16-bit NE/DOS binary (e.g. Windows 3.x games) only accepts 16-bit-capable
profiles (`msvc1.52`, `msvc15`, `msvc10`, `tc16`, `tc20`, `watcom16`;
`watcom`'s wcc386 is a 32-bit compiler) — configuring `msvc6` on an NE
project passes the family check but would silently produce
`COMPILE_ERROR` for every function, so the arch check catches it with a
concrete fix hint ("switch to msvc1.52 / tc16 / tc20 or document as
blockers").  See
`src/rebrew/toolchain_detect.py` and `profile_matches_detection`.

### Extending the registry (third-party / project-local toolchains)

The toolchain registry is not closed: `rebrew.toolchains` is a setuptools
entry-point group whose members are zero-arg callables returning
`dict[str, ToolchainSpec]` — an installed package can add compilers without
editing rebrew source.  The packaged profiles are the base registry; a
duplicate name between any two sources raises `RegistryError`
(`src/rebrew/registry.py`).

Project-local toolchains that are not packaged declare themselves as TOML
files in the directory named by `REBREW_TOOLCHAIN_OVERLAY_DIR` — each file
is one or more `name = { … }` tables of `ToolchainSpec` fields:

```toml
# /path/to/overlay/mytc.toml
[mytc]
image = "rebrew/custom:1.0-win32"
binary = "mycc"
flags_style = "posix"
obj_ext = ".o"
```

Unknown spec fields are a declaration error; a name colliding with a
packaged toolchain raises `RegistryError`.  Once registered (by either
mechanism) the toolchain is a first-class profile: usable in
`rebrew-libraries.toml`, per-function metadata, and `rebrew test --toolchain`.
`rebrew toolchain list` reports each toolchain's provenance (`origin`:
`packaged`, `entry-point:<module>`, or `data-file <path>`; the human table
shows the column only when a non-packaged toolchain exists), and `rebrew
doctor`'s Cache check reports an unregistered `[cache] backend` before the
first compile.

Three companion extension points make a plugin toolchain fully first-class:

- **`rebrew.flag_sets`** — sweep axes for the GA.  A zero-arg callable
  returning `dict[profile, (Flags, tiers)]` (tiers = `{tier: [axis ids]}`
  with `"full": None` meaning all axes).  Without one, a plugin toolchain
  compiles but `rebrew match --sweep` falls back to the MSVC flag space.
- **`rebrew.toolchain_detectors`** — detection-family alignment.  A zero-arg
  callable returning `dict[family, list[profile]]`; the profile is then
  accepted by `rebrew doctor`'s family check and `rebrew init
  --guess-compiler` for that family (e.g. an MSVC-derivative plugin
  declaring `{"msvc": ["mytc"]}`), and a family the packaged table marks
  un-matchable becomes matchable when a plugin declares profiles for it.
- **`rebrew.binary_detectors`** — recognition of genuinely novel compiler
  families.  A callable `(path) -> ToolchainInfo | None` runs when every
  packaged backend (DIE/PDB/PE metadata/heuristics) leaves the family
  unknown; the first non-None result supplies the family, which then flows
  through the alignment table above.  Together the two groups make a novel
  compiler detectable end-to-end: `rebrew toolchain detect` names it and
  doctor/init accept its profiles.
- **`rebrew.library_presets`** — known-library build settings.  A zero-arg
  callable returning `dict[name, {toolchain, cflags}]`; `library = "<name>"`
  in a `rebrew-libraries.toml` then fills missing fields from it.
- **`rebrew.msvc_versions`** — version-exact MSVC matching.  A zero-arg
  callable returning `dict["build:<n>" | "linker:<M>.<m>", list[profile]]`
  (e.g. `{"build:8168": ["mytc"]}`); the profiles join the version-exact
  `suggested_profiles` for that build/linker era, so the doctor's
  "different compiler build" check accepts an MSVC-derivative plugin for
  the exact build it matches (union per key — a build number is evidence,
  not an identity).
- **`rebrew.binary_loaders`** — parsing of novel container formats.  A
  callable `(path, fmt) -> BinaryInfo | None` runs when LIEF cannot parse
  the file (NE/MZ are already native); the first non-None result is used.

A registered toolchain may declare `bits = 16` in its spec (entry-point or
overlay TOML) to join the 16-bit arch-alignment set — it is then accepted on
x86_16 DOS/NE targets and flagged on 32/64-bit binaries, exactly like the
packaged 16-bit profiles.  Plugin CLI commands (entry-point groups
`rebrew.commands` / `rebrew.multicommands`) group under a dedicated
`Plugins` help panel, separate from the packaged command panels.

`rebrew.flag_sets` and `rebrew.library_presets` are tuning data — a provider
may override a packaged name.  `rebrew.toolchain_detectors` extends the
packaged family sets (union).

### Archived MSVC Toolchains (additional MSVC versions)

The most complete collection is the **`archaic-msvc`** GitHub org — one repo
per compiler version, from VC 2.0 through VC 10.0 (every VC 6.0 SP level,
VC 5.0 + SPs, VC 7.0/7.1, VC 8.0/9.0/10.0).  Download via codeload tarball:

```bash
cd tools
for r in msvc-4.2-win32 msvc-5.0-win32; do   # repo names are lowercase: msvc420 msvc500 ...
  curl -L -o $r.tar.gz "https://codeload.github.com/archaic-msvc/${r,,}/tar.gz/refs/heads/master"
  mkdir -p $r && tar xzf $r.tar.gz --strip-components=1 -C $r
done
```
### The MSVC 1.0–11.0 matrix (complete, docker-packaged)

Rebrew now vendors and containerizes the **entire classic MSVC line**, every
version and every service pack whose compiler binary is preserved publicly.
Each row is a first-class toolchain: a `ToolchainSpec` + pinned sha256 source
(`rebrew toolchain vendor <name>` assembles the host tree; `rebrew toolchain
build <name>` builds `rebrew/msvc:<version>-<arch>` from the same tarball), a
config/init/detect profile, and a smoke-gate golden.

**Standalone use**: the docker build source lives in
[`maci0/rebrew-toolchains`](https://github.com/maci0/rebrew-toolchains)
— Dockerfiles, wrappers, the shared `base` image and the pinned-source
manifest (`sources.json`), with **no compiler binaries in the repo** (every
32-bit image curls its sha256-verified source at build time; the six 16-bit
images document their reconstructed-media tarball prerequisite).  rebrew
sources its `toolchain build`/`vendor` from a checkout of that repo — the
sibling directory by default, overridable via `REBREW_TOOLCHAINS_DIR` (a
missing checkout is an actionable error pointing at
`git clone https://github.com/maci0/rebrew-toolchains ../rebrew-toolchains`).
Any tool — e.g. a `recompile`-style compiler-as-a-service — can build or
pull these images without rebrew itself.

| Profile | Version | CL.EXE | Compiler | Source | Runtime |
|---|---|---|---|---|---|
| `msvc10` | 1.0 (1992, 16-bit) | — | 16-bit Phar Lap | WinWorld floppies, pinned tarball | DOSBox |
| `msvc15` | 1.5 (1993, 16-bit) | — | 16-bit Phar Lap | archive.org `en_vc152`, pinned tarball | DOSBox |
| `msvc1.52` | 1.52 (1995, 16-bit) | — | 16-bit Phar Lap | archive.org `en_vc152_202512`, pinned tarball | DOSBox |
| `msvc200` | 2.0 (1994) | 9.00 | first 32-bit | archaic-msvc `msvc200` | docker |
| `msvc400` | 4.0 (1995) | 10.00.5270 | | itsmattkc `MSVC400` | docker |
| `msvc410` | 4.1 (1996) | 10.10.6038 | | archaic-msvc `msvc410` | docker |
| `msvc420` | 4.2 (1996) | 10.20 | | archaic-msvc `msvc420` | docker |
| `msvc5` | 5.0 (1997) | 11.00.7022 | | archaic-msvc `msvc500` | docker |
| `msvc500sp1` | 5.0 SP1 | 11.00.7022 | (same CL) | archaic-msvc `msvc500sp1` | docker |
| `msvc500sp2` | 5.0 SP2 | 11.00.7022 | (same CL) | archaic-msvc `msvc500sp2` | docker |
| `msvc500sp3` | 5.0 SP3 | 11.00.7022 | (same CL) | archaic-msvc `msvc500sp3` | docker |
| `msvc6` | 6.0 (1998) | 12.00.8168 | RTM..SP3 | archaic-msvc `msvc600` | docker |
| `msvc600sp1` | 6.0 SP1 | 12.00.8168 | (same CL) | archaic-toolchains `msvc600_sp1` (RTM + SP1 fixes; SP1 payload not preserved) | docker |
| `msvc600sp2` | 6.0 SP2 | 12.00.8168 | (same CL) | archaic-toolchains `msvc600_sp2` (RTM + official SP2 payload) | docker |
| `msvc600sp3` | 6.0 SP3 | 12.00.8168 | (same CL) | decomp.me `msvc6.3` (archaic sp3 repo has no Bin/) | docker |
| `msvc600sp4` | 6.0 SP4 | 12.00.8804 | | archaic-toolchains `msvc600_sp4` (headers/libs + Bin) | docker |
| `msvc600sp5` | 6.0 SP5 | 12.00.8804 | (same CL) | archaic-msvc `msvc600_sp5` | docker |
| `msvc600sp6` | 6.0 SP6 | 12.00.8804 | (same CL) | archaic-msvc `msvc600_sp6` | docker |
| `msvc7` | 7.0 (2002) | 13.10.3077 | .NET 2003 build | archaic-msvc `msvc710` | docker |
| `msvc700` | 7.0 RTM | 13.00.9466 | true 7.0 | archaic-msvc `msvc700` | docker |
| `msvc700sp1` | 7.0 SP1 | 13.00.9466 | (same CL) | archaic-msvc `msvc700_sp1` | docker |
| `msvc710` | 7.1 (2003) | 13.10.3077 | | archaic-msvc `msvc710` | docker |
| `msvc710sp1` | 7.1 SP1 | 13.10.6030 | | archaic-msvc `msvc710_sp1` | docker |
| `msvc800` | 8.0 (2005) | 14.00.50727 | | archaic-msvc `msvc800` | docker |
| `msvc800sp1` | 8.0 SP1 | 14.00.50727.762 | | archaic-msvc `msvc800_sp1` | docker |
| `msvc900` | 9.0 (2008) | 15.00.21022 | | archaic-msvc `msvc900` | docker |
| `msvc900sp1` | 9.0 SP1 | 15.00.30729 | | archaic-toolchains `msvc900_sp1` (msvc900 + SP1 compiler) | docker |
| `msvc1000` | 10.0 (2010) | 16.00.30319 | | archaic-msvc `msvc1000` | docker |
| `msvc1000sp1` | 10.0 SP1 | 16.00.40219 | | archaic-msvc `msvc1000_sp1` | docker |
| `msvc1100` | 11.0 (2012) | 17.00.50522 | | archaic-msvc `msvc1100` | docker |

Notes:

- **`msvc15`/`msvc1.52` (16-bit)** compile through their `cl15`/`cl16`
  image wrappers (DOSBox inside the image); objects are 16-bit
  OMF decoded by `rebrew.matcher.omf16` — verified end-to-end (VC 1.5
  produces a parseable `push bp`-style function object).
- **`msvc10` (VC 1.0)** compiles end-to-end: the tree was assembled from
  the WinWorld 3.5" floppy set (SZDD payload decompressed, pinned tarball);
  CL.EXE is a Phar Lap TNT DOS-extender (PE32) that runs headless under
  DOSBox in the image (`cl10` wrapper), producing 16-bit OMF decoded
  by `rebrew.matcher.omf16` — smoke-gated and verified (the object for the
  smoke source is byte-identical to 1.5/1.52's, the shared 16-bit codegen).
- **Service packs share compiler binaries**: the real VC 6.0 compiler line is
  **12.00.8168 through SP3** (the RTM..SP3 driver is byte-identical — sha
  `c2eed74a…` in the pinned `msvc600` tarball; the legacy vendored tree
  carries the `91ca0dde…` build of the same 12.00.8168 version) and
  **12.00.8804 from SP4 on** — verified against the official Microsoft
  **Visual Studio 6 SP4 CD** (archive.org item
  `microsoft-visual-studio-6-sp4-x05-78387-x05-78367d1-2000-microsoft-cd`,
  part numbers X05-78387 / X05-78367D1): its `vc98/bin/cl.exe` is exactly
  12.00.8804, the same binary SP4/SP5/SP6 carry (sha `1bf99f20…`).
- **SP1/SP2/SP4 profiles**: SP1/SP2/SP3 changed no compiler binaries and no
  include headers (verified from the official SP2 disc payload) — the delta
  is CRT/MFC sources+libs and the runtime DLLs.  `msvc600sp1` and
  `msvc600sp2` therefore share msvc6's byte-identical smoke object; the
  `msvc600sp1` tree is a reconstruction (RTM + the SP1-fixed files from the
  cumulative SP2 payload) because the standalone SP1 payload
  (`VSE600SP1.EXE`) is not preserved in any public archive — see the repo
  README.  `msvc600sp4` carries the SP4 headers/libs + the 8804 compiler
  (decomp.me `msvc6.4` Bin, sha-verified byte-identical to the SP4 CD).
- **VC 2008 SP1 compiler closed**: `msvc900sp1` carries cl.exe 15.00.30729.01
  (Professional-edition build; the SP1 patch also ships Standard/Team
  variants) extracted from the official VS2008 SP1 DVD — this was previously
  "the only real gap" (`archaic-msvc` publishes only base `msvc900`).
- **VC 11.0**: `msvc1100` (VS 2012, cl.exe 17.00.50522) is the newest
  compiler the `archaic-msvc` org carries.
- **Legacy aliases**: the old `msvc6.3` / `msvc6.6` names are retired — the
  registry names are `msvc600sp3` / `msvc600sp6`.  A config that still says
  `profile = "msvc6.3"` / `"msvc6.6"` is migrated to the modern name at load
  (with a warning), so an old project keeps the right compiler instead of
  falling back to msvc6 RTM or failing with "unknown toolchain"; the legacy
  names also linger in doctor's legacy-path download hints.  `msvc7` keeps its
  historical 13.10.3077 compiler (the canonical `7.0-win32` dir), while
  `msvc700` is the true VC 7.0 build in `7.0-rtm-win32`.

### Provenance & checksums (official releases only)

Every pinned source is an **unmodified official Microsoft release** — the
`archaic-msvc` preservation repos carry the original compiler binaries (not
repacks), and the 16-bit trees come from the original Microsoft media.  The
policy: prefer `archaic-msvc` (GitHub org) for everything it publishes; use
archive.org / WinWorld items only for media archaic-msvc does not carry
(16-bit 1.0/1.5/1.52, and decomp.me `msvc6.3` — the sole public SP3 tarball
with a `Bin/`; the archaic `msvc600_sp3` repo has headers/libs only).

| Source | Original Microsoft release | sha256 (pinned tarball) |
|---|---|---|
| `archaic-msvc/msvc200` | VC 2.0 compiler | `0b058f10…` |
| `archaic-msvc/msvc410` | VC 4.1 compiler | `21486aec…` |
| `archaic-msvc/msvc420` | VC 4.2 compiler | `651db241…` |
| itsmattkc `MSVC400` | VC 4.0 compiler | `c076ab51…` |
| `archaic-msvc/msvc500` | VC 5.0 compiler | `46745771…` |
| `archaic-msvc/msvc500sp1/2/3` | VC 5.0 SP1/SP2/SP3 | `f41e9e5a…` / `55113750…` / `cdba2878…` |
| `archaic-msvc/msvc600` | VC 6.0 compiler (8168) | `19b72020…` |
| `archaic-toolchains/msvc600_sp1` | VC 6.0 SP1 tree (RTM + SP1 fixes; reconstruction) | `2c3d1a6d…` |
| `archaic-toolchains/msvc600_sp2` | VC 6.0 SP2 tree (RTM + official SP2 payload) | `088cd189…` |
| decomp.me `msvc6.3` | VC 6.0 SP3 payload w/ Bin (only source) | `84f73e71…` |
| `archaic-toolchains/msvc600_sp4` | VC 6.0 SP4 tree w/ Bin (headers/libs + msvc6.4 Bin) | `7aeb03f6…` |
| `archaic-msvc/msvc600_sp5` | VC 6.0 SP5 full product tree | `a95a9c17…` |
| `archaic-msvc/msvc600_sp6` | VC 6.0 SP6 full product tree | `7c2aa3dd…` |
| `archaic-toolchains/msvc900_sp1` | VC 9.0 SP1 tree (msvc900 + 15.00.30729 from VS2008 SP1 DVD) | `33a66c77…` |
| `archaic-msvc/msvc1100` | VC 11.0 / VS 2012 (17.00.50522) | `adba1882…` |
| `archaic-msvc/msvc700` | VC 7.0 (2002) compiler (13.00.9466) | `5f75462f…` |
| `archaic-msvc/msvc700_sp1` | VC 7.0 SP1 | `bc130062…` |
| `archaic-msvc/msvc710` | VC 7.1 (.NET 2003) compiler (13.10.3077) | `618e876b…` |
| `archaic-msvc/msvc710_sp1` | VC 7.1 SP1 | `44246ff2…` |
| `archaic-msvc/msvc800` | VC 8.0 (2005) compiler | `ab819164…` |
| `archaic-msvc/msvc800_sp1` | VC 8.0 SP1 | `9b53b515…` |
| `archaic-msvc/msvc900` | VC 9.0 (2008) compiler | `9121d184…` |
| `archaic-msvc/msvc1000` | VC 10.0 (2010) compiler | `5f0b4486…` |
| `archaic-msvc/msvc1000_sp1` | VC 10.0 SP1 | `2e5fbb9b…` |
| archive.org `en_vc152` | VC 1.5 (1993) 16-bit media | pinned `msvc15.tar.xz` |
| archive.org `en_vc152_202512` | VC 1.52 (1995) 16-bit media | pinned `msvc152.tar.xz` |
| WinWorld `visual-c/1x` (3.5\" floppy set) | VC 1.0 Professional (1992) 16-bit media | pinned `msvc10.tar.xz` |
|
| **Gap preservation repos** | the toolchains archaic-msvc does not carry — VC 1.0/1.5/1.52/4.0, 6.0-SP1/SP2/SP4 with their Bin (SP1/SP2 reconstructed from the official SP payloads, SP1 documented as not preserved standalone), 9.0-SP1's 15.00.30729 compiler, plus the non-MSV C line (Borland C++ 5.5, Turbo C 2.0/3.1, Open Watcom 2.0, Delphi 1.0) — are published one-per-repo at **`github.com/archaic-toolchains`** — same tree format, READMEs with provenance + checksums | — |

Full sha256 values live in `_SOURCES` (`src/rebrew/toolchain.py`) — the
Dockerfiles verify them at build time and `rebrew toolchain vendor` refuses a
mismatch, so a changed source fails loudly.  `rebrew toolchain smoke` then
gates byte-reproducibility: every image-backed MSVC profile — `msvc10`
(16-bit) included — has a golden object hash.
### 16-bit Windows NE Binaries (native parsing + disassembly + byte matching)

`rebrew` primarily targets 32-bit PE/ELF/Mach-O with MSVC6/MinGW, but
**16-bit Windows 3.x NE executables** (MZ stub + `NE` header — e.g. 1990s
DOS/Windows games and Borland Delphi 1.0 apps) are now parsed natively:

1. **NE parsing — DONE** (`src/rebrew/ne_loader.py`): MZ `e_lfanew` → NE
   header (segment table with sector math, resident name table = exports,
   module reference + imported names = Win16 imports).  Segments become
   `BinaryInfo` sections with synthetic flat VAs `(segment << 16 | offset)`,
   so `load_binary`, `extract_raw_bytes`, `rebrew strings`, and `rebrew
   analyze` work on NE targets.  A capstone-based probe classifies code vs
   data segments: Borland segments carry a `[index\x00][name-string][content]`
   marker (detected conditionally — MSVC 16-bit segments start directly with
   code and the probe does not skip bytes for them).  `is_ne` reads the
   signature at `e_lfanew` (Borland puts it at 0x40; the MSVC 16-bit linker
   places it at 0x400, past a fixed stub read).
2. **16-bit disassembly — DONE**: the `x86_16` arch preset (`CS_MODE_16`,
   2-byte pointers) makes `asm`, `similar`, and `cu_map` disassemble
   segmented x86-16 (far calls, segment registers).
3. **Function enumeration — DONE**: `rebrew.ne_loader.enumerate_ne_functions`
   runs a 16-bit linear sweep (`push bp` / `enter` prologs, `ret`/`retf`
   epilogs) that handles both conventions — Borland (skip marker+name) and
   MSVC (code from offset 0, with the segment entry forced as a function
   start since MSVC entry code opens `push ds/pop ax/nop/inc bp`).
   holiday.exe (Borland) → 1783 functions; ski16.exe, the original 1991
   16-bit SkiFree (MSVC) → 137.
4. **Strings — DONE for Delphi**: NE targets scan data segments and recognize
   Pascal (length-prefixed) strings in addition to ASCII/UTF-16 runs.
5. **Toolchain detection — DONE**: `detect_toolchain` identifies NE targets
   by their segment markers — Borland markers → `delphi` (high confidence),
   markerless segments with content → `msvc` (16-bit MSVC-style) — falling
   back to RTL string evidence when segments are absent.
6. **16-bit compile profile / byte matching — DONE**: the `msvc1.52`
   profile (Microsoft C 1.52, 16-bit, via the `rebrew/msvc:1.52-win16`
   DOSBox image; the vendored `rebrew-toolchains/msvc/1.52-win16` host
   path backs the standalone `rebrew.msvc16` research module) compiles
   C89 to 16-bit OMF objects, decoded by the built-in
   `omf16` parser (objconv crashes on both the unoptimized 0xA0 and
   /O-optimized 0xC2 dialects; reloc slots: e8/e9 rel16, absolute disp16,
   and far-call 9a/ea via capstone).  `rebrew test`, `verify`, and
   `match --flag-sweep-only` (memory-model axis `/AS /AM /AC /AL`) all work
   on 16-bit NE targets.
   The GA sweep for msvc1.52 covers 75 targeted combos through the image.
   NOTE: the vendored `rebrew-toolchains/msvc/4.2-win32` is the *32-bit* VC
   4.2 compiler (i386 COFF output) — NOT suitable for 16-bit matching.

The workflow for a 16-bit target is: `rebrew intake <ne.exe>` (enumerates +
documents every function as a STUB blocker — Delphi functions are marked
audit-only in `rebrew todo -c documented`), `rebrew analyze <ne.exe>` for the
intelligence dossier (format, toolchain family, imports, strings),
`rebrew asm <va>` for disassembly.  For byte matching, configure
`profile = "msvc1.52"` in `rebrew-project.toml` — `rebrew verify` then runs
the full compile/compare loop (137 functions on ski16.exe compile through
DOSBox with 0 COMPILE_ERROR).

**Delphi 1.0 toolchain (vendored, verified working):** for 16-bit *Delphi*
targets (e.g. `holiday.exe`, a Delphi 1.0 VCL app),
`rebrew-toolchains/delphi/1.0-win16/source/` now ships the exact
command-line toolchain — `DCC.EXE` (Delphi Compiler 8.0,
Sep 1995), `DELPHI.DSL` (compiler symbol table), the `CMDLINE.PAK` tools,
and the RTL/VCL units (`UNITS.PAK` + `LIB.PAK`).  It compiles real 16-bit
NE 6.01 GUI executables; the working recipe and the reverse-engineered
**Quantum archive format**
(`rebrew-toolchains/delphi/1.0-win16/source/pak_extract.py`) are documented
in `rebrew-toolchains/delphi/1.0-win16/source/README.md`.  Delphi's
Borland ABI has no matchable rebrew compiler profile — functions are
documented as blockers, but the toolchain is used for verification-style
research (compile + NE parse).

Layout: `bin/cl.exe` + `include/` + `lib/` (case varies by version).  The
`msvc420` profile is backed by this source; `msvc5` (VC 5.0, 11.00.7022) is
validated against real Microsoft VC5.0 product binaries (e.g. `BIND.EXE`).

decomp.me also maintains win32 compiler data (`github.com/decompme/compilers`,
`platforms/win32/`); its toolchains are published by
`github.com/OmniBlade/decomp.me/releases/download/msvcwin9x/` (a subset —
msvc6.0/6.3/6.4/6.5/6.5pp/6.6/7.0 only, no Lib dir):

| Version | File | CL version | Notes |
|---------|------|------------|-------|
| msvc6.0 | `msvc6.0.tar.gz` (6.2 MB) | 12.00.x | same SP line as the local master |
| msvc-6.0-sp3-win32 | `msvc-6.0-sp3-win32.tar.gz` (6.6 MB) | 12.00.8168 | **SP3 — codegen differs from SP6** |
| msvc-6.0-sp6-win32 | `msvc-6.0-sp6-win32.tar.gz` (6.6 MB) | 12.00.8804 | **SP4+ driver — distinct from `msvc6`'s RTM..SP3 8168** |
| msvc-7.0-win32 | `msvc-7.0-win32.tar.gz` (33 MB) | 13.10.3077 | **VC7 — enables the `msvc7` profile** |
| msvc4.x/7.1/8.0 | not published | — | document + skip |

Layout notes (differ from the local `rebrew-toolchains/msvc/6.0-win32/source/VC98/...`):

- msvc-6.0-sp3-win32/6.6: `Bin/CL.EXE`, `Include/`, **no `Lib/`** (compile-only; link with
  a full toolchain's Lib, e.g. the master's).
- msvc-7.0-win32: `Bin/cl.exe` (lowercase!), `Include/`, `MFC/`, **no `Lib/`**.

When the master (`rebrew-toolchains/msvc/6.0-win32`,
`rebrew-toolchains/msvc/7.0-win32`) is absent, `rebrew init
--compiler msvc6|msvc7` and the config layer resolve the best present layout
instead (newest mirror first) so a fresh project compiles out of the box
rather than pointing at a master path that does not exist.
  Case matters on Linux — point `[compiler] command` at the lowercase file.

Fetch + extract (kept out of git — `tools/` is ignored; ~75 MB total):

```bash
cd tools
for v in msvc-6.0-sp3-win32 msvc-6.0-sp6-win32 msvc-7.0-win32; do
  curl -L -o $v.tar.gz https://github.com/OmniBlade/decomp.me/releases/download/msvcwin9x/$v.tar.gz
  mkdir -p $v && tar xzf $v.tar.gz -C $v
done
```

`rebrew init --compiler msvc600sp3|msvc600sp6` sets up the profiles (the
dir names above are the decomp.me mirror names; the registry ids are
`msvc600sp3` / `msvc600sp6`); each is proven by
`tests/test_toolchain_roundtrip.py` (compile → compare → EXACT; skipped when the
tarballs are absent).  Round-trip validation: compile a snippet with the
toolchain, link against a full toolchain's Lib, intake the result, and
`rebrew test` the source — the profile is correct when it classifies EXACT.
---

## Disassemblers & Decompilers

### Ghidra (Primary)

Connected via ReVa MCP (Model Context Protocol). Rebrew uses the following MCP tools:

| Capability | MCP Tool |
|------------|----------|
| Decompilation | `get-decompilation` |
| Cross-references | `find-cross-references` |
| Memory reads | `read-memory` |
| String search | `search-strings-regex`, `get-strings-by-similarity` |
| Labels and comments | `create-label`, `set-comment`, `set-bookmark` |
| Structure editing | `parse-c-structure`, `modify-structure-from-c` |
| Data flow | `trace-data-flow-backward`, `trace-data-flow-forward` |
| Imports/exports | `list-imports`, `list-exports`, `find-import-references` |
| Call graph | `get-call-graph`, `get-call-tree` |
| Vtable analysis | `analyze-vtable` |

See [GHIDRA_SYNC.md](GHIDRA_SYNC.md) for the sync feature matrix and known issues.

### radare2 / rizin

Used for decompilation backends (r2ghidra, r2dec) and as an alternative analysis
perspective. Rebrew auto-detects whichever is installed (`rz` preferred over `r2`).

**Data files consumed by rebrew:**
- `functions.txt` — Human-readable function list (VA, size, name) — tool-agnostic format
- `function_structure.json` — Ghidra function list (consumed by `rebrew skeleton`, `rebrew todo`)

**Known issues:**
- r2/rz occasionally report bogus sizes for some functions
- r2 names use `fcn.XXXXXXXX` and `sub.DLL_funcname` conventions

### IDA / Binary Ninja

Not integrated into the pipeline. Potential uses:
- Cross-validation of function boundaries (third opinion vs Ghidra/r2)
- MSVC CRT signature matching (Binary Ninja has built-in MSVC sigs)
- FLIRT-based CRT identification (IDA)

---

## Binary Analysis Tools

### DUMPBIN.EXE (MSVC6)

Part of the MSVC6 toolchain. Run via the docker image (wine entrypoint inside the image):

```bash
docker run --rm -v "$PWD":/work -w /work rebrew/msvc:6.0-win32 /c t.c
# ... or reach the image's own tools via the wine entrypoint:
docker run --rm -v "$PWD":/work -w /work --entrypoint wine rebrew/msvc:6.0-win32 /opt/msvc6.0/VC98/Bin/DUMPBIN.EXE /EXPORTS target.dll
docker run --rm -v "$PWD":/work -w /work --entrypoint wine rebrew/msvc:6.0-win32 /opt/msvc6.0/VC98/Bin/DUMPBIN.EXE /IMPORTS target.dll
docker run --rm -v "$PWD":/work -w /work --entrypoint wine rebrew/msvc:6.0-win32 /opt/msvc6.0/VC98/Bin/DUMPBIN.EXE /HEADERS target.dll
docker run --rm -v "$PWD":/work -w /work --entrypoint wine rebrew/msvc:6.0-win32 /opt/msvc6.0/VC98/Bin/DUMPBIN.EXE /DISASM /RAWDATA:1 some_file.obj
```

### objconv

COFF/PE/ELF/OMF format conversion and comp.id extraction (verify compiler version):

```bash
objconv -fasm file.obj /dev/null 2>&1 | grep "comp.id"
```

### objdump (GNU Binutils)

```bash
objdump -x target.dll | grep -A30 "Export Table"   # Dump export table
objdump -d -M intel candidate.obj                   # Disassemble an obj
```

### yara

Signature-based binary pattern matching for bulk identification:

```bash
echo 'rule msvc6_stdcall { strings: $a = { 55 8B EC 83 EC } condition: $a }' > /tmp/test.yar
yara /tmp/test.yar target.dll
```

---

## Python Libraries

### Core Dependencies

| Library | Use in Project |
|---------|----------------|
| **capstone** | x86 disassembly in matcher scoring |
| **diskcache** | Persistent caching for GA compilation results (`matcher/core.py`) |
| **httpx** | HTTP client for Ghidra/ReVa MCP communication (`ghidra/cli.py`, `skeleton.py`, `decompiler.py`) |
| **lief** | PE/ELF/Mach-O parsing — core dependency for `binary_loader.py`, `matcher/parsers.py`, `test.py` |
| **numpy** | Numeric computation |
| **python-flirt** | FLIRT signature matching for library identification (`flirt.py`) |
| **rich** | Terminal formatting |
| **tomlkit** | Comment-preserving TOML editing (`cfg.py`) |
| **tree-sitter** | C source AST parsing for signature and struct extraction |
| **tree-sitter-c** | Tree-sitter C language grammar (used with `tree-sitter`) |
| **typer** | CLI framework with rich help |

### Optional Dependencies

| Library | Purpose | Install |
|---------|---------|--------|
| **angr** | Symbolic execution + Z3 for `rebrew prove` | `uv sync --all-extras` |

### Not Installed (could be added)

| Library | Purpose |
|---------|---------|
| **pyelftools** | ELF parsing (not needed for PE32) |
| **matplotlib** | Plotting / visualization |
| **r2pipe** | Programmatic radare2 access from Python |
| **keystone** | Assembler engine (x86 → bytes) |
| **unicorn** | CPU emulation |

---

## Function Discovery

Multiple tools detect functions independently. Ghidra typically finds the most (most
accurate sizes, includes thunks), while r2 occasionally reports bogus sizes. The catalog
pipeline tracks which tools detected each function via the `detected_by` field.

### Common Discrepancies

| Issue | Details |
|-------|---------|
| Tool count mismatch | Ghidra typically finds more functions than r2 (missed functions or different splitting) |
| 1-byte "functions" | Likely `ret` stubs or alignment — seen by both tools |
| IAT thunks | 6-byte `jmp [IAT]` stubs — not reversible C code |
| Size disagreements | Tools may report different function sizes; `canonical_size` picks the best |

See [NAME_NORMALIZATION.md](NAME_NORMALIZATION.md) for how tool-specific names
are normalized.

---

## Usage Recommendations

### For Function Identification
1. Start with **Ghidra** decompilation (best quality, connected via MCP)
2. Cross-reference with **r2** names for alternative analysis perspective
3. Use **DUMPBIN /IMPORTS** to identify library boundaries
4. Use **yara** rules for bulk pattern identification of CRT/zlib functions

### For Byte Comparison
1. `rebrew diff` for side-by-side disassembly (add `--mismatches-only` for structural diffs only)
2. **objconv** to verify comp.id on compiled .obj files
3. **DUMPBIN /DISASM** for quick .obj inspection

### For Compiler Flag Analysis
1. `rebrew match --flag-sweep-only --tier normal` (~5.4K combos)
2. Use `--tier quick` for fast iteration (192) or `--tier thorough` for deep search (~258K)
3. **objconv** comp.id verification to confirm same compiler
4. Re-sync flags from decomp.me: `python tools/sync_decomp_flags.py`

### For Structure Recovery
1. **Ghidra** structure editor via MCP (`parse-c-structure`, `get-structure-info`)
2. **DUMPBIN /RAWDATA** for raw data inspection at specific offsets
