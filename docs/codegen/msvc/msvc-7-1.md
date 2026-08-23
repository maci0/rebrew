# MSVC 7.1 — codegen patterns

MSVC 7.1 (VS .NET 2003, CL 13.10.3077; SP1 = 13.10.6030).  The last pure
x87 MSVC of the .NET era; codegen-identical to 7.0 for the probe.

**Profiles:** `msvc7`, `msvc710`, `msvc710sp1` — Rich builds 3077
(RTM), 6030 (SP1); linker 7.10.

## Prologue & frame pointer

- `/O2`: no frame pointer; args `[esp+4]`+.  Unoptimized: `55 8b ec`
  (smoke `msvc710/t.obj`).

## Argument passing

- Direct `[esp+N]` loads; /O1//O2 wrapper styles unchanged.

## Register conventions

- Same as 7.0: `movzx` for unsigned char (`movzx edi,[ecx+esi]`),
  `ebx/esi/edi` callee-saved.

## Integer division

- Magic + post-shift (`shr edx,N`) — identical to 7.0
  (`0xAAAAAAAB; mul; shr edx,1; mov eax,edx`).

## FPU / SSE

- Pure x87; `.rdata` constants; unchanged.

## Loops

- `lea esp,[esp]` (`8d 64 24 00`) loop-alignment nops — verified in
  `bigstack`/`csum` (3 at /O2), same as 7.0.
- `strcmp_like`/`sw` show `mov edi,edi` (`8b ff`) used as 2-byte
  alignment padding inside code (`000e: 8b ff` before the loop) — the
  hotpatch-era 2-byte nop.  Observed; also present as padding in VC 6.0
  linked binaries, so not a version-exclusive marker.

## String ops

- `rep stosd`/`rep movsd` unchanged.

## Padding & nops

- Same ladder as 7.0 (`90`/`8b ff`/`8d 74 26 00`/`8d a4 24`) + the
  intra-body `8d 64 24 00`.

## Stack probes / Switch dispatch

- `mov eax,<size>; call __chkstk`; dense jump tables — unchanged.

## Optimization fingerprints

- Same wrapper styles; loop heads aligned with `8d 64 24 00`.

## 100% unique to this version

- **None proven.**  7.1 is codegen-indistinguishable from 7.0 for
  probes 1–5 (same object sizes: 473B /O2; same nops, tails,
  wrappers; `fcmp2` keeps the `fucompp` style — see
  [msvc-7.md](msvc-7.md) for the 7.0-SP1 flip).  Identity via Rich
  build (3077/6030) + linker 7.10.
- **Service pack:** 7.1 SP1 is codegen-identical to 7.1 RTM (probes
  1–5, /O1 and /O2).

## Version deltas

- From VC 7.0: nothing verified in codegen.
- To VC 8.0: /GS security cookies arrive (default-on for buffer
  functions); `lea esp,[esp]` counts drop slightly in the probe (8.0:
  2 vs 7.x: 3).

## Probe12: static-helper inlining — verified positive

Small static helpers inline at /O2 and /O1 (11–12B callers) — VC 7.1
shares VC 7.0's inlining marker; 7.1 SP1 is identical to RTM on this
feature (SP spot-check).  Verified in probe12 (`f1`/`f2`/`fl`).

## Probe13: string intrinsics — verified

- **strlen is inlined as a manual scan loop** at /O2 — `lea edx,[eax+1];
  mov cl,[eax]; inc eax; test cl,cl; jnz; sub eax,edx`
  (`8d 50 01 8a 08 40 84 c9 75 f9 2b c2`) — the 7.0+ form; the
  `repne scasb` intrinsic ends at 6.0.
- **memcmp(8B) keeps `repe cmpsb` (`f3 a6`)** at /O2 — 7.0/7.1 are
  the LAST versions with the rep-string form (8.0+ switch to a
  dword-compare loop).

## Probe14: statement idioms — verified

- **64-bit shifts inline `shld`/`shrd`** — `i64 << 4` = `shld
  edx,eax,4; shl eax,4` (`0f a4 c2 04 c1 e0 04`) — from 7.0 on
  (shared with GCC/bcc32/Zig; the 5.0/6.0 `jmp __allshl` tail-call
  is MSVC-unique to them).
- **64-byte memcpy = `rep movsd`** (`b9 10 00 00 00 f3 a5`), shared
  by every MSVC version.
- **zero-compare era** — `a == 0` = load + `test` + `setz` at /O2
  (5.0–7.1 form; 8.0+ compares in memory against the zero register).

## Probe15: setcc + wide literals — verified

- **setcc loads BOTH operands** — `a < b` = register-form `cmp
  ecx,edx; setl al` (the 5.0–7.1 form; 8.0+ compare in memory).
- **wide-literal sums are CONSTANT-FOLDED from 7.0** — `L"AB"[0] +
  L"AB"[1]` compiles to `mov eax,0x83`; VC 2.0–6.0 (and
  bcc32/Watcom/TC) load the literal from memory.  Shared with
  GCC/Zig — family-level era marker.
- **stdcall args load in REVERSE order** — the 5.0–9.0 form.

## Probe16: 64-bit division + C++ — verified

- **64-bit division = register-load + 4-push helper call** — the
  5.0–10.0 form; /O1 uses the compact 4× memory-push in every
  version.
- **C++ `new`/`delete` TAIL-JUMP from 7.0** — `jmp <operator
  new>`/`jmp <operator delete>` (5.0/6.0 call + ret instead).
  Vtable dispatch uniform `mov eax,[ecx]; call [eax]`.

- **Corpus pointer** — machine-checked in `corpus.json` (7892 records; the mechanical sweep confirmed this file's records and surfaced no un-documented markers here).

## Probe17: conventions + allocator behaviors

- **Probe17 allocator/conventions**: `-1` register form; zero in EAX; inline sret construction.  See RULES.md A8/B5.

- **Decomp idioms** — the probe19/20 game-idiom signatures for this toolchain are in [DECOMP_IDIOMS.md](DECOMP_IDIOMS.md) and the corpus (`probe19`/`probe20` records).

## Verification

Probe `/O1`/`/O2` via `rebrew/msvc:7.1-win32` (`msvc710_{O1,O2}.obj`);
smoke `msvc710/t.obj`, `msvc710sp1/t.obj`, `msvc7/t.obj` (all
unoptimized `_add`, byte-identical).
