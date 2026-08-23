# Zig (`zig cc`) — codegen patterns

Zig targeting MinGW-w64 (`zig cc` → GNU ld PE output).  **Code shape is
indistinguishable from MinGW GCC** (LLVM codegen behind a GNU-ld
front-end) — there is no verified codegen marker that separates Zig
from MinGW GCC by bytes alone.

**Profiles:** `gcc-pe` (structural matching only — LLVM vs GCC codegen
means byte-exact matching is not expected).

## What is verified

- Same external markers as MinGW GCC: `.buildid` section (GNU ld),
  `0f 1f` GNU nops, few/no CRT imports.  A Zig build looks like a
  MinGW build to every byte-level detector.
- The **only** discriminator is a sibling PDB whose module list
  contains `.zig-cache` paths (via `llvm-pdbutil`) — verified in
  rebrew's PDB backend (a real Zig PDB produced the marker).

## Register conventions / Loops / Switch

- LLVM x86-32 codegen: standard cdecl, `ebx/esi/edi` callee-saved —
  none of it Zig-distinctive vs MinGW.  No per-version Zig codegen
  claims are made here (not probed); each of these template sections
  is deliberately **not verified** for Zig.

## Integer division

- Not verified — no Zig toolchain compile was performed for this
  reference.  (LLVM emits magic-number division like MinGW; nothing
  Zig-distinctive is claimed.)

## FPU

- Not verified — see Integer division.  (LLVM is SSE2-capable like
  MinGW with `-msse2`.)

## Stack probes

- Not verified — see Integer division.

## Prologue & frame pointer

- Not verified — no Zig toolchain compile was performed for this
  reference; the shape is MinGW-GCC-equivalent by construction (see
  above).

## 100% unique to this version

- **None verified.**  No byte-level Zig marker exists in the tested
  toolchain set; the `.zig-cache` PDB path is a *metadata* marker,
  not codegen.

## Version deltas

- Not applicable — no codegen fingerprints to diff.

## Probe13 re-verification — claim stands

`probe13.c` compiled with `zig cc -target x86-windows-gnu -O2` (zig
0.16.0): the object differs from the MinGW GCC one per-function
(different register allocation, `55 89 e5` frame prologues, `0f 1f`
nops) but shares every probe13 family shape — libcall strlen, signed
`char` (`shr al,7` in `c_cmp`), `movzx` for unsigned-char sums,
EAX:EDX 8-byte struct returns.  No zig-vs-gcc byte marker exists in
the probe13 set; the "indistinguishable from MinGW GCC" claim is
re-verified.

## Probe14 re-verification — first byte-level divergences, still not Zig markers

`probe14.c` (zig 0.16.0, -O2): 64-byte memcpy inlines as
`movups`-pair SSE copies (`f2 0f 10 … f2 0f 11 …`, 4×16B) where MinGW
GCC emits a register-block — the first verified byte-level divergence
in the corpus probes.  It is an LLVM codegen style, not a Zig marker
(any LLVM-front-end PE build shows it), so the "no Zig-specific
codegen fingerprint" claim stands, sharpened to: *divergences exist
and are LLVM-family traits, not Zig identifiers*.  Zig also uses
`cmov` for `a ? 7 : 13` (shared with VC 11.0), `shld` for 64-bit
shifts (shared with MSVC 7.0+/GCC/bcc32), and `inc eax` (`40`) for
`g_counter++` (like non-8.0 MSVC, unlike GCC's `83 c0 01`).

## Probe15 re-verification — LLVM traits confirmed

`probe15.c` (zig 0.16.0, -O2): no stack cookies (`push ebp; mov
ebp,esp; push esi; sub esp,0x40` — no cookie load/xor, unlike MSVC
8.0+'s `/GS`); wide-literal sums folded (`mov eax,0x83` like
MSVC 7.0+/GCC); setcc compares in memory (`cmp ecx,[ebp+0xc]; setl
al` like MSVC 8.0+/GCC); stdcall args load in reverse order (`mov
eax,[ebp+0xc]` first — shared with MSVC 5.0–9.0).  Every probe15
divergence from MinGW GCC is an LLVM-family trait, not a Zig
identifier — the claim stands.

## Probe16 re-verification — claim stands

`probe16.c` + `probe16.cpp` (zig 0.16.0, -O2): 64-bit division
libcalls (`__divdi3`-style, frame-staged like GCC); C++ mode
compiles (`zig c++`) with LLVM-style vtable dispatch.  No new
zig-vs-gcc byte marker in either dimension.

- **Corpus pointer** — machine-checked in `corpus.json` (7892 records; the mechanical sweep confirmed this file's records and surfaced no un-documented markers here).

## Probe17: conventions + allocator behaviors

- **Probe17 verified-negative**: the allocator/convention markers are MSVC-internal; Zig follows the shared conventions — no new zig-vs-gcc marker; corpus pointer.

- **Decomp idioms** — the probe19-22 game-idiom signatures for this toolchain are in [DECOMP_IDIOMS.md](../DECOMP_IDIOMS.md) and the corpus (`probe19`-`probe22` records).

## Probe22: guild-rule verification (round 19)

- **Probe22 (Zig/LLVM)**: C24 negation via `cmove` (`0f 44 c1`); switch preamble `movzx`-based (`0f b6 08; 83 c1 fd; 83 f9 66`); flags use dword `test` (`f7 c2`) — no AH-slot ops.  See RULES.md F15/C24.


## Verification

PDB module scan of a real Zig-built program (`.zig-cache` paths);
codegen claims intentionally absent.  Matching caveat documented in
[TOOLCHAIN.md](../../TOOLCHAIN.md).
