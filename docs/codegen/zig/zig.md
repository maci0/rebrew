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

## Verification

PDB module scan of a real Zig-built program (`.zig-cache` paths);
codegen claims intentionally absent.  Matching caveat documented in
[TOOLCHAIN.md](../TOOLCHAIN.md).
