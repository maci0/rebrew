# OMF object format — research notes (Open Watcom wcc386)

Watcom's `wcc386` emits **OMF** ("8086 relocatable (Microsoft)") objects by
default — every `-bt=`/`-fo=`/`owcc` combination tested produced OMF, not
COFF.  LIEF cannot parse OMF, so Watcom byte-matching needs an OMF parser
in `matcher/parsers.py` (the README's "Object Parsing ⬜" for Watcom).
This file records the empirical findings from the 2026-08-11 investigation
so the parser starts from ground truth.

## Sample object

```c
int g;
int f(void) { return g; }
int callg(void) { return f() + g; }
```

compiled with `wcc386 -zq -fo=tg.o tg.c` (Open Watcom 2.0 beta, Aug 2026).

## Record framing (critical)

- Record = `[type:1][length:2 LE][data]`.
- **The length includes the checksum byte** — bit 15 of the length *clear*
  means a checksum byte follows the data (and is counted); bit 15 *set*
  means no checksum.  (My first walk misaligned by assuming the opposite.)
- Record advance = `3 + length`.

## Record types observed (tg.o)

| Type | Meaning | Notes |
|------|---------|-------|
| `0x80` | THEADR | length-prefixed source name |
| `0x88` | LEDATA | *debug/aux data records here*, NOT code |
| `0x96` | EXTDEF | external symbols (name length-prefixed) |
| `0x99` | SEGDEF | segment defs (`29 26 00 00 00 08 02 01 04` …) |
| `0x9A` | PUBDEF | public symbols (`07 ff 02 ff 03 …`) |
| `0x8C` | FIXUPP | fixups |
| `0xA1` | **LEDATA32-style code record** | body `01 00 00 00 00 68 04 …` = seg 1, 4-byte offset, then x86-32 code |
| `0x9D` | fixup/reloc table | `a4 06 16 02 01 e4 0b 16 02 02 …` |
| `0x91` | symbol table | `02 01 02 66 5f 00 00 00 00 00 06 63 61 6c 6c 67 …` |
| `0x90` | MODEND | module end |

## Key observations

- The real code bytes live in **type `0xA1` records**: `[seg:1][offset:4 LE][code…]`.
  In the sample, `68 04 00 00 00 e8 00 00 00 00 a1 00 00 00 00 c3` =
  `push 4; call rel32; mov eax,[disp32]; ret` — the reloc slots are the
  4 bytes after `e8` (call target) and `a1` (disp32).
- `0x88` records in this object carry non-code data (the first `0x80`-prefixed
  bodies are debug/aux info — do not treat them as segment data).
- Public symbols are `0x9A` PUBDEF; the symbol table `0x91` maps names to
  segment/offset for function extraction (`f` at `66 5f 00 00 00 00 00`, i.e.
  offset 0x5f66? — verify against `0xA1` code layout when implementing).
- The `0x9D` records pair with `0x8C` FIXUPP for relocations; decode the
  LOCAT offsets to produce the reloc-offset list `parse_obj_relocs_full`
  expects.

## Next steps (when implementing)

1. Parse records into (segments → LEDATA32/A1 code bytes, publics, externals,
   fixups) following the framing above.
2. Wire `matcher/parsers.py::parse_obj_symbol_and_relocs` to detect OMF
   (first record type in `0x80..0xA0` + valid framing) and delegate.
3. Validate reloc offsets against the `e8`/`a1` slots in the sample.
4. Unit-test with a committed tiny OMF fixture (the tg.o bytes) so the
   parser never needs the toolchain installed.

## Update 2026-08-11 — objconv adopted (32-bit OMF)

**objconv** (Agner Fog's object-file converter, vendored at
`tools/objconv/objconv`, ~784 KB single binary) is the LIEF-like tool for
OMF: `objconv -fcoff x.obj -o x.coff` converts OMF→COFF, which the
existing LIEF path parses unchanged.  `matcher/parsers.py` now detects OMF
(first record type 0x80..0xA0) and auto-converts before parsing.

**Verified on the Watcom `tg.o` sample** (converted COFF has 5 sections,
18 symbols — OW appends a trailing underscore: `f_`, `callg_`):
`parse_obj_symbol_and_relocs` returns `callg_` = `68 04 00 00 00 e8 .. .. .. .. e8 .. .. .. .. 03 05 .. .. .. .. c3` with relocs exactly at the
predicted slots — `{6: __CHK, 11: f_, 17: _g}` (the e8 call targets and
the `03 05` disp32).  Watcom (32-bit OMF) byte-matching is therefore
**enabled** — the earlier custom-parser plan is superseded for 32-bit.

**16-bit OMF caveat:** objconv **crashes** ("buffer overflow detected:
terminated") on MSVC 1.52's 16-bit OMF objects.  The 16-bit path still
needs the custom parser (record layout above) — objconv 2.52 only handles
the 32-bit dialect reliably.

## Update 2026-08-11 — MSVC 1.52 16-bit dialect (decoding deferred)

objconv crashes on 16-bit OMF, so the built-in parser was scoped.  Record
dump of a real `msvc16.compile_c` object (test.c: `add` + `main`):

| Type | Meaning (observed) |
|------|--------------------|
| `0x80` | THEADR |
| `0x88` | LEDATA — debug/aux data, NOT code |
| `0x96` | EXTDEF — segment/group names ("CODE","DATA","CONST","BSS", "_TEXT"…) |
| `0x98` | SEGDEF (`48 3c 00 0b 02 01 00` — 4 segments) |
| `0x99` | segment class/size records |
| `0x9A` | PUBDEF (`0f ff 02 ff 03 ff 04 00`) |
| `0x9C` | COMDEF |
| `0x8C` | FIXUPP — carries embedded names (`__aNchkstk`, `__acrtused`) |
| `0xA0` | **code record**: `01 00 00 55 8b ec b8 00 00 e8 00 00 …` (real 16-bit code) |
| `0x90` | MODEND — **publics live here** (`_add`, `_main` + offsets, 0x1a = main) |
| `0xB2` | fixup table (`01 01 04 00 02 00 1e 00 02 00 00`) |
| `0x8A` | LIDATA |

This dialect diverges from both classic OMF and OW's 32-bit OMF (names in
EXTDEF, code in 0xA0, publics in MODEND, no checksum-in-length framing).
Reliable decoding (0xA0 offsets + 0x8C/0xB2 fixup semantics + MODEND
public mapping) needs a focused reverse-engineering effort with more
ground-truth objects — **deferred**; objconv covers the 32-bit Watcom path
in the meantime.

## Update 2026-08-11 — 16-bit MSVC dialect: code extraction DONE

`rebrew.matcher.omf16` now parses the MSVC 1.52 16-bit dialect (wired
into `parse_obj_symbol_and_relocs` as the fallback when objconv crashes):
- `0xA0` records → concatenated code (`[seg:1][offset:2][code...]`)
- `0x90` MODEND → public name/offset pairs (verified: `_main @ 0x1a`
  lands exactly at the second function in the code stream)
- symbol matched across conventions (`_add`/`add`/`add_`)
Verified on real compile_c objects: `_add`/`_main`/`_caller` extract
with correct 16-bit function bytes.  **Relocs are decoded too**: every
`e8`/`e9` opcode marks a 2-byte rel16 slot (16-bit MSVC codegen never
emits literal call/jump opcodes — they are always linker-patched) —
verified: `_add` relocs at 7 (__aNchkstk call) + 18 (tail jmp); `_caller`
at 7/20/30 (chkstk, intra-module call, global disp16).  The 0x8C/0xB2
records are structural (identical across objects); the e8/e9 scan is the
reliable reloc source.

## Update 2026-08-11 (2) — /O-optimized dialect: record layout differs

CL 1.52 compiled with **any /O flag** (the GA flag sweep's default — and
the init profile's default `cflags: /O1`) emits a *different* dialect than
the unoptimized one above.  Empirically mapped on real `/O1` objects
(`g` + `f` + `callg`; `glob1/glob2` + static `helper` + `alpha`/`beta`):

| Type | Meaning (observed, /O1 dialect) |
|------|----------------------------------|
| `0x80` | THEADR |
| `0x88` | COMENT — compiler banner, default libs (SLIBCE, OLDNAMES.LIB) |
| `0x96` | GRPDEF (**starts with `00`** — group/segment names) |
| `0x98` | SEGDEF (4 segments, same shape as unoptimized) |
| `0x9A` / `0x9C` | segment/fixup tables (structural) |
| `0xB0` | EXTDEF — external globals (`[len][name][type...]`) |
| `0xCA` | **static/local name list** `[len][name]...` (e.g. `helper`) |
| `0x96` (no `00` prefix) | **public name list** `[len][name]...` (e.g. `_f`, `_callg`) |
| `0xC2` | **code record**: `[header:9][code...][checksum:1]` — one per function |
| `0x8A` | MODEND |

Key facts:
- **Code lives in `0xC2` records** — 9-byte header (constant shape
  `XX 00 00 00 00 00 00 01 NN`), then the function bytes, then a trailing
  checksum byte (whole record sums to 0 mod 256).  One record per function.
- **Name records (0xCA then 0x96) are in code-record order** — function
  `i` maps to code record `i`.  Static functions appear in 0xCA *before*
  the 0x96 publics, in stream order, matching the 0xC2 code order.
- The unoptimized GRPDEF `0x96` starts with a `00` group-index byte; the
  optimized public-list `0x96` does not — that byte disambiguates the two.
- objconv buffer-overflows on this dialect too; the built-in parser handles
  both via `rebrew.matcher.omf16` (detect 0xA0 *or* 0xC2 code records).
- Relocs: same `e8`/`e9` rel16-slot scan applies; disp16 relocs (e.g.
  `a1 00 00` = `mov ax,[global]`) are not yet decoded (documented gap).
