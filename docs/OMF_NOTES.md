# OMF object format (Open Watcom and 16-bit MSVC)

Watcom `wcc386` emits **OMF** ("8086 relocatable (Microsoft)") by default.
Every `-bt=` / `-fo=` / `owcc` combination tested produced OMF, not COFF.
LIEF cannot parse OMF. `rebrew.matcher.parsers.parse_obj_symbol_and_relocs`
handles it: a 16-bit MSVC object goes to `rebrew.formats.omf16`, and every
other OMF object is converted with the vendored objconv
(`tools/objconv/objconv`) before the COFF path. The vendored binary is the
fixed build (16-bit relocation methods and COMDAT-to-COFF sections). Stock
objconv 2.52 crashes with "buffer overflow detected: terminated" on MSVC
1.52 objects and on the `/O` dialect below. Rebrew prefers the vendored
binary over a PATH objconv.

## Current parser contract

Record lengths use the full unsigned 16-bit little-endian word, including the
checksum byte. The high bit is part of the length, not a checksum flag. A
truncated high-bit record cannot be mistaken for a shorter complete record.
This does not promise rejection of every malformed tail after code was parsed.

The 16-bit parser locates near-call/jump `rel16` operands from decoded `E8`/`E9`
instructions with two-byte immediates. Those byte values inside another
instruction's immediate are not branch relocations; decoder initialization
failure does not enable a raw-byte scan. Absolute `disp16` and far `ptr16:16`
operands also use decoded instruction positions.
`rebrew.formats.omf16.code_relocs(code, start, end)` returns these slots for
`code[start:end]` as offsets relative to `start`, each mapped to `"rel16"`,
`"disp16"` or `"far16"`. The dated updates below retain
historical observations and labels; their raw `e8`/`e9` scan descriptions are
superseded by this contract.

Record = `[type:1][length:2 LE][data]`. Advance = `3 + length`.

The length includes the checksum byte and uses all 16 bits.
`omf16._record_len` requires the declared body to fit. A zero checksum byte
can mean the checksum is unused; bit 15 is not a checksum flag.

Record names below come from the vendored objconv dump (`-dfhsrn`).
The minimal parser uses selected byte layouts and heuristics rather than
fully decoding OMF records; those behaviors are described separately.

## 32-bit Open Watcom (objconv, then COFF)

Sample (`int g; int f(void) { return g; } int callg(void) { return f() + g; }`),
compiled `wcc386 -zq -fo=tg.o tg.c` (Open Watcom 2.0 beta, Aug 2026).

| Type | Meaning | Notes |
|------|---------|-------|
| `0x80` | THEADR | length-prefixed source name |
| `0x88` | COMENT | comments/auxiliary metadata, not code |
| `0x96` | LNAMES | segment/group names (length-prefixed) |
| `0x99` | SEGDEF | segment defs |
| `0x9A` | GRPDEF | group definitions |
| `0x8C` | EXTDEF | external symbol names |
| `0xA1` | LEDATA32-style code | `[seg:1][offset:4 LE][code…]` |
| `0x9D` | FIXUPP32 | relocation records referencing externals |
| `0x91` | PUBDEF32 | public names to segment/offset |
| `0x8A` | MODEND | module end |

Code bytes live in type `0xA1`: `[seg:1][offset:4 LE][code…]`. In fixture
`tests/fixtures/tg_watcom.o`, `f_` is
`68 04 00 00 00 e8 00 00 00 00 a1 00 00 00 00 c3`: `push 4; call rel32;
mov eax,[disp32]; ret`. The reloc slots are the 4 bytes after `e8` and after
`a1` (offsets 6 and 11, targeting `__CHK` and `_g`). `0x88` bodies
are comments/auxiliary metadata, not segment data.

`objconv -fcoff x.obj -o x.coff` is what the matcher runs. On the sample the
converted COFF has 5 sections and 18 symbol-table records (12 symbols
plus auxiliary records). Open Watcom appends a trailing
underscore (`f_`, `callg_`). `parse_obj_symbol_and_relocs` returns `callg_`
as `68 04 00 00 00 e8 .. .. .. .. e8 .. .. .. .. 03 05 .. .. .. .. c3` with
relocs `{6: __CHK, 11: f_, 17: _g}`.

Detection of "this is OMF" is the first record type in `0x80..0xA0` plus a
plausible length (`matcher/parsers.py`). A 16-bit MSVC object matches that
prefix too, so the 16-bit parser runs first.

## 16-bit MSVC 1.52, unoptimized

No `/O` flag. Record dump of `tests/fixtures/tg_msvc16.obj` (`add` + `main`).

| Type | Meaning (observed) |
|------|--------------------|
| `0x80` | THEADR |
| `0x88` | COMENT: comments/auxiliary metadata |
| `0x96` | LNAMES: segment/group names ("CODE", "DATA", "CONST", "BSS", "_TEXT") |
| `0x98` | SEGDEF (4 segments) |
| `0x99` | SEGDEF32: debug segments |
| `0x9A` | GRPDEF |
| `0x9C` | FIXUPP |
| `0x8C` | EXTDEF, with embedded names (`__aNchkstk`, `__acrtused`) |
| `0xA0` | code: `[seg:1][offset:2 LE][code…]` |
| `0x90` | PUBDEF: publics live here (`_add`, `_main` + offsets; `0x1a` = main) |
| `0xB2` | BAKPAT: backpatch records |
| `0x8A` | MODEND |

`rebrew.formats.omf16` concatenates `0xA0` chunks at their 16-bit offsets and
reads `0x90` as `[len][name][offset:2 LE]` pairs. `_main` at `0x1a` lands at
the second function in the stream. Symbols match across `_add` / `add` /
`add_`, and a Borland Pascal uppercase spelling (`F` for `f`).

The minimal parser does not decode FIXUPP or BAKPAT. It scans every
`e8` / `e9` byte and marks the next two bytes as a rel16 slot, including
local jumps; this is a heuristic, not decoded linker-fixup evidence.
In the fixture, `_add` gets slots 7 and 18, and `_main` gets 7, 20 and 26.
The parser labels each `rel16`; it does not recover `__aNchkstk` by name.

Turbo C and 16-bit Watcom fixtures end `0xA0` LEDATA with a valid checksum
(record sum, type and length included, is 0 mod 256). The unoptimized MSVC
fixture uses a zero checksum that does not satisfy that sum. The parser
drops the last byte only when the sum matches; it consequently retains the
MSVC fixture's zero byte at the end of `_main`.

## 16-bit MSVC 1.52, any `/O` flag

CL 1.52 with any `/O` flag (the GA sweep default, and the init profile's
`cflags: /O1`) emits a different dialect. Mapped on real `/O1` objects.

| Type | Meaning (observed, /O dialect) |
|------|--------------------------------|
| `0x80` | THEADR |
| `0x88` | COMENT: compiler banner, default libs (SLIBCE, OLDNAMES.LIB) |
| `0x96` starting with `00` | LNAMES: initial segment/group names |
| `0x98` | SEGDEF (4 segments, same shape as unoptimized) |
| `0x9A` / `0x9C` | GRPDEF / FIXUPP |
| `0xB0` | COMDEF: communal globals (`[len][name][type…]`) |
| `0xCA` | parser treats as static/local name list (not verified in the shipped fixtures) `[len][name]…` (e.g. `helper`) |
| `0x96` with no `00` prefix | LNAMES containing public names `[len][name]…` (e.g. `_f`, `_callg`) |
| `0xC2` | COMDAT code: `[header][code…][checksum:1]`, one record per function |
| `0x8A` | MODEND |

The parser uses the `00` prefix to distinguish the initial LNAMES list
from subsequent public-name lists; both are type `0x96`.

Code lives in `0xC2`. The trailing byte makes the record sum to 0 mod 256.
Header length depends on the code model, which the parser reads from the
initial LNAMES code-segment name:

- Near-code (`/AS` small, `/AC` compact), segment `_TEXT`: 9-byte header,
  shape `XX 00 00 00 00 00 00 01 NN`.
- Far-code (`/AM` medium, `/AL` large), segment `SRC_TEXT`: 7-byte header,
  `00 01 02 00 00 00 NN`. Functions end in `retf`. Far calls are `lcall` /
  `ljmp` (`9a` / `ea`) with a 4-byte ptr16:16 patch slot. 16-bit Windows 3.x
  games (the skifree16 NE target) use this model.

Name records (`0xCA`, then `0x96`) are in code-record order: function `i`
is code record `i`. Statics in `0xCA` precede the `0x96` publics.

`is_omf16` is true when an `0xA0` or `0xC2` record is present in a
well-framed prefix. Relocs add,
on top of the `e8` / `e9` scan, absolute disp16 operands (`a0`-`a3` moffs,
and modrm `mod=00 rm=110` such as `add ax,[global]` / `push [global]`) and
the far `9a` / `ea` slots. Capstone in 16-bit mode locates the displacement
byte. The byte scan also runs when Capstone handle construction fails; the
Capstone import itself is required. Verified:
`_f` (near) = `{1: disp16}`, `_callg` (near) = `{1: rel16, 5: disp16}`,
`_callg` (far) = `{1: far16, 7: disp16}`.

If `is_omf16` matches but `parse_obj_omf16` returns no code for the
requested symbol, the matcher falls through to objconv. Both the near and
far `/O1` fixtures above decode through the minimal parser. The objconv
conversion needs the vendored fixed build. Stock
objconv errors, and the parse then yields no symbol.
