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

## Record framing

Record = `[type:1][length:2 LE][data]`. Advance = `3 + length`.

The length includes the checksum byte. Bit 15 clear means a checksum byte
follows the data and is counted. Bit 15 set means no checksum.

The 16-bit MSVC dialect below does not use that checksum-in-length rule.
`omf16._record_len` still masks bit 15 and requires the body to fit.

## 32-bit Open Watcom (objconv, then COFF)

Sample (`int g; int f(void) { return g; } int callg(void) { return f() + g; }`),
compiled `wcc386 -zq -fo=tg.o tg.c` (Open Watcom 2.0 beta, Aug 2026).

| Type | Meaning | Notes |
|------|---------|-------|
| `0x80` | THEADR | length-prefixed source name |
| `0x88` | LEDATA | debug/aux data, not code |
| `0x96` | EXTDEF | external symbols (name length-prefixed) |
| `0x99` | SEGDEF | segment defs |
| `0x9A` | PUBDEF | public symbols |
| `0x8C` | FIXUPP | fixups |
| `0xA1` | LEDATA32-style code | `[seg:1][offset:4 LE][code…]` |
| `0x9D` | fixup/reloc table | pairs with `0x8C` |
| `0x91` | symbol table | names to segment/offset |
| `0x90` | MODEND | module end |

Code bytes live in type `0xA1`: `[seg:1][offset:4 LE][code…]`. In the sample,
`68 04 00 00 00 e8 00 00 00 00 a1 00 00 00 00 c3` is `push 4; call rel32;
mov eax,[disp32]; ret`. The reloc slots are the 4 bytes after `e8` and after
`a1`. `0x88` bodies are debug/aux, not segment data.

`objconv -fcoff x.obj -o x.coff` is what the matcher runs. On the sample the
converted COFF has 5 sections and 18 symbols. Open Watcom appends a trailing
underscore (`f_`, `callg_`). `parse_obj_symbol_and_relocs` returns `callg_`
as `68 04 00 00 00 e8 .. .. .. .. e8 .. .. .. .. 03 05 .. .. .. .. c3` with
relocs `{6: __CHK, 11: f_, 17: _g}`.

Detection of "this is OMF" is the first record type in `0x80..0xA0` plus a
plausible length (`matcher/parsers.py`). A 16-bit MSVC object matches that
prefix too, so the 16-bit parser runs first.

## 16-bit MSVC 1.52, unoptimized

No `/O` flag. Record dump of a real `msvc16.compile_c` object (`add` + `main`).

| Type | Meaning (observed) |
|------|--------------------|
| `0x80` | THEADR |
| `0x88` | LEDATA: debug/aux data, not code |
| `0x96` | EXTDEF: segment/group names ("CODE", "DATA", "CONST", "BSS", "_TEXT") |
| `0x98` | SEGDEF (4 segments) |
| `0x99` | segment class/size records |
| `0x9A` | PUBDEF |
| `0x9C` | COMDEF |
| `0x8C` | FIXUPP, with embedded names (`__aNchkstk`, `__acrtused`) |
| `0xA0` | code: `[seg:1][offset:2 LE][code…]` |
| `0x90` | MODEND: publics live here (`_add`, `_main` + offsets; `0x1a` = main) |
| `0xB2` | fixup table |
| `0x8A` | LIDATA |

`rebrew.formats.omf16` concatenates `0xA0` chunks at their 16-bit offsets and
reads `0x90` as `[len][name][offset:2 LE]` pairs. `_main` at `0x1a` lands at
the second function in the stream. Symbols match across `_add` / `add` /
`add_`, and a Borland Pascal uppercase spelling (`F` for `f`).

Relocs are not taken from `0x8C` / `0xB2` (those records are structural and
identical across objects). Every `e8` / `e9` marks a 2-byte rel16 slot:
16-bit MSVC never emits a literal call or jump opcode. Verified: `_add`
relocs at 7 (`__aNchkstk`) and 18 (tail jmp); `_caller` at 7, 20, and 30.

Turbo C and 16-bit Watcom also end an `0xA0` LEDATA with a checksum byte
(record sum, type and length included, is 0 mod 256). MSVC 1.52 does not.
The parser drops that byte when the sum matches, so the code slice has no
spurious tail.

## 16-bit MSVC 1.52, any `/O` flag

CL 1.52 with any `/O` flag (the GA sweep default, and the init profile's
`cflags: /O1`) emits a different dialect. Mapped on real `/O1` objects.

| Type | Meaning (observed, /O dialect) |
|------|--------------------------------|
| `0x80` | THEADR |
| `0x88` | COMENT: compiler banner, default libs (SLIBCE, OLDNAMES.LIB) |
| `0x96` starting with `00` | GRPDEF: group/segment names |
| `0x98` | SEGDEF (4 segments, same shape as unoptimized) |
| `0x9A` / `0x9C` | segment/fixup tables (structural) |
| `0xB0` | EXTDEF: external globals (`[len][name][type…]`) |
| `0xCA` | static/local name list `[len][name]…` (e.g. `helper`) |
| `0x96` with no `00` prefix | public name list `[len][name]…` (e.g. `_f`, `_callg`) |
| `0xC2` | code: `[header][code…][checksum:1]`, one record per function |
| `0x8A` | MODEND |

The `00` prefix is what separates GRPDEF `0x96` from the public-name `0x96`.

Code lives in `0xC2`. The trailing byte makes the record sum to 0 mod 256.
Header length depends on the code model, which the parser reads from the
GRPDEF code-segment name:

- Near-code (`/AS` small, `/AC` compact), segment `_TEXT`: 9-byte header,
  shape `XX 00 00 00 00 00 00 01 NN`.
- Far-code (`/AM` medium, `/AL` large), segment `SRC_TEXT`: 7-byte header,
  `00 01 02 00 00 00 NN`. Functions end in `retf`. Far calls are `lcall` /
  `ljmp` (`9a` / `ea`) with a 4-byte ptr16:16 patch slot. 16-bit Windows 3.x
  games (the skifree16 NE target) use this model.

Name records (`0xCA`, then `0x96`) are in code-record order: function `i`
is code record `i`. Statics in `0xCA` precede the `0x96` publics.

`is_omf16` is true when an `0xA0` or `0xC2` record is present. Relocs add,
on top of the `e8` / `e9` scan, absolute disp16 operands (`a0`-`a3` moffs,
and modrm `mod=00 rm=110` such as `add ax,[global]` / `push [global]`) and
the far `9a` / `ea` slots. Capstone in 16-bit mode locates the displacement
byte. The `e8` / `e9` scan still runs when capstone is unavailable. Verified:
`_f` (near) = `{1: disp16}`, `_callg` (near) = `{1: rel16, 5: disp16}`,
`_callg` (far) = `{1: far16, 7: disp16}`.

If `is_omf16` matches but `parse_obj_omf16` returns no code (the `/O1` and
far-code COMDAT models the minimal parser cannot decode), the matcher falls
through to objconv. That conversion needs the vendored fixed build. Stock
objconv errors, and the parse then yields no symbol.
