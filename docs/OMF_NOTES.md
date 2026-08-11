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
