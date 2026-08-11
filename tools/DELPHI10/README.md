# Delphi 1.0 command-line toolchain (16-bit, Borland)

The exact compiler family used to build 16-bit Windows 3.x Delphi apps
(e.g. `HOLIDAY/holiday.exe` — Borland Delphi 1.0, German release).

## Provenance

- `CMDLINE.PAK` tools: archive.org `borland-delphi-1.0-de` ("Borland Delphi
  1.0 Deutsch"), `CMDLINE.PAK` → extracted with `pak_extract.py` (see below).
- `DELPHI.DSL` (compiler symbol table, REQUIRED to compile): from the same
  floppy's `BIN.CA1` split archive (`BIN.PAK` = `BIN.CA1` + `BIN.CA2`
  concatenated), also present in the retail CD RUNIMAGE (`Borland Delphi
  1.00 (2-15-1995)(CD)` / `1.02 (8-24-1995)` on WinWorld).
- `DELPHI\LIB\*.DCU` (RTL/VCL units): `UNITS.PAK` + `LIB.PAK` from the same
  floppy, extracted with `pak_extract.py`.
- License: Borland abandonware (1995). Kept for decompilation toolchain
  reproduction, same policy as the other vendored `tools/` compilers.

## The .PAK format (reverse-engineered)

All Delphi 1.0 installer archives (`CMDLINE.PAK`, `UNITS.PAK`, `LIB.PAK`,
`BIN.CA1`/`CA2`, ...) use **Quantum compression** by David Stafford
(Cinematronics, 1993-1995; also a Microsoft CAB method). `pak_extract.py`
in this directory is a from-scratch Python implementation of the format:

- Header: `"DS"` magic, version, file count, table size (window = 2^N),
  flags; per-file: varstring name, varstring comment, size, DOS time/date.
- Data: one continuous arithmetic-coded LZ77 stream (16-bit range coder,
  MSB-first bit reader, 9 adaptive frequency models) with 16-bit checksums
  between files; window up to 2 MB.

Validated byte-for-byte: all 16 `CMDLINE.PAK` outputs match the real files
extracted by the original Quantum GUI (`UNPAQ.EXE` v0.92), and the 0.97
reference archives match the independent `unquantum` reimplementation.

```bash
python3 pak_extract.py -l CMDLINE.PAK          # list
python3 pak_extract.py -x -o out CMDLINE.PAK   # extract
```

## Contents

| File | Purpose |
|------|---------|
| `DCC.EXE` | Delphi 1.0 compiler (DOS DPMI app, needs `DPMI16BI.OVL`) |
| `DELPHI.DSL` | **Compiler symbol table — required.** Provides the built-in units (System, WinTypes, WinProcs, Strings, ...). Without it DCC errors `Error 15: File not found (SYSTEM.DCU)` even though no such file exists anywhere in the product. |
| `MAKE.EXE` / `TDUMP.EXE` / `RLINK.EXE` / `DLIB.EXE` | Borland make / dump / link / lib |
| `BRCC.EXE` / `BRC.EXE` / `CONVERT.EXE` | Resource compilers / converter |
| `HC31.EXE` / `HC31.ERR` | Help compiler (Win31) |
| `RTM.EXE` / `GREP.COM` / `TOUCH.COM` / `DPMI16BI.OVL` | Utilities / DPMI server |

## Running (DOS app — needs DOSBox)

`DCC.EXE` is a 16-bit DOS application. Wine's `winevdm → DOSBox` bridge
(`wine cmd /c "DCC.EXE ..."`) is unreliable on modern wine; the robust path
is to run DOSBox directly with a config that mounts the wine C: drive:

```
[sdl]
fullscreen=false
[cpu]
cycles=fixed 30000
[autoexec]
mount c /home/maci/.wine/drive_c
C:
cd \
C:\DCC.EXE hello.dpr > C:\dccout.txt
exit
```

```bash
SDL_VIDEODRIVER=dummy dosbox -conf dcc.conf -noconsole
cat /home/maci/.wine/drive_c/DCCOUT.TXT   # DOSBox uppercases filenames!
```

Requirements on C: (the DOSBox working directory):

- `DCC.EXE` + `DELPHI.DSL` + `DPMI16BI.OVL` (compiler + symbol table)
- the RTL/VCL units under the unit path (`/u` in `DCC.CFG`, default
  `DELPHI\LIB`): extracted from `UNITS.PAK` + `LIB.PAK`
- source to compile (`hello.dpr`)

A successful compile prints
`5 lines, 1710 bytes code, 258 bytes data.` and produces `HELLO.EXE`, a
valid 16-bit NE 6.01 Windows 3.10 GUI executable (runs under wine).

Note: DOSBox writes FAT-uppercased filenames (`DCCOUT.TXT`, not
`dccout.txt`) — check with the right case or `ls`.

## 16-bit matching in rebrew

Not yet supported: rebrew targets 32-bit PE/ELF/Mach-O. The documented
16-bit path (NE parsing, segment-relative relocs, OMF objects) is in
`docs/TOOLCHAIN.md`.

**Verified (2026-08-11):** the compile → parse loop works end-to-end.
`hello.dpr` compiled headless via the DOSBox recipe above produces a
genuine NE 6.01 executable that `rebrew` loads natively (`is_ne` ✓, 15
functions enumerated with synthetic flat VAs, `detect_toolchain` →
`delphi`).  What's missing for byte matching is the rebrew-side glue: a
`delphi16` compiler profile wrapping this invocation, parsing DCC's
output, and segment-relative relocation comparison in
`smart_reloc_compare`.

**Two hard requirements discovered while staging a self-contained sandbox
(`rebrew.delphi16.compile_ne`):**

1. **`RTM.EXE` (DOS Runtime Manager) must be present** — DCC is a DPMI app
   and its runtime init silently fails without it (no output, no error).
2. **The mounted drive must NOT be on tmpfs** — DOSBox 0.74-3 mishandles
   tmpfs mounts (e.g. `/tmp`): the autoexec shell starts treating commands
   as `cd` ("Unable to change to: ...") and DCC never runs.  The sandbox
   defaults to the user home (`~`) instead of `/tmp`.

Also: DOSBox writes FAT-uppercased output filenames (`HELLO.EXE`,
`DCCOUT.TXT`) — look them up case-insensitively.
