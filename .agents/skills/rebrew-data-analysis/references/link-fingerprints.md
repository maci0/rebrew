# Link fingerprints of discarded code (MSVC 6 LINK)

Read when every function and data row matches but whole-image bytes still differ
in the import address table, the hint/name table, `.reloc` size, or the order of
library-member `.bss`/`.data`.

A game or engine is often built from source files shared between several
binaries (client and server, editor and runtime). VC6 `/O2` implies `/Gy`, so
`/OPT:REF` discards every function the target never calls. Discarded code is
gone from `.text`, but LINK made several decisions before it discarded it, and
those decisions stay in the output:

| Effect of a discarded function | Where it shows |
|---|---|
| A CRT reference loads that archive member, at that point in the load order | Order of library `.bss`/`.data`, and which imports load when |
| An API reference loads that import member | IAT slot order and hint/name order, though the import itself is dropped |
| Each absolute-address (DIR32) relocation counts into the `.reloc` reservation | `.reloc` VirtualSize, `SizeOfImage`, file size |

## Facts, measured with LINK 6.00.8447 and MSVCRT 6.0.8797

- **Load order.** All command-line `/INCLUDE` symbols enter the unresolved list
  first, then each object's references in object order. A `/include` in an
  object's `.drectve` (`#pragma comment(linker, "/include:...")`) enters when
  that object is read, and a static library member's directive enters only when
  the member loads. Members load in list order, library by library, in
  command-line order; the default libraries follow. `/VERBOSE` prints the exact
  sequence (`Found`, `Referenced in`, `Loaded`).
- **Hint/name table.** `.idata$6` is emitted in import load order, so the
  reference's hint/name table records the original link's import load order.
- **IAT order.** LINK sorts the `.idata$4` and `.idata$5` contributions with the
  `qsort` of the runtime LINK runs on, comparing only the module file name
  (`KERNEL32.dll`). The array holds every loaded import member in load order,
  including members whose import `/OPT:REF` later drops, plus each DLL's null
  thunk; then each null thunk moves to the end of its DLL's run. VC6 `qsort`
  takes the middle element as pivot (no median-of-three) and selection-sorts
  runs of 8 or fewer, keeping the leftmost maximum. With equal keys this is a
  fixed shuffle of the input, so one extra dropped import anywhere can reorder
  most slots.
- **Dropped DLLs leave a name.** If every import of a DLL is dropped, LINK still
  emits that DLL's name string in the import area. A reference without that
  string had no such DLL among its inputs.
- **`.reloc` VirtualSize** is a reservation of `12 * N` bytes, N counting input
  DIR32 records, including those in discarded functions and discarded data
  COMDATs (REL32 call records do not count), up to a page-span bound that a
  large image does not reach. The emitted directory size is the real record
  count, so a short VirtualSize with every site present means discarded inputs
  are missing.
- **The Rich header counts inputs.** Each `@comp.id` record counts linked
  objects per tool and build: game objects (C compiler), library C members,
  weak-alias objects, import members. Comparing the reference's counts with the
  build's gives the exact number of missing objects, members, and imports.

- **Inverting the IAT.** Because the sort compares only the DLL name, the slot
  permutation depends only on the DLL-key sequence of the array, not on which
  entries are dropped. Model the array as blocks (each DLL's live imports in
  hint/name order plus h, w, ... dropped entries per block, and the null
  thunks), compute the permutation per block-count split, and let a constraint
  solver pick which positions are dropped so every DLL's live imports land in
  the reference's slots. The splits that admit a solution bound how many
  dropped imports each library pass had; a named candidate array (real code's
  imports at their load positions) can then be checked exactly.
- **`/INCLUDE` keeps an import.** An `/INCLUDE:__imp__X` is an `/OPT:REF` root,
  so it cannot force the load position of an import the reference drops; stop
  the forced list before it and let the object that references the import
  load it in object order.
- **Old POSIX names are alias objects.** `OLDNAMES.LIB` members (`mkdir`,
  `getcwd`, `stricmp`, `strcmpi`, `itoa`, ...) are weak-alias objects with the
  same Rich `@comp.id` as LIBCMT's `tcmap` members. OLDNAMES is searched after
  LIBCMT, so code that calls `mkdir` instead of `_mkdir` loads the LIBCMT member
  one library pass later (its imports go after the CRT's), unless a CRT member
  already loaded it. A late alias object also changes the final alignment of
  the import thunks. Each distinct old name counts once.
- **ICF survivor.** LINK sorts every executable COMDAT it resolves (in
  resolution order, before `/OPT:REF`, so discarded code included) with the
  same `qsort` by section size and relocation count, and folds each identical
  section into the first of its run. Which copy of two identical library
  functions survives therefore depends on every executable COMDAT in the link;
  adding discarded code or loading a member in another pass can flip it and
  move all code after it.

- **Third-party sources are compiled whole.** A vendored library (zlib, minizip)
  was built from its complete files; functions the target never calls are
  discarded but still count. A copy trimmed to the kept functions misses their
  DIR32 records and the archive members their CRT calls load (zlib 1.1.3's
  `gzio.c` loads `fprintf`, `_fdopen`, `vsprintf` and `rewind` that way).
  Static data of a discarded function is plain `.rdata`/`.data` and stays.
- **Each object's DIR32 total is measurable.** N is the sum of DIR32 records
  over every input object's sections plus one per import member (its thunk),
  dropped imports included; the discarded part per object follows from the
  `/VERBOSE` "Discarded" lines and the COMDAT symbols.
- **A sibling build may compile code away.** A logging macro that expands to a
  call in one binary and to nothing in another leaves the second without the
  call, its strings and its DIR32 records. A formatted message survives as an
  unused `sprintf` into a local buffer; a literal message leaves no trace.
  Discarded code reconstructed from the sibling then undercounts the target's
  reservation by an amount no image records.
- **Pair storage through functions both images contain.** Align the
  instruction streams of a target function and its sibling copy and pair their
  absolute operands; equal offsets over a range map the sibling's storage onto
  the target's. Function correspondence also works across differently named
  globals: a loader that reads a count and reallocates a buffer to count * 0x60
  identifies the sibling's count and buffer even when the two builds place them
  apart. A bracket between two anchors with one offset is not proof alone: the
  target may hold a different object there.

## Workflow

1. Confirm the gap is whole-image: `rebrew binary relocs --json` reports no
   missing or extra sites, all functions sit at their reference VAs, and the
   remaining differences are IAT slots, hint/name order, or `.reloc` size.
2. Compare the Rich header records of the reference and the build to count the
   missing inputs.
3. Compare hint/name order per DLL with the reference to see which imports load
   early or late; a misplaced one names the archive member that should have
   loaded at that point (`rebrew library inspect <lib> --refs __imp__<Name>@<N>`).
4. Find the discarded code in the sibling binaries built from the same sources:
   their copies of the shared files contain the functions the target dropped.
   Reconstruct those functions in the shared files, written against the
   target's symbols (absolute operands as named symbols, so they produce DIR32
   records), and leave them unreferenced so `/OPT:REF` discards them again.
5. Discarded code must still link: LINK resolves every reference before it
   discards anything, so only functions whose callees and globals exist in the
   target can be in the target's build.
6. After each change, re-test every function in the touched file (a definition
   anywhere in a translation unit can change another function's code) and
   re-measure the image.

Do not fill the gap with invented dead code. The bytes fix only counts and load
positions, not which functions they were; synthetic stand-ins can match the
image while recording nothing true about the original source.
