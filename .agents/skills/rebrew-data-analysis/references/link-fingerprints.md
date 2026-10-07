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
