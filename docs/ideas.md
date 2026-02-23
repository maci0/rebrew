# Annotation Extension Ideas

Ideas for rebrew-specific annotations that **extend** the [reccmp](https://github.com/isledecomp/reccmp) annotation format. These use unique key names that don't conflict with reccmp's reserved markers (`FUNCTION`, `LIBRARY`, `STUB`, `GLOBAL`, `VTABLE`, `TEMPLATE`, `SYNTHETIC`, `STRING`, `LINE`).

---

## New Annotation Keys (KV lines)

These go beneath the primary marker line and follow the existing `// KEY: value` format.

### `// CALLERS: func_a, func_b`
List of known callers of this function. Useful for traceability and impact analysis when modifying a function.

### `// CALLEES: helper_init, cleanup_object`
List of functions called by this function. Helps build a manual call graph for analysis tools.

### `// XREFS: 0x10001234, 0x10005678`
Cross-reference addresses — locations in the binary that reference this function. Helps with dead code detection and rename propagation.

### `// CONFIDENCE: HIGH | MEDIUM | LOW`
How confident the reverser is in the decompilation accuracy. Unlike STATUS (which tracks binary match quality), CONFIDENCE tracks semantic understanding.

### `// AUTHOR: username`
Who last worked on this function. Useful for large team projects to route review and questions.

### `// REVIEWED: 2026-02-01`
Date of last human review. Helps prioritize re-review of stale decompilations.

### `// DEPENDS: zlib.h, game_types.h`
Header dependencies that the file needs but may not explicitly include. Helps the build system and skeleton generator.

### `// CALLING_CONV: __cdecl | __stdcall | __fastcall | __thiscall`
Explicit calling convention annotation. While often inferrable from the CFLAGS `/Gd` (cdecl) or `/Gr` (fastcall), making it explicit helps tools and reviewers.

### `// RETURN_TYPE: int | void* | BOOL`
Explicit return type annotation. Useful for tools that generate skeletons or function signatures.

### `// PARAMS: int x, char* name, DWORD flags`
Parameter names and types. Helps with skeleton generation and documentation.

### `// STRUCT_REF: MyStruct 0x1C`
Links a function to a struct it operates on, with the struct size. Useful for cross-referencing struct layouts with the functions that manipulate them.

### `// VTABLE_SLOT: 0x18`
For virtual functions, which vtable slot this function occupies. Compatible with reccmp's `VTABLE` marker (which annotates the table itself, not individual slots).

### `// RELATED: similar_func.c, variant_func.c`
Links to related functions that share logic or are variants of each other. Helps with batch refactoring.

---

## New Marker Types

These would be new top-level `// MARKER: MODULE 0xVA` lines, using names that don't collide with reccmp.

### `// DATA: SERVER 0x10025000`
Mark a global data section or variable. Different from reccmp's `GLOBAL` (which is used inside functions for local static/global references). `DATA` would be a top-level marker for standalone data files, similar to how `FUNCTION` is for code.

```c
// DATA: SERVER 0x10025000
// SIZE: 256
// ORIGIN: GAME
// NOTE: lookup table for sprite indices
unsigned char g_sprite_lut[256] = { ... };
```

### `// IMPORT: SERVER 0x10030000`
Mark an IAT (Import Address Table) thunk or imported function. These are functions the binary imports from other DLLs. Not the same as `LIBRARY` (which marks library functions compiled into the binary).

```c
// IMPORT: SERVER 0x10030000
// SYMBOL: _CreateFileA@28
// SOURCE: kernel32.dll
```

### `// PATCH: SERVER 0x10008880`
Mark a function where the decompilation intentionally differs from the original for bug fixes, security patches, or quality-of-life improvements. Tracked separately from `FUNCTION` so tools know not to flag the diff as a regression.

```c
// PATCH: SERVER 0x10008880
// STATUS: MODIFIED
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2 /Gd
// SYMBOL: _bit_reverse
// NOTE: Fixed off-by-one in original
```

---

## Annotation Blocks (Multi-line)

### `// CONTEXT_START` / `// CONTEXT_END`
Bracket a region of context declarations (externs, typedefs) that are not part of the function body but are needed for compilation. Helps tools strip context when comparing or displaying diffs.

```c
// CONTEXT_START
extern int g_counter;
extern void __cdecl helper_func(int);
typedef struct { int x; int y; } Point;
// CONTEXT_END
```

### `// ASM_START` / `// ASM_END`
Bracket inline assembly or asm-reference sections. Helps the linter skip assembly syntax that doesn't follow C conventions.

---

## Semantic Tags

### `// TAGS: hot-path, networking, save-load`
Free-form tags for categorizing functions. Enables filtering and analysis like "show me all networking functions" or "which hot-path functions are still STUB?"

### `// COMPLEXITY: 3`
A 1-5 rating of reverse engineering difficulty. Helps prioritize work and set expectations for AI-assisted decompilation.

---

## Diff & Match Metadata

These capture the fine-grained details of *why* a function is MATCHING rather than EXACT — the kind of information currently buried in `BLOCKER` freetext.

### `// DIFF_BYTES: 89,90`
Exact byte offsets where compiled output differs from the original. More precise than BLOCKER freetext like "register encoding at byte 89". Enables tools to auto-mask known-acceptable diffs.

### `// DIFF_TYPE: register-encoding | instruction-order | reloc-padding`
Categorizes the kind of mismatch. Enables aggregate analysis like "how many functions are MATCHING only due to register encoding?".

### `// REGISTER_HINT: edx+0xc -> ecx+0xc`
Documents specific register encoding differences (very common in guild-rebrew). When the compiler picks a different register but the logic is identical, this captures exactly what the diff is.

---

## Build & Compilation Metadata

### `// PRAGMA: pack(push, 1)`
Required pragma directives. Some functions need `#pragma pack` for struct alignment or `#pragma comment(lib, ...)`. Making this explicit helps the build system and skeleton generator.

### `// EXTERN_COUNT: 5`
Number of extern declarations the file requires. Helps estimate decompilation complexity and dependency surface. Could be auto-calculated by tooling.

### `// INLINE: memset, strlen`
Functions that the compiler inlined in the original binary. Knowing which standard library calls were inlined vs. called helps match the original optimization behavior.

### `// SECTION: .text`
Which PE section the function resides in. Most functions are `.text` but some live in `.rdata` or custom sections. Useful for the binary loader and address validation.

---

## Provenance & History

### `// DECOMPILER: ghidra | ida | manual`
What tool produced the initial decompilation. Helps gauge baseline quality — Ghidra output typically needs more cleanup than IDA, and manual decompilations are usually higher confidence.

### `// ITERATION: 3`
How many times this function has been revised. Higher iteration count suggests either difficulty or evolving understanding. Useful for dashboards and prioritizing review.

### `// ORIGINAL_NAME: FUN_10006e30`
The auto-generated name from the decompiler before human renaming. Preserves the mapping for cross-referencing with decompiler databases.

---

## Struct & Type Metadata

### `// PACK: 1 | 4 | 8`
Struct packing alignment used in this file. Many guild-rebrew functions need `#pragma pack(push, 1)` for network packet structs. Making this a formal annotation helps the build system apply the right packing globally.

### `// BITFIELD: flags:4, type:2, reserved:2`
Documents bitfield layouts within structs. Critical for matching, since compilers lay out bitfields differently depending on packing and platform.

---

## External API & System Annotations

### `// API: kernel32.dll!CreateFileA, ws2_32.dll!sendto`
External API calls made by this function. Useful for understanding OS/network dependencies and for security analysis.

### `// SWITCH: 0x10003280 (8 cases)`
Documents compiler-generated jump tables. These are notoriously hard to decompile and often cause MATCHING mismatches. Knowing the address and case count helps tooling validate switch reconstruction.

### `// SEH: yes`
Whether the function uses Structured Exception Handling (SEH). SEH functions have different prologue/epilogue patterns and are harder to match exactly. The `SKIP` key in `crt_leaveruntimelock9.c` is related — `// SEH: yes` would make this formal.

---

## Compatibility Notes

All of the above are designed to be **ignored** by reccmp's parser — reccmp only recognizes its own marker types (`FUNCTION`, `LIBRARY`, `STUB`, `GLOBAL`, `VTABLE`, `TEMPLATE`, `SYNTHETIC`, `STRING`, `LINE`) and skips unknown `// KEY: value` lines after them. The new KV keys can safely coexist below any reccmp marker.

New marker types (`DATA`, `IMPORT`, `PATCH`) use names not in reccmp's `MarkerType` enum, so they will be classified as `UNKNOWN` by reccmp and skipped. This is safe — reccmp will simply not process them.

