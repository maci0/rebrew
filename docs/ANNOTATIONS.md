# Annotation Reference

Complete reference for rebrew decomp C file annotations. Compatible with [reccmp](https://github.com/isledecomp/reccmp)'s annotation format.

## Annotation Format

Every `.c` file in the reversed source directory must begin with a header block:

```c
// MARKER: MODULE 0xVA
// STATUS: value
// ORIGIN: value
// SIZE: bytes
// CFLAGS: compiler_flags
// SYMBOL: _decorated_name
```

### Example

```c
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2 /Gd
// SYMBOL: _bit_reverse

int __cdecl bit_reverse(int x)
{
    return x;
}
```

---

## Marker Types

The first line identifies the function type and location.

| Marker | When to use |
|--------|-------------|
| `FUNCTION` | Game code (`ORIGIN: GAME`) that isn't a stub |
| `LIBRARY` | Third-party library code (`ORIGIN: MSVCRT` or `ORIGIN: ZLIB`) |
| `STUB` | Incomplete implementation (any origin, `STATUS: STUB`) |

Format: `// MARKER: MODULE 0xVA`

- **MODULE** — the target identifier from `rebrew.toml` (e.g. `SERVER`, `CLIENT`)
- **VA** — virtual address in the original binary, hex with `0x` prefix

---

## Required Keys

| Key | Values | Description |
|-----|--------|-------------|
| `STATUS` | `EXACT`, `RELOC`, `MATCHING`, `MATCHING_RELOC`, `STUB` | Binary match quality |
| `ORIGIN` | `GAME`, `MSVCRT`, `ZLIB` (or custom per `rebrew.toml`) | Code provenance |
| `SIZE` | Positive integer | Function size in bytes from the original binary |
| `CFLAGS` | Compiler flags string | Flags needed to reproduce the original compilation |

### STATUS values

| Status | Meaning |
|--------|---------|
| `EXACT` | Compiled bytes are identical to the original |
| `RELOC` | Matches after masking relocation addresses |
| `MATCHING` | Functionally equivalent but bytes differ |
| `MATCHING_RELOC` | Functionally equivalent with reloc masking |
| `STUB` | Placeholder, doesn't match yet |

### ORIGIN values

| Origin | Meaning |
|--------|---------|
| `GAME` | Original game code |
| `MSVCRT` | Microsoft Visual C++ runtime library |
| `ZLIB` | zlib compression library |

Custom origins can be added via `rebrew.toml` → `origins = ["GAME", "MSVCRT", "ZLIB", "CUSTOM"]`.

---

## Recommended Keys

| Key | Description |
|-----|-------------|
| `SYMBOL` | Decorated symbol name (e.g. `_bit_reverse`). Used by the verifier to locate the function in compiled `.obj` files. |

---

## Optional Keys

| Key | When to use | Example |
|-----|-------------|---------|
| `SOURCE` | Library functions — reference file in original SDK | `SOURCE: SBHEAP.C:195` |
| `BLOCKER` | STUB functions — explain why it doesn't match | `BLOCKER: missing CRT internals` |
| `NOTE` | Any function — freeform notes | `NOTE: uses SSE2 intrinsics` |
| `GLOBALS` | Functions referencing globals — comma-separated list | `GLOBALS: g_counter, g_state` |
| `SKIP` | Describe known acceptable byte differences | `SKIP: xor edi,edi after call` |

---

## Struct SIZE Comments (reccmp recommendation)

When a file defines structs, annotate their size:

```c
// SIZE 0x1c
typedef struct {
    int x;       // 0x00
    int y;       // 0x04
    char* name;  // 0x08
} MyStruct;
```

The linter (W007) will warn if a file defining structs lacks the `// SIZE 0xNN` annotation.

---

## Linter Error Codes

Run `rebrew-lint` to check all files. Run `rebrew-lint --fix` to auto-migrate old-format annotations.

### Errors (block CI)

| Code | Description |
|------|-------------|
| E000 | Cannot read file |
| E001 | Missing or invalid FUNCTION/LIBRARY/STUB marker |
| E002 | Invalid or suspicious VA (outside 32-bit range) |
| E003 | Missing `// STATUS:` |
| E004 | Invalid STATUS value |
| E005 | Missing `// ORIGIN:` |
| E006 | Invalid ORIGIN value |
| E007 | Missing `// SIZE:` |
| E008 | Invalid SIZE value (non-positive or non-numeric) |
| E009 | Missing `// CFLAGS:` |
| E010 | Unknown annotation key |
| E012 | Module name doesn't match `cfg.marker` from `rebrew.toml` |
| E013 | Duplicate VA — same address annotated in another file |
| E014 | Corrupted annotation value (e.g. literal `\n` in STATUS) |

### Warnings (advisory)

| Code | Description |
|------|-------------|
| W001 | Missing `// SYMBOL:` (recommended) |
| W002 | Old-format header detected (run `--fix` to migrate) |
| W003 | File has annotation but no function implementation |
| W004 | Marker type inconsistent with ORIGIN (e.g. `FUNCTION` for `MSVCRT`) |
| W005 | STUB function missing `// BLOCKER:` |
| W006 | Library function missing `// SOURCE:` |
| W007 | File defines structs without `// SIZE 0xNN` |
| W008 | CFLAGS differ from the preset for this ORIGIN in `rebrew.toml` |
| W009 | Filename doesn't match SYMBOL |
| W010 | Contradictory status/marker (e.g. `MATCHING` with `STUB` marker) |
| W011 | ORIGIN not in configured origins list (advisory for new projects) |
| W012 | Block-comment format (`/* FUNCTION: ... */`) — run `--fix` to migrate |
| W013 | Javadoc format (`@address`) — run `--fix` to migrate |
| W014 | ORIGIN doesn't match filename prefix convention (`crt_*` → MSVCRT) |
| W015 | VA hex digits have mixed case (prefer consistent case) |

---

## CLI Options

```
rebrew-lint                     # Lint all *.c files
rebrew-lint --fix               # Auto-migrate old-format headers
rebrew-lint --quiet             # Errors only, suppress warnings
rebrew-lint --json              # Machine-readable JSON output
rebrew-lint --summary           # Print status/origin breakdown table
rebrew-lint --files f1.c f2.c   # Check specific files
rebrew-lint --target client     # Lint a specific target from rebrew.toml
```

### JSON Output Schema

```json
{
  "total": 402,
  "passed": 350,
  "errors": 12,
  "warnings": 40,
  "files": [
    {
      "file": "func_foo.c",
      "path": "/path/to/func_foo.c",
      "errors": [{"line": 1, "code": "E004", "message": "Invalid STATUS: BOGUS"}],
      "warnings": [],
      "passed": false
    }
  ]
}
```

---

## Old Format (Legacy)

The old format is a single-line comment:

```c
/* func_name @ 0x10008880 (31B) - /O2 /Gd - EXACT [GAME] */
```

Run `rebrew-lint --fix` to auto-migrate to the new multi-line format.

### Block-Comment Format (Legacy)

```c
/* FUNCTION: SERVER 0x10003260 */
/* STATUS: MATCHING */
/* ORIGIN: GAME */
/* SIZE: 183 */
/* CFLAGS: /O2 /Gd */
/* SYMBOL: _AnalyzeInstruction */
```

### Javadoc Format (Legacy)

```c
/**
 * @brief Core logging function
 * @address 0x10003640
 * @size 132
 * @cflags /O2 /Gd
 * @symbol _LogMessageInternal
 * @origin GAME
 * @status RELOC
 */
```

All legacy formats are auto-migrated by `rebrew-lint --fix`.
