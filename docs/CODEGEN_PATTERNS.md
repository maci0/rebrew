# MSVC6 Codegen Patterns

Reference for patterns that affect byte-level output when matching against an MSVC6
binary. Use this when `rebrew diff` shows structural mismatches (`**` lines) and you
need to understand why your C source produces different bytes.

Cross-references: [MATCH_TYPES.md](MATCH_TYPES.md) explains the match status
categories; [GA_MUTATIONS.md](GA_MUTATIONS.md) lists the mutation operators the GA
uses to explore these patterns automatically.

---

## C89 Source Rules (MSVC6)

MSVC6 is a strict C89 compiler. Violations produce compile errors or silent codegen
changes that prevent matching.

**Variable declarations:**
- Declare ALL variables at the top of each block, before any statements
- No `for(int i=0; ...)` — declare `int i;` separately above the loop
- No mixed declarations and code anywhere in the function body

**Comments:**
- No `//` line comments inside function bodies — use `/* */` only

**Unsupported C99 features:**
- No `_Bool`, `restrict`, variable-length arrays, designated initializers

**Calling conventions:**
- Game functions: `__cdecl` (default with `/Gd` flag)
- Win32 API imports: `__stdcall` with `__declspec(dllimport)` for IAT calls;
  plain `__stdcall` prototype (no dllimport) for thunk-style calls
- Symbol decoration: `_funcname` for cdecl, `_funcname@N` for stdcall

**Typical skeleton structure:**

```c
/* Extern declarations for globals */
extern int g_some_global;
extern void *DAT_10035000;

/* Extern declarations for called functions */
extern int __cdecl SomeOtherFunc(int param);

int __cdecl my_func(int param_1, char *param_2)
{
    int result;       /* declare all vars first */
    char *ptr;
    int i;

    ptr = *(char **)(param_1 + 0x5d);
    if (ptr == 0)
        return -1;

    for (i = 0; i < 10; i++) {
        /* loop body */
    }

    result = SomeOtherFunc(*(int *)(param_1 + 8));
    return result;
}
```

---

## Known MSVC6 Codegen Patterns

These patterns affect whether your source produces matching bytes. Check the target
disassembly with `rebrew asm` or `rebrew diff` to determine which apply.

| Pattern | Effect | Solution |
|---------|--------|----------|
| Variable declaration order | Changes register allocation | Match Ghidra's variable order |
| `for` vs `do-while` loops | Different loop peeling behavior | Try both |
| `>=` vs `>` comparisons | `>=5` generates `jl`, `>4` generates `jle` | Check target's comparison opcodes |
| `char` vs `int` return type | `char` uses `mov al,N` (2B), `int` uses `mov eax,N` (5B) | Match target's return instruction size |
| Store ordering | Controls parameter load scheduling | Match Ghidra's assignment order |
| FPU operand order | `fld [a]; fmul [b]` vs `fld [b]; fmul [a]` — both mathematically equal but produce different bytes | NOT controllable from C |
| `BOOL retcode = TRUE` | Extends live range, affects register pressure | Initialization at declaration matters |
| Frame pointer (`push ebp; mov ebp,esp`) | Indicates `/Oy-` flag needed | Check prologue for `push ebp` |
| Switch with jump table | Table appears after function body | Test harness ignores table bytes |
| `signed` vs `unsigned` shift | `(int)x >> n` = `sar`, `(unsigned)x >> n` = `shr` | Check target's shift instructions |
| `>= N` vs `> N-1` constants | `x >= 1` → `cmp ecx,1; jl` (exact constant); `0 < x` → `test ecx,ecx; jle` (optimized away) | Always use `>=`/`<=` with the EXACT constant from the target binary |
| `<= 0` vs `< 1` encoding | `<= 0` → `test reg,reg; setle` (2B test); `< 1` → `cmp reg,1; setl` (3B cmp) | `<= 0` saves 1 byte; check target for `test` vs `cmp ,1` |
| Byte param zero-extend | `mov dl,[reg+off]` vs `xor edx,edx; mov dl,[reg+off]` — compiler decides based on register liveness | NOT controllable from C; causes 2B diff per occurrence; accept as NEAR_MATCHING blocker |
| `if/else` nesting order | First checked condition becomes the fallthrough path; reversing nesting changes branch targets | Match the original nesting order exactly — `if (ptr != NULL)` first, not `if (ptr == NULL) { } else` |
| `unsigned char *` vs `char *` | `char *` → `MOVSX` (sign-extend), `unsigned char *` → `AND reg, 0xFF` (zero-extend) | Check target for `movsx` vs `and 0xff` to determine signedness |
| Short vs far branch encoding | Small target offsets (≤127B) use `jne rel8` (2B); larger use `je rel32` (6B) — 4B diff per branch | Opposite condition with far jump is 4B larger; reorder blocks to minimize branch distance |
| `if (x == -1) return -1;` idiom | Generates `inc/neg/sbb` (7B); `(x != -1) - 1` generates `setne` (13B) | Use explicit `if` + `return` for the compact form; avoid expression tricks |
| `memcpy()` inlining | `memcpy()` inlines to `rep movsd/movsw/movsb`; explicit loops do NOT | Use `memcpy()` when target has `rep movs`; never hand-roll byte loops |
| `goto` for shared error tail | `goto label;` at end of if-block controls block ordering in output | Use `goto` to merge duplicate return paths and match block layout |
| Eliminating intermediate pointers | Removing a temp pointer var in loops can fix register allocation | If loop uses extra callee-saved reg, try inlining `arr[i].field` directly |
| `__stdcall` without `__declspec(dllimport)` | Produces `CALL thunk` instead of `CALL DWORD PTR [IAT]` | For Winsock/DLL imports, declare as plain `__stdcall` prototypes |

---

## Compiler Flag Knobs

When the pattern table doesn't explain the mismatch, try these flag combinations
with `rebrew match`:

| Origin | CFLAGS | Notes |
|--------|--------|-------|
| GAME | `/O2 /Gd` | Full optimization, cdecl calling convention |
| MSVCRT | `/O1` | Size optimization. Some need `/O1 /Oy-` (frame pointer) or `/O1 /Oi` (intrinsics) |
| ZLIB | `/O2` | Full optimization (no `/Gd` needed — zlib uses default cdecl) |

Always include `/nologo /c /MT` as base flags (added automatically by `rebrew test`).

Common knobs: `/O1` vs `/O2` (size vs speed), `/Gd` (cdecl), `/Oy` vs `/Oy-`
(frame pointer omission), `/Oi` (intrinsics), `/Gy` (COMDAT).

---

## SEH (Structured Exception Handling) Helpers

SEH helper functions in MSVCRT are **not matchable from pure C89 source**. These
functions manipulate the exception handling frame directly in ways that cannot be
expressed in C.

**Identified SEH helpers (example from a typical target binary):**

| VA | Size | Name | Description |
|----|------|------|-------------|
| 0x1001e726 | 24B | `__local_unwind2` | Core unwinder for local exception frames |
| 0x1001e899 | 27B | `FUN_1001e899` | SEH frame restore helper |
| 0x1001e8ba | ~20B | `FUN_1001e8ba` | Exception filter helper |

**Why they're unmatchable:**

1. **Frame pointer manipulation**: These functions load `ebp` from a saved value in
   an exception frame structure, not from the normal stack:
   ```asm
   push ebp
   mov ecx, [esp+8]      ; get frame pointer from parameter
   mov ebp, [ecx]        ; load ebp from exception frame - NOT possible in C
   mov eax, [ecx+0x1c]   ; get saved value
   push eax
   call __local_unwind2
   ```

2. **Non-standard control flow**: SEH functions use `ret N` (stack-cleaning return)
   with custom calling conventions that don't match `__cdecl` or `__stdcall`.

3. **Exception registration manipulation**: These functions directly modify the Windows
   exception registration chain (`fs:[0]`), which cannot be done portably in C.

**How to handle them:**

- Mark as `STUB` with BLOCKER: `"SEH helper - not matchable from C"`
- Don't waste time trying to match them — they're CRT internal functions
- The actual game code doesn't call these directly; they're only used by the
  exception handling runtime

**Verification pattern**: If a function:
- Loads `ebp` from `[reg]` or `[reg+offset]` instead of `mov ebp, esp`
- Uses `ret N` with N > 0 but isn't `__stdcall`
- References `fs:[0]` or exception-related structures
- Has `__local_unwind` or `except` in the call graph

…then it's likely an SEH helper. Mark as STUB and move on.

> `rebrew todo` auto-detects functions starting with `mov eax, fs:[0]`
> (`64 A1 00 00 00 00`) and filters them out of actionable lists.

---

## Non-Matchable Functions

> `rebrew todo` auto-detects and excludes unmatchable patterns. Use
> `rebrew todo -c start-function` to see only actionable new functions.

- **IAT thunks**: 6-byte `jmp [addr]` stubs — not C code
- **ASM builtins**: `memset`, `strcmp`, `strstr`, `strchr`, `strlen`, `strncpy`,
  `strpbrk`, `strcspn`, `__local_unwind2`, `__aulldiv`, `__aullrem` — hand-written assembly
- **Single-byte stubs**: `ret` alignment padding — not real functions
- **SEH helpers**: see section above

---

## Reference Sources for CRT / Library Functions

| Source | Location | Use for |
|--------|----------|---------|
| MSVC6 CRT source | `toolchain/msvc/6.0-win32/VC98/CRT/SRC/` | Heap, I/O, startup functions |
| CRT source (extended) | github.com/shihyu/learn_c/tree/master/vc_lib_src/src | Missing CRT files |
| zlib 1.1.3 | `references/zlib-1.1.3/` | All zlib functions |

For library-origin functions, use `rebrew crt-match` to find the reference source:

```bash
rebrew crt-match 0x<VA>
rebrew crt-match --all --fix-source
```
