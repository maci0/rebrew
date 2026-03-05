# Annotation Format Reference

## Function Block

```c
// FUNCTION: MODULE 0xVA
// STATUS: STUB | MATCHING | RELOC | EXACT | PROVEN
// ORIGIN: GAME | MSVCRT | ZLIB | DIRECTX | ...
// SIZE: <bytes>
// CFLAGS: /O2 /Gd              (optional — falls back to project config)
// BLOCKER: register allocation, loop rotation
// BLOCKER_DELTA: 3
// NOTE: implementation notes
// GHIDRA: ghidra_function_name

int __cdecl function_name(int param_1, char* param_2)
{
    // function body
}
```

> Function name and symbol are derived automatically from the C function
> definition. No `// SYMBOL:` or `// PROTOTYPE:` annotations are needed.

## Status Progression

STUB -> MATCHING -> RELOC -> EXACT
                 \-> PROVEN (via rebrew prove)

## Multi-Target

Same function body, multiple annotation blocks:

```c
// FUNCTION: LEGO1 0x1009a8c0
// STATUS: EXACT

// FUNCTION: BETA10 0x101832f7
// STATUS: MATCHING
void my_func() {}
```

## Data Annotations

```c
// DATA: MODULE 0xVA
// SIZE: 256
// SECTION: .rdata
// ORIGIN: GAME
```

## Global Annotations

```c
// GLOBAL: MODULE 0xVA
extern int g_variable;
```
