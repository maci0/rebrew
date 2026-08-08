# Rebrew Quick Start

Rebrew is a compiler-in-the-loop decompilation workbench for binary-matching game
reversing. It compiles your hand-written C89 source with MSVC6 under Wine and
byte-compares the output against the original binary, giving you instant feedback on
whether your reconstruction matches.

This guide covers the minimum path from a fresh clone to your first matched function.
For the full iteration loop see [WORKFLOW.md](WORKFLOW.md). For CLI flags and all
commands see [CLI.md](CLI.md).

## Prerequisites

- MSVC6 toolchain at `tools/MSVC600/VC98/` (already in repo)
- Wine installed and working
- Python dependencies: `uv sync`
- Ghidra with ReVa MCP (optional but strongly recommended)

## 5 Steps to Your First Match

### Step 1 — Initialize the project

```bash
rebrew init --target server.dll --binary original/server.dll --compiler msvc6
```

This creates `rebrew-project.toml` in the current directory, registering the target
binary and compiler settings. See [CONFIG.md](CONFIG.md) for all available keys.

Verify the toolchain is healthy:

```bash
rebrew doctor
```

Fix any errors it reports before continuing.

### Step 2 — Build the function catalog

```bash
rebrew catalog
rebrew flirt flirt_sigs/         # identify library functions via FLIRT
rebrew crt-match --all --fix-source  # auto-annotate MSVCRT functions
```

`rebrew catalog` reads the binary and produces the function list that all other tools
rely on. FLIRT scanning marks known library functions so you don't waste time on them.

See what needs work, ranked by ROI:

```bash
rebrew todo
rebrew todo -c start-function    # only easy uncovered functions
rebrew todo --stats              # coverage summary
```

### Step 3 — Generate a skeleton for a function

Pick a VA from `rebrew todo` output, then:

```bash
rebrew skeleton 0x<VA>
# With inline decompilation from Ghidra (recommended):
rebrew skeleton 0x<VA> --decomp --decomp-backend ghidra
```

This creates `src/server.dll/<name>.c` with the correct marker header and prints
the exact test command to run next.

Alternatively, disassemble the target bytes to guide your implementation:

```bash
rebrew asm 0x<VA> --size <SIZE>
```

### Step 4 — Write C89 source and test

Edit the generated skeleton, replacing the TODO placeholder with real C code.
Key MSVC6/C89 constraints: declare all variables at the top of each block, no `//`
comments inside functions, no `for(int i=0; ...)`. See [CODEGEN_PATTERNS.md](CODEGEN_PATTERNS.md)
for a full list of patterns that affect byte output.

Test immediately:

```bash
rebrew test src/server.dll/my_func.c
```

`rebrew test` compiles your source, byte-compares it against the target, and
auto-promotes STATUS in `rebrew-function.toml` on an EXACT or RELOC match.

If the result is MISMATCH, inspect what differs:

```bash
rebrew diff src/server.dll/my_func.c
```

`**` lines are structural differences that need fixing. `~~` lines are acceptable
relocation-only differences. When the byte delta is small but you can't close it
manually, the GA can search for better compiler flag combinations:

```bash
rebrew match src/server.dll/my_func.c --generations 100 --pop-size 64
```

For a detailed explanation of match types see [MATCH_TYPES.md](MATCH_TYPES.md).

### Step 5 — Verify project-wide

When you have several functions done, check them all at once:

```bash
rebrew verify
rebrew catalog --summary         # overall coverage stats
rebrew lint                      # check marker health
```

`rebrew verify` recompiles every tracked function and updates any drifted STATUS
entries. Run it before committing.

## What Next?

| Topic | Document |
|-------|---------|
| Full iteration loop (diff → match → prove → verify) | [WORKFLOW.md](WORKFLOW.md) |
| Multi-binary projects, shared code, JSON / CI usage | [WORKFLOW.md](WORKFLOW.md) |
| MSVC6 codegen patterns, SEH helpers, matching idioms | [CODEGEN_PATTERNS.md](CODEGEN_PATTERNS.md) |
| All CLI commands and flags | [CLI.md](CLI.md) |
| `rebrew-project.toml` reference | [CONFIG.md](CONFIG.md) |
| Source marker format and linter codes | [ANNOTATIONS.md](ANNOTATIONS.md) |
| Agent skills (rebrew-workflow, rebrew-matching, …) | `src/rebrew/agent-skills/` |
