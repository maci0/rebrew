# Bootstrapping a New Binary

Step-by-step guide for adding an entirely new executable or DLL to the project
when **no prior RE work exists** for it — no `.c` files, no `ghidra_functions.json`,
no catalog entries.

## 1. Initialize the project

Run the initialize command inside an empty or existing directory. Pass the
target name, original executable filename, and compiler profile.

```bash
rebrew init --target mygame --binary mygame.exe --compiler msvc6
```

This will automatically create your `rebrew.toml` as well as the
`original/`, `src/mygame/`, and `bin/mygame/` folders.

## 2. Place the binary

Copy the target file into the generated `original/` directory:

```bash
cp /path/to/mygame.exe original/mygame.exe
```

## 3. Discover functions

You need a `ghidra_functions.json` inside the source directory. This is the
function list that `rebrew skeleton` and `rebrew next` consume.

**Option A — Ghidra (recommended):**

1. Import the binary into a Ghidra project.
2. Run Auto-Analysis (`Analysis → Auto Analyze...`).
3. Export the function list via script or the ReVa MCP plugin.
4. Save as `src/mygame/ghidra_functions.json` with the schema:

```json
[
  {"va": 4198400, "size": 64, "ghidra_name": "FUN_00401000"},
  {"va": 4198464, "size": 128, "ghidra_name": "entry"}
]
```

> [!NOTE]
> VAs must be **integers** (not hex strings). The `ghidra_name` field is used
> for origin detection and filename generation.

**Option B — radare2 (headless):**

```bash
r2 -q -c 'aaa; aflj' original/MyGame/mygame.exe > /tmp/r2_funcs.json
# Convert to rebrew schema:
python3 -c "
import json, sys
funcs = json.load(open('/tmp/r2_funcs.json'))
out = [{'va': f['offset'], 'size': f['size'], 'ghidra_name': f['name']} for f in funcs]
json.dump(out, open('src/mygame/ghidra_functions.json', 'w'), indent=2)
print(f'Exported {len(out)} functions')
"
```

## 4. Identify the compiler and flags

Determine the original compiler so you can set up the correct build backend.

**PE Rich Header (Windows binaries):**

```bash
uv run python -c "
import lief
pe = lief.parse('original/MyGame/mygame.exe')
if pe.has_rich_header:
    print('Rich header entries:')
    for entry in pe.rich_header.entries:
        print(f'  Product {entry.id} count {entry.count}')
"
```

**Quick heuristic checks:**

| Artifact | Indicates |
|----------|-----------|
| Rich Header with product IDs 0x006x | MSVC6 |
| `.comment` section with `GCC:` string | GCC |
| `__local_unwind2` in imports/code | MSVC with SEH |
| CRT strings like `MSVCRT.dll` in imports | Microsoft runtime |
| Presence of `__libc_start_main` | GCC/Linux |

Once identified, ensure the matching toolchain is available (e.g., `tools/MSVC600/`
for MSVC6, or a system GCC for ELF targets).

## 5. Scan with FLIRT signatures

Run the FLIRT scanner to auto-identify known library functions. This provides
**free wins** — functions that can be matched from reference source without
any manual RE.

```bash
rebrew flirt flirt_sigs/
```

If you need signatures for a specific library version, generate them:

```bash
uv run python -m rebrew.gen_flirt_pat /path/to/LIBCMT.LIB \
    -o flirt_sigs/libcmt_vc6.pat
```

See [FLIRT_SIGNATURES.md](FLIRT_SIGNATURES.md) for a comprehensive guide on
obtaining, creating, and troubleshooting FLIRT signatures.

## 6. Triage functions

Run triage to classify discovered functions by type and priority:

```bash
rebrew triage --json
```

This categorizes functions as library, game code, CRT, unmatchable (IAT thunks,
SEH helpers, ASM builtins), etc. Use the output to plan your attack order.

## 7. Start with leaf functions

Begin with the **smallest, simplest functions** — typically 10–30 byte leaf
functions with no calls to other functions. These are often trivial
getters/setters/wrappers.

```bash
rebrew next --stats            # see the overall breakdown
rebrew next --origin GAME -n 20  # smallest actionable functions
```

Each successful match becomes context for harder functions — creating a
**snowball effect** where early wins unlock progressively more of the binary.

## 8. Set up annotation conventions

Decide on the origin categories for your binary and configure them in `rebrew.toml`.
For a typical game DLL, the origins might be `GAME`, `MSVCRT`, and `ZLIB`. Define
your own via the `origins`, `library_origins`, `origin_comments`, and
`origin_todos` config keys. Example annotation:

```c
// FUNCTION: MYGAME 0x00401000
// STATUS: STUB
// ORIGIN: GAME
// SIZE: 64
// CFLAGS: /O2 /Gd
// SYMBOL: _my_func
```

See [ANNOTATIONS.md](ANNOTATIONS.md) for the full annotation format reference.

## 9. Full tool support

The core tools (`rebrew skeleton`, `rebrew next`, `rebrew test`, `rebrew match`)
are fully target-aware. They automatically read the target configuration from
`rebrew.toml` and operate on the selected target's binary and source directory.

If you have multiple targets, switch between them using the `--target` flag:

```bash
rebrew test --target mygame src/mygame/my_func.c
rebrew next --target mygame --stats
```

## Checklist

```text
[ ] Binary placed in original/
[ ] Target added to rebrew.toml under [targets.<name>]
[ ] Source directory created: src/<target>/
[ ] Function list exported: src/<target>/ghidra_functions.json
[ ] Compiler identified and toolchain verified
[ ] FLIRT scan completed, library functions cataloged
[ ] Functions triaged (rebrew triage)
[ ] First leaf functions reversed and tested
[ ] Annotation conventions documented
```
