# Getting started

Work through one function in a binary you already have. Rebrew compiles your
C with the selected compiler profile and compares it with the original bytes.
`test` and `verify` record STATUS in project metadata. Use the CLI to update
`rebrew-functions.toml` and `rebrew-data.toml`. Keep STATUS out of C source.
See [metadata ownership](METADATA.md).

## Prerequisites

Install Rebrew and check the Rust and container runtime requirements in the
[README](../README.md#quick-start). Install `rizin` for function discovery.
Other discovery backends can work without it. For compiler detection, `diec`
is optional. See [compiler detection](TOOLCHAIN.md#toolchain-detection-doctor-alignment-check).

## Walkthrough

### 1. Create a project directory

```bash
mkdir game-decomp
cd game-decomp
```

### 2. Onboard it

```bash
rebrew intake /path/to/game.exe
```

`intake` suggests a compiler profile, copies the binary into `original/`,
builds a function inventory, and generates stubs for unmatched functions it can
document. The summary reports how many functions it discovered and documented.
If you know the compiler, pass `--toolchain <profile>`. See
[onboarding](ONBOARDING.md) for manual setup and discovery errors.

### 3. Check the project's health

```bash
rebrew doctor
```

Check the compiler profile and image before attempting a match. For example,
if `intake` selected `msvc-8.0`, try:

```bash
rebrew toolchain pull msvc-8.0
```

If a prebuilt image is unavailable, use `rebrew toolchain build msvc-8.0` with
the [toolchain source checkout and required media](TOOLCHAIN.md). Re-run
`rebrew doctor` after fixing the reported issues.

### 4. Review project status

```bash
rebrew status
rebrew todo
```

`status` reports file agreement, accounted executable bytes, and stored data
verdicts with separate denominators. `todo` ranks actions by affected byte
extent and estimated effort. For your first match, pick a small function whose
disassembly you understand. See [status and queue accounting](CLI.md#rebrew-status).

### 5. Check library attribution

Check whether the function comes from a library before writing C. Scan any
`.sig` or `.pat` files in the project's `flirt_sigs/` directory:

```bash
rebrew library scan-signatures
```

If you have neither signatures nor a shared signature checkout, use the
[FLIRT guide](FLIRT_SIGNATURES.md) to obtain or generate signatures. Review
candidate hits with `rebrew library identify --dry-run`, then run without
`--dry-run` to record the identification results you reviewed. When you have
the stock archive, use `rebrew library match --lib <archive> --va <VA>` to
compare the function against it. See the [library commands](CLI.md#rebrew-library).

### 6. Match a function

Open the source path from `rebrew todo`. For a function without source, run
`rebrew skeleton` with its virtual address (VA). For example, use
`rebrew skeleton 0x00401000` and open the path it reports. Replace the stub
with C based on the disassembly, then test it. Substitute your function's
address and file path in these commands:

```bash
rebrew binary asm show 0x00401000
rebrew test src/game/fcn_00401000.c
```

| Result | What to do |
| --- | --- |
| `EXACT` or `RELOC` | Move to the next function. Both count as matched. |
| `NEAR_MATCHING` | Use `rebrew diff <file>` and `rebrew diagnose near <file>` to find byte and instruction differences. |
| `STUB` or `SIZE_MISMATCH` | Recheck the control flow and compare the compiled and original lengths. |
| `COMPILE_ERROR` or `NOT_RUN` | Read the diagnostics. Use `rebrew doctor` to check the configured compiler and runtime. |

Edit and test again. If the remaining difference looks like a compiler option,
try `rebrew match flags <file>`. To search for source variants, use
`rebrew match run <file>`. See [the full workflow](WORKFLOW.md) and
[match types](MATCH_TYPES.md).

### 7. Verify the target

```bash
rebrew verify
```

`verify` checks the target's functions and reuses verdicts whose inputs are
unchanged. Use `--no-cache` to recheck them and `--compare` to detect regressions
against the saved baseline. See [CI examples](CI.md#project--workspace-ci).
