# Flag-Sweep Tiers

`rebrew match --flag-sweep-only` (and the GA engine's `--flag-sweep` mode)
exhaustively compiles a function across a grid of MSVC6 flag combinations and
reports the best-matching variant.  To keep runtimes manageable the grid is
tiered by coverage vs. speed.

Tier definitions live in `src/rebrew/matcher/flag_data.py` — the
`MSVC_SWEEP_TIERS` dict maps a tier name to a list of flag-axis IDs from
`MSVC6_FLAGS`.  Each axis is either a `FlagSet` (one value chosen from N
options) or a `Checkbox` (on/off), so total combinations multiply.

## Tier Reference

| Tier | Axes | Combinations | Typical runtime | When to use |
|------|------|-------------|-----------------|-------------|
| `quick` | 3 | 192 | < 1 min | First attempt on a new STUB; rules out most /O and /G variants fast |
| `targeted` | 5 | 1,152 | 1–3 min | Default for `--flag-sweep-only`; adds /Oy and /Op |
| `normal` | 5 | 5,376 | 3–10 min | Follow-up when `targeted` is close but not EXACT; adds /ML-/MTd runtime-library axis |
| `thorough` | 9 | 258,048 | 15–60 min | Use when `normal` still leaves a near-match; adds struct alignment and debug-info toggles |
| `full` | 13 | 6,193,152 | hours | Last resort; exhausts every known axis including /TP, /GR, /GX |

`thorough` and `full` are too large to materialize as a full set (~400 MB):
`generate_flag_combinations` stride-samples the product stream down to a
100,000-combination memory bound (86,016 and 99,890 respectively), so the
columns above are the full product counts, not what actually compiles.

## Axes per Tier

### `quick`
Covers the highest-impact code-generation knobs.

| Axis ID | Flag options |
|---------|-------------|
| `msvc_opt_level` | `/Od` `/O1` `/O2` `/Os` `/Ot` `/Og` `/Ox` |
| `msvc_codegen` | `/GB` `/G3` `/G4` `/G5` `/G6` |
| `msvc_callconv` | `/Gd` `/Gr` `/Gz` |

### `targeted`
Adds frame-pointer and floating-point consistency toggles to the `quick` set.

| Axis ID | Flag options |
|---------|-------------|
| `msvc_opt_level` | (same as quick) |
| `msvc_codegen` | (same as quick) |
| `msvc_callconv` | (same as quick) |
| `msvc_fpo` | `/Oy` `/Oy-` |
| `msvc_fp_consistency` | `/Op` (checkbox) |

### `normal`
Replaces `msvc_fpo`/`msvc_fp_consistency` with the runtime-library and
inlining axes.  Best general-purpose starting point.

| Axis ID | Flag options |
|---------|-------------|
| `msvc_opt_level` | (same as quick) |
| `msvc_codegen` | (same as quick) |
| `msvc_rtlib` | `/ML` `/MT` `/MD` `/MLd` `/MTd` `/MDd` |
| `msvc_inline` | `/Ob0` `/Ob1` `/Ob2` |
| `msvc_callconv` | (same as quick) |

### `thorough`
Adds struct alignment, C++ exception handling, stack checking, and runtime
debug checks on top of `normal`.

| Axis ID | Flag options |
|---------|-------------|
| `msvc_opt_level` | (same as quick) |
| `msvc_codegen` | (same as quick) |
| `msvc_rtlib` | (same as normal) |
| `msvc_inline` | (same as normal) |
| `msvc_callconv` | (same as quick) |
| `msvc_alignment` | `/Zp1` `/Zp2` `/Zp4` `/Zp8` `/Zp16` |
| `msvc_use_ehsc` | `/GX` (checkbox) |
| `msvc_disable_stack_checking` | `/Gs` (checkbox) |
| `msvc_runtime_debug_checks` | `/GZ` (checkbox) |

### `full`
All 13 MSVC6 axes — includes C++ mode (`/TP`), RTTI (`/GR`), and
floating-point axes (`msvc_fpo`, `msvc_fp_consistency`) from `targeted`.
With 6.2 M combinations the product stream is stride-sampled down to the
100,000-combination memory bound, so a `full` run is a bounded sampled
pass, not an exhaustive one.

| Axis ID | Flag options |
|---------|-------------|
| `msvc_opt_level` | (same as quick) |
| `msvc_codegen` | (same as quick) |
| `msvc_rtlib` | (same as normal) |
| `msvc_inline` | (same as normal) |
| `msvc_alignment` | (same as thorough) |
| `msvc_callconv` | (same as quick) |
| `msvc_compile_cpp` | `/TP` (checkbox) |
| `msvc_use_rtti` | `/GR` (checkbox) |
| `msvc_use_ehsc` | `/GX` (checkbox) |
| `msvc_disable_stack_checking` | `/Gs` (checkbox) |
| `msvc_runtime_debug_checks` | `/GZ` (checkbox) |
| `msvc_fpo` | `/Oy` `/Oy-` |
| `msvc_fp_consistency` | `/Op` (checkbox) |

## CLI Usage

```bash
# Default tier (targeted — 1,152 combinations)
rebrew match src/game_dll/my_func.c --flag-sweep-only

# Explicit tier
rebrew match src/game_dll/my_func.c --flag-sweep-only --tier quick
rebrew match src/game_dll/my_func.c --flag-sweep-only --tier targeted
rebrew match src/game_dll/my_func.c --flag-sweep-only --tier thorough
rebrew match src/game_dll/my_func.c --flag-sweep-only --tier full

# Batch: sweep all NEAR_MATCHING functions and auto-update CFLAGS on hit
rebrew match --all --flag-sweep --fix-cflags
```

See also [CLI.md](CLI.md) under `rebrew match` for the full flag reference,
and `rebrew-matching/SKILL.md` for the AI-agent workflow that wraps the GA engine.

## Non-MSVС6 sweep grids

The MSVC6 tier definitions above are the CLI sweep.  The other grids in
`flag_data.py` are reached only through the toolchain sweep
(`--flag-sweep-only --sweep-toolchain`), which enumerates the image-backed
**MSVC** toolchains (`--sweep-only`/`--sweep-exclude` filter by profile
name or version prefix, e.g. `msvc6,6.0,win16`).

### MSVC 1.52 (16-bit)

`rebrew match --flag-sweep-only --sweep-toolchain --sweep-only msvc1.52`
sweeps the 16-bit CL flags (`/Od /O1 /O2 /Ox` opt, `/AS /AM /AC /AL`
**memory models**, `/G2 /G3` codegen, `/Aw /Au` far-data, `/Gs`/`/Za`
toggles) — quick=25, targeted=75, normal=450, thorough=900 combinations.
The memory-model axis is essential: 16-bit Windows games are typically
built far-code (`/AM` medium: `retf` + `lcall`/`ljmp` patch slots) — see
[OMF_NOTES.md](OMF_NOTES.md).  Compiled objects are 16-bit OMF, decoded by
the built-in `omf16` parser (objconv crashes on them); 16-bit NE targets
are scored the same way as PE ones.  Verified end-to-end against the
skifree16 NE target: 75 combos compile through the DOSBox image and
produce structural-similarity reports.

### Watcom / Borland (no CLI sweep)

`flag_data.py` also carries Open Watcom (`-os/-ot/-ol/-ox` optimization,
`-3..-6` codegen, `-zp` packing, `-mf`/`-fpc` toggles) and Borland
Turbo C++ 3.1 / bcc32 (`-O1/-O2/-Od`, `-K`, `-Z`) grids, but these are
**not reachable from the CLI**: `flag_sweep` refuses posix-style profiles
(their `-`-style flags would be passed as files to an MSVC invocation),
and the toolchain sweep enumerates only MSVC images.  The axes remain in
`flag_data.py` for the `generate_flag_combinations(profile=...)` API and
tests; sweeping a non-MSVC toolchain is done by running the GA without
`--flag-sweep-only`.
