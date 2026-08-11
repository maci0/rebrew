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
| `full` | 13 | 6,193,152 | hours | Last resort; exhausts every known axis including /TP, /GR, /GX; combine with random sampling |

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
With 6.2 M combinations this is rarely feasible without random sampling
(`--sample N`).

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

## Watcom profile

`rebrew match --flag-sweep --profile watcom` sweeps wcc386 flags
(`-os/-ot/-ol/-ox` optimization, `-3..-6` codegen, `-zp` packing,
`-mf`/`-fpc` toggles) — quick=5, targeted=25 combinations.  The flag
strings are `-`-style (wcc386), never MSVC `/`-style.

## MSVC 1.52 (16-bit) profile

`rebrew match --flag-sweep --profile msvc1.52` sweeps the 16-bit CL flags
(`/Od /O1 /O2 /Ox` opt, `/G2 /G3` codegen, `/Aw /Au` far-data,
`/Gs`/`/Za` toggles) — quick=5, targeted=15 combinations.
