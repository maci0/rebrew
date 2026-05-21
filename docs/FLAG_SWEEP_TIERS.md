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
| `quick` | 3 | 105 | < 1 min | First attempt on a new STUB; rules out most /O and /G variants fast |
| `targeted` | 5 | 420 | 1–3 min | Follow-up when `quick` is close but not EXACT; adds /Oy and /Op |
| `normal` | 5 | 1,890 | 3–10 min | Default for `--flag-sweep-only`; adds /ML-/MTd runtime-library axis |
| `thorough` | 9 | 75,600 | 15–60 min | Use when `normal` still leaves a near-match; adds struct alignment and debug-info toggles |
| `full` | 13 | 1,209,600 | hours | Last resort; exhausts every known axis including /TP, /GR, /GX; combine with random sampling |

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
With 1.2 M combinations this is rarely feasible without random sampling
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
# Default tier (normal — 1,890 combinations)
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
