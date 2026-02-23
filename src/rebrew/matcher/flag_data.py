"""Auto-generated compiler flag axes from decomp.me.

Source: https://github.com/decompme/decomp.me.git
  File: backend/coreapp/flags.py
Synced: 2026-02-23

Do not edit manually — re-run tools/sync_decomp_flags.py to update.
"""

from rebrew.matcher.flags import Checkbox, Flags, FlagSet

COMMON_MSVC_FLAGS: Flags = [
    FlagSet(
        id='msvc_opt_level',
        flags=['/Od', '/O1', '/O2', '/Os', '/Ot', '/Og', '/Ox'],
    ),
    FlagSet(
        id='msvc_codegen',
        flags=['/GB', '/G3', '/G4', '/G5', '/G6'],
    ),
    FlagSet(id='msvc_fp', flags=['/fp:precise', '/fp:strict', '/fp:fast']),
    FlagSet(
        id='msvc_rtlib',
        flags=['/ML', '/MT', '/MD', '/MLd', '/MTd', '/MDd'],
    ),
    FlagSet(id='msvc_inline', flags=['/Ob0', '/Ob1', '/Ob2']),
    FlagSet(
        id='msvc_alignment',
        flags=['/Zp1', '/Zp2', '/Zp4', '/Zp8', '/Zp16'],
    ),
    FlagSet(id='msvc_callconv', flags=['/Gd', '/Gr', '/Gz']),
    Checkbox(id='msvc_compile_cpp', flag='/TP'),
    Checkbox(id='msvc_use_rtti', flag='/GR'),
    Checkbox(id='msvc_use_ehsc', flag='/GX'),
    Checkbox(id='msvc_disable_stack_checking', flag='/Gs'),
    Checkbox(id='msvc_disable_buffer_security_checks', flag='/GS-'),
    Checkbox(id='msvc_runtime_debug_checks', flag='/GZ'),
]

# MSVC 6.0 — excludes flags only available in 7.x+
MSVC6_FLAGS: Flags = [
    FlagSet(
        id='msvc_opt_level',
        flags=['/Od', '/O1', '/O2', '/Os', '/Ot', '/Og', '/Ox'],
    ),
    FlagSet(
        id='msvc_codegen',
        flags=['/GB', '/G3', '/G4', '/G5', '/G6'],
    ),
    FlagSet(
        id='msvc_rtlib',
        flags=['/ML', '/MT', '/MD', '/MLd', '/MTd', '/MDd'],
    ),
    FlagSet(id='msvc_inline', flags=['/Ob0', '/Ob1', '/Ob2']),
    FlagSet(
        id='msvc_alignment',
        flags=['/Zp1', '/Zp2', '/Zp4', '/Zp8', '/Zp16'],
    ),
    FlagSet(id='msvc_callconv', flags=['/Gd', '/Gr', '/Gz']),
    Checkbox(id='msvc_compile_cpp', flag='/TP'),
    Checkbox(id='msvc_use_rtti', flag='/GR'),
    Checkbox(id='msvc_use_ehsc', flag='/GX'),
    Checkbox(id='msvc_disable_stack_checking', flag='/Gs'),
    Checkbox(id='msvc_runtime_debug_checks', flag='/GZ'),
]

# Flag IDs only available in MSVC 7.x+
MSVC7_ONLY_IDS = {'msvc_disable_buffer_security_checks', 'msvc_fp'}

# Sweep tiers — which flag IDs to include per effort level.
# quick:    core code-affecting axes (~fast)
# normal:   adds codegen, inline, callconv (~moderate)
# thorough: adds alignment + key toggles (~heavy)
# full:     all axes (use with sampling for large spaces)
MSVC_SWEEP_TIERS = {
    'quick': ['msvc_opt_level', 'msvc_callconv', 'msvc_codegen'],
    'normal': ['msvc_opt_level', 'msvc_codegen', 'msvc_fp', 'msvc_rtlib', 'msvc_inline', 'msvc_callconv'],
    'thorough': ['msvc_opt_level', 'msvc_codegen', 'msvc_fp', 'msvc_rtlib', 'msvc_inline', 'msvc_callconv', 'msvc_alignment', 'msvc_disable_stack_checking', 'msvc_use_ehsc', 'msvc_runtime_debug_checks'],
    'full': None,
}
