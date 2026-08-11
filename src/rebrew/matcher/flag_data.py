"""Auto-generated compiler flag axes from decomp.me.

Source: https://github.com/decompme/decomp.me.git
  File: backend/coreapp/flags.py
Synced: 2026-08-10

Do not edit manually — re-run tools/sync_decomp_flags.py to update.
"""

from rebrew.matcher.flags import Checkbox, Flags, FlagSet

COMMON_MSVC_FLAGS: Flags = [
    FlagSet(
        id="msvc_opt_level",
        flags=("/Od", "/O1", "/O2", "/Os", "/Ot", "/Og", "/Ox"),
    ),
    FlagSet(
        id="msvc_codegen",
        flags=("/GB", "/G3", "/G4", "/G5", "/G6"),
    ),
    FlagSet(id="msvc_fp", flags=("/fp:precise", "/fp:strict", "/fp:fast")),
    FlagSet(
        id="msvc_rtlib",
        flags=("/ML", "/MT", "/MD", "/MLd", "/MTd", "/MDd"),
    ),
    FlagSet(id="msvc_inline", flags=("/Ob0", "/Ob1", "/Ob2")),
    FlagSet(
        id="msvc_alignment",
        flags=("/Zp1", "/Zp2", "/Zp4", "/Zp8", "/Zp16"),
    ),
    FlagSet(id="msvc_callconv", flags=("/Gd", "/Gr", "/Gz")),
    FlagSet(id="msvc_source_language", flags=("/TP",)),
    Checkbox(id="msvc_use_rtti", flag="/GR"),
    Checkbox(id="msvc_use_ehsc", flag="/GX"),
    Checkbox(id="msvc_disable_stack_checking", flag="/Gs"),
    Checkbox(id="msvc_disable_buffer_security_checks", flag="/GS-"),
    Checkbox(id="msvc_runtime_debug_checks", flag="/GZ"),
    FlagSet(id="msvc_fpo", flags=("/Oy", "/Oy-")),
    Checkbox(id="msvc_fp_consistency", flag="/Op"),
]

# MSVC 6.0 — excludes flags only available in 7.x+
MSVC6_FLAGS: Flags = [
    FlagSet(
        id="msvc_opt_level",
        flags=("/Od", "/O1", "/O2", "/Os", "/Ot", "/Og", "/Ox"),
    ),
    FlagSet(
        id="msvc_codegen",
        flags=("/GB", "/G3", "/G4", "/G5", "/G6"),
    ),
    FlagSet(
        id="msvc_rtlib",
        flags=("/ML", "/MT", "/MD", "/MLd", "/MTd", "/MDd"),
    ),
    FlagSet(id="msvc_inline", flags=("/Ob0", "/Ob1", "/Ob2")),
    FlagSet(
        id="msvc_alignment",
        flags=("/Zp1", "/Zp2", "/Zp4", "/Zp8", "/Zp16"),
    ),
    FlagSet(id="msvc_callconv", flags=("/Gd", "/Gr", "/Gz")),
    FlagSet(id="msvc_source_language", flags=("/TP",)),
    Checkbox(id="msvc_use_rtti", flag="/GR"),
    Checkbox(id="msvc_use_ehsc", flag="/GX"),
    Checkbox(id="msvc_disable_stack_checking", flag="/Gs"),
    Checkbox(id="msvc_runtime_debug_checks", flag="/GZ"),
    FlagSet(id="msvc_fpo", flags=("/Oy", "/Oy-")),
    Checkbox(id="msvc_fp_consistency", flag="/Op"),
]

# Flag IDs only available in MSVC 7.x+
MSVC7_ONLY_IDS = {"msvc_disable_buffer_security_checks", "msvc_fp"}

# Sweep tiers — which flag IDs to include per effort level.
# quick:    core code-affecting axes (~fast)
# targeted: core + specific codegen-altering flags (/Oy, /Op)
# normal:   adds codegen, inline, callconv (~moderate)
# thorough: adds alignment + key toggles (~heavy)
# full:     all axes (use with sampling for large spaces)
MSVC_SWEEP_TIERS = {
    "quick": ["msvc_opt_level", "msvc_callconv", "msvc_codegen"],
    "targeted": [
        "msvc_opt_level",
        "msvc_callconv",
        "msvc_codegen",
        "msvc_fpo",
        "msvc_fp_consistency",
    ],
    "normal": [
        "msvc_opt_level",
        "msvc_codegen",
        "msvc_fp",
        "msvc_rtlib",
        "msvc_inline",
        "msvc_callconv",
    ],
    "thorough": [
        "msvc_opt_level",
        "msvc_codegen",
        "msvc_fp",
        "msvc_rtlib",
        "msvc_inline",
        "msvc_callconv",
        "msvc_alignment",
        "msvc_disable_stack_checking",
        "msvc_use_ehsc",
        "msvc_runtime_debug_checks",
    ],
    "full": None,
}


# Open Watcom wcc386 — 32-bit OMF codegen.  Flags are wcc386's own:
# -o{space|time|all} optimization, -5/-6 codegen, -zp packing, -bm memory.
WATCOM_FLAGS: Flags = [
    FlagSet(
        id="watcom_opt",
        flags=("-os", "-ot", "-ol", "-ox"),
    ),
    FlagSet(
        id="watcom_codegen",
        flags=("-3", "-4", "-5", "-6"),
    ),
    FlagSet(
        id="watcom_pack",
        flags=("-zp1", "-zp2", "-zp4", "-zp8"),
    ),
    Checkbox(id="watcom_flat", flag="-mf"),
    Checkbox(id="watcom_fp_emulate", flag="-fpc"),
]

WATCOM_SWEEP_TIERS: dict[str, list[str] | None] = {
    "quick": ["watcom_opt"],
    "targeted": ["watcom_opt", "watcom_codegen"],
    "normal": ["watcom_opt", "watcom_codegen", "watcom_pack", "watcom_flat"],
    "thorough": [
        "watcom_opt",
        "watcom_codegen",
        "watcom_pack",
        "watcom_flat",
        "watcom_fp_emulate",
    ],
    "full": None,
}
