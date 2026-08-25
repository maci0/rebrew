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


# MSVC 1.52 (16-bit) — 16-bit codegen flags (DOSBox CL.EXE).  The 16-bit
# compiler shares /O opt levels; codegen is /G2 (286) /G3 (386); /Aw /Au
# select far data (huge/small memory models); /AS /AM /AC /AL are the
# memory models — far-code models (AM/AL) emit retf + lcall/ljmp and are
# what 16-bit Windows games are typically built with.
MSVC152_FLAGS: Flags = [
    FlagSet(
        id="msvc152_opt",
        flags=("/Od", "/O1", "/O2", "/Ox"),
    ),
    FlagSet(
        id="msvc152_model",
        flags=("/AS", "/AM", "/AC", "/AL"),
    ),
    FlagSet(
        id="msvc152_codegen",
        flags=("/G2", "/G3"),
    ),
    FlagSet(
        id="msvc152_data",
        flags=("/Aw", "/Au"),
    ),
    Checkbox(id="msvc152_stack_check", flag="/Gs"),
    Checkbox(id="msvc152_declspec", flag="/Za"),
]

MSVC152_SWEEP_TIERS: dict[str, list[str] | None] = {
    "quick": ["msvc152_opt", "msvc152_model"],
    "targeted": ["msvc152_opt", "msvc152_model", "msvc152_codegen"],
    "normal": [
        "msvc152_opt",
        "msvc152_model",
        "msvc152_codegen",
        "msvc152_data",
        "msvc152_stack_check",
    ],
    "thorough": [
        "msvc152_opt",
        "msvc152_model",
        "msvc152_codegen",
        "msvc152_data",
        "msvc152_stack_check",
        "msvc152_declspec",
    ],
    "full": None,
}


# Borland Turbo C++ 3.1 (tc16, 16-bit DOS) / Borland C++ 5.5 (borlandc55,
# 32-bit) — shared Borland flag dialect (-O1 size / -O2 speed / -Od none;
# -K unsigned char default; -Z suppress redundant reloads).  Verified
# against the real compilers (TCC under DOSBox, bcc32 under wine).
BORLAND_FLAGS: Flags = [
    FlagSet(
        id="borland_opt",
        flags=("-O1", "-O2", "-Od"),
    ),
    Checkbox(id="borland_unsigned_char", flag="-K"),
    Checkbox(id="borland_redundant_loads", flag="-Z"),
]

BORLAND_SWEEP_TIERS: dict[str, list[str] | None] = {
    "quick": ["borland_opt"],
    "targeted": ["borland_opt", "borland_unsigned_char"],
    "normal": ["borland_opt", "borland_unsigned_char", "borland_redundant_loads"],
    "thorough": ["borland_opt", "borland_unsigned_char", "borland_redundant_loads"],
    "full": None,
}


# GCC / Clang (ELF/x86_64) — native PATH compilers.  A minimal posix flag
# space so `rebrew match --flag-sweep` emits flags these compilers accept
# (the MSVC fallback would produce /O2 etc. that gcc rejects).  Clang
# accepts the same opt levels and frame-pointer switch.
GCC_FLAGS: Flags = [
    FlagSet(
        id="gcc_opt",
        flags=("-O0", "-O1", "-O2", "-O3", "-Os"),
    ),
    Checkbox(id="gcc_fomit_frame_pointer", flag="-fomit-frame-pointer"),
    Checkbox(id="gcc_fno_builtin", flag="-fno-builtin"),
]

GCC_SWEEP_TIERS: dict[str, list[str] | None] = {
    "quick": ["gcc_opt"],
    "targeted": ["gcc_opt"],
    "normal": ["gcc_opt", "gcc_fomit_frame_pointer"],
    "thorough": ["gcc_opt", "gcc_fomit_frame_pointer", "gcc_fno_builtin"],
    "full": None,
}
