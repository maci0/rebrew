"""init_profiles.py — declarative data and profile policy for rebrew init.

Holds the new-project template, the per-profile compiler defaults, the
per-profile constraint blocks, and the family tables, plus the two merge
helpers that extend the packaged tables from the toolchain registry.  init.py
keeps the interactive wizard and the CLI and imports everything here.
"""

DEFAULT_REBREW_TOML = """# rebrew project configuration
# This file defines the target binaries, source layout, compiler, and
# architecture so that every tool reads from a single source of truth.
#
# Multiple targets are supported.  Tools use project.default_target
# unless --target <name> is passed.

# ---------------------------------------------------------------------------
# Project-level settings
# ---------------------------------------------------------------------------

[project]
name = "{project_name}"
default_target = "{target_name}"   # target used when --target is not passed
jobs = 4                           # default parallelism for verify/batch/GA
# db_dir = "db"                    # coverage database output
# output_dir = "output"            # GA run output

# ---------------------------------------------------------------------------
# Target definitions
# ---------------------------------------------------------------------------

[targets."{target_name}"]
binary = "original/{binary_name}"
format = "__TARGET_FORMAT__"               # pe | elf | macho | ne | mz
arch = "__TARGET_ARCH__"               # x86_16 | x86_32 | x86_64 | arm32 | arm64
reversed_dir = "src/{target_name}"   # directory containing reversed .c files
function_list = "src/{target_name}/functions.txt"
bin_dir = "bin/{target_name}"        # directory for extracted .bin files
source_ext = ".c"                      # source file extension (.c, .cpp, etc.)
marker = "{marker}"                  # annotation marker (e.g. // FUNCTION: SERVER 0x...)
# ignored_symbols = []              # symbols to skip (ASM builtins etc.)

# Per-target cflags presets — keyed by module name, override global presets.
# [targets."{target_name}".cflags_presets]
# GAME = "/O2 /Gd"

# Per-target compiler override (optional — falls back to global [compiler]).
# Windows/DOS toolchains run ONLY through their docker image; leave the
# command/runner empty (the profile drives the image).  E.g.:
# [targets."{target_name}".compiler]
# profile = "msvc600sp6"

# ---------------------------------------------------------------------------
# Global compiler settings — shared across all targets
# ---------------------------------------------------------------------------

[compiler]
profile = "{compiler_profile}"
runner = "__COMPILER_RUNNER__"
command = "{compiler_command}"
includes = "{compiler_includes}"
libs = "{compiler_libs}"
cflags = "{cflags}"
base_cflags = "{base_cflags}"       # always-on flags prepended to every compile
timeout = 60                         # compile subprocess timeout (seconds)

[compiler.cflags_presets]
GAME = "{cflags}"

# Per-directory overrides — rebrew-libraries.toml at a library root can
# declare toolchain + flags for a whole subtree; per-function TOOLCHAIN/CFLAGS
# metadata wins.  See docs/TOOLCHAIN.md.
# [compiler.profiles.clang]
# command = "clang"
# includes = "/usr/include"
# libs = "/usr/lib"
# cflags = "-O2"
"""


COMPILER_DEFAULTS: dict[str, dict[str, str]] = {
    "msvc400": {
        "runner": "wine",
        "command": "wine tools/MSVC400/bin/cl.exe",
        "includes": "tools/MSVC400/include",
        "libs": "tools/MSVC400/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc420": {
        "runner": "wine",
        "command": "wine toolchain/msvc/4.2-win32/source/bin/cl.exe",
        "includes": "toolchain/msvc/4.2-win32/source/include",
        "libs": "toolchain/msvc/4.2-win32/source/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc5": {
        "runner": "wine",
        "command": "wine toolchain/msvc/5.0-win32/source/bin/cl.exe",
        "includes": "toolchain/msvc/5.0-win32/source/include",
        "libs": "toolchain/msvc/5.0-win32/source/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc6": {
        "runner": "wine",
        "command": "wine toolchain/msvc/6.0-win32/source/VC98/Bin/CL.EXE",
        "includes": "toolchain/msvc/6.0-win32/source/VC98/Include",
        "libs": "toolchain/msvc/6.0-win32/source/VC98/Lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    # Deprecated alias of msvc710: the "7.0-win32" dir/image actually holds
    # the VC 7.1 compiler (cl 13.10.3077) — the 7.0 name is a mislabel.
    "msvc7": {
        "runner": "wine",
        "command": "wine toolchain/msvc/7.0-win32/source/Bin/cl.exe",
        "includes": "toolchain/msvc/7.0-win32/source/Include",
        "libs": "toolchain/msvc/7.0-win32/source/Lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C99",
    },
    "msvc700": {
        "runner": "wine",
        "command": "wine toolchain/msvc/7.0-rtm-win32/source/Vc7/bin/cl.exe",
        "includes": "toolchain/msvc/7.0-rtm-win32/source/Vc7/include",
        "libs": "toolchain/msvc/7.0-rtm-win32/source/Vc7/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C99",
    },
    "msvc700sp1": {
        "runner": "wine",
        "command": "wine toolchain/msvc/7.0-sp1-win32/source/Vc7/bin/cl.exe",
        "includes": "toolchain/msvc/7.0-sp1-win32/source/Vc7/include",
        "libs": "toolchain/msvc/7.0-sp1-win32/source/Vc7/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C99",
    },
    "msvc710": {
        "runner": "wine",
        "command": "wine toolchain/msvc/7.1-win32/source/Vc7/bin/cl.exe",
        "includes": "toolchain/msvc/7.1-win32/source/Vc7/include",
        "libs": "toolchain/msvc/7.1-win32/source/Vc7/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C99",
    },
    "msvc710sp1": {
        "runner": "wine",
        "command": "wine toolchain/msvc/7.1-sp1-win32/source/Vc7/bin/cl.exe",
        "includes": "toolchain/msvc/7.1-sp1-win32/source/Vc7/include",
        "libs": "toolchain/msvc/7.1-sp1-win32/source/Vc7/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C99",
    },
    "msvc800": {
        "runner": "wine",
        "command": "wine toolchain/msvc/8.0-win32/source/VC/bin/cl.exe",
        "includes": "toolchain/msvc/8.0-win32/source/VC/include",
        "libs": "toolchain/msvc/8.0-win32/source/VC/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C99",
    },
    "msvc800sp1": {
        "runner": "wine",
        "command": "wine toolchain/msvc/8.0-sp1-win32/source/VC/bin/cl.exe",
        "includes": "toolchain/msvc/8.0-sp1-win32/source/VC/include",
        "libs": "toolchain/msvc/8.0-sp1-win32/source/VC/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C99",
    },
    "msvc900": {
        "runner": "wine",
        "command": "wine toolchain/msvc/9.0-win32/source/VC/bin/cl.exe",
        "includes": "toolchain/msvc/9.0-win32/source/VC/include",
        "libs": "toolchain/msvc/9.0-win32/source/VC/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C99",
    },
    "msvc1000": {
        "runner": "wine",
        "command": "wine toolchain/msvc/10.0-win32/source/VC/bin/cl.exe",
        "includes": "toolchain/msvc/10.0-win32/source/VC/include",
        "libs": "toolchain/msvc/10.0-win32/source/VC/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C99",
    },
    "msvc1000sp1": {
        "runner": "wine",
        "command": "wine toolchain/msvc/10.0-sp1-win32/source/VC/bin/cl.exe",
        "includes": "toolchain/msvc/10.0-sp1-win32/source/VC/include",
        "libs": "toolchain/msvc/10.0-sp1-win32/source/VC/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C99",
    },
    "msvc200": {
        "runner": "wine",
        "command": "wine toolchain/msvc/2.0-win32/source/bin/cl.exe",
        "includes": "toolchain/msvc/2.0-win32/source/include",
        "libs": "toolchain/msvc/2.0-win32/source/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc410": {
        "runner": "wine",
        "command": "wine toolchain/msvc/4.1-win32/source/bin/CL.EXE",
        "includes": "toolchain/msvc/4.1-win32/source/include",
        "libs": "toolchain/msvc/4.1-win32/source/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc500sp1": {
        "runner": "wine",
        "command": "wine toolchain/msvc/5.0-sp1-win32/source/bin/cl.exe",
        "includes": "toolchain/msvc/5.0-sp1-win32/source/include",
        "libs": "toolchain/msvc/5.0-sp1-win32/source/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc500sp2": {
        "runner": "wine",
        "command": "wine toolchain/msvc/5.0-sp2-win32/source/bin/cl.exe",
        "includes": "toolchain/msvc/5.0-sp2-win32/source/include",
        "libs": "toolchain/msvc/5.0-sp2-win32/source/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc500sp3": {
        "runner": "wine",
        "command": "wine toolchain/msvc/5.0-sp3-win32/source/bin/cl.exe",
        "includes": "toolchain/msvc/5.0-sp3-win32/source/include",
        "libs": "toolchain/msvc/5.0-sp3-win32/source/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc600sp1": {
        "runner": "wine",
        "command": "wine toolchain/msvc/6.0-sp1-win32/source/VC98/bin/CL.EXE",
        "includes": "toolchain/msvc/6.0-sp1-win32/source/VC98/include",
        "libs": "toolchain/msvc/6.0-sp1-win32/source/VC98/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc600sp2": {
        "runner": "wine",
        "command": "wine toolchain/msvc/6.0-sp2-win32/source/VC98/bin/CL.EXE",
        "includes": "toolchain/msvc/6.0-sp2-win32/source/VC98/include",
        "libs": "toolchain/msvc/6.0-sp2-win32/source/VC98/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc600sp3": {
        "runner": "wine",
        "command": "wine toolchain/msvc/6.0-sp3-win32/source/Bin/CL.EXE",
        "includes": "toolchain/msvc/6.0-sp3-win32/source/Include",
        "libs": "",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc600sp4": {
        "runner": "wine",
        "command": "wine toolchain/msvc/6.0-sp4-win32/source/VC98/bin/CL.EXE",
        "includes": "toolchain/msvc/6.0-sp4-win32/source/VC98/include",
        "libs": "toolchain/msvc/6.0-sp4-win32/source/VC98/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc600sp5": {
        "runner": "wine",
        "command": "wine toolchain/msvc/6.0-sp5-win32/source/VC98/Bin/CL.EXE",
        "includes": "toolchain/msvc/6.0-sp5-win32/source/VC98/Include",
        "libs": "toolchain/msvc/6.0-sp5-win32/source/VC98/Lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc600sp6": {
        "runner": "wine",
        "command": "wine toolchain/msvc/6.0-sp6-win32/source/Bin/CL.EXE",
        "includes": "toolchain/msvc/6.0-sp6-win32/source/Include",
        "libs": "",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc900sp1": {
        "runner": "wine",
        "command": "wine toolchain/msvc/9.0-sp1-win32/source/VC/bin/cl.exe",
        "includes": "toolchain/msvc/9.0-sp1-win32/source/VC/include",
        "libs": "toolchain/msvc/9.0-sp1-win32/source/VC/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc1100": {
        "runner": "wine",
        "command": "wine toolchain/msvc/11.0-win32/source/VC/bin/cl.exe",
        "includes": "toolchain/msvc/11.0-win32/source/VC/include",
        "libs": "toolchain/msvc/11.0-win32/source/VC/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc15": {
        "runner": "",
        "command": "toolchain/msvc/1.5-win16/source/BIN/CL.EXE",
        "includes": "toolchain/msvc/1.5-win16/source/INCLUDE",
        "libs": "toolchain/msvc/1.5-win16/source/LIB",
        "cflags": "/O1",
        "base_cflags": "/nologo /c",
        "format": "pe",
        "arch": "x86_16",
        "lang": "C89",
    },
    "msvc10": {
        "runner": "",
        "command": "toolchain/msvc/1.0-win16/source/BIN/CL.EXE",
        "includes": "toolchain/msvc/1.0-win16/source/INCLUDE",
        "libs": "toolchain/msvc/1.0-win16/source/LIB",
        "cflags": "/O1",
        "base_cflags": "/nologo /c",
        "format": "pe",
        "arch": "x86_16",
        "lang": "C89",
    },
    "clang": {
        "runner": "",
        "command": "clang",
        "includes": "/usr/include",
        "libs": "/usr/lib",
        "cflags": "-O2",
        "base_cflags": "",
        "format": "elf",
        "arch": "x86_64",
        "lang": "C99",
    },
    "gcc": {
        "runner": "",
        "command": "gcc",
        "includes": "/usr/include",
        "libs": "/usr/lib",
        "cflags": "-O2",
        "base_cflags": "",
        "format": "elf",
        "arch": "x86_64",
        "lang": "C99",
    },
    "gcc-pe": {
        "runner": "",
        "command": "i686-w64-mingw32-gcc",
        "includes": "",
        "libs": "",
        "cflags": "-O2",
        "base_cflags": "",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C99",
    },
    "watcom": {
        "runner": "",
        "command": "toolchain/watcom/2.0-win32/source/binl/wcc386",
        "includes": "toolchain/watcom/2.0-win32/source/h",
        "libs": "toolchain/watcom/2.0-win32/source/lib386",
        "cflags": "-zq -ot",
        "base_cflags": "",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc1.52": {
        "runner": "",
        "command": "toolchain/msvc/1.52-win16/source/BIN/CL.EXE",
        "includes": "toolchain/msvc/1.52-win16/source/INCLUDE",
        "libs": "toolchain/msvc/1.52-win16/source/LIB",
        "cflags": "/O1",
        "base_cflags": "/nologo /c",
        "format": "pe",
        "arch": "x86_16",
        "lang": "C89",
    },
    "tc20": {
        "runner": "",
        "command": "toolchain/borland/2.0-win16/source/BIN/TCC.EXE",
        "includes": "toolchain/borland/2.0-win16/source/INCLUDE",
        "libs": "toolchain/borland/2.0-win16/source/LIB",
        "cflags": "",
        "base_cflags": "-c",
        "format": "pe",
        "arch": "x86_16",
        "lang": "C89",
    },
    "tc16": {
        "runner": "",
        "command": "toolchain/borland/3.1-win16/source/BIN/TCC.EXE",
        "includes": "toolchain/borland/3.1-win16/source/INCLUDE",
        "libs": "toolchain/borland/3.1-win16/source/LIB",
        "cflags": "",
        "base_cflags": "-c",
        "format": "pe",
        "arch": "x86_16",
        "lang": "C89",
    },
    "borlandc55": {
        "runner": "wine",
        "command": "wine toolchain/borland/5.5-win32/source/Bin/bcc32.exe",
        "includes": "toolchain/borland/5.5-win32/source/Include",
        "libs": "toolchain/borland/5.5-win32/source/Lib",
        "cflags": "-O2",
        "base_cflags": "-c",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "delphi16": {
        # Docker-only (rebrew/delphi:1.0-win16) — command/includes/libs are
        # blanked by the image check below; compile_ne stages its own DCC.CFG.
        # Matching is NOT wired for Delphi (ADR-001): this profile sets up a
        # research project (compile + NE parse), functions stay blockers.
        "runner": "",
        "command": "",
        "includes": "",
        "libs": "",
        "cflags": "",
        "base_cflags": "",
        "format": "ne",
        "arch": "x86_16",
        "lang": "Object Pascal",
    },
    "watcom16": {
        "runner": "",
        "command": "toolchain/watcom/2.0-win32/source/binl/wcc",
        "includes": "toolchain/watcom/2.0-win32/source/h",
        "libs": "toolchain/watcom/2.0-win32/source/lib386",
        "cflags": "-bt=dos",
        "base_cflags": "-c",
        "format": "pe",
        "arch": "x86_16",
        "lang": "C89",
    },
    "ido5.3": {
        "runner": "",
        "command": "",
        "includes": "",
        "libs": "",
        "cflags": "-O2",
        "base_cflags": "",
        "format": "elf",
        "arch": "mips32",
        "lang": "C89",
    },
    "ido7.1": {
        "runner": "",
        "command": "",
        "includes": "",
        "libs": "",
        "cflags": "-O2",
        "base_cflags": "",
        "format": "elf",
        "arch": "mips32",
        "lang": "C89",
    },
}


def profile_defaults() -> dict[str, dict[str, str]]:
    """Defaults for every known profile: :data:`COMPILER_DEFAULTS` merged
    with registry-derived entries.

    Any ``TOOLCHAINS`` name without a hand-written entry (a plugin
    toolchain, or a future packaged profile) is synthesized from its spec —
    flags style drives cflags, ``bits = 16`` drives the arch — so every
    ``toolchain list`` name is accepted by ``init``/``cfg set-compiler``.
    The binary is detection-corrected at write time when it is in place, so
    the synthesized format/arch only matter for empty projects.
    """
    from rebrew.toolchain import TOOLCHAINS

    merged = dict(COMPILER_DEFAULTS)
    for name, spec in TOOLCHAINS.items():
        if name in merged:
            continue
        posix = spec.flags_style == "posix"
        merged[name] = {
            "runner": "",
            "command": spec.binary if spec.image is None else "",
            "includes": "",
            "libs": "",
            "cflags": "-O2" if posix else "/O2 /Gd",
            "base_cflags": "" if posix else "/nologo /c",
            "format": "elf" if posix and spec.image is None else "pe",
            "arch": "x86_16" if spec.bits == 16 else "x86_32",
            "lang": "C99" if posix else "C89",
        }
    return merged


MSVC_CONSTRAINTS = """- **C89 only**: no `for(int i=...)`, declare all variables at block top
- **Comments in code**: use `/* */` only (C89). `//` is used exclusively for annotation headers
- **Symbol decoration**: `_func` for `__cdecl`, `_func@N` for `__stdcall`
- **No `/GS`** (buffer security), no `__declspec(noinline)`
- **Execution**: all CL.EXE/LINK.EXE calls run inside the toolchain's docker image (wine lives in the image; there is no host wine/wibo fallback)"""

MSVC7_CONSTRAINTS = """- **C99 subset**: `for(int i=...)` OK, `//` comments OK
- **Symbol decoration**: `_func` for `__cdecl`, `_func@N` for `__stdcall`
- **Supports `/fp:*`** (floating point model) and `/GS-` (buffer security)
- **Execution**: all CL.EXE/LINK.EXE calls run inside the toolchain's docker image (wine lives in the image; there is no host wine/wibo fallback)"""

GCC_CONSTRAINTS = """- **C99/C11**: standard modern C
- **Symbol decoration**: no leading underscore on Linux
- **ELF format**: use `objdump` / `readelf` for inspection"""

DELPHI16_CONSTRAINTS = """- **Object Pascal**: Delphi 1.0 compiles Pascal, not C — there is no C source to write
- **Matching not wired** (ADR-001): Delphi's Borland ABI has no byte-matching profile; document functions as blockers
- **Research path**: `rebrew.delphi16.compile_ne` compiles NE executables headless (DCC.EXE inside the rebrew/delphi:1.0-win16 image / DOSBox)"""


#: Compiler families each profile expects (for init's family-alignment
#: warning; "unknown" detections never warn).  The packaged base table;
#: :func:`profile_families` extends it from the toolchain registry so every
#: `toolchain list` name is covered.
PROFILE_FAMILIES: dict[str, frozenset[str]] = {
    "msvc400": frozenset({"msvc"}),
    "msvc420": frozenset({"msvc"}),
    "msvc5": frozenset({"msvc"}),
    "msvc6": frozenset({"msvc"}),
    "msvc600sp1": frozenset({"msvc"}),
    "msvc600sp2": frozenset({"msvc"}),
    "msvc600sp3": frozenset({"msvc"}),
    "msvc600sp4": frozenset({"msvc"}),
    "msvc600sp5": frozenset({"msvc"}),
    "msvc600sp6": frozenset({"msvc"}),
    "msvc900sp1": frozenset({"msvc"}),
    "msvc1100": frozenset({"msvc"}),
    "msvc7": frozenset({"msvc"}),
    "msvc1.52": frozenset({"msvc"}),
    "msvc15": frozenset({"msvc"}),
    "msvc10": frozenset({"msvc"}),
    "borlandc55": frozenset({"borlandc"}),
    "tc16": frozenset({"borlandc"}),
    "tc20": frozenset({"borlandc"}),
    "delphi16": frozenset({"delphi"}),
    "watcom16": frozenset({"watcom"}),
    "watcom": frozenset({"watcom"}),
    "gcc-pe": frozenset({"zig", "gcc", "clang", "mingw"}),
    "gcc": frozenset({"gcc", "clang", "icc"}),
    "clang": frozenset({"gcc", "clang", "icc"}),
    "ido5.3": frozenset({"ido"}),
    "ido7.1": frozenset({"ido"}),
}


def profile_families() -> dict[str, frozenset[str]]:
    """Expected detection families per profile: the packaged table plus the
    registry.

    Any ``TOOLCHAINS`` name missing from :data:`PROFILE_FAMILIES` (a plugin
    toolchain, or a future packaged profile) joins with the detection
    families its name is compatible with (inverted
    ``_PROFILE_COMPAT_ALL``) plus its own spec family — an uncovered profile
    otherwise skips the alignment warning entirely, silently onboarding the
    wrong compiler.
    """
    from rebrew.toolchain import TOOLCHAINS
    from rebrew.toolchain_detect import _PROFILE_COMPAT_ALL

    merged = dict(PROFILE_FAMILIES)
    compat_of: dict[str, set[str]] = {}
    for family, profiles in _PROFILE_COMPAT_ALL.items():
        if not profiles:
            continue
        for p in profiles:
            compat_of.setdefault(p, set()).add(family)
    for name, spec in TOOLCHAINS.items():
        if name in merged:
            continue
        merged[name] = frozenset(compat_of.get(name, set()) | {spec.family})
    return merged


#: Opposite profile to suggest when the detection contradicts the choice.
FAMILY_COUNTERPART: dict[str, str] = {
    "zig": "gcc-pe",
    "gcc": "gcc-pe",
    "clang": "gcc-pe",
    "mingw": "gcc-pe",
    "msvc": "msvc6",
    "watcom": "watcom",
    "borlandc": "borlandc55",
    "delphi": "delphi16",
    "symantec": "borlandc55",  # Digital Mars — closest free match
    "zortech": "borlandc55",
}
