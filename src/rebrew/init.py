"""Initialize a new rebrew project directory.

Usage:
    rebrew init [--target NAME] [--binary FILENAME] [--compiler PROFILE]
"""

import re
import shutil
from pathlib import Path

import tomlkit
import typer
from rich.console import Console

from rebrew.cli import error_exit, json_print
from rebrew.toolchain_detect import ToolchainInfo
from rebrew.utils import atomic_write_text, toolchain_link_candidates

console = Console(stderr=True)

app = typer.Typer(
    help="Initialize a new rebrew project directory.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew init · · · · · · · · · · · · · · · · · Defaults (msvc6, program.exe)\n\n"
        "  rebrew init --target mygame --binary mygame.exe  Name the target and binary\n\n"
        "  rebrew init --compiler msvc7 · · · · · · · · · Use MSVC 7.x compiler profile\n\n"
        "  rebrew init --compiler gcc · · · · · · · · · · Use GCC (ELF targets)\n\n"
        "[bold]What it creates:[/bold]\n\n"
        "  rebrew-project.toml · · · Project configuration (compiler, paths, targets)\n\n"
        "  AGENTS.md · · · · · · · · AI agent instructions for the project\n\n"
        "  original/ · · · · · · · · Place your original binaries here\n\n"
        "  src/<target>/ · · · · · · Directory for reversed .c files\n\n"
        "  bin/<target>/ · · · · · · Directory for extracted .bin files\n\n"
        "[bold]Compiler profiles:[/bold]\n\n"
        "  msvc400 · MSVC 4.0 (C89, PE/x86_32) — via Wine (or wibo)\n\n"
        "  msvc420 · MSVC 4.2 (C89, PE/x86_32) — via Wine (or wibo)\n\n"
        "  msvc5 · · MSVC 5.0 (C89, PE/x86_32) — via Wine (or wibo)\n\n"
        "  msvc6 · · MSVC 6.0 (C89, PE/x86_32) — via Wine (or wibo)\n\n"
        "  msvc7 · · MSVC 7.x (C99 subset, PE/x86_32) — via Wine (or wibo)\n\n"
        "  gcc · · · GCC (C99, ELF/x86_64)\n\n"
        "  clang · · Clang (C99, ELF/x86_64)\n\n"
        "[dim]Run this once in an empty directory, then place your binary in original/.[/dim]"
    ),
)

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

# Per-directory overrides — rebrew-library.toml at a library root can
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
        "runner": "wine",  # Alternative: "wibo" (faster, auto-downloadable via rebrew doctor)
        "command": "wine toolchain/msvc/6.0-win32/source/VC98/Bin/CL.EXE",
        "includes": "toolchain/msvc/6.0-win32/source/VC98/Include",
        "libs": "toolchain/msvc/6.0-win32/source/VC98/Lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc7": {
        "runner": "wine",  # Alternative: "wibo" (faster, auto-downloadable via rebrew doctor)
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
}

_AGENTS_MD_TEMPLATE = Path(__file__).parent / "AGENTS.md.template"


MSVC_CONSTRAINTS = """- **C89 only**: no `for(int i=...)`, declare all variables at block top
- **Comments in code**: use `/* */` only (C89). `//` is used exclusively for annotation headers
- **Symbol decoration**: `_func` for `__cdecl`, `_func@N` for `__stdcall`
- **No `/GS`** (buffer security), no `__declspec(noinline)`
- **Execution**: all CL.EXE/LINK.EXE calls go through Wine"""

MSVC7_CONSTRAINTS = """- **C99 subset**: `for(int i=...)` OK, `//` comments OK
- **Symbol decoration**: `_func` for `__cdecl`, `_func@N` for `__stdcall`
- **Supports `/fp:*`** (floating point model) and `/GS-` (buffer security)
- **Execution**: all CL.EXE/LINK.EXE calls go through Wine"""

GCC_CONSTRAINTS = """- **C99/C11**: standard modern C
- **Symbol decoration**: no leading underscore on Linux
- **ELF format**: use `objdump` / `readelf` for inspection"""


_AGENT_SKILLS_SRC = Path(__file__).parent / "agent-skills"
_PRINCIPLES_SRC = Path(__file__).parent / "PRINCIPLES.md"


#: Compiler families each profile expects (for init's family-alignment
#: warning; "unknown" detections never warn).
_PROFILE_FAMILIES: dict[str, frozenset[str]] = {
    "msvc400": frozenset({"msvc"}),
    "msvc420": frozenset({"msvc"}),
    "msvc5": frozenset({"msvc"}),
    "msvc6": frozenset({"msvc"}),
    "msvc600sp1": frozenset({"msvc"}),
    "msvc600sp2": frozenset({"msvc"}),
    "msvc600sp4": frozenset({"msvc"}),
    "msvc900sp1": frozenset({"msvc"}),
    "msvc1100": frozenset({"msvc"}),
    "msvc7": frozenset({"msvc"}),
    "msvc1.52": frozenset({"msvc"}),
    "borlandc55": frozenset({"borlandc"}),
    "watcom16": frozenset({"watcom"}),
    "gcc-pe": frozenset({"zig", "gcc", "clang", "mingw"}),
    "gcc": frozenset({"gcc", "clang", "icc"}),
    "clang": frozenset({"gcc", "clang", "icc"}),
    "watcom": frozenset({"watcom"}),
}

#: Opposite profile to suggest when the detection contradicts the choice.
_FAMILY_COUNTERPART: dict[str, str] = {
    "zig": "gcc-pe",
    "gcc": "gcc-pe",
    "clang": "gcc-pe",
    "mingw": "gcc-pe",
    "msvc": "msvc6",
    "watcom": "watcom",
    "borlandc": "borlandc55",
    "symantec": "borlandc55",  # Digital Mars — closest free match
    "zortech": "borlandc55",
}


def _warn_profile_family_mismatch(profile: str, tc: ToolchainInfo) -> None:
    """Warn when a high-confidence compiler-family detection contradicts the
    chosen profile — a Zig-built DLL with an ``msvc6`` profile can never
    byte-match, so say so at init instead of after the first verify."""
    family = getattr(tc, "family", "") or ""
    expected = _PROFILE_FAMILIES.get(profile)
    if not expected or family in expected or family == "unknown":
        return
    if getattr(tc, "confidence", "") != "high":
        return
    hint = getattr(tc, "version_hint", "") or ""
    alt = _FAMILY_COUNTERPART.get(family)
    alt_msg = f" — use --compiler {alt}" if alt else ""
    console.print(
        f"[yellow]warning:[/yellow] binary looks like {family}"
        f"{' ' + hint if hint else ''} (high confidence) but profile is "
        f"'{profile}'{alt_msg}; byte matching will not converge"
    )


def _warn_profile_mismatch(profile: str, binary_format: str, arch: str) -> None:
    """Warn when the chosen compiler profile contradicts the detected binary.

    The config is still written with the detected format/arch (so doctor's
    alignment check sees the truth), but the user is told up front — a
    16-bit binary with a 32-bit profile would otherwise fail doctor
    immediately after init.  The 16-bit profile set is derived from
    COMPILER_DEFAULTS so newly added 16-bit profiles (tc16, watcom16, ...)
    are covered automatically instead of a hardcoded list.
    """
    profile_arch = COMPILER_DEFAULTS.get(profile, {}).get("arch", "")
    if not profile_arch:
        return
    _bitness_16 = {name for name, cfg in COMPILER_DEFAULTS.items() if cfg.get("arch") == "x86_16"}
    if arch == "x86_16" and profile not in _bitness_16:
        msg = (
            f"detected a 16-bit binary ({binary_format}/{arch}) but profile "
            f"'{profile}' is a 32-bit compiler — switch to --compiler "
            f"{'/'.join(sorted(_bitness_16))} for byte matching (or document "
            "functions as blockers)"
        )
        # Console is stderr — the --json stdout payload stays pure JSON.
        console.print(f"[yellow]warning:[/yellow] {msg}")
    elif arch and arch != "x86_16" and profile in _bitness_16:
        msg = (
            f"profile '{profile}' is a 16-bit compiler but the binary is "
            f"{binary_format}/{arch} — use a 32-bit profile (e.g. msvc6)"
        )
        console.print(f"[yellow]warning:[/yellow] {msg}")


def _guess_compiler_profile(tc: ToolchainInfo, binary: Path | None) -> str | None:
    """Pick the best-matching rebrew profile for a detected toolchain family.

    Delegates to the shared :func:`rebrew.toolchain_detect.suggest_profile`
    (the single source of truth for family→profile selection, used by init,
    intake, and doctor), falling back to ``_FAMILY_COUNTERPART`` for
    families without a compat set.
    """
    from rebrew.toolchain_detect import suggest_profile

    guess = suggest_profile(tc, binary)
    return guess if guess is not None else _FAMILY_COUNTERPART.get(tc.family)


def _detect_binary_format(path: Path) -> tuple[str, str] | None:
    """Detect ``(format, arch)`` from a binary already placed in original/.

    Uses the shared LIEF-based ``detect_format_and_arch`` (PE/ELF/Mach-O)
    plus the native NE loader for 16-bit Windows targets.  Returns ``None``
    when the format cannot be determined (the caller then keeps the profile
    defaults).
    """
    from rebrew.binary_loader import detect_format_and_arch, is_mz, is_ne

    try:
        fmt, arch = detect_format_and_arch(path)
        if fmt and arch:
            return fmt, arch
    except Exception:
        pass  # not PE/ELF/Mach-O — try NE next
    try:
        if is_ne(path):
            return "ne", "x86_16"
        if is_mz(path):
            return "mz", "x86_16"
    except Exception:
        pass
    return None


def _copy_agent_skills(dest: Path, target_name: str) -> None:
    """Copy bundled agent-skills/ into the project under .agents/skills, substituting <target>."""
    if not _AGENT_SKILLS_SRC.is_dir():
        console.print("[yellow]warning:[/yellow] agent-skills not found in package; skipping.")
        return

    dest_skills = dest / ".agents" / "skills"
    shutil.copytree(_AGENT_SKILLS_SRC, dest_skills, dirs_exist_ok=True)

    # Replace <target> placeholder with the actual target name
    for md_file in dest_skills.rglob("*.md"):
        content = md_file.read_text(encoding="utf-8")
        if "<target>" in content:
            md_file.write_text(content.replace("<target>", target_name), encoding="utf-8")

    console.print("[green]Created .agents/skills/[/] (AI workflow instructions)")


def _write_completion_scripts(project_root: Path) -> list[Path]:
    """Generate bash/zsh/fish completion scripts for the umbrella CLI.

    The live ``rebrew --show-completion`` derives the shell from ``$SHELL``
    and ignores an explicit shell argument, so ``rebrew init
    --install-completions`` generates all three explicitly under
    ``completions/``.  Each script drives the same click completion protocol
    (``_REBREW_COMPLETE`` env var) the installed CLI uses.
    """
    from click.shell_completion import BashComplete, FishComplete, ZshComplete
    from typer.main import get_command

    from rebrew.main import app as umbrella_app

    cli_command = get_command(umbrella_app)
    prog_name = "rebrew"
    complete_var = f"_{prog_name.replace('-', '_').replace('.', '_')}_COMPLETE".upper()

    out_dir = project_root / "completions"
    out_dir.mkdir(exist_ok=True)
    written: list[Path] = []
    for shell, cls in (
        ("bash", BashComplete),
        ("zsh", ZshComplete),
        ("fish", FishComplete),
    ):
        script = cls(cli_command, {}, prog_name, complete_var).source()
        dest = out_dir / f"rebrew.{shell}"
        atomic_write_text(dest, script, encoding="utf-8")
        written.append(dest)
    return written


#: Vendored tools/ subdirectory per compiler profile (for --link-tools-from).
_PROFILE_TOOLS: dict[str, str] = {
    "msvc400": "MSVC400",
    "msvc420": "msvc/4.2-win32",
    "msvc5": "msvc/5.0-win32",
    "msvc6": "msvc/6.0-win32",
    "msvc600sp1": "msvc/6.0-sp1-win32",
    "msvc600sp2": "msvc/6.0-sp2-win32",
    "msvc600sp4": "msvc/6.0-sp4-win32",
    "msvc900sp1": "msvc/9.0-sp1-win32",
    "msvc1100": "msvc/11.0-win32",
    "msvc7": "msvc/7.0-win32",
    "borlandc55": "borland/5.5-win32",
    "watcom16": "watcom/2.0-win32",
    "tc20": "borland/2.0-win16",
    "tc16": "borland/3.1-win16",
}


def _link_toolchain(
    cwd: Path,
    compiler_profile: str,
    master: Path,
    json_output: bool,
) -> Path | None:
    """Symlink the profile's toolchain into ``tools/`` from a master dir.

    The profile's ``compiler.command`` references ``tools/<name>/...``
    relative to the project root; one symlink makes that resolve to the
    master installation (e.g. ``~/zine/tools``).  Returns the linked path,
    or None when the profile has no vendored toolchain dir.
    """
    tools_name = _PROFILE_TOOLS.get(compiler_profile)
    if tools_name is None:
        console.print(
            "[yellow]warning:[/yellow] "
            f"profile '{compiler_profile}' has no vendored toolchain dir — nothing to link"
        )
        return None

    candidates = toolchain_link_candidates(compiler_profile) or [tools_name]
    src: Path | None = None
    for cand in candidates:
        cand_path = Path(master).expanduser() / cand
        if cand_path.is_dir():
            src = cand_path
            break
    if src is None:
        error_exit(
            f"Toolchain not found in {Path(master).expanduser()} "
            f"(looked for {', '.join(candidates)})",
            json_mode=json_output,
        )

    rel = src.relative_to(Path(master).expanduser())
    dest = cwd / "toolchain" / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_symlink() or dest.exists():
        console.print(f"[yellow]toolchain/{rel} already exists; leaving it as-is[/]")
        return dest

    dest.symlink_to(src, target_is_directory=True)
    console.print(f"[green]Linked toolchain/{rel} -> {src}[/]")
    return dest


def _rewrite_compiler_paths(toml_path: Path, layout: tuple[str, str, str]) -> None:
    """Point the generated ``[compiler]`` section at *layout* (command,
    includes, libs) — used after ``--link-tools-from`` may have surfaced a
    better toolchain layout than the pre-write resolution saw."""
    cmd, inc, lib = layout
    doc = tomlkit.parse(toml_path.read_text(encoding="utf-8"))
    compiler = doc.get("compiler", tomlkit.table())
    compiler["command"] = cmd
    if inc:
        compiler["includes"] = inc
    if lib:
        compiler["libs"] = lib
    doc["compiler"] = compiler
    atomic_write_text(toml_path, tomlkit.dumps(doc), encoding="utf-8")


@app.callback(invoke_without_command=True)
def main(
    target_name: str = typer.Option("main", "--target", "-t", help="Name of the initial target."),
    binary_name: str = typer.Option(
        "program.exe",
        "--binary",
        "-b",
        help="Name of the executable binary file (an 'original/' prefix is accepted and stripped).",
    ),
    compiler_profile: str = typer.Option(
        "msvc6", "--compiler", "-c", help="Compiler profile to use."
    ),
    guess_compiler: bool = typer.Option(
        False,
        "--guess-compiler",
        help=(
            "Auto-select the compiler profile from the target binary "
            "(diec → PDB → heuristics; prefers the 16-bit profile for "
            "DOS/NE binaries).  Requires the binary to be in place."
        ),
    ),
    install_wibo: bool = typer.Option(
        False, "--install-wibo", help="Download wibo runner to tools/wibo."
    ),
    install_completions: bool = typer.Option(
        False,
        "--install-completions",
        help="Write bash/zsh/fish completion scripts into completions/.",
    ),
    toolchain_dir: Path | None = typer.Option(
        None,
        "--link-tools-from",
        help=(
            "Master toolchain directory to symlink tools/<profile> from "
            "(e.g. ~/zine/tools).  Skips PATH-based profiles (gcc-pe/gcc/clang)."
        ),
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Initialize a new rebrew project in the current directory.

    Creates a rebrew-project.toml configuration, an AGENTS.md for AI agents,
    and the necessary directory structure for decompilation.
    """
    cwd = Path.cwd()
    toml_path = cwd / "rebrew-project.toml"

    if toml_path.exists():
        error_exit(f"A rebrew-project.toml already exists in {cwd}", json_mode=json_output)

    # Direct Python calls to main() (unit-test convention) leak
    # typer.OptionInfo for omitted params — a documented typer quirk (see
    # docs/DEVELOPMENT.md).  Normalize to the declared default.
    from rebrew.cli import option_default

    toolchain_dir = option_default(toolchain_dir, None)
    guess_compiler = option_default(guess_compiler, False)

    # Accept both "original/bench.exe" and "bench.exe" — the config already
    # prefixes binary = "original/<name>", so a user-supplied original/
    # must not produce "original/original/bench.exe".
    binary_name = binary_name.replace("\\", "/")
    if binary_name.lower().startswith("original/"):
        binary_name = binary_name[len("original/") :]

    # --guess-compiler: auto-select the profile from the target binary
    # (must already be in place under original/).  Runs before the profile
    # defaults are looked up so the guessed profile drives the whole
    # config generation.
    binary_path = cwd / "original" / binary_name
    if guess_compiler:
        if not binary_path.exists():
            error_exit(
                f"cannot guess compiler: binary not found at {binary_path} "
                "(copy it into original/ first)",
                json_mode=json_output,
            )
        from rebrew.toolchain_detect import detect_toolchain

        guess_tc = detect_toolchain(binary_path)
        guess = _guess_compiler_profile(guess_tc, binary_path)
        if guess is None:
            error_exit(
                f"cannot guess a compiler profile for {binary_path} "
                f"(detected family {guess_tc.family!r}) — pass --compiler "
                "<profile> explicitly (see --help for the list)",
                json_mode=json_output,
            )
        if guess != compiler_profile:
            console.print(
                f"[green]guessed compiler[/green] {guess} "
                f"(detected {guess_tc.family} {guess_tc.version_hint or ''})"
            )
            compiler_profile = guess

    # Look up compiler defaults for the profile
    if compiler_profile not in COMPILER_DEFAULTS:
        known = ", ".join(sorted(COMPILER_DEFAULTS))
        error_exit(
            f"Unknown compiler profile '{compiler_profile}'. Known profiles: {known}",
            json_mode=json_output,
        )
    profile = COMPILER_DEFAULTS[compiler_profile]
    if compiler_profile in ("msvc6", "msvc7"):
        # The msvc6/msvc7 defaults point at the full master layouts
        # (toolchain/msvc/6.0-win32/source/VC98, toolchain/msvc/7.0-win32).  Machines that only vendor the
        # compile-only mirrors (toolchain/msvc/6.0-sp6-win32 / msvc-6.0-sp3-win32 / msvc-7.0-win32) must not
        # get a broken path — resolve the best layout actually present
        # (project tools/ first, then the rebrew install's own vendored
        # tree) and write those paths into the generated config.
        from rebrew.utils import resolve_msvc_toolchain

        layout = resolve_msvc_toolchain(cwd, compiler_profile)
        if layout is not None:
            cmd, inc, lib = layout
            profile = {**profile, "command": cmd, "includes": inc, "libs": lib}
    # Docker-only execution: every Windows/DOS toolchain compiles through
    # its docker image, so the legacy host wine command/runner are inert —
    # write an empty command so fresh projects are docker-native (no stale
    # "wine toolchain/..." line that doctor/verify might misread).  Native
    # profiles without an image (gcc-pe, watcom16 wcc) keep their command.
    from rebrew.toolchain import TOOLCHAINS

    _spec = TOOLCHAINS.get(compiler_profile)
    if _spec is not None and _spec.image is not None:
        # wibo is a host-wine alternative — obsolete under docker-only
        # execution; ignore --install-wibo for image-backed profiles.
        profile = {**profile, "command": "", "runner": ""}
        install_wibo = False
    runner = "tools/wibo" if install_wibo else profile["runner"]
    compiler_command = profile["command"]
    if install_wibo and compiler_command.startswith("wine "):
        # wibo runs the CL.EXE directly — drop the wine prefix so
        # resolve_cl_command's runner stripping sees cmd_parts[0] == runner
        # (otherwise the config mixes "tools/wibo" with a "wine" command
        # and every compile fails with a bogus argv).
        compiler_command = compiler_command[len("wine ") :]

    # Auto-detect the binary's format/arch when it is already in place
    # (original/<name>) — otherwise the profile's hardcoded defaults (pe /
    # x86_32) silently mislabel NE 16-bit targets (skifree16 got
    # "pe, x86_32" while its binary is NE 16-bit).  The detected values
    # override the profile defaults for both the config and AGENTS.md.
    binary_format = profile.get("format", "pe")
    target_arch = profile.get("arch", "x86_32")
    binary_path = cwd / "original" / binary_name
    if binary_path.exists():
        detected = _detect_binary_format(binary_path)
        if detected is not None:
            binary_format, target_arch = detected

    # Warn when the detected format/arch contradicts the chosen profile —
    # e.g. a 16-bit NE binary with a 32-bit msvc6 profile (doctor will flag
    # it as a misalignment; surface it here instead of after the fact).
    _warn_profile_mismatch(compiler_profile, binary_format, target_arch)

    # Compiler-family alignment: a high-confidence detection that contradicts
    # the profile (Zig-built DLL with msvc6) can never byte-match — warn at
    # init, not after the first verify.  Also used below for CRT linkage.
    tc = None
    if binary_path.exists():
        try:
            from rebrew.toolchain_detect import detect_toolchain

            tc = detect_toolchain(binary_path)
            _warn_profile_family_mismatch(compiler_profile, tc)
        except Exception:
            pass  # detection is best-effort; keep the profile default

    # Auto-detect CRT linkage when the binary is already in place: a dynamic
    # CRT (msvcrt.dll import) requires /MD rather than the /MT default.
    # Compiling libc-calling functions with the wrong linkage breaks
    # byte-matching at every CRT call site (e.g. memcpy becomes a rel32
    # call instead of an IAT call).
    base_cflags = profile.get("base_cflags", "/nologo /c /MT")
    cflags = profile.get("cflags", "/O2 /Gd")
    if tc is not None and compiler_profile.startswith("msvc"):
        if tc.base_cflags:
            base_cflags = f"/nologo /c {tc.base_cflags}"
            console.print(
                f"[cyan]CRT linkage:[/cyan] {tc.crt} "
                f"({tc.crt_linkage}) — base_cflags={tc.base_cflags}"
            )
        # Optimization fingerprint: /O1 vs /O2 change wrapper codegen, so
        # seed the project default from the binary instead of assuming /O2.
        # A "mixed" verdict is left at the default (per-function sweeps).
        if tc.opt_level in ("/O1", "/O2") and tc.opt_level != cflags.split()[0]:
            console.print(
                f"[cyan]Optimization:[/cyan] fingerprint shows {tc.opt_level} — "
                f"setting compiler cflags"
            )
            cflags = f"{tc.opt_level} /Gd"

    # 1. Write rebrew-project.toml
    toml_content = DEFAULT_REBREW_TOML.format(
        project_name=cwd.name,
        target_name=target_name,
        binary_name=binary_name,
        marker=re.sub(r"[^A-Za-z0-9_]", "", target_name).upper(),
        compiler_profile=compiler_profile,
        compiler_command=compiler_command,
        compiler_includes=profile["includes"],
        compiler_libs=profile["libs"],
        cflags=cflags,
        base_cflags=base_cflags,
    )
    toml_content = toml_content.replace("__COMPILER_RUNNER__", runner)
    toml_content = toml_content.replace("__TARGET_FORMAT__", binary_format)
    toml_content = toml_content.replace("__TARGET_ARCH__", target_arch)
    atomic_write_text(toml_path, toml_content, encoding="utf-8")
    console.print(f"[green]Created {toml_path.name}[/]")

    # 2. Write AGENTS.md (for LLM agents)
    if compiler_profile.startswith("msvc6"):
        constraints = MSVC_CONSTRAINTS
    elif compiler_profile.startswith("msvc"):
        constraints = MSVC7_CONSTRAINTS
    else:
        constraints = GCC_CONSTRAINTS

    agents_template = _AGENTS_MD_TEMPLATE.read_text(encoding="utf-8")
    agents_content = agents_template.format(
        project_name=cwd.name,
        target_name=target_name,
        binary_name=binary_name,
        binary_format=binary_format,
        arch=target_arch,
        compiler_profile=compiler_profile,
        compiler_command=profile["command"],
        compiler_constraints=constraints,
        cflags=profile["cflags"],
        lang=profile.get("lang", "C89"),
    )
    agents_path = cwd / "AGENTS.md"
    atomic_write_text(agents_path, agents_content, encoding="utf-8")
    console.print(f"[green]Created {agents_path.name}[/] (AI agent instructions)")

    # 3. Create directories
    original_dir = cwd / "original"
    original_dir.mkdir(exist_ok=True)
    console.print(f"[green]Created {original_dir.name}/[/] (Place your original binaries here)")

    src_dir = cwd / "src" / target_name
    src_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"[green]Created src/{target_name}/[/]")

    bin_dir = cwd / "bin" / target_name
    bin_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"[green]Created bin/{target_name}/[/]")

    # 4. Create empty function list
    func_list = src_dir / "functions.txt"
    func_list.touch(exist_ok=True)
    console.print(f"[green]Created src/{target_name}/functions.txt[/]")

    # 5. Create metadata TOML files (in src/, not src/<target>/)
    metadata_parent = src_dir.parent  # src/
    func_toml = metadata_parent / "rebrew-function.toml"
    func_toml.touch(exist_ok=True)
    data_toml = metadata_parent / "rebrew-data.toml"
    data_toml.touch(exist_ok=True)
    console.print("[green]Created src/rebrew-function.toml[/]")
    console.print("[green]Created src/rebrew-data.toml[/]")

    # 6. Copy agent-skills directory (bundled with the package)
    _copy_agent_skills(cwd, target_name)

    # 7. Copy PRINCIPLES.md to project root
    if _PRINCIPLES_SRC.is_file():
        principles_dest = cwd / "PRINCIPLES.md"
        if not principles_dest.exists():
            shutil.copy2(_PRINCIPLES_SRC, principles_dest)
            console.print("[green]Created PRINCIPLES.md[/] (Project design principles)")

    # 8. Optionally download wibo runner
    if install_wibo:
        from rebrew.wibo import download_wibo

        wibo_path = cwd / "tools" / "wibo"
        tag_name = download_wibo(wibo_path)
        console.print(f"[green]Downloaded wibo {tag_name} to {wibo_path}[/]")

    # 9. Optionally symlink the profile toolchain from a master directory
    linked_toolchain: Path | None = None
    if toolchain_dir is not None:
        linked_toolchain = _link_toolchain(cwd, compiler_profile, toolchain_dir, json_output)
        # The link may have just created a better layout than the pre-write
        # resolution saw (e.g. a master toolchain/msvc/6.0-win32) — re-resolve and
        # point the written [compiler] section at it.
        if compiler_profile in ("msvc6", "msvc7"):
            from rebrew.utils import resolve_msvc_toolchain

            layout = resolve_msvc_toolchain(cwd, compiler_profile)
            if layout is not None:
                _rewrite_compiler_paths(toml_path, layout)

    # 10. Optionally write shell completion scripts
    completion_paths: list[Path] = []
    if install_completions:
        completion_paths = _write_completion_scripts(cwd)
        for p in completion_paths:
            console.print(f"[green]Created {p.relative_to(cwd)}[/] (source this for completions)")

    if json_output:
        json_print(
            {
                "project_root": str(cwd),
                "toml": str(toml_path),
                "target": target_name,
                "binary": binary_name,
                "compiler": compiler_profile,
                "directories": [
                    str(original_dir),
                    str(src_dir),
                    str(bin_dir),
                ],
                "completions": [str(p) for p in completion_paths],
                "linked_toolchain": str(linked_toolchain) if linked_toolchain else None,
            }
        )
    else:
        console.print("\n[bold cyan]Initialization complete! Next steps:[/]")
        console.print(f"1. Copy your original binary to original/{binary_name}")
        console.print("2. Verify your compiler paths in rebrew-project.toml")
        console.print("3. Run 'rebrew todo' to get started!")
        if install_completions:
            console.print("\n[bold cyan]Shell completion:[/]")
            console.print("  bash: source completions/rebrew.bash")
            console.print("  zsh:  source completions/rebrew.zsh")
            console.print("  fish: source completions/rebrew.fish")


# Alias so main.py can register the command as ``init`` without renaming the callback.
init = main


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
