"""Initialize a new rebrew project directory.

Usage:
    rebrew init [--target NAME] [--binary FILENAME] [--compiler PROFILE]
"""

import shutil
from pathlib import Path

import typer
from rich.console import Console

from rebrew.cli import error_exit, json_print
from rebrew.utils import atomic_write_text

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
# Multiple targets are supported.  Tools default to the first target
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
format = "pe"                        # pe | elf | macho
arch = "x86_32"                      # x86_32 | x86_64 | arm32 | arm64
reversed_dir = "src/{target_name}"   # directory containing reversed .c files
function_list = "src/{target_name}/functions.txt"
bin_dir = "bin/{target_name}"        # directory for extracted .bin files
source_ext = ".c"                      # source file extension (.c, .cpp, etc.)
# ignored_symbols = []              # symbols to skip (ASM builtins etc.)

# Per-target cflags presets — keyed by module name, override global presets.
# [targets."{target_name}".cflags_presets]
# GAME = "/O2 /Gd"

# Per-target compiler override (optional — falls back to global [compiler]).
# [targets."{target_name}".compiler]
# command = "wine tools/MSVC600/VC98/Bin/CL.EXE"

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
base_cflags = "/nologo /c /MT"       # always-on flags prepended to every compile
timeout = 60                         # compile subprocess timeout (seconds)

[compiler.cflags_presets]
GAME = "{cflags}"

# Alternative compiler profiles — select with --profile <name> (future).
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
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc420": {
        "runner": "wine",
        "command": "wine tools/MSVC420/bin/cl.exe",
        "includes": "tools/MSVC420/include",
        "libs": "tools/MSVC420/lib",
        "cflags": "/O2 /Gd",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc6": {
        "runner": "wine",  # Alternative: "wibo" (faster, auto-downloadable via rebrew doctor)
        "command": "wine tools/MSVC600/VC98/Bin/CL.EXE",
        "includes": "tools/MSVC600/VC98/Include",
        "libs": "tools/MSVC600/VC98/Lib",
        "cflags": "/O2 /Gd",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc7": {
        "runner": "wine",  # Alternative: "wibo" (faster, auto-downloadable via rebrew doctor)
        "command": "wine tools/MSVC7/Bin/CL.EXE",
        "includes": "tools/MSVC7/Include",
        "libs": "tools/MSVC7/Lib",
        "cflags": "/O2 /Gd",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C99",
    },
    "clang": {
        "runner": "",
        "command": "clang",
        "includes": "/usr/include",
        "libs": "/usr/lib",
        "cflags": "-O2",
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
        "format": "elf",
        "arch": "x86_64",
        "lang": "C99",
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


def _copy_agent_skills(dest: Path, target_name: str) -> None:
    """Copy bundled agent-skills/ into the project under .agents/skills, substituting <target>."""
    if not _AGENT_SKILLS_SRC.is_dir():
        console.print("[yellow]Warning: agent-skills not found in package; skipping.[/]")
        return

    dest_skills = dest / ".agents" / "skills"
    shutil.copytree(_AGENT_SKILLS_SRC, dest_skills, dirs_exist_ok=True)

    # Replace <target> placeholder with the actual target name
    for md_file in dest_skills.rglob("*.md"):
        content = md_file.read_text(encoding="utf-8")
        if "<target>" in content:
            md_file.write_text(content.replace("<target>", target_name), encoding="utf-8")

    console.print("[green]Created .agents/skills/[/] (AI workflow instructions)")


@app.callback(invoke_without_command=True)
def main(
    target_name: str = typer.Option("main", "--target", "-t", help="Name of the initial target."),
    binary_name: str = typer.Option(
        "program.exe", "--binary", "-b", help="Name of the executable binary file."
    ),
    compiler_profile: str = typer.Option(
        "msvc6", "--compiler", "-c", help="Compiler profile to use."
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    install_wibo: bool = typer.Option(
        False, "--install-wibo", help="Download wibo runner to tools/wibo."
    ),
) -> None:
    """Initialize a new rebrew project in the current directory.

    Creates a rebrew-project.toml configuration, an AGENTS.md for AI agents,
    and the necessary directory structure for decompilation.
    """
    cwd = Path.cwd()
    toml_path = cwd / "rebrew-project.toml"

    if toml_path.exists():
        error_exit(f"A rebrew-project.toml already exists in {cwd}", json_mode=json_output)

    # Look up compiler defaults for the profile
    if compiler_profile not in COMPILER_DEFAULTS:
        known = ", ".join(sorted(COMPILER_DEFAULTS))
        error_exit(
            f"Unknown compiler profile '{compiler_profile}'. Known profiles: {known}",
            json_mode=json_output,
        )
    profile = COMPILER_DEFAULTS[compiler_profile]

    # 1. Write rebrew-project.toml
    toml_content = DEFAULT_REBREW_TOML.format(
        project_name=cwd.name,
        target_name=target_name,
        binary_name=binary_name,
        compiler_profile=compiler_profile,
        compiler_command=profile["command"],
        compiler_includes=profile["includes"],
        compiler_libs=profile["libs"],
        cflags=profile["cflags"],
    )
    runner = "tools/wibo" if install_wibo else profile["runner"]
    toml_content = toml_content.replace("__COMPILER_RUNNER__", runner)
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
        binary_format=profile.get("format", "pe"),
        arch=profile.get("arch", "x86_32"),
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
            }
        )
    else:
        console.print("\n[bold cyan]Initialization complete! Next steps:[/]")
        console.print(f"1. Copy your original binary to original/{binary_name}")
        console.print("2. Verify your compiler paths in rebrew-project.toml")
        console.print("3. Run 'rebrew todo' to get started!")


init = main


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
