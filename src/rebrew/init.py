"""Initialize a new rebrew project directory.

Usage:
    rebrew init [--target NAME] [--binary FILENAME] [--compiler PROFILE]
"""

import shutil
from pathlib import Path

import typer

from rebrew.cli import error_exit

app = typer.Typer(
    help="Initialize a new rebrew project directory.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]

rebrew init                                        Defaults (msvc6, program.exe)

rebrew init --target server --binary server.dll    Name the target and binary

rebrew init --compiler msvc7                       Use MSVC 7.x compiler profile

rebrew init --compiler gcc                         Use GCC (ELF targets)

[bold]What it creates:[/bold]

rebrew-project.toml            Project configuration (compiler, paths, targets)

AGENTS.md              AI agent instructions for the project

original/              Place your original binaries here

src/<target>/           Directory for reversed .c files

bin/<target>/           Directory for extracted .bin files

[bold]Compiler profiles:[/bold]

msvc6    MSVC 6.0 (C89, PE/x86_32) — via Wine (or wibo)

msvc7    MSVC 7.x (C99 subset, PE/x86_32) — via Wine (or wibo)

gcc      GCC (C99, ELF/x86_64)

clang    Clang (C99, ELF/x86_64)

[dim]Run this once in an empty directory, then place your binary in original/.[/dim]""",
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
origins = ["GAME"]                   # valid ORIGIN values for annotations
# ignored_symbols = []              # symbols to skip (ASM builtins etc.)

# Per-target cflags presets — keyed by ORIGIN, override global presets.
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
    "msvc6": {
        "runner": "wine",
        "command": "wine tools/MSVC600/VC98/Bin/CL.EXE",
        "includes": "tools/MSVC600/VC98/Include",
        "libs": "tools/MSVC600/VC98/Lib",
        "cflags": "/O2 /Gd",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc7": {
        "runner": "wine",
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

DEFAULT_AGENTS_MD = """# AGENTS.md — {project_name}

> Auto-generated by `rebrew init`. Describes the decomp workflow for AI agents.

## Project

- **Target**: `{binary_name}` ({binary_format}, {arch})
- **Compiler**: {compiler_profile} (`{compiler_command}`)
- **Language**: {lang} — follow compiler constraints below
- **Config**: `rebrew-project.toml` (all tools read from here)

## Quick Start

```
1. rebrew triage --json                        # assess the binary
2. rebrew next --json                          # pick next function
3. rebrew skeleton 0x<VA>                      # generate .c skeleton
4. rebrew test src/{target_name}/<func>.c --json  # compile + compare
5. # iterate code until STATUS: EXACT or RELOC
6. rebrew promote src/{target_name}/<func>.c --json  # update STATUS
```

## CLI Tools

Use `--json` for structured output (preferred for agents).

| Command | Use |
|---------|-----|
| `rebrew triage --json` | Combined overview: coverage, near-misses, recommendations |
| `rebrew doctor` | Check toolchain and project health |
| `rebrew next --json` | Find next function to reverse (sorted by similarity) |
| `rebrew next --improving --json` | List MATCHING functions sorted by byte delta |
| `rebrew skeleton 0x<VA>` | Generate C skeleton from address |
| `rebrew test <file> --json` | Compile and byte-compare against target |
| `rebrew match --diff-only <file> --json` | Structured byte diff |
| `rebrew match --flag-sweep-only <file>` | Find best compiler flags for a single function |
| `rebrew match <file> --json` | Run GA matching engine |
| `rebrew ga --flag-sweep --json` | Batch flag sweep on all MATCHING functions |
| `rebrew ga --near-miss --threshold 5` | Batch GA on MATCHING functions with small deltas |
| `rebrew promote <file> --json` | Test + atomically update STATUS |
| `rebrew rename <old> <new>` | Rename function and update cross-references |
| `rebrew status --json` | Coverage progress |
| `rebrew verify --json` | Bulk verify all reversed files |
| `rebrew lint --json` | Validate annotations |
| `rebrew data --json` | Inventory globals in .data/.rdata/.bss |
| `rebrew graph --format summary` | Dependency graph stats and blockers |
| `rebrew catalog --json` | Generate coverage catalog |
| `rebrew flirt --json` | FLIRT scan for known library functions |
| `rebrew extract --json` | Batch extract and disassemble functions |
| `rebrew asm 0x<VA> --size 128 --json` | Quick offline disassembly |
| `rebrew sync --push` | Push annotations to Ghidra |
| `rebrew sync --summary --json` | Preview what would be synced |

## Annotation Format

Every reversed `.c` file starts with:

```c
// FUNCTION: {target_name} 0x<virtual_address>
// STATUS: STUB
// ORIGIN: GAME
// SIZE: <bytes>
// CFLAGS: {cflags}
// SYMBOL: _function_name
```

**STATUS**: `EXACT` (byte-perfect) > `RELOC` (match after masking relocations)
> `MATCHING` (close) > `STUB` (incomplete)

## Compiler Constraints ({compiler_profile})

{compiler_constraints}

## Agent Skills

Detailed workflow instructions are in `agent-skills/`:

| Skill | Use When |
|-------|----------|
| `rebrew-intake` | Onboarding a new binary, initial triage |
| `rebrew-workflow` | End-to-end function reversing workflow |
| `rebrew-matching` | Flag sweeping, GA engine, diff analysis |
| `rebrew-data-analysis` | Globals, dispatch tables, BSS debugging |

Read the `SKILL.md` in each directory for step-by-step instructions.
"""

MSVC_CONSTRAINTS = """- **C89 only**: no `for(int i=...)`, declare all variables at block top
- **Comments**: use `/* */` (not `//` in strict mode)
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


def _copy_agent_skills(dest: Path, target_name: str) -> None:
    """Copy bundled agent-skills/ into the project, substituting <target>."""
    if not _AGENT_SKILLS_SRC.is_dir():
        typer.secho(
            "Warning: agent-skills not found in package; skipping.",
            fg=typer.colors.YELLOW,
            err=True,
        )
        return

    dest_skills = dest / "agent-skills"
    shutil.copytree(_AGENT_SKILLS_SRC, dest_skills, dirs_exist_ok=True)

    # Replace <target> placeholder with the actual target name
    for md_file in dest_skills.rglob("*.md"):
        content = md_file.read_text(encoding="utf-8")
        if "<target>" in content:
            md_file.write_text(content.replace("<target>", target_name), encoding="utf-8")

    typer.secho("Created agent-skills/ (AI workflow instructions)", fg=typer.colors.GREEN)


@app.callback(invoke_without_command=True)
def main(
    target_name: str = typer.Option("main", "--target", "-t", help="Name of the initial target."),
    binary_name: str = typer.Option(
        "program.exe", "--binary", "-b", help="Name of the executable binary file."
    ),
    compiler_profile: str = typer.Option(
        "msvc6", "--compiler", "-c", help="Compiler profile to use."
    ),
) -> None:
    """
    Initialize a new rebrew project in the current directory.

    Creates a rebrew-project.toml configuration, an AGENTS.md for AI agents,
    and the necessary directory structure for decompilation.
    """
    cwd = Path.cwd()
    toml_path = cwd / "rebrew-project.toml"

    if toml_path.exists():
        error_exit(f"A rebrew-project.toml already exists in {cwd}")

    # Look up compiler defaults for the profile
    if compiler_profile not in COMPILER_DEFAULTS:
        known = ", ".join(sorted(COMPILER_DEFAULTS))
        error_exit(f"Unknown compiler profile '{compiler_profile}'. Known profiles: {known}")
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
    toml_content = toml_content.replace("__COMPILER_RUNNER__", profile["runner"])
    toml_path.write_text(toml_content, encoding="utf-8")
    typer.secho(f"Created {toml_path.name}", fg=typer.colors.GREEN)

    # 2. Write AGENTS.md (for LLM agents)
    if compiler_profile.startswith("msvc6"):
        constraints = MSVC_CONSTRAINTS
    elif compiler_profile.startswith("msvc"):
        constraints = MSVC7_CONSTRAINTS
    else:
        constraints = GCC_CONSTRAINTS

    agents_content = DEFAULT_AGENTS_MD.format(
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
    agents_path.write_text(agents_content, encoding="utf-8")
    typer.secho(f"Created {agents_path.name} (AI agent instructions)", fg=typer.colors.GREEN)

    # 3. Create directories
    original_dir = cwd / "original"
    original_dir.mkdir(exist_ok=True)
    typer.secho(
        f"Created {original_dir.name}/ (Place your original binaries here)", fg=typer.colors.GREEN
    )

    src_dir = cwd / "src" / target_name
    src_dir.mkdir(parents=True, exist_ok=True)
    typer.secho(f"Created src/{target_name}/", fg=typer.colors.GREEN)

    bin_dir = cwd / "bin" / target_name
    bin_dir.mkdir(parents=True, exist_ok=True)
    typer.secho(f"Created bin/{target_name}/", fg=typer.colors.GREEN)

    # 4. Create empty function list
    func_list = src_dir / "functions.txt"
    func_list.touch(exist_ok=True)
    typer.secho(f"Created src/{target_name}/functions.txt", fg=typer.colors.GREEN)

    # 5. Copy agent-skills directory (bundled with the package)
    _copy_agent_skills(cwd, target_name)

    typer.secho("\nInitialization complete! Next steps:", fg=typer.colors.CYAN, bold=True)
    typer.echo(f"1. Copy your original binary to original/{binary_name}")
    typer.echo("2. Verify your compiler paths in rebrew-project.toml")
    typer.echo("3. Run 'rebrew next --stats' to get started!")


init = main


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
