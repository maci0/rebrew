"""Initialize a new rebrew project directory.

Usage:
    rebrew init [--target NAME] [--binary FILENAME] [--compiler PROFILE]
"""

import re
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
format = "pe"                        # pe | elf | macho
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
base_cflags = "{base_cflags}"       # always-on flags prepended to every compile
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
        "base_cflags": "/nologo /c /MT",
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
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc5": {
        "runner": "wine",
        "command": "wine tools/MSVC500/bin/cl.exe",
        "includes": "tools/MSVC500/include",
        "libs": "tools/MSVC500/lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
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
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc6.3": {
        "runner": "wine",
        "command": "wine tools/msvc6.3/Bin/CL.EXE",
        "includes": "tools/msvc6.3/Include",
        "libs": "",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc6.6": {
        "runner": "wine",
        "command": "wine tools/msvc6.6/Bin/CL.EXE",
        "includes": "tools/msvc6.6/Include",
        "libs": "",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc7": {
        "runner": "wine",  # Alternative: "wibo" (faster, auto-downloadable via rebrew doctor)
        "command": "wine tools/MSVC7/Bin/cl.exe",
        "includes": "tools/MSVC7/Include",
        "libs": "tools/MSVC7/Lib",
        "cflags": "/O2 /Gd",
        "base_cflags": "/nologo /c /MT",
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
        "command": "tools/WATCOM/binl/wcc386",
        "includes": "tools/WATCOM/h",
        "libs": "tools/WATCOM/lib386",
        "cflags": "-zq -ot",
        "base_cflags": "",
        "format": "pe",
        "arch": "x86_32",
        "lang": "C89",
    },
    "msvc1.52": {
        "runner": "",
        "command": "tools/MSVC152/BIN/CL.EXE",
        "includes": "tools/MSVC152/INCLUDE",
        "libs": "tools/MSVC152/LIB",
        "cflags": "/O1",
        "base_cflags": "/nologo /c",
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
    "msvc420": "MSVC420",
    "msvc5": "MSVC500",
    "msvc6": "MSVC600",
    "msvc6.3": "msvc6.3",
    "msvc6.6": "msvc6.6",
    "msvc7": "MSVC7",
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

    src = Path(master).expanduser() / tools_name
    if not src.is_dir():
        error_exit(
            f"Toolchain not found at {src} (pass --link-tools-from <dir containing {tools_name}>)",
            json_mode=json_output,
        )

    dest = cwd / "tools" / tools_name
    dest.parent.mkdir(exist_ok=True)
    if dest.is_symlink() or dest.exists():
        console.print(f"[yellow]tools/{tools_name} already exists; leaving it as-is[/]")
        return dest

    dest.symlink_to(src, target_is_directory=True)
    console.print(f"[green]Linked tools/{tools_name} -> {src}[/]")
    return dest


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

    # Accept both "original/bench.exe" and "bench.exe" — the config already
    # prefixes binary = "original/<name>", so a user-supplied original/
    # must not produce "original/original/bench.exe".
    binary_name = binary_name.replace("\\", "/")
    if binary_name.lower().startswith("original/"):
        binary_name = binary_name[len("original/") :]

    # Look up compiler defaults for the profile
    if compiler_profile not in COMPILER_DEFAULTS:
        known = ", ".join(sorted(COMPILER_DEFAULTS))
        error_exit(
            f"Unknown compiler profile '{compiler_profile}'. Known profiles: {known}",
            json_mode=json_output,
        )
    profile = COMPILER_DEFAULTS[compiler_profile]
    runner = "tools/wibo" if install_wibo else profile["runner"]
    compiler_command = profile["command"]
    if install_wibo and compiler_command.startswith("wine "):
        # wibo runs the CL.EXE directly — drop the wine prefix so
        # resolve_cl_command's runner stripping sees cmd_parts[0] == runner
        # (otherwise the config mixes "tools/wibo" with a "wine" command
        # and every compile fails with a bogus argv).
        compiler_command = compiler_command[len("wine ") :]

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
        cflags=profile["cflags"],
        base_cflags=profile.get("base_cflags", "/nologo /c /MT"),
    )
    toml_content = toml_content.replace("__COMPILER_RUNNER__", runner)
    toml_content = toml_content.replace("__TARGET_ARCH__", profile.get("arch", "x86_32"))
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

    # 9. Optionally symlink the profile toolchain from a master directory
    linked_toolchain: Path | None = None
    if toolchain_dir is not None:
        linked_toolchain = _link_toolchain(cwd, compiler_profile, toolchain_dir, json_output)

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
