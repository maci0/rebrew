"""rebrew intake — one-shot binary onboarding.

Takes a target binary and produces a working rebrew decomp project:

1. Detect the compiler family (DIE -> PDB -> heuristics) and pick a matching
   ``[compiler] profile``.
2. ``rebrew init`` with that profile.
3. Copy the binary into ``original/`` and symlink the vendored toolchain
   (from the rebrew repo's ``tools/`` when present).
4. Enumerate functions via rizin (``aaa``, falling back to ``aa; aap``) and
   write ``functions.txt``.
5. Document every function: a STUB .c + metadata blocker explaining the
   family (the "document-unmatched" step that used to be a per-project
   throwaway script).

The result is a lint-clean project where every function is either matched or
blocker-documented — ready for the per-function decomp loop.

Usage::

    rebrew intake original/game.exe --target game
    rebrew intake game.exe --profile msvc6.3 --dry-run
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import typer
from rich.console import Console
from typer.testing import CliRunner

from rebrew.cli import EXIT_ERROR, EXIT_OK, json_print
from rebrew.utils import atomic_write_text

console = Console(stderr=True)

app = typer.Typer(help="One-shot binary onboarding: init + detect + functions + document.")

#: profile -> (project tools/ link name, vendored toolchain dir in the repo)
_TOOLCHAIN_LINKS: dict[str, tuple[str, str]] = {
    "msvc6": ("MSVC600", "MSVC600"),
    "msvc6.3": ("msvc6.3", "msvc6.3"),
    "msvc6.6": ("msvc6.6", "msvc6.6"),
    "msvc7": ("MSVC7", "msvc7.0"),
    "msvc5": ("MSVC500", "MSVC500"),
    "msvc420": ("MSVC420", "MSVC420"),
}

_REPO_TOOLS = Path(__file__).resolve().parents[2] / "tools"


@dataclass
class IntakeResult:
    """Outcome of an intake run."""

    target: str
    binary: Path
    profile: str
    family: str
    version_hint: str
    function_count: int
    documented: int
    errors: list[str] = field(default_factory=list)
    dry_run: bool = False


def _suggest_profile(binary: Path) -> tuple[str, str, str, list[str]]:
    """Detect the toolchain and pick a profile. Returns (profile, family, hint, notes)."""
    from rebrew.toolchain_detect import detect_toolchain

    info = detect_toolchain(binary)
    notes: list[str] = []
    family = info.family
    hint = info.version_hint
    if family == "msvc":
        profile = "msvc6"
    elif family in ("mingw", "zig"):
        profile = "gcc-pe"
    elif family == "delphi":
        profile = "msvc6"
        notes.append(
            "binary looks Borland Delphi — no rebrew compiler profile can byte-match it; "
            "intake will document functions as blockers"
        )
    else:
        profile = "msvc6"
        notes.append("compiler family not identified — defaulting to msvc6 (check `rebrew doctor`)")
    return profile, family, hint, notes


def _run_rizin_functions(binary: Path) -> list[tuple[int, int, str]]:
    """Enumerate functions via rizin. ``aaa`` first, ``aa; aap`` fallback."""
    for cmd in (["aaa"], ["aa", "aap"]):
        try:
            r = subprocess.run(
                ["rizin", "-q", "-c", "; ".join(cmd) + "; afl", str(binary)],
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        funcs: list[tuple[int, int, str]] = []
        for line in r.stdout.splitlines():
            p = line.split()
            if not p or not p[0].startswith("0x"):
                continue
            try:
                va = int(p[0], 16)
            except ValueError:
                continue
            if len(p) >= 4 and p[2].isdigit():
                size, name = int(p[2]), p[3]
            elif len(p) >= 3:
                size, name = int(p[1]), p[2]
            else:
                continue
            if name in ("->", "loc") or name.startswith("sub."):
                name = f"fcn.{va:08x}"
            funcs.append((va, size, name))
        if funcs:
            return sorted(funcs)
    return []


def blocker_reason(family: str, size: int, version_hint: str) -> str:
    if size <= 8:
        return "IAT import thunk / jump stub — not a decomp target"
    if family == "delphi":
        return (
            "Borland Delphi application code — Delphi ABI not reproducible with rebrew "
            "compilers; documented"
        )
    if family in ("mingw", "zig"):
        return (
            f"MinGW GCC/Zig application code ({version_hint or 'codegen not identifiable'}) — "
            "byte-matching requires the author's exact toolchain version; documented"
        )
    return "Application code — pending per-function decompilation"


def classify_all(
    project: Path,
    src_dir: Path,
    marker: str,
    funcs: list[tuple[int, int, str]],
    family: str,
    hint: str,
    metadata_dir: Path | None = None,
) -> int:
    """Write a STUB .c + blocker for every function (document-unmatched step).

    Shared by ``rebrew intake`` (fresh onboarding) and ``rebrew
    document-unmatched`` (existing projects).  *metadata_dir* defaults to
    ``project/src`` (the standard layout); pass ``cfg.metadata_dir`` to
    honor a custom layout.
    """
    from rebrew.metadata import set_field, update_field

    meta_base = metadata_dir if metadata_dir is not None else project / "src"
    documented = 0
    for va, size, _name in funcs:
        reason = blocker_reason(family, size, hint)
        stub = (
            f"// STUB: {marker} 0x{va:08x}\n\nvoid fcn_{va:08x}(void)\n{{\n    /* {reason} */\n}}\n"
        )
        out = src_dir / f"fcn_{va:08x}.c"
        if not out.exists():
            out.write_text(stub)
        update_field(meta_base, va, "blocker", reason, module=marker)
        set_field(meta_base, va, "status", "STUB", module=marker)
        documented += 1
    return documented


def _link_toolchain(project: Path, profile: str) -> str | None:
    """Symlink the vendored toolchain into project/tools; None when not needed/available."""
    if profile == "gcc-pe":
        return None
    entry = _TOOLCHAIN_LINKS.get(profile)
    if entry is None:
        return None
    link_name, src_name = entry
    tools = project / "tools"
    tools.mkdir(exist_ok=True)
    link = tools / link_name
    src = _REPO_TOOLS / src_name
    if link.exists():
        return str(link)
    if not src.exists():
        return None
    try:
        link.symlink_to(src, target_is_directory=True)
        return str(link)
    except OSError:
        return None


@app.callback(invoke_without_command=True)
def main(
    binary: str = typer.Argument(..., help="Path to the target binary (copied into original/)."),
    profile: str | None = typer.Option(
        None, "--profile", "-p", help="Compiler profile (default: auto-detected)."
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = typer.Option(
        None, "--target", "-t", help="Target name (default: binary stem)."
    ),
) -> None:
    """Run the one-shot onboarding flow in the current directory."""
    bin_path = Path(binary)
    if not bin_path.exists():
        msg = f"binary not found: {bin_path}"
        if json_output:
            json_print({"error": msg, "code": EXIT_ERROR})
        else:
            console.print(f"[red]Error:[/red] {msg}")
        raise typer.Exit(code=EXIT_ERROR)

    target_name = target or bin_path.stem
    marker = re.sub(r"[^A-Za-z0-9_]", "", target_name).upper()

    if profile is None:
        profile, family, hint, notes = _suggest_profile(bin_path)
    else:
        family, hint = "unknown", ""
        notes = []

    if dry_run:
        result = IntakeResult(
            target=target_name,
            binary=bin_path,
            profile=profile,
            family=family,
            version_hint=hint,
            function_count=0,
            documented=0,
            errors=[],
            dry_run=True,
        )
        payload = {
            "dry_run": True,
            "target": result.target,
            "binary": str(result.binary),
            "profile": result.profile,
            "family": result.family,
            "version_hint": result.version_hint,
            "notes": notes,
            "actions": [
                "rebrew init --target <name> --binary <name>.exe --compiler <profile>",
                "copy binary to original/",
                "symlink vendored toolchain into tools/",
                "generate src/<target>/functions.txt via rizin",
                "write STUB .c + blocker per function",
            ],
        }
        if json_output:
            json_print(payload)
        else:
            console.print("[cyan]dry-run:[/cyan] would onboard this binary:")
            console.print(
                f"  target={result.target} profile={result.profile} family={result.family}"
            )
            for note in notes:
                console.print(f"  [yellow]note:[/yellow] {note}")
        raise typer.Exit(code=EXIT_OK)

    # 1. init (in-process via the init Typer app)
    from rebrew.init import app as init_app

    runner = CliRunner()
    init_result = runner.invoke(
        init_app, ["--target", target_name, "--binary", f"{target_name}.exe", "--compiler", profile]
    )
    if init_result.exit_code != 0:
        msg = f"rebrew init failed: {init_result.output[:300]}"
        if json_output:
            json_print({"error": msg, "code": EXIT_ERROR})
        else:
            console.print(f"[red]Error:[/red] {msg}")
        raise typer.Exit(code=EXIT_ERROR)

    project = Path(".")
    # 2. copy the binary
    original_dir = project / "original"
    original_dir.mkdir(exist_ok=True)
    dest = original_dir / f"{target_name}.exe"
    try:
        shutil.copy2(bin_path, dest)
    except OSError as e:
        msg = f"failed to copy binary: {e}"
        if json_output:
            json_print({"error": msg, "code": EXIT_ERROR})
        else:
            console.print(f"[red]Error:[/red] {msg}")
        raise typer.Exit(code=EXIT_ERROR)

    # 3. symlink the vendored toolchain
    linked = _link_toolchain(project, profile)

    # 4. functions.txt via rizin
    funcs = _run_rizin_functions(dest)
    src_dir = project / "src" / target_name
    src_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_text(
        src_dir / "functions.txt",
        "".join(f"0x{va:08x} {name} {size}\n" for va, size, name in funcs),
    )

    # 5. document unmatched functions
    documented = classify_all(project, src_dir, marker, funcs, family, hint)

    result = IntakeResult(
        target=target_name,
        binary=dest,
        profile=profile,
        family=family,
        version_hint=hint,
        function_count=len(funcs),
        documented=documented,
        errors=[],
    )

    if json_output:
        json_print(
            {
                "target": result.target,
                "binary": str(result.binary),
                "profile": result.profile,
                "family": result.family,
                "version_hint": result.version_hint,
                "functions": result.function_count,
                "documented": result.documented,
                "toolchain_link": linked,
                "notes": notes,
                "next": "rebrew doctor && rebrew status --json",
            }
        )
    else:
        console.print(f"[green]Intake complete:[/green] {result.target} ({result.profile})")
        console.print(f"  detected family: {result.family} ({result.version_hint or 'n/a'})")
        console.print(f"  functions: {result.function_count}, documented: {result.documented}")
        if linked:
            console.print(f"  toolchain: {linked}")
        elif profile != "gcc-pe":
            console.print(
                f"[yellow]  toolchain: not found in {_REPO_TOOLS} — symlink tools/ yourself or run rebrew doctor[/yellow]"
            )
        for note in notes:
            console.print(f"  [yellow]note:[/yellow] {note}")
        console.print("  next: rebrew doctor && rebrew status --json")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
