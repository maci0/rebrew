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
from typing import Any

import typer
from rich.console import Console
from typer.testing import CliRunner

from rebrew.cli import EXIT_OK, error_exit, json_print
from rebrew.skeleton import C89_STRICT_PROFILES
from rebrew.utils import atomic_write_text

console = Console(stderr=True)

app = typer.Typer(help="One-shot binary onboarding: init + detect + functions + document.")

#: profile -> (project tools/ link name, vendored toolchain dir in the repo)
_TOOLCHAIN_LINKS: dict[str, tuple[str, str]] = {
    "msvc6": ("msvc/6.0-win32", "msvc/6.0-win32"),
    "msvc600sp3": ("msvc/6.0-sp3-win32", "msvc/6.0-sp3-win32"),
    "msvc600sp6": ("msvc/6.0-sp6-win32", "msvc/6.0-sp6-win32"),
    "msvc7": ("msvc/7.0-win32", "msvc/7.0-win32"),
    "msvc5": ("msvc/5.0-win32", "msvc/5.0-win32"),
    "msvc420": ("msvc/4.2-win32", "msvc/4.2-win32"),
    "msvc1.52": ("msvc/1.52-win16", "msvc/1.52-win16"),
    "watcom": ("watcom/2.0-win32", "watcom/2.0-win32"),
    "watcom16": ("watcom/2.0-win32", "watcom/2.0-win32"),
    "tc16": ("borland/3.1-win16", "borland/3.1-win16"),
    "tc20": ("borland/2.0-win16", "borland/2.0-win16"),
}

REPO_TOOLS = Path(__file__).resolve().parents[2] / "tools"


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
    from rebrew.toolchain_detect import detect_toolchain, suggest_profile

    info = detect_toolchain(binary)
    notes: list[str] = []
    family = info.family
    hint = info.version_hint
    profile = suggest_profile(info, binary)
    if family == "msvc" and info.arch == "x86_16":
        notes.append(
            "binary is 16-bit NE (x86_16) — using the msvc1.52 profile "
            "(DOSBox CL.EXE, 16-bit OMF objects)"
        )
    elif family == "watcom":
        notes.append(
            "binary looks Watcom C/C++ — byte matching works via the watcom "
            "profile (OMF objects, see docs/OMF_NOTES.md)"
        )
    elif family == "delphi":
        notes.append(
            "binary looks Borland Delphi — no rebrew compiler profile can byte-match it; "
            "intake will document functions as blockers"
        )
    if profile is None:
        profile = "msvc6"
        notes.append("compiler family not identified — defaulting to msvc6 (check `rebrew doctor`)")
    elif family == "borlandc":
        notes.append(
            f"binary looks Borland C/C++ — using the {profile} profile "
            "(Turbo C++ 3.1 / bcc32 objects, see docs/TOOLCHAIN.md)"
        )
    return profile, family, hint, notes


def _run_ne_functions(binary: Path) -> list[tuple[int, int, str]]:
    """Enumerate functions in a 16-bit NE binary via the built-in linear
    sweep (rizin cannot analyze NE).  Returns ``[(va, size, name)]`` with
    synthetic flat VAs (``segment << 16 | offset``)."""
    from rebrew.binary_loader import load_binary
    from rebrew.ne_loader import enumerate_ne_functions

    info = load_binary(binary)
    return [(f.va, f.size, f.name) for f in enumerate_ne_functions(info)]


def _enumerate_functions(binary: Path) -> list[tuple[int, int, str]]:
    """Function list for a binary: NE linear sweep for 16-bit targets, rizin
    otherwise."""
    from rebrew.binary_loader import is_ne

    if is_ne(binary):
        return _run_ne_functions(binary)
    return _run_rizin_functions(binary)


def _run_rizin_functions(binary: Path) -> list[tuple[int, int, str]]:
    """Enumerate functions via rizin. ``aaa`` first, ``aa; aap`` fallback."""
    from rebrew.catalog import parse_rizin_afl

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
        funcs = parse_rizin_afl(r.stdout)
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
            "byte-exact matching requires the author's exact toolchain version; "
            "structural matching may be viable"
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
    profile: str = "",
) -> int:
    """Write a STUB .c + blocker for every function (document-unmatched step).

    Shared by ``rebrew intake`` (fresh onboarding) and ``rebrew
    document-unmatched`` (existing projects).  *metadata_dir* defaults to
    ``project/src`` (the standard layout); pass ``cfg.metadata_dir`` to
    honor a custom layout.
    """
    from rebrew.metadata import load_metadata, set_fields_batch, update_statuses_batch

    meta_base = metadata_dir if metadata_dir is not None else project / "src"
    documented = 0
    # Two batched metadata writes (fields + statuses) instead of per-function
    # RMWs — the old loop was O(N) full toml rewrites (~5 min for a
    # 646-function NE target; perf-review F2 shape, discovered via intake).
    existing = load_metadata(meta_base)
    existing_sizes = {(mod, va): fields.get("size") for (mod, va), fields in existing.items()}
    field_updates: list[dict[str, Any]] = []
    status_updates: list[dict[str, Any]] = []
    for va, size, _name in funcs:
        reason = blocker_reason(family, size, hint)
        # C89-strict 16-bit profiles (Turbo C 2.0 etc.) reject `//` —
        # emit the block-comment marker form so the stub still compiles.
        use_block = profile in C89_STRICT_PROFILES
        if use_block:
            stub = (
                f"/* STUB: {marker} 0x{va:08x} */\n\n"
                f"void fcn_{va:08x}(void)\n{{\n    /* {reason} */\n}}\n"
            )
        else:
            stub = (
                f"// STUB: {marker} 0x{va:08x}\n\n"
                f"void fcn_{va:08x}(void)\n{{\n    /* {reason} */\n}}\n"
            )
        out = src_dir / f"fcn_{va:08x}.c"
        if not out.exists():
            from rebrew.utils import atomic_write_text

            atomic_write_text(out, stub)
        prev = existing.get((marker, va), {})
        prev_status = str(prev.get("status") or "STUB")
        # Onboarding is a one-shot document step — a RE-RUN (re-discovery
        # via `rebrew intake` on an existing project) must never demote a
        # function the user has since worked on.  Skip the STUB status
        # write for any non-STUB entry (EXACT/RELOC/NEAR_MATCHING/...), and
        # never clobber a user-written blocker (only the auto-generated
        # reason is replaced on re-documentation).
        if prev_status != "STUB":
            continue
        prev_blocker = str(prev.get("blocker") or "")
        fields: dict[str, Any] = {}
        if prev_blocker and prev_blocker != reason:
            # A user-supplied blocker survives re-runs; only the auto reason
            # for a fresh/unblocked stub is written.
            pass
        else:
            fields["blocker"] = reason
        # Record the disassembly-derived size in metadata: a documented stub
        # without a SIZE is untestable (rebrew test refuses "Invalid SIZE: 0",
        # verify reports MISSING_SIZE, and the vacuous 0-byte diff pollutes
        # todo as a fake "0B diff" quick-win).  Never clobber a user-corrected
        # size.
        if size > 0 and existing_sizes.get((marker, va)) is None:
            fields["size"] = size
        if fields:
            field_updates.append({"module": marker, "va": va, "fields": fields})
        status_updates.append(
            {"module": marker, "va": va, "new_status": "STUB", "clear_blockers": False}
        )
        documented += 1
    set_fields_batch(meta_base, field_updates)
    update_statuses_batch(meta_base, status_updates)
    return documented


_AUTO_STUB_RE = re.compile(
    r"^(?://|/\*) STUB: ([A-Za-z0-9_]+) 0x([0-9a-fA-F]{8})(?: \*)?\n\nvoid fcn_\2\(void\)\n\{"
)


def prune_stale_stubs(
    project: Path,
    src_dir: Path,
    marker: str,
    funcs: list[tuple[int, int, str]],
    metadata_dir: Path | None = None,
) -> int:
    """Remove auto-generated STUB files + metadata for functions absent from
    the (re-discovered) function list.

    Re-running intake after a discovery change (rizin update, NE fix, …) can
    leave orphaned ``fcn_<va>.c`` stubs behind — they inflate ``rebrew
    status`` totals and clutter the source tree.  This prunes only files
    whose content still matches the exact auto-stub pattern for *marker*;
    any file the user has edited or renamed is untouched.  A metadata entry
    is removed only together with its stub file, so progressed functions
    (renamed/edited sources) are never dropped.  Returns the number of
    stale stubs removed.
    """
    from rebrew.metadata import delete_metadata_entry

    valid_vas = {va for va, _size, _name in funcs}
    meta_base = metadata_dir if metadata_dir is not None else project / "src"
    removed = 0
    for path in sorted(src_dir.glob("fcn_*.c")):
        text = path.read_text(encoding="utf-8", errors="replace")
        m = _AUTO_STUB_RE.match(text)
        if m is None or m.group(1) != marker:
            continue
        va = int(m.group(2), 16)
        if va in valid_vas:
            continue
        path.unlink()
        delete_metadata_entry(meta_base, va, marker)
        removed += 1
    return removed


def _set_target_arch(project: Path, target_name: str, arch: str, fmt: str) -> None:
    """Patch ``[targets.<name>].arch`` / ``format`` in ``rebrew-project.toml``
    (format-preserving tomlkit round-trip).  Used to set ``x86_16`` for NE
    targets — init defaults every profile to x86_32, which mis-disassembles
    16-bit code — and ``format = "ne"`` so the config does not claim PE for a
    16-bit Windows 3.x binary."""
    import tomlkit

    toml_path = project / "rebrew-project.toml"
    doc = tomlkit.parse(toml_path.read_text(encoding="utf-8"))
    targets = doc.get("targets")
    if targets is not None and target_name in targets:
        targets[target_name]["arch"] = arch
        targets[target_name]["format"] = fmt
        toml_path.write_text(tomlkit.dumps(doc), encoding="utf-8")


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
    src = REPO_TOOLS / src_name
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
        error_exit(msg, json_mode=json_output)

    target_name = target or bin_path.stem
    marker = re.sub(r"[^A-Za-z0-9_]", "", target_name).upper()

    if profile is None:
        profile, family, hint, notes = _suggest_profile(bin_path)
    else:
        family, hint = "unknown", ""
        notes = []

    if dry_run:
        # Preview mode: enumerate functions too (rizin is a read-only
        # subprocess — no writes happen), so the preview tells the user how
        # many functions would actually be documented instead of a thin 0.
        funcs = _enumerate_functions(bin_path)
        preview_count = len(funcs)
        result = IntakeResult(
            target=target_name,
            binary=bin_path,
            profile=profile,
            family=family,
            version_hint=hint,
            function_count=preview_count,
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
            "function_count": preview_count,
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
                f" — {preview_count} function(s) would be documented"
            )
            for note in notes:
                console.print(f"  [yellow]note:[/yellow] {note}")
        raise typer.Exit(code=EXIT_OK)

    # 1. init (in-process via the init Typer app) — skipped when the project
    #    already exists so re-running intake is idempotent (re-discovery).
    from rebrew.init import app as init_app

    runner = CliRunner()
    project_existed = (Path(".") / "rebrew-project.toml").exists()
    if project_existed:
        notes.append("project already exists — re-running intake (re-discovery)")
    else:
        init_result = runner.invoke(
            init_app,
            ["--target", target_name, "--binary", f"{target_name}.exe", "--compiler", profile],
        )
        if init_result.exit_code != 0:
            msg = f"rebrew init failed: {init_result.output[:300]}"
            error_exit(msg, json_mode=json_output)

    project = Path(".")
    # 16-bit DOS/NE targets must disassemble as x86-16 — init defaults every
    # profile to x86_32, which misdecodes segmented 16-bit code — and the
    # config must not claim PE for them.
    from rebrew.binary_loader import is_mz, is_ne

    if is_ne(bin_path):
        _set_target_arch(project, target_name, "x86_16", fmt="ne")
        notes.append("16-bit NE target — target arch set to x86_16 (CS_MODE_16)")
    elif is_mz(bin_path):
        _set_target_arch(project, target_name, "x86_16", fmt="mz")
        notes.append("plain DOS MZ target — target arch set to x86_16 (CS_MODE_16)")

    # 2. copy the binary
    original_dir = project / "original"
    original_dir.mkdir(exist_ok=True)
    dest = original_dir / f"{target_name}.exe"
    try:
        shutil.copy2(bin_path, dest)
    except OSError as e:
        msg = f"failed to copy binary: {e}"
        error_exit(msg, json_mode=json_output)

    # 3. symlink the vendored toolchain
    linked = _link_toolchain(project, profile)

    # 4. functions.txt via rizin
    funcs = _enumerate_functions(dest)
    if not funcs:
        # A project with an empty function list is not a successful
        # onboarding — rizin is missing, timed out, or could not analyze the
        # binary.  Fail loudly instead of reporting "Intake complete: 0".
        msg = (
            "rizin produced no functions — install rizin (or fix the analysis "
            "timeout) and re-run intake; the project scaffold was still created"
        )
        error_exit(msg, json_mode=json_output)

    src_dir = project / "src" / target_name
    src_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_text(
        src_dir / "functions.txt",
        "".join(f"0x{va:08x} {name} {size}\n" for va, size, name in funcs),
    )

    # 5. document unmatched functions
    documented = classify_all(project, src_dir, marker, funcs, family, hint, profile=profile)
    # 6. prune auto-stubs orphaned by a changed function list (re-discovery
    #    only — a fresh onboarding has nothing stale).
    if project_existed:
        pruned = prune_stale_stubs(project, src_dir, marker, funcs)
        if pruned:
            notes.append(f"pruned {pruned} stale auto-stub(s) from the previous discovery")

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
        else:
            # Docker-backed profiles run through their image — the vendored
            # tree symlink is a build-source nicety, not an execution
            # requirement.  Say so instead of "symlink tools/ yourself".
            from rebrew.toolchain import TOOLCHAINS

            spec = TOOLCHAINS.get(profile)
            if spec is not None and spec.image is not None:
                console.print(
                    f"  toolchain: {profile} runs through docker image "
                    f"{spec.image} — run 'rebrew toolchain build {profile}' "
                    "if the image is missing"
                )
            elif profile != "gcc-pe":
                console.print(
                    f"[yellow]  toolchain: not found in {REPO_TOOLS} — symlink "
                    "tools/ yourself or run rebrew doctor[/yellow]"
                )
        for note in notes:
            console.print(f"  [yellow]note:[/yellow] {note}")
        console.print("  next: rebrew doctor && rebrew status --json")
        console.print("  first run? see docs/ONBOARDING.md for the walkthrough")


def main_entry() -> None:
    """Run the Typer CLI application.

    The callback is registered as a plain command on a fresh app: the
    group-style ``invoke_without_command`` callback fails to parse
    positional-then-option invocations (``rebrew-<cmd> ARG --opt`` — click
    treats the positional as a command name), while the umbrella's command
    registration parses both orderings (cli-review F1).
    """
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
