"""rebrew intake — one-shot binary onboarding.

Takes a target binary and produces a working rebrew decomp project:

1. Detect the compiler family (DIE -> PDB -> heuristics) and pick a matching
   ``[compiler] profile``.
2. ``rebrew init`` with that profile.
3. Copy the binary into ``original/`` and symlink the vendored toolchain
   (from the rebrew repo's ``tools/`` when present).
4. Enumerate functions via the discoverer plugins and
   write ``function_structure.json``.
5. Document every function: a STUB .c + metadata blocker explaining the
   family (the "document-unmatched" step that used to be a per-project
   throwaway script).

The result is a lint-clean project where every function is either matched or
blocker-documented — ready for the per-function decomp loop.

Usage::

    rebrew intake ./game.exe --target game
    rebrew intake game.exe --toolchain msvc-6.0-sp3 --dry-run
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from typer.testing import CliRunner

from rebrew.annotation import iter_annotations
from rebrew.cli import EXIT_OK, error_exit, json_print
from rebrew.skeleton import C89_STRICT_PROFILES
from rebrew.sources import iter_sources
from rebrew.utils import SOURCE_CHECKOUT, atomic_write_text

console = Console(stderr=True)

app = typer.Typer(help="One-shot binary onboarding: init + detect + functions + document.")


def _link_names_for(profile: str) -> tuple[str, str] | None:
    """Derive the ``(link_name, src_name)`` toolchain symlink for *profile*.

    Image ``rebrew/<family>:<tag>`` maps to ``<family>/<tag>`` (the
    vendored toolchain layout, e.g. msvc-6.0 → ``msvc/6.0-win32``).
    ``None`` for an image-less spec (a plugin toolchain — nothing to link)
    and unknown profiles.
    """
    from rebrew.toolchain import TOOLCHAINS

    spec = TOOLCHAINS.get(profile)
    if spec is None or spec.image is None:
        return None
    _repo, _, tag = spec.image.partition(":")
    if not tag:
        return None
    name = f"{spec.family}/{tag}"
    return name, name


REPO_TOOLS: Path | None = SOURCE_CHECKOUT / "tools" if SOURCE_CHECKOUT is not None else None


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
            "binary is 16-bit NE (x86_16) — using the msvc-1.52 profile "
            "(DOSBox CL.EXE, 16-bit OMF objects)"
        )
    elif family == "watcom":
        notes.append(
            "binary looks Watcom C/C++ — byte matching works via the watcom-2.0-win32 "
            "profile (OMF objects, see docs/OMF_NOTES.md)"
        )
    elif family == "delphi":
        notes.append(
            "binary looks Borland Delphi — no rebrew compiler profile can byte-match it; "
            "intake will document functions as blockers"
        )
    if profile is None:
        profile = "msvc-6.0"
        notes.append(
            "compiler family not identified — defaulting to msvc-6.0 (check `rebrew doctor`)"
        )
    elif family == "borlandc":
        notes.append(
            f"binary looks Borland C/C++ — using the {profile} profile "
            "(Turbo C++ 3.1 / bcc32 objects, see docs/TOOLCHAIN.md)"
        )
    return profile, family, hint, notes


def _enumerate_functions(binary: Path) -> list[tuple[int, int, str]]:
    """Function list for a binary via the discoverer plugins.

    The same pipeline ``rebrew discover-functions`` runs (packaged rizin /
    capstone / NE / MZ providers plus ``rebrew.discoverers`` plugins),
    minus the capstone-refine pass ``discover`` applies — intake writes the
    raw inventory and lets ``rebrew test --fix-sizes`` converge sizes later.
    """
    from rebrew.discover import discover_functions

    return sorted(discover_functions(binary).functions)


def blocker_reason(family: str, size: int, version_hint: str) -> str:
    """Why an enumerated function is documented-only (too small, vendor-specific, ...)."""
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
    honor a custom layout. Existing annotations for *marker* anywhere under
    *src_dir* prevent duplicate stubs after a source is renamed or moved.
    """
    from rebrew.metadata import load_metadata, set_fields_batch, update_statuses_batch

    meta_base = metadata_dir if metadata_dir is not None else project / "src"
    existing_vas = {
        ann["va"]
        for _, annotations in iter_annotations(iter_sources(src_dir), target=marker)
        for ann in annotations
    }
    documented = 0
    # Two batched metadata writes (fields + statuses) instead of per-function
    # RMWs, each of which rewrites the whole TOML.
    existing = load_metadata(meta_base, deepcopy=False)
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
        if va not in existing_vas and not out.exists():
            atomic_write_text(out, stub)
            existing_vas.add(va)
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
            {
                "module": marker,
                "va": va,
                "new_status": "STUB",
                "clear_blockers": False,
                "updated_by": "intake",
            }
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

    Re-running intake after a discovery change (new plugin, NE fix, …) can
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
    doc = tomlkit.parse(toml_path.read_text(encoding="utf-8-sig"))
    targets = doc.get("targets")
    if targets is not None and target_name in targets:
        targets[target_name]["arch"] = arch
        targets[target_name]["format"] = fmt
        atomic_write_text(toml_path, tomlkit.dumps(doc), encoding="utf-8")


def _link_toolchain(project: Path, profile: str) -> str | None:
    """Symlink the vendored toolchain into project/tools; None when not needed/available."""
    entry = _link_names_for(profile)
    if entry is None:
        return None
    link_name, src_name = entry
    tools = project / "tools"
    tools.mkdir(exist_ok=True)
    link = tools / link_name
    if link.exists():
        return str(link)
    if REPO_TOOLS is None:
        return None
    src = REPO_TOOLS / src_name
    if not src.exists():
        return None
    try:
        link.symlink_to(src, target_is_directory=True)
        return str(link)
    except OSError:
        return None


def _warn_explicit_toolchain(binary: Path, profile: str, notes: list[str]) -> None:
    """Warn when an explicit ``--toolchain`` contradicts the detected binary.

    Same alignment checks ``init`` applies to its profile choice (compiler
    family + 16/32-bit arch); warnings only — the explicit profile still
    wins.  Detection failure is silent (best-effort, like init).
    """
    import logging

    from rebrew.binary_loader import is_mz, is_ne

    log = logging.getLogger(__name__)
    try:
        from rebrew.toolchain_detect import detect_toolchain

        tc = detect_toolchain(binary)
    except Exception:
        log.debug("toolchain detection failed for %s", binary, exc_info=True)
        return
    from rebrew.init import _warn_profile_family_mismatch, _warn_profile_mismatch

    if is_ne(binary):
        _warn_profile_mismatch(profile, "ne", "x86_16")
    elif is_mz(binary):
        _warn_profile_mismatch(profile, "mz", "x86_16")
    elif tc.arch:
        _warn_profile_mismatch(profile, "pe", tc.arch)
    _warn_profile_family_mismatch(profile, tc)
    notes.append(
        f"explicit --toolchain {profile} — alignment with the detected "
        f"{tc.family or 'unknown'} toolchain checked (see warnings above)"
    )


@app.callback(invoke_without_command=True)
def main(
    binary: str = typer.Argument(..., help="Path to the target binary (copied into original/)."),
    toolchain: str | None = typer.Option(
        None, "--toolchain", help="Compiler profile (default: auto-detected)."
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

    if toolchain is None:
        profile, family, hint, notes = _suggest_profile(bin_path)
        toolchain = profile
    else:
        profile = toolchain
        family, hint = "unknown", ""
        notes = []
        # An explicit --toolchain must face the same alignment checks as
        # init's profile choice: warn (don't silently onboard) when the
        # binary's family/arch contradicts the requested profile.
        _warn_explicit_toolchain(bin_path, profile, notes)

    if dry_run:
        # Preview mode: enumerate functions too (discoverers are read-only
        # — no writes happen), so the preview tells the user how
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
                "rebrew init --target <name> --binary <name>.exe --toolchain <profile>",
                "copy binary to original/",
                "symlink vendored toolchain into tools/",
                "enumerate functions via the discoverer plugins",
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
            ["--target", target_name, "--binary", f"{target_name}.exe", "--toolchain", toolchain],
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

    # 4. function inventory via the discoverer plugins
    funcs = _enumerate_functions(dest)
    if not funcs:
        # A project with an empty function inventory is not a successful
        # onboarding — no discoverer found functions.  Fail loudly instead
        # of reporting "Intake complete: 0".
        msg = (
            "no functions discovered — install rizin (or register another "
            "rebrew.discoverers plugin) and re-run intake; the project "
            "scaffold was still created"
        )
        error_exit(msg, json_mode=json_output)

    src_dir = project / "src" / target_name
    src_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_text(
        src_dir / "function_structure.json",
        json.dumps([{"va": va, "size": size, "name": name} for va, size, name in funcs], indent=2)
        + "\n",
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
            elif spec is None or spec.image is None:
                console.print(
                    f"[yellow]  toolchain: not found in {REPO_TOOLS or 'the rebrew install'} — symlink "
                    "tools/ yourself or run rebrew doctor[/yellow]"
                )
        for note in notes:
            console.print(f"  [yellow]note:[/yellow] {note}")
        console.print("  next: rebrew doctor && rebrew status --json")
        console.print("  first run? see docs/ONBOARDING.md for the walkthrough")


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
