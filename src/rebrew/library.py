"""library.py — per-library toolchain/flags overrides (rebrew-library.toml).

A library is a source-directory subtree whose functions were all built
with the same compiler + flags (the normal case — one codebase, one
toolchain).  `rebrew library set <dir>` writes a ``rebrew-library.toml``
at the library root; every tool (verify/test/match/prove) resolves it by
walking up from each function's directory, so the whole library compiles
with the declared toolchain + flags without per-function metadata.

Known shipped libraries can be declared by name (``--preset``) — rebrew
knows the standard build settings (e.g. ``msvcrt-static`` = the MSVC
shipped CRT: /MT /O2 /Gd) and fills the missing fields.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import tomlkit
import typer
from rich.console import Console

from rebrew.cli import error_exit, json_print
from rebrew.metadata import (
    LIBRARY_METADATA_FILE,
    all_library_presets,
    apply_library_presets,
    clear_library_override_cache,
    find_library_override,
    parse_library_metadata,
)

console = Console(stderr=True)

app = typer.Typer(help="Per-library toolchain/flags overrides.", rich_markup_mode="rich")


def _resolve_root(dir_arg: str | None) -> Path:
    """The directory argument (or CWD)."""
    return Path(dir_arg).resolve() if dir_arg else Path.cwd().resolve()


@app.command("show")
def show_cmd(
    directory: str = typer.Argument(".", help="Library directory (walk-up from here)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Show the effective library override for a directory (nearest
    rebrew-library.toml walking up toward the project root)."""
    ovr = find_library_override(directory)
    if ovr is None:
        msg = f"no rebrew-library.toml found from {Path(directory).resolve()} upward"
        if json_output:
            json_print({"found": False, "directory": str(Path(directory).resolve())})
        else:
            console.print(f"[yellow]{msg}[/yellow]")
        return
    data: dict[str, Any] = {
        "found": True,
        "file": str(ovr.path),
        "library": ovr.library,
        "toolchain": ovr.toolchain,
        "cflags": ovr.cflags,
        "presets": list(ovr.presets),
    }
    if json_output:
        json_print(data)
        return
    console.print(f"[bold]{ovr.path}[/bold]")
    if ovr.library:
        console.print(f"  library:   {ovr.library}")
    console.print(f"  toolchain: {ovr.toolchain or '(inherit project default)'}")
    console.print(f"  cflags:    {ovr.cflags or '(inherit project default)'}")
    if ovr.presets:
        console.print(f"  presets:   {', '.join(ovr.presets)}")


@app.command("list")
def list_cmd(
    root: str = typer.Argument(".", help="Project root (recursively finds rebrew-library.toml)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List every rebrew-library.toml under *root* (all library overrides)."""
    base = Path(root).resolve()
    found = []
    for p in sorted(base.rglob(LIBRARY_METADATA_FILE)):
        meta = parse_library_metadata(p)
        merged, presets = apply_library_presets(meta)
        found.append(
            {
                "file": str(p),
                "library": str(merged.get("library", "")),
                "toolchain": str(merged.get("toolchain", "")),
                "cflags": str(merged.get("cflags", "")),
                "presets": list(presets),
            }
        )
    if json_output:
        json_print({"libraries": found})
        return
    if not found:
        console.print(f"[yellow]no {LIBRARY_METADATA_FILE} found under {base}[/yellow]")
        return
    for lib in found:
        tc = lib["toolchain"] or "(inherit)"
        cf = lib["cflags"] or "(inherit)"
        console.print(f"{lib['file']}  toolchain={tc}  cflags={cf}")


@app.command("set")
def set_cmd(
    directory: str = typer.Argument(
        ".", help="Library directory (writes rebrew-library.toml here)"
    ),
    toolchain: str | None = typer.Option(
        None, "--toolchain", help="Compiler profile, e.g. msvc6 / msvc600sp6"
    ),
    cflags: str | None = typer.Option(None, "--cflags", help="Compiler flags, e.g. /O2 /Gd /MT"),
    preset: str | None = typer.Option(
        None, "--preset", help="Known-library preset, e.g. msvcrt-static"
    ),
    library: str | None = typer.Option(None, "--library", help="Library name (drives presets)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Declare (or update) the per-library toolchain/flags override.

    Writes ``rebrew-library.toml`` at *directory*.  Explicit --toolchain /
    --cflags always win; a --preset fills the fields rebrew knows for a
    shipped library (e.g. the MSVC CRT)."""
    target = _resolve_root(directory)
    if not target.is_dir():
        msg = f"{target} is not a directory"
        error_exit(msg, json_mode=json_output)
    if preset is not None and preset not in all_library_presets():
        msg = f"unknown preset {preset!r} (known: {sorted(all_library_presets())})"
        error_exit(msg, json_mode=json_output)
    if toolchain is not None:
        from rebrew.toolchain import TOOLCHAINS

        if toolchain not in TOOLCHAINS:
            msg = f"unknown toolchain {toolchain!r} (known: {sorted(TOOLCHAINS)})"
            error_exit(msg, json_mode=json_output)
    path = target / LIBRARY_METADATA_FILE
    doc = tomlkit.document()
    if path.exists():
        existing = parse_library_metadata(path)
        for k, v in existing.items():
            doc[k] = v
    if library is not None:
        doc["library"] = library
    if preset is not None:
        doc["library"] = preset
    if toolchain is not None:
        doc["toolchain"] = toolchain
    if cflags is not None:
        doc["cflags"] = cflags
    path.write_text(tomlkit.dumps(doc), encoding="utf-8")
    clear_library_override_cache()
    merged, presets = apply_library_presets({k: doc[k] for k in doc})
    if json_output:
        json_print(
            {
                "file": str(path),
                "library": str(merged.get("library", "")),
                "toolchain": str(merged.get("toolchain", "")),
                "cflags": str(merged.get("cflags", "")),
                "presets": list(presets),
            }
        )
    else:
        console.print(f"[green]wrote {path}[/green]")
        if presets:
            console.print(
                f"  preset {presets[0]}: toolchain={merged.get('toolchain', '')} cflags={merged.get('cflags', '')}"
            )


@app.command("rm")
def rm_cmd(
    directory: str = typer.Argument(
        ".", help="Library directory (removes rebrew-library.toml here)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Remove a rebrew-library.toml (revert to project defaults)."""
    path = _resolve_root(directory) / LIBRARY_METADATA_FILE
    if not path.exists():
        msg = f"no {LIBRARY_METADATA_FILE} at {path.parent}"
        if json_output:
            json_print({"removed": False, "file": str(path)})
        else:
            console.print(f"[yellow]{msg}[/yellow]")
        return
    path.unlink()
    clear_library_override_cache()
    if json_output:
        json_print({"removed": True, "file": str(path)})
    else:
        console.print(f"[green]removed {path}[/green]")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
