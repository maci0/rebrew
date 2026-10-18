"""library.py — per-library toolchain/flags overrides (rebrew-libraries.toml).

A library is a source-directory subtree whose functions were all built
with the same compiler + flags (the normal case — one codebase, one
toolchain).  `rebrew library set <dir>` writes a ``rebrew-libraries.toml``
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
from typer.models import TyperPath

from rebrew.cli import (
    EXPECTED_DIGEST_HELP,
    TargetOption,
    console,
    error_exit,
    json_print,
    parse_va,
    require_config,
)
from rebrew.metadata.document import metadata_write_lock
from rebrew.metadata.functions import (
    LIBRARY_METADATA_FILE,
    all_library_presets,
    apply_library_presets,
    clear_library_override_cache,
    find_library_override,
    parse_library_metadata,
)
from rebrew.utils import atomic_write_text, load_toml_for_write
from rebrew.workspace.config import walk_up_to_root

app = typer.Typer(
    help="Identify libraries, compare code, and manage source providers and compiler settings.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew library identify --dry-run\n\n"
        "  rebrew library inspect path/to/runtime.lib\n\n"
        "  rebrew library show src/mylib\n\n"
        "  rebrew library set src/mylib --toolchain gcc-14.2.0 --cflags=-O1\n\n"
        "  rebrew library vendor --help\n\n"
        "[dim]identify and signature commands find library functions; match/crt-match compare known library code. bind-source selects a source provider. show/set/list/remove manage per-library compiler settings; vendor manages pristine sources and patches. Settings resolve from function metadata, then the nearest rebrew-libraries.toml, then project defaults.[/dim]\n\n"
    ),
)


@app.command(
    "bind-source",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew library bind-source 0x401000 refs/adler.c --symbol _adler32\n"
    ),
)
def bind_source_cmd(
    va: str = typer.Argument(..., help="Reference virtual address of a library function"),
    source: Path = typer.Argument(..., help="Project source file compiled for this function"),
    symbol: str = typer.Option(..., "--symbol", help="Native object symbol to compare"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Bind an identified library function to a source file we compile ourselves."""
    from rebrew.config import target_module
    from rebrew.metadata.bindings import library_bindings_for_file
    from rebrew.metadata.functions import get_entry, record_function_rows
    from rebrew.sources import iter_library_headers
    from rebrew.utils import preset_module_key

    cfg = require_config(target=target, json_mode=json_output)
    address = parse_va(va, json_mode=json_output)
    target_module_name = preset_module_key(target_module(cfg))
    known = any(
        entry.va == address and preset_module_key(entry.module or "") == target_module_name
        for header in iter_library_headers(cfg.reversed_dir, cfg)
        for entry in library_bindings_for_file(header, metadata_dir=cfg.metadata_dir)
    )
    existing = get_entry(cfg.metadata_dir, address, target_module(cfg))
    known = known or existing.get("kind") == "LIBRARY"
    if not known:
        error_exit(
            f"No library declaration for {va} in target {cfg.target_name}", json_mode=json_output
        )
    candidate = (cfg.root / source).resolve()
    if not candidate.is_relative_to(cfg.root.resolve()) or not candidate.is_file():
        error_exit(
            "Library source must be an existing file inside the project", json_mode=json_output
        )
    if candidate.suffix.casefold() not in {".c", ".cpp", ".cc", ".cxx"} or not symbol.strip():
        error_exit(
            "Provide a C/C++ source file and a nonempty native symbol", json_mode=json_output
        )
    identity = {
        "file": candidate.relative_to(cfg.root.resolve()).as_posix(),
        "symbol": symbol,
        "kind": "LIBRARY",
    }
    if not dry_run:
        record_function_rows(
            cfg.metadata_dir,
            [{"module": target_module(cfg), "va": address, "identity": identity}],
        )
    payload = {"va": f"0x{address:08x}", "provider": "compiled", **identity, "dry_run": dry_run}
    if json_output:
        json_print(payload)
    else:
        console.print(
            f"{'Would bind' if dry_run else 'Bound'} {va} to {identity['file']} ({symbol})"
        )


@app.command(
    "review-native",
    epilog="[bold]Examples:[/bold]\n\n  rebrew library review-native 0x401000 f.obj --symbol _f --reason proof",
)
def review_native_cmd(
    va: str = typer.Argument(..., help="Native library function address"),
    obj: Path = typer.Argument(..., help="Compiled i386 COFF object with the complete function"),
    symbol: str = typer.Option(..., "--symbol", help="Exact native object symbol to establish"),
    reason: str = typer.Option(..., "--reason", help="Reviewed identity evidence"),
    expected_digest: str | None = typer.Option(
        None, "--expected-digest", help=EXPECTED_DIGEST_HELP
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Establish a native library name using a strict complete object proof."""
    from rebrew.native_review import review_native_identity

    cfg = require_config(target=target, json_mode=json_output)
    address = parse_va(va, json_mode=json_output)
    try:
        report = review_native_identity(
            cfg,
            address,
            obj,
            symbol,
            reason=reason,
            dry_run=dry_run,
            expected_digest=expected_digest,
        )
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print(report)
    else:
        console.print(report)


def _resolve_root(dir_arg: str | None) -> Path:
    """The directory argument (or CWD)."""
    return Path(dir_arg).resolve() if dir_arg else Path.cwd().resolve()


@app.command(
    "show",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew library show --json\n\n"
        "Overrides are resolved per function, nearest library configuration, then project defaults."
    ),
)
def show_cmd(
    directory: str = typer.Argument(
        ".", help="Library directory (walk-up from here)", click_type=TyperPath(path_type=str)
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Show the effective library override for a directory (nearest rebrew-libraries.toml walking up toward the project root)."""
    # Stop at the enclosing project root, as the compile paths (root=cfg.root) do.
    ovr = find_library_override(directory, root=walk_up_to_root(Path(directory)))
    if ovr is None:
        msg = f"no rebrew-libraries.toml found from {Path(directory).resolve()} upward"
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


@app.command(
    "list",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew library list --json\n\n"
        "Overrides are resolved per function, nearest library configuration, then project defaults."
    ),
)
def list_cmd(
    root: str = typer.Argument(
        ".",
        help="Project root (recursively finds rebrew-libraries.toml)",
        click_type=TyperPath(path_type=str),
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List every rebrew-libraries.toml under root (all library overrides)."""
    # The default is the project root, not the CWD: `library list` run from a
    # source subdirectory must still see every override in the project. An
    # explicit ROOT outside any project (no marker anywhere above it) is taken
    # verbatim, so a standalone tree can still be listed.
    start = Path(root).resolve()
    base = walk_up_to_root(start) or start
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


@app.command(
    "set",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew library set --dry-run --json\n\n"
        "Overrides are resolved per function, nearest library configuration, then project defaults."
    ),
)
def set_cmd(
    directory: str = typer.Argument(
        ".",
        help="Library directory (writes rebrew-libraries.toml here)",
        click_type=TyperPath(path_type=str),
    ),
    toolchain: str | None = typer.Option(
        None, "--toolchain", help="Compiler profile, e.g. msvc-6.0 / msvc-6.0-sp6"
    ),
    cflags: str | None = typer.Option(None, "--cflags", help="Compiler flags, e.g. /O2 /Gd /MT"),
    preset: str | None = typer.Option(
        None, "--preset", help="Known-library preset, e.g. msvcrt-static; excludes --library"
    ),
    library: str | None = typer.Option(
        None, "--library", help="Library name (drives presets); excludes --preset"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Declare (or update) the per-library toolchain/flags override.

    Writes rebrew-libraries.toml at directory.  Explicit --toolchain /
    --cflags always win; a --preset fills the fields rebrew knows for a
    shipped library (e.g. the MSVC CRT).
    """
    target = _resolve_root(directory)
    if not target.is_dir():
        msg = f"{target} is not a directory"
        error_exit(msg, json_mode=json_output)
    if library is not None and preset is not None:
        # Both write the ``library`` key; one would silently discard the other.
        error_exit("--library and --preset are mutually exclusive", json_mode=json_output)
    if preset is not None and preset not in all_library_presets():
        msg = f"unknown preset {preset!r} (known: {sorted(all_library_presets())})"
        error_exit(msg, json_mode=json_output)
    if library is not None and library not in all_library_presets():
        # --library is a free-form name (it may only label the tree), but a
        # typo would write a file whose preset never matches.  Warn, do not
        # refuse: the name is also a label.
        console.print(
            f"[yellow]warning:[/yellow] {library!r} is not a known library preset "
            f"(known: {sorted(all_library_presets())}); no toolchain or cflags will be filled in"
        )
    if toolchain is not None:
        from rebrew.compiler.toolchain import TOOLCHAINS

        if toolchain not in TOOLCHAINS:
            msg = f"unknown toolchain {toolchain!r} (known: {sorted(TOOLCHAINS)})"
            error_exit(msg, json_mode=json_output)
    path = target / LIBRARY_METADATA_FILE
    doc_library = library if library is not None else preset
    # One locked read-modify-write, like every other canonical TOML store
    # (rebrew-functions.toml, rebrew-data.toml): a second process editing a
    # different key in the same file must not lose this write, and the
    # in-place tomlkit edit keeps the comments and key order of a
    # hand-written file instead of rewriting it from a bare dict.
    with metadata_write_lock(target, LIBRARY_METADATA_FILE):
        # A malformed store refuses the write outright rather than being
        # replaced from an empty document.
        if path.exists():
            parse_library_metadata(path)
        doc = load_toml_for_write(path, "library override")
        if doc_library is not None:
            doc["library"] = doc_library
        if toolchain is not None:
            doc["toolchain"] = toolchain
        if cflags is not None:
            doc["cflags"] = cflags
        merged, presets = apply_library_presets({str(k): doc[k] for k in doc})
        payload: dict[str, Any] = {
            "file": str(path),
            "library": str(merged.get("library", "")),
            "toolchain": str(merged.get("toolchain", "")),
            "cflags": str(merged.get("cflags", "")),
            "presets": list(presets),
        }
        if dry_run:
            if json_output:
                payload["dry_run"] = True
                json_print(payload)
            else:
                console.print(f"[yellow]would write {path}[/yellow]")
            return
        atomic_write_text(path, tomlkit.dumps(doc), encoding="utf-8")
    clear_library_override_cache()
    if json_output:
        json_print(payload)
    else:
        console.print(f"[green]wrote {path}[/green]")
        if presets:
            console.print(
                f"  preset {presets[0]}: toolchain={merged.get('toolchain', '')} cflags={merged.get('cflags', '')}"
            )


@app.command(
    "remove",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew library remove --dry-run --json\n\n"
        "Overrides are resolved per function, nearest library configuration, then project defaults."
    ),
)
def rm_cmd(
    directory: str = typer.Argument(
        ".",
        help="Library directory (removes rebrew-libraries.toml here)",
        click_type=TyperPath(path_type=str),
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Remove a rebrew-libraries.toml (revert to project defaults)."""
    target = _resolve_root(directory)
    path = target / LIBRARY_METADATA_FILE
    if not path.exists():
        msg = f"no {LIBRARY_METADATA_FILE} at {path.parent}"
        if json_output:
            json_print({"removed": False, "file": str(path)})
        else:
            console.print(f"[yellow]{msg}[/yellow]")
        return
    if dry_run:
        if json_output:
            json_print({"removed": False, "file": str(path), "dry_run": True})
        else:
            console.print(f"[yellow]would remove {path}[/yellow]")
        return
    # Unlink under the same lock `set` writes under, so a removal cannot
    # interleave with a concurrent `rebrew library set` on the same file.
    with metadata_write_lock(target, LIBRARY_METADATA_FILE):
        path.unlink(missing_ok=True)
    clear_library_override_cache()
    if json_output:
        json_print({"removed": True, "file": str(path)})
    else:
        console.print(f"[green]removed {path}[/green]")


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_cli

    run_cli(app)


if __name__ == "__main__":
    main_entry()
