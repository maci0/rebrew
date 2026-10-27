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

lazy import re
lazy from pathlib import Path
lazy from typing import Any

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
lazy from rebrew.metadata.functions import (
    LIBRARY_METADATA_FILE,
    METADATA_FILENAME,
    all_library_presets,
    apply_library_presets,
    clear_library_override_cache,
    find_library_override,
    parse_library_metadata,
)
lazy from rebrew.metadata.storage import (
    metadata_store,
    metadata_write_lock,
    project_metadata_stores,
)
lazy from rebrew.workspace.config import walk_up_to_root

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
    """Bind an identified library function to a source file we compile ourselves.

    Works for a VA that already has a library declaration or a LIBRARY row, for a
    retired row (replaced through the binding history), and for a VA with no row
    at all (the LIBRARY row is recorded directly). An active FUNCTION or STUB
    claim still needs a reviewed rebind first, so this command never overwrites
    one silently.
    """
    from rebrew.config import target_module
    from rebrew.metadata.binding_history import change_source_binding, retired_binding
    from rebrew.metadata.bindings import library_bindings_for_file
    from rebrew.metadata.functions import get_entry, record_function_identity, record_function_rows
    from rebrew.rename_ops import c_name_from_symbol
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
    retired = retired_binding(existing)
    claim = bool(existing.get("file")) and not retired and not known
    if claim:
        error_exit(
            f"{va} has an active non-library source claim; retire or rebind it before "
            "binding a library source",
            json_mode=json_output,
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
        if retired:
            change_source_binding(
                cfg.metadata_dir,
                target_module(cfg),
                address,
                reason=f"Compiled library source {identity['file']} provides {symbol}.",
                identity={**identity, "name": c_name_from_symbol(symbol)},
                project_root=cfg.root,
            )
        elif not existing:
            record_function_identity(
                cfg.metadata_dir,
                module=target_module(cfg),
                va=address,
                file=identity["file"],
                kind="LIBRARY",
                name=c_name_from_symbol(symbol),
                symbol=symbol,
                updated_by="match",
            )
        else:
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
    stores = {
        store.path
        for store in project_metadata_stores(base, recursive=True)
        if store.path.name == LIBRARY_METADATA_FILE
    }
    for p in sorted(stores):
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

    def prepare() -> tuple[dict[str, Any], dict[str, Any]]:
        # A malformed store refuses the write outright rather than being
        # replaced from an empty document.
        parse_library_metadata(path)
        doc = metadata_store(path).read("library override", roundtrip=True)
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
        return doc, payload

    if dry_run:
        _doc, payload = prepare()
        if json_output:
            payload["dry_run"] = True
            json_print(payload)
        else:
            console.print(f"[yellow]would write {path}[/yellow]")
        return
    with metadata_write_lock(target, LIBRARY_METADATA_FILE):
        doc, payload = prepare()
        metadata_store(path).write(doc, "library override")
    clear_library_override_cache()
    if json_output:
        json_print(payload)
    else:
        console.print(f"[green]wrote {path}[/green]")
        if payload["presets"]:
            console.print(
                f"  preset {payload['presets'][0]}: toolchain={payload['toolchain']} cflags={payload['cflags']}"
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
    if not metadata_store(path).exists():
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
        metadata_store(path).remove()
    clear_library_override_cache()
    if json_output:
        json_print({"removed": True, "file": str(path)})
    else:
        console.print(f"[green]removed {path}[/green]")


def _safe_library_name(symbol: str) -> str:
    """C-identifier display name derived from a native archive symbol.

    C++ mangled and static data symbols (``?fn@@YAXXZ``, ``_c_rgodfDIKeyboard$1``)
    have no C identifier form. The native symbol stays exact in ``symbol``; the
    display name keeps every alphanumeric run so the row stays a valid identity.
    """
    name = re.sub(r"[^0-9A-Za-z_]+", "_", symbol).strip("_")
    if not name:
        name = "library_symbol"
    if not (name[0].isalpha() or name[0] == "_"):
        name = f"_{name}"
    return name


def _library_family(object_label: str) -> str | None:
    """Archive family from a stock object label like ``..._libc_stock.lib:...``."""
    if ":" not in object_label:
        return None
    stem = Path(object_label.split(":", 1)[0]).stem
    for suffix in ("_stock", "-stock"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
    family = stem.rsplit("_", 1)[-1]
    return family or None


@app.command(
    "adopt",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        '  rebrew library adopt 0x401000 --reason "unique LIBC body" --dry-run'
    ),
)
def adopt_cmd(
    va: str = typer.Argument(..., help="Native VA of the FUNCTION/STUB row proved library code"),
    reason: str = typer.Option(..., "--reason", help="Reviewed evidence naming the unique match"),
    expected_digest: str | None = typer.Option(
        None, "--expected-digest", help=EXPECTED_DIGEST_HELP
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    symbol: str | None = typer.Option(
        None,
        "--symbol",
        help="Reviewed native symbol when the bytes match several byte-identical archive "
        "aliases; the stored identity is the symbol alone",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Record a unique stock-archive match, with or without a prior claim.

    The match must be unique against the archives the target links; the row then
    becomes kind LIBRARY with the archive family's declaration header and the
    native symbol. A prior claim (FUNCTION/STUB or a retired binding) goes to
    binding_history; a VA with no row gets the LIBRARY row directly, sized from
    the discovery inventory. The preview digest guards the write. Vendored-object
    matches are refused: bind their source with ``rebrew library bind-source``.
    """
    import hashlib
    import json as json_mod

    from rebrew.catalog import cached_function_list
    from rebrew.config import target_module
    from rebrew.formats.binary_loader import extract_raw_bytes
    from rebrew.identify_library import prepare_library_header
    from rebrew.lib_match import PREFIX_BYTES, match_bytes, project_match_index
    from rebrew.metadata.binding_history import change_source_binding, retired_binding
    from rebrew.metadata.functions import get_entry, record_function_identity
    from rebrew.metadata.storage import metadata_store
    from rebrew.rename_ops import c_name_from_symbol
    from rebrew.utils import library_header_name

    cfg = require_config(target=target, json_mode=json_output)
    address = parse_va(va, json_mode=json_output)
    module = target_module(cfg)
    row = get_entry(cfg.metadata_dir, address, module)
    has_claim = bool(row.get("file")) and not retired_binding(row)
    if has_claim and row.get("kind") not in {"FUNCTION", "STUB"}:
        error_exit(
            f"0x{address:x} is already {row.get('kind') or 'unclaimed'}; adopt needs a "
            "FUNCTION or STUB claim, a retired binding, or no row at all",
            json_mode=json_output,
        )
    try:
        index, _archives, _objects = project_match_index(cfg, json_mode=json_output)
    except ValueError as exc:
        error_exit(str(exc), json_mode=json_output)
    size = int(row.get("size") or 0)
    if not size:
        for func in cached_function_list(cfg):
            try:
                if int(func.get("va", -1)) == address:
                    size = int(func.get("size") or 0)
                    break
            except TypeError, ValueError:
                continue
    if not size:
        error_exit(
            f"no native metadata row and no inventory size for {module}.0x{address:x}",
            json_mode=json_output,
        )
    data = extract_raw_bytes(cfg.target_binary, address, size or PREFIX_BYTES)
    hit = match_bytes(index, data)
    if not hit and size > PREFIX_BYTES:
        hit = match_bytes(index, extract_raw_bytes(cfg.target_binary, address, PREFIX_BYTES))
    pairs = {(symbol, obj) for symbol, obj in hit}
    if not pairs:
        error_exit(
            f"0x{address:x} does not match any linked archive; nothing to adopt",
            json_mode=json_output,
        )
    if symbol is not None:
        chosen = {pair for pair in pairs if pair[0] == symbol}
        if not chosen:
            listed = "; ".join(f"{sym} in {obj}" for sym, obj in sorted(pairs))
            error_exit(
                f"0x{address:x} has no candidate named {symbol} ({listed})",
                json_mode=json_output,
            )
        pairs = chosen
    if len(pairs) > 1:
        symbols = {pair[0] for pair in pairs}
        if len(symbols) > 1:
            listed = "; ".join(f"{sym} in {obj}" for sym, obj in sorted(pairs))
            error_exit(
                f"0x{address:x} has ambiguous library candidates ({listed}); pass --symbol "
                "with the reviewed native symbol",
                json_mode=json_output,
            )
    symbol, object_label = pairs.pop()
    if object_label.endswith(".c.obj") or ":" not in object_label:
        error_exit(
            f"0x{address:x} matched a project-built object ({object_label}); bind its source "
            "with `rebrew library bind-source`",
            json_mode=json_output,
        )
    family = _library_family(object_label)
    if family is None:
        error_exit(f"cannot derive the archive family from {object_label}", json_mode=json_output)
    name = c_name_from_symbol(symbol)
    if not name.isidentifier():
        name = _safe_library_name(symbol)
    header = cfg.reversed_dir / library_header_name(family)
    try:
        relative_header = header.resolve().relative_to(cfg.root.resolve()).as_posix()
    except ValueError:
        error_exit(f"library header {header} is outside the project root", json_mode=json_output)
    identity = {"file": relative_header, "symbol": symbol, "name": name, "kind": "LIBRARY"}
    binary_hash = hashlib.sha256(cfg.target_binary.read_bytes()).hexdigest()
    metadata_digest = metadata_store(cfg.metadata_dir / METADATA_FILENAME).digest()
    digest = hashlib.sha256(
        json_mod.dumps(
            {
                "binary": binary_hash,
                "metadata": metadata_digest,
                "va": address,
                "identity": identity,
                "object": object_label,
                "reason": reason.strip(),
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()
    if expected_digest is not None and digest != expected_digest:
        error_exit("library adopt inputs changed; review a new preview", json_mode=json_output)
    if not dry_run:
        prepare_library_header(cfg, header)
    try:
        if row.get("file") or row.get("binding_history"):
            result = change_source_binding(
                cfg.metadata_dir,
                module,
                address,
                reason=reason,
                identity=identity,
                dry_run=dry_run,
                expected_digest=None if dry_run else metadata_digest,
                project_root=cfg.root,
            )
        else:
            if not dry_run:
                record_function_identity(
                    cfg.metadata_dir,
                    module=module,
                    va=address,
                    file=identity["file"],
                    kind="LIBRARY",
                    name=identity["name"],
                    symbol=identity["symbol"],
                    updated_by="match",
                )
            result = {"action": "record"}
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if not dry_run and result.get("action") in {"rebind", "retire"}:
        # The retired claim's byte verdict measured a compile nobody runs any
        # more; library rows are never compiled, so a reader that falls back to
        # the stored verdict would report a status for source that is gone.
        from rebrew.metadata.functions import remove_fields_batch

        remove_fields_batch(
            cfg.metadata_dir, [{"module": module, "va": address, "keys": ["verification"]}]
        )
    payload = {
        "va": f"0x{address:08x}",
        "provider": "stock-archive",
        "object": object_label,
        "input_digest": digest,
        "dry_run": dry_run,
        **identity,
        "action": result.get("action"),
    }
    if json_output:
        json_print(payload)
    else:
        console.print(
            f"{'Would adopt' if dry_run else 'Adopted'} 0x{address:08x} as LIBRARY "
            f"({symbol} from {object_label})"
        )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_cli

    run_cli(app)


if __name__ == "__main__":
    main_entry()
