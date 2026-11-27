"""Register declaration-bound source addresses in the canonical metadata stores."""

lazy from contextlib import nullcontext
lazy from pathlib import Path
lazy from typing import Any

import typer

from rebrew.cli import TargetOption, console, error_exit, json_print, require_config
lazy from rebrew.c_syntax.parser import find_extern_variables
lazy from rebrew.metadata.anchors import metadata_comments, parse_address_anchors
lazy from rebrew.metadata.bindings import derive_c_symbol
lazy from rebrew.metadata.coordinated import coordinated_inputs, coordinated_transaction
lazy from rebrew.metadata.data import load_data_metadata, record_data_rows, validate_data_field
lazy from rebrew.metadata.functions import (
    identity_file,
    load_metadata,
    record_function_rows,
    stored_file_matches,
    validate_identity_file,
)
lazy from rebrew.metadata.locking import file_transaction
lazy from rebrew.metadata.source_provenance import set_source_file
lazy from rebrew.source.discovery import iter_sources_and_headers
lazy from rebrew.utils import preset_module_key, read_source_text

app = typer.Typer(
    help="Register address-only source bindings, or a support file purpose, in metadata.",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew source register\n\n"
        "  rebrew source register src/shared/net.c --dry-run\n\n"
        '  rebrew source register src/link_shims.c --support "native link layout"'
    ),
)


def plan_registration(
    cfg: Any, paths: list[Path]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Validate every address before constructing any metadata write."""
    function_rows: list[dict[str, Any]] = []
    data_rows: list[dict[str, Any]] = []
    metadata_dir = cfg.metadata_dir
    functions = load_metadata(metadata_dir, deepcopy=False)
    data = load_data_metadata(metadata_dir, deepcopy=False)
    seen: dict[tuple[str, int, bool], tuple[Path, str]] = {}
    library_modules = set(getattr(cfg, "library_modules", ()) or ())
    library_keys = {preset_module_key(module) for module in library_modules}
    configured: dict[str, set[str]] = {}
    for module in (
        set(getattr(cfg, "target_modules", ()) or ())
        | library_modules
        | set(getattr(cfg, "external_libs", ()) or ())
    ):
        configured.setdefault(preset_module_key(module), set()).add(module)
    stored: dict[tuple[str, int, bool], list[tuple[str, dict[str, Any]]]] = {}
    for is_data, entries in ((False, functions), (True, data)):
        for (module, va), entry in entries.items():
            stored.setdefault((preset_module_key(module), va, is_data), []).append((module, entry))
    for path in paths:
        text, _ = read_source_text(path)
        syntax = getattr(cfg, "address_comments", None)
        forbidden = metadata_comments(text, syntax=syntax)
        if forbidden:
            raise ValueError(f"{path}:{forbidden[0][0]}: source metadata tags are not supported")
        anchors = parse_address_anchors(text, syntax=syntax)
        variables = (
            {v.name: v for v in find_extern_variables(text, include_definitions=True)}
            if any(a.kind == "DATA" for a in anchors)
            else {}
        )
        for anchor in anchors:
            module_key = preset_module_key(anchor.module)
            if module_key not in configured:
                raise ValueError(f"{path}:{anchor.line}: unknown target module {anchor.module!r}")
            is_data = anchor.kind == "DATA"
            key = (module_key, anchor.va, is_data)
            owner = (path.resolve(), anchor.name)
            if key in seen:
                if seen[key] != owner:
                    raise ValueError(f"{anchor.module}.{anchor.va:#x} binds several declarations")
                continue
            seen[key] = owner
            matches = stored.get(key, [])
            if len(matches) > 1 or (not matches and len(configured[module_key]) > 1):
                raise ValueError(f"{path}:{anchor.line}: ambiguous address anchor module")
            module, entry = matches[0] if matches else (next(iter(configured[module_key])), {})
            default_kind = (
                "DATA" if is_data else "LIBRARY" if module_key in library_keys else "FUNCTION"
            )
            kind = str(entry.get("kind") or default_kind)
            if is_data:
                kind = validate_data_field("kind", kind)
            relative = validate_identity_file(
                path.resolve().relative_to(cfg.root.resolve()).as_posix()
                if kind == "LIBRARY"
                else identity_file(path, metadata_dir)
            )
            if entry.get("file") and not stored_file_matches(str(entry["file"]), relative):
                raise ValueError(f"{module}.{anchor.va:#x} already belongs to {entry['file']}")
            if entry.get("name") and entry["name"] != anchor.name:
                raise ValueError(
                    f"{module}.{anchor.va:#x} names {entry['name']!r}; use source rename"
                )
            identity = {"file": relative, "name": anchor.name, "kind": kind}
            if is_data:
                row: dict[str, Any] = {
                    "module": module,
                    "va": anchor.va,
                    "identity": identity,
                }
                if not entry:
                    row["fill"] = {"type": variables[anchor.name].type_str}
                data_rows.append(row)
            else:
                from rebrew.source.rename_ops import c_name_from_symbol

                stored_symbol = str(entry.get("symbol") or "")
                derived = derive_c_symbol(anchor.name, anchor.prototype) if anchor.prototype else ""
                # A stored decoration of this same C name follows the prototype.
                # An empty parse keeps the stored symbol, and a symbol that names
                # something else is not a calling-convention refresh.
                if not stored_symbol or (
                    derived
                    and c_name_from_symbol(stored_symbol) == anchor.name
                    and stored_symbol != derived
                ):
                    symbol = derived
                else:
                    symbol = stored_symbol
                identity["symbol"] = symbol
                function_rows.append({"module": module, "va": anchor.va, "identity": identity})
    return function_rows, data_rows


@app.callback(invoke_without_command=True)
def main(
    source: Path | None = typer.Argument(
        None, help="Source to register (default: configured sources and headers)"
    ),
    support: str | None = typer.Option(
        None, "--support", help="Record a reason for a support file without a native address"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Register syntax-bound identities; never import metadata from source comments."""
    cfg = require_config(target=target, json_mode=json_output)
    try:
        paths = [source] if source is not None else iter_sources_and_headers(cfg.reversed_dir, cfg)
        if support is not None:
            if source is None or not source.is_file() or not support.strip():
                raise ValueError("--support requires one source file and a non-empty reason")
            relative = identity_file(source, cfg.metadata_dir)
            if not dry_run:
                set_source_file(cfg.metadata_dir, relative, cfg.module, support)
            result = {
                "file": relative,
                "module": cfg.module,
                "purpose": support,
                "dry_run": dry_run,
            }
        else:
            with nullcontext() if dry_run else file_transaction(cfg.root, "rebrew-project.toml"):
                expected = (
                    {} if dry_run else coordinated_inputs(cfg.metadata_dir, [], watched=paths)
                )
                functions, data = plan_registration(cfg, paths)
                if not dry_run:
                    transaction = (
                        coordinated_transaction(
                            cfg.metadata_dir, [], expected_inputs=expected, watched=paths
                        )
                        if functions and data
                        else nullcontext()
                    )
                    with transaction:
                        record_function_rows(cfg.metadata_dir, functions)
                        record_data_rows(cfg.metadata_dir, data)
            result = {"functions": len(functions), "data": len(data), "dry_run": dry_run}
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print(result)
    else:
        console.print(result)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)
