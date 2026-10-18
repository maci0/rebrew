"""Register declaration-bound source addresses in the canonical metadata stores."""

from pathlib import Path
from typing import Any

import typer

from rebrew.c_parser import find_extern_variables
from rebrew.cli import TargetOption, console, error_exit, json_print, require_config
from rebrew.metadata.anchors import metadata_comments, parse_address_anchors
from rebrew.metadata.bindings import derive_c_symbol
from rebrew.metadata.data import load_data_metadata, record_data_rows
from rebrew.metadata.functions import (
    identity_file,
    load_metadata,
    record_function_rows,
    stored_file_matches,
)
from rebrew.metadata.source_provenance import set_source_file
from rebrew.sources import iter_sources_and_headers
from rebrew.utils import preset_module_key, read_source_text

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
    functions = load_metadata(cfg.metadata_dir)
    data = load_data_metadata(cfg.metadata_dir)
    seen: dict[tuple[str, int, bool], tuple[Path, str]] = {}
    allowed = {
        preset_module_key(m)
        for m in (
            set(getattr(cfg, "target_modules", ()) or ())
            | set(getattr(cfg, "library_modules", ()) or ())
            | set(getattr(cfg, "external_libs", ()) or ())
        )
    }
    for path in paths:
        text, _ = read_source_text(path)
        forbidden = metadata_comments(text)
        if forbidden:
            raise ValueError(f"{path}:{forbidden[0][0]}: source metadata tags are not supported")
        anchors = parse_address_anchors(text)
        variables = (
            {v.name: v for v in find_extern_variables(text, include_definitions=True)}
            if any(a.kind == "DATA" for a in anchors)
            else {}
        )
        for anchor in anchors:
            if preset_module_key(anchor.module) not in allowed:
                raise ValueError(f"{path}:{anchor.line}: unknown target module {anchor.module!r}")
            is_data = anchor.kind == "DATA"
            key = (anchor.module, anchor.va, is_data)
            owner = (path.resolve(), anchor.name)
            if key in seen:
                if seen[key] != owner:
                    raise ValueError(f"{anchor.module}.{anchor.va:#x} binds several declarations")
                continue
            seen[key] = owner
            entry = (data if is_data else functions).get((anchor.module, anchor.va), {})
            default_kind = (
                "DATA"
                if is_data
                else "LIBRARY"
                if anchor.module in (getattr(cfg, "library_modules", ()) or ())
                else "FUNCTION"
            )
            kind = str(entry.get("kind") or default_kind)
            relative = (
                path.resolve().relative_to(cfg.root.resolve()).as_posix()
                if kind == "LIBRARY"
                else identity_file(path, cfg.metadata_dir)
            )
            if entry.get("file") and not stored_file_matches(str(entry["file"]), relative):
                raise ValueError(
                    f"{anchor.module}.{anchor.va:#x} already belongs to {entry['file']}"
                )
            if entry.get("name") and entry["name"] != anchor.name:
                raise ValueError(
                    f"{anchor.module}.{anchor.va:#x} names {entry['name']!r}; use source rename"
                )
            identity = {"file": relative, "name": anchor.name, "kind": kind}
            if is_data:
                row: dict[str, Any] = {
                    "module": anchor.module,
                    "va": anchor.va,
                    "identity": identity,
                }
                if not entry:
                    row["fill"] = {"type": variables[anchor.name].type_str}
                data_rows.append(row)
            else:
                from rebrew.rename_ops import c_name_from_symbol

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
                function_rows.append(
                    {"module": anchor.module, "va": anchor.va, "identity": identity}
                )
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
            functions, data = plan_registration(cfg, paths)
            if not dry_run:
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
