"""Inventory native source-path strings and their direct instruction references."""

import re
lazy import hashlib
lazy from typing import Any

import typer

from rebrew.cli import TargetOption, console, error_exit, json_print, require_config
lazy from rebrew.analysis import (
    data_references,
    instruction_text,
    iter_instructions,
    iter_strings,
    reachable_code,
    scan_references,
)
lazy from rebrew.catalog import cached_function_list
lazy from rebrew.config import ProjectConfig, target_module
lazy from rebrew.formats.binary_loader import (
    extract_bytes_at_va,
    function_extent_from_bytes,
    load_binary,
)
lazy from rebrew.formats.binary_model import BinaryInfo
lazy from rebrew.metadata.functions import load_metadata
lazy from rebrew.workspace.status import MATCHED_STATUSES

app = typer.Typer(
    help="Inventory native source-path strings and bounded direct references.",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew source units --json\n\n"
        "  rebrew source units --target client.exe\n\n"
        "Direct references are evidence; conflicting paths do not establish a source owner."
    ),
)

_SOURCE_PATH = re.compile(
    r"(?:[^\r\n\x00<>\"|?*]+[/\\])+[^/\\\r\n\x00<>\"|?*]+\.(?:c|cc|cpp|cxx|pas|asm|s)",
    re.IGNORECASE,
)


def source_unit_evidence(info: BinaryInfo, functions: list[dict[str, Any]]) -> dict[str, Any]:
    """Find direct path operands in independently bounded instruction windows.

    A current reference-byte receipt can establish a complete body size. The
    conservative native walker bounds the decoded window either way, so a
    discovery range merging later bodies never lends their paths to its start.
    A jump-ended window is explicitly a prefix, not a complete function extent.
    """
    strings = {
        s.va: s
        for s in iter_strings(info, section_names=list(info.sections))
        if _SOURCE_PATH.fullmatch(s.text)
    }
    paths: dict[int, dict[str, Any]] = {
        va: {"path": s.text, "string_va": va, "section": s.section, "references": []}
        for va, s in strings.items()
    }
    ordered = sorted(functions, key=lambda f: int(f["va"]))
    refused: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    for index, function in enumerate(ordered):
        va, size = int(function["va"]), int(function.get("size") or 0)
        if index + 1 < len(ordered):
            next_va = int(ordered[index + 1]["va"])
            size = min(size, next_va - va) if size > 0 else next_va - va
        if size <= 0:
            refused.append({"function_va": va, "reason": "no bounded extent"})
            continue
        raw = extract_bytes_at_va(info, va, size, trim_padding=False)
        if not raw:
            refused.append({"function_va": va, "reason": "no mapped bytes"})
            continue
        extent = function_extent_from_bytes(info, raw, va, with_kind=True)
        if not isinstance(extent, tuple):
            refused.append({"function_va": va, "reason": "no native terminator"})
            continue
        scan_size, kind = extent
        receipt = function.get("verification") or {}
        current = (
            function.get("status") in MATCHED_STATUSES
            and str(receipt.get("reference_size") or "") == str(len(raw))
            and receipt.get("reference_hash") == hashlib.sha256(raw).hexdigest()
        )
        body_size = len(raw) if current else scan_size if kind == "ret" else None
        if current and info.arch in {"x86_32", "x86_64"}:
            try:
                decoded, refs = reachable_code(info, va, len(raw))
            except ValueError as exc:
                refused.append({"function_va": va, "reason": str(exc)})
                continue
            scan_size = len(raw)
        else:
            decoded = iter_instructions(info, va, scan_size)
            refs = data_references(info, va, scan_size)
        references = [r for r in refs if r.to_va in strings]
        if not references:
            continue
        instructions = {i.va: instruction_text(i) for i in decoded}
        found_paths: set[str] = set()
        for ref in references:
            found_paths.add(strings[ref.to_va].text)
            paths[ref.to_va]["references"].append(
                {
                    "function_va": va,
                    "function_size": body_size,
                    "extent_kind": "verified-reference" if current else kind,
                    "scan_size": scan_size,
                    "instruction_va": ref.from_va,
                    "instruction": instructions.get(ref.from_va),
                    "operand_kind": ref.kind,
                    "source": function.get("file") or None,
                    "bindings": function.get("bindings") or [],
                }
            )
        if len(found_paths) > 1:
            conflicts.append({"function_va": va, "paths": sorted(found_paths)})
    attributed = {
        (ref["instruction_va"], path["string_va"])
        for path in paths.values()
        for ref in path["references"]
    }
    unattributed = [
        {
            "instruction_va": ref.from_va,
            "string_va": ref.to_va,
            "path": strings[ref.to_va].text,
            "operand_kind": ref.kind,
            "scope": "section-linear",
            "function_va": None,
        }
        for ref in scan_references(info)
        if ref.to_va in strings and (ref.from_va, ref.to_va) not in attributed
    ]
    return {
        "paths": list(paths.values()),
        "conflicts": conflicts,
        "refused": refused,
        "unattributed_references": unattributed,
    }


def collect_source_units(cfg: ProjectConfig) -> dict[str, Any]:
    """Join native path evidence with the selected target's managed bindings."""
    info = load_binary(cfg.target_binary)
    rows = load_metadata(cfg.metadata_dir)
    module = target_module(cfg)
    bindings: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for (target_module_name, va), row in rows.items():
        if row.get("file") and row.get("name"):
            key = (str(row["file"]), str(row["name"]))
            bindings.setdefault(key, []).append({"module": target_module_name, "va": va})
    functions = {int(f["va"]): dict(f) for f in cached_function_list(cfg)}
    for (target_module_name, va), row in rows.items():
        if target_module_name != module:
            continue
        function = functions.setdefault(va, {"va": va})
        function.update(row)
        function["bindings"] = bindings.get((str(row.get("file")), str(row.get("name"))), [])
    result = source_unit_evidence(info, list(functions.values()))
    return {"target": cfg.target_name, "binary": str(cfg.target_binary), **result}


@app.callback(invoke_without_command=True)
def main(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Report native source-unit evidence without moving or merging sources."""
    cfg = require_config(target=target, json_mode=json_output)
    try:
        result = collect_source_units(cfg)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print(result)
        return
    for path in result["paths"]:
        console.print(f"{path['path']}  string 0x{path['string_va']:x}", markup=False)
        for ref in path["references"]:
            console.print(
                f"  function 0x{ref['function_va']:x}, instruction 0x{ref['instruction_va']:x}: "
                f"{ref['instruction']}",
                markup=False,
            )
    console.print(
        f"{len(result['conflicts'])} path conflict(s); {len(result['refused'])} unbounded function(s); "
        f"{len(result['unattributed_references'])} reference(s) without a confirmed function owner"
    )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
