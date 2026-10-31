"""Preview reviewed retirement/replacement of a native function's source claim."""

from __future__ import annotations

lazy import hashlib
lazy import json
lazy from pathlib import Path
lazy from typing import Any

import typer

from rebrew.cli import (
    EXPECTED_DIGEST_HELP,
    TargetOption,
    console,
    error_exit,
    json_print,
    parse_va,
    require_config,
)
lazy from rebrew.c_parser import (
    find_function_name_in_node,
    function_signatures,
    mask_msvc_syntax,
    mask_va_arg_types,
    parse_c_source,
)
lazy from rebrew.c_rename import ORDINARY_ROLES, ParsedSource, definitions, occurrences
lazy from rebrew.config import ProjectConfig, target_module
lazy from rebrew.metadata.binding_history import change_source_binding, validate_binding_history
lazy from rebrew.metadata.bindings import derive_c_symbol
lazy from rebrew.metadata.functions import get_entry, identity_file, load_metadata
lazy from rebrew.metadata.source_provenance import function_definition_hashes
lazy from rebrew.sources import iter_sources
lazy from rebrew.utils import preset_module_key, read_source_text

app = typer.Typer(
    help="Review and change source bindings while retaining native inventory and evidence.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew source binding retire 0x401000 --reason proof --dry-run\n\n"
        "  rebrew source binding rebind 0x401000 src/f.c --reason proof\n\n"
        "Preview first; --expected-digest rejects changed review inputs."
    ),
)


def _storage_macro_definition(source: str, name: str) -> bool:
    """Validate a definition whose storage macro confuses the C grammar."""
    tree, raw = parse_c_source(mask_va_arg_types(mask_msvc_syntax(source)))
    pending = [tree.root_node]
    definitions = []
    macros: dict[bytes, set[bytes]] = {}
    while pending:
        node = pending.pop()
        pending.extend(node.named_children)
        if node.type == "preproc_def":
            macro = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if macro is not None:
                macros.setdefault(raw[macro.start_byte : macro.end_byte], set()).add(
                    raw[value.start_byte : value.end_byte].strip() if value else b""
                )
        elif node.type == "function_definition":
            declarator = node.child_by_field_name("declarator")
            if declarator and find_function_name_in_node(declarator, raw) == name:
                definitions.append(node)
    if len(definitions) != 1:
        return False
    node = definitions[0]
    first = node.named_children[0]
    macro = raw[first.start_byte : first.end_byte]
    if first.type != "type_identifier" or macros.get(macro) != {b"static"}:
        return False
    # Reparse the complete raw extent with only the storage alias blanked.
    body = bytearray(raw[node.start_byte : node.end_byte])
    body[first.start_byte - node.start_byte : first.end_byte - node.start_byte] = b" " * len(macro)
    parsed, _ = parse_c_source(bytes(body))
    children = parsed.root_node.named_children
    return (
        len(children) == 1
        and children[0].type == "function_definition"
        and not children[0].has_error
    )


def has_unique_source_definition(source: str, name: str) -> bool:
    """Recognize one complete C definition, including simple storage aliases."""
    return name in function_definition_hashes(source) or _storage_macro_definition(source, name)


def supported_decorated_signature(prototype: str) -> bool:
    """Reject calling-convention sizes that need unknown typedef or struct layouts."""
    tree, _ = parse_c_source(mask_msvc_syntax(prototype + " {}"))
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if node.type == "function_declarator":
            parameters = node.child_by_field_name("parameters")
            if parameters is None:
                return False
            for parameter in parameters.named_children:
                if parameter.type != "parameter_declaration":
                    return False
                typ = parameter.child_by_field_name("type")
                declarator = parameter.child_by_field_name("declarator")
                if typ is None:
                    return False
                if typ.type in {"primitive_type", "sized_type_specifier"}:
                    continue
                if declarator is None or declarator.type not in {
                    "pointer_declarator",
                    "array_declarator",
                }:
                    return False
            return True
        pending.extend(reversed(node.named_children))
    return False


def _change(
    cfg: ProjectConfig,
    va: int,
    *,
    source: Path | None,
    name: str | None,
    symbol: str | None,
    counterpart_va: int | None,
    reason: str,
    dry_run: bool,
    expected_digest: str | None,
) -> dict[str, Any]:
    module = target_module(cfg) or ""
    current = get_entry(cfg.metadata_dir, va, module)
    history = validate_binding_history(current.get("binding_history", []))
    identity = None
    inputs: dict[Path, str] = {}

    def pin(path: Path, parsed_text: str | None = None) -> None:
        raw = path.read_bytes()
        if parsed_text is not None and (
            read_source_text(path)[0] != parsed_text or path.read_bytes() != raw
        ):
            raise ValueError(f"binding review input changed while parsing: {path}")
        inputs[path.resolve()] = hashlib.sha256(raw).hexdigest()

    pin(cfg.target_binary)
    if source is not None:
        source = source.resolve()
        if not source.is_relative_to(cfg.root.resolve()):
            raise ValueError("replacement source must be inside the project")
        text, _ = read_source_text(source)
        name = name or str(
            current.get("name") or (history[-1]["previous"].get("name") if history else "")
        )
        if not name or not has_unique_source_definition(text, name):
            raise ValueError("replacement must contain one unambiguous definition; select --name")
        pin(source, text)
        # Preserve library ancestry without accepting a new attribution by name.
        kind = str(
            current.get("kind")
            or (history[-1]["previous"].get("kind") if history else None)
            or "FUNCTION"
        )
        if kind != "LIBRARY" and source not in {
            path.resolve() for path in iter_sources(cfg.reversed_dir, cfg)
        }:
            raise ValueError("replacement is outside the target/shared source discovery roots")
        root = cfg.root if kind == "LIBRARY" else cfg.metadata_dir
        identity = {
            "file": identity_file(source, root),
            "name": name,
            "symbol": symbol or derive_c_symbol(name, function_signatures(text)[name]),
            "kind": kind,
        }
        local = any(item.static for item in definitions(ParsedSource.parse(text), name))
        if not local:
            for (other_module, other_va), other in load_metadata(
                cfg.metadata_dir, deepcopy=False
            ).items():
                if other_va == va or preset_module_key(other_module) != preset_module_key(module):
                    continue
                if not other.get("file") or other.get("symbol") != identity["symbol"]:
                    continue
                other_root = cfg.root if other.get("kind") == "LIBRARY" else cfg.metadata_dir
                other_path = (other_root / other["file"]).resolve()
                if other_path == source:
                    if other.get("name") == name or other.get("symbol") == identity["symbol"]:
                        raise ValueError(
                            f"replacement definition already belongs to {other_module}.0x{other_va:x}"
                        )
                    continue
                other_text, _ = read_source_text(other_path)
                pin(other_path, other_text)
                other_definitions = definitions(
                    ParsedSource.parse(other_text), str(other.get("name") or "")
                )
                if not other_definitions or not all(item.static for item in other_definitions):
                    raise ValueError(
                        f"external symbol already belongs to {other_module}.0x{other_va:x}"
                    )
    old_name = str(current.get("name") or "")
    references = []
    for path in iter_sources(cfg.reversed_dir, cfg):
        text, _ = read_source_text(path)
        if not old_name or old_name not in text:
            continue
        parsed = ParsedSource.parse(text)
        sites = [site for site in occurrences(parsed, old_name) if site.role in ORDINARY_ROLES]
        if sites:
            pin(path, text)
            references.append(
                {
                    "file": identity_file(path, cfg.root),
                    "lines": sorted({site.line for site in sites}),
                }
            )
    if counterpart_va is not None:
        other = get_entry(cfg.metadata_dir, counterpart_va, module)
        if other.get("file"):
            root = cfg.root if other.get("kind") == "LIBRARY" else cfg.metadata_dir
            counterpart = (root / other["file"]).resolve()
            text, _ = read_source_text(counterpart)
            if str(other.get("name") or "") not in function_definition_hashes(text):
                raise ValueError("counterpart no longer has its recorded unique definition")
            pin(counterpart, text)
    preview = change_source_binding(
        cfg.metadata_dir,
        module,
        va,
        reason=reason,
        identity=identity,
        counterpart_va=counterpart_va,
        dry_run=True,
        expected_inputs=inputs,
        project_root=cfg.root,
    )
    digest_inputs = {str(path): digest for path, digest in inputs.items()}
    digest_inputs["metadata"] = preview["input_digest"]
    digest = hashlib.sha256(json.dumps(digest_inputs, sort_keys=True).encode()).hexdigest()
    if expected_digest is not None and digest != expected_digest:
        raise ValueError("binding review inputs changed; review a new preview")
    result = (
        preview
        if dry_run
        else change_source_binding(
            cfg.metadata_dir,
            module,
            va,
            reason=reason,
            identity=identity,
            counterpart_va=counterpart_va,
            expected_digest=preview["input_digest"],
            expected_inputs=inputs,
            project_root=cfg.root,
        )
    )
    return {
        **result,
        "input_digest": digest,
        "source_references": references,
        "references_rewritten": False,
    }


def _emit(result: dict[str, Any], json_output: bool) -> None:
    if json_output:
        json_print(result)
    else:
        console.print(result)


@app.command(
    epilog=(
        "[bold]Examples:[/bold]\n\n  rebrew source binding retire 0x401000 --reason proof --dry-run"
    )
)
def retire(
    va: str = typer.Argument(..., help="Native function address"),
    reason: str = typer.Option(
        ..., "--reason", help="Reviewed evidence explaining the incorrect binding"
    ),
    counterpart: str | None = typer.Option(
        None, "--counterpart", help="Existing native counterpart; its binding/verdict is preserved"
    ),
    expected_digest: str | None = typer.Option(
        None, "--expected-digest", help=EXPECTED_DIGEST_HELP
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Retire an incorrect source claim without deleting its native row or evidence."""
    cfg = require_config(target=target, json_mode=json_output)
    try:
        result = _change(
            cfg,
            parse_va(va, json_mode=json_output),
            source=None,
            name=None,
            symbol=None,
            counterpart_va=parse_va(counterpart, json_mode=json_output) if counterpart else None,
            reason=reason,
            dry_run=dry_run,
            expected_digest=expected_digest,
        )
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    _emit(result, json_output)


@app.command(
    epilog=(
        "[bold]Examples:[/bold]\n\n  rebrew source binding rebind 0x401000 src/f.c --reason proof"
    )
)
def rebind(
    va: str = typer.Argument(..., help="Native function address"),
    source: Path = typer.Argument(..., help="Source containing the replacement definition"),
    name: str | None = typer.Option(
        None, "--name", help="Replacement C definition (default: current or last retired name)"
    ),
    symbol: str | None = typer.Option(
        None, "--symbol", help="Native object symbol (default: derived from definition)"
    ),
    reason: str = typer.Option(
        ..., "--reason", help="Reviewed native evidence supporting this binding"
    ),
    expected_digest: str | None = typer.Option(
        None, "--expected-digest", help=EXPECTED_DIGEST_HELP
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Bind a unique definition; the replacement must earn its own comparison verdict."""
    cfg = require_config(target=target, json_mode=json_output)
    try:
        result = _change(
            cfg,
            parse_va(va, json_mode=json_output),
            source=source,
            name=name,
            symbol=symbol,
            counterpart_va=None,
            reason=reason,
            dry_run=dry_run,
            expected_digest=expected_digest,
        )
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    _emit(result, json_output)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_cli

    run_cli(app)


if __name__ == "__main__":
    main_entry()
