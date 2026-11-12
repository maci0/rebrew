"""Preview reviewed retirement/replacement of a native function's source claim."""

from __future__ import annotations

lazy import hashlib
lazy import json
lazy import re
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
lazy from rebrew.rename_ops import RenameError
lazy from rebrew.sources import iter_sources
lazy from rebrew.utils import detect_source_encoding, preset_module_key, read_source_text

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


#: A generated function name: its hex suffix is the VA it was generated for.
_GENERATED_NAME = re.compile(r"(?:fcn|sub|FUN)_([0-9A-Fa-f]{6,16})")


def _is_call_target(binary: Path, va: int) -> bool:
    """True when an x86 ``call rel32`` in a code section of *binary* lands on *va*.

    An inventory can miss functions; a direct call proves one starts there.
    Non-x86 or unreadable images answer False.
    """
    import capstone
    from capstone import x86

    from rebrew.formats.binary_loader import capstone_config_for, load_binary

    try:
        info = load_binary(binary)
    except OSError, ValueError:
        return False
    if not str(info.arch).startswith("x86"):
        return False
    md = capstone.Cs(*capstone_config_for(info))
    md.detail = True
    for section in info.sections.values():
        if not section.is_code_section:
            continue
        data = info.data[
            section.file_offset : section.file_offset + min(section.raw_size, section.size)
        ]
        for ins in md.disasm(data, section.va):
            if (
                ins.id == x86.X86_INS_CALL
                and len(ins.operands) == 1
                and ins.operands[0].type == x86.X86_OP_IMM
                and ins.operands[0].imm == va
            ):
                return True
    return False


def _refuse_generated_name_of_another_function(cfg: ProjectConfig, va: int, name: str) -> None:
    """Refuse *name* when it is the generated name of a different function in this target.

    A twin's source from another binary carries that binary's address in its name
    (GoldTL ``fcn_005c61c0`` for Gold's 0x5ba750), and the same address can be a
    different function here, already called by that name.
    """
    from rebrew.catalog.loaders import load_function_structure
    from rebrew.config import inventory_path_for

    match = _GENERATED_NAME.fullmatch(name)
    if match is None or int(match.group(1), 16) == va:
        return
    named = int(match.group(1), 16)
    rows = load_metadata(cfg.metadata_dir, deepcopy=False)
    known = (
        (target_module(cfg) or "", named) in rows
        or any(
            entry.va == named
            for entry in load_function_structure(inventory_path_for(cfg.reversed_dir, cfg))
        )
        or _is_call_target(cfg.target_binary, named)
    )
    if known:
        raise ValueError(
            f"{name} is the generated name of another {target_module(cfg)} function at "
            f"0x{named:08x}; rename the replacement definition first"
        )


def _replacement_type_key(identity: dict[str, Any] | None, source: Path | None) -> str | None:
    """Type key of the replacement definition, or None when there is nothing to compare."""
    from rebrew.c_parser import prototype_type_key

    if identity is None or source is None:
        return None
    text, _ = read_source_text(source)
    signature = function_signatures(text).get(identity["name"])
    return prototype_type_key(signature) if signature else None


def _refuse_conflicting_prototype(
    text: str, name: str, key: str, path: Path, cfg: ProjectConfig
) -> None:
    """Refuse when *path* already declares *name* at file scope with other types.

    The name then already means another function in this target (a placeholder
    or a stale twin name); binding a definition to it breaks that caller.
    """
    from rebrew.c_parser import prototype_type_key

    if name not in text:
        return
    tree, raw = parse_c_source(mask_msvc_syntax(text))
    original = text.encode("utf-8", errors="surrogateescape")
    pending = list(tree.root_node.named_children)
    while pending:
        node = pending.pop()
        if node.type.startswith("preproc_"):
            pending.extend(node.named_children)
        if node.type != "declaration":
            continue
        declarator = node.child_by_field_name("declarator")
        if declarator is None or find_function_name_in_node(declarator, raw) != name:
            continue
        line = original[node.start_byte : node.end_byte].decode("utf-8", errors="surrogateescape")
        clean = bytearray(original[node.start_byte : node.end_byte])
        for child in node.named_children:
            if child.type == "storage_class_specifier":
                start, end = child.start_byte - node.start_byte, child.end_byte - node.start_byte
                clean[start:end] = b" " * (end - start)
        other = prototype_type_key(clean.decode("utf-8", errors="surrogateescape"))
        parameters = []
        parts = [declarator]
        while parts:
            part = parts.pop()
            if part.type == "function_declarator":
                params = part.child_by_field_name("parameters")
                if params is not None:
                    parameters.append(params)
            parts.extend(part.named_children)
        unspecified = len(parameters) == 1 and not parameters[0].named_children
        compatible = other == key
        if unspecified and other is not None:
            compatible = _unprototyped_compatible(key, other)
        if other is not None and not compatible:
            raise ValueError(
                f"{name} is already declared as `{line.strip()}` in "
                f"{identity_file(path, cfg.root)}; rename the replacement definition first"
            )


def _unprototyped_compatible(key: str, other: str) -> bool:
    """Compare return/ABI types and require parameters unchanged by default promotions."""
    prefix, opening, suffix = key.partition("(")
    if not opening or other != prefix + "()":
        return False
    tree, raw = parse_c_source(mask_msvc_syntax(prefix + " f(" + suffix + ";"))
    if tree.root_node.has_error:
        return False
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if node.type == "variadic_parameter":
            return False
        if node.type == "parameter_declaration":
            declarator = node.child_by_field_name("declarator")
            if declarator is not None:
                continue  # Pointer and array parameters do not undergo scalar promotions.
            typ = node.child_by_field_name("type")
            if typ is None:
                return False
            spelling = raw[typ.start_byte : typ.end_byte].decode().split()
            if typ.type == "type_identifier" or any(
                word in {"float", "char", "short", "_Bool"} for word in spelling
            ):
                return False
        pending.extend(node.named_children)
    return True


def _obsolete_body(
    cfg: ProjectConfig, va: int, current: dict[str, Any], source: Path
) -> Path | None:
    """Remove only a single-body file with no remaining storage or metadata owner."""
    from rebrew.c_parser import find_c_function_definitions, find_extern_variables
    from rebrew.metadata.data import load_data_metadata
    from rebrew.metadata.source_provenance import load_source_files

    if not current.get("file"):
        return None
    root = cfg.root if current.get("kind") == "LIBRARY" else cfg.metadata_dir
    old: Path = (root / current["file"]).absolute()
    if old.resolve() == source or old.is_symlink() or not old.is_file():
        return None
    if not old.resolve().is_relative_to(cfg.root.resolve()):
        return None
    rows = [
        row
        for (module, address), row in load_metadata(cfg.metadata_dir).items()
        if (module, address) != (target_module(cfg), va)
    ] + list(load_data_metadata(cfg.metadata_dir).values())
    for row in rows:
        base = cfg.root if row.get("kind") == "LIBRARY" else cfg.metadata_dir
        if row.get("file") and (base / row["file"]).resolve() == old.resolve():
            return None
    if any(
        (cfg.metadata_dir / row.file).resolve() == old.resolve()
        for row in load_source_files(cfg.metadata_dir)
    ):
        return None
    text, _ = read_source_text(old)
    names = find_c_function_definitions(text)
    if len(names) != 1 or names[0][0] != current.get("name"):
        return None
    if any(var.is_definition for var in find_extern_variables(text, include_definitions=True)):
        return None
    tree, _ = parse_c_source(mask_msvc_syntax(text))
    if tree.root_node.has_error:
        return None
    return old


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
    retarget_references: bool = False,
) -> dict[str, Any]:
    module = target_module(cfg) or ""
    module_key = preset_module_key(module)
    current = get_entry(cfg.metadata_dir, va, module)
    history = validate_binding_history(current.get("binding_history", []))
    identity = None
    inputs: dict[Path, str] = {}

    def pin(path: Path, parsed_text: str | None = None) -> None:
        raw = path.read_bytes()
        if parsed_text is not None:
            text = raw.decode(detect_source_encoding(raw), errors="replace")
            if text != parsed_text or path.read_bytes() != raw:
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
        _refuse_generated_name_of_another_function(cfg, va, name)
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
                if other_va == va or preset_module_key(other_module) != module_key:
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
    new_key = _replacement_type_key(identity, source)
    for path in iter_sources(cfg.reversed_dir, cfg):
        text, _ = read_source_text(path)
        if new_key is not None and identity is not None and path.resolve() != source:
            _refuse_conflicting_prototype(text, identity["name"], new_key, path, cfg)
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
    retarget_plan = None
    removed = None
    coordinated = None
    file_changes = []
    watched: list[Path] = []
    paths: list[Path] = []
    if retarget_references:
        from rebrew.metadata.coordinated import coordinated_inputs
        from rebrew.rename_ops import Selection, plan_rebound_references

        if identity is None or source is None:
            raise ValueError("retargeting requires a replacement definition")
        retarget_plan = plan_rebound_references(cfg, Selection("function", module, va), identity)
        for change in retarget_plan.files:
            if new_key is not None and change.path.suffix.lower() != ".rsp":
                _refuse_conflicting_prototype(change.old_text, old_name, new_key, change.path, cfg)
        removed = _obsolete_body(cfg, va, current, source)
        if removed is not None:
            retarget_plan.files = [c for c in retarget_plan.files if c.path.absolute() != removed]
        paths = [change.path.absolute() for change in retarget_plan.files]
        if removed is not None:
            paths.append(removed)
        watched = sorted({*inputs, *(Path(p) for p in retarget_plan.input_hashes)} - set(paths))
        coordinated = coordinated_inputs(cfg.metadata_dir, paths, watched=watched)
        file_changes = [
            {"file": identity_file(change.path, cfg.root), "action": "rewrite"}
            for change in retarget_plan.files
        ]
        if removed is not None:
            file_changes.append({"file": identity_file(removed, cfg.root), "action": "remove"})
    digest_inputs = {str(path): digest for path, digest in inputs.items()}
    digest_inputs["metadata"] = preview["input_digest"]
    if retarget_plan is not None:
        digest_inputs["binding"] = json.dumps(
            {"identity": identity, "reason": reason}, sort_keys=True
        )
        digest_inputs["retarget"] = retarget_plan.input_digest
        digest_inputs["coordinated"] = json.dumps(coordinated, sort_keys=True)
        digest_inputs["file_changes"] = json.dumps(file_changes, sort_keys=True)
    digest = hashlib.sha256(json.dumps(digest_inputs, sort_keys=True).encode()).hexdigest()
    if expected_digest is not None and digest != expected_digest:
        raise ValueError("binding review inputs changed; review a new preview")
    if dry_run:
        result = preview
    elif retarget_plan is not None and coordinated is not None:
        from rebrew.metadata.coordinated import coordinated_transaction, path_identity_digest
        from rebrew.metadata.source_provenance import rename_source_provenance
        from rebrew.metadata.storage import input_digest, managed_metadata_filenames
        from rebrew.rename_ops import check_rename_inputs
        from rebrew.sources import iter_sources_and_headers

        discovered = {p.resolve() for p in iter_sources_and_headers(cfg.reversed_dir, cfg)}
        expected_discovery = discovered - ({removed.resolve()} if removed else set())

        def validate_after() -> None:
            for path in watched:
                if path.name in managed_metadata_filenames():
                    continue
                if input_digest(path) != coordinated.get(
                    str(path.resolve())
                ) or path_identity_digest(path) != coordinated.get(
                    "path-identity:" + str(path.absolute())
                ):
                    raise ValueError(f"binding input changed during publication: {path}")
            if {
                p.resolve() for p in iter_sources_and_headers(cfg.reversed_dir, cfg)
            } != expected_discovery:
                raise ValueError("binding source discovery changed during publication")

        with coordinated_transaction(
            cfg.metadata_dir,
            paths,
            expected_inputs=coordinated,
            watched=watched,
            validate=lambda: check_rename_inputs(cfg, retarget_plan),
            validate_after=validate_after,
            allow_unconfigured=True,
            extra_suffixes=frozenset({".rsp"}),
        ) as staged:
            for change in retarget_plan.files:
                staged.publish(change.path, change.new_text.encode(change.encoding))
            result = change_source_binding(
                cfg.metadata_dir,
                module,
                va,
                reason=reason,
                identity=identity,
                expected_digest=preview["input_digest"],
                project_root=cfg.root,
            )
            rename_source_provenance(
                cfg.metadata_dir,
                {c.path: (c.old_text, c.new_text) for c in retarget_plan.files},
                symbol_rename=(retarget_plan.old_name, retarget_plan.new_name),
            )
    else:
        result = change_source_binding(
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
    return {
        **result,
        "input_digest": digest,
        "source_references": references,
        "references_rewritten": retarget_references,
        "file_changes": file_changes,
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
    except (OSError, ValueError, RenameError) as exc:
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
    retarget_references: bool = typer.Option(
        False,
        "--retarget-references",
        help="Retarget owned references and remove an unowned single-body file",
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
            retarget_references=retarget_references,
        )
    except (OSError, ValueError, RenameError) as exc:
        error_exit(str(exc), json_mode=json_output)
    _emit(result, json_output)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_cli

    run_cli(app)


if __name__ == "__main__":
    main_entry()
