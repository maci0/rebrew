"""Target-scoped C declaration contracts, independent of byte-match verdicts."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from rebrew.c_parser import (
    array_type_shape,
    declares_function,
    find_extern_variables,
    prototype_name_span,
    prototype_type_key,
    replace_function_prototype,
    type_from_declaration,
)
from rebrew.c_rename import ParsedSource, declarator_name, non_external_function_declarations
from rebrew.compiler.cache import scan_include_closure
from rebrew.compiler.compile import effective_compile_flags, extract_include_dirs
from rebrew.compiler.overrides import resolve_compile_overrides
from rebrew.config import ProjectConfig, target_module
from rebrew.metadata.bindings import read_source_bindings
from rebrew.metadata.document import metadata_write_lock
from rebrew.rename_ops import FileChange, RenamePlan, SourceEdit, apply_rename_plan
from rebrew.source_selection import collect_target_sources
from rebrew.types import type_size
from rebrew.utils import detect_source_encoding, source_newline


@dataclass(frozen=True)
class ContractSite:
    """One physical signature/declaration and the translation unit that sees it."""

    name: str
    kind: str
    file: str
    context: str
    line: int
    start: int
    end: int
    prototype: str
    key: str
    definition: bool
    static: bool
    conditional: bool


def _nodes(node: Any) -> Any:
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        pending.extend(reversed(current.named_children))


def _read_text(path: Path) -> tuple[bytes, str, str]:
    raw = path.read_bytes()
    encoding = detect_source_encoding(raw)
    return raw, raw.decode(encoding), encoding


def _header_guard(node: Any, path: Path) -> bool:
    if (
        path.suffix.lower() != ".h"
        or node.type != "preproc_ifdef"
        or node.parent.type != "translation_unit"
        or not node.text.startswith(b"#ifndef")
        or node.child_by_field_name("alternative") is not None
    ):
        return False
    name = node.child_by_field_name("name")
    if name is None:
        return False
    roots = [child for child in node.parent.named_children if child.type != "comment"]
    definitions = [child for child in node.named_children if child.type == "preproc_def"]
    return roots == [node] and bool(
        definitions
        and definitions[0].child_by_field_name("name") is not None
        and definitions[0].child_by_field_name("name").text == name.text
    )


def _conditional(node: Any, path: Path) -> bool:
    parent = node.parent
    while parent is not None:
        if parent.type in {
            "preproc_if",
            "preproc_ifdef",
            "preproc_else",
            "preproc_elif",
        } and not _header_guard(parent, path):
            return True
        parent = parent.parent
    return False


def _functions(path: Path, context: Path, text: str) -> list[ContractSite]:
    parsed = ParsedSource.parse(text)
    sites = []
    for node in _nodes(parsed.tree.root_node):
        if node.type not in {"function_definition", "declaration"}:
            continue
        declarators = node.children_by_field_name("declarator")
        if len(declarators) != 1 or not declares_function(declarators[0]):
            continue
        name = declarator_name(declarators[0], parsed)
        body = node.child_by_field_name("body")
        end = body.start_byte if body is not None else node.end_byte
        proto = (
            parsed.data[node.start_byte : end]
            .decode("utf-8", errors="surrogateescape")
            .strip()
            .rstrip(";")
        )
        key = prototype_type_key(proto)
        if name and key:
            for storage in ("extern ", "static ", "inline "):
                key = key.removeprefix(storage)
            sites.append(
                ContractSite(
                    name,
                    "function",
                    str(path),
                    str(context),
                    node.start_point[0] + 1,
                    node.start_byte,
                    end,
                    proto,
                    key,
                    body is not None,
                    any(
                        c.type == "storage_class_specifier" and parsed.node_text(c) == "static"
                        for c in node.named_children
                    ),
                    _conditional(node, path),
                )
            )
    return sites


def contract_contexts(
    cfg: ProjectConfig, *, selected_sources: set[Path] | None = None
) -> tuple[dict[Path, set[Path]], list[dict[str, Any]]]:
    """Read actual target providers and their include closure, reporting uncertainty."""
    sources, _foreign = collect_target_sources(cfg, target_module(cfg))
    if selected_sources is not None:
        sources = [source for source in sources if source.resolve() in selected_sources]
    contexts: dict[Path, set[Path]] = {}
    unknown = []
    for source in sources:
        text = _read_text(source)[1]
        annotations = read_source_bindings(
            source,
            target_name=target_module(cfg),
            metadata_dir=cfg.metadata_dir,
            project_root=cfg.root,
        )
        flags = {
            resolve_compile_overrides(
                cfg, source.parent, a.toolchain or None, a.cflags or None, a.module
            )[1]
            for a in annotations
            if a.kind in {"FUNCTION", "STUB", "LIBRARY"}
        }
        if not flags:
            flags = {
                resolve_compile_overrides(cfg, source.parent, None, None, target_module(cfg))[1]
            }
        headers: set[Path] = set()
        for cflags in flags:
            includes = extract_include_dirs(
                effective_compile_flags(cfg, None, cflags, source.parent)
            )
            if cfg.compiler_includes != Path():
                includes.append(str(cfg.compiler_includes))
            misses: list[tuple[str, tuple[str, ...]]] = []
            paths, fallback, _stats, consistent = scan_include_closure(
                text, str(source.parent), tuple(includes), unresolved=misses
            )
            headers.update(Path(p) for p in paths)
            if fallback or not consistent or misses:
                unknown.append(
                    {
                        "context": str(source),
                        "reason": "include closure is incomplete or changed",
                        "missing": [name for name, _ in misses],
                    }
                )
        for path in {source, *headers}:
            contexts.setdefault(path.resolve(), set()).add(source)
    return contexts, unknown


def _difference(left: str, right: str) -> str:
    if left == right:
        return "equal"
    # Treat pointee spelling changes as reviewable views, never as ABI proof.
    if (
        "*" in left
        and "*" in right
        and left.count("*") == right.count("*")
        and all(c not in left + right for c in "([]")
    ):
        return "pointer_view"
    if ("*" in left) != ("*" in right):
        return "pointer_value"
    base_a, dimensions_a = array_type_shape(left)
    base_b, dimensions_b = array_type_shape(right)
    if (
        dimensions_a
        and dimensions_b
        and base_a == base_b
        and len(dimensions_a) == len(dimensions_b)
        and all(
            a == b or a is None or b is None
            for a, b in zip(dimensions_a, dimensions_b, strict=True)
        )
    ):
        return "incomplete_array_view"
    if left != "void" and right != "void" and (type_size(left) is None or type_size(right) is None):
        return "unresolved_type"
    return "value_type"


def _signature_differences(left: str, right: str) -> list[str]:
    a, separator_a, args_a = left.partition("(")
    b, separator_b, args_b = right.partition("(")
    if not separator_a or not separator_b or "(" in args_a + args_b:
        return ["signature"]
    changes = []
    conventions = (
        "__stdcall",
        "__fastcall",
        "__thiscall",
        "__vectorcall",
        "WINAPI",
        "CALLBACK",
        "APIENTRY",
    )
    convention_a = next((cc for cc in conventions if cc in a), "__cdecl")
    convention_b = next((cc for cc in conventions if cc in b), "__cdecl")
    if convention_a != convention_b:
        changes.append("calling_convention")
    for cc in conventions:
        a, b = a.replace(cc, "").strip(), b.replace(cc, "").strip()
    if (difference := _difference(a, b)) != "equal":
        changes.append("return_" + difference)
    params_a, params_b = args_a.rstrip(")").split(","), args_b.rstrip(")").split(",")
    if len(params_a) != len(params_b):
        changes.append("argument_count")
    else:
        for index, (param_a, param_b) in enumerate(zip(params_a, params_b, strict=True)):
            if (difference := _difference(param_a, param_b)) != "equal":
                changes.append(f"argument_{index}_{difference}")
    return changes


def _resolved_contract_sites(
    sites: list[ContractSite], contexts: dict[Path, set[Path]], texts: dict[Path, str]
) -> tuple[list[ContractSite], list[dict[str, Any]]]:
    aliases: dict[str, dict[str, set[str]]] = {}
    callbacks: dict[tuple[str, str, str], tuple[bytes, int, int]] = {}
    for path, units in contexts.items():
        parsed = ParsedSource.parse(texts[path])
        for node in _nodes(parsed.tree.root_node):
            if node.type != "type_definition":
                continue
            parent = node.parent
            while parent is not None and parent.type != "function_definition":
                parent = parent.parent
            if parent is not None:
                continue
            for declarator in node.children_by_field_name("declarator"):
                name = declarator_name(declarator, parsed)
                if not name:
                    continue
                declaration = parsed.node_text(node).removeprefix("typedef").lstrip().rstrip(";")
                value = type_from_declaration(declaration, name) or ""
                callback = None
                kind = node.child_by_field_name("type")
                if kind is not None and kind.type in {
                    "struct_specifier",
                    "union_specifier",
                    "enum_specifier",
                }:
                    tag = kind.child_by_field_name("name")
                    if tag is not None:
                        record = kind.type.removesuffix("_specifier") + " " + parsed.node_text(tag)
                        declaration = (
                            parsed.data[node.start_byte : kind.start_byte]
                            + record.encode("utf-8")
                            + parsed.data[kind.end_byte : node.end_byte]
                        ).decode("utf-8")
                        declaration = declaration.removeprefix("typedef").lstrip().rstrip(";")
                        value = type_from_declaration(declaration, name) or ""
                    else:
                        value = ""
                if "(" in value:
                    span = prototype_name_span(declaration)
                    key = prototype_type_key(f"void callback_type({declaration});")
                    if (
                        span is not None
                        and span[0] == name
                        and key is not None
                        and not declares_function(declarator)
                        and any(n.type == "pointer_declarator" for n in _nodes(declarator))
                    ):
                        value = key[len("void(") : -1]
                        callback = (declaration.encode("utf-8"), span[1], span[2])
                    else:
                        value = ""
                if _conditional(node, path) or any(token in value for token in ("[", "{")):
                    value = ""
                for unit in units:
                    aliases.setdefault(str(unit), {}).setdefault(name, set()).add(value)
                    if callback is not None and value:
                        callbacks.setdefault((str(unit), name, value), callback)
    resolved = []
    unknown = []
    for site in sites:
        source = site.prototype
        seen: set[str] = set()
        uncertain: set[str] = set()
        for _depth in range(16):
            if source in seen:
                uncertain.add("cyclic typedef")
                break
            seen.add(source)
            parsed = ParsedSource.parse(source.rstrip(";") + ";")
            edits = []
            for node in _nodes(parsed.tree.root_node):
                if node.type != "type_identifier" or node.parent.type in {
                    "struct_specifier",
                    "union_specifier",
                    "enum_specifier",
                }:
                    continue
                name = parsed.node_text(node)
                values = aliases.get(site.context, {}).get(name, set())
                if len(values) != 1 or not next(iter(values), ""):
                    uncertain.add(name)
                    continue
                value = next(iter(values))
                callback = callbacks.get((site.context, name, value))
                if callback is not None:
                    parent = node.parent
                    declarator = parent.child_by_field_name("declarator")
                    if (
                        parent.type != "parameter_declaration"
                        or declarator is None
                        or declarator.type != "identifier"
                        or any(c.type == "type_qualifier" for c in parent.named_children)
                    ):
                        uncertain.add(name)
                        continue
                    template, start, end = callback
                    replacement = template[:start] + declarator.text + template[end:]
                    edits.append((parent.start_byte, parent.end_byte, replacement))
                else:
                    edits.append((node.start_byte, node.end_byte, value.encode("utf-8")))
            if not edits:
                break
            raw = parsed.data
            for start, end, replacement_bytes in sorted(edits, reverse=True):
                raw = raw[:start] + replacement_bytes + raw[end:]
            source = raw.decode("utf-8")
        else:
            uncertain.add("typedef expansion depth")
        if uncertain:
            unknown.append(
                {
                    "context": site.context,
                    "file": site.file,
                    "name": site.name,
                    "reason": "unresolved context-specific typedef",
                    "types": sorted(uncertain),
                }
            )
        key = (
            prototype_type_key(source)
            if site.kind == "function"
            else type_from_declaration(source, site.name)
        )
        if key:
            for storage in ("extern ", "static ", "inline "):
                key = key.removeprefix(storage)
            site = replace(site, key="".join(key.split()) if site.kind == "object" else key)
        resolved.append(site)
    return resolved, unknown


def audit_contracts(cfg: ProjectConfig, *, name: str | None = None) -> dict[str, Any]:
    """Compare physical declarations, definitions and return-consuming call sites."""
    selection_inputs = [p for p in cfg.metadata_dir.glob("rebrew-*.toml") if p.is_file()]
    if (cfg.root / "rebrew-project.toml").is_file():
        selection_inputs.append(cfg.root / "rebrew-project.toml")
    input_hashes = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in selection_inputs}
    contexts, unknown = contract_contexts(cfg)
    source_units = sorted({str(unit) for units in contexts.values() for unit in units})
    sites: list[ContractSite] = []
    calls = []
    source_texts: dict[Path, str] = {}
    for path, units in contexts.items():
        before, text, _encoding = _read_text(path)
        if path.read_bytes() != before:
            raise ValueError(f"source changed while auditing: {path}")
        input_hashes[str(path)] = hashlib.sha256(before).hexdigest()
        source_texts[path] = text
        function_sites = _functions(path, path, text)
        variables = list(find_extern_variables(text, include_definitions=True))
        parsed = ParsedSource.parse(text)
        declarations = [n for n in _nodes(parsed.tree.root_node) if n.type == "declaration"]
        declarations_by_line: dict[int, list[Any]] = {}
        for declaration in declarations:
            declarations_by_line.setdefault(declaration.start_point[0] + 1, []).append(declaration)
        for unit in sorted(units):
            sites.extend(replace(site, context=str(unit)) for site in function_sites)
            if parsed.tree.root_node.has_error:
                unknown.append(
                    {
                        "context": str(unit),
                        "file": str(path),
                        "reason": "C syntax contains parse errors or missing tokens",
                    }
                )
            if name and non_external_function_declarations(parsed, name):
                unknown.append(
                    {
                        "context": str(unit),
                        "file": str(path),
                        "reason": "selected name has a non-external-function declaration",
                    }
                )
            for declaration in declarations:
                if (
                    declaration.type == "declaration"
                    and len(declaration.children_by_field_name("declarator")) > 1
                    and any(
                        declares_function(d)
                        for d in declaration.children_by_field_name("declarator")
                    )
                ):
                    unknown.append(
                        {
                            "context": str(unit),
                            "file": str(path),
                            "reason": "multi-declarator function declaration requires explicit review",
                        }
                    )
            for variable in variables:
                candidates = declarations_by_line.get(variable.line, [])
                static = bool(
                    candidates
                    and any(
                        c.type == "storage_class_specifier" and parsed.node_text(c) == "static"
                        for c in candidates[0].named_children
                    )
                )
                sites.append(
                    ContractSite(
                        variable.name,
                        "object",
                        str(path),
                        str(unit),
                        variable.line,
                        0,
                        0,
                        variable.declaration,
                        "".join(variable.type_str.split()),
                        variable.is_definition,
                        static,
                        _conditional(candidates[0], path) if candidates else True,
                    )
                )
            for node in _nodes(parsed.tree.root_node):
                if node.type != "call_expression":
                    continue
                callee = node.child_by_field_name("function")
                arguments = node.child_by_field_name("arguments")
                if callee is not None and callee.type == "identifier":
                    parent = node.parent
                    while parent is not None and parent.type == "parenthesized_expression":
                        parent = parent.parent
                    calls.append(
                        {
                            "name": parsed.node_text(callee),
                            "file": str(path),
                            "context": str(unit),
                            "line": node.start_point[0] + 1,
                            "return_used": parent is not None
                            and parent.type != "expression_statement",
                            "arguments": [parsed.node_text(arg) for arg in arguments.named_children]
                            if arguments
                            else [],
                            "argument_kinds": [arg.type for arg in arguments.named_children]
                            if arguments
                            else [],
                            "conditional": _conditional(node, path),
                        }
                    )
    selected_sites = [site for site in sites if name is None or site.name == name]
    sites, unresolved = _resolved_contract_sites(selected_sites, contexts, source_texts)
    unknown.extend(unresolved)
    groups: dict[tuple[str, str, str], list[ContractSite]] = {}
    internal = {(site.kind, site.name, site.context) for site in sites if site.static}
    for site in sites:
        if name is None or site.name == name:
            groups.setdefault(
                (
                    site.kind,
                    site.name,
                    site.context if (site.kind, site.name, site.context) in internal else "",
                ),
                [],
            ).append(site)
    findings = []
    linkage_groups: dict[tuple[str, str], list[ContractSite]] = {}
    for site in sites:
        if site.kind == "function":
            linkage_groups.setdefault((site.context, site.name), []).append(site)
    for (_context, symbol), claims in linkage_groups.items():
        static_sites = [site for site in claims if site.static]
        if static_sites and any(
            not site.static
            and (
                site.file != static_sites[0].file or site.start < min(s.start for s in static_sites)
            )
            for site in claims
        ):
            findings.append(
                {
                    "kind": "function",
                    "name": symbol,
                    "differences": ["linkage"],
                    "severity": "error",
                    "sites": [asdict(site) for site in claims],
                }
            )
    for (kind, symbol, _scope), claims in sorted(groups.items()):
        keys = sorted({site.key for site in claims})
        if len(keys) < 2:
            continue
        differences = sorted(
            {
                difference
                for key in keys[1:]
                for difference in (
                    _signature_differences(keys[0], key)
                    if kind == "function"
                    else [_difference(keys[0], key)]
                )
            }
        )
        findings.append(
            {
                "kind": kind,
                "name": symbol,
                "differences": differences,
                "severity": "review"
                if all(
                    d.endswith(("pointer_view", "incomplete_array_view", "unresolved_type"))
                    for d in differences
                )
                else "error",
                "sites": [asdict(site) for site in claims],
            }
        )
    if any(
        hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest
        for path, digest in input_hashes.items()
    ):
        raise ValueError("contract inputs changed during audit")
    return {
        "input_hashes": input_hashes,
        "source_units": source_units,
        "target": cfg.target_name,
        "findings": findings,
        "sites": [asdict(site) for site in sites if name is None or site.name == name],
        "calls": [call for call in calls if name is None or call["name"] == name],
        "unknown": unknown,
        "verdicts_changed": False,
        "preprocessed": False,
    }


def _parameter_names(prototype: str) -> list[str | None]:
    parsed = ParsedSource.parse(prototype.rstrip(";") + ";")
    for node in _nodes(parsed.tree.root_node):
        if node.type == "function_declarator":
            params = node.child_by_field_name("parameters")
            if params is None:
                return []
            return [
                declarator_name(p.child_by_field_name("declarator"), parsed)
                for p in params.named_children
                if p.type == "parameter_declaration" and parsed.node_text(p) != "void"
            ]
    raise ValueError("prototype has no supported function declarator")


def _definition_prototype(prototype: str, original: str) -> str:
    names = _parameter_names(original)
    canonical = ParsedSource.parse(prototype.rstrip(";") + ";")
    if len(names) != len(_parameter_names(prototype)):
        raise ValueError("reviewed signature must preserve definition parameter count")
    edits = []
    params = next(n for n in _nodes(canonical.tree.root_node) if n.type == "parameter_list")
    parameters = [
        p
        for p in params.named_children
        if p.type == "parameter_declaration" and canonical.node_text(p) != "void"
    ]
    for name, param in zip(names, parameters, strict=True):
        declarator = param.child_by_field_name("declarator")
        proposed_name = declarator_name(declarator, canonical)
        if name is None or proposed_name is None:
            raise ValueError("reviewed definition signatures require named parameters")
        identifiers = [
            n
            for n in _nodes(declarator)
            if n.type == "identifier" and canonical.node_text(n) == proposed_name
        ]
        if len(identifiers) != 1:
            raise ValueError("ambiguous parameter declarator")
        ident = identifiers[0]
        edits.append((ident.start_byte, ident.end_byte, name.encode("ascii")))
    raw = canonical.data
    for start, end, replacement in sorted(edits, reverse=True):
        raw = raw[:start] + replacement + raw[end:]
    return raw.decode("utf-8", errors="surrogateescape").rstrip(";")


def reconcile_contract(
    cfgs: list[ProjectConfig],
    name: str,
    header: Path,
    prototype: str,
    *,
    dry_run: bool = False,
    expected_digest: str | None = None,
) -> dict[str, Any]:
    """Preview/apply one explicitly reviewed signature across every selected context.

    Source edits use the existing rollback/provenance writer. Conditional or
    ambiguous sites are refused; caller expressions are reported for verification.
    No byte-match status is manufactured by this source-only operation.
    """
    if not cfgs or any(cfg.root.resolve() != cfgs[0].root.resolve() for cfg in cfgs):
        raise ValueError("contract reconciliation requires one project")
    root = cfgs[0].root.resolve()
    header = (root / header).resolve()
    if not header.is_relative_to(root) or not header.is_file() or header.suffix.lower() != ".h":
        raise ValueError("canonical header must be an existing project .h file")
    canonical_sites = _functions(header, header, prototype.rstrip(";") + ";")
    if (
        len(canonical_sites) != 1
        or canonical_sites[0].name != name
        or canonical_sites[0].definition
        or canonical_sites[0].static
        or "..." in prototype
    ):
        raise ValueError(
            "provide one non-static, non-variadic reviewed prototype for the selected name"
        )
    # Reject extra declarations/macros hidden after the selected prototype.
    parsed_prototype = ParsedSource.parse(prototype.rstrip(";") + ";")
    if (
        parsed_prototype.tree.root_node.has_error
        or len(parsed_prototype.tree.root_node.named_children) != 1
    ):
        raise ValueError("reviewed prototype must contain exactly one declaration")
    reports = [audit_contracts(cfg, name=name) for cfg in cfgs]
    if any(report["unknown"] for report in reports):
        raise ValueError("resolve incomplete source/include contexts before reconciliation")
    sites = {
        (site["file"], site["start"], site["end"]): site
        for report in reports
        for site in report["sites"]
        if site["kind"] == "function"
    }
    header_raw, header_text, _header_encoding = _read_text(header)
    if ParsedSource.parse(header_text).tree.root_node.has_error:
        raise ValueError("canonical header contains C parse errors or missing tokens")
    for header_site in _functions(header, header, header_text):
        if header_site.name == name:
            sites[(header_site.file, header_site.start, header_site.end)] = asdict(header_site)
    if any(not Path(site["file"]).resolve().is_relative_to(root) for site in sites.values()):
        raise ValueError("contract reconciliation cannot edit external headers or sources")
    if not sites or not any(site["definition"] for site in sites.values()):
        raise ValueError("no selected definition-owned contract")
    if any(
        site["static"]
        or "..." in site["prototype"]
        or site["conditional"]
        or (site["definition"] and Path(site["file"]) == header)
        for site in sites.values()
    ):
        raise ValueError(
            "static or target-conditional signatures require an explicit source repair"
        )
    inputs = {Path(site["file"]) for site in sites.values()} | {header}
    for report in reports:
        inputs.update(Path(call["file"]) for call in report["calls"])
    # Include every audited input and authoritative selection input in the guard.
    for cfg in cfgs:
        contexts, _unknown = contract_contexts(cfg)
        inputs.update(contexts)
        inputs.update(p for p in cfg.metadata_dir.glob("rebrew-*.toml") if p.is_file())
        if (cfg.root / "rebrew-project.toml").is_file():
            inputs.add(cfg.root / "rebrew-project.toml")
    original = {path: path.read_bytes() for path in inputs}
    if original[header] != header_raw:
        raise ValueError("canonical header changed after audit")
    for audit in reports:
        if any(
            hashlib.sha256(original[Path(path)]).hexdigest() != digest
            for path, digest in audit["input_hashes"].items()
        ):
            raise ValueError("contract inputs changed after audit")
    digest = hashlib.sha256(
        json.dumps(
            {str(p): hashlib.sha256(raw).hexdigest() for p, raw in sorted(original.items())},
            sort_keys=True,
        ).encode()
    ).hexdigest()
    if expected_digest is not None and digest != expected_digest:
        raise ValueError("contract inputs changed; review a new preview")
    edits: dict[Path, list[tuple[int, int, bytes]]] = {}
    texts = {
        path: (raw.decode(detect_source_encoding(raw)), detect_source_encoding(raw))
        for path, raw in original.items()
    }
    canonical = prototype.rstrip().rstrip(";") + ";"
    for site in sites.values():
        path = Path(site["file"])
        if site["definition"]:
            replacement = _definition_prototype(prototype, site["prototype"])
            updated = replace_function_prototype(
                site["prototype"] + " {}", name, replacement
            ).removesuffix("{}")
            edits.setdefault(path, []).append(
                (site["start"], site["end"], updated.encode("utf-8", errors="surrogateescape"))
            )
        else:
            edits.setdefault(path, []).append((site["start"], site["end"], b""))
    proposed_key = canonical_sites[0].key
    parameter_key = proposed_key.partition("(")[2].rstrip(")")
    if "(" in parameter_key:
        raise ValueError("function-pointer contracts require an explicit source repair")
    proposed_parameters = [] if not parameter_key else parameter_key.split(",")
    proposed_declaration = parsed_prototype.tree.root_node.named_children[0]
    return_type = proposed_declaration.child_by_field_name("type")
    declarator = proposed_declaration.child_by_field_name("declarator")
    returns_void = bool(
        return_type is not None
        and parsed_prototype.node_text(return_type) == "void"
        and declarator is not None
        and declarator.type == "function_declarator"
    )
    for audit in reports:
        if any(len(call["arguments"]) != len(proposed_parameters) for call in audit["calls"]):
            raise ValueError("reviewed signature contradicts a caller argument count")
    for site in sites.values():
        if not site["definition"]:
            continue
        path = Path(site["file"])
        parsed = ParsedSource.parse(texts[path][0])
        definition = next(
            node
            for node in _nodes(parsed.tree.root_node)
            if node.type == "function_definition" and node.start_byte == site["start"]
        )
        returns = [
            node
            for node in _nodes(definition.child_by_field_name("body"))
            if node.type == "return_statement"
        ]
        if (returns_void and any(node.named_children for node in returns)) or (
            not returns_void and (not returns or any(not node.named_children for node in returns))
        ):
            raise ValueError("definition return statements require an explicit body repair")
    # Keep an existing canonical header declaration at its original position.
    header_sites = [
        site for site in sites.values() if Path(site["file"]) == header and not site["definition"]
    ]
    if len(header_sites) > 1:
        raise ValueError("canonical header has duplicate signatures; reconcile them explicitly")
    if header_sites:
        site = header_sites[0]
        edits[header] = [edit for edit in edits.get(header, []) if edit[0] != site["start"]]
        edits[header].append((site["start"], site["end"], canonical.encode("utf-8")))
    else:
        text = texts[header][0]
        parsed = ParsedSource.parse(text)
        guards = [
            node for node in parsed.tree.root_node.named_children if _header_guard(node, header)
        ]
        offset = len(parsed.data)
        if guards:
            ends = [n for n in guards[0].children if n.type == "#endif"]
            if not ends:
                raise ValueError("canonical header guard is incomplete")
            offset = ends[-1].start_byte
        newline = source_newline(text)
        edits.setdefault(header, []).append(
            (offset, offset, (newline + canonical + newline).encode("utf-8"))
        )
    affected = sorted(
        {Path(site["context"]) for report in reports for site in report["sites"]}
        | {Path(call["context"]) for report in reports for call in report["calls"]}
    )
    changes = []
    for path in sorted(set(edits) | set(affected)):
        text, encoding = texts[path]
        raw = text.encode("utf-8", errors="surrogateescape")
        for start, end, replacement_bytes in sorted(edits.get(path, []), reverse=True):
            raw = raw[:start] + replacement_bytes + raw[end:]
        updated = raw.decode("utf-8", errors="surrogateescape")
        if path != header:
            include = Path(os.path.relpath(header, path.parent)).as_posix()
            directive = f'#include "{include}"'
            parsed_updated = ParsedSource.parse(updated)
            has_include = any(
                n.type == "preproc_include"
                and not _conditional(n, path)
                and n.child_by_field_name("path") is not None
                and parsed_updated.node_text(n.child_by_field_name("path")) == f'"{include}"'
                for n in _nodes(parsed_updated.tree.root_node)
            )
            if not has_include:
                # Insert at the first removed declaration to retain TU order.
                position = min((start for start, _end, _new in edits.get(path, [])), default=0)
                prefix = raw[:position]
                updated = (
                    prefix + (directive + source_newline(text)).encode("utf-8") + raw[position:]
                ).decode("utf-8", errors="surrogateescape")
        if updated != text:
            changes.append(
                FileChange(path, text, updated, encoding, [SourceEdit(1, 1, "contract")])
            )
    calls = [
        {
            "target": report["target"],
            **call,
            "reviewed_parameters": proposed_parameters,
            "conversions": [
                {
                    "expression": expression,
                    "parameter_type": proposed_parameters[index],
                    "source_type": "unknown; requires compiler check",
                }
                for index, expression in enumerate(call["arguments"])
            ],
            "conversion_check": "requires compiler and affected-function verification",
        }
        for report in reports
        for call in report["calls"]
    ]
    report = {
        "dry_run": dry_run,
        "input_digest": digest,
        "name": name,
        "header": str(header),
        "prototype": canonical,
        "targets": [cfg.target_name for cfg in cfgs],
        "files": [
            {"file": str(change.path), "before": change.old_text, "after": change.new_text}
            for change in changes
        ],
        "calls": calls,
        "verification_required": True,
        "verdicts_changed": False,
    }
    if any(path.read_bytes() != raw for path, raw in original.items()):
        raise ValueError("contract inputs changed during planning")
    if not dry_run:
        with metadata_write_lock(cfgs[0].metadata_dir, "rebrew-functions.toml"):
            if any(path.read_bytes() != raw for path, raw in original.items()):
                raise ValueError("contract inputs changed before publication")
            for cfg, audit in zip(cfgs, reports, strict=True):
                current, _ = collect_target_sources(cfg, target_module(cfg))
                if sorted(str(p) for p in current) != audit["source_units"]:
                    raise ValueError("target provider scope changed before publication")
            apply_rename_plan(cfgs[0], RenamePlan("contract", name, name, files=changes))
    return report
