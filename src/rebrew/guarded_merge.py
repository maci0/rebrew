"""Conservative guarded function interleaving without invented macro conditions."""

import re
lazy from graphlib import CycleError, TopologicalSorter
lazy from itertools import pairwise
lazy from pathlib import Path
lazy from typing import Any

lazy from rebrew.c_parser import parse_c_source
lazy from rebrew.source_guard_context import guard_contexts
lazy from rebrew.source_layout import mask_for_parse, source_layout, span_extent

_SIMPLE_OPEN = re.compile(r"\s*#\s*ifn?def\s+[A-Za-z_]\w*\s*")
_SIMPLE_CLOSE = re.compile(r"\s*#\s*endif\s*")
_SENSITIVE = re.compile(
    r"\b__(?:LINE|FILE|BASE_FILE|INCLUDE_LEVEL|COUNTER|TIMESTAMP|DATE|TIME)__\b"
)
_SHARED_PROTOTYPE = re.compile(
    r"\A[ \t]*(int|float|void)[ \t]+([A-Za-z][A-Za-z_0-9]*)[ \t]*\(void\)[ \t]*;[ \t]*\r?\n"
)

#: Explicit calling conventions searched in a declarator head.
_CALLING_CONVENTION_RE = re.compile(
    rb"\b(?:__cdecl|__stdcall|__fastcall|_cdecl|_stdcall|_fastcall)\b"
)


def prepare_guarded_inputs(
    readings: dict[Path, tuple[str, str]],
) -> tuple[dict[Path, str], dict[Path, tuple[str, str]], set[str], str, bool]:
    """Mask only reviewed simple outer guards while retaining every source offset.

    This deliberately narrow writer accepts complete UTF-8 units containing
    only bound, external functions with simple scalar signatures and attached comments.
    Headers, declarations, storage, nested branches and unattached comments
    are refused. This prevents declaration, macro and static-instance changes.
    """
    report = guard_contexts(list(readings))
    if report["declaration_conflicts"]:
        raise ValueError("guarded interleave has incompatible or unassessed declarations")
    masks: dict[Path, str] = {}
    wrappers: dict[Path, tuple[str, str]] = {}
    names = {row["name"] for row in report["definitions"]}
    prefixes = [
        match.group(0) if (match := _SHARED_PROTOTYPE.match(text)) else ""
        for text, _ in readings.values()
    ]
    if len(set(prefixes)) != 1:
        raise ValueError("guarded interleave requires an identical shared declaration preamble")
    prefix = prefixes[0]
    prototype = _SHARED_PROTOTYPE.match(prefix)
    calls: list[str] = []
    references: set[str] = set()
    parameter_names: set[str] = set()
    parameter_counts: dict[str, int] = {}
    return_types: dict[str, bytes] = {}
    explicit_conventions: dict[str, str] = {}
    newline_styles = set()
    for path, (text, _encoding) in readings.items():
        raw = text.encode("utf-8")
        if raw != path.read_bytes():
            raise ValueError(f"{path}: guarded interleave requires exact UTF-8 source")
        if b"\r" in raw.replace(b"\r\n", b"") or (
            b"\r\n" in raw and b"\n" in raw.replace(b"\r\n", b"")
        ):
            raise ValueError(f"{path}: mixed line endings require manual review")
        newline_styles.add("crlf" if b"\r\n" in raw else "lf")
        tree, _ = parse_c_source(mask_for_parse(raw))
        if tree.root_node.has_error:
            raise ValueError(f"{path}: incomplete guarded syntax")
        _source, spans = source_layout(text)
        funcs = [span for span in spans if span.kind == "function"]
        if not funcs or any(span.static for span in funcs):
            raise ValueError(f"{path}: guarded interleave requires external functions")
        parameters_by_start: dict[int, set[str]] = {}
        pending_nodes = [tree.root_node]
        while pending_nodes:
            node = pending_nodes.pop()
            if node.type == "function_definition":
                result_type = node.child_by_field_name("type")
                decl = node.child_by_field_name("declarator")
                if (
                    result_type is None
                    or result_type.type != "primitive_type"
                    or raw[result_type.start_byte : result_type.end_byte]
                    not in {b"int", b"void", b"float"}
                    or decl is None
                    or decl.type != "function_declarator"
                ):
                    raise ValueError(f"{path}: unsupported guarded function signature")
                params = decl.child_by_field_name("parameters")
                func_name = decl.child_by_field_name("declarator")
                if params is None:
                    raise ValueError(f"{path}: unsupported guarded function parameters")
                if func_name is None or func_name.type != "identifier":
                    raise ValueError(f"{path}: unsupported guarded function declarator")
                local: set[str] = set()
                for param in params.named_children:
                    param_type = param.child_by_field_name("type")
                    param_decl = param.child_by_field_name("declarator")
                    if param_type is None or param_type.type != "primitive_type":
                        raise ValueError(f"{path}: unsupported guarded function parameter")
                    scalar = raw[param_type.start_byte : param_type.end_byte]
                    if scalar == b"void" and param_decl is None and len(params.named_children) == 1:
                        continue
                    if (
                        scalar not in {b"int", b"float"}
                        or param_decl is None
                        or param_decl.type != "identifier"
                    ):
                        raise ValueError(f"{path}: unsupported guarded function parameter")
                    name = raw[param_decl.start_byte : param_decl.end_byte].decode("utf-8")
                    if name in local or name in names or name.startswith("_"):
                        raise ValueError(f"{path}: guarded parameter name is ambiguous")
                    local.add(name)
                parameters_by_start[node.start_byte] = local
                parameter_names.update(local)
                name = raw[func_name.start_byte : func_name.end_byte].decode("utf-8")
                parameter_counts[name] = len(local)
                return_types[name] = raw[result_type.start_byte : result_type.end_byte]
                body_node = node.child_by_field_name("body")
                if body_node is None:
                    raise ValueError(f"{path}: guarded function has no body")
                modifier = _CALLING_CONVENTION_RE.search(
                    raw[node.start_byte : body_node.start_byte]
                )
                if modifier:
                    explicit_conventions[name] = modifier.group().decode("ascii")
                continue
            pending_nodes.extend(node.named_children)
        rows = [item for item in report["definitions"] if Path(item["file"]).resolve() == path]
        chains = {tuple(g["directive"] for g in item["guards"]) for item in rows}
        if len(chains) != 1 or len(next(iter(chains))) > 1:
            raise ValueError(f"{path}: nested or differing guard groups require manual review")
        chain = next(iter(chains))
        opening = closing = ""
        directive_ranges: list[tuple[int, int]] = []
        if chain:
            opening = chain[0]
            if not _SIMPLE_OPEN.fullmatch(opening):
                raise ValueError(f"{path}: only simple ifdef/ifndef guards are supported")
            groups = [n for n in tree.root_node.named_children if n.type == "preproc_ifdef"]
            if len(groups) != 1:
                raise ValueError(f"{path}: guarded group is ambiguous")
            endings = [n for n in groups[0].children if n.type == "#endif"]
            if len(endings) != 1:
                raise ValueError(f"{path}: guarded group has no unique endif")
            start = raw.rfind(b"\n", 0, endings[0].start_byte) + 1
            end = raw.find(b"\n", endings[0].end_byte)
            end = len(raw) if end < 0 else end + 1
            closing = raw[start:end].decode("utf-8")
            if not closing.endswith("\n") or not _SIMPLE_CLOSE.fullmatch(closing):
                raise ValueError(f"{path}: endif has unsupported trailing content")
            first = rows[0]["guards"][0]
            directive_ranges = [(first["start"], first["end"]), (start, end)]
        residual = bytearray(raw)
        residual[: len(prefix.encode("utf-8"))] = b" " * len(prefix.encode("utf-8"))
        for span in funcs:
            start, end = span_extent(raw, span, spans)
            residual[start:end] = b" " * (end - start)
            body = raw[span.start : span.end].decode("utf-8")
            if "__asm" in body or "_asm" in body:
                raise ValueError(f"{path}: assembly cannot be moved")
        for start, end in directive_ranges:
            residual[start:end] = b" " * (end - start)
        if bytes(residual).strip():
            raise ValueError(
                f"{path}: preambles, storage, directives or unattached comments need review"
            )
        pending: list[tuple[Any, bool, frozenset[str]]] = [(tree.root_node, False, frozenset())]
        while pending:
            node, in_function, scope = pending.pop()
            if node.type == "function_definition":
                scope = frozenset(parameters_by_start[node.start_byte])
            in_function = in_function or node.type == "function_definition"
            if in_function and node.type.startswith("preproc_"):
                raise ValueError(f"{path}: directives inside functions require manual review")
            if in_function and node.type in {"declaration", "string_literal"}:
                raise ValueError(
                    f"{path}: local declarations and string storage require manual review"
                )
            if in_function and node.type == "number_literal":
                number = raw[node.start_byte : node.end_byte].decode("ascii", "replace")
                exponent = "p" if number.lower().startswith("0x") else "e"
                if "." in number or exponent in number.lower():
                    raise ValueError(f"{path}: floating literal storage requires manual review")
            if node.type == "identifier":
                identifier = raw[node.start_byte : node.end_byte].decode("utf-8")
                if _SENSITIVE.fullmatch(identifier):
                    raise ValueError(f"{path}: line-sensitive macros cannot be moved")
                if in_function and identifier not in scope:
                    references.add(identifier)
            if node.type == "call_expression":
                function = node.child_by_field_name("function")
                arguments = node.child_by_field_name("arguments")
                if (
                    not function
                    or function.type != "identifier"
                    or not arguments
                    or arguments.named_children
                ):
                    raise ValueError(f"{path}: guarded calls require known no-argument functions")
                calls.append(raw[function.start_byte : function.end_byte].decode("utf-8"))
            pending.extend((child, in_function, scope) for child in node.named_children)
        masked = bytearray(raw)
        for i in range(len(prefix.encode("utf-8"))):
            if masked[i] not in (10, 13):
                masked[i] = 32
        for start, end in directive_ranges:
            for i in range(start, end):
                if masked[i] not in (10, 13):
                    masked[i] = 32
        masks[path] = masked.decode("utf-8")
        wrappers[path] = (opening, closing)
    if len(newline_styles) != 1:
        raise ValueError("guarded interleave requires identical source line endings")
    if prototype and (
        prototype.group(2) not in names
        or parameter_counts.get(prototype.group(2)) != 0
        or return_types.get(prototype.group(2)) != prototype.group(1).encode("ascii")
    ):
        raise ValueError("shared declaration is incompatible with its definition")
    if any(
        name not in names
        or explicit_conventions.get(name, "__cdecl") not in {"__cdecl", "_cdecl"}
        or parameter_counts.get(name) != 0
        or (return_types.get(name) != b"int" and (prototype is None or prototype.group(2) != name))
        for name in calls
    ):
        raise ValueError("guarded interleave cannot resolve an external call contract")
    unknown = references - names
    if unknown:
        raise ValueError(
            "guarded interleave refuses macro or unresolved identifier references: "
            + ", ".join(sorted(unknown))
        )
    require_gd = any(name in explicit_conventions for name in calls)
    return masks, wrappers, parameter_names, prefix, require_gd


def validate_guarded_flags(
    names: set[str], configurations: list[Any], review: dict[str, Any], *, require_gd: bool = False
) -> None:
    """Reject known macro capture and compiler-supplied hidden preambles."""
    from rebrew.compiler.compile import effective_compile_flags

    if any(name.startswith("_") for name in names):
        raise ValueError("guarded interleave refuses implementation-reserved function names")
    by_target = {str(cfg.target_name): cfg for cfg in configurations}
    for target in review["targets"]:
        cfg = by_target.get(str(target["target"]))
        if cfg is None:
            raise ValueError("guarded interleave has an unknown target compiler context")
        for context in target["contexts"]:
            for setting in context["settings"]:
                flags = effective_compile_flags(
                    cfg, None, setting.get("cflags") or "", Path(context["source"]).parent
                )
                if require_gd and not any(flag.lower() in {"/gd", "-gd"} for flag in flags):
                    raise ValueError(
                        "guarded interleave requires explicit /Gd for called __cdecl functions"
                    )
                index = 0
                while index < len(flags):
                    flag = flags[index]
                    lower = flag.lower()
                    if (
                        flag.startswith(("@", "-include", "-imacros", "-Wp,", "-Xpreprocessor"))
                        or lower.startswith(
                            ("/fi", "/yu", "/yc", "/fp", "-fi", "-yu", "-yc", "-fp")
                        )
                        or lower in {"/x", "-x"}
                    ):
                        raise ValueError(
                            "guarded interleave refuses forced includes, precompiled headers or response files"
                        )
                    if lower in {"/gz", "-gz", "/gr", "-gr"}:
                        raise ValueError(
                            "guarded interleave requires the default C calling convention"
                        )
                    if flag.startswith(("/D", "-D")):
                        value = flag[2:]
                        if not value:
                            index += 1
                            if index >= len(flags):
                                raise ValueError(
                                    "guarded interleave cannot parse compiler macro flags"
                                )
                            value = flags[index]
                        match = re.match(r"[A-Za-z_]\w*", value.strip("\"'"))
                        if not match:
                            raise ValueError("guarded interleave cannot parse compiler macro flags")
                        if match.group() in names or (
                            require_gd and match.group() in {"__cdecl", "_cdecl"}
                        ):
                            raise ValueError(
                                f"guarded interleave function {match.group()} is a compiler macro"
                            )
                    index += 1


def interleave_guarded(
    layouts: list[Any],
    wrappers: dict[str, tuple[str, str]],
    providers: dict[str, set[str]],
    *,
    shared: bool,
) -> list[Any]:
    """Order bounded definitions by every module's native constraints."""
    if (
        not providers
        or len({frozenset(value) for value in providers.values()}) != 1
        or not next(iter(providers.values()))
    ):
        raise ValueError("guarded interleave requires identical nonempty target participation")
    pieces: dict[str, Any] = {}
    guards: dict[str, tuple[str, str]] = {}
    for layout in layouts:
        if layout.stores:
            raise ValueError("guarded interleave cannot move file-scope storage")
        for piece in layout.functions:
            if not piece.rows:
                raise ValueError(f"{piece.name}: guarded interleave requires an active binding")
            if piece.name in pieces:
                prior = pieces[piece.name]
                if (
                    not shared
                    or prior.norm != piece.norm
                    or guards[piece.name] != wrappers[layout.rel]
                ):
                    raise ValueError(f"{piece.name}: duplicate or differently guarded definitions")
                prior.rows.extend(row for row in piece.rows if row not in prior.rows)
            else:
                pieces[piece.name] = piece
                guards[piece.name] = wrappers[layout.rel]
    graph: dict[str, set[str]] = {name: set() for name in pieces}
    modules: dict[str, list[tuple[int, str]]] = {}
    for name, piece in pieces.items():
        seen = set()
        for module, va, _file in piece.rows:
            if module in seen:
                raise ValueError(f"{name}: multiple addresses in one module are ambiguous")
            seen.add(module)
            modules.setdefault(module, []).append((va, name))
    for rows in modules.values():
        rows.sort()
        for (_, before), (_, after) in pairwise(rows):
            graph[after].add(before)
    try:
        order = list(TopologicalSorter(graph).static_order())
    except CycleError as exc:
        raise ValueError("guarded definitions have conflicting native orders") from exc
    return [(pieces[name], guards[name]) for name in order]
