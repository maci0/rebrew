"""name_decomp.py — apply known struct names to decompiler output.

Decompilers (Kuna, Ghidra, ...) emit untyped pointers (``int a0``) with
cast-deref member access (``*(int *)(a0 + 0x14)``).  When the project
already declares a struct whose layout covers the accessed offsets, the
naming pass rewrites the decompilation to use it::

    unsigned int sub_1000d350(int a0)          ->  unsigned int sub_1000d350(command_s *a0)
    *(int *)(a0 + 0x14)                        ->  a0->field_14
    *(char *)(a0 + 0x10) == 1                  ->  a0->field_10 == 1
    sub_1000b1c0(a0 + 0x10)                    ->  sub_1000b1c0(&a0->field_10)
    *(unsigned int *)&v2[10]  (v2 = a0, short*) ->  v2->field_14   (array-index form)
    *(unsigned int *)&v2[0xA] (same offset)    ->  v2->field_14
    y = p[1] / z = &p[1]      (short *p)       ->  y = p->field / z = &p->field

This is the "feed the recovered structs back in" loop: ``rebrew types
recover`` recovers the layout as an anonymous candidate, the user
names the type (e.g. ``command_s``) in a header, and ``rebrew decompile
--named`` picks it up.  Matching is conservative: a variable is typed when
at least one of its accessed offsets is an exact (non-padding) field of a
declared struct and every access falls within the struct's span; offsets
that land in padding (``gap_*`` arrays) or on undeclared positions are
left as written.  ``vN = a0;`` aliases inherit the match, and the smallest
covering struct wins.  The pass never edits files — it only rewrites the
decompilation text.

Usage::

    rebrew decompile 0x1000d350 --named
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
lazy from pathlib import Path

import typer

from rebrew.cli import (
    DECOMPILER_NOT_AVAILABLE_KIND,
    TargetOption,
    console,
    error_exit,
    json_print,
    parse_va,
    require_config,
)
from rebrew.decompiler import BACKEND_HELP_CHOICES, complete_backends
lazy from rebrew.struct_recover import (
    PSEUDO_TYPES,
    TYPE_WIDTHS,
    StructEvidence,
    parse_decomp_for_structs,
    parse_member_index,
    pointer_element_widths,
    type_width,
)
lazy from rebrew.utils import (
    join_source_lines,  # noqa: F401
    parse_c_integer_literal,  # noqa: F401
    parse_int_literal,
    split_source_lines,  # noqa: F401
)

# ---------------------------------------------------------------------------
# Struct layout parsing
# ---------------------------------------------------------------------------


@dataclass
class FieldLayout:
    """Offsets of a declared struct, for matching + rewriting.

    ``complete`` is False when the body contained something the parser
    cannot size (bitfields, embedded structs, ...) — such structs are never
    matched, because a partial layout would mis-attribute offsets.
    """

    fields: dict[int, tuple[str, int]] = field(default_factory=dict)  # off → (name, width)
    size: int = 0
    complete: bool = True


def _struct_def_to_layout(struct: Any, pointer_width: int = 4) -> FieldLayout:
    """Convert a ``rebrew.types.StructDef`` into a ``FieldLayout``."""
    from rebrew.types import type_size

    lay = FieldLayout()
    lay.complete = struct.complete
    ordered = sorted(struct.fields, key=lambda f: f[2])
    for idx, (field_name, spelling, off) in enumerate(ordered):
        end = ordered[idx + 1][2] if idx + 1 < len(ordered) else struct.size
        width = type_size(spelling, pointer_width=pointer_width)
        lay.fields[off] = (field_name, width if width is not None else max(0, end - off))
    lay.size = struct.size
    return lay


def struct_field_layout(definition: str, pointer_width: int = 4) -> FieldLayout:
    """Compute packed ``{offset: (field_name, width)}`` for a typedef struct body.

    Delegates to :func:`rebrew.types.parse_structs` with ``packed=True``.
    Handles typed primitives, pointer fields (*pointer_width* bytes),
    explicit byte arrays, constant-expression bounds, and multi-dim arrays.
    Bitfields, embedded unknown ``struct`` members, or anything else unsized
    mark the layout ``complete = False`` so it is never matched against evidence.
    """
    from rebrew.types import parse_structs

    parsed = parse_structs(definition, packed=True, pointer_width=pointer_width)
    struct = next(iter(parsed.values()), None)
    if struct is None:
        return FieldLayout(complete=False)
    return _struct_def_to_layout(struct, pointer_width=pointer_width)


# A bound ``int()`` cannot size: hex, a constant expression, or a suffix.
# ``010`` stays on the aligned path; ``int()`` already accepted it.
# ``&``, ``|``, ``^``, ``(``, ``?``, ``=``, and ``'`` are in the class so
# ``gap[15 & 7]``, ``gap[(2)]``, ``gap[0 ? 8 : 2]``, ``gap[2 == 2]``, and
# ``gap['\\n']`` stay packed.  A plain ``char a; int b`` has none of these.
_C_BOUND_RE = re.compile(r"\[[^\]]*(?:0[xX]|[+*/%\-<>&|^(?=']|[uUlL])")


def struct_definitions_to_layouts(
    definitions: dict[str, str], pointer_width: int = 4
) -> dict[str, FieldLayout]:
    """Map struct name → parsed layout for every raw definition.

    Parses via the shared :mod:`rebrew.types` model (tree-sitter offsets
    with MSVC alignment); falls back to packed layout for decompiler structs
    whose bounds use hex/expressions/suffixes where natural alignment would
    move fields off the offsets their names and the decompiler both use.
    """
    from rebrew.types import parse_structs

    layouts: dict[str, FieldLayout] = {}
    for name, definition in definitions.items():
        packed = struct_field_layout(definition, pointer_width=pointer_width)
        parsed = parse_structs(definition, pointer_width=pointer_width)
        struct = parsed.get(name) or next(iter(parsed.values()), None)
        if struct is not None and struct.fields:
            lay = _struct_def_to_layout(struct, pointer_width=pointer_width)
            disagree = lay.complete and packed.complete and lay.fields != packed.fields
            if disagree and _C_BOUND_RE.search(definition):
                layouts[name] = packed
            else:
                layouts[name] = lay
        else:
            layouts[name] = packed
    return layouts


def _match_struct(var_offsets: set[int], layouts: dict[str, FieldLayout]) -> str | None:
    """Pick the smallest COMPLETE struct a variable's accesses plausibly use.

    Requires every evidence offset to fall within the struct's span AND at
    least one offset to be an exact, non-padding field start.  Offsets that
    fall inside padding (``gap_*`` arrays) are tolerated — decompilers emit
    misaligned reads — but are not rewritten.  Ties → alphabetically first.
    """
    candidates = [
        name
        for name, lay in layouts.items()
        if lay.complete
        and all(off < lay.size for off in var_offsets)
        and any(
            lay.fields.get(off) is not None and not lay.fields[off][0].startswith("gap_")
            for off in var_offsets
        )
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda n: (layouts[n].size, n))


# ---------------------------------------------------------------------------
# AST helpers + Rewriting
# ---------------------------------------------------------------------------

_CAST_INDEX_WIDTHS = {
    "char": 1,
    "signed char": 1,
    "unsigned char": 1,
    "short": 2,
    "unsigned short": 2,
    "int": 4,
    "unsigned int": 4,
}


def _unwrap_parens(node: Any) -> Any:
    while node is not None and node.type == "parenthesized_expression":
        inner = [c for c in node.named_children if c.type != "comment"]
        if len(inner) != 1:
            return node
        node = inner[0]
    return node


def _node_op(node: Any, data: bytes) -> str:
    from rebrew.c_parser import node_text

    op = node.child_by_field_name("operator")
    return node_text(op, data).strip() if op is not None else ""


def _specifier_type(node: Any, data: bytes) -> str:
    from rebrew.c_parser import node_text

    parts: list[str] = []
    for child in node.named_children:
        if child.type in ("primitive_type", "sized_type_specifier", "type_identifier"):
            parts.append(" ".join(node_text(child, data).split()))
        elif child.type in ("struct_specifier", "union_specifier", "enum_specifier"):
            tag = child.child_by_field_name("name")
            if tag is not None:
                parts.append(node_text(tag, data))
    return " ".join(parts)


def _cast_pointee(type_desc: Any, data: bytes) -> tuple[str, int] | None:
    base = _specifier_type(type_desc, data)
    if not base:
        return None
    decl = type_desc.child_by_field_name("declarator")
    stars = 0
    while decl is not None and decl.type == "abstract_pointer_declarator":
        stars += 1
        decl = decl.child_by_field_name("declarator")
    if stars == 0 or decl is not None:
        return None
    return (base, 1) if stars == 1 else (f"{base} {'*' * (stars - 1)}", stars)


def _parse_cast_index_subscript(sub_node: Any, data: bytes) -> tuple[str, str, int] | None:
    """Parse ``((T *)var)[idx]`` into ``(cast_type, var, idx_val)``, or None."""
    from rebrew.c_parser import node_text

    if sub_node.type != "subscript_expression":
        return None
    arg = _unwrap_parens(sub_node.child_by_field_name("argument"))
    idx_node = _unwrap_parens(sub_node.child_by_field_name("index"))
    if (
        arg is None
        or arg.type != "cast_expression"
        or idx_node is None
        or idx_node.type != "number_literal"
    ):
        return None
    type_desc = arg.child_by_field_name("type")
    val = _unwrap_parens(arg.child_by_field_name("value"))
    if type_desc is None or val is None or val.type != "identifier":
        return None
    cast_info = _cast_pointee(type_desc, data)
    if cast_info is None or cast_info[1] != 1:
        return None
    index = parse_member_index(node_text(idx_node, data))
    if index is None:
        return None
    return cast_info[0], node_text(val, data), index


def _pointer_vars(text: str) -> set[str]:
    """Vars with evidence of being a pointer: ``T *var`` decls/params,
    ``(T *)var`` casts, ``*(T *)(var + N)`` / ``*(T *)&var + N`` cast-derefs,
    ``*(T *)&var[i]`` derefs, ``var->field``, or ``var[i]`` index uses.

    The anonymous rewrite pass only renames these; a plain ``int`` used in
    ``var + N`` arithmetic has no such evidence and a bare ``var + N`` on it
    is integer math, not a member access.
    """
    from rebrew.c_parser import mask_msvc_syntax, node_text, parse_c_source

    tree, data = parse_c_source(mask_msvc_syntax(text))
    out: set[str] = set()
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        kind = node.type
        if kind in ("comment", "string_literal", "char_literal"):
            continue
        if kind in ("declaration", "parameter_declaration"):
            for decl in node.children_by_field_name("declarator"):
                if decl.type == "init_declarator":
                    decl = decl.child_by_field_name("declarator")
                if decl is not None and decl.type == "pointer_declarator":
                    inner = decl.child_by_field_name("declarator")
                    while inner is not None and inner.type == "pointer_declarator":
                        inner = inner.child_by_field_name("declarator")
                    if inner is not None and inner.type == "identifier":
                        out.add(node_text(inner, data))
        elif kind == "cast_expression":
            type_desc = node.child_by_field_name("type")
            if type_desc is not None and _cast_pointee(type_desc, data) is not None:
                val = _unwrap_parens(node.child_by_field_name("value"))
                if val is not None:
                    if val.type == "identifier":
                        out.add(node_text(val, data))
                    elif val.type == "pointer_expression" and _node_op(val, data) == "&":
                        inner = _unwrap_parens(val.child_by_field_name("argument"))
                        if inner is not None and inner.type == "identifier":
                            out.add(node_text(inner, data))
                        elif inner is not None and inner.type == "subscript_expression":
                            sub_arg = _unwrap_parens(inner.child_by_field_name("argument"))
                            if sub_arg is not None and sub_arg.type == "identifier":
                                out.add(node_text(sub_arg, data))
                    elif val.type == "binary_expression" and _node_op(val, data) == "+":
                        left = _unwrap_parens(val.child_by_field_name("left"))
                        right = _unwrap_parens(val.child_by_field_name("right"))
                        if (
                            left is not None
                            and left.type == "pointer_expression"
                            and _node_op(left, data) == "&"
                        ):
                            left = _unwrap_parens(left.child_by_field_name("argument"))
                        if (
                            left is not None
                            and left.type == "identifier"
                            and right is not None
                            and right.type == "number_literal"
                        ):
                            out.add(node_text(left, data))
                    elif val.type == "subscript_expression":
                        sub_arg = _unwrap_parens(val.child_by_field_name("argument"))
                        if sub_arg is not None and sub_arg.type == "identifier":
                            out.add(node_text(sub_arg, data))
        elif kind == "subscript_expression":
            sub_arg = _unwrap_parens(node.child_by_field_name("argument"))
            sub_idx = _unwrap_parens(node.child_by_field_name("index"))
            if (
                sub_arg is not None
                and sub_arg.type == "identifier"
                and sub_idx is not None
                and sub_idx.type == "number_literal"
            ):
                out.add(node_text(sub_arg, data))
        elif kind == "field_expression" and _node_op(node, data) == "->":
            arg = _unwrap_parens(node.child_by_field_name("argument"))
            if arg is not None and arg.type == "identifier":
                out.add(node_text(arg, data))
        stack.extend(reversed(node.named_children))
    return out


def _first_function_params(
    root: Any, data: bytes
) -> tuple[str | None, list[tuple[int, str, str, bool]]]:
    """Return ``(func_name, [(index, var_name, base_type, is_ptr), ...])`` for the first function."""
    from rebrew.c_parser import node_text

    fn_node: Any = None
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "function_definition":
            fn_node = node
            break
        stack.extend(reversed(node.named_children))
    if fn_node is None:
        return None, []

    decl = fn_node.child_by_field_name("declarator")
    while decl is not None and decl.type != "function_declarator":
        if decl.type == "pointer_declarator":
            decl = decl.child_by_field_name("declarator")
        elif decl.type == "parenthesized_declarator":
            inner = [c for c in decl.named_children if c.type != "comment"]
            decl = inner[0] if inner else None
        else:
            decl = None
    if decl is None:
        return None, []
    ident = next((c for c in decl.children if c.type == "identifier"), None)
    func_name = node_text(ident, data) if ident is not None else None
    params_node = decl.child_by_field_name("parameters")
    if params_node is None:
        return func_name, []

    params: list[tuple[int, str, str, bool]] = []
    param_decls = [c for c in params_node.children if c.type == "parameter_declaration"]
    for idx, pdecl in enumerate(param_decls):
        base = _specifier_type(pdecl, data)
        p_declarator = pdecl.child_by_field_name("declarator")
        is_ptr = False
        if p_declarator is not None and p_declarator.type == "pointer_declarator":
            is_ptr = True
            p_declarator = p_declarator.child_by_field_name("declarator")
        if p_declarator is not None and p_declarator.type == "identifier":
            params.append((idx, node_text(p_declarator, data), base, is_ptr))
    return func_name, params


def _is_primitive_base(base: str) -> bool:
    if base in TYPE_WIDTHS or base in PSEUDO_TYPES:
        return True
    last = base.rsplit(maxsplit=1)[-1] if base else ""
    return last in TYPE_WIDTHS or last in PSEUDO_TYPES


@dataclass
class NamingResult:
    """Rewritten code plus what the pass applied."""

    code: str
    applied: list[dict[str, Any]]  # {var, struct, offsets: [...]}


def apply_known_names(
    text: str, definitions: dict[str, str], pointer_width: int = 4
) -> NamingResult:
    """Rewrite *text* to use known structs for anonymous pointer variables.

    *definitions* maps struct name → raw ``typedef struct ...`` text (e.g.
    ``rebrew.struct_recover.existing_structs``).  *pointer_width* is the
    target's pointer size in bytes (4 for 32-bit, 2 for 16-bit, 8 for 64-bit).
    Returns the rewritten code and the list of ``{var, struct, offsets}``
    applications (empty when nothing matched).

    A variable is only rewritten when there is evidence it is a pointer:
    a ``T *var`` declaration/param, a ``(T *)var`` cast, or an array-index
    use (``var[i]``); a plain ``int`` variable with integer arithmetic
    (``a0 + 0x10`` where ``a0`` is never dereferenced as a pointer) is left
    alone, since a bare ``var + N`` is address arithmetic on an unknown base.
    """
    from rebrew.c_parser import mask_msvc_syntax, node_text, parse_c_source
    from rebrew.types import rewrite_param_type

    layouts = struct_definitions_to_layouts(definitions, pointer_width=pointer_width)
    elem_widths = pointer_element_widths(text)
    pointer_vars = _pointer_vars(text)

    # Anonymous pointer vars → evidence offsets (temps excluded already).
    # Only vars with pointer evidence are rewritten: a bare ``int`` loop
    # counter used in ``var + N`` address arithmetic must not be renamed.
    parsed = parse_decomp_for_structs(text, cast_index=False)

    masked = mask_msvc_syntax(text)
    tree, masked_bytes = parse_c_source(masked)
    raw_bytes = text.encode("utf-8", errors="surrogateescape")

    func_name, fn_params = _first_function_params(tree.root_node, raw_bytes)

    # Only rewrite cast-index parameters when no other use could change meaning
    # after the parameter's type changes from a primitive pointer to a struct.
    if pointer_width in (4, 8):
        ptr_params = {
            var for _idx, var, base, is_ptr in fn_params if is_ptr and _is_primitive_base(base)
        }
        if ptr_params:
            uses_by_var: dict[str, list[tuple[str, int]]] = {}
            ident_counts: dict[str, int] = {}
            stack = [tree.root_node]
            while stack:
                node = stack.pop()
                if node.type in ("comment", "string_literal", "char_literal"):
                    continue
                if node.type == "identifier":
                    ident = node_text(node, raw_bytes)
                    if ident in ptr_params:
                        ident_counts[ident] = ident_counts.get(ident, 0) + 1
                elif node.type == "subscript_expression":
                    ci = _parse_cast_index_subscript(node, raw_bytes)
                    if ci is not None and ci[1] in ptr_params:
                        uses_by_var.setdefault(ci[1], []).append((ci[0], ci[2]))
                stack.extend(reversed(node.named_children))
            for var in ptr_params:
                uses = uses_by_var.get(var, [])
                if ident_counts.get(var, 0) != len(uses) + 1:
                    continue
                for cast_type, index in uses:
                    width = _CAST_INDEX_WIDTHS.get(" ".join(cast_type.split()))
                    if width is not None and index * width < 0x1000000:
                        indexed_offsets = parsed.anonymous.setdefault(var, StructEvidence()).offsets
                        counts = indexed_offsets.setdefault(index * width, {})
                        counts[width] = counts.get(width, 0) + 1

    var_structs: dict[str, str] = {}
    for var, ev in parsed.anonymous.items():
        if var not in pointer_vars:
            continue
        struct = _match_struct(set(ev.offsets), layouts)
        if struct is not None:
            var_structs[var] = struct

    # ``vN = a0;`` aliases inherit the match (path-compressed chains).
    alias_of: dict[str, str] = {}
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in ("comment", "string_literal", "char_literal"):
            continue
        if node.type == "assignment_expression" and _node_op(node, raw_bytes) == "=":
            left = _unwrap_parens(node.child_by_field_name("left"))
            right = _unwrap_parens(node.child_by_field_name("right"))
            if (
                left is not None
                and left.type == "identifier"
                and right is not None
                and right.type == "identifier"
            ):
                alias_of.setdefault(node_text(left, raw_bytes), node_text(right, raw_bytes))
        stack.extend(reversed(node.named_children))
    for alias in list(alias_of):
        path: list[str] = []
        cur = alias
        while cur not in var_structs and cur in alias_of and cur not in path:
            path.append(cur)
            cur = alias_of[cur]
        src = var_structs.get(cur)
        if src is not None:
            for node_name in path:
                var_structs[node_name] = src

    if not var_structs:
        return NamingResult(code=text, applied=[])

    applied: list[dict[str, Any]] = []
    for var, struct in sorted(var_structs.items()):
        entry = parsed.anonymous.get(var)
        offsets = sorted(entry.offsets) if entry is not None else []
        applied.append({"var": var, "struct": struct, "offsets": [f"0x{o:x}" for o in offsets]})

    # Collect non-overlapping AST expression rewrites (outermost wins).
    edits: list[tuple[int, int, str]] = []

    def _collect_rewrites(node: Any) -> None:
        if node.type in ("comment", "string_literal", "char_literal"):
            return
        replacement = _rewrite_expr_node(
            node,
            raw_bytes,
            var_structs,
            layouts,
            elem_widths,
            pointer_vars,
            pointer_width,
        )
        if replacement is not None:
            edits.append((int(node.start_byte), int(node.end_byte), replacement))
            return
        for child in node.named_children:
            _collect_rewrites(child)

    _collect_rewrites(tree.root_node)

    out_bytes = bytearray(raw_bytes)
    for start, end, repl in sorted(edits, key=lambda item: item[0], reverse=True):
        out_bytes[start:end] = repl.encode("utf-8", errors="surrogateescape")
    code = bytes(out_bytes).decode("utf-8", errors="surrogateescape")

    # Rewrite matched parameter types in the function signature via types.rewrite_param_type.
    if func_name is not None:
        for idx, var, base, _is_ptr in fn_params:
            struct = var_structs.get(var)
            if struct is None or not _is_primitive_base(base):
                continue
            rewritten = rewrite_param_type(code, func_name, idx, f"{struct} *")
            if rewritten is not None:
                code = rewritten

    return NamingResult(code=code, applied=applied)


def _rewrite_expr_node(
    node: Any,
    data: bytes,
    var_structs: dict[str, str],
    layouts: dict[str, FieldLayout],
    elem_widths: dict[str, int],
    pointer_vars: set[str],
    pointer_width: int,
) -> str | None:
    """Return the rewritten C expression for *node*, or None to leave unchanged."""
    from rebrew.c_parser import node_text

    kind = node.type

    # 1. ``&((T *)var)[idx]`` or ``&var[idx]``
    if kind == "pointer_expression" and _node_op(node, data) == "&":
        inner = _unwrap_parens(node.child_by_field_name("argument"))
        if inner is not None and inner.type == "subscript_expression":
            ci = _parse_cast_index_subscript(inner, data)
            if ci is not None:
                cast_type, var, index = ci
                width = _CAST_INDEX_WIDTHS.get(" ".join(cast_type.split()))
                struct = var_structs.get(var)
                if pointer_width in (4, 8) and width is not None and struct is not None:
                    fld = layouts[struct].fields.get(index * width)
                    if fld is not None:
                        return f"({cast_type} *)&{var}->{fld[0]}"
            sub_arg = _unwrap_parens(inner.child_by_field_name("argument"))
            sub_idx = _unwrap_parens(inner.child_by_field_name("index"))
            if (
                sub_arg is not None
                and sub_arg.type == "identifier"
                and sub_idx is not None
                and sub_idx.type == "number_literal"
            ):
                var = node_text(sub_arg, data)
                struct = var_structs.get(var)
                elem = elem_widths.get(var)
                if struct is not None and elem is not None:
                    try:
                        index = parse_int_literal(node_text(sub_idx, data))
                    except ValueError:
                        return None
                    fld = layouts[struct].fields.get(index * elem)
                    if fld is not None:
                        name, width = fld
                        if elem == width:
                            return f"&{var}->{name}"
                        return f"({_elem_type(elem)} *)&{var}->{name}"
        return None

    # 2. ``*(T *)(var + N)`` or ``*(T *)&var[i]`` / ``*(T *)var[i]``
    if kind == "pointer_expression" and _node_op(node, data) == "*":
        cast_node = _unwrap_parens(node.child_by_field_name("argument"))
        if cast_node is None or cast_node.type != "cast_expression":
            return None
        type_desc = cast_node.child_by_field_name("type")
        if type_desc is None:
            return None
        cast_info = _cast_pointee(type_desc, data)
        if cast_info is None or cast_info[1] != 1:
            return None
        cast_type = cast_info[0]
        cast_w = type_width(cast_type)
        if cast_w is None:
            return None
        val = _unwrap_parens(cast_node.child_by_field_name("value"))
        if val is None:
            return None

        # ``*(T *)(var + N)``
        if val.type == "binary_expression" and _node_op(val, data) == "+":
            left = _unwrap_parens(val.child_by_field_name("left"))
            right = _unwrap_parens(val.child_by_field_name("right"))
            if (
                left is not None
                and left.type == "identifier"
                and right is not None
                and right.type == "number_literal"
            ):
                var = node_text(left, data)
                struct = var_structs.get(var)
                if struct is None:
                    return None
                try:
                    off = parse_int_literal(node_text(right, data))
                except ValueError:
                    return None
                fld = layouts[struct].fields.get(off)
                if fld is None:
                    return None
                name, width = fld
                return f"{var}->{name}" if cast_w == width else f"*({cast_type} *)&{var}->{name}"
            return None

        # ``*(T *)&var[i]`` / ``*(T *)var[i]``
        sub = val
        if sub.type == "pointer_expression" and _node_op(sub, data) == "&":
            sub = _unwrap_parens(sub.child_by_field_name("argument"))
        if sub is not None and sub.type == "subscript_expression":
            sub_arg = _unwrap_parens(sub.child_by_field_name("argument"))
            sub_idx = _unwrap_parens(sub.child_by_field_name("index"))
            if (
                sub_arg is not None
                and sub_arg.type == "identifier"
                and sub_idx is not None
                and sub_idx.type == "number_literal"
            ):
                var = node_text(sub_arg, data)
                struct = var_structs.get(var)
                elem = elem_widths.get(var)
                if struct is None or elem is None:
                    return None
                try:
                    index = parse_int_literal(node_text(sub_idx, data))
                except ValueError:
                    return None
                fld = layouts[struct].fields.get(index * elem)
                if fld is None:
                    return None
                name, width = fld
                return f"{var}->{name}" if cast_w == width else f"*({cast_type} *)&{var}->{name}"
        return None

    # 3. ``((T *)var)[idx]`` or bare ``var[idx]``
    if kind == "subscript_expression":
        ci = _parse_cast_index_subscript(node, data)
        if ci is not None:
            cast_type, var, index = ci
            width = _CAST_INDEX_WIDTHS.get(" ".join(cast_type.split()))
            struct = var_structs.get(var)
            if pointer_width in (4, 8) and width is not None and struct is not None:
                fld = layouts[struct].fields.get(index * width)
                if fld is not None:
                    return f"*(({cast_type} *)&{var}->{fld[0]})"
            return None
        sub_arg = _unwrap_parens(node.child_by_field_name("argument"))
        sub_idx = _unwrap_parens(node.child_by_field_name("index"))
        if (
            sub_arg is not None
            and sub_arg.type == "identifier"
            and sub_idx is not None
            and sub_idx.type == "number_literal"
        ):
            var = node_text(sub_arg, data)
            struct = var_structs.get(var)
            elem = elem_widths.get(var)
            if struct is None or elem is None:
                return None
            try:
                index = parse_int_literal(node_text(sub_idx, data))
            except ValueError:
                return None
            fld = layouts[struct].fields.get(index * elem)
            if fld is None:
                return None
            name, width = fld
            if elem == width:
                return f"{var}->{name}"
            return f"*({_elem_type(elem)} *)&{var}->{name}"
        return None

    # 4. Bare ``var + N`` (address arithmetic on a known pointer var)
    if kind == "binary_expression" and _node_op(node, data) == "+":
        left = _unwrap_parens(node.child_by_field_name("left"))
        right = _unwrap_parens(node.child_by_field_name("right"))
        if (
            left is not None
            and left.type == "identifier"
            and right is not None
            and right.type == "number_literal"
        ):
            var = node_text(left, data)
            if var not in pointer_vars:
                return None
            struct = var_structs.get(var)
            if struct is None:
                return None
            try:
                off = parse_int_literal(node_text(right, data))
            except ValueError:
                return None
            fld = layouts[struct].fields.get(off)
            if fld is None:
                return None
            return f"&{var}->{fld[0]}"
    return None


def _elem_type(elem_width: int) -> str:
    """C type spelling for an array element of width *elem_width*."""
    return {1: "char", 2: "short", 4: "int", 8: "double"}.get(elem_width, "int")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew decompile 0x10009310  # Decompile one function\n\n"
    "  rebrew decompile 0x10009310 --named  # Apply known struct and field names\n\n"
    "  # Pick a backend, machine-readable\n"
    "  rebrew decompile 0x10009310 --decompiler ghidra --json"
)

app = typer.Typer(
    help="Decompile a function, optionally applying known struct names.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    address: str = typer.Argument(..., metavar="va", help="Function VA (hex, e.g. 0x1000d350)"),
    decompiler: str = typer.Option(
        "kuna",
        "--decompiler",
        help=f"Decompiler backend: {BACKEND_HELP_CHOICES}",
        autocompletion=complete_backends,
    ),
    named: bool = typer.Option(False, "--named", help="Apply known struct names to the output"),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write decompilation to this file (default: stdout)",
        metavar="<path>",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Fetch one function's decompilation and print it (raw C, pipeable).

    --named additionally rewrites anonymous pointer variables to the
    project's declared structs (see module docstring); structs are read
    from the reversed sources and library_*.h headers.
    """
    cfg = require_config(target=target, json_mode=json_output)
    va = parse_va(address, json_mode=json_output)

    from rebrew.decompiler import (
        PACKAGED_BACKEND_MAP,
        REASON_TEXT,
        cli_backend_state,
        fetch_decompilation,
    )

    if decompiler in PACKAGED_BACKEND_MAP:
        state = cli_backend_state(decompiler)
        if state.reason is not None:
            error_exit(
                f"decompiler '{decompiler}' is not available here: {REASON_TEXT[state.reason]}",
                json_mode=json_output,
                kind=DECOMPILER_NOT_AVAILABLE_KIND,
            )
    code, backend = fetch_decompilation(decompiler, cfg.target_binary, va, cfg.root)
    if not code:
        error_exit(
            f"decompilation failed via '{decompiler}' for 0x{va:x} "
            f"(backend unavailable or unsupported address)",
            json_mode=json_output,
        )

    applied: list[dict[str, Any]] = []
    if named:
        from rebrew.source.discovery import iter_library_headers, iter_sources, scan_files
        from rebrew.struct_recover import existing_structs

        tree = scan_files(cfg.reversed_dir)
        sources = list(iter_sources(cfg.reversed_dir, cfg, scanned=tree))
        sources += list(iter_library_headers(cfg.reversed_dir, cfg, scanned=tree))
        try:
            definitions = existing_structs(sources)
        except ValueError as exc:
            error_exit(str(exc), json_mode=json_output)
        pointer_width = int(getattr(cfg, "pointer_size", 4) or 4)
        result = apply_known_names(code, definitions, pointer_width=pointer_width)
        code = result.code
        applied = result.applied
        if not json_output:
            for a in applied:
                console.print(
                    f"[dim]named {a['var']} → {a['struct']} ({len(a['offsets'])} offset(s))[/dim]"
                )

    if json_output:
        json_print(
            {
                "va": f"0x{va:x}",
                "backend": backend,
                "named": bool(applied),
                "applied": applied,
                "code": code,
            }
        )
        return

    if named and not applied:
        console.print("[dim]no known struct matched this function's pointer accesses[/dim]")
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(code if code.endswith("\n") else code + "\n", encoding="utf-8")
        console.print(f"  wrote {output}")
    else:
        print(code)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
