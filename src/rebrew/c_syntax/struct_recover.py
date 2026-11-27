"""struct_recover.py — recover struct definitions from decompiler output.

Decompilers (Kuna, Ghidra, r2ghidra, r2dec) emit member accesses at byte
offsets: ``this->field_8``, ``*(int *)(p + 0x10)``, ``(PlayerInfo *)p``
casts.  Collecting the offset → width evidence per named pointer base type
lets rebrew synthesize struct definitions the project can adopt — the
"recover more structs" workflow (e.g. for guild-rebrew's DieGildeAddOn
types).

Evidence sources parsed from decompiled C:

- ``->field_(0x)?N`` / ``->field_NNNN`` — Ghidra/Kuna-style auto-named
  members; the offset is the member name, the width defaults to 4 bytes
  (dword) because the name carries no width.
- ``*(T *)(p + 0xN)`` and ``*(T *)&p + 0xN`` — explicit casts; the
  width comes from *T* (int/undefined4/pointer → 4, short → 2, char → 1,
  double → 8, ...).  Offsets may be hex (``0x10``) or decimal (``3``) —
  decompilers disagree.
- ``*(T *)&p[10]`` / ``p[0x10]`` — Kuna and Ghidra index pointer params
  as arrays; the byte offset is index × element width of the declared
  base type.  The index is hex (``0x10``) or decimal (``010`` is ten).
- ``(T *)p`` casts and ``T *var`` declarations — they give the BASE TYPE a
  pointer is accessed through.

Named base types yield structs directly.  When a pointer has no usable type
(``int a0`` in Kuna output, Ghidra's ``undefined4 *param_1``) the offset
evidence is NOT lost: it is grouped by variable name as an *anonymous
candidate* (e.g. ``a0``), reported with its layout so the user can name the
type in Ghidra and re-run.  Candidates whose variable name is meaningful
(``pPlayer``, ``this``) get a synthesized type name with the Hungarian
pointer prefix stripped (``Player``); compiler temporaries (``v1``,
``local_8``, ``uVar2``) are noise and dropped.  Synthesized definitions
follow the guild convention::

    typedef struct name_s {
        int field_0;
        char gap_0004[0x10];
        ...
    } name;

The merge step compares against the project's existing structs (via
``rebrew.c_syntax.struct_parser``) and reports only NEW structs / new offsets beyond
the existing layout — never rewrites what is already declared.

Usage::

    rebrew types recover --all                      # every annotated function
    rebrew types recover --functions 0x401000,0x401100 --decompiler kuna
    rebrew types recover --all --output src/common.h  # append new typedefs
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
lazy from pathlib import Path
lazy from typing import Any

import typer

from rebrew.cli import (
    TargetOption,
    all_items_option,
    console,
    error_exit,
    json_print,
    option_default,
    require_config,
    require_non_negative,
)
from rebrew.decompiler import BACKEND_HELP_CHOICES, complete_backends
from rebrew.errors import RebrewError
lazy from rebrew.utils import atomic_write_text, fold_ident, parse_int_literal, read_source_text

# ---------------------------------------------------------------------------
# Evidence parsing
# ---------------------------------------------------------------------------

#: Ghidra/Kuna auto-named member suffix (``field_8`` / ``field_0x10`` / ``field_0008``).
_FIELD_OFFSET_RE = re.compile(r"\Afield_0?x?([0-9a-fA-F]+)\Z")

#: Pseudo-types that never name a recoverable struct.
PSEUDO_TYPES = frozenset(
    {
        "undefined",
        "undefined1",
        "undefined2",
        "undefined4",
        "undefined8",
        "byte",
        "word",
        "dword",
        "qword",
        "char",
        "short",
        "int",
        "long",
        "float",
        "double",
        "void",
        "bool",
        "uint",
        "ulong",
        "ushort",
        "uchar",
        "int8",
        "int16",
        "int32",
        "int64",
        "uint8",
        "uint16",
        "uint32",
        "uint64",
        "size_t",
        "BOOL",
        "DWORD",
        "WORD",
        "BYTE",
        "LONG",
        "wchar_t",
        "UINT",
        "ULONG",
    }
)

#: Cast type → access width in bytes.
TYPE_WIDTHS: dict[str, int] = {
    "char": 1,
    "bool": 1,
    "uchar": 1,
    "unsigned char": 1,
    "byte": 1,
    "uint8": 1,
    "uint8_t": 1,
    "short": 2,
    "wchar_t": 2,
    "ushort": 2,
    "unsigned short": 2,
    "word": 2,
    "uint16": 2,
    "uint16_t": 2,
    "int": 4,
    "uint": 4,
    "unsigned int": 4,
    "long": 4,
    "ulong": 4,
    "unsigned long": 4,
    "undefined4": 4,
    "dword": 4,
    "uint32": 4,
    "uint32_t": 4,
    "int32": 4,
    "int32_t": 4,
    "float": 4,
    "BOOL": 4,
    "DWORD": 4,
    "WORD": 2,
    "BYTE": 1,
    "LONG": 4,
    "UINT": 4,
    "ULONG": 4,
    "double": 8,
    "undefined8": 8,
    "qword": 8,
    "uint64": 8,
    "uint64_t": 8,
    "int64": 8,
    "int64_t": 8,
    "long long": 8,
    "long long int": 8,
    "unsigned long long": 8,
    "long double": 8,
    "short int": 2,
    "long int": 4,
}


#: Words that make a multi-word spelling a primitive (``long long``,
#: ``unsigned int``) rather than a struct name.
_PRIMITIVE_WORDS = frozenset(
    {"unsigned", "signed", "long", "short", "int", "char", "float", "double", "void", "bool"}
)


def _is_primitive_type(type_name: str) -> bool:
    """True when *type_name* is a primitive, not a recoverable struct base.

    A single word uses :data:`PSEUDO_TYPES`.  ``long long`` and
    ``unsigned int`` are primitive too: the declaration parser keeps those
    words together, and they must not become a struct named ``long long``.
    """
    if type_name in PSEUDO_TYPES:
        return True
    words = type_name.split()
    return len(words) > 1 and all(word in _PRIMITIVE_WORDS for word in words)


def _declared_width(type_name: str) -> int | None:
    """Element width of a pointer base, or None when it is not a known primitive.

    ``signed long`` is not its own row; stripping ``signed`` / ``unsigned``
    once reaches ``long`` (4) or ``long long`` (8).
    """
    width = TYPE_WIDTHS.get(type_name)
    if width is not None:
        return width
    rest = type_name.removeprefix("unsigned ").removeprefix("signed ")
    if rest != type_name:
        return TYPE_WIDTHS.get(rest)
    return None


def type_width(cast_type: str) -> int | None:
    """Width of *cast_type* when it is a primitive (None for named structs).

    Delegates to the shared :mod:`rebrew.c_syntax.types` model first (primitives,
    pointers, arrays); the decompiler-alias table below covers spellings
    the model does not know (``uint32_t``, ``undefined4``, Windows types).
    """
    from rebrew.c_syntax.types import type_size

    shared = type_size(cast_type.strip())
    if shared is not None:
        return shared
    t = cast_type.strip()
    if t in TYPE_WIDTHS:
        return TYPE_WIDTHS[t]
    return None


#: Compiler temporaries — never evidence of a struct base (Kuna ``v1``,
#: Ghidra ``local_8``/``uVar2``, r2ghidra ``var_10h``).
_TEMP_VAR_RE = re.compile(r"^(?:v\d+|(?:local|var)_[0-9a-fA-F_]+h?|[A-Za-z]{1,3}Var\d+)$")

#: Member offsets at or above this are absolute addresses (Kuna folds
#: ``global_base + index`` into ``var + 0xADDR``), not struct members.
_MAX_MEMBER_OFFSET = 0x1000000  # 16 MiB — far above any real x86-32 struct

#: Longest array-index token converted to evidence.  A nine-digit index is
#: already past ``_MAX_MEMBER_OFFSET`` at every element width, so the extra
#: digits only reach the literal parser — which rejects a run past CPython's
#: conversion limit with a bare ``ValueError``.
_MAX_INDEX_DIGITS = 8


def parse_member_index(text: str) -> int | None:
    """An array index as evidence, or ``None`` when it cannot be a member offset.

    Hex (``0x10``) and decimal (``16``, ``010``) follow
    :func:`rebrew.utils.parse_int_literal`: a leading zero is ten, matching
    the cast-deref offset parser.  ``int()`` rejected ``0x10``.  A token
    longer than ``_MAX_INDEX_DIGITS`` is not a member index.
    """
    if len(text) > _MAX_INDEX_DIGITS:
        return None
    try:
        value = parse_int_literal(text)
    except ValueError:
        return None
    if value < 0:
        return None
    return value


def _member_offset_cap(cfg: Any) -> int:
    """Member-offset cap for evidence parsing: image base, else the 16 MiB fallback.

    Offsets at or above the image base are absolute addresses (Kuna folds
    ``global_base + index`` into ``var + 0xADDR``).  When the binary cannot be
    read the base is unknown; the fallback still drops large globals, but a low
    absolute address (e.g. ``0x401000`` under a 4 MiB base) can slip through as
    a member, so the degradation warns instead of failing silently.
    """
    try:
        from rebrew.formats.binary_loader import load_binary

        base = load_binary(cfg.target_binary).image_base
        if base > 0:
            return base
    except (OSError, ValueError) as exc:
        console.print(
            f"[yellow]warning:[/yellow] cannot read {cfg.target_binary} ({exc}); "
            f"using the {_MAX_MEMBER_OFFSET:#x} member-offset cap — absolute "
            "addresses below it may appear as struct members"
        )
    return _MAX_MEMBER_OFFSET


def _unwrap_parens(node: Any) -> Any:
    """Strip surrounding ``parenthesized_expression`` nodes."""
    while node is not None and node.type == "parenthesized_expression":
        inner = [c for c in node.named_children if c.type != "comment"]
        if len(inner) != 1:
            return node
        node = inner[0]
    return node


def _specifier_type_text(node: Any, data: bytes) -> str:
    """Normalized base type text from a declaration / parameter / type_descriptor."""
    from rebrew.c_syntax.parser import node_text

    parts: list[str] = []
    for child in node.named_children:
        kind = child.type
        if kind in ("primitive_type", "sized_type_specifier", "type_identifier"):
            parts.append(" ".join(node_text(child, data).split()))
        elif kind in ("struct_specifier", "union_specifier", "enum_specifier"):
            tag = child.child_by_field_name("name")
            if tag is not None:
                parts.append(node_text(tag, data))
    return " ".join(parts)


def _pointer_cast_pointee(type_desc: Any, data: bytes) -> tuple[str, int] | None:
    """Return ``(pointee_type, star_count)`` for a pointer ``type_descriptor``."""
    base = _specifier_type_text(type_desc, data)
    if not base:
        return None
    decl = type_desc.child_by_field_name("declarator")
    stars = 0
    while decl is not None and decl.type == "abstract_pointer_declarator":
        stars += 1
        decl = decl.child_by_field_name("declarator")
    if stars == 0 or decl is not None:
        return None
    if stars == 1:
        return base, 1
    return f"{base} {'*' * (stars - 1)}", stars


def _single_pointer_decl_vars(node: Any, data: bytes) -> list[tuple[str, str]]:
    """Return ``[(base_type, var_name), ...]`` for plain ``T *var`` declarators."""
    from rebrew.c_syntax.parser import node_text

    base = _specifier_type_text(node, data)
    if not base:
        return []
    out: list[tuple[str, str]] = []
    for decl in node.children_by_field_name("declarator"):
        if decl.type == "init_declarator":
            decl = decl.child_by_field_name("declarator")
        if decl is None or decl.type != "pointer_declarator":
            continue
        inner = decl.child_by_field_name("declarator")
        if inner is not None and inner.type == "identifier":
            out.append((base, node_text(inner, data)))
    return out


def _parse_offset_literal(text: str) -> int | None:
    """Parse a non-negative hex or decimal offset literal safely."""
    stripped = text.strip()
    if not stripped or len(stripped) > 20:
        return None
    try:
        value = parse_int_literal(stripped)
    except ValueError:
        return None
    return value if value >= 0 else None


def _pointer_op(node: Any, data: bytes) -> str:
    """Return the unary operator (``*`` or ``&``) of a ``pointer_expression``."""
    from rebrew.c_syntax.parser import node_text

    op = node.child_by_field_name("operator")
    return node_text(op, data).strip() if op is not None else ""


def _binary_op(node: Any, data: bytes) -> str:
    """Return the operator text of a ``binary_expression``."""
    from rebrew.c_syntax.parser import node_text

    op = node.child_by_field_name("operator")
    return node_text(op, data).strip() if op is not None else ""


def pointer_element_widths(text: str) -> dict[str, int]:
    """Map pointer variables to their element width when the declared base
    type is a primitive (``short *a0`` → 2, ``char *s`` → 1).

    Kuna types struct pointers as primitive arrays (``short *a0``) and
    indexes them (``a0[10]``); the byte offset is index × element width.
    ``rebrew.c_syntax.name_decomp`` uses this to rewrite array-index accesses.
    """
    from rebrew.c_syntax.parser import mask_msvc_syntax, parse_c_source

    tree, data = parse_c_source(mask_msvc_syntax(text))
    out: dict[str, int] = {}
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in ("declaration", "parameter_declaration"):
            for base, var in _single_pointer_decl_vars(node, data):
                w = _declared_width(base)
                if w is not None:
                    out[var] = w
        stack.extend(reversed(node.named_children))
    return out


#: Variable names meaningful enough to synthesize a type name from:
#: ``this``/``self``/``it``, Hungarian ``pPlayer``/``lpData``, or any
#: camelCase with an uppercase transition (``playerInfo``).
_SEMANTIC_VAR_RE = re.compile(
    r"^(?:this|self|it|(?:p|lp)[A-Z][A-Za-z0-9_]*|[a-z]+[A-Z][A-Za-z0-9_]*)$"
)

#: Hungarian ``pX`` / ``lpX`` prefix (lookahead requires an uppercase letter).
_HUNGARIAN_PREFIX_RE = re.compile(r"^(?:lp|p)(?=[A-Z])")


def _type_name_from_var(var: str) -> str:
    """Strip a Hungarian pointer prefix (``pX`` / ``lpX``) from *var*."""
    m = _HUNGARIAN_PREFIX_RE.match(var)
    return var[m.end() :] if m else var


@dataclass
class StructEvidence:
    """Offset → (width, count) evidence for one named base type."""

    offsets: dict[int, dict[int, int]] = field(default_factory=dict)  # off → {width: count}


@dataclass
class ParseResult:
    """Evidence parsed from one decompilation.

    ``named`` maps a named base type to its offset evidence; ``anonymous``
    does the same for pointer variables whose type is unknown (keyed by
    variable name — callers merging across functions must re-key by
    ``(function, var)`` first, since bare names repeat across functions).
    """

    named: dict[str, StructEvidence] = field(default_factory=dict)
    anonymous: dict[str, StructEvidence] = field(default_factory=dict)


def parse_decomp_for_structs(
    text: str, max_offset: int = _MAX_MEMBER_OFFSET, *, cast_index: bool = True
) -> ParseResult:
    """Parse decompiled C into named + anonymous pointer evidence.

    The base type of a pointer is taken from its declaration/cast when it is
    a *named* type (not a pseudo-type); ``->field_N`` accesses and
    ``*(T *)(var + N)`` cast-derefs contribute offset/width evidence.  A
    type only yields evidence when its pointer appears BOTH in a
    declaration/cast AND with at least one member access — a bare
    declaration with no accesses tells us nothing about layout.

    Pointers with unknown or pseudo types are grouped by variable name into
    ``ParseResult.anonymous`` (compiler temporaries excluded); the caller
    decides what to synthesize from those.  *max_offset* filters out offsets
    that are really absolute addresses (pass the image base when known).
    *cast_index* reads ``((T *)p)[N]`` accesses; :func:`rebrew.c_syntax.name_decomp.apply_known_names`
    turns it off because it applies its own pointer-width gate to that form.
    """
    from rebrew.c_syntax.parser import mask_msvc_syntax, node_text, parse_c_source

    tree, data = parse_c_source(mask_msvc_syntax(text))
    named: dict[str, StructEvidence] = {}
    anonymous: dict[str, StructEvidence] = {}

    # var → declared/cast base type; a NAMED type always wins over a
    # pseudo-type so ``(PlayerInfo *)raw`` overrides ``void *raw``.
    var_types: dict[str, str] = {}

    def _set_var_type(var: str, t: str) -> None:
        if _is_primitive_type(t):
            var_types.setdefault(var, t)
        else:
            var_types[var] = t

    nodes: list[Any] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in ("comment", "string_literal", "char_literal"):
            continue
        nodes.append(node)
        stack.extend(reversed(node.named_children))

    # Pass 1: collect pointer declarations and pointer casts to establish var_types.
    for node in nodes:
        if node.type in ("declaration", "parameter_declaration"):
            for base, var in _single_pointer_decl_vars(node, data):
                _set_var_type(var, base)
        elif node.type == "cast_expression":
            type_desc = node.child_by_field_name("type")
            val = _unwrap_parens(node.child_by_field_name("value"))
            if type_desc is not None and val is not None and val.type == "identifier":
                cast_info = _pointer_cast_pointee(type_desc, data)
                if cast_info is not None and cast_info[1] == 1:
                    _set_var_type(node_text(val, data), cast_info[0])

    bases_with_pointers = {t for t in var_types.values() if not _is_primitive_type(t)}

    def _bump(container: dict[str, StructEvidence], base: str, offset: int, width: int) -> None:
        if offset < 0 or offset >= max_offset:
            return
        ent = container.setdefault(base, StructEvidence())
        slots = ent.offsets.setdefault(offset, {})
        slots[width] = slots.get(width, 0) + 1

    def _record(var: str | None, offset: int, width: int) -> None:
        """Attribute one access: to a named base type, or an anonymous var."""
        if var:
            base = var_types.get(var)
            if base is not None and not _is_primitive_type(base):
                _bump(named, base, offset, width)
                return
            if not _TEMP_VAR_RE.match(var):
                _bump(anonymous, var, offset, width)
            return
        # Var-less access (e.g. after a cast) — attribute to every named
        # base type known in this function (best approximation).
        for base in bases_with_pointers:
            _bump(named, base, offset, width)

    # Track subscript_expression nodes already consumed by ``*(T *)&var[idx]``
    # so bare ``var[idx]`` does not double-count them.
    consumed_subscripts: set[tuple[int, int]] = set()

    # Pass 2: walk expressions to gather member offset / width evidence.
    for node in nodes:
        kind = node.type

        if kind == "field_expression":
            op = node.child_by_field_name("operator")
            if op is None or node_text(op, data).strip() != "->":
                continue
            fld = node.child_by_field_name("field")
            if fld is None:
                continue
            m = _FIELD_OFFSET_RE.match(node_text(fld, data))
            if not m:
                continue
            off = int(m.group(1), 16)
            arg = _unwrap_parens(node.child_by_field_name("argument"))
            field_var: str | None = (
                node_text(arg, data) if arg is not None and arg.type == "identifier" else None
            )
            _record(field_var, off, 4)

        elif kind == "pointer_expression" and _pointer_op(node, data) == "*":
            cast_node = _unwrap_parens(node.child_by_field_name("argument"))
            if cast_node is None or cast_node.type != "cast_expression":
                continue
            type_desc = cast_node.child_by_field_name("type")
            if type_desc is None:
                continue
            cast_info = _pointer_cast_pointee(type_desc, data)
            if cast_info is None:
                continue
            width = type_width(cast_info[0])
            if width is None:
                continue
            val = _unwrap_parens(cast_node.child_by_field_name("value"))
            if val is None:
                continue

            # ``*(T *)(var + N)`` / ``*(T *)(&var + N)``
            if val.type == "binary_expression" and _binary_op(val, data) == "+":
                left = _unwrap_parens(val.child_by_field_name("left"))
                right = _unwrap_parens(val.child_by_field_name("right"))
                if (
                    left is not None
                    and left.type == "pointer_expression"
                    and _pointer_op(left, data) == "&"
                ):
                    left = _unwrap_parens(left.child_by_field_name("argument"))
                if (
                    left is not None
                    and left.type == "identifier"
                    and right is not None
                    and right.type == "number_literal"
                ):
                    parsed_off = _parse_offset_literal(node_text(right, data))
                    if parsed_off is not None:
                        _record(node_text(left, data), parsed_off, width)
                continue

            # ``*(T *)&var[idx]`` / ``*(T *)var[idx]``
            sub = val
            if sub.type == "pointer_expression" and _pointer_op(sub, data) == "&":
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
                    consumed_subscripts.add((int(sub.start_byte), int(sub.end_byte)))
                    var = node_text(sub_arg, data)
                    elem = _declared_width(var_types.get(var, ""))
                    index = parse_member_index(node_text(sub_idx, data))
                    if elem is not None and index is not None:
                        _record(var, index * elem, width)

        elif kind == "binary_expression" and _binary_op(node, data) == "+":
            # ``*(T *)&p + 0x8`` — in C precedence, ``+`` binds outside ``*``.
            left = _unwrap_parens(node.child_by_field_name("left"))
            right = _unwrap_parens(node.child_by_field_name("right"))
            if (
                left is not None
                and left.type == "pointer_expression"
                and _pointer_op(left, data) == "*"
                and right is not None
                and right.type == "number_literal"
            ):
                cast_node = _unwrap_parens(left.child_by_field_name("argument"))
                if cast_node is not None and cast_node.type == "cast_expression":
                    type_desc = cast_node.child_by_field_name("type")
                    val = _unwrap_parens(cast_node.child_by_field_name("value"))
                    if (
                        type_desc is not None
                        and val is not None
                        and val.type == "pointer_expression"
                        and _pointer_op(val, data) == "&"
                    ):
                        inner_var = _unwrap_parens(val.child_by_field_name("argument"))
                        cast_info = _pointer_cast_pointee(type_desc, data)
                        if (
                            inner_var is not None
                            and inner_var.type == "identifier"
                            and cast_info is not None
                        ):
                            width = type_width(cast_info[0])
                            parsed_off = _parse_offset_literal(node_text(right, data))
                            if width is not None and parsed_off is not None:
                                _record(node_text(inner_var, data), parsed_off, width)

    for node in nodes:
        if node.type != "subscript_expression":
            continue
        if (int(node.start_byte), int(node.end_byte)) in consumed_subscripts:
            continue
        sub_arg = _unwrap_parens(node.child_by_field_name("argument"))
        sub_idx = _unwrap_parens(node.child_by_field_name("index"))
        if sub_arg is None or sub_idx is None or sub_idx.type != "number_literal":
            continue
        index = parse_member_index(node_text(sub_idx, data))
        if index is None:
            continue
        # Bare ``var[idx]``
        if sub_arg.type == "identifier":
            var = node_text(sub_arg, data)
            elem = _declared_width(var_types.get(var, ""))
            if elem is not None:
                _record(var, index * elem, elem)
        # Cast-index ``((T *)var)[idx]``
        elif cast_index and sub_arg.type == "cast_expression":
            type_desc = sub_arg.child_by_field_name("type")
            val = _unwrap_parens(sub_arg.child_by_field_name("value"))
            if type_desc is not None and val is not None and val.type == "identifier":
                cast_info = _pointer_cast_pointee(type_desc, data)
                if cast_info is not None:
                    width = type_width(cast_info[0])
                    if width is not None:
                        _record(node_text(val, data), index * width, width)

    return ParseResult(named=named, anonymous=anonymous)


# ---------------------------------------------------------------------------
# Synthesis + merge
# ---------------------------------------------------------------------------


def majority_width(slots: dict[int, int]) -> int:
    """The most-observed width at an offset (ties → largest)."""
    best = max(slots, key=lambda w: (slots[w], int(w)))
    return int(best)


def synthesize_struct(name: str, offsets: dict[int, dict[int, int]]) -> str:
    """Render ``typedef struct name_s { ... } name;`` for *offsets*.

    Fields are emitted at their offsets with the majority width; gaps are
    ``char gap_XXXX[0xN];`` padding. Unaligned fields use byte arrays;
    overlapping evidence raises ValueError. The base
    is materialized from offset 0 via a gap when no evidence anchors it —
    never an invented field, which could overlap real evidence.
    """
    offsets = {int(k): v for k, v in offsets.items()}
    fields: list[str] = []
    prev_end = 0
    for offset, slots in sorted(offsets.items()):
        width = majority_width(slots)
        if offset < 0 or width <= 0:
            raise ValueError(f"{name}: invalid field evidence at offset {offset}, width {width}")
        if offset < prev_end:
            raise ValueError(f"{name}: overlapping field evidence at offset 0x{offset:x}")
        if offset > prev_end:
            fields.append(f"\tchar gap_{prev_end:04X}[0x{offset - prev_end:x}];")
        fields.append(_field_line(offset, width))
        prev_end = offset + width
    return f"typedef struct {name}_s {{\n" + "\n".join(fields) + f"\n}} {name};\n"


def _field_line(offset: int, width: int) -> str:
    """Render one field line.  Known widths get typed fields; everything
    else stays an opaque byte array (safe for C89)."""
    type_for = {1: "char", 2: "short", 4: "int", 8: "double"}
    t = type_for.get(width) if offset % width == 0 else None
    if t is None:
        return f"\tchar field_{offset:X}[0x{width:x}];"
    return f"\t{t} field_{offset:X};"


def existing_structs(sources: list[Path]) -> dict[str, str]:
    """Map existing struct name → raw definition text across *sources*."""
    from rebrew.c_syntax.parser import node_text, parse_c_source
    from rebrew.c_syntax.struct_parser import extract_structs_from_file

    out: dict[str, str] = {}
    for src in sources:
        try:
            definitions = list(extract_structs_from_file(src, strict=True))
        except OSError as exc:
            raise ValueError(f"cannot read struct source {src}: {exc}") from exc
        for definition in definitions:
            tree, raw = parse_c_source(definition)
            for node in tree.root_node.named_children:
                if node.type != "type_definition" or node.has_error:
                    continue
                specifier = node.child_by_field_name("type")
                if specifier is None or specifier.type != "struct_specifier":
                    continue
                for declarator in node.children_by_field_name("declarator"):
                    if declarator.type == "type_identifier":
                        out[node_text(declarator, raw)] = definition
    return out


def recover_structs(
    decompilations: list[tuple[int, str, str]],
    existing: dict[str, str] | None = None,
    max_offset: int = _MAX_MEMBER_OFFSET,
) -> list[dict[str, Any]]:
    """Aggregate evidence across decompilations and report recoverable structs.

    *decompilations* is ``[(va, symbol, decompiled_c), ...]``.  Returns a
    list of result dicts — one per named base type with offset evidence, plus
    one per anonymous pointer variable (``"anonymous": True``):

    - named: ``{"name", "anonymous": False, "new", "definition", "offsets",
      "evidence", "functions"}``; *new* = False when the project already
      declares a struct with that name (the definition is still offered, with
      only the new offsets called out when the existing layout is a prefix).
    - anonymous: ``{"name" (synthesized or the var), "anonymous": True,
      "semantic", "var", "va", "new", "definition", "offsets", "evidence",
      "functions"}``; *semantic* = True when the variable name was meaningful
      enough to derive a type name from.  Anonymous evidence is keyed by
      ``(va, var)`` — bare variable names (``a0``) repeat across functions and
      must never merge into one layout.
    """
    merged_named: dict[str, StructEvidence] = {}
    merged_anon: dict[tuple[int, str], tuple[StructEvidence, set[int]]] = {}
    for idx, (_va, _symbol, text) in enumerate(decompilations):
        parsed = parse_decomp_for_structs(text, max_offset=max_offset)
        for base, ev in parsed.named.items():
            if base not in merged_named:
                merged_named[base] = StructEvidence()
            for off, slots in ev.offsets.items():
                merged_named[base].offsets.setdefault(off, {})
                for w, c in slots.items():
                    merged_named[base].offsets[off][w] = (
                        merged_named[base].offsets[off].get(w, 0) + c
                    )
        for var, ev in parsed.anonymous.items():
            ent, funcs = merged_anon.setdefault((_va, var), (StructEvidence(), set()))
            for off, slots in ev.offsets.items():
                ent.offsets.setdefault(off, {})
                for w, c in slots.items():
                    ent.offsets[off][w] = ent.offsets[off].get(w, 0) + c
            funcs.add(idx)

    existing = existing or {}
    results: list[dict[str, Any]] = []
    for name, ev in sorted(merged_named.items()):
        if not ev.offsets:
            continue
        definition = synthesize_struct(name, ev.offsets)
        results.append(
            {
                "name": name,
                "anonymous": False,
                "new": existing.get(name) is None,
                "definition": definition,
                "offsets": [f"0x{o:x}" for o in sorted(ev.offsets)],
                "evidence": sum(sum(s.values()) for s in ev.offsets.values()),
            }
        )
    for (fn_va, var), (ev, funcs) in sorted(merged_anon.items()):
        if not ev.offsets:
            continue
        semantic = bool(_SEMANTIC_VAR_RE.match(var))
        type_name = _type_name_from_var(var) if semantic else var
        definition = synthesize_struct(type_name, ev.offsets)
        results.append(
            {
                "name": type_name,
                "anonymous": True,
                "semantic": semantic,
                "var": var,
                "va": fn_va,
                "new": existing.get(type_name) is None,
                "definition": definition,
                "offsets": [f"0x{o:x}" for o in sorted(ev.offsets)],
                "evidence": sum(sum(s.values()) for s in ev.offsets.values()),
                "functions": len(funcs),
            }
        )
    results.sort(key=lambda r: (r["new"], r["name"]))
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew types recover --functions 0x10009310\n\n"
    "  rebrew types recover --functions 0x10009310,0x10009400\n\n"
    "  rebrew types recover --all --output src/recovered_types.h --json\n\n"
    "[dim]Preview recovered typedefs by default. --output appends new definitions to a header; --dry-run previews that write.[/dim]"
)

app = typer.Typer(
    help="Recover struct definitions from decompiler output.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


def _collect_functions(
    cfg: Any,
    functions: str | None,
    all_funcs: bool,
    filter_substr: str | None,
) -> list[tuple[int, str]]:
    """Resolve the function set to decompile: explicit VAs, --all, or filtered.

    Raises ``ValueError`` for an unparseable VA, an empty selection, or
    conflicting selectors; the CLI turns either into ``error_exit``.
    """
    from rebrew.config import target_module
    from rebrew.metadata.bindings import read_source_bindings
    from rebrew.source.discovery import iter_sources

    if functions and (all_funcs or filter_substr):
        others: list[str] = []
        if all_funcs:
            others.append("--all")
        if filter_substr:
            others.append("--filter")
        raise ValueError(
            "--functions cannot be combined with " + " or ".join(others) + "; pass one selector"
        )

    if functions:
        out: list[tuple[int, str]] = []
        for tok in functions.split(","):
            tok = tok.strip()
            if not tok:
                continue
            try:
                va = parse_int_literal(tok, base=16)
            except ValueError:
                raise ValueError(f"Invalid hex VA: {tok!r}") from None
            out.append((va, f"0x{va:x}"))
        return out

    target_module_name = target_module(cfg)
    seen: set[int] = set()
    out = []
    metadata_dir = cfg.metadata_dir
    project_root = getattr(cfg, "root", None)
    from rebrew.metadata.functions import load_metadata

    function_entries = load_metadata(metadata_dir, deepcopy=False)
    for src in iter_sources(cfg.reversed_dir, cfg):
        annos = read_source_bindings(
            src,
            target_name=target_module_name,
            metadata_dir=metadata_dir,
            project_root=project_root,
            function_entries=function_entries,
        )
        for a in annos:
            if a.kind not in ("FUNCTION", "STUB", "LIBRARY"):
                continue
            if filter_substr and fold_ident(filter_substr) not in fold_ident(a.name or ""):
                continue
            if a.va in seen:
                continue
            seen.add(a.va)
            out.append((a.va, a.name or f"0x{a.va:x}"))
    if all_funcs is False and not functions and not out:
        raise ValueError("pass --functions VA,VA, --all, or --filter SUBSTR to select functions")
    return sorted(out)


class NoDecompilationError(RebrewError, RuntimeError):
    """The selected decompiler backend produced no output for any function."""


def recover_project_structs(
    cfg: Any,
    *,
    decompiler: str,
    functions: str | None = None,
    all_funcs: bool = False,
    filter_substr: str | None = None,
    limit: int | None = None,
    output: Path | None = None,
    dry_run: bool = False,
    json_output: bool = False,
) -> dict[str, Any]:
    """Decompile the selected functions and recover struct definitions.

    The same pipeline the ``rebrew types recover`` callback runs: resolve
    the function set (*functions* / *all_funcs* / *filter_substr*, capped by
    *limit*), decompile each via *decompiler*, aggregate the member-offset
    evidence against the project's existing structs, and — with *output* and
    without *dry_run* — append the new definitions to that file.  Returns the
    object the CLI prints under ``--json`` (``decompiled`` / ``skipped`` /
    ``structs`` / ``applied``), or ``{"functions": 0, "structs": []}`` when
    the selection is empty.  When *json_output* is false the human progress
    and "no functions selected" lines are printed like the CLI.

    Raises:
        ValueError: A VA in *functions* is unparseable, or no functions were
            selected (pass ``all_funcs=True`` to accept an empty set).
        NoDecompilationError: No backend returned code for any selected
            function (the CLI exits ``EXIT_ERROR`` with the same message).
    """
    funcs = _collect_functions(cfg, functions, all_funcs, filter_substr)
    if limit is not None:
        if limit < 0:
            raise ValueError("limit must be non-negative")
        funcs = funcs[:limit]
    if not funcs:
        if not json_output:
            console.print("[dim]No functions selected.[/dim]")
        return {"functions": 0, "structs": []}

    from rebrew.decompiler import fetch_decompilation

    decompilations: list[tuple[int, str, str]] = []
    skipped = 0
    if not json_output:
        console.print(f"[bold]Decompiling {len(funcs)} function(s) via {decompiler}...[/bold]")
    for va, name in funcs:
        code, backend = fetch_decompilation(decompiler, cfg.target_binary, va, cfg.root)
        if not code:
            skipped += 1
            continue
        decompilations.append((va, name, code))

    if not decompilations:
        raise NoDecompilationError(
            f"no decompilation obtained via '{decompiler}' ({skipped} function(s) skipped) — "
            "install the backend (kuna: github.com/Noelo-Lab/kuna; r2ghidra needs the "
            "ghidra plugin in rizin)"
        )

    # Existing structs in the project, for the merge report.  Library headers
    # are included too — name_decomp.py scans them and recover_structs must
    # agree, or its "new" structs would duplicate ones already defined.
    from rebrew.source.discovery import iter_library_headers, iter_sources, scan_files

    tree = scan_files(cfg.reversed_dir)
    sources = list(iter_sources(cfg.reversed_dir, cfg, scanned=tree))
    sources += list(iter_library_headers(cfg.reversed_dir, cfg, scanned=tree))
    # ``--output`` may point outside the source tree; without scanning it,
    # a second run would re-append the same typedefs (duplicate definitions).
    if output is not None and output.exists():
        apply_key = output.resolve()
        if apply_key not in {p.resolve() for p in sources}:
            sources.append(output)
    existing = existing_structs(sources)
    # Offsets ≥ the image base are absolute addresses (Kuna folds
    # global_base + index into ``var + 0xADDR``) — never member offsets.
    results = recover_structs(decompilations, existing=existing, max_offset=_member_offset_cap(cfg))

    # Anonymous candidates need a user-chosen name first — never auto-output.
    new_structs = [r for r in results if r["new"] and not r["anonymous"]]
    applied = str(output) if output and new_structs and not dry_run else None
    if output and new_structs and not dry_run:
        # Belt: skip names already present in the output target (partial writes).
        already = existing_structs([output]) if output.exists() else {}
        to_write = [r for r in new_structs if r["name"] not in already]
        if to_write:
            block = "\n\n".join(r["definition"] for r in to_write)
            # Rewrite atomically: a crash or a full disk mid-append would leave
            # a half-written typedef, and the dedup belt above would then skip
            # that name forever because it already registers as present.
            # Detected encoding, not utf-8: the output target is a source file
            # that may be Shift-JIS or CP1252, and a legacy byte in a comment
            # would raise UnicodeDecodeError instead of appending one typedef.
            previous, encoding = read_source_text(output) if output.is_file() else ("", "utf-8")
            atomic_write_text(output, previous + "\n" + block, encoding=encoding)
            console.print(f"[green]Appended {len(to_write)} struct(s) to {output}[/green]")
            applied = str(output)
        else:
            applied = None

    return {
        "decompiled": len(decompilations),
        "skipped": skipped,
        "structs": results,
        "applied": applied,
    }


@app.callback(invoke_without_command=True)
def main(
    functions: str | None = typer.Option(
        None,
        "--functions",
        help="Comma-separated VAs to decompile. Excludes --all and --filter",
    ),
    all_funcs: bool = all_items_option("function bound in metadata"),
    filter_substr: str | None = typer.Option(
        None,
        "--filter",
        help="Only functions whose name contains SUBSTR. Excludes --functions",
    ),
    decompiler: str = typer.Option(
        "kuna",
        "--decompiler",
        help=f"Decompiler backend: {BACKEND_HELP_CHOICES}",
        autocompletion=complete_backends,
    ),
    limit: int | None = typer.Option(
        None, "--limit", help="Cap functions decompiled (default: unlimited; 0 = none)"
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Append recovered definitions to this header; required with --dry-run",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Recover struct definitions by decompiling functions and aggregating their member-access offsets per named pointer type."""
    if option_default(dry_run, False) and option_default(output, None) is None:
        error_exit("--dry-run requires --output", json_mode=option_default(json_output, False))
    limit = option_default(limit, None)
    if limit is not None:
        limit = require_non_negative(limit, "--limit", json_mode=json_output)
    cfg = require_config(target=target, json_mode=json_output)

    try:
        payload = recover_project_structs(
            cfg,
            decompiler=decompiler,
            functions=functions,
            all_funcs=all_funcs,
            filter_substr=filter_substr,
            limit=limit,
            output=output,
            dry_run=dry_run,
            json_output=json_output,
        )
    except ValueError as exc:
        error_exit(str(exc), json_mode=json_output)
    except NoDecompilationError as exc:
        error_exit(str(exc), json_mode=json_output)

    if json_output:
        json_print(payload)
        return

    if "functions" in payload:
        return  # recover_project_structs printed the "No functions selected." note

    results = payload["structs"]
    new_structs = [r for r in results if r["new"] and not r["anonymous"]]
    console.print(
        f"\n[bold]{len(results)} recoverable struct(s)[/bold] "
        f"(from {payload['decompiled']} decompiled function(s), {payload['skipped']} skipped):\n"
    )
    for r in results:
        if r["anonymous"]:
            hint = (
                "synthesized from var name — rename in Ghidra to stabilize"
                if r["semantic"]
                else "unnamed pointer — name the type in Ghidra, then re-run to synthesize"
            )
            console.print(
                f"[yellow]ANON[/yellow] {r['name']} (var {r['var']}) — "
                f"{len(r['offsets'])} offset(s), {r['evidence']} evidence, "
                f"{r['functions']} function(s)"
            )
            console.print(f"[dim]  {hint}[/dim]")
            console.print(r["definition"])
            continue
        tag = "[green]NEW[/green]" if r["new"] else "[dim]existing[/dim]"
        console.print(
            f"{tag} {r['name']} — {len(r['offsets'])} offset(s), {r['evidence']} evidence"
        )
        console.print(r["definition"])
    if dry_run and new_structs:
        console.print(
            f"[dim]--dry-run: {len(new_structs)} new struct(s) would be appended to {output}[/dim]"
        )
    if not new_structs and results and not any(r["anonymous"] for r in results):
        console.print("[dim]No NEW structs — the recovered layouts are already declared.[/dim]")


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
