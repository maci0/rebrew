"""types.py - Shared parsed C type model (structs, sizes, alignment).

Track 3 of the gap-analysis goal: struct layouts are recomputed by regex in
three places (name_decomp, binsync.export, struct_recover) with no shared
model.  This module parses struct definitions once via tree-sitter into
``StructDef`` (fields with offsets, total size, 32-bit MSVC alignment) and
sizes scalar/array/pointer type spellings.  Pure logic, no I/O.
"""

from dataclasses import dataclass, field
from typing import Any

_PRIMITIVE_SIZES: dict[str, int] = {
    "char": 1,
    # 32-bit MSVC ``bool`` is 1 byte, the same width as ``char``.
    "bool": 1,
    "short": 2,
    "int": 4,
    "long": 4,
    "float": 4,
    "double": 8,
    # 32-bit MSVC: ``long long`` and ``__int64`` are 8 bytes.  ``unsigned``
    # and ``signed`` are stripped before this lookup.
    "long long": 8,
    "long long int": 8,
    "__int64": 8,
    # ``long double`` is 8 on 32-bit MSVC, the same width as ``double``.
    # ``short int`` / ``long int`` are the long forms of ``short`` / ``long``.
    "long double": 8,
    "short int": 2,
    "long int": 4,
    # 32-bit MSVC ``wchar_t`` is 2 bytes, the same width as an ``L`` string unit.
    "wchar_t": 2,
}

#: Scalars whose natural alignment is 8 on 32-bit MSVC (the same rule as
#: ``double``).  A 4-byte cap put ``long long`` at offset 4 after a ``char``.
_EIGHT_BYTE_ALIGNED = frozenset({"double", "long double", "long long", "long long int", "__int64"})


def _align_up(offset: int, align: int) -> int:
    # align <= 0 is not a valid natural alignment (negative field sizes used
    # to reach here and ``offset % align`` then moved the cursor backwards).
    if align <= 1:
        return offset
    remainder = offset % align
    return offset if remainder == 0 else offset + (align - remainder)


@dataclass
class StructDef:
    """One parsed struct: ordered ``(name, type, offset)`` fields + size."""

    name: str
    fields: list[tuple[str, str, int]] = field(default_factory=list)
    size: int = 0
    complete: bool = True


def type_size(spelling: str, known_structs: dict[str, StructDef] | None = None) -> int | None:
    """Size in bytes of a 32-bit MSVC type spelling, or None when unknown.

    Handles primitives, pointers (4), ``T[N]`` arrays, and known struct
    names via *known_structs*.  Struct/union/enum spellings without a
    definition, bitfields, and function pointers are unknown.
    """
    text = " ".join(spelling.strip().split())
    if not text:
        return None
    if text.endswith("*"):
        return 4
    text = text.removeprefix("unsigned ").removeprefix("signed ")
    if text.startswith(("struct ", "union ", "enum ")):
        struct_name = text.split(None, 1)[1].strip()
        if known_structs and struct_name in known_structs:
            return known_structs[struct_name].size
        return None
    if text == "void":
        # Incomplete type, never a struct field.  Size 0 would let the next
        # field share offset 0 (``typedef struct { void v; int x; }``).
        return None
    if text in _PRIMITIVE_SIZES:
        return _PRIMITIVE_SIZES[text]
    # ``T (*)[N]`` is one pointer. The bracket is the array it addresses,
    # not a dimension of this object. ``T *[N]`` has no ``(*)``.
    if _is_pointer_to_array(text):
        return 4
    if "[" in text or "(*" in text:
        from rebrew.c_parser import abstract_pointer_array_dimensions, array_type_shape

        # ``T (*[N])`` is N pointers. The brackets sit inside the
        # parentheses, so the array shape never saw a dimension.
        abstract = abstract_pointer_array_dimensions(text)
        if abstract:
            count = 1
            for bound in abstract:
                if not isinstance(bound, int) or bound < 0:
                    return None
                count *= bound
            return 4 * count
        if "[" not in text:
            return None
        base, dimensions = array_type_shape(text)
        if not dimensions:
            return None
        # Negative bounds are not valid C array sizes; accepting them made
        # ``char pad[-2]; int x;`` lay both fields at offset 0.  A hex, octal,
        # or constant-expression bound folds the same way estimate_type_size
        # does; ``int()`` read ``0x10`` as unknown and ``010`` as ten.
        count = 1
        for bound in dimensions:
            if not isinstance(bound, int) or bound < 0:
                return None
            count *= bound
        base_size = type_size(base, known_structs)
        return None if base_size is None else base_size * count
    if known_structs and text in known_structs:
        return known_structs[text].size
    return None


def _is_pointer_to_array(text: str) -> bool:
    """True when *text* is ``T (*)[N]`` or ``T (**)[N]``, not ``T *[N]``.

    A ``(*)`` inside a bound is not this object's declarator.
    """
    from rebrew.c_parser import is_pointer_to_array

    return is_pointer_to_array(text)


def _field_text(node: Any, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="surrogateescape")


_DECLARATOR_TYPES = frozenset(
    {
        "field_identifier",
        "pointer_declarator",
        "array_declarator",
        "parenthesized_declarator",
        "function_declarator",
    }
)


def _declarator_child(node: Any) -> Any | None:
    for child in node.children:
        if child.type in _DECLARATOR_TYPES:
            return child
    return None


def _array_bracket(node: Any, source: bytes) -> str | None:
    """The ``[N]`` that belongs to this array node, including a nested bound."""
    start = None
    end = None
    for child in node.children:
        if child.type == "[":
            start = child.start_byte
        elif child.type == "]" and start is not None and child.end_byte > start:
            end = child.end_byte
    if start is None or end is None:
        return None
    return source[start:end].decode("utf-8", errors="surrogateescape")


def _abstract_declarator(node: Any, source: bytes) -> tuple[str, str] | None:
    """``(name, suffix)`` so the field type is the base spelling plus *suffix*.

    Postfix ``[]`` binds tighter than prefix ``*``, unless parentheses say
    otherwise. ``*rows[4]`` is `` *[4]`` (an array of pointers). ``(*row)[4]``
    is `` (*)[4]`` (a pointer to an array). A function declarator stays unknown.
    """
    if node.type == "field_identifier":
        return _field_text(node, source), ""
    if node.type == "function_declarator":
        return None
    inner = _declarator_child(node)
    if inner is None:
        return None
    parsed = _abstract_declarator(inner, source)
    if parsed is None:
        return None
    name, suffix = parsed
    if node.type == "parenthesized_declarator":
        # ``(*row)[4]`` groups a pointer. ``(*table[4])`` does not: the
        # brackets are already inside, and wrapping them made ``int (*[4])``,
        # which has no size, so the following field was dropped.
        stars = suffix.replace(" ", "")
        if stars and set(stars) == {"*"}:
            return name, f" ({stars})"
        return name, suffix
    if node.type == "pointer_declarator":
        return name, " *" + suffix
    if node.type == "array_declarator":
        bracket = _array_bracket(node, source)
        if bracket is None:
            return None
        # ``(*table[2])[3]`` groups an array of pointers. Appending the
        # pointee bracket to `` *[2]`` spelled `` *[2][3]``, a grid of
        # pointers. ``(*row)[4]`` has no bracket inside the parentheses.
        inner = _declarator_child(node)
        grouped = suffix.replace(" ", "")
        if (
            inner is not None
            and inner.type == "parenthesized_declarator"
            and grouped.startswith("*")
            and "[" in grouped
        ):
            return name, f" ({grouped}){bracket}"
        # The node closest to the name holds the first source dimension.
        # ``grid[2][3][4]`` must stay ``[2][3][4]``, and ``(*)[4]`` keeps
        # the bracket after the parenthesized pointer.
        return name, suffix + bracket
    return None


def _parse_field(decl: Any, source: bytes) -> tuple[str, str] | None:
    """Return ``(field name, type spelling)`` for a field_declaration node."""
    base_parts: list[str] = []
    declarator = None
    for child in decl.children:
        if child.type in _DECLARATOR_TYPES:
            declarator = child
        elif child.type not in (";", ","):
            base_parts.append(_field_text(child, source))
    if declarator is None:
        return None
    if declarator.type == "field_identifier":
        name = _field_text(declarator, source)
        suffix = ""
    else:
        parsed = _abstract_declarator(declarator, source)
        if parsed is None:
            return None
        name, suffix = parsed
    if not name:
        return None
    spelling = " ".join(" ".join(base_parts).split()) + suffix
    spelling = " ".join(spelling.split())
    if not spelling:
        spelling = "void *"
    return name, spelling


def _struct_name(spec: Any, source: bytes) -> str:
    for child in spec.children:
        if child.type == "type_identifier":
            return _field_text(child, source)
    return ""


def parse_structs(source_text: str) -> dict[str, StructDef]:
    """Parse ``typedef struct {...} Name;`` and ``struct Tag {...};`` definitions.

    Returns ``{name: StructDef}`` with MSVC 32-bit field offsets (natural
    alignment, struct size padded to the max field alignment).  Fields whose
    type size is unknown (nested structs, bitfields, function pointers) end
    the parseable prefix — the struct keeps the fields before the gap with
    its size set to what is known so far.

    Layouts are built to a fixed point, so a field whose type is a struct
    declared LATER in the file resolves instead of truncating the layout.
    C forbids embedding cycles, so the pass count is bounded by the number
    of structs.
    """
    from rebrew.c_parser import parse_c_source

    tree, source = parse_c_source(source_text)
    bodies: dict[str, Any] = {}

    def collect(node: Any) -> None:
        if node.type == "struct_specifier":
            body = next((c for c in node.children if c.type == "field_declaration_list"), None)
            if body is not None:
                parent = node.parent
                name = ""
                if parent is not None and parent.type == "type_definition":
                    name = next(
                        (
                            _field_text(c, source)
                            for c in parent.children
                            if c.type == "type_identifier"
                        ),
                        "",
                    )
                if not name:
                    name = _struct_name(node, source)
                if name:
                    bodies.setdefault(name, body)
        for child in node.children:
            collect(child)

    collect(tree.root_node)

    def signature(defs: dict[str, StructDef]) -> dict[str, tuple[int, bool, tuple[Any, ...]]]:
        return {n: (d.size, d.complete, tuple(d.fields)) for n, d in defs.items()}

    structs: dict[str, StructDef] = {}
    for _ in range(len(bodies) + 1):
        updated = {
            name: _build_struct(name, body, source, structs) for name, body in bodies.items()
        }
        if signature(updated) == signature(structs):
            structs = updated
            break
        structs = updated
    return structs


def _build_struct(name: str, body: Any, source: bytes, known: dict[str, StructDef]) -> StructDef:
    """Lay out one struct_specifier body with natural alignment."""
    fields: list[tuple[str, str, int]] = []
    offset = 0
    max_align = 1
    complete = True
    for decl in body.children:
        if decl.type != "field_declaration":
            continue
        parsed = _parse_field(decl, source)
        if parsed is None:
            complete = False
            break
        field_name, spelling = parsed
        size = type_size(spelling, known)
        if size is None:
            complete = False
            break
        align = _field_align(spelling, size, known)
        offset = _align_up(offset, align)
        max_align = max(max_align, align)
        fields.append((field_name, spelling, offset))
        offset += size
    return StructDef(
        name=name,
        fields=fields,
        size=_align_up(offset, max_align) if fields else 0,
        complete=complete,
    )


def _field_align(spelling: str, size: int, known: dict[str, StructDef] | None) -> int:
    """Natural alignment: arrays align by element, scalars by size (cap 4).

    ``double``, ``long double``, ``long long``, and ``__int64`` align to 8
    on 32-bit MSVC.
    """
    text = " ".join(spelling.split())
    # A pointer to an array aligns as a pointer. The ``]`` is the pointee.
    if _is_pointer_to_array(text):
        return 4
    # ``T (*[N])`` and ``T (*[N])[M]`` are pointers. Peeling the pointee
    # bracket left ``T (*``, which has no size, so the field aligned to 1.
    from rebrew.c_parser import abstract_pointer_array_dimensions

    if abstract_pointer_array_dimensions(text):
        return 4
    if text.endswith("]"):
        base, _, _count = text[:-1].rpartition("[")
        base = base.strip()
        base_size = type_size(base, known)
        if base_size is None:
            return 1
        # An array aligns by its element: ``double arr[2]`` is 8-aligned, not
        # capped at 4 like a scalar 8-byte type would be.
        return _field_align(base, base_size, known)
    canon = text.removeprefix("unsigned ").removeprefix("signed ")
    if canon in _EIGHT_BYTE_ALIGNED:
        return 8
    # size <= 0 (flexible ``T[0]``, or a caller that slipped past type_size)
    # must not yield a negative align for ``_align_up``.
    return min(size, 4) if size > 0 else 1


def check_struct(
    declared: StructDef,
    evidence: dict[int, int],
    known_structs: dict[str, StructDef] | None = None,
) -> list[dict[str, object]]:
    """Validate *declared* field offsets against *evidence* (offset → width).

    Returns a list of findings; empty means the declaration covers every
    evidenced offset with a compatible width.  Each finding names the
    offset, the evidenced width, and what the declaration has there
    (``missing`` when no field covers it, ``width`` when the covering
    field is narrower).  Pass *known_structs* so a field whose type is
    another declared struct gets its real span instead of a zero-width one
    (which would report every read inside it as ``missing``).
    """
    findings: list[dict[str, object]] = []
    spans = [
        (off, off + (type_size(spelling, known_structs) or 0), name)
        for name, spelling, off in declared.fields
    ]
    for ev_off, ev_width in sorted(evidence.items()):
        cover = next(
            (name for start, end, name in spans if start <= ev_off < end),
            None,
        )
        if cover is None:
            findings.append({"offset": ev_off, "evidenced_width": ev_width, "issue": "missing"})
            continue
        start = next(s for s, _e, n in spans if n == cover)
        covered = next(e for s, e, n in spans if n == cover) - start
        if ev_off + ev_width > start + covered:
            findings.append(
                {
                    "offset": ev_off,
                    "evidenced_width": ev_width,
                    "issue": "width",
                    "field": cover,
                }
            )
    return findings


def rewrite_param_type(
    source_text: str, func_name: str, param_index: int, new_type: str
) -> str | None:
    """Rewrite one parameter's type in the named function definition.

    Returns the rewritten source, or None when the function or parameter
    is not found.  Only the type spelling of the indexed parameter is
    replaced (0-based); name, calling convention, and body are untouched.
    """
    from rebrew.c_parser import parse_c_source

    tree, source = parse_c_source(source_text)

    target: Any = None

    def visit(node: Any) -> None:
        nonlocal target
        if target is not None:
            return
        if node.type != "function_definition":
            for child in node.children:
                visit(child)
            return
        declarator = next((c for c in node.children if c.type == "function_declarator"), None)
        if declarator is None:
            return
        ident = next((c for c in declarator.children if c.type == "identifier"), None)
        if ident is None:
            return
        name = source[ident.start_byte : ident.end_byte].decode("utf-8", errors="surrogateescape")
        if name != func_name:
            return
        params = next((c for c in declarator.children if c.type == "parameter_list"), None)
        if params is None:
            return
        decls = [c for c in params.children if c.type == "parameter_declaration"]
        if 0 <= param_index < len(decls):
            target = decls[param_index]

    visit(tree.root_node)
    if target is None:
        return None

    children = target.children
    if not children:
        return None
    declarator_kinds = {
        "identifier",
        "pointer_declarator",
        "array_declarator",
        "function_declarator",
        "parenthesized_declarator",
    }
    cut = next(
        (c.start_byte for c in children if c.type in declarator_kinds),
        children[-1].end_byte,
    )
    type_start = children[0].start_byte
    if cut <= type_start:
        return None
    # Inverse of parse_c_source's surrogateescape encode: "replace" would turn every
    # legacy (cp1252/Shift-JIS) byte in the rewritten file into U+FFFD.
    before: str = source[:type_start].decode("utf-8", errors="surrogateescape")
    after: str = source[cut:].decode("utf-8", errors="surrogateescape")
    stripped = new_type.strip()
    if after.startswith("*"):
        stripped = stripped.rstrip("*").strip()
    return before + stripped + " " + after
