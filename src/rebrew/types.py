"""types.py - Shared parsed C type model (structs, sizes, alignment).

Track 3 of the gap-analysis goal: struct layouts are recomputed by regex in
three places (name_decomp, binsync_export, struct_recover) with no shared
model.  This module parses struct definitions once via tree-sitter into
``StructDef`` (fields with offsets, total size, 32-bit MSVC alignment) and
sizes scalar/array/pointer type spellings.  Pure logic, no I/O.
"""

from dataclasses import dataclass, field
from typing import Any

_PRIMITIVE_SIZES: dict[str, int] = {
    "char": 1,
    "short": 2,
    "int": 4,
    "long": 4,
    "float": 4,
    "double": 8,
    "void": 0,
}


def _align_up(offset: int, align: int) -> int:
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
    if text.startswith("unsigned "):
        text = text[len("unsigned ") :]
    if text.startswith("signed "):
        text = text[len("signed ") :]
    if text.startswith("struct ") or text.startswith("union ") or text.startswith("enum "):
        struct_name = text.split(None, 1)[1].strip()
        if known_structs and struct_name in known_structs:
            return known_structs[struct_name].size
        return None
    if text in _PRIMITIVE_SIZES:
        return _PRIMITIVE_SIZES[text]
    if text.endswith("]"):
        base, _, count_text = text[:-1].rpartition("[")
        try:
            count = int(count_text.strip())
        except ValueError:
            return None
        base_size = type_size(base.strip(), known_structs)
        return None if base_size is None else base_size * count
    if known_structs and text in known_structs:
        return known_structs[text].size
    return None


def _field_text(node: Any, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _parse_field(decl: Any, source: bytes) -> tuple[str, str] | None:
    """Return ``(field name, type spelling)`` for a field_declaration node."""
    base_parts: list[str] = []
    name = ""
    suffix = ""
    for child in decl.children:
        if child.type == "field_identifier":
            name = _field_text(child, source)
        elif child.type == "pointer_declarator":
            inner = _field_text(child, source).lstrip("*").strip()
            name = inner
            suffix = " *"
        elif child.type == "array_declarator":
            raw = _field_text(child, source)
            ident = _field_text(
                next(c for c in child.children if c.type == "field_identifier"), source
            )
            name = ident
            suffix = raw[len(ident) :].strip()
        elif child.type not in (";", ","):
            base_parts.append(_field_text(child, source))
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
    from rebrew.c_parser import _parse

    tree, source = _parse(source_text)
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
    """Natural alignment: arrays align by element, scalars by size (cap 4, double 8)."""
    text = spelling.strip()
    if text.endswith("]"):
        base, _, _count = text[:-1].rpartition("[")
        base = base.strip()
        base_size = type_size(base, known)
        if base_size is None:
            return 1
        # An array aligns by its element: ``double arr[2]`` is 8-aligned, not
        # capped at 4 like a scalar 8-byte type would be.
        return _field_align(base, base_size, known)
    if text == "double":
        return 8
    return min(size, 4) if size else 1


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
    from rebrew.c_parser import _parse

    tree, source = _parse(source_text)

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
        name = source[ident.start_byte : ident.end_byte].decode("utf-8", errors="replace")
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
    before: str = source[:type_start].decode("utf-8", errors="replace")
    after: str = source[cut:].decode("utf-8", errors="replace")
    stripped = new_type.strip()
    if after.startswith("*"):
        stripped = stripped.rstrip("*").strip()
    return before + stripped + " " + after
