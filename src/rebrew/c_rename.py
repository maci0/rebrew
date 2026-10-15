"""c_rename.py - Syntax-aware occurrences of a C name for ``rebrew source rename``.

Every whole-word occurrence of a name is classified by the tree-sitter node
that holds it, so a rename rewrites only the namespace it targets:

- ordinary identifiers (functions, globals, typedef names),
- type names (typedef names and struct/union/enum tags),
- the members of one struct or union, resolved through declarations, casts,
  subscripts, member chains and ``offsetof``.

String and character literals are never rewritten. Comments are rewritten
only on request. Macro bodies are raw text to the parser; an occurrence there
counts as code unless it sits in a literal or follows ``->`` / ``.``.

All offsets are UTF-8 byte offsets into the source, as tree-sitter reports
them.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from rebrew.c_parser import find_function_name_in_node, mask_msvc_syntax, parse_c_source

# ---------------------------------------------------------------------------
# Occurrence roles
# ---------------------------------------------------------------------------

#: An ordinary identifier in code (call, reference, declarator).
ROLE_IDENT = "ident"
#: A ``type_identifier`` outside a struct/union/enum tag position.
ROLE_TYPENAME = "typename"
#: A struct/union/enum tag (``struct NAME``).
ROLE_TAG = "tag"
#: A member name (``field_identifier``).
ROLE_MEMBER = "member"
#: A goto label.
ROLE_LABEL = "label"
#: Inside a string or character literal.
ROLE_LITERAL = "literal"
#: Inside a comment.
ROLE_COMMENT = "comment"
#: The name of a ``#define``.
ROLE_MACRO_NAME = "macro_name"
#: A macro parameter, or a body occurrence of one.
ROLE_MACRO_PARAM = "macro_param"
#: Code inside a macro body.
ROLE_MACRO = "macro"
#: A member access (``->NAME`` / ``.NAME``) inside a macro body.
ROLE_MACRO_MEMBER = "macro_member"
#: A token span tree-sitter did not split as one name (``$SG123``).
ROLE_CODE = "code"

#: Roles an ordinary (function / global) rename rewrites.
ORDINARY_ROLES = frozenset({ROLE_IDENT, ROLE_TYPENAME, ROLE_MACRO, ROLE_CODE})

_LITERAL_TYPES = frozenset(
    {"string_literal", "char_literal", "system_lib_string", "concatenated_string"}
)
_TAG_PARENTS = frozenset({"struct_specifier", "union_specifier", "enum_specifier"})
_RECORD_SPECIFIERS = frozenset({"struct_specifier", "union_specifier"})
_DECLARATOR_WRAPPERS = frozenset(
    {
        "pointer_declarator",
        "array_declarator",
        "function_declarator",
        "parenthesized_declarator",
        "init_declarator",
        "attributed_declarator",
    }
)
_DECLARATION_OWNERS = frozenset(
    {"declaration", "parameter_declaration", "function_definition", "type_definition"}
)
_MEMBER_ACCESS_RE = re.compile(rb"(?:->|\.)\s*$")
_NAMED_MEMBER_ACCESS_RE = re.compile(rb"([A-Za-z_][A-Za-z0-9_]*)\s*(?:->|\.)\s*$")
_WORD_BYTES = rb"A-Za-z0-9_$\x80-\xff"


def name_regex(name: str) -> re.Pattern[bytes]:
    """Whole-word byte pattern for *name*; ``$`` and non-ASCII bytes are word bytes."""
    escaped = re.escape(name.encode("utf-8", errors="surrogateescape"))
    return re.compile(rb"(?<![" + _WORD_BYTES + rb"])" + escaped + rb"(?![" + _WORD_BYTES + rb"])")


@dataclass(frozen=True)
class Occurrence:
    """One whole-word occurrence of a name and the role the parser gives it."""

    start: int
    end: int
    line: int
    column: int
    role: str


@dataclass
class ParsedSource:
    """A source text with its tree, parsed once per rename."""

    text: str
    data: bytes
    tree: Any

    @classmethod
    def parse(cls, text: str) -> ParsedSource:
        """Parse *text* with MSVC extensions blanked; offsets address *text* itself."""
        tree, _masked = parse_c_source(mask_msvc_syntax(text))
        return cls(text=text, data=text.encode("utf-8", errors="surrogateescape"), tree=tree)

    def node_text(self, node: Any) -> str:
        return self.data[node.start_byte : node.end_byte].decode("utf-8", errors="surrogateescape")

    def line_col(self, offset: int) -> tuple[int, int]:
        line_start = self.data.rfind(b"\n", 0, offset) + 1
        line = self.data.count(b"\n", 0, offset) + 1
        return line, len(self.data[line_start:offset].decode("utf-8", errors="replace")) + 1


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def _ancestors(node: Any) -> Iterator[Any]:
    while node is not None:
        yield node
        node = node.parent


def _is_field(parent: Any, field_name: str, node: Any) -> bool:
    child = parent.child_by_field_name(field_name)
    return child is not None and child.start_byte == node.start_byte and child.type == node.type


def _macro_role(src: ParsedSource, arg: Any, start: int, end: int, name: str) -> str:
    """Role of an occurrence inside a ``preproc_arg`` (raw macro body text)."""
    definition = arg.parent
    if definition is not None and definition.type == "preproc_function_def":
        params = definition.child_by_field_name("parameters")
        if params is not None and any(
            child.type == "identifier" and src.node_text(child) == name for child in params.children
        ):
            return ROLE_MACRO_PARAM
    body = src.data[arg.start_byte : arg.end_byte]
    sub = ParsedSource.parse(body.decode("utf-8", errors="surrogateescape"))
    rel_start, rel_end = start - arg.start_byte, end - arg.start_byte
    node = sub.tree.root_node.descendant_for_byte_range(rel_start, rel_end)
    for ancestor in _ancestors(node):
        if ancestor.type == "comment":
            return ROLE_COMMENT
        if ancestor.type in _LITERAL_TYPES:
            return ROLE_LITERAL
    if _MEMBER_ACCESS_RE.search(body[:rel_start]):
        return ROLE_MACRO_MEMBER
    return ROLE_MACRO


def classify(src: ParsedSource, start: int, end: int, name: str) -> str:
    """Role of the occurrence of *name* at bytes ``[start, end)``."""
    node = src.tree.root_node.descendant_for_byte_range(start, end)
    for ancestor in _ancestors(node):
        if ancestor.type == "comment":
            return ROLE_COMMENT
        if ancestor.type in _LITERAL_TYPES:
            return ROLE_LITERAL
        if ancestor.type == "preproc_arg":
            return _macro_role(src, ancestor, start, end, name)
    if node is None or node.start_byte != start or node.end_byte != end:
        return ROLE_CODE
    parent = node.parent
    parent_type = parent.type if parent is not None else ""
    if node.type == "identifier":
        if parent_type in ("preproc_def", "preproc_function_def") and _is_field(
            parent, "name", node
        ):
            return ROLE_MACRO_NAME
        if parent_type == "preproc_params":
            return ROLE_MACRO_PARAM
        return ROLE_IDENT
    if node.type == "type_identifier":
        return ROLE_TAG if parent_type in _TAG_PARENTS else ROLE_TYPENAME
    if node.type == "field_identifier":
        return ROLE_MEMBER
    if node.type == "statement_identifier":
        return ROLE_LABEL
    return ROLE_CODE


def occurrences(src: ParsedSource, name: str) -> list[Occurrence]:
    """Every whole-word occurrence of *name* in *src*, classified."""
    out: list[Occurrence] = []
    for match in name_regex(name).finditer(src.data):
        start, end = match.span()
        line, column = src.line_col(start)
        out.append(Occurrence(start, end, line, column, classify(src, start, end, name)))
    return out


def rewrite(src: ParsedSource, spans: list[tuple[int, int]], new_name: str) -> str:
    """*src* text with every byte span in *spans* replaced by *new_name*."""
    replacement = new_name.encode("utf-8", errors="surrogateescape")
    out: list[bytes] = []
    pos = 0
    for start, end in sorted(spans):
        out.append(src.data[pos:start])
        out.append(replacement)
        pos = end
    out.append(src.data[pos:])
    return b"".join(out).decode("utf-8", errors="surrogateescape")


# ---------------------------------------------------------------------------
# Declarations
# ---------------------------------------------------------------------------


def declarator_name(node: Any, src: ParsedSource) -> str | None:
    """Name a declarator declares, descending through pointer/array/function wrappers."""
    while node is not None:
        if node.type == "function_declarator":
            return find_function_name_in_node(node, src.data)
        if node.type in ("identifier", "field_identifier", "type_identifier"):
            return src.node_text(node)
        if node.type == "parenthesized_declarator":
            node = next((c for c in node.named_children if c.type != "comment"), None)
            continue
        if node.type not in _DECLARATOR_WRAPPERS:
            return None
        node = node.child_by_field_name("declarator")
    return None


def _declares_function(node: Any) -> bool:
    """True when the wrapper nearest the name declares a function, not a pointer."""
    function = False
    while node is not None:
        if node.type == "function_declarator":
            function = True
        elif node.type in ("pointer_declarator", "array_declarator"):
            function = False
        if node.type == "parenthesized_declarator":
            node = next((c for c in node.named_children if c.type != "comment"), None)
            continue
        if node.type not in _DECLARATOR_WRAPPERS:
            break
        node = node.child_by_field_name("declarator")
    return function


def _storage_classes(node: Any, src: ParsedSource) -> set[str]:
    return {src.node_text(c) for c in node.children if c.type == "storage_class_specifier"}


def _at_file_scope(node: Any) -> bool:
    parent = node.parent
    while parent is not None:
        if parent.type in ("function_definition", "compound_statement", "struct_specifier"):
            return False
        if parent.type == "translation_unit":
            return True
        parent = parent.parent
    return False


def is_declarator(node: Any) -> bool:
    """True when *node* is the name a declaration, parameter or definition declares."""
    child = node
    parent = node.parent
    while parent is not None and parent.type in _DECLARATOR_WRAPPERS:
        if not _is_field(parent, "declarator", child):
            return False
        child, parent = parent, parent.parent
    return (
        parent is not None
        and parent.type in _DECLARATION_OWNERS
        and _is_field(parent, "declarator", child)
    )


@dataclass(frozen=True)
class Definition:
    """A file-scope definition of an ordinary name."""

    kind: str  # "function" or "variable"
    static: bool
    line: int


def _walk(node: Any) -> Iterator[Any]:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def definitions(src: ParsedSource, name: str) -> list[Definition]:
    """File-scope function and variable definitions of *name* in *src*.

    ``extern`` declarations and prototypes are declarations, not definitions.
    """
    found: list[Definition] = []
    if not name_regex(name).search(src.data):
        return found
    for node in _walk(src.tree.root_node):
        if node.type == "function_definition":
            declarator = node.child_by_field_name("declarator")
            if declarator_name(declarator, src) == name:
                found.append(
                    Definition(
                        "function",
                        "static" in _storage_classes(node, src),
                        src.line_col(node.start_byte)[0],
                    )
                )
        elif node.type == "declaration" and _at_file_scope(node):
            storage = _storage_classes(node, src)
            for declarator in node.children_by_field_name("declarator"):
                if "extern" in storage and declarator.type != "init_declarator":
                    continue
                if _declares_function(declarator):
                    continue
                if declarator_name(declarator, src) == name:
                    found.append(
                        Definition(
                            "variable", "static" in storage, src.line_col(node.start_byte)[0]
                        )
                    )
    return found


def declares_ordinary(src: ParsedSource, name: str) -> list[int]:
    """Lines where *name* is declared as a function, variable or parameter."""
    lines: list[int] = []
    for occ in occurrences(src, name):
        if occ.role != ROLE_IDENT:
            continue
        node = src.tree.root_node.descendant_for_byte_range(occ.start, occ.end)
        if is_declarator(node):
            owner = node.parent
            while owner is not None and owner.type in _DECLARATOR_WRAPPERS:
                owner = owner.parent
            if owner is not None and owner.type != "type_definition":
                lines.append(occ.line)
    return lines


def non_external_function_declarations(src: ParsedSource, name: str) -> list[int]:
    """Lines declaring *name* as anything except an external function, at any scope."""
    return [
        src.line_col(declarator.start_byte)[0]
        for node in _walk(src.tree.root_node)
        if node.type in ("declaration", "parameter_declaration", "type_definition")
        for declarator in node.children_by_field_name("declarator")
        if declarator_name(declarator, src) == name
        and (
            node.type == "type_definition"
            or not _declares_function(declarator)
            or "static" in _storage_classes(node, src)
        )
    ]


# ---------------------------------------------------------------------------
# Types and struct members
# ---------------------------------------------------------------------------


def type_token(type_node: Any, src: ParsedSource, anon_key: Callable[[Any], str]) -> str | None:
    """Canonical token for a declaration's type specifier.

    ``tag:NAME`` for a struct/union/enum tag, ``typedef:NAME`` for a typedef
    name, the anonymous record's key for ``struct { ... }``, else ``None``.
    """
    if type_node is None:
        return None
    if type_node.type in _TAG_PARENTS:
        tag = type_node.child_by_field_name("name")
        if tag is not None:
            return f"tag:{src.node_text(tag)}"
        return anon_key(type_node) if type_node.type in _RECORD_SPECIFIERS else None
    if type_node.type == "type_identifier":
        return f"typedef:{src.node_text(type_node)}"
    return None


@dataclass
class TypeIndex:
    """Struct/union definitions and typedefs of a project, for member resolution."""

    #: Record key -> member name -> member type token.
    members: dict[str, dict[str, str | None]] = field(default_factory=dict)
    #: Typedef name -> token of its underlying type (first definition seen).
    typedefs: dict[str, str | None] = field(default_factory=dict)
    #: (path, typedef name) -> token, for files that define their own copy.
    local_typedefs: dict[tuple[str, str], str | None] = field(default_factory=dict)
    #: Tags and typedef names that name a type anywhere.
    type_names: set[str] = field(default_factory=set)
    #: Typedef names (ordinary namespace).
    typedef_names: set[str] = field(default_factory=set)
    #: Record key -> (path, line) of each definition.
    sites: dict[str, list[tuple[str, int]]] = field(default_factory=dict)

    def resolve(self, token: str | None, path: str | None = None) -> str | None:
        """Record key a token names, following typedef chains.

        A typedef defined in *path* itself wins over another file's
        definition of the same name.
        """
        seen: set[str] = set()
        while token is not None and token.startswith("typedef:"):
            alias = token.split(":", 1)[1]
            if alias in seen:
                return None
            seen.add(alias)
            if path is not None and (path, alias) in self.local_typedefs:
                token = self.local_typedefs[(path, alias)]
            elif alias in self.typedefs:
                token = self.typedefs[alias]
            else:
                return None
        return token

    def keys_named(self, name: str) -> set[str]:
        """Record keys *name* denotes, as a tag or as a typedef name."""
        keys = set()
        if f"tag:{name}" in self.members:
            keys.add(f"tag:{name}")
        resolved = self.resolve(f"typedef:{name}")
        if resolved is not None and resolved in self.members:
            keys.add(resolved)
        return keys

    def add_source(self, path: str, src: ParsedSource) -> None:
        def anon_key(node: Any) -> str:
            return f"anon:{path}:{node.start_byte}"

        for node in _walk(src.tree.root_node):
            if node.type in _TAG_PARENTS:
                tag = node.child_by_field_name("name")
                if tag is not None:
                    self.type_names.add(src.node_text(tag))
            if node.type in _RECORD_SPECIFIERS and node.child_by_field_name("body") is not None:
                key = type_token(node, src, anon_key)
                if key is None:
                    continue
                members = self.members.setdefault(key, {})
                self.sites.setdefault(key, []).append((path, src.line_col(node.start_byte)[0]))
                body = node.child_by_field_name("body")
                for decl in body.named_children:
                    if decl.type != "field_declaration":
                        continue
                    token = type_token(decl.child_by_field_name("type"), src, anon_key)
                    for declarator in decl.children_by_field_name("declarator"):
                        member = declarator_name(declarator, src)
                        if member:
                            members[member] = token
            elif node.type == "type_definition":
                token = type_token(node.child_by_field_name("type"), src, anon_key)
                for declarator in node.children_by_field_name("declarator"):
                    alias = declarator_name(declarator, src)
                    if alias:
                        self.typedefs.setdefault(alias, token)
                        self.local_typedefs.setdefault((path, alias), token)
                        self.type_names.add(alias)
                        self.typedef_names.add(alias)


#: Global lookup: the record key a file-scope name's declarations agree on, or None.
GlobalLookup = Callable[[str], str | None]


def _declaration_tokens(
    scope: Any,
    name: str,
    src: ParsedSource,
    anon_key: Callable[[Any], str],
    *,
    before: int | None = None,
    file_scope: bool = False,
) -> list[tuple[int, str | None]]:
    """``(offset, type token)`` of each declaration of *name* under *scope*."""
    found: list[tuple[int, str | None]] = []
    for node in _walk(scope):
        if node.type not in ("declaration", "parameter_declaration"):
            continue
        if before is not None and node.start_byte > before:
            continue
        if file_scope and not _at_file_scope(node):
            continue
        for declarator in node.children_by_field_name("declarator"):
            if declarator_name(declarator, src) == name:
                found.append(
                    (node.start_byte, type_token(node.child_by_field_name("type"), src, anon_key))
                )
    return found


def _identifier_record(
    ident: Any, path: str, src: ParsedSource, index: TypeIndex, lookup: GlobalLookup
) -> str | None:
    """Record key of a named variable: function scope, file scope, then project scope.

    A function body the grammar misparsed (MSVC syntax) can sit outside its
    ``function_definition``; then every declaration of the name in the file
    is consulted, and it resolves only when they all agree.
    """

    def anon_key(n: Any) -> str:
        return f"anon:{path}:{n.start_byte}"

    name = src.node_text(ident)
    function = next((a for a in _ancestors(ident) if a.type == "function_definition"), None)
    if function is not None:
        local = _declaration_tokens(function, name, src, anon_key, before=ident.start_byte)
        if local:
            return index.resolve(max(local, key=lambda item: item[0])[1], path)
    root = src.tree.root_node
    file_level = _declaration_tokens(root, name, src, anon_key, file_scope=True)
    if file_level:
        return index.resolve(max(file_level, key=lambda item: item[0])[1], path)
    anywhere = {
        index.resolve(token, path) for _off, token in _declaration_tokens(root, name, src, anon_key)
    }
    if len(anywhere) == 1:
        return next(iter(anywhere))
    if anywhere:
        return None
    return lookup(name)


def expression_record(
    node: Any,
    path: str,
    src: ParsedSource,
    index: TypeIndex,
    lookup: GlobalLookup,
) -> str | None:
    """Record key of the struct/union an expression evaluates to (or points to)."""

    def anon_key(n: Any) -> str:
        return f"anon:{path}:{n.start_byte}"

    if node is None:
        return None
    kind = node.type
    if kind == "parenthesized_expression":
        inner = next((c for c in node.named_children if c.type != "comment"), None)
        return expression_record(inner, path, src, index, lookup)
    if kind == "cast_expression":
        descriptor = node.child_by_field_name("type")
        if descriptor is None:
            return None
        return index.resolve(
            type_token(descriptor.child_by_field_name("type"), src, anon_key), path
        )
    if kind in ("subscript_expression", "pointer_expression"):
        return expression_record(node.child_by_field_name("argument"), path, src, index, lookup)
    if kind == "field_expression":
        owner = expression_record(node.child_by_field_name("argument"), path, src, index, lookup)
        member = node.child_by_field_name("field")
        if owner is None or member is None or owner not in index.members:
            return None
        return index.resolve(index.members[owner].get(src.node_text(member)), path)
    if kind == "call_expression":
        callee = node.child_by_field_name("function")
        if callee is None or callee.type != "identifier":
            return None
        return lookup(src.node_text(callee))
    if kind == "identifier":
        return _identifier_record(node, path, src, index, lookup)
    return None


@dataclass(frozen=True)
class MemberSite:
    """A member occurrence and its resolution against the renamed record."""

    occurrence: Occurrence
    #: ``"rename"`` (the record), ``"other"`` (another record) or ``"unresolved"``.
    verdict: str
    context: str


def _member_context(node: Any) -> str:
    parent = node.parent
    return parent.type if parent is not None else ""


def member_sites(
    src: ParsedSource,
    path: str,
    member: str,
    targets: set[str],
    index: TypeIndex,
    lookup: GlobalLookup,
    *,
    unique: bool,
) -> list[MemberSite]:
    """Every member occurrence of *member*, resolved against record keys *targets*.

    *unique* means no other record declares *member*: every member access is
    then the renamed one and needs no resolution.
    """

    def anon_key(n: Any) -> str:
        return f"anon:{path}:{n.start_byte}"

    def verdict_for(key: str | None) -> str:
        if key in targets:
            return "rename"
        if unique:
            return "rename"
        return "other" if key is not None else "unresolved"

    sites: list[MemberSite] = []
    for occ in occurrences(src, member):
        if occ.role == ROLE_MACRO_MEMBER:
            # ``g_root.count`` in a macro body: the base is a file-scope name.
            base = _NAMED_MEMBER_ACCESS_RE.search(src.data[max(0, occ.start - 128) : occ.start])
            key = lookup(base.group(1).decode("utf-8", "replace")) if base else None
            sites.append(MemberSite(occ, verdict_for(key), "macro"))
            continue
        if occ.role != ROLE_MEMBER:
            continue
        node = src.tree.root_node.descendant_for_byte_range(occ.start, occ.end)
        context = _member_context(node)
        owner = node.parent
        while owner is not None and owner.type in _DECLARATOR_WRAPPERS:
            owner = owner.parent
        if owner is not None and owner.type == "field_declaration":
            record = owner.parent.parent if owner.parent is not None else None
            key = (
                type_token(record, src, anon_key)
                if record is not None and record.type in _RECORD_SPECIFIERS
                else None
            )
            # A declaration is never resolved by uniqueness: it IS the record.
            sites.append(MemberSite(occ, "rename" if key in targets else "other", "declaration"))
            continue
        if context == "field_expression":
            key = expression_record(
                node.parent.child_by_field_name("argument"), path, src, index, lookup
            )
            sites.append(MemberSite(occ, verdict_for(key), context))
            continue
        if context == "offsetof_expression":
            descriptor = node.parent.child_by_field_name("type")
            key = (
                index.resolve(
                    type_token(descriptor.child_by_field_name("type"), src, anon_key), path
                )
                if descriptor is not None
                else None
            )
            sites.append(MemberSite(occ, verdict_for(key), context))
            continue
        if context == "field_designator":
            sites.append(
                MemberSite(occ, verdict_for(_designated_record(node, path, src, index)), context)
            )
            continue
        sites.append(MemberSite(occ, "rename" if unique else "unresolved", context))
    return sites


def _designated_record(node: Any, path: str, src: ParsedSource, index: TypeIndex) -> str | None:
    """Record a ``.member =`` designator initializes, for a direct declaration."""

    def anon_key(n: Any) -> str:
        return f"anon:{path}:{n.start_byte}"

    depth = 0
    current = node
    while current is not None and current.type != "init_declarator":
        if current.type == "initializer_list":
            depth += 1
        current = current.parent
    if current is None or current.parent is None or current.parent.type != "declaration":
        return None
    is_array = current.child_by_field_name("declarator") is not None and (
        current.child_by_field_name("declarator").type == "array_declarator"
    )
    if depth != (2 if is_array else 1):
        return None
    return index.resolve(
        type_token(current.parent.child_by_field_name("type"), src, anon_key), path
    )


def file_scope_type(src: ParsedSource, path: str, name: str) -> list[str | None]:
    """Type tokens of every file-scope declaration or definition of *name*."""

    def anon_key(n: Any) -> str:
        return f"anon:{path}:{n.start_byte}"

    tokens: list[str | None] = []
    for node in _walk(src.tree.root_node):
        if node.type == "function_definition":
            if declarator_name(node.child_by_field_name("declarator"), src) == name:
                tokens.append(type_token(node.child_by_field_name("type"), src, anon_key))
        elif node.type == "declaration" and _at_file_scope(node):
            for declarator in node.children_by_field_name("declarator"):
                if declarator_name(declarator, src) == name:
                    tokens.append(type_token(node.child_by_field_name("type"), src, anon_key))
    return tokens


def rename_function_source(source: str, new_name: str) -> str:
    """Rename one complete function and its references without capturing a name.

    Comments/literals and other namespaces stay intact. Refuse shadowing or a
    destination already used by the source, including an implicit external call.
    """
    from rebrew.c_parser import extract_function_name_and_proto, function_source_error

    reason = function_source_error(source, allow_declarations=True)
    if reason is not None:
        raise ValueError(reason)
    signature = extract_function_name_and_proto(source)
    assert signature is not None
    old_name = signature[0]
    if old_name == new_name:
        return source
    parsed = ParsedSource.parse(source)
    if non_external_function_declarations(parsed, old_name) or any(
        occurrence.role in ORDINARY_ROLES for occurrence in occurrences(parsed, new_name)
    ):
        raise ValueError("renaming the function would capture an existing name")
    spans = [(o.start, o.end) for o in occurrences(parsed, old_name) if o.role == ROLE_IDENT]
    result = rewrite(parsed, spans, new_name)
    reason = function_source_error(result, expect_name=new_name, allow_declarations=True)
    if reason is not None:
        raise ValueError(reason)
    return result
