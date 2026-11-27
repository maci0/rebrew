"""signature_parser.py – Extract function signatures from C source via tree-sitter.

Walks the AST of a C file and yields ``(function_name, signature_string)``
tuples for each function definition found.  The signature includes the return
type, name, and parameter list, without a trailing semicolon.

Signatures are normalised for Ghidra's CParser: MSVC calling conventions
(``__cdecl``, ``__stdcall``, etc.), ``__declspec``, ``const``/``volatile``
qualifiers, and function-pointer parameters are stripped or simplified.
"""

import re
lazy import unicodedata
lazy from collections.abc import Iterator
lazy from pathlib import Path
lazy from typing import Any

lazy from rebrew.c_parser import get_ts_parser, parse_c_source
lazy from rebrew.utils import detect_source_encoding

_PTR_NOSPACE_RE = re.compile(r"([a-zA-Z0-9_])\*")
_MULTI_SPACE_RE = re.compile(r"  +")
_RBW_RE = re.compile(r"\bRBW_\w+\b")
_NON_NEWLINE_RE = re.compile(r"[^\r\n]")
_BANNED_QUALS = frozenset({"const", "volatile"})


def _funcptr_param_replacement(param_node: Any, data: bytes) -> str | None:
    """Return ``void * name[dims]`` when *param_node* declares a function pointer, else None."""
    from rebrew.c_parser import node_text

    decl = param_node.child_by_field_name("declarator")
    if decl is None:
        return None

    fn_decl: Any = None
    cur: Any = decl
    while cur is not None:
        if cur.type in ("function_declarator", "abstract_function_declarator"):
            fn_decl = cur
            break
        if cur.type in (
            "pointer_declarator",
            "abstract_pointer_declarator",
            "array_declarator",
            "abstract_array_declarator",
        ):
            cur = cur.child_by_field_name("declarator")
        elif cur.type in ("parenthesized_declarator", "abstract_parenthesized_declarator"):
            inner = [c for c in cur.named_children if c.type != "comment"]
            cur = inner[0] if inner else None
        else:
            break

    if fn_decl is None:
        return None

    inner_decl = fn_decl.child_by_field_name("declarator")
    name: str | None = None
    brackets: list[str] = []

    def _collect(node: Any) -> None:
        nonlocal name
        if node is None:
            return
        if node.type == "identifier":
            if name is None:
                name = node_text(node, data)
            return
        if node.type in ("array_declarator", "abstract_array_declarator"):
            sub = node.child_by_field_name("declarator")
            _collect(sub)
            start: int | None = None
            end: int | None = None
            for child in node.children:
                if child.type == "[" and start is None:
                    start = int(child.start_byte)
                elif child.type == "]" and start is not None:
                    end = int(child.end_byte)
            if start is not None and end is not None:
                brackets.append(data[start:end].decode("utf-8", errors="surrogateescape"))
            return
        if node.type in ("function_declarator", "abstract_function_declarator"):
            _collect(node.child_by_field_name("declarator"))
            return
        for child in node.named_children:
            if child.type != "comment":
                _collect(child)

    _collect(inner_decl)
    if name:
        return f"void * {name}{''.join(brackets)}"
    return "void *"


def _normalize_signature(sig: str) -> str:
    """Strip syntax that Ghidra's CParser does not accept (MSVC extensions, const/volatile, function pointers)."""
    from rebrew.c_parser import mask_msvc_syntax, node_text

    sig = unicodedata.normalize("NFC", sig)
    sig = sig.replace("\r", "")
    # Mask MSVC calling conventions / __declspec and project RBW_* macros with
    # same-length spaces before parsing so byte offsets and newlines stay aligned
    # (preserving newlines ensures ``//`` comments do not swallow subsequent code).
    masked = mask_msvc_syntax(sig)
    masked = _RBW_RE.sub(lambda m: _NON_NEWLINE_RE.sub(" ", m.group(0)), masked)

    probe = masked.rstrip("; \n\t") + ";"
    if get_ts_parser() is not None:
        tree, data = parse_c_source(probe)
        edits: list[tuple[int, int, str]] = []
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type == "comment":
                # Drop ``//`` line comments so flattening newlines cannot swallow
                # the following tokens; preserve ``/* ... */`` block comments.
                if data[int(node.start_byte) : int(node.start_byte) + 2] == b"//":
                    edits.append((int(node.start_byte), int(node.end_byte), ""))
                continue
            if node.type in ("string_literal", "char_literal"):
                continue
            if node.type == "parameter_declaration":
                replacement = _funcptr_param_replacement(node, data)
                if replacement is not None:
                    edits.append((int(node.start_byte), int(node.end_byte), replacement))
                    continue
            if node.type == "type_qualifier" and node_text(node, data) in _BANNED_QUALS:
                edits.append((int(node.start_byte), int(node.end_byte), ""))
                continue
            if node.child_count == 0 and node_text(node, data) in _BANNED_QUALS:
                edits.append((int(node.start_byte), int(node.end_byte), ""))
                continue
            stack.extend(node.children)

        if edits:
            out = bytearray(data)
            for start, end, repl in sorted(edits, key=lambda item: item[0], reverse=True):
                out[start:end] = repl.encode("utf-8", errors="surrogateescape")
            masked = bytes(out).decode("utf-8", errors="surrogateescape")
        else:
            masked = probe

    masked = masked.replace("\n", " ")
    sig = _PTR_NOSPACE_RE.sub(r"\1 *", masked)
    sig = sig.rstrip("; ")
    sig = _MULTI_SPACE_RE.sub(" ", sig)
    return sig.strip()


def _parse_source(filepath: Path) -> tuple[bytes, str, Any] | None:
    """Read and parse *filepath* into ``(code_bytes, encoding, root_node)``.

    Returns None when tree-sitter is unavailable or the file cannot be read,
    so every extractor fails the same way instead of one silently yielding.
    """
    from rebrew.c_parser import mask_msvc_syntax

    if get_ts_parser() is None:
        return None
    try:
        code_bytes = filepath.read_bytes()
    except OSError:
        return None
    encoding = detect_source_encoding(code_bytes)
    masked_str = mask_msvc_syntax(code_bytes.decode("utf-8", errors="surrogateescape"))
    masked_str = _RBW_RE.sub(lambda m: _NON_NEWLINE_RE.sub(" ", m.group(0)), masked_str)
    tree, _ = parse_c_source(masked_str)
    return code_bytes, encoding, tree.root_node


def extract_function_signatures(filepath: Path) -> Iterator[tuple[str, str]]:
    """Parse a C file using tree-sitter and yield (function_name, signature_string).

    Signatures are normalized (MSVC extensions stripped) for Ghidra CParser
    compatibility.  Returns empty if tree-sitter is unavailable or file unreadable.
    """
    parsed = _parse_source(filepath)
    if parsed is None:
        return
    code_bytes, encoding, root = parsed

    def get_function_name(node: Any) -> str | None:
        if node.type == "function_declarator":
            for child in node.children:
                if child.type == "identifier":
                    return unicodedata.normalize(
                        "NFC",
                        code_bytes[child.start_byte : child.end_byte].decode(
                            encoding, errors="replace"
                        ),
                    )
                res = get_function_name(child)
                if res:
                    return res
        else:
            for child in node.children:
                res = get_function_name(child)
                if res:
                    return res
        return None

    def walk(node: Any) -> Iterator[tuple[str, str]]:
        if node.type == "function_definition":
            compound_stmt = None
            decl_node = None

            for child in node.children:
                if child.type == "compound_statement":
                    compound_stmt = child
                elif child.type in ("function_declarator", "pointer_declarator", "declaration"):
                    decl_node = child

            if not decl_node:
                decl_node = node

            if compound_stmt:
                sig_bytes = code_bytes[node.start_byte : compound_stmt.start_byte].strip()
                # Match read_source_text: CP1252 holes (0x81/…) become U+FFFD
                # instead of raising and dropping the whole file's signatures.
                sig_str = sig_bytes.decode(encoding, errors="replace")

                name = get_function_name(decl_node)
                if name:
                    yield name, _normalize_signature(sig_str)
        else:
            for child in node.children:
                yield from walk(child)

    yield from walk(root)


def extract_function_prototypes(filepath: Path) -> Iterator[str]:
    """Parse a C file and yield function prototype signatures.

    Prototypes are *declarations without bodies* (``void draw(int);``) —
    the m2c-style universal context file needs them alongside the
    definition signatures, but :func:`extract_function_signatures` only
    walks ``function_definition`` nodes.  Normalized identically, so a
    prototype and a definition of the same function deduplicate by text.
    """
    parsed = _parse_source(filepath)
    if parsed is None:
        return
    code_bytes, encoding, root = parsed

    def _is_plain_prototype(node: Any) -> bool:
        """True when *node* is a declaration with a plain function
        prototype.  Walk the declarator chain: a function_declarator reached
        without a parenthesized_declarator is a prototype (``int *f(void);``
        returns a pointer — keep it), while a function-pointer variable or
        typedef (``int (*cb)(void);``) passes through a
        parenthesized_declarator and is skipped — the Ghidra normalization
        mangles those into plain ``void *``, poisoning the context."""

        def chain(n: Any) -> bool:
            t = getattr(n, "type", None)
            if t == "parenthesized_declarator":
                return False
            if t == "function_declarator":
                # Plain only when no parenthesized_declarator (function
                # pointer) nests in the declarator chain OUTSIDE the
                # parameter list (pointer params live inside parameter_list
                # and are fine).
                for child in getattr(n, "children", []):
                    cty = getattr(child, "type", None)
                    if cty == "parameter_list":
                        continue
                    if cty == "parenthesized_declarator":
                        return False
                    if cty in ("pointer_declarator", "declarator"):
                        return chain(child)
                return True
            for child in getattr(n, "children", []):
                if getattr(child, "type", None) in (
                    "pointer_declarator",
                    "function_declarator",
                    "parenthesized_declarator",
                    "declarator",
                ):
                    return chain(child)
            return False

        return chain(node)

    pending = [root]
    while pending:
        node = pending.pop()
        if node.type == "declaration" and _is_plain_prototype(node):
            text = (
                code_bytes[node.start_byte : node.end_byte]
                .decode(encoding, errors="replace")
                .strip()
            )
            yield _normalize_signature(text)
        pending.extend(reversed(getattr(node, "children", [])))
