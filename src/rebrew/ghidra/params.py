"""params.py — apply Ghidra parameter names to local C signatures.

Ghidra's decompiled signature (or PROTOTYPE metadata) carries parameter
names the local .c often lacks (``int f(int, char *)``).  These pure helpers
fill the unnamed parameters with Ghidra's names, merge-safe: a parameter that
already has a name is never overwritten, and anything unsafe to rewrite
(function-pointer params, arity mismatch) is skipped.
"""

from __future__ import annotations

import re

from rebrew.c_parser import iter_function_name_and_proto

_TYPE_KEYWORDS = frozenset(
    {
        "int",
        "char",
        "void",
        "unsigned",
        "short",
        "long",
        "float",
        "double",
        "signed",
        "const",
        "volatile",
        "struct",
        "union",
        "enum",
        "static",
        "register",
        "extern",
        "__cdecl",
        "__stdcall",
        "__fastcall",
    }
)

#: Param-list chars that make a rewrite unsafe (nested parens = function
#: pointers, array declarators with parens, etc.).
_UNSAFE = re.compile(r"[()]")


def _param_name(part: str) -> str | None:
    """The identifier of a param (stars stripped), or None when unnamed.

    ``char *buf`` → ``"buf"``; ``char *`` / ``unsigned int`` → ``None``.
    """
    tokens = part.split()
    last = tokens[-1].lstrip("*")
    if last in _TYPE_KEYWORDS or last == "":
        return None
    return last


def param_names_from_proto(proto: str) -> list[str] | None:
    """Extract parameter names from a C prototype; None when unparseable.

    ``int f(int a, char *b)`` → ``["a", "b"]``.  Unnamed params yield empty
    strings.  Function-pointer params (nested parens) → None (unsafe).
    """
    proto = proto.strip().rstrip(";").strip()
    if not proto.endswith(")"):
        return None
    start = proto.rfind("(")
    if start < 0:
        return None
    inner = proto[start + 1 : -1]
    if _UNSAFE.search(inner):
        return None
    if not inner.strip():
        return []  # void / no params
    if inner.strip() == "void":
        return []
    names: list[str] = []
    for part in _split_top_level(inner):
        part = part.strip()
        if not part:
            return None
        name = _param_name(part)
        names.append(name if name is not None else "")
    return names


def _split_top_level(s: str) -> list[str]:
    """Split *s* on commas at paren depth 0."""
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def apply_param_names(source: str, func_name: str, ghra_names: list[str]) -> str | None:
    """Fill unnamed parameters of *func_name* with *ghra_names*.

    Returns the rewritten source, or None when the function is not found,
    the arity differs, or the signature is unsafe to rewrite.  Named
    parameters are preserved verbatim.  Multi-function files are walked —
    every definition is matched by name, not just the first
    (sync-review F11).
    """
    for name, proto in iter_function_name_and_proto(source):
        if name != func_name:
            continue
        local_names = param_names_from_proto(proto)
        if local_names is None:
            return None
        if len(local_names) != len(ghra_names):
            return None  # arity mismatch — do not guess

        # Nothing to do when every param already has a name.
        if all(n for n in local_names):
            return None

        # Build the named param list from the original proto's paren group.
        start = proto.rfind("(")
        end = proto.rfind(")")
        old_inner = proto[start + 1 : end]
        new_parts: list[str] = []
        for i, part in enumerate(_split_top_level(old_inner)):
            part = part.strip()
            if _param_name(part) is None:
                # Unnamed → append the Ghidra name.
                new_parts.append(f"{part} {ghra_names[i]}")
            else:
                new_parts.append(part)
        new_inner = ", ".join(new_parts)
        if new_inner == old_inner:
            return None
        new_proto = proto[: start + 1] + new_inner + proto[end:]

        # Replace the prototype in the source.  iter_function_name_and_proto
        # returns the definition's verbatim text, so a direct replace is exact.
        if proto in source and new_proto != proto:
            return source.replace(proto, new_proto, 1)
        return None
    return None
