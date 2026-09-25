"""Rewrite decompiler pseudo-C into tokens a C89 compiler accepts.

Decompiler output (Ghidra, r2ghidra, r2dec, Kuna) uses pseudo-types,
qualified symbol names, and junk specifiers that msvc-6.0 rejects.
:func:`sanitize_tokens` is that rewrite.  ``rebrew fix`` and Kuna
seeding both call it from here.
"""

from __future__ import annotations

import re
from collections.abc import Callable

# ---------------------------------------------------------------------------
# Token sanitization
# ---------------------------------------------------------------------------

#: Decompiler pseudo-types → C89 types.  Order matters (longest first).
_PSEUDO_TYPE_RE = re.compile(
    r"\b(undefined8|undefined4|undefined2|undefined1|undefined|"
    r"ulonglong|longlong|ulong|uint|ushort|uchar|ushort|"
    r"qword|dword|word|byte)\b"
)
_PSEUDO_TYPE_MAP: dict[str, str] = {
    "undefined8": "long long",
    "undefined4": "int",
    "undefined2": "short",
    "undefined1": "char",
    "undefined": "int",
    "ulonglong": "unsigned long long",
    "longlong": "long long",
    "ulong": "unsigned long",
    "uint": "unsigned int",
    "ushort": "unsigned short",
    "uchar": "unsigned char",
    "qword": "unsigned long long",
    "dword": "unsigned int",
    "word": "unsigned short",
    "byte": "unsigned char",
}

#: ``*(undefined4 *)ptr`` → ``*(int *)ptr`` — the map above handles the inner
#: token; the asterisk forms like ``(undefined4)`` are handled by the same
#: word-boundary replacement (parens are not word chars).

#: Qualified symbol names ``GLIBC_2.2.5::stderr`` / ``std::X::Y`` → last
#: component (the compiler cannot see library internals from decompiler
#: symbol tables).
_QUALIFIED_NAME_RE = re.compile(r"\b(?:[A-Za-z_][A-Za-z0-9_.]*::)+[A-Za-z_][A-Za-z0-9_]*")

#: MSVC decoration artifacts ``__cdecl``/``__fastcall`` are fine; strip the
#: Borland/Ghidra ``__based`` and ``_near``/``_far``-adjacent oddities that
#: block C89 parsing.
_JUNK_SPECIFIER_RE = re.compile(r"\b(?:__based|__unaligned|__ptr32|__ptr64|__restrict)\b")


def _sub_outside_literals(
    text: str, pattern: re.Pattern[str], repl: Callable[[re.Match[str]], str]
) -> str:
    """Substitute tokens while preserving literals and macro names at byte offsets."""
    from rebrew.c_parser import protected_spans

    spans = protected_spans(text)
    data = text.encode("utf-8", errors="surrogateescape")
    out: list[str] = []
    pos = 0
    for start, end in spans:
        out.append(pattern.sub(repl, data[pos:start].decode("utf-8", errors="surrogateescape")))
        out.append(data[start:end].decode("utf-8", errors="surrogateescape"))
        pos = end
    out.append(pattern.sub(repl, data[pos:].decode("utf-8", errors="surrogateescape")))
    return "".join(out)


#: Leading ``*``/``&`` on function-returning decls that break declarations
#: (``* FUN_00401000(...)`` at statement level is a Ghidra cast idiom).
_LEADING_STAR_RE = re.compile(r"^(\s*)\*(?=\s*[A-Za-z_])", re.MULTILINE)


def sanitize_tokens(source: str) -> tuple[str, list[str]]:
    """Apply the deterministic token-sanitization pass.

    Returns ``(fixed_source, changes)`` where *changes* is a list of
    ``"pseudo-type 'undefined4' -> 'int'"`` style descriptions (empty when
    the source needed no repairs).  Never raises; degenerate input is
    returned unchanged.
    """
    changes: list[str] = []

    def _sub_pseudo(m: re.Match[str]) -> str:
        rep = _PSEUDO_TYPE_MAP.get(m.group(1), "int")
        changes.append(f"pseudo-type '{m.group(1)}' -> '{rep}'")
        return rep

    out = _PSEUDO_TYPE_RE.sub(_sub_pseudo, source)

    def _sub_qualified(m: re.Match[str]) -> str:
        name = m.group(0).rsplit("::", 1)[1]
        changes.append(f"qualified name '{m.group(0)}' -> '{name}'")
        return name

    out = _sub_outside_literals(out, _QUALIFIED_NAME_RE, _sub_qualified)

    def _sub_junk(m: re.Match[str]) -> str:
        changes.append(f"removed specifier '{m.group(0)}'")
        return ""

    out = _JUNK_SPECIFIER_RE.sub(_sub_junk, out)

    def _sub_star(m: re.Match[str]) -> str:
        changes.append("normalized leading '* cast")
        return f"{m.group(1)}"

    out = _LEADING_STAR_RE.sub(_sub_star, out)
    return out, changes
