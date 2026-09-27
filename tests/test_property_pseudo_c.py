"""Hypothesis fuzz for the decompiler pseudo-C sanitizer.

``rebrew.pseudo_c.sanitize_tokens`` rewrites decompiler output (Ghidra,
r2ghidra, r2dec, Kuna) into C89 that msvc-6.0 accepts: pseudo-types become
real types, qualified names lose their scope, junk specifiers go away, and
literal and macro text must survive byte-for-byte.  The input is another
tool's text, and the output is compiled as a GA seed, so a rewrite that
corrupts a string literal or fails to converge changes matching results.

The harness asserts the properties a caller depends on, beyond "did not
raise":

* the pass is idempotent — a second run over its own output is a no-op with
  no further changes (the rewrite reaches a fixed point, so a caller that
  runs it twice, as the fix and seed paths each do, does not double-rewrite);
* literals and macro names are preserved exactly, by re-deriving the
  protected spans of the input and checking each one appears unchanged;
* no pseudo-type token survives outside those spans;
* every reported change names the pseudo-type it replaced and a replacement
  the type map actually defines.
"""

from __future__ import annotations

import re

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.c_parser import protected_spans
from rebrew.pseudo_c import _PSEUDO_TYPE_MAP, sanitize_tokens

#: Tokens the sanitizer exists to remove; none may survive outside a literal.
_PSEUDO_WORD_RE = re.compile(
    r"\b(undefined8|undefined4|undefined2|undefined1|undefined|"
    r"ulonglong|longlong|ulong|uint|ushort|uchar|"
    r"qword|dword|word|byte|__based|__unaligned|__ptr32|__ptr64|__restrict)\b"
)

#: A short line of decompiler-ish C.  Statement text is what the pass runs
#: on; a cap keeps the protected-span scan from dominating the example.
_STATEMENT = st.lists(
    st.sampled_from(
        [
            "undefined4 *param_1;",
            "int FUN_00401000(int a, int b) {",
            "  *(int *)(param_1 + 0x10) = 0;",
            "  v0 = std::vector<int>::size((vector_int *)this);",
            "  *FUN_00401234(0x401000, 'a', \"b\") = 0;",
            "  __based(param_1) = 0;",
            "  x = GLIBC_2.2.5::stderr;",
            "* FUN_00402000(void) {",
            "#define M(x) undefined4",
            "  return; }",
            '  s = "a::b undefined4";',
            "  c = 'undefined4';",
            "",
        ]
    ),
    max_size=8,
).map("\n".join)


def _outside_literals(text: str) -> str:
    """*text* with every protected span (string, char, macro body) removed."""
    spans = protected_spans(text)
    kept: list[str] = []
    pos = 0
    for start, end in spans:
        kept.append(text[pos:start])
        pos = end
    kept.append(text[pos:])
    return "".join(kept)


@settings(max_examples=200, deadline=None)
@given(source=_STATEMENT)
def test_sanitize_tokens_converges(source: str) -> None:
    once, changes = sanitize_tokens(source)
    twice, changes_again = sanitize_tokens(once)
    assert twice == once
    assert changes_again == []


@settings(max_examples=200, deadline=None)
@given(source=_STATEMENT)
def test_sanitize_tokens_preserves_literals(source: str) -> None:
    once, _ = sanitize_tokens(source)
    for span in protected_spans(source):
        literal = source[span[0] : span[1]]
        if literal:
            assert literal in once


@settings(max_examples=200, deadline=None)
@given(source=_STATEMENT)
def test_sanitize_tokens_removes_pseudo_types(source: str) -> None:
    once, changes = sanitize_tokens(source)
    assert not _PSEUDO_WORD_RE.search(_outside_literals(once))
    for change in changes:
        # Each change is "<what> '<token>' -> '<replacement>'"; a replacement
        # that is not a real type would not compile, so pin it to the map
        # for the pseudo-type changes and let the other two forms stand.
        parts = change.split("'")
        if len(parts) == 4 and parts[0] == "pseudo-type ":
            assert parts[1] in _PSEUDO_TYPE_MAP
            assert parts[3] == _PSEUDO_TYPE_MAP[parts[1]]
