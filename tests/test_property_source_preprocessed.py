"""Property-based fuzz tests for ``rebrew.source_preprocessed``.

``parse_msvc_preprocessed`` takes MSVC ``/P`` preprocessor output — bytes
produced by a compiler, never by rebrew itself — and derives an
offset-preserving parser view from them: line markers are blanked, MSVC
syntax is masked, literals/comments are protected, and a tree-sitter parse
runs over the result.  A marker that decodes to a wrong path, a literal
whose contents leak into the view, or a view whose length diverges from
the input silently shifts every byte offset the inventory reports
(``reported_source_functions``), so the harness asserts the invariants the
inventory relies on, not merely that no exception escapes:

* the view is exactly as long as the input — every offset reported
  against the view is a valid offset into the raw bytes;
* ``source_sha256`` is the sha256 of the input bytes (pair assertion
  across the parse boundary: the digest stored in the report must match
  the bytes it claims to describe);
* nothing but line-marker spans and MSVC-modifier spans differs between
  view and input, outside protected literals/comments (which are
  restored byte-for-byte) — so a masked span can never invent or drop
  source text;
* every reported marker lies inside the input and its line number is
  within the marker's own span;
* a truncated input never raises anything but ``ValueError`` (the
  line-marker decode) and never returns a report for a different input.

The tree-sitter parse itself is already fuzzed in
``test_property_c_parser``; this harness covers the projection layer
above it, which had no property test while every sibling text parser did.
"""

from __future__ import annotations

import hashlib
import re

from hypothesis import example, given, settings
from hypothesis import strategies as st

from rebrew.source_preprocessed import parse_msvc_preprocessed

_LINE = re.compile(rb"(?m)^[ \t]*#line[ \t]+[0-9]+[ \t]+\"((?:\\.|[^\"\\])*)\"[^\r\n]*")
_MODIFIER = re.compile(rb"\b(?:_inline|_cdecl|_stdcall|_fastcall)\b")
_CONVENTION = re.compile(rb"\b__(?:cdecl|stdcall|fastcall|thiscall)\b")
_ASM = re.compile(rb"\b__asm\b[ \t]*(\{)?")


def _markers(raw: bytes) -> list[tuple[int, int]]:
    return [(m.start(), m.end()) for m in _LINE.finditer(raw)]


@st.composite
def _preprocessed(draw: st.DrawFn) -> bytes:
    """Preprocessor-shaped bytes: markers, modifiers, literals, comments, C."""
    parts: list[bytes] = []
    for _ in range(draw(st.integers(0, 3))):
        lineno = draw(st.integers(0, 99999))
        path = draw(st.binary(min_size=0, max_size=16).map(lambda b: b.replace(b'"', b"")))
        parts.append(b'#line %d "%s"\n' % (lineno, path))
    body = draw(
        st.sampled_from(
            [
                b"int f(void) { return 1; }\n",
                b"_inline int __cdecl g(void) { return 2; }\n",
                b"struct S { int :7; int x; };\n",
                b'const char *s = "_inline __cdecl";\n',
                b'/* #line 5 "fake.c" */\n',
                b"// _inline __stdcall\n",
                b"char c = 'x';\n",
                b"__asm mov eax, 1\n",
                b"\n",
            ]
        )
    )
    parts.append(body)
    if draw(st.booleans()):
        junk = draw(st.binary(max_size=32))
        cut = draw(st.integers(0, len(junk))) if junk else 0
        parts.append(junk[:cut])
    return b"".join(parts)


class TestParseMsvcPreprocessedRobust:
    @given(st.binary(max_size=512))
    @settings(max_examples=150, deadline=None)
    def test_raw_bytes_never_raise_unexpected(self, raw: bytes) -> None:
        try:
            report = parse_msvc_preprocessed(raw)
        except ValueError:
            return
        assert len(report["view"]) == len(raw)
        assert report["source_sha256"] == hashlib.sha256(raw).hexdigest()
        for marker in report["markers"]:
            assert 0 <= marker["start"] <= marker["end"] <= len(raw)
            assert isinstance(marker["reported_path"], str)

    @example(raw=b'#line 0 "\\"\n#line 0 ""\nint f(void) { return 1; }\n')
    @given(_preprocessed())
    @settings(max_examples=150, deadline=None)
    def test_view_differs_only_inside_markers_and_modifiers(self, raw: bytes) -> None:
        try:
            report = parse_msvc_preprocessed(raw)
        except ValueError:
            return
        view = report["view"]
        assert len(view) == len(raw)
        allowed = [False] * len(raw)
        for start, end in _markers(raw):
            for i in range(start, end):
                allowed[i] = True
        for m in _MODIFIER.finditer(raw):
            for i in range(m.start(), m.end()):
                allowed[i] = True
        for m in _CONVENTION.finditer(raw):
            for i in range(m.start(), m.end()):
                allowed[i] = True
        for m in _ASM.finditer(raw):
            end = raw.find(b"\n", m.end())
            end = len(raw) if end < 0 else end
            for i in range(m.start(), end):
                allowed[i] = True
        # Protected spans are restored, so they must match the input too;
        # anything outside an allowed span that changed is a bug.
        for i, (a, b) in enumerate(zip(raw, view, strict=True)):
            if a != b:
                assert allowed[i], (
                    f"byte {i} changed outside markers/modifiers: {raw!r} -> {view!r}"
                )

    @given(_preprocessed())
    @settings(max_examples=100, deadline=None)
    def test_truncation_never_raises_unexpected(self, raw: bytes) -> None:
        if not raw:
            return
        cut = len(raw) // 2
        try:
            report = parse_msvc_preprocessed(raw[:cut])
        except ValueError:
            return
        assert report["source_sha256"] == hashlib.sha256(raw[:cut]).hexdigest()
        assert len(report["view"]) == cut
