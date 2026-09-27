"""Property-based fuzz for the C source scanners feeding Ghidra's CParser.

``rebrew.signature_parser`` and ``rebrew.struct_parser`` read rebrew's own C
sources — files that mix MSVC extensions, function-pointer parameters, and
non-UTF-8 bytes lifted out of the target headers — and re-emit text that
Ghidra's parser must accept.  These harnesses drive both scanners with
generated C and assert the postcondition the normalizer promises: the output
carries none of the syntax Ghidra rejects, and a definition still has a
balanced parameter list.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.c_parser import get_ts_parser
from rebrew.signature_parser import extract_function_signatures
from rebrew.struct_parser import extract_structs_from_file, extract_type_definitions

#: Constructs Ghidra's CParser rejects, so ``_normalize_signature`` must
#: remove all of them.  Matched on word boundaries so an identifier that
#: merely contains one (``my_const``) is not flagged, and so a qualifier
#: glued to its parameter (``f(const char *s)``) still trips the check.
_BANNED_RE = re.compile(
    r"\b(?:__cdecl|__stdcall|__fastcall|__thiscall|__declspec|const|volatile|RBW_\w+)\b"
)

_NAME = st.from_regex(r"\A[A-Za-z_][A-Za-z0-9_]{0,15}\Z", fullmatch=True)

_RETURN_TYPES = st.sampled_from(
    ["void", "int", "unsigned int", "char *", "struct Foo *", "unsigned short", "long", "float"]
)

_MODIFIERS = st.sampled_from(
    [
        "",
        "__cdecl ",
        "__stdcall ",
        "__declspec(dllexport) ",
        "const ",
        "volatile ",
        "RBW_EXPORT ",
    ]
)

_PARAMS = st.sampled_from(
    [
        "void",
        "int a",
        "int a, int b",
        "const char *s",
        "volatile unsigned int *p",
        "int (*fn)(int, int)",
        "struct Foo *out, unsigned char **buf",
        "int a, const char *s, unsigned long flags",
    ]
)


@st.composite
def _c_source(draw: st.DrawFn) -> bytes:
    """A small C translation unit with fuzzed declarations, defs, and junk."""
    chunks: list[str] = []
    for _ in range(draw(st.integers(min_value=1, max_value=4))):
        name = draw(_NAME)
        kind = draw(st.sampled_from(["definition", "declaration", "struct", "junk"]))
        ret = draw(_RETURN_TYPES)
        mod = draw(_MODIFIERS)
        params = draw(_PARAMS)
        if kind == "definition":
            chunks.append(f"{ret} {mod}{name}({params}) {{ return; }}")
        elif kind == "declaration":
            chunks.append(f"{ret} {mod}{name}({params});")
        elif kind == "struct":
            body = draw(
                st.lists(st.sampled_from(["int a;", "char b[4];", "void (*fn)(void);"]), max_size=3)
            )
            chunks.append(f"struct {name} {{ " + " ".join(body) + " };")
            chunks.append(f"typedef struct {name} {name}_t;")
        else:
            chunks.append(
                draw(
                    st.sampled_from(
                        [
                            "/* unterminated comment",
                            '"unterminated string',
                            "#if 0",
                            "int ((( unbalanced;",
                            "typedef int",
                            "\x00",
                        ]
                    )
                )
            )
        if draw(st.booleans()):
            chunks.append("// trailing comment")
    return ("\n".join(chunks) + "\n").encode("utf-8", "surrogateescape")


def _balanced_parens(text: str) -> bool:
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def _write(tmp: str, data: bytes) -> Path:
    path = Path(tmp) / "fuzz.c"
    path.write_bytes(data)
    return path


@settings(max_examples=150, deadline=None)
@given(_c_source())
def test_extract_function_signatures_normalized_for_ghidra(data: bytes) -> None:
    """Every emitted signature is Ghidra-safe and never raises on junk input.

    The normalizer's contract: one line, no MSVC calling conventions, no
    ``__declspec``, no qualifiers, no function-pointer parameter syntax, and
    no doubled spaces.  Those are exactly the forms Ghidra's CParser
    rejects, so anything left behind is a real ingestion failure.
    """
    if get_ts_parser() is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, data)
        for name, sig in extract_function_signatures(path):
            assert name, f"empty function name from {data!r}"
            assert "\n" not in sig and "\r" not in sig, sig
            assert not sig.endswith((";", " ")), sig
            assert "  " not in sig, sig
            leaked = _BANNED_RE.search(sig)
            assert leaked is None, f"{leaked.group(0)!r} survived in {sig!r}"
            assert not sig.startswith((" ", "\t")), sig
            # A definition always keeps its parameter list after the body is
            # cut off, and the parens must balance for Ghidra to parse it.
            assert _balanced_parens(sig), sig
            assert sig.endswith(")"), sig
            # An inline function-pointer parameter is rewritten to ``void *``.
            assert "(*" not in sig, sig


@settings(max_examples=150, deadline=None)
@given(_c_source())
def test_struct_extraction_yields_balanced_bodies(data: bytes) -> None:
    """Struct extraction never raises and never emits an unbalanced body.

    Both are fed verbatim to Ghidra's ``parse-c-structure``, so a missing
    brace or a half-decoded byte becomes a rejected struct rather than a
    warning.
    """
    if get_ts_parser() is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, data)
        structs = list(extract_structs_from_file(path))
        for text in structs:
            assert "{" in text and "}" in text, text
            assert _balanced_parens(text), text
            assert text.count("{") == text.count("}"), text
            assert "\x00" not in text
        # The all-typedefs mode is a superset: it also yields standalone
        # typedefs, but must never drop a struct the narrow mode found.
        all_defs = list(extract_type_definitions(path))
        for text in structs:
            assert text in all_defs, f"{text!r} missing from the all-typedefs pass"
        for text in all_defs:
            assert "\x00" not in text
            if "{" in text:
                assert text.count("{") == text.count("}"), text
