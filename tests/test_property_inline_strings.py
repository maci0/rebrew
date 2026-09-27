"""Property-based fuzz for ``rebrew.inline_strings.c_literal``.

``c_literal`` is a trust boundary: bytes lifted out of the untrusted target
binary are re-emitted as a C string literal and written into a ``.c`` file
that is then compiled.  A literal that leaks a raw quote, a backslash, a
newline, or an octal escape that runs into a following digit breaks the
build or, worse, splices source.  These harnesses assert the round-trip
decode of the emitted literal equals the input bytes, and drive the two
rewriting entry points end to end over fuzzed payloads.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.c_parser import get_ts_parser
from rebrew.inline_strings import c_literal, define_remaining_strings, inline_string_uses

#: Bytes a C string literal must never carry raw: ``"`` and ```` \ ```` end or
#: continue the literal, the rest are whitespace or bytes a compiler folds.
_ILLEGAL_RAW = frozenset({0x00, 0x07, 0x08, 0x0A, 0x0B, 0x0C, 0x0D, 0x1A, 0x1B, 0x22, 0x5C})

_OCTAL = frozenset("01234567")

#: A string global is NUL-terminated in the binary, so an embedded NUL would
#: truncate the read: the fuzzed payload carries every other byte value.
_payload = st.binary(min_size=1, max_size=40).filter(lambda b: b"\x00" not in b)

_SIMPLE_ESCAPES = {
    "n": 0x0A,
    "r": 0x0D,
    "t": 0x09,
    "b": 0x08,
    "a": 0x07,
    "f": 0x0C,
    "v": 0x0B,
    "?": 0x3F,
    "\\": 0x5C,
    "'": 0x27,
    '"': 0x22,
}


def _decode_literal(literal: str) -> bytes:
    """Decode a C string literal the way a compiler would, escapes included.

    Deliberately independent of :func:`c_literal`: sharing the encoder here
    would make the round-trip assertion pass by construction.
    """
    assert literal.startswith('"') and literal.endswith('"'), literal
    body = literal[1:-1]
    out = bytearray()
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            assert ord(ch) not in _ILLEGAL_RAW, f"raw {ord(ch):#04x} in {literal!r}"
            out.extend(ch.encode("latin-1"))
            i += 1
            continue
        i += 1
        assert i < len(body), f"trailing backslash in {literal!r}"
        esc = body[i]
        if esc in _OCTAL:
            digits = ""
            # A C octal escape is at most three digits; more is a syntax error.
            while i < len(body) and len(digits) < 3 and body[i] in _OCTAL:
                digits += body[i]
                i += 1
            out.append(int(digits, 8) & 0xFF)
            continue
        assert esc in _SIMPLE_ESCAPES, f"unknown escape \\{esc} in {literal!r}"
        out.append(_SIMPLE_ESCAPES[esc])
        i += 1
    return bytes(out)


@settings(max_examples=500, deadline=None)
@given(st.binary(min_size=0, max_size=64))
def test_c_literal_roundtrips_arbitrary_bytes(data: bytes) -> None:
    """Any byte string, including NULs, quotes, backslashes, and 0x80-0xFF.

    ``_decode_literal`` rejects raw control bytes, trailing backslashes, and
    unknown escapes, so a literal that would not survive the preprocessor
    fails the decode rather than the round-trip comparison.
    """
    assert _decode_literal(c_literal(data)) == data


@settings(max_examples=300, deadline=None)
@given(st.binary(min_size=1, max_size=32))
def test_c_literal_octal_escape_is_not_greedy(data: bytes) -> None:
    """A leading-zero escape must not absorb a following octal digit.

    ``b"\\x01" + b"1"`` decodes as ``\\017`` (0x0F) under a one-or-two digit
    octal escape; ``c_literal`` emits fixed three-digit octal, so the byte
    after the escape is unambiguous no matter what follows.
    """
    for tail in (b"1", b"7", b"77", b"777"):
        payload = b"\x01" + tail
        assert c_literal(payload) == '"\\001' + tail.decode("ascii") + '"'
        assert _decode_literal(c_literal(payload)) == payload


@settings(max_examples=60, deadline=None)
@given(st.text(max_size=24), _payload)
def test_inline_string_uses_writes_compilable_source(name: str, payload: bytes) -> None:
    """The full rewrite path: fuzzed binary bytes land in a ``.c`` file.

    The written file must still parse as a C translation unit with no error
    nodes, and the literal recovered from that source must decode back to the
    bytes that were lifted out of the binary.
    """
    result = get_ts_parser()
    if result is None:
        return
    parser, _ = result

    safe = re.sub(r"[^A-Za-z0-9_]", "_", name) or "s"
    va = 0x10027000
    token_re = re.compile(rf"\bs_{safe}_([0-9a-fA-F]{{6,8}})\b")
    src = f"int f(void) {{ return s_{safe}_{va:08x}[0]; }}\n"
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "a.c"
        path.write_text(src, encoding="utf-8")
        assert inline_string_uses(path, payload + b"\x00", va, token_re, {}, dry_run=False) == 1
        text = path.read_text(encoding="utf-8")
        # The rewrite never breaks out of the line it edited.
        assert text.count("\n") == 1
        assert parser.parse(text.encode("utf-8")).root_node.has_error is False
        lit = text.strip().removeprefix("int f(void) { return ").removesuffix("[0]; }")
        assert _decode_literal(lit) == payload


@settings(max_examples=60, deadline=None)
@given(st.text(max_size=16), _payload)
def test_define_remaining_strings_keeps_declaration_shape(name: str, payload: bytes) -> None:
    """``define_remaining_strings`` writes ``char s_x[N] = "...";``.

    The array is ``len + 1`` so the trailing NUL stays inside the object, and
    the initializer must decode to exactly the string body, not the body plus
    its terminator.
    """
    safe = re.sub(r"[^A-Za-z0-9_]", "_", name) or "s"
    va = 0x10027000
    tok = f"s_{safe}_{va:08x}"
    src = f"extern char {tok}[];\nint f(void) {{ return {tok}[0]; }}\n"
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "a.c"
        path.write_text(src, encoding="utf-8")
        # The token regex carries the VA as group 1; that is how the function
        # resolves the address of the extern it is about to define.
        token_re = re.compile(rf"\bs_{safe}_([0-9a-fA-F]{{6,8}})\b")
        assert define_remaining_strings([path], payload + b"\x00", va, token_re, dry_run=False) == 1
        decl = path.read_text(encoding="utf-8").splitlines()[0]
        assert decl.startswith(f"char {tok}[{len(payload) + 1}] = ")
        lit = decl.removeprefix(f"char {tok}[{len(payload) + 1}] = ").removesuffix(";")
        assert _decode_literal(lit) == payload
