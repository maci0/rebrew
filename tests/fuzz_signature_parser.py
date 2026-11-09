"""Atheris (libFuzzer) target: C signature and struct scanners.

Coverage-guided sibling of tests/test_property_signature_parser.py and
tests/test_property_c_parser.py (Hypothesis drives those harnesses in CI;
this file is the libFuzzer entry point for local/OSSFuzz runs).

``rebrew.signature_parser`` and ``rebrew.struct_parser`` read untrusted C
source — decompiler and LLM output that mixes MSVC extensions,
function-pointer parameters, and non-UTF-8 bytes — and re-emit text that
Ghidra's ``CParser`` / ``parse-c-structure`` must accept.  Arbitrary bytes
must never raise, and every emitted signature / definition must satisfy
the postcondition the normalizers promise: Ghidra-safe, balanced, and
round-trippable through the tree-sitter parser.

    uv run --frozen --group fuzz --group dev python tests/fuzz_signature_parser.py <corpus_dir> [flags]
    uv run --frozen --group fuzz --group dev python tests/fuzz_signature_parser.py tests/fixtures/signature_parser -runs=1000

Seed corpus: tests/fixtures/signature_parser/minimal.c (a real committed
shape, never production traffic) plus one truncated / hostile variant.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import atheris

from rebrew.c_parser import get_ts_parser
from rebrew.signature_parser import extract_function_prototypes, extract_function_signatures
from rebrew.struct_parser import (
    extract_enums_from_file,
    extract_structs_from_file,
    extract_type_blocks,
    extract_type_definitions,
)

#: Constructs Ghidra's CParser rejects, so ``_normalize_signature`` must
#: remove all of them.  Same banned surface as
#: tests/test_property_signature_parser.py.
_BANNED_RE = re.compile(
    r"\b(?:__cdecl|__stdcall|__fastcall|__thiscall|__declspec|const|volatile|RBW_\w+)\b"
)

#: Smallest real translation unit: one definition, one struct, one typedef.
_MINIMAL = (
    b"void __cdecl foo(const int a) { return; }\n"
    b"struct Bar { int x; char y; };\n"
    b"typedef struct Baz { int z; } Baz_t;\n"
)


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


def _assert_signature_invariants(name: str, sig: str) -> None:
    """The Ghidra-safety postcondition ``_normalize_signature`` promises.

    Tree-sitter error recovery can expose a truncated declarator (an
    unterminated comment swallowed the closing paren), yielding an
    unbalanced span.  That span is still emitted downstream as data, not a
    crash; the hard invariants are that it never raises, stays one
    NUL-free line, and carries no banned MSVC syntax.
    """
    assert name, f"empty function name in {sig!r}"
    assert "\n" not in sig and "\r" not in sig, sig
    assert "\x00" not in sig, sig
    assert not sig.endswith((";", " ")), sig
    assert "  " not in sig, sig
    assert not sig.startswith((" ", "\t")), sig
    leaked = _BANNED_RE.search(sig)
    assert leaked is None, f"{leaked.group(0)!r} survived in {sig!r}"
    assert "(*" not in sig, sig


def _assert_definition_invariants(text: str) -> None:
    """A span handed to Ghidra's ``parse-c-structure`` is balanced and NUL-free."""
    assert "{" in text and "}" in text, text
    assert _balanced_parens(text), text
    assert text.count("{") == text.count("}"), text
    assert "\x00" not in text, text


def TestOneInput(data: bytes) -> None:
    """Scanners must never raise on arbitrary bytes; emitted text is Ghidra-safe.

    Pair assertion across the trust boundary: the file-path scanners and the
    single-walk ``extract_type_blocks`` must agree on exactly the same bytes
    (one walk classifies every block, so the three views cannot disagree),
    and re-running on the same file yields identical results.
    """
    if get_ts_parser() is None:
        return
    if not data:
        data = _MINIMAL
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "fuzz.c"
        path.write_bytes(data)

        # Signature surface.
        sigs = list(extract_function_signatures(path))
        for name, sig in sigs:
            _assert_signature_invariants(name, sig)
        # Determinism on exactly the same bytes.
        assert list(extract_function_signatures(path)) == sigs
        # Prototype surface shares the same normalizer.
        protos = list(extract_function_prototypes(path))
        for proto in protos:
            assert "\n" not in proto and "\r" not in proto, proto
            assert "\x00" not in proto, proto
            leaked = _BANNED_RE.search(proto)
            assert leaked is None, f"{leaked.group(0)!r} survived in {proto!r}"

        # Struct / typedef / enum surfaces.
        structs = list(extract_structs_from_file(path))
        for text in structs:
            _assert_definition_invariants(text)
        all_defs = list(extract_type_definitions(path))
        for text in structs:
            assert text in all_defs, f"{text!r} missing from the all-typedefs pass"
        for text in all_defs:
            assert "\x00" not in text, text
            if "{" in text:
                assert text.count("{") == text.count("}"), text
        enums = list(extract_enums_from_file(path))
        for text in enums:
            _assert_definition_invariants(text)

        # Pair: the single-walk classifier agrees with the three passes.
        blocks_structs, blocks_typedefs, blocks_enums = extract_type_blocks(path)
        assert blocks_structs == structs, (blocks_structs, structs)
        assert blocks_typedefs == all_defs, (blocks_typedefs, all_defs)
        assert blocks_enums == enums, (blocks_enums, enums)
        # Truncation can only shrink the definition set to a subset.
        if len(data) > 1:
            path.write_bytes(data[: len(data) // 2])
            truncated = list(extract_structs_from_file(path))
            assert all(t in structs for t in truncated), (truncated, structs)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
