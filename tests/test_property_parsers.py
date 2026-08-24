"""Property-based tests for pure parser/math helpers (hypothesis)."""

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer
from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.gen_flirt_pat import bytes_to_pat_line

if TYPE_CHECKING:
    from rebrew.catalog.models import GhidraDataLabel


@settings(max_examples=200, deadline=None)
@given(
    st.lists(
        st.binary(min_size=1, max_size=16),
        min_size=1,
        max_size=1,
    )
)
def test_bytes_to_pat_line_structure(code: list[bytes]) -> None:
    # min_size=1: an empty body degenerates the line format, and the
    # gen_flirt_pat main loop skips functions shorter than 4 bytes anyway.
    body = code[0]
    line = bytes_to_pat_line("_f", body, set())
    # Empty code → still a structurally valid line.
    parts = line.split()
    assert parts[-2] == ":0000"
    assert parts[-1] == "_f"
    lead = parts[0]
    assert len(lead) % 2 == 0  # hex pairs
    assert len(lead) == 2 * min(len(body), 32)
    # CRC length field matches the trailing-byte count.
    assert int(parts[1], 16) == min(max(len(body) - min(len(body), 32), 0), 255)


@given(st.binary(min_size=0, max_size=40), st.integers(min_value=0, max_value=7))
def test_bytes_to_pat_line_reloc_masking(code: bytes, reloc_byte: int) -> None:
    relocs = {reloc_byte} if reloc_byte < len(code) else set()
    line = bytes_to_pat_line("_f", code, relocs)
    lead = line.split()[0]
    # A masked byte yields ".." in the leading hex.
    if reloc_byte < min(len(code), 32):
        idx = reloc_byte * 2
        assert lead[idx : idx + 2] == ".."


# ---------------------------------------------------------------------------
# FLIRT .pat round-trip through python-flirt (the reader `rebrew flirt` uses)
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(
    st.binary(min_size=4, max_size=128),
    st.lists(st.integers(min_value=0, max_value=127), max_size=6),
)
def test_pat_line_roundtrip_matches(code: bytes, reloc_offsets: list[int]) -> None:
    """A .pat line written by bytes_to_pat_line must be readable and match the
    original function bytes via python-flirt (parse → compile → match).

    Regression: the old non-reflected-0x8005 CRC produced lines that parsed
    but never matched — silent false negatives for the whole FLIRT pipeline.
    """
    import flirt

    relocs = {r for r in reloc_offsets if r < len(code)}
    # Object-file reality: reloc slots hold 0 (the linker fills them later);
    # the writer zeroes them in the CRC window, so the matcher must see 0s.
    zeroed = bytearray(code)
    for r in relocs:
        zeroed[r] = 0
    obj = bytes(zeroed)

    line = bytes_to_pat_line("_f", obj, relocs)
    sigs = flirt.parse_pat(line + "\n---\n")
    matcher = flirt.compile(sigs)
    matches = matcher.match(obj)
    assert len(matches) == 1
    assert matches[0].names[0][0] == "_f"


@settings(max_examples=200, deadline=None)
@given(
    st.binary(min_size=4, max_size=128),
    st.lists(st.integers(min_value=0, max_value=127), max_size=6),
)
def test_pat_line_rejects_tampered_bytes(code: bytes, reloc_offsets: list[int]) -> None:
    """The signature must discriminate: tampering a byte inside the covered
    region (lead or CRC window) makes the match fail."""
    import flirt

    relocs = {r for r in reloc_offsets if r < len(code)}
    obj = bytearray(code)
    for r in relocs:
        obj[r] = 0
    # Covered region: the lead plus the CRC window, which the writer truncates
    # at the first tail relocation.  Bytes beyond it are unprotected by design.
    tail_relocs = [r for r in relocs if r >= 32]
    cover_end = tail_relocs[0] if tail_relocs else len(obj)
    candidates = [i for i in range(min(cover_end, len(obj))) if i not in relocs]
    if not candidates:
        return
    tampered = bytearray(obj)
    tampered[candidates[0]] ^= 0x01

    line = bytes_to_pat_line("_f", bytes(obj), relocs)
    sigs = flirt.parse_pat(line + "\n---\n")
    matches = flirt.compile(sigs).match(bytes(tampered))
    assert len(matches) == 0


# ---------------------------------------------------------------------------
# Annotation block parsing (rebrew.annotation)
# ---------------------------------------------------------------------------


@st.composite
def annotation_block(draw: st.DrawFn) -> tuple[list[str], int, str | None, int | None, str | None]:
    """A valid annotation block: marker + optional canonical keys + C body."""
    va = draw(st.integers(min_value=0, max_value=0xFFFFFFFF))
    lines = [f"// FUNCTION: SERVER 0x{va:08x}"]
    status: str | None = None
    size: int | None = None
    cflags: str | None = None
    if draw(st.booleans()):
        status = draw(
            st.sampled_from(["STUB", "EXACT", "RELOC", "NEAR_MATCHING", "PROVEN", "SKIP"])
        )
        lines.append(f"// STATUS: {status}")
    if draw(st.booleans()):
        size = draw(st.integers(min_value=1, max_value=1_000_000))
        lines.append(f"// SIZE: {size}")
    if draw(st.booleans()):
        cflags = draw(st.from_regex(r"/[A-Za-z0-9]+", fullmatch=True))
        lines.append(f"// CFLAGS: {cflags}")
    lines.append("int fn(void) { return 0; }")
    return lines, va, status, size, cflags


# ---------------------------------------------------------------------------
# c_parser declarator extraction (tree-sitter)
# ---------------------------------------------------------------------------

_RET_TYPES = ["int", "void", "char *", "unsigned int", "short", "unsigned short"]
_PARAM_TYPES = ["int", "char *", "unsigned int", "short", "void *"]


@st.composite
def _c_function_def(draw: Any) -> tuple[str, str]:
    """Draw (name, source) for a well-formed C function definition."""
    name = draw(st.from_regex(r"fn_[a-z][a-z0-9_]*", fullmatch=True))
    ret = draw(st.sampled_from(_RET_TYPES))
    n_params = draw(st.integers(min_value=0, max_value=3))
    params = ", ".join(f"{draw(st.sampled_from(_PARAM_TYPES))} p{i}" for i in range(n_params))
    body = "{}" if ret == "void" else "{ return 0; }"
    return name, f"{ret} {name}({params}) {body}"


@settings(max_examples=200, deadline=None)
@given(_c_function_def())
def test_extract_function_name_roundtrip(data: tuple[str, str]) -> None:
    """The name extracted from a generated definition must round-trip; the
    prototype must keep the name and end at the parameter list."""
    from rebrew.c_parser import extract_function_name_and_proto

    name, src = data
    result = extract_function_name_and_proto(src)
    assert result is not None
    got_name, proto = result
    assert got_name == name
    assert name in proto
    assert proto.endswith(")")


@settings(max_examples=200, deadline=None)
@given(
    st.lists(_c_function_def(), min_size=1, max_size=8),
)
def test_find_c_function_definitions_all_names(defs: list[tuple[str, str]]) -> None:
    """Every generated definition must be discovered with its own name and a
    strictly increasing 1-based line number."""
    from rebrew.c_parser import find_c_function_definitions

    # Ensure unique names so the count is deterministic.
    seen: set[str] = set()
    unique_defs: list[tuple[str, str]] = []
    for name, src in defs:
        if name not in seen:
            seen.add(name)
            unique_defs.append((name, src))
    if not unique_defs:
        return
    source = "\n".join(src for _name, src in unique_defs)
    results = find_c_function_definitions(source)
    found = {name for name, _line in results}
    assert found == {name for name, _src in unique_defs}
    lines = [line for _name, line in results]
    assert lines == sorted(lines)
    assert lines[0] >= 1


@settings(max_examples=200, deadline=None)
@given(_c_function_def())
def test_extract_function_name_from_line_roundtrip(data: tuple[str, str]) -> None:
    """A single-line definition (as found in decomp .c files) yields the same
    name via the line-based extractor."""
    from rebrew.c_parser import extract_function_name_from_line

    name, src = data
    line = src.split("{", 1)[0].strip()
    result = extract_function_name_from_line(line)
    assert result is not None
    got_name, proto = result
    assert got_name == name
    assert line in proto or proto == line


# ---------------------------------------------------------------------------
# FLIRT CRC16 (gen_flirt_pat._crc16_flirt)
# ---------------------------------------------------------------------------


def _crc16_independent(buf: bytes) -> int:
    """Independent derivation of IDA's FLIRT CRC16 (reflected poly 0x8408,
    init 0xFFFF, final bitwise invert, byte-swap) written in the standard
    byte-XOR shift-register form — a different formulation than the
    per-bit-input loop in gen_flirt_pat, so a transcription error in either
    derivation shows up as a mismatch."""
    if not buf:
        return 0
    crc = 0xFFFF
    for b in buf:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    crc = (~crc) & 0xFFFF
    return ((crc & 0xFF) << 8) | (crc >> 8)


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=256))
def test_crc16_flirt_matches_independent_derivation(buf: bytes) -> None:
    from rebrew.gen_flirt_pat import _crc16_flirt

    assert _crc16_flirt(buf) == _crc16_independent(buf)


@settings(max_examples=100, deadline=None)
@given(st.binary(max_size=256))
def test_crc16_flirt_domain(buf: bytes) -> None:
    from rebrew.gen_flirt_pat import _crc16_flirt

    assert 0 <= _crc16_flirt(buf) <= 0xFFFF


def test_crc16_flirt_known_vectors() -> None:
    """Pinned regression vectors for IDA's FLIRT CRC16 variant."""
    from rebrew.gen_flirt_pat import _crc16_flirt

    assert _crc16_flirt(b"") == 0x0
    assert _crc16_flirt(b"\x00") == 0x78F0
    assert _crc16_flirt(b"abc") == 0x259E
    assert _crc16_flirt(b"123456789") == 0x6E90
    assert _crc16_flirt(b"\xff" * 16) == 0xA92D
    assert _crc16_flirt(b"function_code\x00\x00") == 0x77D2


@settings(max_examples=200, deadline=None)
@given(annotation_block())
def test_annotation_block_roundtrip(
    data: tuple[list[str], int, str | None, int | None, str | None],
) -> None:
    from rebrew.annotation import parse_new_format

    lines, va, status, size, cflags = data
    ann = parse_new_format(lines)
    assert ann is not None
    assert ann.va == va
    assert ann.module == "SERVER"
    if status is not None:
        assert ann.status == status
    if size is not None:
        assert ann.size == size
    if cflags is not None:
        assert ann.cflags == cflags


@settings(max_examples=200, deadline=None)
@given(st.integers(min_value=0, max_value=0xFFFFFFFF))
def test_annotation_va_hex_roundtrip(va: int) -> None:
    """0x%08x formatting must round-trip through the marker regex."""
    from rebrew.annotation import parse_new_format

    ann = parse_new_format([f"// FUNCTION: SERVER 0x{va:08x}", "int fn(void) { return 0; }"])
    assert ann is not None
    assert ann.va == va


# ---------------------------------------------------------------------------
# C declarator parsing (rebrew.c_parser)
# ---------------------------------------------------------------------------

_C_KEYWORDS = frozenset(
    {
        "int",
        "void",
        "char",
        "long",
        "short",
        "unsigned",
        "signed",
        "struct",
        "union",
        "enum",
        "return",
        "if",
        "else",
        "for",
        "while",
        "static",
        "const",
    }
)


@st.composite
def c_function_source(draw: st.DrawFn) -> tuple[str, str]:
    """A C function definition and its expected name."""
    ret = draw(st.sampled_from(["int", "void", "char *", "unsigned int", "long", "float"]))
    name = draw(
        st.from_regex(r"[a-z][a-z0-9_]{0,12}", fullmatch=True).filter(
            lambda n: n not in _C_KEYWORDS
        )
    )
    params = draw(st.sampled_from(["void", "int x", "int a, int b", "char *s", "void *ctx", ""]))
    body = draw(st.sampled_from(["{ return 0; }", "{}", "{ return x; }", "{\n    return 0;\n}"]))
    return f"{ret} {name}({params}) {body}", name


@settings(max_examples=200, deadline=None)
@given(c_function_source())
def test_extract_function_name_matches(data: tuple[str, str]) -> None:
    from rebrew.c_parser import extract_function_name_and_proto

    source, expected = data
    result = extract_function_name_and_proto(source)
    assert result is not None, f"no definition parsed from {source!r}"
    name, proto = result
    assert name == expected
    assert proto.strip()


@settings(max_examples=200, deadline=None)
@given(c_function_source())
def test_find_c_function_definitions_contains_name(data: tuple[str, str]) -> None:
    from rebrew.c_parser import find_c_function_definitions

    source, expected = data
    names = [n for n, _line in find_c_function_definitions(source)]
    assert expected in names, f"{expected!r} not in {names} for {source!r}"


# ---------------------------------------------------------------------------
# Annotation parser robustness on malformed input (fuzz)
# ---------------------------------------------------------------------------

# Characters that ``str.splitlines`` treats as line boundaries beyond ``\n``.
# They are excluded from the generated alphabet so the join/splitlines
# round-trip stays exact and the partition invariant below is a true
# statement about the generated input text.
_SPLITLINES_BOUNDARY_CHARS = "\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"

_annotation_line = st.text(
    alphabet=st.characters(blacklist_characters=_SPLITLINES_BOUNDARY_CHARS),
    max_size=80,
)


@settings(max_examples=500, deadline=None)
@given(st.lists(_annotation_line, max_size=40))
def test_annotation_parsers_robust_on_malformed_lines(lines: list[str]) -> None:
    """Fuzz: arbitrary/malformed line lists must never crash the parsers.

    ``parse_new_format`` / ``parse_new_format_multi`` are regex-driven state
    machines over untrusted ``.c`` source; garbage lines — truncated markers,
    invalid hex VAs, control characters — must be tolerated without raising.
    Also asserts the ``split_annotation_sections`` partition invariant: the
    preamble + blocks must cover exactly the same line segments as the input
    (the orphan-KV rescue may reorder, but never drop or duplicate).
    """
    from collections import Counter

    from rebrew.annotation import (
        NEW_FUNC_CAPTURE_RE,
        parse_new_format,
        parse_new_format_multi,
        split_annotation_sections,
    )

    # Crash-freedom on all three entry points.
    parse_new_format(lines)
    parse_new_format_multi(lines)
    text = "\n".join(lines)
    preamble, blocks = split_annotation_sections(text)

    # Partition invariant (multiset of segments must be preserved).
    assert Counter(text.splitlines()) == Counter((preamble + "".join(blocks)).splitlines())

    # Every marker line opens exactly one block, and each block holds its marker.
    segments = text.splitlines()
    assert len(blocks) == sum(1 for ln in segments if NEW_FUNC_CAPTURE_RE.match(ln.strip()))
    for block in blocks:
        assert any(NEW_FUNC_CAPTURE_RE.match(ln.strip()) for ln in block.splitlines())


@st.composite
def lines_with_embedded_marker(draw: st.DrawFn) -> tuple[list[str], int]:
    """Arbitrary garbage lines with one valid ``// FUNCTION: FUZZ 0x...`` marker."""
    lines = draw(st.lists(_annotation_line, max_size=40))
    va = draw(st.integers(min_value=0, max_value=0xFFFFFFFF))
    marker = f"// FUNCTION: FUZZ 0x{va:08x}"
    pos = draw(st.integers(min_value=0, max_value=len(lines)))
    return lines[:pos] + [marker] + lines[pos:], va


@settings(max_examples=500, deadline=None)
@given(lines_with_embedded_marker())
def test_annotation_marker_survives_garbage(data: tuple[list[str], int]) -> None:
    """A valid marker embedded in garbage must parse with exact VA/module.

    Also guards against phantom annotations: every returned VA must come
    from an actual marker line in the input.
    """
    from rebrew.annotation import NEW_FUNC_CAPTURE_RE, parse_new_format_multi

    lines, va = data
    anns = parse_new_format_multi(lines)
    assert any(a.va == va and a.module == "FUZZ" for a in anns)

    marker_vas = {
        int(m.group("va"), 16) for ln in lines if (m := NEW_FUNC_CAPTURE_RE.match(ln.strip()))
    }
    for ann in anns:
        assert ann.va in marker_vas


# ---------------------------------------------------------------------------
# round_trip._rel32_target — REL32 displacement decoding
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(
    st.integers(min_value=0, max_value=2**24),
    st.integers(min_value=0, max_value=2**31 - 1),
    st.integers(min_value=0, max_value=0xFF),
)
def test_rel32_target_roundtrip(disp: int, fn_va: int, b0: int) -> None:
    """Decoding the disp bytes reproduces fn_va + offset + 4 + disp."""
    from rebrew.round_trip import _rel32_target

    # Build a blob with a REL32 field at offset 4: disp as little-endian int32.
    d = disp - (1 << 32) if disp >= (1 << 31) else disp  # allow negative disp
    packed = int(d & 0xFFFFFFFF).to_bytes(4, "little")
    blob = b"\x00" * 4 + packed + bytes([b0])
    assert _rel32_target(blob, 4, fn_va) == fn_va + 4 + 4 + d


@settings(max_examples=50, deadline=None)
@given(st.binary(max_size=64), st.integers(min_value=0, max_value=2**31))
def test_rel32_target_bounds(blob: bytes, fn_va: int) -> None:
    """A field past the end returns None; a complete field decodes to an int."""
    from rebrew.round_trip import _rel32_target

    result = _rel32_target(blob, 0, fn_va)
    if len(blob) < 4:
        assert result is None  # the 4-byte field lies past the end
    else:
        assert isinstance(result, int)


# ---------------------------------------------------------------------------
# catalog.sections.trim_trailing_padding — padding invariants
# ---------------------------------------------------------------------------


@settings(max_examples=100, deadline=None)
@given(st.binary(max_size=64))
def test_trim_trailing_padding_invariants(data: bytes) -> None:
    """Trimmed length ≤ len; stripped suffix is all padding; prefix is padding-free."""
    from rebrew.binary_loader import PADDING_BYTES
    from rebrew.catalog.sections import trim_trailing_padding

    n = trim_trailing_padding(data)
    assert 0 <= n <= len(data)
    assert all(b in PADDING_BYTES for b in data[n:])
    if n > 0:
        assert data[n - 1] not in PADDING_BYTES


# ---------------------------------------------------------------------------
# parse_va (rebrew.cli) — the shared hex-VA parser
# ---------------------------------------------------------------------------


@settings(max_examples=300, deadline=None)
@given(st.integers(min_value=0, max_value=0xFFFFFFFF))
def test_parse_va_hex_roundtrip(va: int) -> None:
    """0x%08x input must parse back to the same int."""
    from rebrew.cli import parse_va

    assert parse_va(f"0x{va:08x}") == va


@settings(max_examples=300, deadline=None)
@given(st.integers(min_value=0, max_value=0xFFFFFFFF))
def test_parse_va_prefix_invariance(va: int) -> None:
    """Bare hex (no 0x) parses identically — always base 16."""
    from rebrew.cli import parse_va

    bare = f"{va:x}"
    assert parse_va(bare) == va
    assert parse_va("0x" + bare) == va


@settings(max_examples=200, deadline=None)
@given(st.integers(min_value=0, max_value=0xFFFFFFFF))
def test_parse_va_whitespace_tolerance(va: int) -> None:
    from rebrew.cli import parse_va

    assert parse_va(f"  0x{va:08x}  ") == va


@settings(max_examples=100, deadline=None)
@given(st.text(alphabet="0123456789abcdefABCDEFxX", max_size=20))
def test_parse_va_invalid_rejects(raw: str) -> None:
    """parse_va must accept exactly what int(raw.strip(), 16) accepts: every
    VALID hex string parses to the same int, every INVALID one raises
    typer.Exit (error_exit) — never a bare exception."""
    import pytest

    from rebrew.cli import parse_va

    stripped = raw.strip()
    try:
        expected = int(stripped, 16)
    except ValueError:
        with pytest.raises(typer.Exit):
            parse_va(raw)
    else:
        assert parse_va(raw) == expected


# ---------------------------------------------------------------------------
# round_trip COFF .obj extraction helpers — structure-aware fuzz
# (_extract_local_labels, _extract_string_symbols)
# ---------------------------------------------------------------------------


@st.composite
def coff_obj_spec(draw: st.DrawFn) -> tuple[bytes, str, int, list[tuple[str, int]]]:
    """A valid COFF .obj spec: code, function symbol, its section offset, and
    a set of section-defined symbols (``$L``/``$SG``/``??_C@``/plain names)."""
    code = draw(st.binary(min_size=0, max_size=128))
    func_symbol = draw(st.from_regex(r"[A-Za-z_][A-Za-z0-9_]{0,7}", fullmatch=True))
    func_value = draw(st.integers(min_value=0, max_value=len(code)))
    n_syms = draw(st.integers(min_value=0, max_value=5))
    section_symbols: list[tuple[str, int]] = []
    used: set[str] = set()
    for _ in range(n_syms):
        kind = draw(st.sampled_from(["$L", "$SG", "??_C@", "plain"]))
        if kind == "$L":
            name = f"$L{draw(st.integers(min_value=0, max_value=99999))}"
        elif kind == "$SG":
            name = f"$SG{draw(st.integers(min_value=0, max_value=99999))}"
        elif kind == "??_C@":
            name = f"??_C@_0{draw(st.integers(min_value=0, max_value=99))}@X@t{draw(st.integers(min_value=0, max_value=99999))}@"
        else:
            name = draw(st.from_regex(r"[A-Za-z_][A-Za-z0-9_]{0,20}", fullmatch=True))
        if name in used:
            continue
        used.add(name)
        section_symbols.append((name, draw(st.integers(min_value=0, max_value=len(code)))))
    return code, func_symbol, func_value, section_symbols


@settings(max_examples=200, deadline=None)
@given(coff_obj_spec())
def test_extract_local_labels_invariants(
    data: tuple[bytes, str, int, list[tuple[str, int]]],
) -> None:
    """Fuzz: ``_extract_local_labels`` maps every ``$``-prefixed same-section
    label to exactly ``fn_va + (sym.value - fn.value)`` and nothing else."""
    from bin_util import make_coff_obj

    from rebrew.round_trip import _extract_local_labels

    code, func_symbol, func_value, section_symbols = data
    obj = make_coff_obj(
        code,
        func_symbol=func_symbol,
        func_value=func_value,
        section_symbols=section_symbols,
    )
    with tempfile.TemporaryDirectory() as td:
        obj_path = Path(td) / "x.obj"
        obj_path.write_bytes(obj)
        fn_va = 0x10001000
        out = _extract_local_labels(obj_path, func_symbol, fn_va)

    expected = {
        name: fn_va + (value - func_value)
        for name, value in section_symbols
        if name.startswith("$")
    }
    assert out == expected


@settings(max_examples=200, deadline=None)
@given(coff_obj_spec())
def test_extract_string_symbols_content_in_section(
    data: tuple[bytes, str, int, list[tuple[str, int]]],
) -> None:
    """Fuzz: every extracted string's content must appear verbatim in the
    section data at the symbol's own value (never garbage or OOB)."""
    from bin_util import make_coff_obj

    from rebrew.round_trip import _extract_string_symbols

    code, func_symbol, func_value, section_symbols = data
    obj = make_coff_obj(
        code,
        func_symbol=func_symbol,
        func_value=func_value,
        section_symbols=section_symbols,
    )
    with tempfile.TemporaryDirectory() as td:
        obj_path = Path(td) / "x.obj"
        obj_path.write_bytes(obj)
        symbol_names = {name for name, _value in section_symbols}
        out = _extract_string_symbols(obj_path, symbol_names)

    # make_coff_obj pads the section data to 4-byte alignment; the first NUL
    # (and hence the extracted content) may live in that padding.
    padded = code + b"\x00" * ((4 - len(code) % 4) % 4)
    by_value = dict(section_symbols)
    for name, content in out.items():
        value = by_value[name]
        assert content
        assert value + len(content) <= len(padded)
        assert padded[value : value + len(content)] == content
        # Content runs to the section's first NUL at/after value.
        end = padded.find(b"\x00", value)
        expected_len = (len(padded) - value) if end < 0 else end - value + 1
        assert len(content) == expected_len


def _mutate(obj: bytes) -> list[bytes]:
    """Deterministic malformed variants: truncations + single-byte flips."""
    variants: list[bytes] = []
    for k in (0, 1, 2, 5, 8, len(obj) // 2, len(obj) - 1):
        variants.append(obj[:k])
    for pos in range(min(len(obj), 8)):
        flipped = bytearray(obj)
        flipped[pos] ^= 0xFF
        variants.append(bytes(flipped))
    return variants


@settings(max_examples=100, deadline=None)
@given(coff_obj_spec())
def test_obj_helpers_robust_on_malformed(
    data: tuple[bytes, str, int, list[tuple[str, int]]],
) -> None:
    """Fuzz: truncated/corrupted .obj blobs must never make the extraction
    helpers raise — they degrade to empty results."""
    from bin_util import make_coff_obj

    from rebrew.round_trip import _extract_local_labels, _extract_string_symbols

    code, func_symbol, func_value, section_symbols = data
    obj = make_coff_obj(
        code,
        func_symbol=func_symbol,
        func_value=func_value,
        section_symbols=section_symbols,
    )
    with tempfile.TemporaryDirectory() as td:
        obj_path = Path(td) / "x.obj"
        for _i, variant in enumerate(_mutate(obj)):
            obj_path.write_bytes(variant)
            # Neither helper may raise on adversarial input.
            _extract_local_labels(obj_path, func_symbol, 0x10001000)
            _extract_string_symbols(obj_path, {name for name, _v in section_symbols})


# ---------------------------------------------------------------------------
# _name_encoded_va — Ghidra auto-name VA decoding
# ---------------------------------------------------------------------------


@settings(max_examples=300, deadline=None)
@given(st.integers(min_value=0, max_value=0xFFFFFFFF))
def test_name_encoded_va_roundtrip(va: int) -> None:
    """``_g_<hex>`` with a 6-8 digit suffix decodes back to the same VA."""
    from rebrew.round_trip import _name_encoded_va

    hex_digits = len(f"{va:x}")
    if va >= 0x100000 and 6 <= hex_digits <= 8:
        assert _name_encoded_va(f"_g_{va:x}") == va
    elif va < 0x100000:
        assert _name_encoded_va(f"_g_{va:x}") is None


@settings(max_examples=300, deadline=None)
@given(
    st.text(alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_", max_size=64)
)
def test_name_encoded_va_output_domain(raw: str) -> None:
    """The decoder returns None or an int that is actually encoded in the
    suffix — never a value invented from the prefix."""
    from rebrew.round_trip import _name_encoded_va

    out = _name_encoded_va(raw)
    if out is None:
        return
    assert out >= 0x100000
    # The trailing hex digits of the input must equal the decoded VA.
    m = __import__("re").search(r"([0-9a-fA-F]{6,8})$", raw)
    assert m is not None
    assert out == int(m.group(1), 16)


# ---------------------------------------------------------------------------
# catalog.grid — section/label lookup, status counting, grid reorder-invariance
# ---------------------------------------------------------------------------


@st.composite
def section_map(draw: st.DrawFn) -> dict[str, dict[str, int]]:
    """A dict of non-overlapping sections: {name: {va, size, fileOffset}}."""
    n = draw(st.integers(min_value=0, max_value=8))
    sections: dict[str, dict[str, int]] = {}
    cursor = draw(st.integers(min_value=0, max_value=0x1000))
    for i in range(n):
        size = draw(st.integers(min_value=1, max_value=0x2000))
        sections[f".sec{i}"] = {"va": cursor, "size": size, "fileOffset": cursor}
        cursor += size + draw(st.integers(min_value=0, max_value=0x1000))
    return sections


def _ref_lookup_section(
    sections: dict[str, dict[str, int]], va: int
) -> tuple[str, int, int] | None:
    """Reference: linear scan over the section dict."""
    for name, sd in sections.items():
        if sd["va"] <= va < sd["va"] + sd["size"]:
            return name, sd["fileOffset"] + (va - sd["va"]), va - sd["va"]
    return None


@settings(max_examples=200, deadline=None)
@given(section_map(), st.integers(min_value=0, max_value=0x20000))
def test_lookup_section_matches_reference(sections: dict[str, dict[str, int]], va: int) -> None:
    from rebrew.catalog.grid import _build_section_index, _lookup_section

    starts, info = _build_section_index(sections)
    result = _lookup_section(va, starts, info)
    expected = _ref_lookup_section(sections, va)
    assert result == expected, f"va=0x{va:x}: got {result}, want {expected}"


@st.composite
def label_map(draw: st.DrawFn) -> tuple[dict[int, "GhidraDataLabel"], list[tuple[int, int]]]:
    """Non-overlapping data labels: {va: label} plus their (va, va+size) spans."""
    from rebrew.catalog.models import GhidraDataLabel

    n = draw(st.integers(min_value=0, max_value=8))
    labels: dict[int, GhidraDataLabel] = {}
    spans: list[tuple[int, int]] = []
    cursor = draw(st.integers(min_value=0, max_value=0x1000))
    for i in range(n):
        size = draw(st.integers(min_value=1, max_value=0x200))
        labels[cursor] = GhidraDataLabel(va=cursor, size=size, label=f"L{i}", state="data")
        spans.append((cursor, cursor + size))
        cursor += size + draw(st.integers(min_value=0, max_value=0x1000))
    return labels, spans


@settings(max_examples=200, deadline=None)
@given(label_map(), st.integers(min_value=0, max_value=0x20000))
def test_find_ghidra_data_label_matches_reference(
    data: tuple[dict[int, "GhidraDataLabel"], list[tuple[int, int]]], va: int
) -> None:
    from rebrew.catalog.grid import _build_label_index, _find_ghidra_data_label

    labels, spans = data
    idx = _build_label_index(labels)
    result = _find_ghidra_data_label(va, idx)
    expected = next((s for s, e in spans if s <= va < e), None)
    if expected is None:
        assert result is None
    else:
        assert result is not None
        assert result[0] == expected  # the containing label's start VA


_STATUS_GROUP_PRIORITY = (
    ("EXACT",),
    ("RELOC",),
    ("NEAR_MATCHING", "NEAR_MATCH"),
    ("STUB",),
)
_STATUSES = ("STUB", "EXACT", "RELOC", "NEAR_MATCHING", "NEAR_MATCH", "PROVEN", "SKIP")


@st.composite
def status_map(draw: st.DrawFn) -> dict[int, list[str]]:
    """{va: [status, ...]} with random statuses and marker types."""
    n = draw(st.integers(min_value=0, max_value=12))
    out: dict[int, list[str]] = {}
    for _ in range(n):
        va = draw(st.integers(min_value=0, max_value=0xFFFF))
        statuses = draw(st.lists(st.sampled_from(_STATUSES), min_size=1, max_size=3))
        marker = draw(st.sampled_from(["FUNCTION", "GLOBAL", "DATA"]))
        if marker != "FUNCTION":
            statuses = ["STUB"]  # GLOBAL/DATA entries never count
        out[va] = statuses
    return out


@settings(max_examples=200, deadline=None)
@given(status_map())
def test_count_statuses_invariants(statuses: dict[int, list[str]]) -> None:
    """Every VA is counted at most once; EXACT beats STUB; PROVEN/SKIP never count."""
    from rebrew.catalog.grid import count_statuses

    # Convert to the annotation-dict shape count_statuses expects.
    by_va = {
        va: [{"marker_type": "FUNCTION", "status": s} for s in slist]
        for va, slist in statuses.items()
    }
    out = count_statuses(by_va)
    assert set(out) == {"EXACT", "RELOC", "NEAR_MATCHING", "STUB"}
    assert sum(out.values()) <= len(statuses)
    # EXACT outranks STUB wherever both appear for the same VA.
    for _va, slist in statuses.items():
        if "EXACT" in slist and "STUB" in slist:
            assert out["EXACT"] >= 1
    # Spot-check priority: a VA with EXACT+STUB counts under EXACT.
    probe = {
        0x10: [
            {"marker_type": "FUNCTION", "status": "EXACT"},
            {"marker_type": "FUNCTION", "status": "STUB"},
        ]
    }
    assert count_statuses(probe) == {"EXACT": 1, "RELOC": 0, "NEAR_MATCHING": 0, "STUB": 0}


@settings(max_examples=20, deadline=None)
@given(
    st.lists(
        st.sampled_from(["STUB", "EXACT", "RELOC", "NEAR_MATCHING", "PROVEN"]),
        min_size=2,
        max_size=2,
    )
)
def test_generate_data_json_reorder_invariant(statuses: list[str]) -> None:
    """Shuffling the entries/funcs input order must not change the grid output.

    The fixture PE (tests/fixtures/mini_pe.exe) supplies the real .text bytes,
    so the whole cell pipeline (sections, hashes, cells, absorption, summary)
    runs end-to-end without wine.
    """
    import random

    from rebrew.annotation import Annotation
    from rebrew.binary_loader import load_binary
    from rebrew.catalog.grid import generate_data_json

    fixtures = Path(__file__).parent / "fixtures"
    info = load_binary(fixtures / "mini_pe.exe")
    text = info.sections[".text"]
    text_start = text.va

    # Two functions inside .text with the generated statuses.
    vas = [text_start, text_start + 0x10]
    entries = [
        Annotation(
            va=vas[0],
            name="fn_a",
            symbol="_fn_a",
            module="SERVER",
            status=statuses[0],
            size=11,
            marker_type="FUNCTION",
            filepath="a.c",
            cflags="",
            blocker="",
            blocker_delta=None,
        ),
        Annotation(
            va=vas[1],
            name="fn_b",
            symbol="_fn_b",
            module="SERVER",
            status=statuses[1],
            size=10,
            marker_type="FUNCTION",
            filepath="b.c",
            cflags="",
            blocker="",
            blocker_delta=None,
        ),
    ]
    funcs = [{"va": vas[0], "size": 11}, {"va": vas[1], "size": 10}]
    kwargs = {
        "text_size": text.size,
        "bin_path": fixtures / "mini_pe.exe",
        "registry": None,
        "src_dir": None,
        "root_dir": None,
    }

    base = generate_data_json(entries, funcs, **kwargs)
    for _ in range(3):
        rng = random.Random(_)
        shuffled_entries = list(entries)
        rng.shuffle(shuffled_entries)
        shuffled_funcs = list(funcs)
        rng.shuffle(shuffled_funcs)
        assert generate_data_json(shuffled_entries, shuffled_funcs, **kwargs) == base

    # Every entry with a resolvable size inside .text is emitted.
    assert f"0x{vas[0]:08x}" in base["functions"]
    assert f"0x{vas[1]:08x}" in base["functions"]


@settings(max_examples=100, deadline=None)
@given(st.binary(min_size=1, max_size=64))
def test_code_relocs_are_valid_slots(code: bytes) -> None:
    """The 16-bit reloc scan (omf16._code_relocs) must always return
    distinct, in-bounds offsets — never overlapping positions or out-of-
    range indices, on arbitrary bytes."""
    from rebrew.matcher.omf16 import _code_relocs

    relocs = _code_relocs(code, 0, len(code))
    assert len(relocs) == len(set(relocs))  # no duplicate offsets
    for off, kind in relocs.items():
        assert 0 <= off < len(code)
        # a 2-byte reloc slot must not overrun the code
        assert off + 2 <= len(code)
        assert kind in ("rel16", "disp16", "far16")
    # every reloc slot's first byte is a real opcode position: e8/e9 for
    # rel16, an absolute-operand instruction for disp16
    for off, kind in relocs.items():
        if kind == "rel16":
            assert code[off - 1] in (0xE8, 0xE9)


# ---------------------------------------------------------------------------
# catalog/grid._build_cells — coverage-cell invariants
# ---------------------------------------------------------------------------


def _contiguous_segments(
    lengths: list[int], states: list[str]
) -> list[tuple[int, int, str, list[Any], None, None]]:
    """Build contiguous (start, end) segments with per-segment states."""
    out = []
    cur = 0
    for ln, state in zip(lengths, states, strict=True):
        out.append((cur, cur + ln, state, [], None, None))
        cur += ln
    return out


@given(
    st.lists(st.integers(min_value=1, max_value=500), min_size=1, max_size=12),
    st.integers(min_value=1, max_value=64),
    st.integers(min_value=1, max_value=16),
)
def test_build_cells_cover_contiguously(lengths: list[int], unit_bytes: int, columns: int) -> None:
    """Cells tile the section exactly: no gaps, no overlap, no overrun."""
    import math

    from rebrew.catalog.grid import _build_cells

    total = sum(lengths)
    states = ["code"] * len(lengths)
    cells = _build_cells(_contiguous_segments(lengths, states), unit_bytes, columns)

    assert cells, "non-empty section must produce cells"
    assert cells[0]["start"] == 0
    for i in range(len(cells) - 1):
        a, b = cells[i], cells[i + 1]
        assert a["end"] == b["start"], "cells must be contiguous"
    assert cells[-1]["end"] == total, "cells must cover the whole section"

    for c in cells:
        assert c["start"] < c["end"]
        expected_span = max(1, math.ceil((c["end"] - c["start"]) / unit_bytes))
        assert c["span"] == expected_span
        assert c["span"] <= columns, "a cell must not exceed the row width"


@given(
    st.lists(st.integers(min_value=1, max_value=300), min_size=1, max_size=10),
    st.sampled_from(["code", "gap", "padding", "data"]),
    st.integers(min_value=1, max_value=32),
    st.integers(min_value=1, max_value=8),
)
def test_build_cells_preserve_segment_state(
    lengths: list[int], state: str, unit_bytes: int, columns: int
) -> None:
    """Every cell keeps the state of the segment it was carved from."""
    from rebrew.catalog.grid import _build_cells

    cells = _build_cells(_contiguous_segments(lengths, [state] * len(lengths)), unit_bytes, columns)
    assert cells
    assert all(c["state"] == state for c in cells)
