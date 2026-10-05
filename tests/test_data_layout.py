"""Tests for rebrew.data_layout — the shared .data placement model."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from rebrew.data_layout import (
    c_type_size,
    data_symbols,
    estimate_type_size,
    fill_data,
    hex_list,
    insert_definition,
    layout_geometry,
    owner_of,
    reference_counts,
)


def test_data_symbols(tmp_path: Path) -> None:
    meta = tmp_path / "rebrew-data.toml"
    meta.write_text(
        '["SERVER.0x10027000"]\nname = "g_a"\nsection = ".data"\n'
        '["SERVER.0x10027004"]\nname = "g_b"\nsection = ".bss"\n'
        '["SERVER.0x10027010"]\nname = "g_c"\nsection = ".data"\n',
        encoding="utf-8",
    )
    assert data_symbols(meta) == {"g_a": 0x10027000, "g_c": 0x10027010}


def test_layout_geometry(tmp_path: Path) -> None:
    pkg = tmp_path / "layout" / "game.dll"
    pkg.mkdir(parents=True)
    (pkg / "rebrew-layout.toml").write_text(
        "[layout]\n"
        'target = "game.dll"\n'
        "image_base = 268435456\n"
        'sections = [{ name = ".data", va = 98304, raw = 57344, vs = 24380828, ptr = 0, chars = 0 }]\n'
        "imports = []\n"
        "exports = []\n",
        encoding="utf-8",
    )
    toml = tmp_path / "rebrew-project.toml"
    toml.write_text('[project]\ndefault_target = "game.dll"\n', encoding="utf-8")
    base, raw_end, sec_end = layout_geometry(toml)
    assert base == 0x10018000  # 0x10000000 + 0x18000
    assert raw_end == 0x10026000
    assert sec_end == 0x10018000 + 0x174059C


def test_hex_list() -> None:
    assert hex_list(b"\x01\x02\x03\x04") == "{\n    0x01, 0x02, 0x03, 0x04,\n}"


def test_owner_of(tmp_path: Path) -> None:
    a = tmp_path / "a.c"
    b = tmp_path / "b.c"
    a.write_text("int g_x;\nint g_x;\n", encoding="utf-8")
    b.write_text("int g_x;\n", encoding="utf-8")
    assert owner_of(["g_x"], [a, b]) == a


def test_unreadable_source_fails_ownership_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unreadable TU must fail the scan, not drop out of the reference table.

    A skipped file looks unowned, so its globals get emitted into another unit
    while it keeps the definitions: duplicate globals at link time, from a run
    that reports edits and moved counts.
    """
    a = tmp_path / "a.c"
    b = tmp_path / "b.c"
    a.write_text("int g_x;\n", encoding="utf-8")
    b.write_text("int g_x;\n", encoding="utf-8")
    from rebrew.utils import read_source_text

    real = read_source_text

    def _boom(path: Any, *args: Any, **kwargs: Any) -> tuple[str, str]:
        if Path(path) == b:
            raise OSError(f"cannot read {path}")
        return real(path)

    monkeypatch.setattr("rebrew.data_layout.read_source_text", _boom)
    with pytest.raises(OSError, match="b.c"):
        reference_counts([a, b])
    with pytest.raises(OSError, match="b.c"):
        owner_of(["g_x"], [a, b])


def test_owner_of_reference_counts_match_the_scan(tmp_path: Path) -> None:
    """The one-pass word index agrees with the per-call alternation scan."""
    a = tmp_path / "a.c"
    b = tmp_path / "b.c"
    a.write_text("int g_x;\nint g_xy;\nint g_y;\n", encoding="utf-8")
    b.write_text("int g_y;\nint g_y;\nint g_x;\n", encoding="utf-8")
    files = [a, b]
    refs = reference_counts(files)
    for names in (["g_x"], ["g_y"], ["g_xy"], ["g_x", "g_y"], ["g_x", "g_x"]):
        assert owner_of(names, files, refs) == owner_of(names, files)
    # Equal counts: the earlier file wins, same as max() on insertion order.
    a.write_text("int g_z;\n", encoding="utf-8")
    b.write_text("int g_z;\n", encoding="utf-8")
    files = [a, b]
    refs = reference_counts(files)
    assert owner_of(["g_z"], files, refs) == a


def test_owner_of_reference_counts_keep_non_word_names(tmp_path: Path) -> None:
    """A ``$`` in the symbol still uses the alternation when an index is passed."""
    a = tmp_path / "a.c"
    b = tmp_path / "b.c"
    a.write_text("int foo$bar;\nint foo$bar;\n", encoding="utf-8")
    b.write_text("int foo$bar;\n", encoding="utf-8")
    files = [a, b]
    assert owner_of(["foo$bar"], files, reference_counts(files)) == a


def test_insert_definition(tmp_path: Path) -> None:
    f = tmp_path / "mod.c"
    f.write_text("extern int g_a[1];\n", encoding="utf-8")
    ok = insert_definition(f, "g_a", "unsigned char", 8, "{0x01,0x02,0x03,0x04}", dry_run=True)
    assert ok
    assert "unsigned char g_a[8]" not in f.read_text(encoding="utf-8")  # dry run
    ok = insert_definition(f, "g_a", "unsigned char", 8, "{0x01,0x02,0x03,0x04}", dry_run=False)
    assert ok
    text = f.read_text(encoding="utf-8")
    assert "unsigned char g_a[8] = {0x01,0x02,0x03,0x04};" in text


def test_insert_definition_rerun_does_not_duplicate(tmp_path: Path) -> None:
    """A second insert of the same name must replace, not append a twin def."""
    f = tmp_path / "mod.c"
    f.write_text("unsigned char g_a[4] = {0x01,0x02,0x03,0x04};\n", encoding="utf-8")
    ok = insert_definition(f, "g_a", "unsigned char", 4, "{0xaa,0xbb,0xcc,0xdd}", dry_run=False)
    assert ok
    text = f.read_text(encoding="utf-8")
    assert text.count("g_a[4]") == 1
    assert "unsigned char g_a[4] = {0xaa,0xbb,0xcc,0xdd};" in text
    # Identical re-run is a no-op write (still True — definition is present).
    assert insert_definition(f, "g_a", "unsigned char", 4, "{0xaa,0xbb,0xcc,0xdd}", dry_run=False)
    assert f.read_text(encoding="utf-8").count("unsigned char g_a[4]") == 1


def test_insert_definition_replaces_hex_bound(tmp_path: Path) -> None:
    """An extern or pad whose bound is not decimal is still that symbol.

    ``[0x10]`` did not match the digit bracket, so the insert appended a
    second line and left the extern in place.
    """
    extern = tmp_path / "mod.c"
    extern.write_text("extern unsigned char g_hex[0x10];\n", encoding="utf-8")
    assert insert_definition(extern, "g_hex", "unsigned char", 16, "{0}", dry_run=False)
    text = extern.read_text(encoding="utf-8")
    assert text.count("g_hex") == 1
    assert "unsigned char g_hex[16] = {0};" in text
    assert "extern" not in text

    pad = tmp_path / "pad.c"
    pad.write_text("unsigned char _dpad_1000[0x10];\n", encoding="utf-8")
    assert insert_definition(pad, "_dpad_1000", "unsigned char", 16, None, dry_run=False)
    pad_text = pad.read_text(encoding="utf-8")
    assert pad_text.count("_dpad_1000") == 1
    assert "unsigned char _dpad_1000[16];" in pad_text


def test_insert_definition_replaces_nested_bracket_bound(tmp_path: Path) -> None:
    """An extern whose bound contains a nested bracket is still that symbol.

    ``[sizeof(wchar_t[3])]`` stopped at the inner ``]``, so the insert
    appended a second line and left the extern in place.
    """
    extern = tmp_path / "mod.c"
    extern.write_text("extern char g_wide[sizeof(wchar_t[3])];\n", encoding="utf-8")
    assert insert_definition(extern, "g_wide", "char", 6, "{0}", dry_run=False)
    text = extern.read_text(encoding="utf-8")
    assert text.count("g_wide") == 1
    assert "char g_wide[6] = {0};" in text
    assert "extern" not in text


def test_insert_definition_replaces_pointer_to_array_extern(tmp_path: Path) -> None:
    """``extern char (*g_row)[4];`` is still the declaration of ``g_row``.

    The name sits inside parentheses, so the insert appended a second line
    and left the extern in place.
    """
    extern = tmp_path / "mod.c"
    extern.write_text("extern char (*g_row)[4];\n", encoding="utf-8")
    assert insert_definition(extern, "g_row", "char", 4, "{0}", dry_run=False)
    text = extern.read_text(encoding="utf-8")
    assert text.count("g_row") == 1
    assert "char g_row[4] = {0};" in text
    assert "extern" not in text


def test_insert_definition_replaces_pointer_to_array_definition(tmp_path: Path) -> None:
    """``char (*g_row)[4] = {0};`` is still the definition of ``g_row``.

    The name sits inside parentheses, so a re-run appended a second line.
    """
    f = tmp_path / "mod.c"
    f.write_text("char (*g_row)[4] = {0};\n", encoding="utf-8")
    assert insert_definition(f, "g_row", "char", 4, "{0}", dry_run=False)
    text = f.read_text(encoding="utf-8")
    assert text.count("g_row") == 1
    assert "char g_row[4] = {0};" in text


def test_insert_definition_replaces_parenthesized_pointer_array(tmp_path: Path) -> None:
    """``extern int (*table[4]);`` is still the declaration of ``table``.

    The brackets sit inside the parentheses, and ``int *table[4]`` glues the
    star to the name. Either spelling was left in place and a second
    definition was appended. ``(table[4])`` is the same array.
    """
    extern = tmp_path / "extern.c"
    extern.write_text("extern int (*table[4]);\n", encoding="utf-8")
    assert insert_definition(extern, "table", "int", 4, "{0}", dry_run=False)
    text = extern.read_text(encoding="utf-8")
    assert text.count("table") == 1
    assert "int table[4] = {0};" in text
    assert "extern" not in text

    defined = tmp_path / "defined.c"
    defined.write_text("int (*table[4]) = {0};\n", encoding="utf-8")
    assert insert_definition(defined, "table", "int", 4, "{0}", dry_run=False)
    def_text = defined.read_text(encoding="utf-8")
    assert def_text.count("table") == 1
    assert "int table[4] = {0};" in def_text

    bare = tmp_path / "bare.c"
    bare.write_text("extern int *table[4];\n", encoding="utf-8")
    assert insert_definition(bare, "table", "int", 4, "{0}", dry_run=False)
    bare_text = bare.read_text(encoding="utf-8")
    assert bare_text.count("table") == 1
    assert "int table[4] = {0};" in bare_text
    assert "extern" not in bare_text

    wrapped = tmp_path / "wrapped.c"
    wrapped.write_text("extern int (table[4]);\n", encoding="utf-8")
    assert insert_definition(wrapped, "table", "int", 4, "{0}", dry_run=False)
    wrapped_text = wrapped.read_text(encoding="utf-8")
    assert wrapped_text.count("table") == 1
    assert "int table[4] = {0};" in wrapped_text
    assert "extern" not in wrapped_text


def test_insert_definition_replaces_array_of_pointers_to_array(tmp_path: Path) -> None:
    """``extern int (*table[2])[3];`` is still the declaration of ``table``.

    The pointee brackets sat after the closing parenthesis, so the insert
    appended a second line and left the extern in place.
    """
    extern = tmp_path / "extern.c"
    extern.write_text("extern int (*table[2])[3];\n", encoding="utf-8")
    assert insert_definition(extern, "table", "int", 2, "{0}", dry_run=False)
    text = extern.read_text(encoding="utf-8")
    assert text.count("table") == 1
    assert "int table[2] = {0};" in text
    assert "extern" not in text

    bare = tmp_path / "bare.c"
    bare.write_text("int (*table[2])[3];\n", encoding="utf-8")
    assert insert_definition(bare, "table", "int", 2, "{0}", dry_run=False)
    bare_text = bare.read_text(encoding="utf-8")
    assert bare_text.count("table") == 1
    assert "int table[2] = {0};" in bare_text


def test_insert_definition_replaces_pointer_array_initializer(tmp_path: Path) -> None:
    """``int (*table[2])[3] = {0};`` is still the definition of ``table``.

    The pointee brackets sat after the closing parenthesis, so a re-run
    appended a second line.
    """
    defined = tmp_path / "mod.c"
    defined.write_text("int (*table[2])[3] = {0};\n", encoding="utf-8")
    assert insert_definition(defined, "table", "int", 2, "{0}", dry_run=False)
    text = defined.read_text(encoding="utf-8")
    assert text.count("table") == 1
    assert "int table[2] = {0};" in text


def test_insert_definition_rerun_no_init_pad(tmp_path: Path) -> None:
    """BSS/pad defs without ``=`` must not accumulate on re-run either."""
    f = tmp_path / "pad.c"
    f.write_text("unsigned char _dpad_1000[16];\n", encoding="utf-8")
    assert insert_definition(f, "_dpad_1000", "unsigned char", 16, None, dry_run=False)
    text = f.read_text(encoding="utf-8")
    assert text.count("_dpad_1000") == 1
    assert "unsigned char _dpad_1000[16];" in text


def test_insert_definition_preserves_shift_jis(tmp_path: Path) -> None:
    """Write-back must not UTF-8-rewrite a Shift-JIS TU (corrupting comments).

    Concrete input: Shift-JIS bytes for ``// 日本語`` (U+65E5 U+672C U+8A9E).
    Reading as UTF-8+replace then writing UTF-8 permanently replaced those
    bytes with U+FFFD; round-trip via read_source_text keeps them intact.
    """
    comment = "// \u65e5\u672c\u8a9e\n".encode("shift_jis")
    body = b"extern int g_a[1];\n" + comment
    f = tmp_path / "jp.c"
    f.write_bytes(body)
    ok = insert_definition(f, "g_a", "unsigned char", 4, "{0}", dry_run=False)
    assert ok
    raw = f.read_bytes()
    assert comment.strip() in raw  # original Shift-JIS comment bytes survive
    assert b"unsigned char g_a[4] = {0};" in raw
    assert b"\xef\xbf\xbd" not in raw  # no U+FFFD UTF-8 replacement


# ---------------------------------------------------------------------------
# Helpers: crafted minimal PE + layout metadata
# ---------------------------------------------------------------------------


def _make_pe(data_raw: bytes, image_base: int = 0x10000000, data_va: int = 0x18000) -> bytes:
    """A minimal PE32 whose .data section carries *data_raw* (raw at file 0x800)."""
    import struct

    pe_off = 0x40
    opt_size = 0xE0
    nsec = 1
    raw_ptr = 0x800
    size = raw_ptr + len(data_raw)
    d = bytearray(b"\0" * size)
    d[0:2] = b"MZ"
    struct.pack_into("<I", d, 0x3C, pe_off)
    struct.pack_into("<I", d, pe_off, 0x00004550)  # "PE\0\0"
    coff = pe_off + 4
    struct.pack_into("<H", d, coff, 0x14C)  # I386
    struct.pack_into("<H", d, coff + 2, nsec)
    struct.pack_into("<I", d, coff + 8, 0)  # symbols
    struct.pack_into("<H", d, coff + 16, opt_size)
    opt = coff + 20
    struct.pack_into("<H", d, opt, 0x10B)  # PE32 magic
    struct.pack_into("<I", d, opt + 28, image_base)
    sh = opt + opt_size
    d[sh : sh + 8] = b".data\0\0\0"
    struct.pack_into("<IIII", d, sh + 8, 0, data_va, len(data_raw), raw_ptr)
    d[raw_ptr : raw_ptr + len(data_raw)] = data_raw
    return bytes(d)


def _write_layout(tmp_path: Path, data_base: int, raw_size: int, vs: int) -> None:
    pkg = tmp_path / "layout" / "game.dll"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "rebrew-layout.toml").write_text(
        "[layout]\n"
        'target = "game.dll"\n'
        f"image_base = {data_base - 0x18000}\n"
        f'sections = [{{ name = ".data", va = 0x18000, raw = {raw_size}, vs = {vs}, ptr = 0, chars = 0 }}]\n'
        "imports = []\n"
        "exports = []\n",
        encoding="utf-8",
    )
    (tmp_path / "rebrew-project.toml").write_text(
        "[project]\n"
        'default_target = "game.dll"\n'
        '[targets."game.dll"]\n'
        'binary = "original/x.dll"\n'
        'reversed_dir = "src"\n',
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Scalar insert_definition + stub parsing
# ---------------------------------------------------------------------------


def test_insert_definition_scalar(tmp_path: Path) -> None:
    f = tmp_path / "mod.c"
    f.write_text("extern int g_a;\n", encoding="utf-8")
    ok = insert_definition(f, "g_a", "int", 4, "42", dry_run=False, is_array=False)
    assert ok
    assert "int g_a = 42;" in f.read_text(encoding="utf-8")


def test_parse_stub_globals(tmp_path: Path) -> None:
    from rebrew.data_layout import _parse_stub_globals

    stub = tmp_path / "link_stubs.c"
    stub.write_text(
        "int g_count = 0;\n"
        'char s_x[1] = "";\n'
        "char g_big[0x264264] = {0};\n"
        "int __cdecl foo(void) { return 0; }\n",
        encoding="utf-8",
    )
    parsed = _parse_stub_globals(stub)
    assert parsed["g_count"] == ("int", None)
    assert parsed["s_x"] == ("char", 1)
    assert parsed["g_big"] == ("char", 0x264264)
    assert "foo" not in parsed  # functions are not global defs


def test_parse_stub_globals_counts_zero_length_array_as_one(tmp_path: Path) -> None:
    """``T[0]`` is a flexible-array extension. estimate_type_size counts it as
    one element; the declarator parser must agree, or the symbol reaches the
    layout with size 0 and is silently dropped."""
    from rebrew.data_layout import _parse_stub_globals

    stub = tmp_path / "link_stubs.c"
    stub.write_text("int g_flex[0] = {0};\n", encoding="utf-8")
    assert _parse_stub_globals(stub)["g_flex"] == ("int", 1)


def test_parse_stub_globals_folds_constant_expression_bounds(tmp_path: Path) -> None:
    """A constant expression is a bound. ``estimate_type_size`` folds it; the
    stub parser must report the same element count, or ``data --own`` drops
    the symbol. A name (``[N]``) stays unknown."""
    from rebrew.data_layout import _parse_stub_globals, c_type_size, estimate_type_size

    stub = tmp_path / "link_stubs.c"
    stub.write_text(
        "unsigned char g_map[0x300 * 0x21c] = {0};\n"
        "unsigned short g_rows[(2 + 1) * 4][2] = {0};\n"
        "int g_named[N] = {0};\n",
        encoding="utf-8",
    )
    parsed = _parse_stub_globals(stub)

    def elements(type_str: str) -> int:
        base = type_str.split("[", 1)[0].strip()
        return estimate_type_size(type_str) // c_type_size(base)

    assert parsed["g_map"] == ("unsigned char", elements("unsigned char[0x300 * 0x21c]"))
    assert parsed["g_rows"] == (
        "unsigned short",
        elements("unsigned short[(2 + 1) * 4][2]"),
    )
    assert "g_named" not in parsed


def test_parse_stub_globals_accepts_nested_bracket_bound(tmp_path: Path) -> None:
    """A bound that contains brackets is still a definition.

    ``char g[sizeof(wchar_t[3])] = {0};`` stopped at the inner ``]``, so
    the symbol was dropped. ``int g[sizeof(int[2])]`` was dropped the same
    way.
    """
    from rebrew.data_layout import _parse_stub_globals

    stub = tmp_path / "link_stubs.c"
    stub.write_text(
        "char g_wide[sizeof(wchar_t[3])] = {0};\nint g_ints[sizeof(int[2])] = {0};\n",
        encoding="utf-8",
    )
    parsed = _parse_stub_globals(stub)
    assert parsed["g_wide"] == ("char", 6)
    assert parsed["g_ints"] == ("int", 8)


# ---------------------------------------------------------------------------
# Scalar literal rendering (float bit-exactness, non-finite handling)
# ---------------------------------------------------------------------------


def test_scalar_literal_float_emits_decimal_not_hex() -> None:
    """A FLOAT typedef must render as a float literal: an integer literal
    would be implicitly converted by C and silently change the value."""
    import struct

    from rebrew.data_layout import _scalar_literal

    assert _scalar_literal(struct.pack("<f", 123.0), "float", 4) == "123.0f"
    assert _scalar_literal(struct.pack("<f", 123.0), "FLOAT", 4) == "123.0f"
    assert _scalar_literal(struct.pack("<f", -2.5), "float", 4) == "-2.5f"


def test_scalar_literal_float_round_trips_bits() -> None:
    """The emitted literal re-parsed by a compiler (float(double(literal)))
    must reproduce the original 4 bytes exactly."""
    import struct

    from rebrew.data_layout import _scalar_literal

    for bits in (0x3DCCCCCD, 0x7F7FFFFF, 0x00000001, 0x80000000, 0x4B18967F):
        raw = struct.pack("<I", bits)
        lit = _scalar_literal(raw, "float", 4)
        assert lit is not None and lit.endswith("f")
        # A C compiler parses the decimal literal as double, then narrows.
        narrowed = struct.unpack("<f", struct.pack("<f", float(lit.rstrip("f"))))[0]
        assert struct.pack("<f", narrowed) == raw


def test_scalar_literal_non_finite_returns_none() -> None:
    """NaN/Inf have no C89 literal; an integer fallback would change the value."""
    import math
    import struct

    from rebrew.data_layout import _scalar_literal

    assert _scalar_literal(struct.pack("<I", 0x7FC00000), "float", 4) is None  # qNaN
    assert _scalar_literal(struct.pack("<I", 0x7F800000), "float", 4) is None  # inf
    assert _scalar_literal(struct.pack("<d", math.inf), "double", 8) is None
    assert _scalar_literal(struct.pack("<d", math.nan), "DOUBLE", 8) is None


def test_typed_array_literal_rejects_non_finite_element() -> None:
    import struct

    from rebrew.data_layout import typed_array_literal

    good = struct.pack("<f", 1.0)
    inf = struct.pack("<I", 0x7F800000)
    with pytest.raises(ValueError, match="no C89 literal"):
        typed_array_literal("float", good + inf)


def test_typed_array_literal_big_endian_target() -> None:
    """Big-endian targets (GameCube PPC, N64 MIPS) decode MSB-first."""
    import struct

    from rebrew.data_layout import typed_array_literal

    data = struct.pack(">HH", 1, 0x1234) + struct.pack(">f", 2.5)
    assert typed_array_literal("short", data[:4], ">") == ("{\n    1, 4660,\n}", 2)
    assert typed_array_literal("float", data[4:], ">") == ("{\n    2.5f,\n}", 1)


def test_own_data_globals_skips_nan_float_and_materializes_finite(tmp_path: Path) -> None:
    import struct

    from rebrew.data_layout import own_data_globals

    data_base = 0x10027000
    raw = (
        struct.pack("<f", 12.5)
        + struct.pack("<I", 0x7FC00000)  # NaN
        + b"\x00" * 24
    )
    binp = _own_fixture(tmp_path, raw, data_base)
    (tmp_path / "src" / "mod.c").write_text(
        "extern float g_ok;\nextern FLOAT g_nan;\n", encoding="utf-8"
    )
    meta = tmp_path / "rebrew-data.toml"
    meta.write_text(
        f'["SERVER.0x{data_base:x}"]\nname = "g_ok"\nsection = ".data"\ntype = "float"\n'
        f'["SERVER.0x{data_base + 4:x}"]\nname = "g_nan"\nsection = ".data"\ntype = "FLOAT"\n',
        encoding="utf-8",
    )
    stub = tmp_path / "src" / "link_stubs.c"
    stub.write_text("float g_ok = 0;\nFLOAT g_nan = 0;\n", encoding="utf-8")

    result = own_data_globals(tmp_path, meta, binp, tmp_path / "src", stub, dry_run=False)
    text = (tmp_path / "src" / "mod.c").read_text()
    assert "float g_ok = 12.5f;" in text
    assert "nanf" not in text.lower()
    assert "inff" not in text.lower()
    assert "g_nan" in result["skipped"]
    assert "FLOAT g_nan =" not in text


# ---------------------------------------------------------------------------
# data --fix-ownership (integration with a mingw-compiled COFF object)
# ---------------------------------------------------------------------------
# data --own
# ---------------------------------------------------------------------------


def _own_fixture(tmp_path: Path, raw: bytes, data_base: int) -> Path:
    _write_layout(tmp_path, data_base, len(raw), len(raw))
    (tmp_path / "original").mkdir(exist_ok=True)
    binp = tmp_path / "original" / "x.dll"
    binp.write_bytes(_make_pe(raw, image_base=data_base - 0x18000))
    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / "src" / "mod.c").write_text(
        "extern int g_count;\nextern char g_msg[1];\n", encoding="utf-8"
    )
    return binp


def test_own_data_globals_scalar_and_string(tmp_path: Path) -> None:
    from rebrew.data_layout import own_data_globals

    data_base = 0x10027000
    raw = b"\x2a\x00\x00\x00" + b"hello\x00" + b"\x00" * 20  # g_count=42, g_msg="hello"
    binp = _own_fixture(tmp_path, raw, data_base)
    meta = tmp_path / "rebrew-data.toml"
    meta.write_text(
        f'["SERVER.0x{data_base:x}"]\nname = "g_count"\nsection = ".data"\ntype = "int"\n'
        f'["SERVER.0x{data_base + 4:x}"]\nname = "g_msg"\nsection = ".data"\ntype = "char"\n',
        encoding="utf-8",
    )
    stub = tmp_path / "src" / "link_stubs.c"
    stub.write_text('int g_count = 0;\nchar g_msg[1] = "";\n', encoding="utf-8")

    result = own_data_globals(tmp_path, meta, binp, tmp_path / "src", stub, dry_run=True)
    assert result["owned"] == 2
    text = (tmp_path / "src" / "mod.c").read_text()
    assert "int g_count = 42;" not in text  # dry run

    result = own_data_globals(tmp_path, meta, binp, tmp_path / "src", stub, dry_run=False)
    assert result["owned"] == 2
    text = (tmp_path / "src" / "mod.c").read_text()
    assert "int g_count = 42;" in text
    assert "char g_msg[6] = {\n    0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x00,\n};" in text


def test_own_data_globals_skips_bss_and_unmapped(tmp_path: Path) -> None:
    from rebrew.data_layout import own_data_globals

    data_base = 0x10027000
    raw = b"\x2a\x00\x00\x00"
    binp = _own_fixture(tmp_path, raw, data_base)
    meta = tmp_path / "rebrew-data.toml"
    meta.write_text(
        f'["SERVER.0x{data_base:x}"]\nname = "g_count"\nsection = ".data"\ntype = "int"\n'
        f'["SERVER.0x10035000"]\nname = "g_bss_thing"\nsection = ".data"\ntype = "int"\n',
        encoding="utf-8",
    )
    stub = tmp_path / "src" / "link_stubs.c"
    stub.write_text(
        "int g_count = 0;\nint g_bss_thing = 0;\nint g_no_toml = 0;\n", encoding="utf-8"
    )
    result = own_data_globals(tmp_path, meta, binp, tmp_path / "src", stub, dry_run=True)
    assert result["owned"] == 1  # only g_count is in the initialized region
    assert "g_no_toml" in result["skipped"]


# ---------------------------------------------------------------------------
# data --fix-ownership (integration with a mingw-compiled COFF object)
# ---------------------------------------------------------------------------


def _mingw_obj(tmp_path: Path, name: str, body: str) -> Path:
    import shutil
    import subprocess

    cc = shutil.which("i686-w64-mingw32-gcc")
    if cc is None:
        pytest.skip("i686-w64-mingw32-gcc not available")
    d = tmp_path / "build" / "CMakeFiles" / "x.dir"
    d.mkdir(parents=True, exist_ok=True)
    src = tmp_path / f"{name}.c"
    src.write_text(body, encoding="utf-8")
    obj = d / f"{name}.obj"
    subprocess.run([cc, "-c", str(src), "-o", str(obj)], check=True, capture_output=True)
    return obj


def _write_rsp(tmp_path: Path, objs: list[Path]) -> None:
    rsp_dir = tmp_path / "build" / "CMakeFiles" / "x.dir"
    rsp_dir.mkdir(parents=True, exist_ok=True)
    entries = " ".join(f"CMakeFiles/x.dir/{o.name}" for o in objs)
    (rsp_dir / "objects1.rsp").write_text(entries, encoding="utf-8")


def test_fix_ownership_partitions_across_tus(tmp_path: Path) -> None:
    from rebrew.data_layout import fix_ownership

    data_base = 0x10027000
    obj_a = _mingw_obj(tmp_path, "a", "int g_a = 1;\nint g_ab = 2;\n")
    obj_b = _mingw_obj(tmp_path, "b", "int g_b = 3;\n")
    _write_rsp(tmp_path, [obj_a, obj_b])
    _write_layout(tmp_path, data_base, 0x1000, 0x1000)
    (tmp_path / "original").mkdir(exist_ok=True)
    binp = tmp_path / "original" / "x.dll"
    binp.write_bytes(_make_pe(b"\x00" * 0x1000))
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.c").write_text("int g_a = 1;\nint g_ab = 2;\n", encoding="utf-8")
    (src / "b.c").write_text("int g_b = 3;\n", encoding="utf-8")
    meta = tmp_path / "rebrew-data.toml"
    meta.write_text(
        f'["SERVER.0x{data_base:x}"]\nname = "g_a"\nsection = ".data"\ntype = "int"\n'
        f'["SERVER.0x{data_base + 4:x}"]\nname = "g_ab"\nsection = ".data"\ntype = "int"\n'
        f'["SERVER.0x{data_base + 0x1000:x}"]\nname = "g_b"\nsection = ".data"\ntype = "int"\n',
        encoding="utf-8",
    )
    result = fix_ownership(tmp_path, meta, binp, src, dry_run=True)
    assert "edits" in result
    # dry run: sources untouched
    assert "int g_a = 1;" in (src / "a.c").read_text()


def test_fix_ownership_sees_array_of_pointers_to_array(tmp_path: Path) -> None:
    """``int (*table[2])[3] = {0}`` is the definition of ``table``.

    The name sat inside the parentheses, so the scan did not own it.
    The symbol moved and the original definition stayed, leaving two
    definitions.
    """
    from rebrew.data_layout import fix_ownership

    data_base = 0x10027000
    # CMake names the object after the source (``a.c.obj``). A bare
    # ``a.obj`` does not map back to ``src/a.c``, so nothing is moved.
    obj_a = _mingw_obj(tmp_path, "a.c", "int g_a = 1;\n")
    obj_b = _mingw_obj(tmp_path, "b.c", "int g_b = 3;\n")
    _write_rsp(tmp_path, [obj_a, obj_b])
    _write_layout(tmp_path, data_base, 0x2000, 0x2000)
    (tmp_path / "original").mkdir(exist_ok=True)
    binp = tmp_path / "original" / "x.dll"
    binp.write_bytes(_make_pe(b"\x00" * 0x2000))
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.c").write_text(
        "int g_a = 1;\nint (*table[2])[3] = {0};\n",
        encoding="utf-8",
    )
    (src / "b.c").write_text("int g_b = 3;\n", encoding="utf-8")
    meta = tmp_path / "rebrew-data.toml"
    meta.write_text(
        f'["SERVER.0x{data_base:x}"]\nname = "g_a"\nsection = ".data"\ntype = "int"\n'
        f'["SERVER.0x{data_base + 0x1000:x}"]\nname = "table"\nsection = ".data"\ntype = "int"\n'
        f'["SERVER.0x{data_base + 0x1004:x}"]\nname = "g_b"\nsection = ".data"\ntype = "int"\n',
        encoding="utf-8",
    )
    fix_ownership(tmp_path, meta, binp, src, dry_run=False)
    a_text = (src / "a.c").read_text(encoding="utf-8")
    b_text = (src / "b.c").read_text(encoding="utf-8")
    assert "(*table[2])[3] =" not in a_text
    assert "table" in b_text
    assert b_text.count("table") == 1


def test_fix_ownership_keeps_pointer_array_extern(tmp_path: Path) -> None:
    """Moving ``int (*table[2])[3] = {0}`` leaves that declarator as an extern.

    The removal rebuilt ``extern int table[2];``. The pointer and the
    pointee ``[3]`` were gone, so the original file no longer declared
    an array of pointers to an array.
    """
    from rebrew.data_layout import fix_ownership

    data_base = 0x10027000
    obj_a = _mingw_obj(tmp_path, "a.c", "int g_a = 1;\n")
    obj_b = _mingw_obj(tmp_path, "b.c", "int g_b = 3;\n")
    _write_rsp(tmp_path, [obj_a, obj_b])
    _write_layout(tmp_path, data_base, 0x2000, 0x2000)
    (tmp_path / "original").mkdir(exist_ok=True)
    binp = tmp_path / "original" / "x.dll"
    binp.write_bytes(_make_pe(b"\x00" * 0x2000))
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.c").write_text(
        "int g_a = 1;\nint (*table[2])[3] = {0};\n",
        encoding="utf-8",
    )
    (src / "b.c").write_text("int g_b = 3;\n", encoding="utf-8")
    meta = tmp_path / "rebrew-data.toml"
    meta.write_text(
        f'["SERVER.0x{data_base:x}"]\nname = "g_a"\nsection = ".data"\ntype = "int"\n'
        f'["SERVER.0x{data_base + 0x1000:x}"]\nname = "table"\nsection = ".data"\ntype = "int"\n'
        f'["SERVER.0x{data_base + 0x1004:x}"]\nname = "g_b"\nsection = ".data"\ntype = "int"\n',
        encoding="utf-8",
    )
    fix_ownership(tmp_path, meta, binp, src, dry_run=False)
    a_text = (src / "a.c").read_text(encoding="utf-8")
    assert "extern int (*table[2])[3];" in a_text


def test_fix_ownership_keeps_const_pointer_array_extern(tmp_path: Path) -> None:
    """Moving ``int (* const table[2])[3] = {0}`` leaves that declarator.

    ``const`` sat between the star and the name, so the scan did not own
    ``table`` and the definition stayed in the original file.
    """
    from rebrew.data_layout import fix_ownership

    data_base = 0x10027000
    obj_a = _mingw_obj(tmp_path, "a.c", "int g_a = 1;\n")
    obj_b = _mingw_obj(tmp_path, "b.c", "int g_b = 3;\n")
    _write_rsp(tmp_path, [obj_a, obj_b])
    _write_layout(tmp_path, data_base, 0x2000, 0x2000)
    (tmp_path / "original").mkdir(exist_ok=True)
    binp = tmp_path / "original" / "x.dll"
    binp.write_bytes(_make_pe(b"\x00" * 0x2000))
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.c").write_text(
        "int g_a = 1;\nint (* const table[2])[3] = {0};\n",
        encoding="utf-8",
    )
    (src / "b.c").write_text("int g_b = 3;\n", encoding="utf-8")
    meta = tmp_path / "rebrew-data.toml"
    meta.write_text(
        f'["SERVER.0x{data_base:x}"]\nname = "g_a"\nsection = ".data"\ntype = "int"\n'
        f'["SERVER.0x{data_base + 0x1000:x}"]\nname = "table"\nsection = ".data"\ntype = "int"\n'
        f'["SERVER.0x{data_base + 0x1004:x}"]\nname = "g_b"\nsection = ".data"\ntype = "int"\n',
        encoding="utf-8",
    )
    fix_ownership(tmp_path, meta, binp, src, dry_run=False)
    a_text = (src / "a.c").read_text(encoding="utf-8")
    assert "extern int (* const table[2])[3];" in a_text


# ---------------------------------------------------------------------------
# data --converge / built_data_va
# ---------------------------------------------------------------------------


def test_built_data_va(tmp_path: Path) -> None:
    from rebrew.data_layout import built_data_va

    pe = _make_pe(b"\x00" * 64, image_base=0x10000000, data_va=0x18000)
    dll = tmp_path / "server.dll"
    dll.write_bytes(pe)
    assert built_data_va(dll) == 0x10018000


def test_converge_layout_single_tu(tmp_path: Path) -> None:
    from rebrew.data_layout import converge_layout

    data_base = 0x10027000
    obj_a = _mingw_obj(tmp_path, "a", "int g_a = 1;\n")
    _write_rsp(tmp_path, [obj_a])
    _write_layout(tmp_path, data_base, 0x1000, 0x1000)
    # The built DLL mirrors the single TU: .data raw carries g_a's 4 bytes.
    raw = b"\x01\x00\x00\x00"
    dll_dir = tmp_path / "build"
    dll_dir.mkdir(exist_ok=True)
    (dll_dir / "game.dll").write_bytes(_make_pe(raw, image_base=0x10000000, data_va=0x18000))
    (tmp_path / "original").mkdir(exist_ok=True)
    (tmp_path / "original" / "x.dll").write_bytes(_make_pe(raw))
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.c").write_text("int g_a = 1;\n", encoding="utf-8")
    meta = tmp_path / "rebrew-data.toml"
    meta.write_text(
        f'["SERVER.0x{data_base:x}"]\nname = "g_a"\nsection = ".data"\ntype = "int"\n',
        encoding="utf-8",
    )
    # expected (0x10027000) == current (build data_va + offset) — no pad needed.
    # The target matches the fixture's [targets."game.dll"] layout section: the
    # geometry is resolved per target now, so a name with no layout entry fails
    # loud instead of silently borrowing another target's numbers.
    result = converge_layout(
        tmp_path, meta, tmp_path / "original" / "x.dll", src, dry_run=True, target="game.dll"
    )
    assert result["adjustments"] == []


def test_converge_layout_resolves_target_from_config(tmp_path: Path) -> None:
    """The build output is ``build/<target>``, never hardcoded: with a
    ``default_target`` of game.dll only ``build/game.dll`` is consulted."""
    from rebrew.data_layout import _converge_target, converge_layout

    data_base = 0x10027000
    obj_a = _mingw_obj(tmp_path, "a", "int g_a = 1;\n")
    _write_rsp(tmp_path, [obj_a])
    pkg = tmp_path / "layout" / "game.dll"
    pkg.mkdir(parents=True)
    (pkg / "rebrew-layout.toml").write_text(
        "[layout]\n"
        'target = "game.dll"\n'
        f"image_base = {0x10000000}\n"
        'sections = [{ name = ".data", va = 0x18000, raw = 4096, vs = 4096, ptr = 0, chars = 0 }]\n'
        "imports = []\n"
        "exports = []\n",
        encoding="utf-8",
    )
    (tmp_path / "rebrew-project.toml").write_text(
        "[project]\n"
        'default_target = "game.dll"\n'
        '[targets."game.dll"]\n'
        'binary = "original/x.dll"\n'
        'reversed_dir = "src"\n',
        encoding="utf-8",
    )
    assert _converge_target(tmp_path, None) == "game.dll"
    assert _converge_target(tmp_path, "other.dll") == "other.dll"

    raw = b"\x01\x00\x00\x00"
    (tmp_path / "build").mkdir(exist_ok=True)
    (tmp_path / "build" / "game.dll").write_bytes(
        _make_pe(raw, image_base=0x10000000, data_va=0x18000)
    )
    (tmp_path / "original").mkdir(exist_ok=True)
    (tmp_path / "original" / "x.dll").write_bytes(_make_pe(raw))
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.c").write_text("int g_a = 1;\n", encoding="utf-8")
    meta = tmp_path / "rebrew-data.toml"
    meta.write_text(
        f'["SERVER.0x{data_base:x}"]\nname = "g_a"\nsection = ".data"\ntype = "int"\n',
        encoding="utf-8",
    )
    result = converge_layout(tmp_path, meta, tmp_path / "original" / "x.dll", src, dry_run=True)
    assert result["adjustments"] == []
    # no build/server.dll anywhere — the hardcoded name is gone
    assert not (tmp_path / "build" / "server.dll").exists()


def test_converge_layout_missing_output_names_target(tmp_path: Path) -> None:
    """The not-built error names the resolved output, not a hardcoded name."""
    from rebrew.data_layout import converge_layout

    _write_layout(tmp_path, 0x10027000, 0x1000, 0x1000)
    (tmp_path / "original").mkdir(exist_ok=True)
    binp = tmp_path / "original" / "x.dll"
    binp.write_bytes(_make_pe(b"\x00" * 16))
    meta = tmp_path / "rebrew-data.toml"
    meta.write_text("", encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    with pytest.raises(FileNotFoundError, match="build/game.dll"):
        converge_layout(tmp_path, meta, binp, src, target="game.dll")


# ---------------------------------------------------------------------------
# objdump failure surfacing (no silent zero sizes)
# ---------------------------------------------------------------------------


def test_obj_data_symbols_raises_on_bad_object(tmp_path: Path) -> None:
    from rebrew.data_layout import obj_data_symbols

    bad = tmp_path / "bad.obj"
    bad.write_text("this is not an object file\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="objdump -h failed"):
        obj_data_symbols(bad)


def test_audit_layout_records_objdump_error(tmp_path: Path) -> None:
    """A broken object must surface as a flagged row, not silent zeros."""
    from rebrew.data_layout import audit_layout

    bad = tmp_path / "bad.obj"
    bad.write_text("not an object\n", encoding="utf-8")
    _write_rsp(tmp_path, [bad])
    meta = tmp_path / "rebrew-data.toml"
    meta.write_text("", encoding="utf-8")
    report = audit_layout(tmp_path, meta)
    assert report["violations"] == 1
    (row,) = report["rows"]
    assert row["flags"] == ["OBJDUMP_ERROR"]
    assert "objdump" in row["error"]


# ---------------------------------------------------------------------------
# CRLF sources: definition spans must stay byte-exact
# ---------------------------------------------------------------------------


def test_find_definition_crlf_offsets() -> None:
    """Splice offsets must account for CRLF, not drift one byte per line."""
    from rebrew.data_layout import _find_definition

    text = "int g_a = 1;\r\nstatic char g_pad[4];\r\n\r\nint g_b = { 2, 3 };\r\n"
    r = _find_definition(text, "g_b")
    assert r is not None
    start, end, typ, sz = r
    assert typ == "int"
    assert sz == ""
    # The span must slice exactly the definition out of the CRLF text.
    assert text[start:end] == "int g_b = { 2, 3 };"

    s_a = _find_definition(text, "g_a")
    assert s_a is not None
    assert text[s_a[0] : s_a[1]] == "int g_a = 1;"


def test_find_definition_crlf_scalar_form() -> None:
    from rebrew.data_layout import _find_definition

    text = "extern int g_x;\r\nint g_y = 5;\r\nint g_z = 7;\r\n"
    r = _find_definition(text, "g_z")
    assert r is not None
    assert text[r[0] : r[1]] == "int g_z = 7;"


def test_find_definition_accepts_constant_bounds() -> None:
    """A hex, expression, or second dimension is still the definition.

    The bracket pattern was decimal digits only, so ``g[0x10]`` was not a
    definition and an ownership move could not find it to replace.
    """
    from rebrew.data_layout import _DEF_LINE_RE, _decl_info, _find_definition

    text = "int g_hex[0x10] = {1};\nint g_expr[2 + 2] = {1};\nint g_2d[2][4] = {1};\n"
    hex_def = _find_definition(text, "g_hex")
    assert hex_def is not None
    assert text[hex_def[0] : hex_def[1]] == "int g_hex[0x10] = {1};"
    assert hex_def[3] == "[0x10]"
    expr = _find_definition(text, "g_expr")
    assert expr is not None
    assert expr[3] == "[2 + 2]"
    two = _find_definition(text, "g_2d")
    assert two is not None
    assert two[3] == "[2][4]"
    assert _DEF_LINE_RE.match("int g_hex[0x10] = {1};") is not None
    assert _decl_info("extern unsigned char g_hex[0x10];\n", "g_hex") == (
        "extern unsigned char",
        16,
    )
    assert _decl_info("extern int g_2d[2][4];\n", "g_2d") == ("extern int", 8)
    assert _decl_info("extern int g_expr[2 + 2];\n", "g_expr") == ("extern int", 4)


def test_find_definition_accepts_nested_bracket_bound() -> None:
    """``g[sizeof(wchar_t[3])]`` is still that definition.

    The bracket pattern stopped at the inner ``]``, so an ownership move
    could not find the line. ``sizeof(int[2])`` is 8 elements.
    """
    from rebrew.data_layout import _DEF_LINE_RE, _decl_info, _find_definition

    text = "int g_wide[sizeof(wchar_t[3])] = {1};\nint g_ints[sizeof(int[2])] = {1};\n"
    wide = _find_definition(text, "g_wide")
    assert wide is not None
    assert wide[3] == "[sizeof(wchar_t[3])]"
    ints = _find_definition(text, "g_ints")
    assert ints is not None
    assert ints[3] == "[sizeof(int[2])]"
    assert _DEF_LINE_RE.match("int g_wide[sizeof(wchar_t[3])] = {1};") is not None
    assert _decl_info("extern char g_wide[sizeof(wchar_t[3])];\n", "g_wide") == (
        "extern char",
        6,
    )
    assert _decl_info("extern int g_ints[sizeof(int[2])];\n", "g_ints") == ("extern int", 8)


def test_decl_info_pointer_array_counts_every_element() -> None:
    """``extern int (*table[4])`` and ``extern int *table[4]`` are four pointers.

    The star is glued to the name, or the brackets sit inside the
    parentheses, so the declaration was invisible. ``[4]`` is the element
    count. ``extern char (*g_row)[4]`` stays one pointer.
    """
    from rebrew.data_layout import _decl_info

    assert _decl_info("extern int *table[4];\n", "table") == ("extern int *", 4)
    assert _decl_info("extern int (*table[4]);\n", "table") == ("extern int *", 4)
    assert _decl_info("extern char **ptrs[2];\n", "ptrs") == ("extern char **", 2)
    assert _decl_info("extern int (table[4]);\n", "table") == ("extern int", 4)
    assert _decl_info("extern char (*g_row)[4];\n", "g_row") == ("extern char", None)


def test_decl_info_pointer_to_array_is_not_an_array() -> None:
    """``extern char (*g_row)[4]`` declares one pointer.

    The name sits inside parentheses, so the declaration was invisible.
    ``[4]`` is the array that pointer addresses, not four elements.
    """
    from rebrew.data_layout import _decl_info

    assert _decl_info("extern char (*g_row)[4];\n", "g_row") == ("extern char", None)
    assert _decl_info("extern char (**g_ptrs)[4];\n", "g_ptrs") == ("extern char", None)
    assert _decl_info("extern int g_2d[2][4];\n", "g_2d") == ("extern int", 8)


def test_decl_info_array_of_pointers_to_array_counts_the_pointers() -> None:
    """``extern int (*table[2])[3]`` is two pointers.

    The pointee brackets sat after the closing parenthesis, so the
    declaration was invisible. ``[3]`` is the array each pointer addresses.
    ``extern char (*g_row)[4]`` stays one pointer.
    """
    from rebrew.data_layout import _decl_info

    assert _decl_info("extern int (*table[2])[3];\n", "table") == ("extern int *", 2)
    assert _decl_info("extern char (**rows[2])[4];\n", "rows") == ("extern char **", 2)
    assert _decl_info("extern char (*g_row)[4];\n", "g_row") == ("extern char", None)


def test_find_definition_sees_function_pointer_array() -> None:
    """``void (*cbs[4])(int) = {0}`` defines ``cbs``.

    The parameter list sat after the brackets, so the scan did not own
    the symbol. ``int (*table[2])[3] = {0}`` stays that definition.
    """
    from rebrew.data_layout import _DEF_LINE_RE, _find_definition

    line = "void (*cbs[4])(int) = {0};"
    matched = _DEF_LINE_RE.match(line)
    assert matched is not None
    assert (matched.group(1) or matched.group(2)) == "cbs"
    found = _find_definition(line + "\n", "cbs")
    assert found is not None
    assert line[found[0] : found[1]] == line
    calls = _DEF_LINE_RE.match("int (*table[4])(int) = {0};")
    assert calls is not None
    assert (calls.group(1) or calls.group(2)) == "table"
    plain = _DEF_LINE_RE.match("int (*table[2])[3] = {0};")
    assert plain is not None
    assert (plain.group(1) or plain.group(2)) == "table"
    scalar = _DEF_LINE_RE.match("int g_a = 1;")
    assert scalar is not None
    assert (scalar.group(1) or scalar.group(2)) == "g_a"


def test_find_definition_sees_cdecl_pointer_array() -> None:
    """``int (__cdecl *table[2])[3] = {0}`` defines ``table``.

    ``__cdecl`` sat before the star, so the symbol was not owned.
    ``void (__cdecl *cbs[4])(int) = {0}`` defines ``cbs``.
    ``int (*table[2])[3] = {0}`` stays that definition.
    """
    from rebrew.data_layout import _DEF_LINE_RE, _find_definition

    line = "int (__cdecl *table[2])[3] = {0};"
    matched = _DEF_LINE_RE.match(line)
    assert matched is not None
    assert (matched.group(1) or matched.group(2)) == "table"
    found = _find_definition(line + "\n", "table")
    assert found is not None
    assert line[found[0] : found[1]] == line
    calls = _DEF_LINE_RE.match("void (__cdecl *cbs[4])(int) = {0};")
    assert calls is not None
    assert (calls.group(1) or calls.group(2)) == "cbs"
    const = _DEF_LINE_RE.match("int (__cdecl * const table[2])[3] = {0};")
    assert const is not None
    assert (const.group(1) or const.group(2)) == "table"
    plain = _DEF_LINE_RE.match("int (*table[2])[3] = {0};")
    assert plain is not None
    assert (plain.group(1) or plain.group(2)) == "table"
    scalar = _DEF_LINE_RE.match("int g_a = 1;")
    assert scalar is not None
    assert (scalar.group(1) or scalar.group(2)) == "g_a"


def test_find_definition_sees_scalar_function_pointer() -> None:
    """``void (*cb)(int) = 0`` defines ``cb``.

    The initializer was not a brace list, so a move could not find the
    definition it already owned. ``void (__cdecl *cb)(int) = NULL`` is
    the same definition. ``int g_a = 1`` stays that definition.
    """
    from rebrew.data_layout import _find_definition

    line = "void (*cb)(int) = 0;"
    found = _find_definition(line + "\n", "cb")
    assert found is not None
    assert line[found[0] : found[1]] == line
    cdecl = "void (__cdecl *cb)(int) = NULL;"
    found_cc = _find_definition(cdecl + "\n", "cb")
    assert found_cc is not None
    assert cdecl[found_cc[0] : found_cc[1]] == cdecl
    braced = "void (*cb)(int) = {0};"
    found_br = _find_definition(braced + "\n", "cb")
    assert found_br is not None
    assert braced[found_br[0] : found_br[1]] == braced
    scalar_text = "int g_a = 1;\n"
    scalar = _find_definition(scalar_text, "g_a")
    assert scalar is not None
    assert scalar[2] == "int"
    assert scalar_text[scalar[0] : scalar[1]] == "int g_a = 1;"


def test_decl_info_function_pointer_array_counts_the_pointers() -> None:
    """``extern void (*cbs[4])(int)`` is four function pointers.

    The parameter list sat after the brackets, so the declaration was
    invisible. ``extern int (*table[2])[3]`` stays two pointers.
    """
    from rebrew.data_layout import _decl_info

    assert _decl_info("extern void (*cbs[4])(int);\n", "cbs") == ("extern void *", 4)
    assert _decl_info("extern int (*table[4])(int);\n", "table") == ("extern int *", 4)
    assert _decl_info("extern int (*table[2])[3];\n", "table") == ("extern int *", 2)
    assert _decl_info("extern char (*row)[4];\n", "row") == ("extern char", None)


def test_decl_info_cdecl_pointer_array_counts_the_pointers() -> None:
    """``extern int (__cdecl *table[2])[3]`` is two pointers.

    ``__cdecl`` sat before the star, so the declaration was invisible.
    ``extern char (__cdecl *row)[4]`` stays one pointer.
    ``extern void (__cdecl *cbs[4])(int)`` is four function pointers.
    """
    from rebrew.data_layout import _decl_info

    assert _decl_info("extern int (__cdecl *table[2])[3];\n", "table") == (
        "extern int __cdecl *",
        2,
    )
    assert _decl_info("extern int (__stdcall *table[2])[3];\n", "table") == (
        "extern int __stdcall *",
        2,
    )
    assert _decl_info("extern int (__cdecl * const table[2])[3];\n", "table") == (
        "extern int __cdecl * const",
        2,
    )
    assert _decl_info("extern void (__cdecl *cbs[4])(int);\n", "cbs") == (
        "extern void __cdecl *",
        4,
    )
    assert _decl_info("extern char (__cdecl *row)[4];\n", "row") == ("extern char", None)
    assert _decl_info("extern char (__cdecl * const row)[4];\n", "row") == (
        "extern char",
        None,
    )
    assert _decl_info("extern int (*table[2])[3];\n", "table") == ("extern int *", 2)
    assert _decl_info("extern int (* const table[2])[3];\n", "table") == (
        "extern int * const",
        2,
    )
    assert _decl_info("extern void (*cbs[4])(int);\n", "cbs") == ("extern void *", 4)
    assert _decl_info("extern char (*row)[4];\n", "row") == ("extern char", None)
    assert _decl_info("extern int (table[4]);\n", "table") == ("extern int", 4)


def test_decl_info_const_pointer_array_counts_the_pointers() -> None:
    """``extern int (* const table[2])[3]`` is two const pointers.

    ``const`` sat between the star and the name, so the declaration was
    invisible. ``extern char (* const row)[4]`` stays one pointer.
    """
    from rebrew.data_layout import _decl_info

    assert _decl_info("extern int (* const table[2])[3];\n", "table") == (
        "extern int * const",
        2,
    )
    assert _decl_info("extern int (* volatile table[2])[3];\n", "table") == (
        "extern int * volatile",
        2,
    )
    assert _decl_info("extern char (** const rows[2])[4];\n", "rows") == (
        "extern char ** const",
        2,
    )
    assert _decl_info("extern char (* const row)[4];\n", "row") == ("extern char", None)
    assert _decl_info("extern int (*table[2])[3];\n", "table") == ("extern int *", 2)
    assert _decl_info("extern int (table[4]);\n", "table") == ("extern int", 4)


def test_link_objects_cmake_rsp(tmp_path: Path) -> None:
    """CMake builds keep link order via build/CMakeFiles/*/objects*.rsp."""
    from rebrew.data_layout import link_objects

    rsp_dir = tmp_path / "build/CMakeFiles/game.dir"
    rsp_dir.mkdir(parents=True)
    (rsp_dir / "objects1.rsp").write_text(
        'CMakeFiles/game.dir/src/zed.c.obj "CMakeFiles/game.dir/src/alpha.c.obj" '
        "CMakeFiles/game.dir/src/mid.c.obj\n",
        encoding="utf-8",
    )
    objs = link_objects(tmp_path)
    assert objs == [
        tmp_path / "build" / "CMakeFiles/game.dir/src/zed.c.obj",
        tmp_path / "build" / "CMakeFiles/game.dir/src/alpha.c.obj",
        tmp_path / "build" / "CMakeFiles/game.dir/src/mid.c.obj",
    ]


def test_link_objects_cmake_rsp_backslash_paths(tmp_path: Path) -> None:
    """Wine/MSVC CMake rsp lines may use ``\\``; POSIX Path must still join."""
    from rebrew.data_layout import link_objects

    rsp_dir = tmp_path / "build/CMakeFiles/game.dir"
    rsp_dir.mkdir(parents=True)
    (rsp_dir / "objects1.rsp").write_text(
        r"CMakeFiles\game.dir\src\zed.c.obj CMakeFiles\game.dir\src\alpha.c.obj" + "\n",
        encoding="utf-8",
    )
    objs = link_objects(tmp_path)
    assert objs == [
        tmp_path / "build" / "CMakeFiles" / "game.dir" / "src" / "zed.c.obj",
        tmp_path / "build" / "CMakeFiles" / "game.dir" / "src" / "alpha.c.obj",
    ]


def test_obj_to_source_backslash_cmake_path(tmp_path: Path) -> None:
    """Object paths with embedded ``\\`` still resolve to the owning ``.c``."""
    from rebrew.data_layout import _obj_to_source

    src = tmp_path / "src" / "zed.c"
    src.parent.mkdir(parents=True)
    src.write_text("int zed(void) { return 0; }\n", encoding="utf-8")
    # Simulate a Path whose as_posix/str still carries backslashes from an rsp.
    obj = tmp_path / "build" / r"CMakeFiles\game.dir\src\zed.c.obj"
    got = _obj_to_source(obj, tmp_path, tmp_path / "src")
    assert got == src


def test_link_objects_makefile_out_fallback(tmp_path: Path) -> None:
    """Makefile builds (no rsp) fall back to out/*.obj in make's sorted order.

    Regression: verify-placement --built np_recompiled.exe on notepad's
    Makefile build errored 'no build/CMakeFiles/*/objects*.rsp found — build
    the project first' even though the project was built."""
    from rebrew.data_layout import link_objects

    out = tmp_path / "out"
    out.mkdir()
    for name in ("AddDefaultExtension", "AlertUser", "bss_padding"):
        (out / f"{name}.obj").write_bytes(b"")

    objs = link_objects(tmp_path)
    assert objs == [
        out / "AddDefaultExtension.obj",
        out / "AlertUser.obj",
        out / "bss_padding.obj",
    ]


def test_link_objects_makefile_build_fallback(tmp_path: Path) -> None:
    """build/*.obj is tried after out/ (and only when out/ has no objects)."""
    from rebrew.data_layout import link_objects

    build = tmp_path / "build"
    build.mkdir()
    (build / "zeta.obj").write_bytes(b"")
    (build / "alpha.obj").write_bytes(b"")
    objs = link_objects(tmp_path)
    assert objs == [build / "alpha.obj", build / "zeta.obj"]


def test_link_objects_missing_raises(tmp_path: Path) -> None:
    from rebrew.data_layout import link_objects

    with pytest.raises(FileNotFoundError, match="build the project first"):
        link_objects(tmp_path)


class TestObjSectionSymbols:
    def test_rdata_bucket(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.data_layout import obj_section_symbols

        def fake_run(obj: Path, flag: str) -> str:
            if flag == "-h":
                return "  1 .data  00000010\n  2 .rdata 00000008\n  3 .bss   00000004\n"
            assert flag == "-t"
            return (
                "[  1](sec  2)(fl 0x00)(ty 300)(scl 2) (nx 0) 0x00000000 _g_data\n"
                "[  2](sec  3)(fl 0x00)(ty 300)(scl 2) (nx 0) 0x00000000 _g_const\n"
                "[  3](sec  4)(fl 0x00)(ty 300)(scl 2) (nx 0) 0x00000000 _g_bss\n"
            )

        monkeypatch.setattr("rebrew.data_layout._run_objdump", fake_run)
        sizes, buckets = obj_section_symbols(tmp_path / "f.obj", ".data", ".bss", ".rdata")
        assert (sizes[".data"], sizes[".bss"], sizes[".rdata"]) == (0x10, 0x04, 0x08)
        assert buckets[".data"] == {"g_data"}
        assert buckets[".bss"] == {"g_bss"}
        assert buckets[".rdata"] == {"g_const"}

    def test_legacy_wrapper_unchanged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.data_layout import obj_data_symbols

        def fake_run(obj: Path, flag: str) -> str:
            if flag == "-h":
                return "  1 .data  00000010\n  2 .bss   00000004\n"
            assert flag == "-t"
            return "[  1](sec  2)(fl 0x00)(ty 300)(scl 2) (nx 0) 0x00000000 _g_data\n"

        monkeypatch.setattr("rebrew.data_layout._run_objdump", fake_run)
        assert obj_data_symbols(tmp_path / "f.obj") == (0x10, 0x04, {"g_data"}, set())

    def test_decorated_data_symbols_stay_distinct(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``lstrip("_")`` stored ``__g_foo`` and ``_g_foo`` as ``g_foo``.

        The C names are ``_g_foo`` and ``g_foo``. ``hook@@12`` is ``hook``.
        A cdecl ``_g_plain`` is still ``g_plain``.
        """
        from rebrew.data_layout import obj_data_symbol_offsets, obj_section_symbols

        def fake_run(obj: Path, flag: str) -> str:
            if flag == "-h":
                return "  1 .data  0000000c\n"
            assert flag == "-t"
            return (
                "[  1](sec  2)(fl 0x00)(ty 0)(scl 2) (nx 0) 0x00000000 __g_foo\n"
                "[  2](sec  2)(fl 0x00)(ty 0)(scl 2) (nx 0) 0x00000004 _g_foo\n"
                "[  3](sec  2)(fl 0x00)(ty 0)(scl 2) (nx 0) 0x00000008 hook@@12\n"
                "[  4](sec  2)(fl 0x00)(ty 0)(scl 2) (nx 0) 0x0000000c _g_plain\n"
            )

        monkeypatch.setattr("rebrew.data_layout._run_objdump", fake_run)
        _size, syms = obj_data_symbol_offsets(tmp_path / "f.obj")
        assert syms == {"_g_foo": 0, "g_foo": 4, "hook": 8, "g_plain": 12}
        _sizes, buckets = obj_section_symbols(tmp_path / "f.obj", ".data")
        assert buckets[".data"] == {"_g_foo", "g_foo", "hook", "g_plain"}


class TestObjdumpMemoBound:
    """The objdump memo is bounded by retained stdout, not by entry count."""

    def test_evicts_by_retained_chars(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.data_layout as dl

        calls: list[str] = []

        def fake_uncached(obj: Path, flag: str) -> str:
            calls.append(str(obj))
            return "x" * 2048

        monkeypatch.setattr(dl, "_run_objdump_uncached", fake_uncached)
        monkeypatch.setattr(dl, "_OBJDUMP_CACHE_MAX_CHARS", 4096)
        with dl._OBJDUMP_CACHE_LOCK:
            dl._OBJDUMP_CACHE.clear()
            dl._OBJDUMP_CACHE_CHARS = 0
        try:
            for i in range(4):
                obj = tmp_path / f"o{i}.obj"
                obj.write_bytes(b"obj")
                assert dl._run_objdump(obj, "-t") == "x" * 2048
            assert dl._OBJDUMP_CACHE_CHARS <= 4096
            assert len(dl._OBJDUMP_CACHE) < 4
            # A repeat read of the newest object is served from the memo.
            newest = tmp_path / "o3.obj"
            before = len(calls)
            assert dl._run_objdump(newest, "-t") == "x" * 2048
            assert len(calls) == before
        finally:
            with dl._OBJDUMP_CACHE_LOCK:
                dl._OBJDUMP_CACHE.clear()
                dl._OBJDUMP_CACHE_CHARS = 0


class TestObjdumpHexSpellings:
    """objdump emits uppercase and variable-width hex; the parsers must take
    every spelling (8-digit lowercase is just one)."""

    def test_section_sizes_uppercase(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.data_layout import _obj_section_sizes

        def fake_run(obj: Path, flag: str) -> str:
            assert flag == "-h"
            return "  1 .data  0000001A\n  2 .rdata DEADBEEF\n  3 .bss   4\n"

        monkeypatch.setattr("rebrew.data_layout._run_objdump", fake_run)
        _secname, sizes = _obj_section_sizes(tmp_path / "f.obj")
        assert sizes == {".data": 0x1A, ".rdata": 0xDEADBEEF, ".bss": 0x4}

    def test_symbols_uppercase_and_short(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.data_layout import obj_section_symbols

        def fake_run(obj: Path, flag: str) -> str:
            if flag == "-h":
                return "  1 .data  00000010\n"
            assert flag == "-t"
            return (
                "[  1](sec  2)(fl 0x00)(ty 300)(scl 2) (nx 0) 0x0000000A _g_upper\n"
                "[  2](sec  2)(fl 0x00)(ty 300)(scl 2) (nx 0) 0x4 _g_short\n"
                "[  3](sec  2)(fl 0x00)(ty 300)(scl 2) (nx 0) 00000000 _g_bare\n"
            )

        monkeypatch.setattr("rebrew.data_layout._run_objdump", fake_run)
        sizes, buckets = obj_section_symbols(tmp_path / "f.obj", ".data")
        assert sizes == {".data": 0x10}
        assert buckets[".data"] == {"g_upper", "g_short", "g_bare"}


class TestAuditLayoutSection:
    def test_rdata_audit(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.data_layout import audit_layout

        meta = tmp_path / "rebrew-data.toml"
        meta.write_text(
            '["SERVER.0x1000"]\nname = "g_c"\nsize = 4\nsection = ".rdata"\n'
            '["SERVER.0x2000"]\nname = "g_d"\nsize = 4\nsection = ".data"\n',
            encoding="utf-8",
        )

        def fake_run(obj: Path, flag: str) -> str:
            if flag == "-h":
                return "  1 .data  00000010\n  2 .rdata 00000008\n"
            assert flag == "-t"
            return (
                "[  1](sec  2)(fl 0x00)(ty 300)(scl 2) (nx 0) 0x00000000 _g_d\n"
                "[  2](sec  3)(fl 0x00)(ty 300)(scl 2) (nx 0) 0x00000004 _g_c\n"
            )

        import rebrew.data_layout as dl

        monkeypatch.setattr(dl, "_run_objdump", fake_run)
        monkeypatch.setattr(dl, "link_objects", lambda root: [tmp_path / "f.obj"])
        report = audit_layout(tmp_path, meta, ".rdata")
        assert report["violations"] == 0
        assert report["unowned"] == []
        row = report["rows"][0]
        assert row["dsyms"] == ["g_c"]
        assert row["bsyms"] == []


def test_converge_layout_preserves_source_encoding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A legacy-encoded TU must not be rewritten as UTF-8 (byte 0xA9 kept)."""
    from rebrew import data_layout as dl

    src = tmp_path / "src"
    src.mkdir()
    f = src / "a.c"
    # 0xA9 is a valid Shift-JIS/cp1252 byte but not valid UTF-8.
    f.write_bytes(b"// \xa9 note\n// FUNCTION: SERVER 0x10027000\nint g_a = 1;\n")

    build = tmp_path / "build"
    build.mkdir()
    (build / "server.dll").write_bytes(b"MZ")
    orig = tmp_path / "orig.dll"
    orig.write_bytes(b"\x00" * 0x40)

    data_base = 0x10027000
    monkeypatch.setattr(dl, "layout_geometry", lambda p, target=None: (data_base, 0x1000, 0x1000))
    monkeypatch.setattr(dl, "data_raw_from_binary", lambda p: b"\x00" * 0x40)
    monkeypatch.setattr(dl, "data_symbols", lambda m: {"g_a": data_base + 0x20})
    monkeypatch.setattr(dl, "_converge_target", lambda root, target: "server.dll")
    monkeypatch.setattr(dl, "built_data_va", lambda d: data_base)
    monkeypatch.setattr(dl, "link_objects", lambda root: [tmp_path / "a.obj"])
    monkeypatch.setattr(dl, "obj_data_symbol_offsets", lambda o: (0x10, {"g_a": 0}))
    monkeypatch.setattr(dl, "_obj_to_source", lambda o, root, src_dir: f)

    result = dl.converge_layout(
        tmp_path, tmp_path / "m.toml", orig, src, rounds=1, target="server.dll"
    )
    assert result["adjustments"], result
    raw = f.read_bytes()
    assert b"\xa9" in raw
    assert b"_dlead_a" in raw


def test_converge_layout_negative_delta_without_pad_leaves_tu_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A TU placed too late with no lead pad has nothing to shrink: no edit, every run."""
    from rebrew import data_layout as dl

    src = tmp_path / "src"
    src.mkdir()
    f = src / "a.c"
    original = b"// FUNCTION: SERVER 0x10027000\nint g_a = 1;\n"
    f.write_bytes(original)
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "server.dll").write_bytes(b"MZ")

    data_base = 0x10027000
    monkeypatch.setattr(dl, "layout_geometry", lambda p, target=None: (data_base, 0x1000, 0x1000))
    monkeypatch.setattr(dl, "data_raw_from_binary", lambda p: b"\x00" * 0x40)
    monkeypatch.setattr(dl, "data_symbols", lambda m: {"g_a": data_base})
    monkeypatch.setattr(dl, "_converge_target", lambda root, target: "server.dll")
    monkeypatch.setattr(dl, "built_data_va", lambda d: data_base)
    monkeypatch.setattr(dl, "link_objects", lambda root: [tmp_path / "a.obj"])
    monkeypatch.setattr(dl, "obj_data_symbol_offsets", lambda o: (0x10, {"g_a": 0x20}))
    monkeypatch.setattr(dl, "_obj_to_source", lambda o, root, src_dir: f)

    for _ in range(2):
        result = dl.converge_layout(
            tmp_path, tmp_path / "m.toml", tmp_path / "orig.dll", src, target="server.dll"
        )
        assert result["adjustments"] == []
    assert f.read_bytes() == original


def test_layout_geometry_honours_the_requested_target(tmp_path: Path) -> None:
    """A multi-target project must read the REQUESTED target's .data geometry.

    The old reader returned the first `[targets.*]` match, so
    `data --converge --target B` sized its pads against target A's data_base.
    """
    for target, base, va, raw, vs in [
        ("A", 4194304, 4096, 256, 512),
        ("B", 8388608, 8192, 1024, 2048),
    ]:
        pkg = tmp_path / "layout" / target
        pkg.mkdir(parents=True)
        (pkg / "rebrew-layout.toml").write_text(
            "[layout]\n"
            f'target = "{target}"\n'
            f"image_base = {base}\n"
            f'sections = [{{ name = ".data", va = {va}, raw = {raw}, vs = {vs}, ptr = 0, chars = 0 }}]\n'
            "imports = []\n"
            "exports = []\n",
            encoding="utf-8",
        )
    toml = tmp_path / "rebrew-project.toml"
    toml.write_text('[project]\ndefault_target = "A"\n', encoding="utf-8")
    # No target → the project default (A).
    assert layout_geometry(toml) == (0x400000 + 0x1000, 0x400000 + 0x1100, 0x400000 + 0x1200)
    # Explicit target → that target's numbers.
    assert layout_geometry(toml, "B") == (0x800000 + 0x2000, 0x800000 + 0x2400, 0x800000 + 0x2800)
    # Unknown target fails loud rather than borrowing another target's geometry.
    with pytest.raises(ValueError, match=r"no layout package"):
        layout_geometry(toml, "C")


def test_data_symbols_includes_bss_when_asked(tmp_path: Path) -> None:
    """`.bss` globals carry section=".bss"; a `.data`-only read drops them, so
    `--fill-data` never emitted BSS pads."""
    meta = tmp_path / "rebrew-data.toml"
    meta.write_text(
        '["T.0x1000"]\nname = "g_init"\nsection = ".data"\n'
        '["T.0x2000"]\nname = "g_zero"\nsection = ".bss"\n',
        encoding="utf-8",
    )
    assert data_symbols(meta) == {"g_init": 0x1000}
    assert data_symbols(meta, (".data", ".bss")) == {"g_init": 0x1000, "g_zero": 0x2000}


def test_fill_data_emits_bss_pads(tmp_path: Path) -> None:
    """`.bss` globals live past the raw end and must become zero-init pads.

    `fill_data` read the metadata with the default `section=".data"`, so every
    `.bss` symbol was filtered out before the region split: no BSS pad was ever
    emitted and `--bss-only` was a no-op.
    """
    raw = b"\x01\x00\x00\x00"
    data_base = 0x10027000
    _write_layout(tmp_path, data_base, 0x1000, 0x2000)  # vs > raw → BSS tail
    orig = tmp_path / "original"
    orig.mkdir(exist_ok=True)
    (orig / "x.dll").write_bytes(_make_pe(raw, image_base=0x10000000, data_va=0x18000))
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.c").write_text("int g_zero;\n", encoding="utf-8")
    meta = tmp_path / "rebrew-data.toml"
    # One `.bss` symbol PAST the raw end (raw_end = base + 0x1000) and well
    # before the section end: the gap to section_end becomes the zero-init pad.
    meta.write_text(
        f'["SERVER.0x{data_base + 0x1500:x}"]\nname = "g_zero"\nsection = ".bss"\ntype = "int"\n',
        encoding="utf-8",
    )
    result = fill_data(tmp_path, meta, tmp_path / "original" / "x.dll", src)
    assert result["bss_pads"] == 1, result
    assert "_dpad_" in (src / "a.c").read_text(encoding="utf-8")


class TestMergedDefinitionLine:
    def test_unsized_extern_array_takes_the_array_form(self) -> None:
        """An unsized `extern char g[];` plus a brace initializer used to emit
        `extern char g = { … };` — uncompilable C."""
        from rebrew.data_layout import _merged_definition_line

        out = _merged_definition_line(
            "extern char", None, "g_buf", "char g_buf[4] = {0x68, 1, 2, 3};"
        )
        assert out == "char g_buf[4] = {0x68, 1, 2, 3};"
        assert not out.startswith("extern")

    def test_sized_declaration_keeps_its_size(self) -> None:
        from rebrew.data_layout import _merged_definition_line

        out = _merged_definition_line("extern int", 8, "g_a", "int g_a[4] = {1, 2, 3, 4};")
        assert out == "int g_a[8] = {1, 2, 3, 4};"

    def test_scalar_initializer_stays_scalar(self) -> None:
        from rebrew.data_layout import _merged_definition_line

        assert _merged_definition_line("extern int", None, "g_a", "int g_a = 7;") == "int g_a = 7;"


class TestDataModeTarget:
    """`--fill-data`, `--own` and `--fix-ownership` must size against the
    requested target, not the project default (a multi-target project
    otherwise padded against another binary's `.data` geometry)."""

    def test_data_modes_forward_the_target_to_the_geometry(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.data_layout as dl

        seen: list[str | None] = []

        class _Probe(Exception):
            pass

        def _probe(toml: Path, target: str | None = None) -> tuple[int, int, int]:
            seen.append(target)
            raise _Probe

        monkeypatch.setattr(dl, "layout_geometry", _probe)
        meta = tmp_path / "rebrew-data.toml"
        meta.write_text('["A.0x1000"]\nname = "g"\nsection = ".data"\n', encoding="utf-8")
        stub = tmp_path / "link_stubs.c"
        stub.write_text("int g;\n", encoding="utf-8")
        src = tmp_path / "src"
        src.mkdir()
        binp = tmp_path / "x.dll"
        binp.write_bytes(b"MZ")

        with pytest.raises(_Probe):
            dl.fill_data(tmp_path, meta, binp, src, target="B")
        with pytest.raises(_Probe):
            dl.own_data_globals(tmp_path, meta, binp, src, stub, target="B")
        with pytest.raises(_Probe):
            dl.fix_ownership(tmp_path, meta, binp, src, target="B")
        assert seen == ["B", "B", "B"]


class TestSharedScans:
    """DATA tooling sees src/shared (DATA markers belong to every target)."""

    def test_scan_files_includes_shared(self, tmp_path: Path) -> None:
        from rebrew.data_layout import scan_files

        src = tmp_path / "src" / "V1"
        src.mkdir(parents=True)
        (src / "a.c").write_text("int a;\n", encoding="utf-8")
        shared = tmp_path / "src" / "shared"
        shared.mkdir(parents=True)
        (shared / "s.c").write_text("int s;\n", encoding="utf-8")
        files = scan_files(src, shared)
        assert (src / "a.c") in files
        assert (shared / "s.c") in files

    def test_scan_files_no_shared_unchanged(self, tmp_path: Path) -> None:
        from rebrew.data_layout import scan_files

        src = tmp_path / "src"
        src.mkdir(parents=True)
        (src / "a.c").write_text("int a;\n", encoding="utf-8")
        assert scan_files(src, None) == [src / "a.c"]
        assert scan_files(src, tmp_path / "nope") == [src / "a.c"]

    def test_own_materializes_in_shared_owner(self, tmp_path: Path) -> None:
        """--own finds the extern in a shared TU and defines it there."""
        import struct

        from rebrew.data_layout import own_data_globals

        data_base = 0x10027000
        raw = struct.pack("<i", 42) + b"\x00" * 20
        binp = _own_fixture(tmp_path, raw, data_base)
        shared = tmp_path / "src" / "shared"
        shared.mkdir(parents=True)
        (shared / "owner.c").write_text("extern int g_count;\n", encoding="utf-8")
        # The fixture's mod.c also declares it — remove so ownership is shared-only.
        (tmp_path / "src" / "mod.c").write_text("int unrelated;\n", encoding="utf-8")
        meta = tmp_path / "rebrew-data.toml"
        meta.write_text(
            f'["SERVER.0x{data_base:x}"]\nname = "g_count"\nsection = ".data"\ntype = "int"\n',
            encoding="utf-8",
        )
        stub = tmp_path / "src" / "link_stubs.c"
        stub.write_text("int g_count = 0;\n", encoding="utf-8")

        result = own_data_globals(
            tmp_path, meta, binp, tmp_path / "src", stub, dry_run=False, shared_dir=shared
        )
        assert result["owned"] == 1
        assert "int g_count = 42;" in (shared / "owner.c").read_text()


def test_find_dlead_pad() -> None:
    from rebrew.data_layout import _find_dlead_pad

    text = "// note\nunsigned char _dlead_foo[16] = {0x00, 0x01};\nint x = 0;\n"
    res = _find_dlead_pad(text)
    assert res is not None
    start, end, name, size, indent = res
    assert name == "_dlead_foo"
    assert size == 16
    assert indent == ""
    assert text[start:end] == "unsigned char _dlead_foo[16] = {0x00, 0x01};\n"

    multiline = "  unsigned char _dlead_bar[32] = {\n    0x01, 0x02\n  };\n"
    res2 = _find_dlead_pad(multiline)
    assert res2 is not None
    start2, end2, name2, size2, indent2 = res2
    assert name2 == "_dlead_bar"
    assert size2 == 32
    assert indent2 == "  "
    assert multiline[start2:end2] == multiline


def test_converge_layout_rerun_updates_existing_pad_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Running converge_layout twice updates the existing pad without duplicate declarations or syntax corruption."""
    from rebrew import data_layout as dl

    src = tmp_path / "src"
    src.mkdir()
    f = src / "a.c"
    f.write_text("// Header\n// FUNCTION: SERVER 0x10027000\nint g_a = 1;\n", encoding="utf-8")

    build = tmp_path / "build"
    build.mkdir()
    (build / "server.dll").write_bytes(b"MZ")
    orig = tmp_path / "orig.dll"
    orig.write_bytes(b"\x00" * 0x80)

    data_base = 0x10027000
    monkeypatch.setattr(dl, "layout_geometry", lambda p, target=None: (data_base, 0x1000, 0x1000))
    monkeypatch.setattr(dl, "data_raw_from_binary", lambda p: b"\xab" * 0x80)
    monkeypatch.setattr(dl, "_converge_target", lambda root, target: "server.dll")
    monkeypatch.setattr(dl, "built_data_va", lambda d: data_base)
    monkeypatch.setattr(dl, "link_objects", lambda root: [tmp_path / "a.obj"])
    monkeypatch.setattr(dl, "_obj_to_source", lambda o, root, src_dir: f)

    # Run 1: offset 0x20 -> needs pad of 32 bytes
    monkeypatch.setattr(dl, "data_symbols", lambda m: {"g_a": data_base + 0x20})
    monkeypatch.setattr(dl, "obj_data_symbol_offsets", lambda o: (0x10, {"g_a": 0}))

    r1 = dl.converge_layout(tmp_path, tmp_path / "m.toml", orig, src, rounds=1, target="server.dll")
    assert len(r1["adjustments"]) == 1
    content1 = f.read_text(encoding="utf-8")
    assert content1.count("_dlead_a") == 1
    assert "unsigned char _dlead_a[32] = " in content1
    assert "; = " not in content1  # No syntax corruption

    # Run 2: symbol moved further (offset 0x30; object has 32 byte pad -> delta 16 -> pad grows to 48 bytes)
    monkeypatch.setattr(dl, "data_symbols", lambda m: {"g_a": data_base + 0x30})
    monkeypatch.setattr(dl, "obj_data_symbol_offsets", lambda o: (0x30, {"g_a": 32}))
    r2 = dl.converge_layout(tmp_path, tmp_path / "m.toml", orig, src, rounds=1, target="server.dll")
    assert len(r2["adjustments"]) == 1
    content2 = f.read_text(encoding="utf-8")
    # Must update in place: single declaration, no duplicate, no dangling syntax
    assert content2.count("_dlead_a") == 1
    assert "unsigned char _dlead_a[48] = " in content2
    assert "; = " not in content2

    # Run 3: delta is 0 -> strict no-op, leaves content identical
    monkeypatch.setattr(dl, "obj_data_symbol_offsets", lambda o: (0x40, {"g_a": 48}))
    r3 = dl.converge_layout(tmp_path, tmp_path / "m.toml", orig, src, rounds=1, target="server.dll")
    assert len(r3["adjustments"]) == 0
    assert f.read_text(encoding="utf-8") == content2


def test_converge_layout_shrinks_to_zero_removes_pad(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When a pad shrinks to 0 on rerun, it is removed cleanly without leaving dangling syntax."""
    from rebrew import data_layout as dl

    src = tmp_path / "src"
    src.mkdir()
    f = src / "a.c"
    f.write_text(
        "// Header\nunsigned char _dlead_a[16] = {0x00};\nint g_a = 1;\n", encoding="utf-8"
    )

    build = tmp_path / "build"
    build.mkdir()
    (build / "server.dll").write_bytes(b"MZ")
    orig = tmp_path / "orig.dll"
    orig.write_bytes(b"\x00" * 0x80)

    data_base = 0x10027000
    monkeypatch.setattr(dl, "layout_geometry", lambda p, target=None: (data_base, 0x1000, 0x1000))
    monkeypatch.setattr(dl, "data_raw_from_binary", lambda p: b"\xab" * 0x80)
    monkeypatch.setattr(dl, "_converge_target", lambda root, target: "server.dll")
    monkeypatch.setattr(dl, "built_data_va", lambda d: data_base)
    monkeypatch.setattr(dl, "link_objects", lambda root: [tmp_path / "a.obj"])
    monkeypatch.setattr(dl, "_obj_to_source", lambda o, root, src_dir: f)

    # exp (0) - cur (0x20) = delta -32, old_size 16 -> new_size 0
    monkeypatch.setattr(dl, "data_symbols", lambda m: {"g_a": data_base})
    monkeypatch.setattr(dl, "obj_data_symbol_offsets", lambda o: (0x10, {"g_a": 0x20}))

    r = dl.converge_layout(tmp_path, tmp_path / "m.toml", orig, src, rounds=1, target="server.dll")
    assert len(r["adjustments"]) == 1
    content = f.read_text(encoding="utf-8")
    assert "_dlead_a" not in content
    assert "= {0x00};" not in content
    assert content == "// Header\nint g_a = 1;\n"


class TestLongLongSize:
    """`long long` is 8 bytes on every target; sizing it as 4 mis-strides a
    `long long` table so every element after the first is garbage."""

    def test_base_type_is_eight(self) -> None:
        for spelling in (
            "long long",
            "signed long long",
            "unsigned long long",
            "long long int",
            "unsigned long long int",
            "__int64",
        ):
            assert c_type_size(spelling) == 8, spelling

    def test_declarator_and_array(self) -> None:
        assert c_type_size("long long g_qpc") == 8
        assert c_type_size("static unsigned long long tbl[4]") == 8
        assert estimate_type_size("long long tbl[4]") == 32

    def test_narrower_types_unchanged(self) -> None:
        assert c_type_size("int") == 4
        assert c_type_size("long") == 4
        assert c_type_size("short") == 2
        assert c_type_size("char") == 1
        assert estimate_type_size("int tbl[4]") == 16

    def test_explicit_int_spellings_keep_their_width(self) -> None:
        from rebrew.data_layout import data_symbol_size

        for spelling in ("short int", "signed short int", "unsigned short int"):
            assert c_type_size(spelling) == 2
            assert data_symbol_size({"type": f"{spelling}[2 + 2]"}) == 8
        assert data_symbol_size({"type": "const unsigned long int[3]"}) == 12
        assert data_symbol_size({"type": "void*"}, arch="x86_64") == 0
        assert data_symbol_size({"type": "void*", "size": 8}, arch="x86_64") == 8


def test_data_symbol_size_pointer_to_array_is_a_pointer() -> None:
    """``char (*)[4]`` is one pointer. The bound is not a dimension.

    The parentheses made the extent unknown. An array of pointers stays
    16 bytes. A function pointer stays unknown. An explicit size wins.
    """
    from rebrew.data_layout import data_symbol_size

    assert data_symbol_size({"type": "char (*)[4]"}) == 4
    assert data_symbol_size({"type": "char (**)[4]"}) == 4
    assert data_symbol_size({"type": "char *[4]"}) == 16
    assert data_symbol_size({"type": "void (*)(int)"}) == 0
    assert data_symbol_size({"type": "char (*)[4]", "size": 8}) == 8


def test_data_symbol_size_sizeof_pointer_in_bound() -> None:
    """``(*)`` inside a bound is not the symbol's declarator.

    ``int[sizeof(char (*)[4])]`` was 4. ``char[sizeof(char *[2])]`` was 0.
    """
    from rebrew.data_layout import data_symbol_size

    assert data_symbol_size({"type": "int[sizeof(char (*)[4])]"}) == 16
    assert data_symbol_size({"type": "char[sizeof(char *[2])]"}) == 8
    assert data_symbol_size({"type": "char (*)[4]"}) == 4


def test_fix_ownership_rolls_back_when_a_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failure after the extern pass must not leave definitions stranded."""
    import rebrew.data_layout as dl

    data_base = 0x10027000
    obj_a = _mingw_obj(tmp_path, "a", "int g_a = 1;\nint g_ab = 2;\n")
    obj_b = _mingw_obj(tmp_path, "b", "int g_b = 3;\n")
    _write_rsp(tmp_path, [obj_a, obj_b])
    _write_layout(tmp_path, data_base, 0x1000, 0x1000)
    (tmp_path / "original").mkdir(exist_ok=True)
    binp = tmp_path / "original" / "x.dll"
    binp.write_bytes(_make_pe(b"\x00" * 0x1000))
    src = tmp_path / "src"
    src.mkdir()
    before = {"a.c": "int g_a = 1;\nint g_ab = 2;\n", "b.c": "int g_b = 3;\n"}
    for name, text in before.items():
        (src / name).write_text(text, encoding="utf-8")
    meta = tmp_path / "rebrew-data.toml"
    meta.write_text(
        f'["SERVER.0x{data_base:x}"]\nname = "g_a"\nsection = ".data"\ntype = "int"\n'
        f'["SERVER.0x{data_base + 4:x}"]\nname = "g_ab"\nsection = ".data"\ntype = "int"\n'
        f'["SERVER.0x{data_base + 0x1000:x}"]\nname = "g_b"\nsection = ".data"\ntype = "int"\n',
        encoding="utf-8",
    )

    real_write = dl.atomic_write_text
    seen: list[Path] = []

    def flaky(path: Path, text: str, **kwargs: Any) -> None:
        seen.append(path)
        # Let the first write through, then fail: the tree is mid-transaction.
        if len(seen) > 1:
            raise OSError("no space left on device")
        real_write(path, text, **kwargs)

    monkeypatch.setattr(dl, "atomic_write_text", flaky)
    with pytest.raises(OSError, match="no space left"):
        dl.fix_ownership(tmp_path, meta, binp, src)

    for name, text in before.items():
        assert (src / name).read_text(encoding="utf-8") == text, name


def test_fix_ownership_rollback_survives_a_non_oserror_restore_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A restore that raises something other than OSError must not abort the rest.

    Every ``atomic_write_text`` is its own commit, so a restore skipped partway
    through the rollback leaves a translation unit holding the extern form with
    the definition written nowhere: an undefined symbol at link time.  The
    rollback guards each restore individually for that reason, and the
    exception it is cleaning up after is the one most likely to land in the
    loop again.
    """
    import rebrew.data_layout as dl

    data_base = 0x10027000
    obj_a = _mingw_obj(tmp_path, "a", "int g_a = 1;\nint g_ab = 2;\n")
    obj_b = _mingw_obj(tmp_path, "b", "int g_b = 3;\n")
    _write_rsp(tmp_path, [obj_a, obj_b])
    _write_layout(tmp_path, data_base, 0x1000, 0x1000)
    (tmp_path / "original").mkdir(exist_ok=True)
    binp = tmp_path / "original" / "x.dll"
    binp.write_bytes(_make_pe(b"\x00" * 0x1000))
    src = tmp_path / "src"
    src.mkdir()
    before = {"a.c": "int g_a = 1;\nint g_ab = 2;\n", "b.c": "int g_b = 3;\n"}
    for name, text in before.items():
        (src / name).write_text(text, encoding="utf-8")
    meta = tmp_path / "rebrew-data.toml"
    meta.write_text(
        f'["SERVER.0x{data_base:x}"]\nname = "g_a"\nsection = ".data"\ntype = "int"\n'
        f'["SERVER.0x{data_base + 4:x}"]\nname = "g_ab"\nsection = ".data"\ntype = "int"\n'
        f'["SERVER.0x{data_base + 0x1000:x}"]\nname = "g_b"\nsection = ".data"\ntype = "int"\n',
        encoding="utf-8",
    )

    real_write = dl.atomic_write_text
    seen: list[Path] = []

    def flaky(path: Path, text: str, **kwargs: Any) -> None:
        seen.append(path)
        # Let the first write through, then interrupt the transaction, then
        # raise something that is not an OSError from inside the rollback.
        if len(seen) == 2:
            raise KeyboardInterrupt
        if len(seen) == 3:
            raise RuntimeError("rollback step blew up")
        real_write(path, text, **kwargs)

    monkeypatch.setattr(dl, "atomic_write_text", flaky)
    # The interrupt that aborted the transaction is what propagates, not the
    # restore's own RuntimeError.
    with pytest.raises(KeyboardInterrupt):
        dl.fix_ownership(tmp_path, meta, binp, src)

    for name, text in before.items():
        assert (src / name).read_text(encoding="utf-8") == text, name


def test_estimate_type_size_folds_complete_arithmetic_bounds() -> None:
    assert estimate_type_size("unsigned char[0x300 * 0x21c]") == 0x300 * 0x21C
    assert estimate_type_size("unsigned short[(2 + 1) * 4][2]") == 48
    assert estimate_type_size("extern char records[16 * 0xac];") == 16 * 0xAC
