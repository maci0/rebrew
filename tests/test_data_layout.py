"""Tests for rebrew.data_layout — the shared .data placement model."""

from __future__ import annotations

from pathlib import Path

import pytest

from rebrew.data_layout import (
    data_symbols,
    hex_list,
    insert_definition,
    layout_geometry,
    owner_of,
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
    toml = tmp_path / "rebrew-project.toml"
    toml.write_text(
        '[targets."game.dll".layout]\n'
        "image_base = 268435456\n"
        'sections = [{ name = ".data", va = 98304, raw = 57344, vs = 24380828 }]\n',
        encoding="utf-8",
    )
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


def test_insert_definition(tmp_path: Path) -> None:
    f = tmp_path / "mod.c"
    f.write_text("extern int g_a[1];\n", encoding="utf-8")
    ok = insert_definition(f, "g_a", "unsigned char", 8, "{0x01,0x02,0x03,0x04}", dry_run=True)
    assert ok
    assert "unsigned char g_a[8]" not in f.read_text()  # dry run
    ok = insert_definition(f, "g_a", "unsigned char", 8, "{0x01,0x02,0x03,0x04}", dry_run=False)
    assert ok
    text = f.read_text()
    assert "unsigned char g_a[8] = {0x01,0x02,0x03,0x04};" in text


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
    toml = tmp_path / "rebrew-project.toml"
    toml.write_text(
        "[project]\n"
        'default_target = "game.dll"\n'
        f'[targets."game.dll"]\n'
        'binary = "original/x.dll"\n'
        'reversed_dir = "src"\n'
        f'[targets."game.dll".layout]\n'
        f"image_base = {data_base - 0x18000}\n"
        f'sections = [{{ name = ".data", va = 0x18000, raw = {raw_size}, vs = {vs} }}]\n',
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
    assert "int g_a = 42;" in f.read_text()


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
    (dll_dir / "server.dll").write_bytes(_make_pe(raw, image_base=0x10000000, data_va=0x18000))
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
    # expected (0x10027000) == current (build data_va + offset) — no pad needed
    result = converge_layout(tmp_path, meta, tmp_path / "original" / "x.dll", src, dry_run=True)
    assert result["adjustments"] == []


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
