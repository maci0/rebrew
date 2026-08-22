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
