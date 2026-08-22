"""Tests for rebrew.data_layout — the shared .data placement model."""

from __future__ import annotations

from pathlib import Path

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
