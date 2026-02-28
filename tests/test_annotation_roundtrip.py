"""Tests for annotation round-trip fidelity (Idea 19)."""

from pathlib import Path

import pytest

from rebrew.annotation import (
    parse_c_file_multi,
    update_annotation_key,
)


@pytest.fixture
def base_file(tmp_path: Path) -> Path:
    f = tmp_path / "test.c"
    f.write_text(
        "// FUNCTION: MAIN 0x1000\n"
        "// STATUS: STUB\n"
        "// ORIGIN: GAME\n"
        "// SIZE: 10\n"
        "// CFLAGS: /O2\n"
        "// SYMBOL: _start\n"
        "void start() {}\n",
        encoding="utf-8",
    )
    return f


@pytest.mark.parametrize(
    "key, initial_val, new_val",
    [
        ("SYMBOL", "_start", "_complex_@_symbol"),
        ("STATUS", "STUB", "EXACT"),
        ("SIZE", "10", "42"),
        ("CFLAGS", "/O2", "/O2 /Oy- /Ob1"),
        ("BLOCKER", "", "register allocation (eax/ecx swap)"),
        ("NOTE", "", "This has spaces and // fake slashes"),
        ("GLOBALS", "", "g_var1, g_var2, g_var3"),
    ],
)
def test_roundtrip_single_value(base_file: Path, key: str, initial_val: str, new_val: str) -> None:
    """Test that writing a value and reading it back preserves the exact string."""
    # Write
    modified = update_annotation_key(base_file, 0x1000, key, new_val)
    assert modified

    # Read
    anns = parse_c_file_multi(base_file)
    assert len(anns) == 1
    ann = anns[0]

    # Verify
    if key == "SIZE":
        assert ann.size == int(new_val)
    elif key == "GLOBALS":
        assert ", ".join(ann.globals_list) == new_val
    else:
        assert getattr(ann, key.lower()) == new_val


def test_roundtrip_multi_target(tmp_path: Path) -> None:
    f = tmp_path / "multi.c"
    f.write_text(
        "// FUNCTION: TARGET1 0x1000\n"
        "// STATUS: EXACT\n"
        "// ORIGIN: GAME\n"
        "// SIZE: 10\n"
        "// CFLAGS: /O2\n"
        "// SYMBOL: _func\n"
        "\n"
        "// FUNCTION: TARGET2 0x2000\n"
        "// STATUS: STUB\n"
        "// ORIGIN: ZLIB\n"
        "// SIZE: 20\n"
        "// CFLAGS: /O1\n"
        "// SYMBOL: _func2\n"
        "void func() {}\n",
        encoding="utf-8",
    )

    # Update TARGET1
    update_annotation_key(f, 0x1000, "STATUS", "RELOC")
    # Update TARGET2
    update_annotation_key(f, 0x2000, "SYMBOL", "_func2_updated")

    anns = parse_c_file_multi(f)
    assert len(anns) == 2

    # Verify TARGET1
    assert anns[0].va == 0x1000
    assert anns[0].status == "RELOC"
    assert anns[0].symbol == "_func"

    # Verify TARGET2
    assert anns[1].va == 0x2000
    assert anns[1].status == "STUB"
    assert anns[1].symbol == "_func2_updated"


def test_roundtrip_creates_missing_key(base_file: Path) -> None:
    # BLOCKER doesn't exist initially
    update_annotation_key(base_file, 0x1000, "BLOCKER", "Loop unrolling")
    anns = parse_c_file_multi(base_file)
    assert anns[0].blocker == "Loop unrolling"
