"""Tests for annotation round-trip fidelity (Idea 19).

After the sidecar migration, volatile fields (STATUS, CFLAGS, BLOCKER, NOTE,
GLOBALS, SIZE) are stored in rebrew-function.toml rather than in the .c file. Round-trip
reads must pass ``sidecar_dir`` to ``parse_c_file_multi`` to see them.
"""

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
        "// FUNCTION: MAIN 0x1000\n// SYMBOL: _start\nvoid start() {}\n",
        encoding="utf-8",
    )
    return f


@pytest.mark.parametrize(
    "key, initial_val, new_val",
    [
        ("STATUS", "STUB", "EXACT"),
        ("SIZE", "10", "42"),
        ("CFLAGS", "/O2", "/O2 /Oy- /Ob1"),
        ("BLOCKER", "", "register allocation (eax/ecx swap)"),
        ("NOTE", "", "This has spaces and // fake slashes"),
        ("GLOBALS", "", "g_var1, g_var2, g_var3"),
    ],
)
def test_roundtrip_single_value(base_file: Path, key: str, initial_val: str, new_val: str) -> None:
    """Writing a sidecar field and reading it back preserves the exact string."""
    # Write — goes to sidecar for sidecar-owned keys
    modified = update_annotation_key(base_file, 0x1000, key, new_val)
    assert modified

    # Read — must pass sidecar_dir to pick up the sidecar entries
    anns = parse_c_file_multi(base_file, sidecar_dir=base_file.parent)
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
        "// SYMBOL: _func_a\n"
        "\n"
        "// FUNCTION: TARGET2 0x2000\n"
        "// SYMBOL: _func_b\n"
        "void func() {}\n",
        encoding="utf-8",
    )

    # Update TARGET1 status → goes to sidecar
    update_annotation_key(f, 0x1000, "STATUS", "RELOC")

    anns = parse_c_file_multi(f, sidecar_dir=f.parent)
    assert len(anns) == 2

    # Verify TARGET1
    assert anns[0].va == 0x1000
    assert anns[0].status == "RELOC"

    # Verify TARGET2 — name derived from C function def
    assert anns[1].va == 0x2000
    assert anns[1].name == "func"


def test_roundtrip_creates_missing_key(base_file: Path) -> None:
    update_annotation_key(base_file, 0x1000, "BLOCKER", "Loop unrolling")
    anns = parse_c_file_multi(base_file, sidecar_dir=base_file.parent)
    assert anns[0].blocker == "Loop unrolling"
