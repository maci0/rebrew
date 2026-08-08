"""Tests for annotation round-trip fidelity (Idea 19).

After the metadata migration, volatile fields (STATUS, CFLAGS, BLOCKER, NOTE,
GLOBALS, SIZE) are stored in rebrew-function.toml rather than in the .c file. Round-trip
reads must pass ``metadata_dir`` to ``parse_c_file_multi`` to see them.
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
    """Writing a metadata field and reading it back preserves the exact string."""
    # Write — goes to metadata for metadata-owned keys
    modified = update_annotation_key(base_file, 0x1000, key, new_val)
    assert modified

    # Read — must pass metadata_dir to pick up the metadata entries
    anns = parse_c_file_multi(base_file, metadata_dir=base_file.parent)
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

    # Update TARGET1 status → goes to metadata
    update_annotation_key(f, 0x1000, "STATUS", "RELOC")

    anns = parse_c_file_multi(f, metadata_dir=f.parent)
    assert len(anns) == 2

    # Verify TARGET1
    assert anns[0].va == 0x1000
    assert anns[0].status == "RELOC"

    # Verify TARGET2 — name derived from C function def
    assert anns[1].va == 0x2000
    assert anns[1].name == "func"


def test_roundtrip_creates_missing_key(base_file: Path) -> None:
    update_annotation_key(base_file, 0x1000, "BLOCKER", "Loop unrolling")
    anns = parse_c_file_multi(base_file, metadata_dir=base_file.parent)
    assert anns[0].blocker == "Loop unrolling"


def test_remove_metadata_key_roundtrip(base_file: Path) -> None:
    """update → remove of a metadata key must leave the .c file untouched and
    the parsed annotation back to its default."""
    from rebrew.annotation import remove_annotation_key

    original = base_file.read_text(encoding="utf-8")

    assert update_annotation_key(base_file, 0x1000, "SIZE", "42")
    anns = parse_c_file_multi(base_file, metadata_dir=base_file.parent)
    assert anns[0].size == 42
    # Metadata keys never touch the .c file.
    assert base_file.read_text(encoding="utf-8") == original

    assert remove_annotation_key(base_file, 0x1000, "SIZE", metadata_dir=base_file.parent)
    anns = parse_c_file_multi(base_file, metadata_dir=base_file.parent)
    assert anns[0].size == 0  # back to the dataclass default
    assert base_file.read_text(encoding="utf-8") == original


def test_remove_absent_metadata_key_returns_false(base_file: Path) -> None:
    """Removing a metadata field that was never written is a no-op (False)."""
    from rebrew.annotation import remove_annotation_key

    assert remove_annotation_key(base_file, 0x1000, "SIZE", metadata_dir=base_file.parent) is False


def test_update_same_value_idempotent(base_file: Path) -> None:
    """Writing the same value twice: the second write reports no change."""
    assert update_annotation_key(base_file, 0x1000, "SIZE", "42", metadata_dir=base_file.parent)
    assert (
        update_annotation_key(base_file, 0x1000, "SIZE", "42", metadata_dir=base_file.parent)
        is False
    )


def test_inline_key_update_remove_roundtrip(base_file: Path) -> None:
    """Non-metadata keys round-trip through the .c file: update inserts a
    ``// KEY:`` line, remove strips it, the file is byte-identical after."""
    from rebrew.annotation import remove_annotation_key

    original = base_file.read_text(encoding="utf-8")
    key = "AUTHOR"  # not in METADATA_FIELDS → lives in the .c file

    assert update_annotation_key(base_file, 0x1000, key, "rebrewer")
    text = base_file.read_text(encoding="utf-8")
    assert "// AUTHOR: rebrewer" in text

    assert remove_annotation_key(base_file, 0x1000, key)
    assert base_file.read_text(encoding="utf-8") == original


def test_remove_inline_key_never_creates_metadata(base_file: Path) -> None:
    """remove_inline_annotation_key strips the inline line only — it must not
    create or write rebrew-function.toml."""
    from rebrew.annotation import remove_inline_annotation_key, update_annotation_key

    update_annotation_key(base_file, 0x1000, "AUTHOR", "x")
    assert "// AUTHOR: x" in base_file.read_text(encoding="utf-8")
    assert not (base_file.parent / "rebrew-function.toml").exists()

    assert remove_inline_annotation_key(base_file, 0x1000, "AUTHOR")
    assert "// AUTHOR" not in base_file.read_text(encoding="utf-8")
    assert not (base_file.parent / "rebrew-function.toml").exists()


def test_update_key_preserves_legacy_encoding(tmp_path: Path) -> None:
    """A CP1252 source keeps its non-ASCII comment bytes after a key update.

    Regression for R18: reads used errors="replace" and wrote back UTF-8,
    permanently replacing every non-ASCII byte with U+FFFD on the first
    edit of a legacy-encoded source.  SYMBOL is a file-only key, so the
    update exercises the read-modify-write path on the .c file itself.
    """
    from rebrew.annotation import remove_inline_annotation_key

    f = tmp_path / "legacy.c"
    original = (
        b"// FUNCTION: MAIN 0x1000\n"
        b"// SYMBOL: _start\n"
        b"// NOTE: Caf\xe9 comment\n"  # é in cp1252
        b"void start() {}\n"
    )
    f.write_bytes(original)

    assert update_annotation_key(f, 0x1000, "SYMBOL", "_renamed")
    data = f.read_bytes()
    # The SYMBOL line was rewritten...
    assert b"_renamed" in data
    # ...and the cp1252 byte in the NOTE comment survived byte-for-byte.
    assert b"\xe9" in data
    assert b"\xef\xbf\xbd" not in data  # no U+FFFD replacement chars

    # remove_inline_annotation_key (lint --fix path) must also round-trip.
    f2 = tmp_path / "legacy2.c"
    f2.write_bytes(
        b"// FUNCTION: MAIN 0x2000\n"
        b"// SYMBOL: _other\n"
        b"// NOTE: keep\xe9\n"
        b"// CFLAGS: /O2\n"
        b"void start() {}\n"
    )
    assert remove_inline_annotation_key(f2, 0x2000, "CFLAGS")
    assert b"\xe9" in f2.read_bytes()
    assert b"CFLAGS" not in f2.read_bytes()
