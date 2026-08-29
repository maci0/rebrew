"""Tests for annotation round-trip fidelity (Idea 19).

After the metadata migration, volatile fields (STATUS, CFLAGS, BLOCKER, NOTE,
GLOBALS, SIZE) are stored in rebrew-functions.toml rather than in the .c file. Round-trip
reads must pass ``metadata_dir`` to ``parse_c_file_multi`` to see them.
"""

from pathlib import Path

import pytest

from rebrew.annotation import (
    VALID_MARKERS,
    parse_c_file_multi,
    update_annotation_key,
)
from rebrew.metadata import METADATA_FIELDS


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


def test_inline_update_remove_symmetry_property(tmp_path: Path) -> None:
    """Property: for arbitrary file-owned keys and value strings (incl.
    values containing ``//`` or odd whitespace), update then remove restores
    the file byte-for-byte — a value-escaped bug would break the round-trip."""
    from hypothesis import given, settings
    from hypothesis import strategies as st

    from rebrew.annotation import remove_annotation_key, update_annotation_key

    @given(
        st.text(
            alphabet=st.characters(min_codepoint=0x41, max_codepoint=0x5A), min_size=1, max_size=12
        ).filter(lambda s: s not in METADATA_FIELDS and s not in VALID_MARKERS),
        # Annotation values are single-line printable text — newlines/control
        # chars would break the line-based `// KEY:` format by construction.
        st.text(alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E), max_size=40),
    )
    @settings(max_examples=120, deadline=None)
    def _check(key: str, value: str) -> None:
        f = tmp_path / f"prop_{key}.c"
        f.write_text(
            "// FUNCTION: MAIN 0x1000\nvoid start() {}\n",
            encoding="utf-8",
        )
        original = f.read_text(encoding="utf-8")
        assert update_annotation_key(f, 0x1000, key, value)
        assert remove_annotation_key(f, 0x1000, key)
        assert f.read_text(encoding="utf-8") == original, (key, value)

    _check()


def test_remove_inline_key_never_creates_metadata(base_file: Path) -> None:
    """remove_inline_annotation_key strips the inline line only — it must not
    create or write rebrew-functions.toml."""
    from rebrew.annotation import remove_inline_annotation_key, update_annotation_key

    update_annotation_key(base_file, 0x1000, "AUTHOR", "x")
    assert "// AUTHOR: x" in base_file.read_text(encoding="utf-8")
    assert not (base_file.parent / "rebrew-functions.toml").exists()

    assert remove_inline_annotation_key(base_file, 0x1000, "AUTHOR")
    assert "// AUTHOR" not in base_file.read_text(encoding="utf-8")
    assert not (base_file.parent / "rebrew-functions.toml").exists()


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


def test_block_comment_marker_parses(tmp_path: Path) -> None:
    """C89-strict 16-bit compilers (Turbo C 2.0) reject ``//`` comments, so
    their skeletons emit ``/* FUNCTION: ... */`` markers — the parser must
    treat them identically to the ``//`` form."""
    from rebrew.annotation import parse_c_file_multi

    src = (
        "/* FUNCTION: MAIN 0x0000042e */\n"
        "int fcn_042e(void)\n"
        "{\n"
        "    /* TODO: Implement */\n"
        "    return 0;\n"
        "}\n"
    )
    tmp = Path(tmp_path)
    f = tmp / "fcn_042e.c"
    f.write_text(src, encoding="utf-8")
    anns = parse_c_file_multi(f)
    assert len(anns) == 1
    assert anns[0].marker_type == "FUNCTION"
    assert anns[0].va == 0x42E
    assert anns[0].module == "MAIN"


def test_skeleton_marker_style_matches_profile() -> None:
    """Skeletons use ``/* */`` markers for C89-strict 16-bit profiles and
    keep ``//`` for the rest."""
    from rebrew.skeleton import _render_annotation_block

    def first_line(profile: str) -> str:
        return _render_annotation_block(
            marker="FUNCTION",
            cfg_marker="MAIN",
            va=0x42E,
            xref_context=None,
            decomp_code=None,
            decomp_backend="",
            func_name="fcn_042e",
            ghidra_name="",
            convention_stub=None,
            profile=profile,
        ).splitlines()[0]

    assert first_line("tc20") == "/* FUNCTION: MAIN 0x0000042e */"
    assert first_line("msvc1.52") == "/* FUNCTION: MAIN 0x0000042e */"
    assert first_line("tc16") == "// FUNCTION: MAIN 0x0000042e"
    # cdecl is the default convention for the Borland family — no __cdecl.
    body = _render_annotation_block(
        marker="FUNCTION",
        cfg_marker="MAIN",
        va=0x42E,
        xref_context=None,
        decomp_code=None,
        decomp_backend="",
        func_name="fcn_042e",
        ghidra_name="",
        convention_stub=None,
        profile="tc20",
    )
    assert "int fcn_042e(void)" in body
    assert "__cdecl" not in body


def test_x86_16_va_floor(tmp_path: Path) -> None:
    """16-bit DOS targets address code from segment 0 — VA 0x42e is valid
    for an MZ binary and must not trip the 0x1000 PE-era suspicious-VA
    check when the arch-aware floor is passed."""
    from types import SimpleNamespace

    from rebrew.annotation import Annotation, min_valid_va_for

    cfg16 = SimpleNamespace(arch="x86_16")
    cfg32 = SimpleNamespace(arch="x86_32")
    assert min_valid_va_for(cfg16) == 0
    assert min_valid_va_for(cfg32) == 0x1000

    a = Annotation(marker_type="FUNCTION", module="MAIN", va=0x42E, size=38)
    errs, _ = a.validate(min_va=min_valid_va_for(cfg16))
    assert not any("suspicious" in e for e in errs)
    errs32, _ = a.validate(min_va=min_valid_va_for(cfg32))
    assert any("suspicious" in e for e in errs32)
