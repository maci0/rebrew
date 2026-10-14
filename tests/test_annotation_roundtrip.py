"""Tests for annotation round-trip fidelity (Idea 19).

After the metadata migration, volatile fields (STATUS, CFLAGS, BLOCKER, NOTE,
GLOBALS, SIZE) are stored in rebrew-functions.toml rather than in the .c file. Round-trip
reads must pass ``metadata_dir`` to ``read_source_bindings`` to see them.
"""

from pathlib import Path

import pytest
from source_util import SourceFixture, write_source

from rebrew.metadata.bindings import (
    read_source_bindings,
    set_binding_field,
)


@pytest.fixture
def base_file(tmp_path: Path) -> Path:
    f = tmp_path / "test.c"
    write_source(
        f,
        "/* ADDRESS: MAIN 0x1000 */\n\nvoid start() {}\n",
        encoding="utf-8",
        metadata_fields={"MAIN.0x1000": {"kind": "FUNCTION", "symbol": "_start"}},
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
    modified = set_binding_field(base_file, 0x1000, key, new_val)
    assert modified

    # Read — must pass metadata_dir to pick up the metadata entries
    anns = read_source_bindings(base_file, metadata_dir=base_file.parent)
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
    write_source(
        f,
        "/* ADDRESS: TARGET1 0x1000 */\n\n\n/* ADDRESS: TARGET2 0x2000 */\n\nvoid func() {}\n",
        encoding="utf-8",
        metadata_fields={
            "TARGET1.0x1000": {"kind": "FUNCTION", "symbol": "_func_a"},
            "TARGET2.0x2000": {"kind": "FUNCTION", "symbol": "_func_b"},
        },
        metadata_dir=f.parent,
    )

    # Update TARGET1 status → goes to metadata
    set_binding_field(f, 0x1000, "STATUS", "RELOC")

    anns = read_source_bindings(f, metadata_dir=f.parent)
    assert len(anns) == 2

    # Verify TARGET1
    assert anns[0].va == 0x1000
    assert anns[0].status == "RELOC"

    # Verify TARGET2 — name derived from C function def
    assert anns[1].va == 0x2000
    assert anns[1].name == "func"


def test_roundtrip_creates_missing_key(base_file: Path) -> None:
    set_binding_field(base_file, 0x1000, "BLOCKER", "Loop unrolling")
    anns = read_source_bindings(base_file, metadata_dir=base_file.parent)
    assert anns[0].blocker == "Loop unrolling"


def test_remove_metadata_key_roundtrip(base_file: Path) -> None:
    """update → remove of a metadata key must leave the .c file untouched and
    the parsed annotation back to its default."""
    from rebrew.metadata.bindings import remove_binding_field

    original = base_file.read_text(encoding="utf-8")

    assert set_binding_field(base_file, 0x1000, "SIZE", "42")
    anns = read_source_bindings(base_file, metadata_dir=base_file.parent)
    assert anns[0].size == 42
    # Metadata keys never touch the .c file.
    assert base_file.read_text(encoding="utf-8") == original

    assert remove_binding_field(base_file, 0x1000, "SIZE", metadata_dir=base_file.parent)
    anns = read_source_bindings(base_file, metadata_dir=base_file.parent)
    assert anns[0].size == 0  # back to the dataclass default
    assert base_file.read_text(encoding="utf-8") == original


def test_remove_absent_metadata_key_returns_false(base_file: Path) -> None:
    """Removing a metadata field that was never written is a no-op (False)."""
    from rebrew.metadata.bindings import remove_binding_field

    assert remove_binding_field(base_file, 0x1000, "SIZE", metadata_dir=base_file.parent) is False


def test_update_same_value_idempotent(base_file: Path) -> None:
    """Writing the same value twice: the second write reports no change."""
    assert set_binding_field(base_file, 0x1000, "SIZE", "42", metadata_dir=base_file.parent)
    assert (
        set_binding_field(base_file, 0x1000, "SIZE", "42", metadata_dir=base_file.parent) is False
    )


def test_update_equivalent_spelling_reports_no_change(base_file: Path) -> None:
    """A differently-spelled equal value stores nothing and reports no change.

    The writer coerces SIZE to an int, so ``"42"`` and ``"0x2A"`` are the same
    stored value. The idempotency check compared raw text, so the second call
    took the write path, wrote nothing, and still returned True.
    """
    assert set_binding_field(base_file, 0x1000, "SIZE", "42", metadata_dir=base_file.parent)
    assert (
        set_binding_field(base_file, 0x1000, "SIZE", "0x2A", metadata_dir=base_file.parent) is False
    )


def test_block_comment_marker_parses(tmp_path: Path) -> None:
    """C89-strict 16-bit compilers (Turbo C 2.0) reject ``//`` comments, so
    their skeletons emit ``/* FUNCTION: ... */`` markers — the parser must
    treat them identically to the ``//`` form."""
    from rebrew.metadata.bindings import read_source_bindings

    (
        SourceFixture(
            "/* ADDRESS: MAIN 0x0000042e */\nint fcn_042e(void)\n{\n    /* TODO: Implement */\n    return 0;\n}\n",
            {"MAIN.0x0000042e": {"kind": "FUNCTION"}},
        )
    )
    tmp = Path(tmp_path)
    f = tmp / "fcn_042e.c"
    write_source(
        f,
        "/* ADDRESS: MAIN 0x0000042e */\nint fcn_042e(void)\n{\n    /* TODO: Implement */\n    return 0;\n}\n",
        encoding="utf-8",
        metadata_fields={"MAIN.0x0000042e": {"kind": "FUNCTION"}},
    )
    anns = read_source_bindings(f)
    assert len(anns) == 1
    assert anns[0].kind == "FUNCTION"
    assert anns[0].va == 0x42E
    assert anns[0].module == "MAIN"


def test_skeleton_marker_style_matches_profile() -> None:
    """Skeletons are pure C for every profile. The profile still chooses the
    signature: cdecl-default compilers omit ``__cdecl``; MSVC keeps it.
    No profile emits a marker line."""
    from rebrew.skeleton import _render_skeleton

    def rendered(profile: str) -> str:
        return _render_skeleton(
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
        )

    for profile in ("borland-2.0", "msvc-1.52", "borland-3.1"):
        text = rendered(profile)
        assert "// FUNCTION:" not in text
        assert "/* FUNCTION:" not in text
        assert "// LIBRARY:" not in text
        assert "// SIZE:" not in text
    # cdecl is the default convention for the Borland family, so no __cdecl.
    # msvc-1.52 is not in that set and keeps the MSVC spelling.
    assert rendered("borland-2.0").splitlines()[0] == "int fcn_042e(void)"
    assert rendered("borland-3.1").splitlines()[0] == "int fcn_042e(void)"
    assert rendered("msvc-1.52").splitlines()[0] == "int __cdecl fcn_042e(void)"
    body = rendered("borland-2.0")
    assert "int fcn_042e(void)" in body
    assert "__cdecl" not in body


def test_x86_16_va_floor(tmp_path: Path) -> None:
    """16-bit DOS targets address code from segment 0 — VA 0x42e is valid
    for an MZ binary and must not trip the 0x1000 PE-era suspicious-VA
    check when the arch-aware floor is passed."""
    from types import SimpleNamespace

    from rebrew.metadata.bindings import SourceBinding, min_valid_va_for

    cfg16 = SimpleNamespace(arch="x86_16")
    cfg32 = SimpleNamespace(arch="x86_32")
    assert min_valid_va_for(cfg16) == 0
    assert min_valid_va_for(cfg32) == 0x1000

    a = SourceBinding(kind="FUNCTION", module="MAIN", va=0x42E, size=38)
    errs, _ = a.validate(min_va=min_valid_va_for(cfg16))
    assert not any("suspicious" in e for e in errs)
    errs32, _ = a.validate(min_va=min_valid_va_for(cfg32))
    assert any("suspicious" in e for e in errs32)


def test_unknown_field_is_rejected_without_source_changes(base_file: Path) -> None:
    original = base_file.read_bytes()
    with pytest.raises(ValueError, match="not a function metadata field"):
        set_binding_field(base_file, 0x1000, "AUTHOR", "someone")
    assert base_file.read_bytes() == original


def test_metadata_edit_preserves_source_encoding(tmp_path: Path) -> None:
    path = tmp_path / "legacy.c"
    original = b"/* ADDRESS: MAIN 0x1000 */\n/* Caf\xe9 */\nvoid start(void) {}\n"
    path.write_bytes(original)
    assert set_binding_field(path, 0x1000, "NOTE", "reviewed")
    assert path.read_bytes() == original
    assert read_source_bindings(path, metadata_dir=tmp_path)[0].note == "reviewed"
