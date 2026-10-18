"""Tests for rebrew.metadata.bindings — SourceBinding dataclass and parsers."""

from pathlib import Path

import pytest
from source_util import write_source

from rebrew.metadata.bindings import (
    SourceBinding,
    make_function_binding,
    read_source_bindings,
    set_binding_field,
)

# ---------------------------------------------------------------------------
# SourceBinding dataclass basics
# ---------------------------------------------------------------------------


class TestAnnotationDataclass:
    """Verify SourceBinding dataclass behavior."""

    def test_defaults(self) -> None:
        ann = SourceBinding()
        assert ann.va == 0
        assert ann.size == 0
        assert ann.name == ""
        assert ann.globals_list == []

    def test_field_access(self) -> None:
        ann = SourceBinding(va=0x10001000, size=42, name="foo", status="EXACT")
        assert ann.va == 0x10001000
        assert ann.size == 42
        assert ann.name == "foo"
        assert ann.status == "EXACT"

    def test_deepcopy_isolates_nested_container_values(self) -> None:
        """SourceBinding.__deepcopy__ shares scalars but never mutable values.

        The specialised copy is what keeps _finalize_entries fast on
        every source scan; this pins the isolation contract it must
        preserve (mutating a twin, even deeply, never reaches the memoised
        original that parse results are cached under).
        """
        import copy

        ann = SourceBinding(
            va=0x1000,
            name="f",
            locals={"regs": ["eax"], "frame": {"bp": 4}},
            comments={"note": "hi"},
            globals_list=["g_x"],
        )
        twin = copy.deepcopy(ann, {})
        # scalars may be shared...
        twin.name = "renamed"
        assert ann.name == "f"
        # ...container values must not be
        twin.locals["regs"].append("ebx")
        twin.locals["frame"]["bp"] = 8
        twin.comments["note"] = "changed"
        twin.globals_list.append("g_y")
        assert ann.locals == {"regs": ["eax"], "frame": {"bp": 4}}
        assert ann.comments == {"note": "hi"}
        assert ann.globals_list == ["g_x"]

    def test_deepcopy_returns_same_type(self) -> None:
        import copy

        twin = copy.deepcopy(SourceBinding(va=7), {})
        assert type(twin) is SourceBinding
        assert twin.va == 7
        assert twin is not None

    def test_dict_getitem(self) -> None:
        ann = SourceBinding(va=0x10001000, status="RELOC")
        assert ann["va"] == 0x10001000
        assert ann["status"] == "RELOC"

    def test_dict_setitem(self) -> None:
        ann = SourceBinding()
        ann["status"] = "EXACT"
        assert ann.status == "EXACT"
        assert ann["status"] == "EXACT"

    def test_dict_globals_alias(self) -> None:
        """The 'globals' key should map to globals_list field."""
        ann = SourceBinding(globals_list=["a", "b"])
        assert ann["globals"] == ["a", "b"]
        ann["globals"] = ["c"]
        assert ann.globals_list == ["c"]

    def test_dict_contains(self) -> None:
        ann = SourceBinding()
        assert "va" in ann
        assert "status" in ann
        assert "globals" in ann
        assert "nonexistent_field" not in ann

    def test_dict_get_existing(self) -> None:
        ann = SourceBinding(status="EXACT")
        assert ann.get("status") == "EXACT"

    def test_dict_get_missing(self) -> None:
        ann = SourceBinding()
        assert ann.get("nonexistent", "default") == "default"

    def test_dict_getitem_invalid_key(self) -> None:
        ann = SourceBinding()
        with pytest.raises(KeyError):
            _ = ann["nonexistent_key"]

    def test_dict_setitem_invalid_key(self) -> None:
        ann = SourceBinding()
        with pytest.raises(KeyError):
            ann["nonexistent_key"] = "value"

    def test_to_dict(self) -> None:
        ann = SourceBinding(
            va=0x10001000,
            size=42,
            name="foo",
            symbol="_foo",
            status="EXACT",
            module="SERVER",
            cflags="/O2",
            toolchain="msvc-5.0",
            kind="FUNCTION",
            filepath="foo.c",
            source="",
            blocker="",
            note="",
            globals_list=["g1"],
        )
        d = ann.to_dict()
        assert d["va"] == 0x10001000
        assert d["size"] == 42
        assert d["name"] == "foo"
        assert d["symbol"] == "_foo"
        assert d["status"] == "EXACT"
        assert d["module"] == "SERVER"
        assert d["cflags"] == "/O2"
        # to_dict completeness: every volatile compile-routing field must be
        # serialised — toolchain routes the compiler image just like cflags.
        assert d["toolchain"] == "msvc-5.0"
        assert d["kind"] == "FUNCTION"
        assert d["filepath"] == "foo.c"
        assert d["globals"] == ["g1"]
        assert d["source"] == ""
        assert d["blocker"] == ""
        assert d["note"] == ""

    def test_make_func_entry_returns_annotation(self) -> None:
        ann = make_function_binding(
            va=0x10001000,
            size=42,
            name="foo",
            symbol="_foo",
            status="EXACT",
            module="SERVER",
            cflags="/O2",
            kind="FUNCTION",
            filepath="foo.c",
        )
        assert isinstance(ann, SourceBinding)
        assert ann.va == 0x10001000
        assert ann["va"] == 0x10001000


# ---------------------------------------------------------------------------
# SourceBinding.validate()
# ---------------------------------------------------------------------------


class TestAnnotationValidation:
    """Verify SourceBinding.validate() catches issues."""

    def test_valid_annotation_no_errors(self) -> None:
        ann = SourceBinding(
            va=0x10001000,
            size=42,
            name="foo",
            symbol="_foo",
            status="EXACT",
            cflags="/O2",
            kind="FUNCTION",
        )
        errors, warnings = ann.validate()
        assert errors == []

    def test_invalid_module(self) -> None:
        """SourceBinding.validate() does not validate module values (open field)."""
        ann = SourceBinding(
            va=0x10001000,
            size=42,
            cflags="/O2",
            status="EXACT",
            module="BOGUS",
            kind="FUNCTION",
        )
        errors, _ = ann.validate()
        # module is a free-form field, no ORIGIN error expected
        assert not any("ORIGIN" in e for e in errors)

    def test_invalid_size(self) -> None:
        ann = SourceBinding(
            va=0x10001000,
            size=0,
            cflags="/O2",
            status="EXACT",
            kind="FUNCTION",
        )
        errors, _ = ann.validate()
        assert any("SIZE" in e for e in errors)

    def test_missing_cflags_no_error(self) -> None:
        """CFLAGS is optional — missing cflags should not produce a validation error."""
        ann = SourceBinding(
            va=0x10001000,
            size=42,
            cflags="",
            status="EXACT",
            kind="FUNCTION",
        )
        errors, _ = ann.validate()
        assert not any("CFLAGS" in e for e in errors)

    def test_no_symbol_warning_when_derived(self) -> None:
        """SYMBOL is now derived from C definition — no warning needed."""
        ann = SourceBinding(
            va=0x10001000,
            size=42,
            cflags="/O2",
            symbol="",
            status="EXACT",
            kind="FUNCTION",
        )
        _, warnings = ann.validate()
        assert warnings == [], f"Expected no warnings, got: {warnings}"

    def test_stub_without_blocker_warning(self) -> None:
        ann = SourceBinding(
            va=0x10001000,
            size=42,
            cflags="/O2",
            symbol="_foo",
            status="STUB",
            kind="STUB",
        )
        _, warnings = ann.validate()
        assert any("BLOCKER" in w for w in warnings)

    def test_msvcrt_without_source_warning(self) -> None:
        """Library module missing SOURCE should warn when that module is in library_modules."""
        ann = SourceBinding(
            va=0x10001000,
            size=42,
            cflags="/O2",
            symbol="_foo",
            status="EXACT",
            module="MSVCRT",
            kind="LIBRARY",
        )
        _, warnings = ann.validate(library_modules={"MSVCRT"})
        assert any("SOURCE" in w for w in warnings)


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Multi-function parsing tests
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Shared helper tests
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# library_bindings_for_file
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Regression tests
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# split_address_sections
# ---------------------------------------------------------------------------


def test_update_annotation_key_multiple_funcs(tmp_path: Path) -> None:
    cfile = tmp_path / "test.c"
    write_source(
        cfile,
        "/* ADDRESS: GAME 0x1000 */\n\n\n\nvoid func_1000() {}\n\n/* ADDRESS: GAME 0x2000 */\n\nvoid func_2000() {}\n",
        encoding="utf-8",
        metadata_fields={
            "GAME.0x1000": {"kind": "FUNCTION", "cflags": "/O2", "size": 10},
            "GAME.0x2000": {"kind": "FUNCTION", "size": 10},
        },
    )

    from rebrew.metadata.functions import get_entry, record_function_identity

    original = cfile.read_bytes()
    for va, symbol in [(0x1000, "ResetScore"), (0x2000, "AddScore")]:
        record_function_identity(
            tmp_path, module="GAME", va=va, file="test.c", symbol=symbol, kind="FUNCTION"
        )
        assert get_entry(tmp_path, va, "GAME")["symbol"] == symbol
    assert cfile.read_bytes() == original


class TestValidateEdgeBranches:
    def test_suspicious_va_reported(self) -> None:
        ann = SourceBinding(va=0x500)  # below MIN_VALID_VA
        errors, _warnings = ann.validate()
        assert any("suspicious" in e for e in errors)

    def test_invalid_kind_reported(self) -> None:
        ann = SourceBinding(va=0x10001000, kind="NOTAMARKER")
        errors, _warnings = ann.validate()
        assert any("Invalid metadata kind" in e for e in errors)


class TestAnnotationValidateBranches:
    def test_library_without_source_warns(self) -> None:
        from rebrew.metadata.bindings import SourceBinding

        ann = SourceBinding(va=0x1000, module="MSVCRT", name="f", kind="LIBRARY", status="EXACT")
        errors, warnings = ann.validate(library_modules={"MSVCRT"})
        assert any("missing SOURCE" in w for w in warnings)

    def test_near_matching_stub_contradiction(self) -> None:
        from rebrew.metadata.bindings import SourceBinding

        ann = SourceBinding(va=0x1000, module="GAME", name="f", kind="STUB", status="NEAR_MATCHING")
        errors, warnings = ann.validate()
        assert any("Contradictory" in w for w in warnings)


class TestStdcallParamSizeDeclspec:
    """__declspec(...) groups contain parens — the param-list must not be
    confused with the declspec group (np-rebrew TOOLCHAIN_BUGS naked gap)."""

    def test_naked_void_is_zero(self) -> None:
        from rebrew.metadata.bindings import _calc_stdcall_param_size

        assert _calc_stdcall_param_size("void __declspec(naked) __stdcall foo(void)") == 0
        assert _calc_stdcall_param_size("void __declspec(naked) __stdcall foo()") == 0

    def test_naked_with_params(self) -> None:
        from rebrew.metadata.bindings import _calc_stdcall_param_size

        assert _calc_stdcall_param_size("void __declspec(naked) __stdcall foo(int a)") == 4
        assert _calc_stdcall_param_size("int __declspec(naked) __stdcall foo(int a, int b)") == 8

    def test_plain_unchanged(self) -> None:
        from rebrew.metadata.bindings import _calc_stdcall_param_size

        assert _calc_stdcall_param_size("void __stdcall foo(void)") == 0
        assert _calc_stdcall_param_size("int __stdcall foo(int a, int b, int c)") == 12


def test_data_markers_are_exempt_from_the_size_check() -> None:
    """A DATA/GLOBAL annotation has no byte size, and must not fail validate().

    Regression: validate() applied the function-only `size > 0` rule to every
    marker, so a single `// DATA:` line in an otherwise-valid source made
    `rebrew diff --fix-blocker` abort with "Invalid SIZE: 0" and refuse to
    refresh that function's blocker -- while `rebrew lint`, which knows the
    difference, passed the same file.  Two tools disagreeing about the same
    annotation is the bug.
    """
    for marker in ("DATA", "GLOBAL", "VTABLE", "STRING"):
        ann = SourceBinding(va=0x10027104, size=0, kind=marker, name="g_msg")
        errors, _ = ann.validate()
        assert not any("Invalid SIZE" in e for e in errors), (marker, errors)

    # Code annotations must still be caught.
    code = SourceBinding(va=0x10002770, size=0, kind="FUNCTION", name="f")
    errors, _ = code.validate()
    assert any("Invalid SIZE" in e for e in errors), errors


def test_update_annotation_key_rejects_multiline_value(tmp_path: Path) -> None:
    """An annotation value is spliced into one line; a newline would land as code.

    The value can arrive from a received BinSync state or a Ghidra sync, and
    the .c file is compiled and linked.
    """

    content = "// LIBRARY: SERVER\n// FUNCTION: 0x10001000\n// SIZE: 42\nint func_a(void) {}\n"
    f = tmp_path / "proto.c"
    f.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="not a function metadata field"):
        set_binding_field(f, 0x10001000, "PROTOTYPE", "int f(void)\nvoid pwn(void) {}\n//")
    assert f.read_text(encoding="utf-8") == content


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("FUNCTION", "LIBRARY"),
        ("LIBRARY", "FUNCTION"),
        ("LIBRARY", "LIBRARY"),
        ("STUB", "LIBRARY"),
        ("FUNCTION", "STUB"),
    ],
)
def test_mixed_code_marker_stack_binds_common_definition(
    tmp_path: Path, first: str, second: str
) -> None:
    """Different target classifications do not erase a common C identity."""
    source = tmp_path / "gzread.c"
    write_source(
        source,
        "#include <stdio.h>\nvoid helper(void);\n"
        "/* ADDRESS: GOLDTL 0x0045f380 */\n/* ADDRESS: SERVER 0x10003960 */\n"
        "int ZEXPORT gzread(int file, void *buf, unsigned len)\n{ return file; }\n",
        metadata_fields={
            "GOLDTL.0x0045f380": {"kind": first, "size": 560},
            "SERVER.0x10003960": {"kind": second, "size": 600},
        },
    )
    annotations = read_source_bindings(source, metadata_dir=tmp_path)
    assert [ann.name for ann in annotations] == ["gzread", "gzread"]
    assert [ann.symbol for ann in annotations] == ["_gzread", "_gzread"]
    assert [ann.size for ann in annotations] == [560, 600]
    assert [ann.kind for ann in annotations] == [first, second]
    assert all("ZEXPORT gzread" in ann.prototype for ann in annotations)
    for target in ("GOLDTL", "SERVER"):
        selected = read_source_bindings(source, target_name=target, metadata_dir=tmp_path)
        assert len(selected) == 1
        assert selected[0].name == "gzread"


def test_code_marker_stack_stops_at_data_marker(tmp_path: Path) -> None:
    """A data marker cannot acquire the next code block's function identity."""
    source = tmp_path / "mixed.c"
    write_source(
        source,
        "/* ADDRESS: A 0x2000 */\nextern int count;\n/* ADDRESS: B 0x3000 */\nint later(void) { return 1; }\n",
        metadata_fields={
            "A.0x1000": {"kind": "FUNCTION", "name": "unbound"},
            "A.0x2000": {"kind": "DATA"},
            "B.0x3000": {"kind": "LIBRARY"},
        },
    )
    annotations = read_source_bindings(source, metadata_dir=tmp_path)
    by_va = {a.va: a for a in annotations}
    assert by_va[0x1000].name == "unbound"
    assert by_va[0x2000].name == "count"
    assert by_va[0x3000].name == "later"


def test_mixed_code_markers_after_definition_are_separate(tmp_path: Path) -> None:
    """Code between the markers preserves distinct definitions."""
    source = tmp_path / "separate.c"
    write_source(
        source,
        "/* ADDRESS: A 0x1000 */\nint first(void) { return 1; }\n/* ADDRESS: B 0x2000 */\nint second(void) { return 2; }\n",
        metadata_fields={"A.0x1000": {"kind": "FUNCTION"}, "B.0x2000": {"kind": "LIBRARY"}},
    )
    assert [ann.name for ann in read_source_bindings(source)] == ["first", "second"]
