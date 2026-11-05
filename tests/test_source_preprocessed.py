"""The MSVC preprocessed parser view retains raw offsets and uncertainty."""

lazy from pathlib import Path

import pytest

from rebrew.source_preprocessed import (
    parse_msvc_preprocessed,
    reported_declaration_scopes,
    reported_source_functions,
)


def test_msvc_projection_preserves_literals_offsets_and_anonymous_fields() -> None:
    raw = (
        b'#line 1 "Z:\\\\project\\\\unit.c"\r\n'
        b"struct S { int :7; int x; };\r\n"
        b"_inline int __cdecl f(void) { __asm mov eax, 1 }\r\n"
        b'const char *s = "_inline __cdecl __asm";\r\n'
    )
    report = parse_msvc_preprocessed(raw)
    assert report["parse_complete"] and len(report["anonymous_bitfields"]) == 1
    assert len(report["view"]) == len(raw)
    start = raw.index(b'"_inline')
    end = raw.index(b";", start)
    assert report["view"][start:end] == raw[start:end]
    assert not report["abi_proven"] and not report["marker_origins_proven"]


def test_msvc_projection_does_not_hide_line_text_inside_comment() -> None:
    raw = b'/*\n#line 5 "fake.c"\n*/\nint f(void) { return 1; }\n'
    report = parse_msvc_preprocessed(raw)
    assert report["parse_complete"] and not report["markers"]
    assert report["view"] == raw


def test_msvc_projection_reports_unknown_syntax() -> None:
    report = parse_msvc_preprocessed(b"int f( { return 1; }\n")
    assert not report["parse_complete"] and report["unknown_syntax"]


def test_inventory_checks_all_own_definitions_and_rejects_masked_prefix(tmp_path: Path) -> None:
    source = tmp_path / "unit.c"
    encoded = ("Z:" + str(source).replace("/", "\\")).replace("\\", "\\\\")
    raw = f'#line 1 "{encoded}"\nint expected(void) {{return 1;}}\nint extra(void) {{return 2;}}\n'.encode()
    report = parse_msvc_preprocessed(raw)
    with pytest.raises(ValueError, match="inventory differs"):
        reported_source_functions(raw, report, source, expected_names={"expected"})
    assert set(reported_source_functions(raw, report, source)) == {"expected", "extra"}
    for prefix in (
        "__stdcall ",
        "__cdecl\n",
        "_inline\n",
        "__cdecl /* hello */ ",
        "__stdcall\n/* hello */\n",
    ):
        prefixed = f'#line 1 "{encoded}"\n{prefix}int expected(void) {{return 1;}}\n'.encode()
        with pytest.raises(ValueError, match="precedes"):
            reported_source_functions(prefixed, parse_msvc_preprocessed(prefixed), source)


def test_inventory_retains_raw_asm_bytes(tmp_path: Path) -> None:
    source = tmp_path / "unit.c"
    encoded = ("Z:" + str(source).replace("/", "\\")).replace("\\", "\\\\")
    first = f'#line 1 "{encoded}"\nint f(void) {{ __asm mov eax, 1 }}\n'.encode()
    second = first.replace(b"eax, 1", b"eax, 2")
    a = reported_source_functions(first, parse_msvc_preprocessed(first), source)["f"]
    b = reported_source_functions(second, parse_msvc_preprocessed(second), source)["f"]
    assert first[slice(*a)] != second[slice(*b)]


def test_inventory_never_drops_leading_declspec(tmp_path: Path) -> None:
    source = tmp_path / "unit.c"
    encoded = ("Z:" + str(source).replace("/", "\\")).replace("\\", "\\\\")
    raw = f'#line 1 "{encoded}"\n__declspec(dllexport) int f(void) {{return 1;}}\n'.encode()
    report = parse_msvc_preprocessed(raw)
    try:
        start, end = reported_source_functions(raw, report, source)["f"]
    except ValueError:
        return
    assert raw[start:end].startswith(b"__declspec(dllexport)")


def test_inventory_requires_exact_reported_path_and_refuses_internal_marker(tmp_path: Path) -> None:
    source = tmp_path / "one" / "unit.c"
    other = tmp_path / "two" / "unit.c"

    def marker(path: Path) -> str:
        encoded = ("Z:" + str(path).replace("/", "\\")).replace("\\", "\\\\")
        return f'#line 1 "{encoded}"\n'

    raw = (
        marker(source)
        + "int expected(void) {return 1;}\n"
        + marker(other)
        + "int unrelated(void) {return 2;}\n"
    ).encode()
    report = parse_msvc_preprocessed(raw)
    assert set(reported_source_functions(raw, report, source)) == {"expected"}
    interior = (marker(source) + "int f(void) {\n" + marker(other) + "return 1;\n}\n").encode()
    with pytest.raises(ValueError, match="contains a preprocessor line marker"):
        reported_source_functions(interior, parse_msvc_preprocessed(interior), source)


def test_declaration_scope_inventory_retains_order_and_unknowns(tmp_path: Path) -> None:
    source = tmp_path / "unit.c"
    encoded = ("Z:" + str(source).replace("/", "\\")).replace("\\", "\\\\")
    raw = (
        f'#line 1 "{encoded}"\n'
        "extern int item;\nextern int item;\nint f(void) { return item + unresolved(); }\n"
    ).encode()
    report = parse_msvc_preprocessed(raw)
    scopes = reported_declaration_scopes(raw, report, source, expected_names={"f"})
    declarations = scopes["functions"]["f"]["item"]
    assert len(declarations) == 2 and declarations[0]["start"] < declarations[1]["start"]
    assert scopes["functions"]["f"]["unresolved"] == []
    assert not scopes["reference_classification_proven"]
    assert not scopes["declaration_extents_proven"] and not scopes["abi_proven"]


@pytest.mark.parametrize(
    "prefix", ["__stdcall ", "__cdecl /* comment */ ", "__stdcall\n/* comment */\n"]
)
def test_declaration_scope_refuses_masked_convention_prefix(tmp_path: Path, prefix: str) -> None:
    source = tmp_path / "unit.c"
    encoded = ("Z:" + str(source).replace("/", "\\")).replace("\\", "\\\\")
    raw = f'#line 1 "{encoded}"\n{prefix}int dep(void);\nint f(void) {{ return dep(); }}\n'.encode()
    with pytest.raises(ValueError, match="precedes a visible declaration"):
        reported_declaration_scopes(raw, parse_msvc_preprocessed(raw), source, expected_names={"f"})
