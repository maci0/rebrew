"""Conditional opening braces must not consume later C definitions."""

from rebrew.c_parser import (
    find_c_function_definitions,
    find_extern_variables,
    find_variable_roles,
    function_definition_spans,
)
from rebrew.split import source_layout

SOURCE = """int counter = 3;
extern int left, right;
void first(int local)
{
#ifdef FIRST
    if (left) {
#else
    if (right) {
#endif
        local++;
    }
}
int second(int n, ...)
{
    return counter + n;
}
"""


def test_definition_inventory_and_complete_extents() -> None:
    assert find_c_function_definitions(SOURCE) == [("first", 3), ("second", 13)]
    spans = function_definition_spans(SOURCE)
    assert [name for name, _, _ in spans] == ["first", "second"]
    assert (
        SOURCE.encode()[spans[0][1] : spans[0][2]]
        == SOURCE.encode()[SOURCE.index("void first") : SOURCE.index("int second")].rstrip()
    )


def test_layout_retains_one_body_and_each_storage_owner() -> None:
    raw, spans = source_layout(SOURCE)
    functions = [span for span in spans if span.kind == "function"]
    assert [span.name for span in functions] == ["first", "second"]
    assert not any(span.inside_pp for span in functions)
    assert raw[functions[0].start : functions[0].end].endswith(b"local++;\n    }\n}")
    assert [span.name for span in spans if span.kind == "storage"] == ["counter"]


def test_roles_keep_both_branches_and_parameter_shadowing() -> None:
    definitions, declarations, uses = find_variable_roles(SOURCE)
    assert definitions == {"counter"}
    assert declarations == {"left", "right"}
    assert uses == {"left", "right", "counter"}
    assert find_variable_roles(SOURCE, function_filter=lambda _: False)[2] == set()
    found = find_extern_variables(SOURCE, include_definitions=True)
    assert [(row.name, row.line) for row in found] == [("counter", 1), ("left", 2), ("right", 2)]


def test_fake_directives_and_braces_in_strings_comments_and_macros() -> None:
    source = (
        "/* café\n#if FAKE\n{\n#else\n{\n#endif\n*/\n"
        "#define MACRO { \\\n }\n"
        'const char *s = "{\\\n#if FAKE\\\n}";\n' + SOURCE
    )
    names = [name for name, _ in find_c_function_definitions(source)]
    assert names == ["first", "second"]
    assert find_variable_roles(source)[2] == {"left", "right", "counter"}


def test_nested_gnu_function_stays_with_its_outer_definition() -> None:
    source = "void outer(void) { int inner(void) { return 1; } inner(); }"
    assert find_c_function_definitions(source) == [("outer", 1)]
    assert function_definition_spans(source) == [("outer", 0, len(source))]


def test_nested_alternatives_in_an_inactive_parent_are_all_inventoried() -> None:
    source = """#if OUTER
#if INNER
void aa(void) {
#else
void ab(void) {
#endif
#else
#if OTHER
void ba(void) {
#else
void bb(void) {
#endif
#endif
    return;
}
void tail(void) {}
"""
    assert [name for name, _ in find_c_function_definitions(source)] == [
        "aa",
        "ab",
        "ba",
        "bb",
        "tail",
    ]
    _, spans = source_layout(source)
    (first,) = [span for span in spans if span.name == "aa"]
    assert first.inside_pp
