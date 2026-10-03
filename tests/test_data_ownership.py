"""Storage owners, extern declarations, and symbol users stay separate."""

from io import StringIO
from pathlib import Path

from rich.console import Console

from rebrew.c_parser import find_variable_roles
from rebrew.data_render import render_globals
from rebrew.data_scan import scan_globals


def test_owner_and_users_are_independent_of_markers(tmp_path: Path) -> None:
    (tmp_path / "owner.c").write_text("// DATA: SERVER 0x1000\nint g;\n")
    (tmp_path / "global.h").write_text("// GLOBAL: SERVER 0x1000\nextern int g;\n")
    (tmp_path / "declaration.c").write_text("extern int g;\n")
    (tmp_path / "user.c").write_text("extern int g;\nint read(void) { return g; }\n")
    (tmp_path / "include_user.c").write_text('#include "global.h"\nint read2(void) { return g; }\n')
    scan = scan_globals(tmp_path)
    entry = scan.globals["g"]
    assert entry.defined_in == ["owner.c"]
    assert entry.referenced_in == ["include_user.c", "user.c"]
    assert set(entry.declared_in) == {"owner.c", "global.h", "declaration.c", "user.c"}
    assert scan.to_dict()["summary"]["multiple_definitions"] == 0
    assert entry.to_dict()["defined_in"] == ["owner.c"]
    assert entry.to_dict()["referenced_in"] == ["include_user.c", "user.c"]


def test_extern_only_inventory_has_no_source_owner(tmp_path: Path) -> None:
    (tmp_path / "runtime.h").write_text("// GLOBAL: SERVER 0x1000\nextern int __argc;\n")
    scan = scan_globals(tmp_path)
    entry = scan.globals["__argc"]
    assert entry.defined_in == []
    assert entry.referenced_in == []
    buf = StringIO()
    render_globals(Console(file=buf, width=180, color_system=None), scan)
    assert "Owner" in buf.getvalue()
    assert "library:object with link-map evidence" in buf.getvalue()


def test_duplicate_tentative_definitions_are_owners(tmp_path: Path) -> None:
    for name in ("a.c", "b.c"):
        (tmp_path / name).write_text("// GLOBAL: SERVER 0x1000\nint g;\n")
    scan = scan_globals(tmp_path)
    assert scan.globals["g"].defined_in == ["a.c", "b.c"]
    assert scan.to_dict()["summary"]["multiple_definitions"] == 1


def test_roles_include_initialized_externs_and_function_pointer_storage() -> None:
    owners, declarations, users = find_variable_roles(
        "extern int declared; extern int initialized = 3; int tentative;\n"
        "void (*hook)(int); extern void (*other_hook)(int);\n"
        "int function(int); int run(void) { hook(declared); return initialized; }\n"
    )
    assert owners == {"initialized", "tentative", "hook"}
    assert declarations == {"declared", "other_hook"}
    assert users == {"hook", "declared", "initialized"}


def test_uses_exclude_declarations_members_strings_and_shadowed_names() -> None:
    assert find_variable_roles("int f(int g) { return g; }")[2] == set()
    assert find_variable_roles("int f(void) { int g; return g; }")[2] == set()
    assert "g" not in find_variable_roles("int f(void) { struct S *p; return p->g; }")[2]
    assert "g" not in find_variable_roles('char *s = "g";')[2]
    assert find_variable_roles("int f(void) { { int g; } return g; }")[2] == {"g"}


def test_imported_storage_is_never_a_local_owner() -> None:
    owners, declarations, users = find_variable_roles(
        "__declspec(dllimport) int imported; int run(void) { return imported; }"
    )
    assert owners == set()
    assert declarations == {"imported"}
    assert users == {"imported"}


def test_for_scope_does_not_shadow_a_global_after_the_loop() -> None:
    assert find_variable_roles("int run(void) { for (int g = 0; g < 1; ++g) {} return g; }")[2] == {
        "g"
    }
