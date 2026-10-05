"""Storage owners, extern declarations, and symbol users stay separate."""

from io import StringIO
from pathlib import Path

from rich.console import Console

from rebrew.c_parser import find_variable_roles
from rebrew.data_render import render_globals
from rebrew.data_scan import scan_globals


def test_function_pointer_type_keeps_calling_convention_in_inventory(tmp_path: Path) -> None:
    (tmp_path / "runtime.h").write_text(
        "// GLOBAL: SERVER 0x1000\n"
        "extern int (__stdcall *g_handler)(void *, unsigned int, void *);\n"
    )
    scan = scan_globals(tmp_path)
    entry = scan.globals["g_handler"]
    assert entry.type_str == "int (__stdcall *)(void *, unsigned int, void *)"
    assert entry.to_dict()["type"] == entry.type_str
    buf = StringIO()
    # TERM=dumb with FORCE_COLOR set ignores width unless height is set too.
    render_globals(Console(file=buf, width=240, height=40, color_system=None), scan)
    assert entry.type_str in buf.getvalue()


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


def test_first_field_alias_does_not_reclassify_its_backing_definition(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from rebrew.data_metadata import set_data_fields_batch
    from rebrew.data_ownership import resolve_backing_owners

    (tmp_path / "owner.c").write_text("// GLOBAL: SERVER 0x1000\nint storage[8];\n")
    (tmp_path / "field.h").write_text("// GLOBAL: SERVER 0x1000\nextern int first;\n")
    set_data_fields_batch(
        tmp_path,
        [
            {
                "va": 0x1000,
                "module": "SERVER",
                "updated_by": "data",
                "fields": {
                    "name": "storage",
                    "size": 32,
                    "storage_kind": "alias",
                    "backing": "storage",
                },
            }
        ],
    )
    cfg = SimpleNamespace(marker="SERVER", all_markers={"SERVER"}, metadata_dir=tmp_path)
    scan = scan_globals(tmp_path, cfg)
    resolve_backing_owners(scan)
    assert scan.globals["storage"].storage_kind == "object"
    assert scan.globals["storage"].backing == ""
    assert scan.globals["storage"].size == 32
    assert scan.globals["first"].storage_kind == "alias"
    assert scan.globals["first"].size == 4
    assert scan.globals["first"].generated_owners == ["owner.c (via storage)"]


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


def test_multiline_marker_declaration_keeps_foreign_target_scoping(tmp_path: Path) -> None:
    from types import SimpleNamespace

    (tmp_path / "globals.h").write_text(
        "// GLOBAL: SERVER 0x1000\nextern void\n (*hook)(void);\n"
        "// GLOBAL: GOLD 0x2000\nextern unsigned\n int foreign[4];\n"
    )
    cfg = SimpleNamespace(marker="SERVER", all_markers={"SERVER", "GOLD"}, metadata_dir=tmp_path)
    scan = scan_globals(tmp_path, cfg)
    assert set(scan.globals) == {"hook"}
    assert scan.globals["hook"].va == 0x1000
    assert scan.globals["hook"].type_str.startswith("void")


def test_coverage_includes_header_data_and_separates_owner_from_declarers(tmp_path: Path) -> None:
    from rebrew.sections import get_globals

    (tmp_path / "globals.h").write_text("// DATA: SERVER 0x1000\nextern int object[4];\n")
    (tmp_path / "owner.c").write_text("int object[4];\n")
    (tmp_path / "use.c").write_text("int read(void) { return object[0]; }\n")
    row = get_globals(tmp_path)[0x1000]
    assert row["owners"] == ["owner.c"]
    assert row["referenced_in"] == ["use.c"]
    assert set(row["declared_in"]) == {"globals.h", "owner.c"}
    assert row["size"] == 16


def test_foreign_function_bodies_do_not_contribute_users(tmp_path: Path) -> None:
    from types import SimpleNamespace

    (tmp_path / "mixed.c").write_text(
        "int server_value; int foreign_value;\n"
        "// FUNCTION: SERVER 0x1000\nint server_fn(void) { return server_value; }\n"
        "// FUNCTION: GOLD 0x2000\nint gold_fn(void) { return foreign_value; }\n"
    )
    cfg = SimpleNamespace(marker="SERVER", all_markers={"SERVER", "GOLD"}, metadata_dir=tmp_path)
    scan = scan_globals(tmp_path, cfg)
    assert scan.globals["server_value"].referenced_in == ["mixed.c"]
    assert scan.globals["foreign_value"].referenced_in == []


def test_stacked_identity_markers_keep_shared_function_users(tmp_path: Path) -> None:
    from types import SimpleNamespace

    (tmp_path / "shared.c").write_text(
        "int value;\n// FUNCTION: SERVER 0x1000\n// FUNCTION: GOLD 0x2000\n"
        "int shared(void) { return value; }\n"
    )
    cfg = SimpleNamespace(marker="SERVER", all_markers={"SERVER", "GOLD"}, metadata_dir=tmp_path)
    assert scan_globals(tmp_path, cfg).globals["value"].referenced_in == ["shared.c"]
