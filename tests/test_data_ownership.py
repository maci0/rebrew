"""Storage owners, extern declarations, and symbol users stay separate."""

from io import StringIO
lazy from pathlib import Path

from rich.console import Console
from source_util import write_source

from rebrew.c_parser import find_variable_roles
from rebrew.data_render import render_globals
from rebrew.data_scan import scan_data_annotations, scan_globals


def test_function_pointer_type_keeps_calling_convention_in_inventory(tmp_path: Path) -> None:
    write_source(
        tmp_path / "runtime.h",
        "/* ADDRESS: SERVER 0x1000 */\nextern int (__stdcall *g_handler)(void *, unsigned int, void *);\n",
        metadata_fields={"SERVER.0x1000": {"kind": "GLOBAL"}},
    )
    scan = scan_globals(tmp_path)
    entry = scan.globals["g_handler"]
    assert entry.type_str == "int (__stdcall *)(void *, unsigned int, void *)"
    assert entry.to_dict()["type"] == entry.type_str
    buf = StringIO()
    # TERM=dumb with FORCE_COLOR set ignores width unless height is set too.
    render_globals(Console(file=buf, width=240, height=40, color_system=None), scan)
    assert entry.type_str in buf.getvalue()


def test_filtered_definition_does_not_contribute_initializer_uses() -> None:
    source = "extern int server; extern int client;\nint *foreign = &server, *local = &client;\n"
    definitions, declarations, uses = find_variable_roles(
        source, variable_filter=lambda name, _definition: name != "foreign"
    )
    assert definitions == {"local"}
    assert declarations == {"server", "client"}
    assert uses == {"client"}


def test_owner_and_users_are_independent_of_markers(tmp_path: Path) -> None:
    write_source(
        tmp_path / "owner.c",
        "/* ADDRESS: SERVER 0x1000 */\nint g;\n",
        metadata_fields={"SERVER.0x1000": {"kind": "DATA"}},
    )
    write_source(
        tmp_path / "global.h",
        "/* ADDRESS: SERVER 0x1000 */\nextern int g;\n",
        metadata_fields={"SERVER.0x1000": {"kind": "GLOBAL"}},
    )
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
    write_source(
        tmp_path / "runtime.h",
        "/* ADDRESS: SERVER 0x1000 */\nextern int __argc;\n",
        metadata_fields={"SERVER.0x1000": {"kind": "GLOBAL"}},
    )
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
        write_source(
            tmp_path / name,
            "/* ADDRESS: SERVER 0x1000 */\nint g;\n",
            metadata_fields={"SERVER.0x1000": {"kind": "GLOBAL"}},
        )
    scan = scan_globals(tmp_path)
    assert scan.globals["g"].defined_in == ["a.c", "b.c"]
    assert scan.to_dict()["summary"]["multiple_definitions"] == 1


def test_first_field_alias_does_not_reclassify_its_backing_definition(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from rebrew.data_ownership import resolve_backing_owners
    from rebrew.metadata.data import set_data_fields_batch

    write_source(
        tmp_path / "owner.c",
        "/* ADDRESS: SERVER 0x1000 */\nint storage[8];\n",
        metadata_fields={"SERVER.0x1000": {"kind": "GLOBAL"}},
        metadata_dir=tmp_path,
    )
    write_source(
        tmp_path / "field.h",
        "/* ADDRESS: SERVER 0x1000 */\nextern int first;\n",
        metadata_fields={"SERVER.0x1000": {"kind": "GLOBAL"}},
        metadata_dir=tmp_path,
    )
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
    cfg = SimpleNamespace(module="SERVER", target_modules={"SERVER"}, metadata_dir=tmp_path)
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

    write_source(
        tmp_path / "globals.h",
        "/* ADDRESS: SERVER 0x1000 */\nextern void\n (*hook)(void);\n/* ADDRESS: GOLD 0x2000 */\nextern unsigned\n int foreign[4];\n",
        metadata_fields={"SERVER.0x1000": {"kind": "GLOBAL"}, "GOLD.0x2000": {"kind": "GLOBAL"}},
        metadata_dir=tmp_path,
    )
    cfg = SimpleNamespace(module="SERVER", target_modules={"SERVER", "GOLD"}, metadata_dir=tmp_path)
    scan = scan_globals(tmp_path, cfg)
    assert set(scan.globals) == {"hook"}
    assert scan.globals["hook"].va == 0x1000
    assert scan.globals["hook"].type_str.startswith("void")


def test_coverage_includes_header_data_and_separates_owner_from_declarers(tmp_path: Path) -> None:
    from rebrew.sections import get_globals

    write_source(
        tmp_path / "globals.h",
        "/* ADDRESS: SERVER 0x1000 */\nextern int object[4];\n",
        metadata_fields={"SERVER.0x1000": {"kind": "DATA"}},
    )
    (tmp_path / "owner.c").write_text("int object[4];\n")
    (tmp_path / "use.c").write_text("int read(void) { return object[0]; }\n")
    row = get_globals(tmp_path)[0x1000]
    assert row["owners"] == ["owner.c"]
    assert row["referenced_in"] == ["use.c"]
    assert set(row["declared_in"]) == {"globals.h", "owner.c"}
    assert row["size"] == 16


def test_foreign_function_bodies_do_not_contribute_users(tmp_path: Path) -> None:
    from types import SimpleNamespace

    write_source(
        tmp_path / "mixed.c",
        "int server_value; int foreign_value;\n/* ADDRESS: SERVER 0x1000 */\nint server_fn(void) { return server_value; }\n/* ADDRESS: GOLD 0x2000 */\nint gold_fn(void) { return foreign_value; }\n",
        metadata_fields={
            "SERVER.0x1000": {"kind": "FUNCTION"},
            "GOLD.0x2000": {"kind": "FUNCTION"},
        },
        metadata_dir=tmp_path,
    )
    cfg = SimpleNamespace(module="SERVER", target_modules={"SERVER", "GOLD"}, metadata_dir=tmp_path)
    scan = scan_globals(tmp_path, cfg)
    assert scan.globals["server_value"].referenced_in == ["mixed.c"]
    assert scan.globals["foreign_value"].referenced_in == []


def test_stacked_identity_markers_keep_shared_function_users(tmp_path: Path) -> None:
    from types import SimpleNamespace

    write_source(
        tmp_path / "shared.c",
        "int value;\n/* ADDRESS: SERVER 0x1000 */\n/* ADDRESS: GOLD 0x2000 */\nint shared(void) { return value; }\n",
        metadata_fields={
            "SERVER.0x1000": {"kind": "FUNCTION"},
            "GOLD.0x2000": {"kind": "FUNCTION"},
        },
        metadata_dir=tmp_path,
    )
    cfg = SimpleNamespace(module="SERVER", target_modules={"SERVER", "GOLD"}, metadata_dir=tmp_path)
    assert scan_globals(tmp_path, cfg).globals["value"].referenced_in == ["shared.c"]


class TestRoleIndexing:
    def test_users_keep_file_order_and_unknown_identifiers_do_not_create_globals(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "globals.h").write_text("extern int first; extern int second;\n")
        (tmp_path / "a.c").write_text("int first; int a(void) { return second + unknown; }\n")
        (tmp_path / "z.c").write_text("int second; int z(void) { return first + second; }\n")
        scan = scan_globals(tmp_path)
        assert set(scan.globals) == {"first", "second"}
        assert scan.globals["first"].defined_in == ["a.c"]
        assert scan.globals["second"].defined_in == ["z.c"]
        assert scan.globals["first"].referenced_in == ["z.c"]
        assert scan.globals["second"].referenced_in == ["a.c", "z.c"]


def test_data_scans_reuse_a_shared_tree_walk(tmp_path: Path, monkeypatch) -> None:
    """``rebrew data list`` walks the tree once and hands it to both scans."""
    import rebrew.sources as sources

    (tmp_path / "a.c").write_text("int first;\nint table[4];\n")
    scanned = sources.scan_files(tmp_path)

    def no_walk(*_args: object, **_kwargs: object) -> list[Path]:
        raise AssertionError("data scans walked the tree again")

    monkeypatch.setattr(sources, "scan_files", no_walk)
    scan = scan_globals(tmp_path, scanned=scanned)
    annotations = scan_data_annotations(tmp_path, scanned=scanned)

    assert set(scan.globals) == {"first", "table"}
    assert annotations == []


def test_warm_data_scan_replays_roles_without_parsing_again(tmp_path: Path, monkeypatch) -> None:
    """``rebrew data`` calls ``scan_globals``. A second scan of unchanged sources must not parse them."""
    from unittest.mock import Mock

    from rebrew.c_parser import find_extern_variables, find_variable_roles
    from rebrew.data_scan import _ROLE_FACT_CACHE

    source = tmp_path / "a.c"
    source.write_text("int first;\nint a(void) { return first; }\n")
    roles = Mock(wraps=find_variable_roles)
    externs = Mock(wraps=find_extern_variables)
    monkeypatch.setattr("rebrew.c_parser.find_variable_roles", roles)
    monkeypatch.setattr("rebrew.c_parser.find_extern_variables", externs)

    cold = scan_globals(tmp_path)
    assert roles.call_count == 1
    assert externs.call_count == 1
    assert (tmp_path / ".rebrew" / "data-scan-roles.json").is_file()

    _ROLE_FACT_CACHE.clear()
    warm = scan_globals(tmp_path)
    assert roles.call_count == 1
    assert externs.call_count == 1
    assert warm.globals["first"].defined_in == cold.globals["first"].defined_in == ["a.c"]
    assert warm.globals["first"].referenced_in == cold.globals["first"].referenced_in == ["a.c"]

    source.write_text("int first;\nint a(void) { return 0; }\n")
    changed = scan_globals(tmp_path)
    assert roles.call_count == 2
    assert externs.call_count == 2
    assert changed.globals["first"].defined_in == ["a.c"]
    assert changed.globals["first"].referenced_in == []


def test_data_scan_caches_are_bounded(tmp_path: Path) -> None:
    """Per-root and per-target fact caches must not grow with every root visited."""
    import rebrew.data_scan as data_scan

    data_scan._NAME_COVER_CACHE.clear()
    data_scan._ROLE_FACT_CACHE.clear()
    roots = [tmp_path / f"root-{index}" for index in range(data_scan._NAME_COVER_CACHE_MAX + 2)]
    for root in roots:
        root.mkdir()
        data_scan._begin_name_cover(root)
        data_scan._begin_role_cache(root, None)
    assert len(data_scan._NAME_COVER_CACHE) == data_scan._NAME_COVER_CACHE_MAX
    assert len(data_scan._ROLE_FACT_CACHE) == data_scan._ROLE_FACT_CACHE_MAX
    assert str(roots[0].resolve()) not in data_scan._NAME_COVER_CACHE
    assert str(roots[-1].resolve()) in data_scan._NAME_COVER_CACHE


def test_name_cover_publishes_one_record_per_store(tmp_path: Path, monkeypatch) -> None:
    """Two scans that miss together must share one cover record.

    Each built its own record after reading the same cache file, and the later
    publish replaced the map the earlier scan was filling.
    """
    import json
    import threading

    import rebrew.data_scan as data_scan

    stamp = data_scan._store_stamp(tmp_path)
    cache_path = tmp_path / ".rebrew" / "name-map-cover.json"
    cache_path.parent.mkdir(parents=True)
    cache_path.write_text(
        json.dumps({"version": data_scan._NAME_COVER_VERSION, "stamp": stamp, "files": {}}),
        encoding="utf-8",
    )
    data_scan._NAME_COVER_CACHE.clear()
    published = {
        "dir": tmp_path,
        "stamp": stamp,
        "files": {},
        "dirty": False,
        "lock": threading.Lock(),
    }
    real_loads = data_scan.json.loads

    def _loads(text: str) -> object:
        with data_scan._NAME_COVER_CACHE_LOCK:
            data_scan._NAME_COVER_CACHE.setdefault(data_scan._path_key(tmp_path), published)
        return real_loads(text)

    monkeypatch.setattr(data_scan.json, "loads", _loads)
    assert data_scan._begin_name_cover(tmp_path) is published


def test_role_cache_publishes_one_record_per_identity(tmp_path: Path, monkeypatch) -> None:
    """The role record has the same publish race as the name cover."""
    import json
    import threading

    import rebrew.data_scan as data_scan

    stamp = data_scan._store_stamp(tmp_path)
    identity = data_scan._role_identity(None)
    cache_path = tmp_path / ".rebrew" / "data-scan-roles.json"
    cache_path.parent.mkdir(parents=True)
    cache_path.write_text(
        json.dumps(
            {
                "version": data_scan._ROLE_FACT_VERSION,
                "stamp": stamp,
                "identity": identity,
                "files": {},
            }
        ),
        encoding="utf-8",
    )
    data_scan._ROLE_FACT_CACHE.clear()
    published = {
        "dir": tmp_path,
        "stamp": stamp,
        "identity": identity,
        "version": data_scan._ROLE_FACT_VERSION,
        "files": {},
        "dirty": False,
        "lock": threading.Lock(),
    }
    real_loads = data_scan.json.loads

    def _loads(text: str) -> object:
        with data_scan._ROLE_FACT_CACHE_LOCK:
            data_scan._ROLE_FACT_CACHE.setdefault(
                data_scan._path_key(tmp_path) + "\n" + identity, published
            )
        return real_loads(text)

    monkeypatch.setattr(data_scan.json, "loads", _loads)
    assert data_scan._begin_role_cache(tmp_path, None) is published


def test_name_cover_flush_serializes_a_concurrent_remember(tmp_path: Path, monkeypatch) -> None:
    """A flush must not mark a remember clean before it reaches the file.

    Concurrent scans of one metadata root share the record, and the flush used
    to build its payload and clear ``dirty`` outside any per-record section: a
    remember landing in that window was dropped from the file and never
    written, so the next process re-parsed the file this one had already done.
    """
    import threading

    from thread_util import join_all

    import rebrew.data_scan as data_scan

    first = tmp_path / "a.c"
    first.write_text("int first;\n")
    second = tmp_path / "b.c"
    second.write_text("int second;\n")
    data_scan._NAME_COVER_CACHE.clear()
    cover = data_scan._begin_name_cover(tmp_path)
    data_scan._name_cover_remember(cover, first)

    writing = threading.Event()
    release = threading.Event()
    real_write = data_scan.atomic_write_text

    def _blocking_write(path, text, **kwargs):
        writing.set()
        assert release.wait(10.0), "test never released the cover write"
        return real_write(path, text, **kwargs)

    monkeypatch.setattr(data_scan, "atomic_write_text", _blocking_write)
    flush = threading.Thread(target=data_scan._flush_name_cover, args=(cover,))
    flush.start()
    assert writing.wait(10.0), "flush never reached the write"

    remembered = threading.Event()

    def _remember() -> None:
        data_scan._name_cover_remember(cover, second)
        remembered.set()

    remember = threading.Thread(target=_remember)
    remember.start()
    # The record lock makes the remember wait for the flush.  Without it the
    # remember lands mid-write and the flush then clears dirty over it.
    assert not remembered.wait(0.2), "remember ran inside the flush window"
    release.set()
    join_all([flush, remember])
    assert remembered.is_set()
    assert cover["dirty"] is True


def test_unversioned_name_cover_is_ignored(tmp_path: Path) -> None:
    """A cover written by older coverage semantics must not skip a source."""
    import json

    import rebrew.data_scan as data_scan

    source = tmp_path / "a.c"
    source.write_text("int first;\n")
    stamp = data_scan._source_stamp(source)
    assert stamp is not None
    files = {str(source.resolve()): stamp}
    payload = {"stamp": data_scan._store_stamp(tmp_path), "files": files}
    cache_path = tmp_path / ".rebrew" / "name-map-cover.json"
    cache_path.parent.mkdir(parents=True)
    cache_path.write_text(json.dumps(payload), encoding="utf-8")
    data_scan._NAME_COVER_CACHE.clear()
    assert data_scan._begin_name_cover(tmp_path)["files"] == {}
    payload["version"] = data_scan._NAME_COVER_VERSION
    cache_path.write_text(json.dumps(payload), encoding="utf-8")
    data_scan._NAME_COVER_CACHE.clear()
    assert data_scan._begin_name_cover(tmp_path)["files"] == files
