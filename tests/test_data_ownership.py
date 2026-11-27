"""Storage owners, extern declarations, and symbol users stay separate."""

import sqlite3
from io import StringIO
from typing import Any
lazy from pathlib import Path

import pytest
from rich.console import Console
from source_util import write_source

from rebrew.c_syntax.parser import find_variable_roles
from rebrew.config import load_config
from rebrew.data.render import render_globals
from rebrew.data.scan import scan_data_annotations, scan_globals


def _sqlite_scan_project(root: Path, count: int) -> Any:
    """A SQLite-backed target with *count* sources binding functions and data.

    Each source has a function anchor, a data anchor, a migrated data row with
    no anchor, and an anchored extern of a global whose row names the header.
    """
    (root / "src").mkdir(parents=True)
    (root / "rebrew-project.toml").write_text(
        '[project]\ndefault_target = "game"\nshared_dir = ""\n'
        '[targets.game]\nbinary = "game.exe"\nreversed_dir = "src"\nmodule = "GAME"\n'
        '[metadata]\nbackend = "sqlite"\n'
    )
    (root / "src" / "shared.c").write_text('#include "globals.h"\nint g_shared;\n')
    for i in range(count):
        counter, table, function = 0x30000 + i * 0x10, 0x38000 + i * 0x10, 0x10000 + i * 0x100
        write_source(
            root / "src" / f"unit_{i}.c",
            f"/* ADDRESS: GAME 0x{counter:x} */\nint g_counter_{i} = 1;\n"
            f"int g_table_{i}[4];\n/* ADDRESS: GAME 0x40000 */\nextern int g_shared;\n"
            f"/* ADDRESS: GAME 0x{function:x} */\n"
            f"int f_{i}(void) {{ return g_counter_{i} + g_table_{i}[0] + g_shared; }}\n",
            metadata_fields={
                f"GAME.0x{counter:x}": {"kind": "GLOBAL", "size": 4, "status": "EXACT"},
                f"GAME.0x{table:x}": {"kind": "DATA", "name": f"g_table_{i}", "size": 16},
                f"GAME.0x{function:x}": {"size": 16},
            },
            metadata_dir=root,
        )
    # Last, so the shared row names the header rather than the final unit.
    write_source(
        root / "src" / "globals.h",
        "/* ADDRESS: GAME 0x40000 */\nextern int g_shared;\n",
        metadata_fields={"GAME.0x40000": {"kind": "GLOBAL", "size": 4}},
        metadata_dir=root,
    )
    return load_config(root)


def _count_sqlite_opens(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    opens: list[object] = []
    real = sqlite3.connect

    def counting(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        opens.append(args[0])
        return real(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", counting)
    return opens


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

    from rebrew.data.ownership import resolve_backing_owners
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
    from rebrew.binary.sections import get_globals

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
    import rebrew.source.discovery as sources

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

    from rebrew.c_syntax.parser import find_extern_variables, find_variable_roles
    from rebrew.data.scan import _ROLE_FACT_CACHE

    source = tmp_path / "a.c"
    source.write_text("int first;\nint a(void) { return first; }\n")
    roles = Mock(wraps=find_variable_roles)
    externs = Mock(wraps=find_extern_variables)
    monkeypatch.setattr("rebrew.c_syntax.parser.find_variable_roles", roles)
    monkeypatch.setattr("rebrew.c_syntax.parser.find_extern_variables", externs)

    import os

    # The role cache is a cache: it is written whole by a rename, never synced to disk.
    syncs: list[int] = []
    real_fsync = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (syncs.append(fd), real_fsync(fd))[1])
    cold = scan_globals(tmp_path)
    assert syncs == []
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
    import rebrew.data.scan as data_scan

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


@pytest.mark.parametrize("roles", [False, True])
def test_data_scan_keeps_cache_facts_with_the_revision_read(
    tmp_path: Path, monkeypatch, roles: bool
) -> None:
    from rebrew.data import scan as data_scan

    source = tmp_path / "globals.c"
    source.write_text("int retired;\n", encoding="utf-8")
    replacement = source.with_suffix(".new")
    replacement.write_text(
        "/* ADDRESS: SERVER 0x501000 */\nextern int replacement;\n", encoding="utf-8"
    )
    hook = "_collect_scan_file_facts" if roles else "_store_names_the_file"
    original = getattr(data_scan, hook)

    def replace_after_read(*args, **kwargs):
        facts = original(*args, **kwargs)
        replacement.replace(source)
        return facts

    with monkeypatch.context() as scoped:
        scoped.setattr(data_scan, hook, replace_after_read)
        data_scan.scan_globals(tmp_path, record_roles=roles, declarations=roles)
    monkeypatch.setattr(data_scan, "_NAME_COVER_CACHE", {})
    monkeypatch.setattr(data_scan, "_ROLE_FACT_CACHE", {})
    scanned = data_scan.scan_globals(tmp_path, record_roles=roles, declarations=roles)
    assert "retired" not in scanned.globals
    assert scanned.globals["replacement"].va == 0x501000


def test_name_cover_publishes_one_record_per_store(tmp_path: Path, monkeypatch) -> None:
    """Two scans that miss together must share one cover record.

    Each built its own record after reading the same cache file, and the later
    publish replaced the map the earlier scan was filling.
    """
    import json
    import threading

    import rebrew.data.scan as data_scan

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
    import msgspec

    real_decode = msgspec.json.decode

    def _decode(raw: bytes | str) -> object:
        with data_scan._NAME_COVER_CACHE_LOCK:
            data_scan._NAME_COVER_CACHE.setdefault(data_scan._path_key(tmp_path), published)
        return real_decode(raw)

    monkeypatch.setattr(data_scan.msgspec.json, "decode", _decode)
    assert data_scan._begin_name_cover(tmp_path) is published


def test_role_cache_publishes_one_record_per_identity(tmp_path: Path, monkeypatch) -> None:
    """The role record has the same publish race as the name cover."""
    import json
    import threading

    import msgspec

    import rebrew.data.scan as data_scan

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
    real_decode = msgspec.json.decode

    def _decode(raw: bytes | str) -> object:
        with data_scan._ROLE_FACT_CACHE_LOCK:
            data_scan._ROLE_FACT_CACHE.setdefault(
                data_scan._path_key(tmp_path) + "\n" + identity, published
            )
        return real_decode(raw)

    monkeypatch.setattr(data_scan.msgspec.json, "decode", _decode)
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

    import rebrew.data.scan as data_scan

    first = tmp_path / "a.c"
    first.write_text("int first;\n")
    second = tmp_path / "b.c"
    second.write_text("int second;\n")
    data_scan._NAME_COVER_CACHE.clear()
    cover = data_scan._begin_name_cover(tmp_path)
    data_scan._name_cover_remember(cover, first, data_scan._source_stamp(first))

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
        data_scan._name_cover_remember(cover, second, data_scan._source_stamp(second))
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

    import rebrew.data.scan as data_scan

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


class TestStoreSnapshot:
    """The scan reads both stores once and joins every source against that snapshot."""

    def test_result_of_the_sqlite_fixture(self, tmp_path: Path) -> None:
        """Captured from the scan that reopened the stores per source."""
        cfg = _sqlite_scan_project(tmp_path, 2)

        def unit(name: str, va: int, size: int, type_str: str, fname: str) -> dict[str, Any]:
            return {
                "name": name,
                "va": f"0x{va:08x}",
                "type": type_str,
                "annotated": True,
                "size": size,
                "declared_in": [fname],
                "defined_in": [fname],
                "referenced_in": [fname],
                "library_owners": [],
                "generated_owners": [],
                "storage_kind": "object",
                "backing": "",
                "link_symbol": "",
            }

        expected = {
            "globals": {
                "g_counter_0": unit("g_counter_0", 0x30000, 4, "int", "unit_0.c"),
                "g_counter_1": unit("g_counter_1", 0x30010, 4, "int", "unit_1.c"),
                "g_shared": {
                    **unit("g_shared", 0x40000, 4, "int", "shared.c"),
                    "declared_in": ["shared.c", "unit_0.c", "unit_1.c", "globals.h"],
                    "referenced_in": ["unit_0.c", "unit_1.c"],
                },
                "g_table_0": unit("g_table_0", 0x38000, 16, "int[4]", "unit_0.c"),
                "g_table_1": unit("g_table_1", 0x38010, 16, "int[4]", "unit_1.c"),
            },
            "data_annotations": [],
            "type_conflicts": [],
            "summary": {
                "total": 5,
                "annotated": 5,
                "unannotated": 0,
                "conflicts": 0,
                "multiple_definitions": 0,
                "library_owned": 0,
                "data_entries": 0,
            },
        }
        assert scan_globals(cfg.reversed_dir, cfg).to_dict() == expected

    def test_store_opens_do_not_grow_with_the_sources(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Each source used to reopen both stores: 2,935 SQLite opens for one 572-source map."""
        opens = _count_sqlite_opens(monkeypatch)
        per_scan: list[int] = []
        for count in (1, 6):
            cfg = _sqlite_scan_project(tmp_path / f"sources-{count}", count)
            opens.clear()
            scan = scan_globals(cfg.reversed_dir, cfg)
            assert len(scan.globals) == 2 * count + 1
            per_scan.append(len(opens))
        assert per_scan[0] == per_scan[1]

    def test_coverage_globals_read_the_data_store_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Each annotated global used to fingerprint the data store for its size and status."""
        from rebrew.binary.sections import get_globals

        opens = _count_sqlite_opens(monkeypatch)
        per_scan: list[int] = []
        for count in (1, 6):
            cfg = _sqlite_scan_project(tmp_path / f"sources-{count}", count)
            opens.clear()
            rows = get_globals(cfg.reversed_dir, cfg)
            per_scan.append(len(opens))
            assert {row["name"]: (row["size"], row["status"]) for row in rows.values()} == {
                "g_shared": (4, ""),
                **{f"g_counter_{i}": (4, "EXACT") for i in range(count)},
                **{f"g_table_{i}": (16, "") for i in range(count)},
            }
        assert per_scan[0] == per_scan[1]
