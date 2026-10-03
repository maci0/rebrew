"""Linked library data owners need symbol and selected-member evidence."""

import struct
from pathlib import Path
from types import SimpleNamespace

import pytest
from bin_util import make_coff_obj, make_lib_archive
from typer.testing import CliRunner

from rebrew.data_ownership import enrich_library_owners, parse_link_map
from rebrew.data_scan import GlobalEntry, ScanResult


def _cfg(root: Path, **kwargs: object) -> SimpleNamespace:
    return SimpleNamespace(root=root, arch="x86_32", compiler_profile="msvc-6.0", **kwargs)


def _common_object(name: str, size: int) -> bytes:
    obj = bytearray(make_coff_obj(b"", func_symbol=name))
    offset = struct.unpack_from("<I", obj, 8)[0]
    struct.pack_into("<IhH", obj, offset + 8, size, 0, 0)
    return bytes(obj)


def test_map_distinguishes_archives_common_objects_functions_and_imports() -> None:
    rows = parse_link_map(
        " 0003:00000000 ___argc 117663d4 LIBCMT:crt0dat.obj\n"
        " 0003:00000004 _g 117663d8 <common>\n"
        " 0003:00000008 _source 117663dc C:\\game\\source.obj\n"
        " 0001:00000000 _init 10001000 f C:\\SDK\\CRT.lib:heap.obj\n"
        " 0002:00000000 __imp__GetVersion@0 10024000 KERNEL32:KERNEL32.dll\n"
        " 0001:00000004 _import 10001004 f i KERNEL32:KERNEL32.dll\n"
    )
    assert [(r.name, r.library, r.member, r.common, r.is_function) for r in rows] == [
        ("___argc", "LIBCMT", "crt0dat.obj", False, False),
        ("_g", "", "", True, False),
        ("_source", "", "", False, False),
        ("_init", "CRT.lib", "heap.obj", False, True),
    ]


def test_map_matches_symbol_name_even_if_reference_va_drifted(tmp_path: Path) -> None:
    link_map = tmp_path / "server.map"
    link_map.write_text(" 0003:00000000 ___argc 117663d4 LIBCMT:crt0dat.obj\n")
    entry = GlobalEntry("__argc", va=0x100354C4, declared_in=["crt_globals.h"])
    scan = ScanResult(globals={entry.name: entry})
    cfg = _cfg(tmp_path, raw_link=tmp_path / "server.dll", external_libs={})
    enrich_library_owners(scan, cfg)
    assert entry.defined_in == []
    owner = entry.library_owners[0]
    assert (owner["library"], owner["member"], owner["symbol"]) == (
        "LIBCMT",
        "crt0dat.obj",
        "___argc",
    )
    assert owner["linked_va"] == "0x117663d4"
    assert owner["evidence"] == "link-map"
    assert len(owner["map_hash"]) == 64
    assert scan.to_dict()["summary"]["library_owned"] == 1


def test_no_prefix_header_or_va_guessing(tmp_path: Path) -> None:
    link_map = tmp_path / "server.map"
    link_map.write_text(" 0003:00000000 ___argc 100354c4 LIBCMT:crt0dat.obj\n")
    entry = GlobalEntry("g_crt_argc", va=0x100354C4, declared_in=["crt_globals.h"])
    scan = ScanResult(globals={entry.name: entry})
    enrich_library_owners(scan, _cfg(tmp_path), link_map)
    assert entry.library_owners == []


def test_common_owner_requires_a_selected_defining_member(tmp_path: Path) -> None:
    archive = tmp_path / "crt.lib"
    archive.write_bytes(
        make_lib_archive(
            [
                ("heap.obj", _common_object("_g", 4)),
                ("unused.obj", _common_object("_g", 4)),
                ("reader.obj", _common_object("_g", 0)),
            ]
        )
    )
    link_map = tmp_path / "server.map"
    link_map.write_text(
        " 0001:00000000 _heap_init 10001000 f CRT:heap.obj\n"
        " 0001:00000020 _read 10001020 f CRT:reader.obj\n"
        " 0003:00000000 _g 117663d4 <common>\n"
    )
    entry = GlobalEntry("g")
    scan = ScanResult(globals={"g": entry})
    cfg = _cfg(tmp_path, external_libs={"CRT": "./crt.lib"})
    enrich_library_owners(scan, cfg, link_map)
    owner = entry.library_owners[0]
    assert (owner["library"], owner["member"]) == ("CRT", "heap.obj")
    assert owner["evidence"] == "link-map+archive"
    assert len(owner["archive_hash"]) == 64
    # Selecting a second defining member makes COMMON attribution ambiguous.
    link_map.write_text(link_map.read_text() + " 0001:00000040 _other 10001040 f CRT:unused.obj\n")
    enrich_library_owners(scan, cfg, link_map)
    assert entry.library_owners == []


def test_map_source_or_function_never_becomes_a_library_data_owner(tmp_path: Path) -> None:
    link_map = tmp_path / "server.map"
    link_map.write_text(
        " 0003:00000000 _g 100354c4 local.obj\n 0001:00000000 _fn 10001000 f CRT:code.obj\n"
    )
    scan = ScanResult(
        globals={"g": GlobalEntry("g", defined_in=["local.c"]), "fn": GlobalEntry("fn")}
    )
    enrich_library_owners(scan, _cfg(tmp_path), link_map)
    assert scan.globals["g"].defined_in == ["local.c"]
    assert all(not g.library_owners for g in scan.globals.values())


def test_missing_auto_map_is_optional_explicit_missing_map_errors(tmp_path: Path) -> None:
    scan = ScanResult(globals={"g": GlobalEntry("g")})
    cfg = _cfg(tmp_path, raw_link=tmp_path / "missing.dll")
    enrich_library_owners(scan, cfg)
    assert scan.globals["g"].library_owners == []
    with pytest.raises(FileNotFoundError):
        enrich_library_owners(scan, cfg, tmp_path / "missing.map")


def test_data_cli_exposes_explicit_library_owners(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json

    import rebrew.data as cli

    src = tmp_path / "src"
    src.mkdir()
    (src / "crt.h").write_text("// GLOBAL: SERVER 0x100354c4\nextern int __argc;\n")
    link_map = tmp_path / "server.map"
    link_map.write_text(" 0003:00000000 ___argc 117663d4 LIBCMT:crt0dat.obj\n")
    cfg = _cfg(
        tmp_path,
        reversed_dir=src,
        target_binary=tmp_path / "missing.dll",
        metadata_dir=tmp_path,
        marker="SERVER",
        source_ext=".c",
        external_libs={},
        target_name="SERVER",
        all_targets=["SERVER"],
    )
    monkeypatch.setattr(cli, "require_config", lambda **kwargs: cfg)
    result = CliRunner().invoke(cli.app, ["--link-map", str(link_map), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["globals"]["__argc"]["library_owners"][0]["member"] == "crt0dat.obj"
    assert payload["summary"]["library_owned"] == 1


def test_stock_cache_case_matches_the_stock_lib_cli(tmp_path: Path) -> None:
    from rebrew.lib_match import stock_lib_cache

    cache = stock_lib_cache(tmp_path, "CRT.LIB", "msvc-6.0")
    cache.parent.mkdir(parents=True)
    cache.write_bytes(make_lib_archive([("heap.obj", _common_object("_g", 4))]))
    link_map = tmp_path / "server.map"
    link_map.write_text(
        " 0001:00000000 _init 10001000 f CRT:heap.obj\n 0003:00000000 _g 117663d4 <common>\n"
    )
    scan = ScanResult(globals={"g": GlobalEntry("g")})
    enrich_library_owners(scan, _cfg(tmp_path, external_libs={"CRT": "CRT.lib"}), link_map)
    assert scan.globals["g"].library_owners[0]["member"] == "heap.obj"


def test_colliding_map_symbols_do_not_choose_a_library(tmp_path: Path) -> None:
    link_map = tmp_path / "server.map"
    link_map.write_text(
        " 0003:00000000 _g 117663d4 CRT:first.obj\n 0003:00000004 _g 117663d8 CRT:second.obj\n"
    )
    scan = ScanResult(globals={"g": GlobalEntry("g")})
    enrich_library_owners(scan, _cfg(tmp_path), link_map)
    assert scan.globals["g"].library_owners == []


def test_removed_auto_map_clears_derived_library_owners(tmp_path: Path) -> None:
    link_map = tmp_path / "server.map"
    link_map.write_text(" 0003:00000000 _g 117663d4 CRT:first.obj\n")
    scan = ScanResult(globals={"g": GlobalEntry("g")})
    cfg = _cfg(tmp_path, raw_link=tmp_path / "server.dll")
    enrich_library_owners(scan, cfg)
    assert scan.globals["g"].library_owners
    link_map.unlink()
    enrich_library_owners(scan, cfg)
    assert scan.globals["g"].library_owners == []
