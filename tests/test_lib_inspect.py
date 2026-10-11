"""Tests for rebrew library inspect: COFF archive members, symbols, and short imports."""

import json
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from bin_util import make_lib_archive
from typer.testing import CliRunner

from rebrew.main import app

_EXTERNAL = 2
_STATIC = 3
_WEAK_EXTERNAL = 105
_TEXT_COMDAT = 0x60501020  # code, COMDAT, align 16, execute/read
_BSS = 0xC0300080  # uninitialized data, align 4, read/write
_I386 = 0x14C


def _coff(
    sections: list[tuple[str, bytes, int]], symbols: list[tuple[str, int, int, int]]
) -> bytes:
    """COFF object with *sections* ``(name, data, chars)`` and *symbols* ``(name, value, section, class)``.

    An uninitialized section gets SizeOfRawData = len(data) and no file bytes.
    """
    strings = b""
    offsets: dict[str, int] = {}
    for name, *_ in symbols:
        if len(name) > 8:
            offsets[name] = 4 + len(strings)
            strings += name.encode() + b"\0"
    cursor = 20 + 40 * len(sections)
    headers = b""
    raw = b""
    for name, data, chars in sections:
        uninit = bool(chars & 0x80)
        pointer = 0 if uninit else cursor + len(raw)
        headers += struct.pack(
            "<8sIIIIIIHHI", name.encode(), 0, 0, len(data), pointer, 0, 0, 0, 0, chars
        )
        raw += b"" if uninit else data
    table = b""
    for name, value, section, storage in symbols:
        field = (
            struct.pack("<II", 0, offsets[name])
            if name in offsets
            else name.encode().ljust(8, b"\0")
        )
        table += field + struct.pack("<IhHBB", value, section, 0, storage, 0)
    header = struct.pack("<HHIIIHH", _I386, len(sections), 0, cursor + len(raw), len(symbols), 0, 0)
    return header + headers + raw + table + struct.pack("<I", 4 + len(strings)) + strings


def _alias_obj(alias: str, target: str) -> bytes:
    """Member whose only definition is a weak SEARCH_ALIAS *alias* -> *target*."""
    strings = target.encode() + b"\0" + alias.encode() + b"\0"
    symbols = struct.pack("<8sIhHBB", b".text", 0, 1, 0, _STATIC, 1) + bytes(18)
    symbols += struct.pack("<IIIhHBB", 0, 4, 0, 0, 0, _EXTERNAL, 0)
    symbols += struct.pack("<IIIhHBB", 0, 5 + len(target), 0, 0, 0, _WEAK_EXTERNAL, 1)
    symbols += struct.pack("<II10s", 2, 3, bytes(10))
    header = struct.pack("<HHIIIHH", _I386, 1, 0, 60, 5, 0, 0)
    section = struct.pack("<8sIIIIIIHHI", b".text", 0, 0, 0, 0, 0, 0, 0, 0, 0x60000020)
    return header + section + symbols + struct.pack("<I", len(strings) + 4) + strings


def _short_import(symbol: str, dll: str, *, import_type: int, name_type: int, hint: int) -> bytes:
    """Short import member (IMPORT_OBJECT_HEADER + symbol and DLL names)."""
    names = symbol.encode() + b"\0" + dll.encode() + b"\0"
    flags = import_type | (name_type << 2)
    return struct.pack("<HHHHIIHH", 0, 0xFFFF, 0, _I386, 0, len(names), hint, flags) + names


def _write_lib(tmp_path: Path) -> Path:
    """Archive: a data-and-code member, a user of it, a weak alias, three imports."""
    mbctype = _coff(
        [(".text", b"\xc3" * 5, _TEXT_COMDAT), (".bss", bytes(8), _BSS)],
        [
            (".text", 0, 1, _STATIC),
            ("__setmbcp", 0, 1, _EXTERNAL),
            (".bss", 0, 2, _STATIC),
            ("_fSystemSet", 0, 2, _STATIC),
            ("__mbctype", 0x101, 0, _EXTERNAL),
            ("__imp__GetCPInfo@8", 0, 0, _EXTERNAL),
            ("__lock", 0, 0, _EXTERNAL),
        ],
    )
    user = _coff(
        [(".text", b"\xc3", _TEXT_COMDAT)],
        [("_user", 0, 1, _EXTERNAL), ("__setmbcp", 0, 0, _EXTERNAL)],
    )
    lib = tmp_path / "t.lib"
    lib.write_bytes(
        make_lib_archive(
            [
                ("obj\\mbctype.obj", mbctype),
                ("obj\\user.obj", user),
                ("tcmap.obj", _alias_obj("__tcsdup", "__strdup")),
                (
                    "KERNEL32.dll",
                    _short_import(
                        "_GetCPInfo@8", "KERNEL32.dll", import_type=0, name_type=3, hint=7
                    ),
                ),
                (
                    "KERNEL32.dll",
                    _short_import("_errno_val", "MSVCRT.dll", import_type=1, name_type=2, hint=0),
                ),
                (
                    "WS2_32.dll",
                    _short_import("_recv@16", "WS2_32.dll", import_type=0, name_type=0, hint=16),
                ),
            ]
        )
    )
    return lib


def _run(args: list[str]) -> dict[str, Any]:
    res = CliRunner().invoke(app, ["library", "inspect", *args, "--json"])
    assert res.exit_code == 0, res.output
    out: dict[str, Any] = json.loads(res.stdout)
    return out


class TestListing:
    def test_coff_member_sections_and_symbols(self, tmp_path: Path) -> None:
        out = _run([str(_write_lib(tmp_path)), "--member", "mbctype.obj"])
        assert out["count"] == 1
        row = out["members"][0]
        assert row["member"] == "obj\\mbctype.obj"
        assert row["kind"] == "coff"
        text, bss = row["sections"]
        assert (text["name"], text["size"], text["align"], text["comdat"]) == (".text", 5, 16, True)
        assert (bss["name"], bss["size"], bss["align"], bss["uninitialized"]) == (
            ".bss",
            8,
            4,
            True,
        )
        assert row["defined"] == [{"name": "__setmbcp", "section": ".text", "section_index": 1}]
        assert row["common"] == [{"name": "__mbctype", "size": 0x101}]
        assert row["undefined"] == ["__imp__GetCPInfo@8", "__lock"]

    def test_weak_alias_member(self, tmp_path: Path) -> None:
        row = _run([str(_write_lib(tmp_path)), "-m", "tcmap.obj"])["members"][0]
        assert row["aliases"] == [{"name": "__tcsdup", "target": "__strdup"}]

    def test_short_import_members(self, tmp_path: Path) -> None:
        rows = [r for r in _run([str(_write_lib(tmp_path))])["members"] if r["kind"] == "import"]
        by_symbol = {r["symbol"]: r for r in rows}
        cp = by_symbol["_GetCPInfo@8"]
        assert (cp["dll"], cp["import_name"], cp["type"], cp["hint"]) == (
            "KERNEL32.dll",
            "GetCPInfo",
            "code",
            7,
        )
        assert cp["defines"] == ["__imp__GetCPInfo@8", "_GetCPInfo@8"]
        data = by_symbol["_errno_val"]
        assert (data["import_name"], data["type"], data["defines"]) == (
            "errno_val",
            "data",
            ["__imp__errno_val"],
        )
        recv = by_symbol["_recv@16"]
        assert (recv["import_name"], recv["ordinal"], recv["hint"]) == (None, 16, None)

    def test_human_output_names_dll_and_bss(self, tmp_path: Path) -> None:
        res = CliRunner().invoke(app, ["library", "inspect", str(_write_lib(tmp_path))])
        assert res.exit_code == 0, res.output
        assert "import _GetCPInfo@8 -> KERNEL32.dll!GetCPInfo (code)" in res.output
        assert "import _recv@16 -> WS2_32.dll!ordinal 16 (code)" in res.output
        assert ".bss       size 0x8 align 4 uninit" in res.output

    def test_non_coff_member_is_listed_unparsed(self, tmp_path: Path) -> None:
        lib = tmp_path / "junk.lib"
        lib.write_bytes(make_lib_archive([("junk.obj", b"\x7fELF" + bytes(60))]))
        assert _run([str(lib)])["members"] == [{"member": "junk.obj", "kind": "unparsed"}]

    def test_unknown_member_fails(self, tmp_path: Path) -> None:
        res = CliRunner().invoke(
            app, ["library", "inspect", str(_write_lib(tmp_path)), "-m", "nope.obj", "--json"]
        )
        assert res.exit_code != 0
        assert "nope.obj" in json.loads(res.stdout)["error"]


class TestQueries:
    def test_refs_lists_referencing_members(self, tmp_path: Path) -> None:
        lib = _write_lib(tmp_path)
        assert _run([str(lib), "--refs", "__imp__GetCPInfo@8"])["members"] == ["obj\\mbctype.obj"]
        assert _run([str(lib), "--refs", "__setmbcp"])["members"] == ["obj\\user.obj"]

    def test_defines_covers_section_common_alias_import(self, tmp_path: Path) -> None:
        lib = str(_write_lib(tmp_path))
        assert _run([lib, "--defines", "__setmbcp"])["members"] == [
            {"member": "obj\\mbctype.obj", "how": "section:.text"}
        ]
        assert _run([lib, "--defines", "__mbctype"])["members"] == [
            {"member": "obj\\mbctype.obj", "how": "common"}
        ]
        assert _run([lib, "--defines", "__tcsdup"])["members"] == [
            {"member": "tcmap.obj", "how": "alias"}
        ]
        assert _run([lib, "--defines", "__imp__GetCPInfo@8"])["members"] == [
            {"member": "KERNEL32.dll", "how": "import"}
        ]

    def test_refs_and_defines_are_exclusive(self, tmp_path: Path) -> None:
        res = CliRunner().invoke(
            app,
            ["library", "inspect", str(_write_lib(tmp_path)), "--refs", "a", "--defines", "b"],
        )
        assert res.exit_code != 0


class TestConfiguredArchive:
    def test_external_libs_key_resolves_to_project_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        lib = _write_lib(tmp_path)
        cfg = SimpleNamespace(
            root=tmp_path, external_libs={"MYLIB": "./t.lib"}, compiler_profile="msvc-6.0"
        )
        monkeypatch.setattr("rebrew.lib_inspect.require_config", lambda **_: cfg)
        out = _run(["mylib", "--refs", "__lock"])
        assert out["archive"] == str(lib)
        assert out["members"] == ["obj\\mbctype.obj"]

    def test_bare_spec_uses_cached_stock_archive(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cached = tmp_path / ".scratch" / "msvc-6.0_libcmt_stock.LIB"
        cached.parent.mkdir()
        cached.write_bytes(_write_lib(tmp_path).read_bytes())
        cfg = SimpleNamespace(
            root=tmp_path, external_libs={"LIBCMT": "LIBCMT.lib"}, compiler_profile="msvc-6.0"
        )
        monkeypatch.setattr("rebrew.lib_inspect.require_config", lambda **_: cfg)
        assert _run(["LIBCMT", "--defines", "__lock"])["archive"] == str(cached)

    def test_unknown_name_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = SimpleNamespace(root=tmp_path, external_libs={}, compiler_profile="msvc-6.0")
        monkeypatch.setattr("rebrew.lib_inspect.require_config", lambda **_: cfg)
        res = CliRunner().invoke(app, ["library", "inspect", "NOPE", "--json"])
        assert res.exit_code != 0
        assert "external_libs" in json.loads(res.stdout)["error"]


def test_mounted_under_library() -> None:
    res = CliRunner().invoke(app, ["library", "inspect", "--help"])
    assert res.exit_code == 0
    assert "--refs" in res.output


class TestStockExtraction:
    def test_spec_case_differs_from_the_image_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """guild-rebrew configures ``LIBCMT = "LIBCMT.lib"`` while the image
        holds ``VC98/Lib/LIBCMT.LIB``: a case-sensitive copy of the spelled
        name failed with no cache present. The container command runs here
        under ``sh`` against a stand-in Lib directory."""
        import shutil
        import subprocess

        import rebrew.lib_match as lm

        lib_dir = tmp_path / "image-lib"
        lib_dir.mkdir()
        (lib_dir / "LIBCMT.LIB").write_bytes(_write_lib(tmp_path).read_bytes())
        real_run = subprocess.run

        def container(argv: list[str], **kwargs: Any) -> Any:
            out = next(a.split(":/out")[0] for a in argv if a.endswith(":/out"))
            script = argv[argv.index("-c") + 1].replace("/out/", f"{out}/")
            args = argv[argv.index("-c") + 2 :]
            args = [str(lib_dir) if a.endswith("/VC98/Lib") else a for a in args]
            return real_run(["sh", "-c", script, *args], **kwargs)

        monkeypatch.setattr(lm, "container_runtime", lambda: "docker")
        monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr(lm.subprocess, "run", container)
        cfg = SimpleNamespace(
            root=tmp_path, external_libs={"LIBCMT": "LIBCMT.lib"}, compiler_profile="msvc-6.0-sp5"
        )
        monkeypatch.setattr("rebrew.lib_inspect.require_config", lambda **_: cfg)
        out = _run(["LIBCMT.lib", "--refs", "__lock"])
        assert out["archive"] == str(tmp_path / ".scratch" / "msvc-6.0-sp5_libcmt_stock.lib")
        assert out["members"] == ["obj\\mbctype.obj"]

    def test_ambiguous_case_match_is_an_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import shutil
        import subprocess

        import rebrew.lib_match as lm
        from rebrew.toolchain import ToolchainError

        lib_dir = tmp_path / "image-lib"
        lib_dir.mkdir()
        (lib_dir / "LIBCMT.LIB").write_bytes(b"A")
        (lib_dir / "libcmt.lib").write_bytes(b"B")
        real_run = subprocess.run

        def container(argv: list[str], **kwargs: Any) -> Any:
            script = argv[argv.index("-c") + 1]
            args = [
                str(lib_dir) if a.endswith("/VC98/Lib") else a for a in argv[argv.index("-c") + 2 :]
            ]
            return real_run(["sh", "-c", script, *args], **kwargs)

        monkeypatch.setattr(lm, "container_runtime", lambda: "docker")
        monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr(lm.subprocess, "run", container)
        with pytest.raises(ToolchainError, match="several"):
            lm.ensure_stock_lib(tmp_path / "x.lib", profile="msvc-6.0-sp5", name="LIBCMT.lib")
