"""Tests for rebrew layout_map — reference-side binary measurement dump.

Builds synthetic LIEF-parseable PEs with ``bin_util`` (code with two
functions, imports, an export table, a wired ``.reloc``), drives the real
Typer entry point via ``CliRunner`` under a minimal project, and checks the
JSON manifest fields plus the ``--output`` text-map package.
"""

from __future__ import annotations

import json
import struct
import sys
import warnings
from pathlib import Path

import pytest
from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent))  # tests/ on path for bin_util
from bin_util import append_pe_section, make_pe

_TOML = """\
[project]
default_target = "game"

[targets.game]
binary = "game.exe"
marker = "GAME"
reversed_dir = "src"
function_list = "src/functions.txt"

[compiler]
profile = "msvc6"
command = "cl"
cflags = "/O2"
"""

_F1 = b"\x55\x8b\xec\xc3"  # func at offset 0, size 4
_F2 = b"\x55\x8b\xec\x5d\xc3"  # func at offset 16, size 5


def _pe_with_reloc(code: bytes = _F1 + b"\xcc" * 12 + _F2) -> bytes:
    """PE with two code functions, one import lib, and a wired ``.reloc``."""
    pe = bytearray(make_pe(code, imports=[("KERNEL32.dll", ["HeapCreate"])]))
    entries = [0x3000, 0x3004, 0x0000, 0x0000]
    blk = struct.pack("<II", 0x1000, 8 + 2 * len(entries)) + struct.pack(
        "<" + "H" * len(entries), *entries
    )
    pe2 = bytearray(append_pe_section(bytes(pe), ".reloc", blk))
    lfanew = struct.unpack_from("<I", pe2, 0x3C)[0]
    opt = lfanew + 24
    nsec = struct.unpack_from("<H", pe2, lfanew + 6)[0]
    sh = opt + 0xE0
    for i in range(nsec):
        if bytes(pe2[sh + i * 40 : sh + i * 40 + 8]).rstrip(b"\x00") == b".reloc":
            va = struct.unpack_from("<I", pe2, sh + i * 40 + 12)[0]
            struct.pack_into("<II", pe2, opt + 96 + 5 * 8, va, len(blk))
    return bytes(pe2)


def _project(tmp_path: Path, pe: bytes, functions: str) -> Path:
    (tmp_path / "rebrew-project.toml").write_text(_TOML, encoding="utf-8")
    (tmp_path / "game.exe").write_bytes(pe)
    src = tmp_path / "src"
    src.mkdir()
    (src / "functions.txt").write_text(functions, encoding="utf-8")
    return tmp_path


def _invoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *args: str):
    from rebrew.layout_map import app

    monkeypatch.chdir(tmp_path)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return CliRunner().invoke(app, list(args))


def _manifest(result) -> dict:
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)


class TestLayoutMapCli:
    def test_json_manifest_schema(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        base = 0x400000 + 0x1000
        _project(
            tmp_path,
            _pe_with_reloc(),
            f"0x{base:x} f1 4\n0x{base + 16:x} f2 5\n",
        )
        payload = _manifest(_invoke(tmp_path, monkeypatch, "--json"))
        for key in (
            "target",
            "format",
            "arch",
            "image_base",
            "sections",
            "alignment",
            "gaps",
            "reloc_density",
            "iat",
            "exports",
            "toolchain",
            "pe_header",
        ):
            assert key in payload
        assert payload["format"] == "pe"
        assert payload["image_base"] == 0x400000
        assert payload["functions"] == 2
        assert len(payload["sections"]) == 2
        assert payload["sections"][0]["name"] == ".text"
        assert payload["sections"][0]["characteristics"] == 0x60000020
        assert payload["pe_header"]["linker_version"] == "8.0"
        assert payload["pe_header"]["subsystem"] == 3

    def test_alignment_and_gap_histograms(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        base = 0x400000 + 0x1000
        _project(
            tmp_path,
            _pe_with_reloc(),
            f"0x{base:x} f1 4\n0x{base + 16:x} f2 5\n",
        )
        payload = _manifest(_invoke(tmp_path, monkeypatch, "--json"))
        assert payload["alignment"]["total"] == 2
        assert payload["alignment"]["histogram"]["0"] == 2
        assert payload["gaps"]["total"] == 1
        assert payload["gaps"]["histogram"]["padding"] == 1
        gap = payload["gaps"]["rows"][0]
        assert gap["start"] == base + 4
        assert gap["end"] == base + 16
        assert gap["class"] == "padding"

    def test_iat_and_reloc_density(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        base = 0x400000 + 0x1000
        _project(
            tmp_path,
            _pe_with_reloc(),
            f"0x{base:x} f1 4\n0x{base + 16:x} f2 5\n",
        )
        payload = _manifest(_invoke(tmp_path, monkeypatch, "--json"))
        assert len(payload["iat"]) == 1
        assert payload["iat"][0]["dll"] == "KERNEL32.dll"
        assert payload["iat"][0]["name"] == "HeapCreate"
        assert payload["iat"][0]["slot_va"] > 0x400000
        assert payload["reloc_density"]["total_highlow"] == 2
        assert len(payload["reloc_density"]["pages"]) == 1
        assert payload["reloc_density"]["pages"][0]["page_rva"] == 0x1000

    def test_toolchain_guess_present(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _project(tmp_path, _pe_with_reloc(), "")
        payload = _manifest(_invoke(tmp_path, monkeypatch, "--json"))
        toolchain = payload["toolchain"]
        assert toolchain["family"]
        assert toolchain["confidence"] in ("low", "medium", "high")
        assert isinstance(toolchain["evidence"], list)

    def test_write_mode_text_map(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        base = 0x400000 + 0x1000
        _project(
            tmp_path,
            _pe_with_reloc(),
            f"0x{base:x} f1 4\n0x{base + 16:x} f2 5\n",
        )
        out = tmp_path / "layout" / "game.exe" / "text-map"
        payload = _manifest(_invoke(tmp_path, monkeypatch, "--json", "--output", str(out)))
        for name in ("sections.txt", "gaps.txt", "iat.txt", "exports.txt"):
            assert (out / name).is_file()
        assert payload["written"] == [
            str(out / n) for n in ("sections.txt", "gaps.txt", "iat.txt", "exports.txt")
        ]
        sections = (out / "sections.txt").read_text(encoding="utf-8")
        assert sections.startswith("# game ")
        assert ".text 0x401000" in sections
        iat = (out / "iat.txt").read_text(encoding="utf-8")
        assert "KERNEL32.dll!HeapCreate" in iat

    def test_human_summary(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        base = 0x400000 + 0x1000
        _project(
            tmp_path,
            _pe_with_reloc(),
            f"0x{base:x} f1 4\n0x{base + 16:x} f2 5\n",
        )
        result = _invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        assert "layout-map" in result.output
        assert ".text" in result.output
        assert "iat slots: 1" in result.output

    def test_missing_binary_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _project(tmp_path, _pe_with_reloc(), "")
        (tmp_path / "game.exe").unlink()
        result = _invoke(tmp_path, monkeypatch, "--json")
        assert result.exit_code == 2
        assert json.loads(result.stdout)["error"]

    def test_help_lists_options(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.layout_map import app

        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["--help"])
        assert result.exit_code == 0
        for flag in ("--output", "--json", "--target"):
            assert flag in result.stdout


def _pe_with_null_and_forwarder_exports() -> bytes:
    """Minimal PE whose export function table holds one code RVA, one null
    entry, and one forwarder RVA (pointing at a forwarder string inside the
    export directory)."""
    e = 0x80
    optsz = 0xE0
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e)
    coff = struct.pack("<HHIIIHH", 0x14C, 2, 0, 0, 0, optsz, 0x0102)
    opt = bytearray(struct.pack("<H", 0x10B)) + b"\x00" * (optsz - 2)
    struct.pack_into("<I", opt, 28, 0x400000)  # image base
    struct.pack_into("<I", opt, 56, 0x3000)  # size of image
    struct.pack_into("<I", opt, 60, 0x200)  # SizeOfHeaders
    secs = struct.pack(
        "<8sIIIIIIHHI", b".text\x00\x00\x00", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020
    )
    secs += struct.pack(
        "<8sIIIIIIHHI", b".edata\x00\x00", 0x200, 0x2000, 0x200, 0x400, 0, 0, 0, 0, 0x40000040
    )
    names = [b"aaa", b"bbb", b"ccc"]
    n = 3
    funcs_off, names_off = 40, 40 + 4 * n
    ords_off = names_off + 4 * n
    strs = b"".join(s + b"\x00" for s in names)
    fwd_rva = 0x2000 + ords_off + 2 * n + len(strs)
    strs += b"OTHER.Func\x00"
    ed = bytearray(b"\x00" * 0x200)
    struct.pack_into("<I", ed, 16, 1)  # ordinal base
    struct.pack_into("<I", ed, 20, n)
    struct.pack_into("<I", ed, 24, n)
    struct.pack_into("<I", ed, 28, 0x2000 + funcs_off)
    struct.pack_into("<I", ed, 32, 0x2000 + names_off)
    struct.pack_into("<I", ed, 36, 0x2000 + ords_off)
    for i, rva in enumerate([0x1000, 0, fwd_rva]):
        struct.pack_into("<I", ed, funcs_off + 4 * i, rva)
    for i, _name in enumerate(names):
        struct.pack_into(
            "<I",
            ed,
            names_off + 4 * i,
            0x2000 + ords_off + 2 * n + sum(len(s) + 1 for s in names[:i]),
        )
        struct.pack_into("<H", ed, ords_off + 2 * i, i)
    ed[ords_off + 2 * n : ords_off + 2 * n + len(strs)] = strs
    struct.pack_into("<II", opt, 96, 0x2000, 40 + 4 * n + 4 * n + 2 * n + len(strs))
    hdrs = (bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + secs).ljust(0x200, b"\x00")
    return hdrs + b"\x90" * 0x200 + bytes(ed)


class TestForwarderExports:
    def test_null_and_forwarder_entries_skipped(self) -> None:
        """A null function-table entry and a forwarder RVA (inside the
        export directory range) are both skipped: only the real code
        export reaches the .def/layout exports."""
        from rebrew.gen_layout import parse_pe

        _sections, exports, _imports, _pe = parse_pe(_pe_with_null_and_forwarder_exports())
        assert exports == [{"name": "aaa", "ordinal": 1, "va": 0x400000 + 0x1000}]
