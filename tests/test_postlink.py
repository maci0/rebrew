"""Tests for rebrew.postlink — the ``rebrew postlink`` layout normalizer.

The fixers converge a built binary onto a reference by copying linker-derived
regions (import bookkeeping, ``.data``, ``.reloc``, PE headers).  ``make_pe``
in ``bin_util`` only builds a single-section PE, so these tests construct a
four-section PE (``.text``/``.rdata``/``.data``/``.reloc``) with a real
import directory + export directory, mirroring the MSVC6 server.dll layout.

Each scenario builds a *reference* and a deliberately-mutated *built* (the
kind of drift the MSVC6 linker produces: scrambled hint/name record order,
wrong ``.data`` raw size + operand, stamped headers), then asserts that
``run_fixers`` restores the built to byte-identical with the reference.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

from typer.testing import CliRunner

from rebrew.postlink import FIXER_ORDER, app, run_fixers

runner = CliRunner()

_IMAGE_BASE = 0x400000
_TEXT_VA = 0x1000
_RDATA_VA = 0x2000
_DATA_VA = 0x3000
_RELOC_VA = 0x4000
_SEC_ALIGN = 0x1000
_FILE_ALIGN = 0x200
_HEADERS = 0x1000
_TEXT_CHARS = 0x60000020
_RDATA_CHARS = 0x40000040  # INITIALIZED_DATA | READ
_DATA_CHARS = 0xC0000040  # INITIALIZED_DATA | READ | WRITE
_RELOC_CHARS = 0x42000040  # INITIALIZED_DATA | READ | DISCARDABLE


def _bookkeeping(imports: list[tuple[str, list[str]]], record_order: list[str], base: int) -> bytes:
    """Import bookkeeping blob: descriptors + INT/IAT arrays + hint/name records + DLL names.

    *record_order* is the order the hint/name records are emitted in; the
    INT/IAT arrays point at them, so scrambling it simulates the MSVC6
    linker's hash-driven placement.
    """
    n = len(imports)

    def _entry(api: str) -> bytes:
        entry = struct.pack("<H", 0) + api.encode("ascii") + b"\x00"
        return entry + (b"\x00" if len(entry) % 2 else b"")

    # descriptors + INT/IAT arrays only; the records + names are appended
    blob = bytearray(20 * (n + 1) + sum(8 * (len(a) + 1) for _, a in imports))

    rec_start = 20 * (n + 1) + sum(8 * (len(a) + 1) for _, a in imports)
    records: dict[str, int] = {}
    pos = rec_start
    for api in record_order:
        records[api] = base + pos
        entry = struct.pack("<H", 0) + api.encode("ascii") + b"\x00"
        if len(entry) % 2:
            entry += b"\x00"
        pos += len(entry)

    name_start = pos
    names: dict[str, int] = {}
    for dll, _ in imports:
        names[dll] = base + name_start
        name_start += len(dll) + 1

    pos = 20 * (n + 1)
    for i, (dll, apis) in enumerate(imports):
        int_rva = base + pos
        iat_rva = int_rva + 4 * (len(apis) + 1)
        for j, api in enumerate(apis):
            struct.pack_into("<I", blob, pos + 4 * j, records[api])
            struct.pack_into("<I", blob, pos + 4 * (len(apis) + 1) + 4 * j, records[api])
        struct.pack_into("<IIIII", blob, 20 * i, int_rva, 0, 0, names[dll], iat_rva)
        pos += 8 * (len(apis) + 1)

    blob += b"".join(
        struct.pack("<H", 0) + a.encode("ascii") + b"\x00" + (b"\x00" if (len(a) + 3) % 2 else b"")
        for a in record_order
    )
    blob += b"".join(dll.encode("ascii") + b"\x00" for dll, _ in imports)
    return bytes(blob)


def make_full_pe(
    *,
    code: bytes = b"\xc3",
    imports: list[tuple[str, list[str]]] | None = None,
    record_order: list[str] | None = None,
    data: bytes = b"",
    timestamp: int = 0x60000000,
    checksum: int = 0,
    e_lfanew: int = 0x80,
    reloc_bytes: bytes = b"",
) -> bytes:
    """Build a four-section PE mirroring the MSVC6 server.dll layout."""
    imports = imports or []
    record_order = record_order or [api for _, apis in imports for api in apis]

    imp_base = _RDATA_VA + 0x80 + 0x40  # after the IAT region + prefix
    bookkeeping = _bookkeeping(imports, record_order, imp_base)
    exp_rva = imp_base + len(bookkeeping)
    # export directory (Characteristics = timestamp like MSVC6 LINK stamps it)
    bookkeeping += struct.pack("<IIIII", 0x60000000, 0, 0, 0, 0)

    # IAT region at the start of .rdata (per-DLL arrays + terminator words)
    iat = bytearray(b"\x00" * 0x80)
    rec_base = imp_base + 20 * (len(imports) + 1) + sum(8 * (len(a) + 1) for _, a in imports)
    pos = 0
    for _, apis in imports:
        for j, api in enumerate(apis):
            rec_off = 0
            for a in record_order:
                if a == api:
                    break
                entry = struct.pack("<H", 0) + a.encode("ascii") + b"\x00"
                if len(entry) % 2:
                    entry += b"\x00"
                rec_off += len(entry)
            struct.pack_into("<I", iat, pos + 4 * j, rec_base + rec_off)
        pos += 4 * (len(apis) + 1)

    rdata = bytes(iat) + b"\xab" * 0x40 + bookkeeping
    rdata = rdata[:0x200].ljust(0x200, b"\x00")
    iat_rva, iat_size = _RDATA_VA, 0x80
    imp_rva = _RDATA_VA + 0x80 + 0x40

    text_raw = code.ljust(0x1000, b"\x00")[:0x1000]
    rdata_raw = rdata[:0x200]
    data_raw = data.ljust(0x200, b"\x00")[:0x200]
    reloc_raw = reloc_bytes.ljust(0x200, b"\x00")[:0x200]

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    coff = struct.pack("<HHIIIHH", 0x14C, 4, timestamp, 0, 0, 0xE0, 0x0102)

    size_of_image = ((_RELOC_VA + len(reloc_raw) + _SEC_ALIGN - 1) // _SEC_ALIGN) * _SEC_ALIGN
    opt = bytearray(struct.pack("<H", 0x10B))
    opt += struct.pack("<BB", 8, 0)
    opt += struct.pack("<I", len(text_raw))
    opt += struct.pack("<I", len(rdata_raw) + len(data_raw))
    opt += struct.pack("<I", 0)
    opt += struct.pack("<I", _TEXT_VA)
    opt += struct.pack("<I", _TEXT_VA)
    opt += struct.pack("<I", _DATA_VA)
    opt += struct.pack("<I", _IMAGE_BASE)
    opt += struct.pack("<I", _SEC_ALIGN)
    opt += struct.pack("<I", _FILE_ALIGN)
    opt += struct.pack("<HH", 6, 0)
    opt += struct.pack("<HH", 0, 0)
    opt += struct.pack("<HH", 6, 0)
    opt += struct.pack("<I", 0)
    opt += struct.pack("<I", size_of_image)
    opt += struct.pack("<I", _HEADERS)
    opt += struct.pack("<I", checksum)
    opt += struct.pack("<H", 3)
    opt += struct.pack("<H", 0)
    opt += struct.pack("<I", 0x100000)
    opt += struct.pack("<I", 0x1000)
    opt += struct.pack("<I", 0x100000)
    opt += struct.pack("<I", 0x1000)
    opt += struct.pack("<I", 0)
    opt += struct.pack("<I", 16)
    opt += b"\x00" * (16 * 8)
    struct.pack_into("<II", opt, 0x68, imp_rva, 20 * (len(imports) + 1))
    struct.pack_into("<II", opt, 0x68 + (12 - 1) * 8, iat_rva, iat_size)
    # export directory (index 0) — marks the end of the import bookkeeping
    struct.pack_into("<II", opt, 0x68 - 8, exp_rva, 0x14)
    assert len(opt) == 0xE0

    secs = b""
    for name, vsz, va, raw_sz, raw_off, chars in (
        (b".text\x00\x00\x00", len(text_raw), _TEXT_VA, len(text_raw), _HEADERS, _TEXT_CHARS),
        (b".rdata\x00\x00", len(rdata_raw), _RDATA_VA, len(rdata_raw), _RDATA_VA, _RDATA_CHARS),
        (b".data\x00\x00\x00", len(data_raw), _DATA_VA, len(data_raw), _DATA_VA, _DATA_CHARS),
        (b".reloc\x00\x00", len(reloc_raw), _RELOC_VA, len(reloc_raw), _RELOC_VA, _RELOC_CHARS),
    ):
        secs += struct.pack("<8sIIIIIIHHI", name, vsz, va, raw_sz, raw_off, 0, 0, 0, 0, chars)

    hdrs = dos + b"PE\x00\x00" + coff + opt + secs
    hdrs += b"\x00" * (_HEADERS - len(hdrs))

    # raw sections at their file offsets (== RVAs), padded between
    raw = bytearray(hdrs)
    for off, chunk in (
        (_HEADERS, text_raw),
        (_RDATA_VA, rdata_raw),
        (_DATA_VA, data_raw),
        (_RELOC_VA, reloc_raw),
    ):
        if len(raw) < off:
            raw += b"\x00" * (off - len(raw))
        raw += chunk
    return bytes(raw)


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


class TestImportsFixer:
    IMPORTS = [("KERNEL32.dll", ["GetLocalTime", "WriteFile"]), ("USER32.dll", ["MessageBoxA"])]

    def test_converges_scrambled_records(self, tmp_path: Path) -> None:
        ref = _write(tmp_path, "ref.dll", make_full_pe(imports=self.IMPORTS))
        built = _write(
            tmp_path,
            "built.dll",
            make_full_pe(
                imports=self.IMPORTS, record_order=["WriteFile", "GetLocalTime", "MessageBoxA"]
            ),
        )
        patched, reports = run_fixers(built, ref, ["imports"])
        assert patched == ref.read_bytes()
        assert reports[0].changed

    def test_rejects_different_import_set(self, tmp_path: Path) -> None:
        ref = _write(tmp_path, "ref.dll", make_full_pe(imports=self.IMPORTS))
        built = _write(
            tmp_path,
            "built.dll",
            make_full_pe(imports=[("KERNEL32.dll", ["GetLocalTime", "WriteFile", "Sleep"])]),
        )
        import pytest

        with pytest.raises(ValueError, match="import sets differ"):
            run_fixers(built, ref, ["imports"])

    def test_idempotent(self, tmp_path: Path) -> None:
        ref = _write(tmp_path, "ref.dll", make_full_pe(imports=self.IMPORTS))
        built = _write(tmp_path, "built.dll", make_full_pe(imports=self.IMPORTS))
        patched, reports = run_fixers(built, ref, ["imports"])
        assert patched == ref.read_bytes()
        assert not reports[0].changed


class TestDataFixer:
    IMPORTS: list[tuple[str, list[str]]] = []

    def test_grows_data_and_rewrites_operand(self, tmp_path: Path) -> None:
        # .text: mov eax, imm32 (B8 + 4 bytes) referencing .data
        operand = _DATA_VA + 0x10 + _IMAGE_BASE
        code = b"\xb8" + struct.pack("<I", operand) + b"\xc3"
        data = bytes(range(0x20))
        ref = _write(tmp_path, "ref.dll", make_full_pe(code=code, data=data))

        # built: same code but the operand points at a shifted .data offset
        wrong = b"\xb8" + struct.pack("<I", _DATA_VA + 4 + _IMAGE_BASE) + b"\xc3"
        built = _write(tmp_path, "built.dll", make_full_pe(code=wrong, data=b"\x00" * 4))

        patched, reports = run_fixers(built, ref, ["data"])
        assert patched == ref.read_bytes()
        assert reports[0].stats["data_operands"] >= 1


class TestPeMetadataFixer:
    def test_converges_stamped_headers(self, tmp_path: Path) -> None:
        ref = _write(tmp_path, "ref.dll", make_full_pe(timestamp=0x60000000, checksum=0x4D328))
        built = _write(tmp_path, "built.dll", make_full_pe(timestamp=0x70000001, checksum=0))
        patched, reports = run_fixers(built, ref, ["pe-metadata"])
        assert patched == ref.read_bytes()
        assert reports[0].changed


class TestCli:
    def test_json_report(self, tmp_path: Path) -> None:
        imports = [("KERNEL32.dll", ["GetLocalTime"])]
        ref = _write(tmp_path, "ref.dll", make_full_pe(imports=imports))
        built = _write(
            tmp_path,
            "built.dll",
            make_full_pe(imports=imports, record_order=["GetLocalTime"]),
        )
        out = tmp_path / "out.dll"
        result = runner.invoke(
            app,
            ["--json", "--output", str(out), str(built), str(ref)],
            env={"COLUMNS": "200"},
        )
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["reports"]
        assert out.exists()
        assert out.read_bytes() == ref.read_bytes()

    def test_unknown_fixer(self, tmp_path: Path) -> None:
        ref = _write(tmp_path, "ref.dll", make_full_pe())
        built = _write(tmp_path, "built.dll", make_full_pe())
        result = runner.invoke(app, ["--fix", "nope", str(built), str(ref)], env={"COLUMNS": "200"})
        assert result.exit_code == 2
        assert "unknown fixer" in result.output


def test_fixer_order_constant() -> None:
    assert FIXER_ORDER == ("imports", "data", "pe-metadata")


def _write_pkg(tmp_path: Path, ref: bytes, name: str = "pkg") -> Path:
    """Write a text-only layout package for *ref* (the gen-layout emission path)."""
    import tomlkit

    from rebrew.layout_meta import extract_layout, write_package

    meta = extract_layout(ref, "ref.dll")

    def fmt(m):
        doc = tomlkit.document()
        doc["layout"] = tomlkit.inline_table()
        for k, v in m.as_dict().items():
            doc["layout"][k] = v
        return tomlkit.dumps(doc)

    pkg = tmp_path / name
    write_package(meta, pkg, fmt_toml=fmt)
    return pkg


class TestLayoutPackage:
    """The text-only layout package: write/load roundtrip + fixer consumption."""

    def test_package_roundtrip_preserves_all_reference_bytes(self, tmp_path: Path) -> None:
        imports = [("KERNEL32.dll", ["GetLocalTime", "WriteFile"])]
        ref = _write(tmp_path, "ref.dll", make_full_pe(imports=imports, data=b"\x07" * 0x20))
        pkg = _write_pkg(tmp_path, ref.read_bytes())

        from rebrew.layout_meta import load_package

        meta = load_package(pkg)
        assert meta.header == ref.read_bytes()[: len(meta.header)]
        assert meta.iat and meta.bookkeeping
        assert len(meta.data) == 0x200 and meta.data[:0x20] == b"\x07" * 0x20
        assert meta.image_base == _IMAGE_BASE
        assert [(i.dll, i.name) for i in meta.imports] == [
            ("KERNEL32.dll", "GetLocalTime"),
            ("KERNEL32.dll", "WriteFile"),
        ]
        # every committed file is plain text (no binary blobs at rest)
        for f in pkg.iterdir():
            if f.name != "layout.txt":
                assert f.read_bytes().decode("ascii"), f"not text: {f.name}"

    def test_fixers_run_from_package(self, tmp_path: Path) -> None:
        imports = [("KERNEL32.dll", ["GetLocalTime", "WriteFile"])]
        ref = _write(tmp_path, "ref.dll", make_full_pe(imports=imports))
        pkg = _write_pkg(tmp_path, ref.read_bytes())
        built = _write(
            tmp_path,
            "built.dll",
            make_full_pe(imports=imports, record_order=["WriteFile", "GetLocalTime"]),
        )
        patched, reports = run_fixers(built, None, ["imports"], layout_dir=pkg)
        assert patched == ref.read_bytes()
        assert reports[0].changed

    def test_package_missing_file_is_rejected(self, tmp_path: Path) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        import pytest

        from rebrew.layout_meta import load_package

        with pytest.raises(ValueError, match="missing layout.txt"):
            load_package(pkg)

    def test_full_fixer_chain_from_package(self, tmp_path: Path) -> None:
        # the exact scenario the CMake POST_BUILD performs: raw link → package
        imports = [("KERNEL32.dll", ["GetLocalTime", "WriteFile"])]
        operand = _DATA_VA + 0x10 + _IMAGE_BASE
        ref = _write(
            tmp_path,
            "ref.dll",
            make_full_pe(
                imports=imports,
                code=b"\xb8" + struct.pack("<I", operand) + b"\xc3",
                data=bytes(range(0x20)),
                timestamp=0x60000000,
                checksum=0x4D328,
            ),
        )
        pkg = _write_pkg(tmp_path, ref.read_bytes())
        built = _write(
            tmp_path,
            "built.dll",
            make_full_pe(
                imports=imports,
                record_order=["WriteFile", "GetLocalTime"],
                code=b"\xb8" + struct.pack("<I", _DATA_VA + 4 + _IMAGE_BASE) + b"\xc3",
                data=b"\x00" * 4,
                timestamp=0x70000001,
                checksum=0,
            ),
        )
        patched, reports = run_fixers(built, None, None, layout_dir=pkg)
        assert patched == ref.read_bytes()
        assert len(reports) == len(FIXER_ORDER)
