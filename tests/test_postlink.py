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

import pytest
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
    text_pad_byte: int = 0x00,
) -> bytes:
    """Build a four-section PE mirroring the MSVC6 server.dll layout.

    *text_pad_byte* fills the .text raw tail beyond the code (the VirtualSize
    is set to ``len(code)``, so a non-zero pad simulates real linkers' INT3
    padding — used to prove the fixers preserve the reference's padding).
    """
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

    text_raw = code.ljust(0x1000, bytes([text_pad_byte]))[:0x1000]
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
        (b".text\x00\x00\x00", len(code), _TEXT_VA, len(text_raw), _HEADERS, _TEXT_CHARS),
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

    def test_converges_reordered_dll_descriptors(self, tmp_path: Path) -> None:
        """Identical import sets in a different descriptor order (the linker's
        hash order) must converge, not be refused as a set mismatch."""
        ref = _write(tmp_path, "ref.dll", make_full_pe(imports=self.IMPORTS))
        built = _write(tmp_path, "built.dll", make_full_pe(imports=list(reversed(self.IMPORTS))))
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

    def test_rewrite_requires_indirect_call_opcode(self, tmp_path: Path) -> None:
        """Only FF /2 (call [mem]) and FF /5 (jmp [mem]) operands are IAT
        references.  A bare dword equal to a moved slot VA (e.g. a
        mov-imm32 constant) must be left alone, not rewritten."""
        import dataclasses

        from rebrew.binary_loader import load_binary
        from rebrew.layout_meta import extract_layout
        from rebrew.postlink import _fix_imports

        imports = [("KERNEL32.dll", ["GetLocalTime", "WriteFile"])]
        ref = make_full_pe(imports=imports)
        meta = extract_layout(ref, "ref.dll")
        # A built link that assigned the two IAT slots swapped: the
        # reference metadata with the slots exchanged.
        swapped = dataclasses.replace(
            meta,
            imports=[
                dataclasses.replace(meta.imports[0], iat_va=meta.imports[1].iat_va),
                dataclasses.replace(meta.imports[1], iat_va=meta.imports[0].iat_va),
            ],
        )
        slot_get = meta.imports[0].iat_va + _IMAGE_BASE
        slot_wri = meta.imports[1].iat_va + _IMAGE_BASE
        # .text holds the *built* slot (WriteFile's reference slot) in three
        # guises: FF 25 and FF 15 (must rewrite) and a mov-imm32 constant
        # (coincidental, must survive).
        code = (
            b"\xff\x25"
            + struct.pack("<I", slot_wri)
            + b"\xb8"
            + struct.pack("<I", slot_wri)
            + b"\xff\x15"
            + struct.pack("<I", slot_wri)
            + b"\xc3"
        )
        blob = bytearray(make_full_pe(code=code, imports=imports))
        built = _write(tmp_path, "built.dll", bytes(blob))
        report = _fix_imports(blob, swapped, load_binary(built))
        base = _HEADERS  # .text file offset in the fixture
        assert struct.unpack_from("<I", blob, base + 2)[0] == slot_get
        assert struct.unpack_from("<I", blob, base + 7)[0] == slot_wri
        assert struct.unpack_from("<I", blob, base + 13)[0] == slot_get
        assert report.stats["slot_operands_rewritten"] == 2
        assert report.stats["slot_operands_skipped"] == 1


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

    def test_preserves_reference_text_padding(self, tmp_path: Path) -> None:
        """`postlink X X` must reproduce X byte-for-byte: the data fixer
        trimmed .text to the reference's VirtualSize, zeroing the reference's
        own file padding.  Regression: cpubench .text vs 0x29d11 < raw
        0x29e00 — 239 bytes of 0xCC padding were corrupted."""
        ref = _write(tmp_path, "ref.dll", make_full_pe(code=b"\xc3", text_pad_byte=0xCC))
        patched, reports = run_fixers(ref, ref, ["data"])
        assert patched == ref.read_bytes()
        assert patched[0x1001:0x1008] == b"\xcc" * 7  # padding untouched

    def test_reloc_written_at_built_offset_not_reference(self, tmp_path: Path) -> None:
        """The .reloc bytes must land at the *built* file's own .reloc raw
        pointer (from its headers), not the reference's raw_ptr: a built
        link whose .reloc sits 0x200 later must keep it there."""
        from rebrew.layout_meta import extract_layout
        from rebrew.postlink import _fix_data

        reloc = struct.pack("<II", 0x1000, 8) + struct.pack("<HH", 0x123, 0x3000)
        ref = _write(tmp_path, "ref.dll", make_full_pe(reloc_bytes=reloc))
        meta = extract_layout(ref.read_bytes(), "ref.dll")
        assert meta.reloc  # the fixture must carry real reloc content

        sec_reloc = 0x178 + 40 * 3  # .reloc section-table entry in the fixture
        new_ptr = _RELOC_VA + 0x200
        raw = bytearray(make_full_pe(reloc_bytes=reloc))
        raw[new_ptr:new_ptr] = b"\x00" * 0x200  # gap: built .reloc raw sits later
        struct.pack_into("<I", raw, sec_reloc + 20, new_ptr)
        built = _write(tmp_path, "built.dll", bytes(raw))

        from rebrew.binary_loader import load_binary

        blob = bytearray(built.read_bytes())
        _fix_data(blob, meta, load_binary(built))
        assert bytes(blob[new_ptr : new_ptr + len(meta.reloc)]) == meta.reloc
        # the built header still points at the built offset (pre-fix the
        # write went to the reference's raw_ptr and the header was stamped
        # with it).
        assert struct.unpack_from("<I", blob, sec_reloc + 20)[0] == new_ptr

    def test_tail_trim_uses_built_geometry(self, tmp_path: Path) -> None:
        """The .text tail trim resolves the built trim point from the built
        file's own headers: a built .text raw 0x100 larger than the
        reference's must be trimmed back to the reference's raw extent."""
        ref = _write(tmp_path, "ref.dll", make_full_pe(code=b"\xc3"))
        meta_ptr = _HEADERS + 0x1000  # reference .text raw extent
        raw = bytearray(make_full_pe(code=b"\xc3"))
        # grow the built .text raw by 0x100 (header + raw bytes)
        sec_text = 0x178  # .text section-table entry in the fixture
        old_raw = struct.unpack_from("<I", raw, sec_text + 16)[0]
        struct.pack_into("<I", raw, sec_text + 16, old_raw + 0x100)
        raw[_HEADERS + old_raw : _HEADERS + old_raw] = b"\x90" * 0x100
        built = _write(tmp_path, "built.dll", bytes(raw))

        from rebrew.binary_loader import load_binary
        from rebrew.layout_meta import extract_layout
        from rebrew.postlink import _fix_data

        blob = bytearray(built.read_bytes())
        _fix_data(blob, extract_layout(ref.read_bytes(), "ref.dll"), load_binary(built))
        assert bytes(blob[meta_ptr : meta_ptr + 0x100]) == b"\x00" * 0x100
        assert struct.unpack_from("<I", blob, sec_text + 16)[0] == old_raw

    def test_tail_trim_uses_built_file_offset(self, tmp_path: Path) -> None:
        """A built link whose raw sections sit 0x200 later must not be trimmed:
        the trim point resolves from the built section's own file offset, never
        the reference's ``raw_ptr`` (which indexed the built buffer)."""
        from rebrew.binary_loader import load_binary
        from rebrew.layout_meta import extract_layout
        from rebrew.postlink import _fix_data

        ref = _write(tmp_path, "ref.dll", make_full_pe(code=b"\xc3", text_pad_byte=0xCC))
        raw = bytearray(make_full_pe(code=b"\xc3", text_pad_byte=0xCC))
        # Shift every raw section 0x200 later (a gap between headers and .text):
        # file offsets move, RVAs do not.
        raw[_HEADERS:_HEADERS] = b"\x00" * 0x200
        sec_off = 0x178
        for i in range(4):
            h = sec_off + 40 * i
            ptr = struct.unpack_from("<I", raw, h + 20)[0]
            struct.pack_into("<I", raw, h + 20, ptr + 0x200)
        built = _write(tmp_path, "built.dll", bytes(raw))

        # Built .text spans [0x1200, 0x2200) and its raw size equals the
        # reference's, so nothing lies beyond the reference's raw extent.
        blob = bytearray(built.read_bytes())
        _fix_data(blob, extract_layout(ref.read_bytes(), "ref.dll"), load_binary(built))
        assert bytes(blob[0x2000:0x2200]) == b"\xcc" * 0x200
        assert struct.unpack_from("<I", blob, sec_off + 16)[0] == 0x1000


class TestTextAlignmentGuard:
    """The layout maps are .text-relative, so they only describe a link that
    placed every function at the reference's VA.  A shifted .text must be
    refused before anything is patched, not padded to the reference's
    VirtualSize and shipped."""

    def test_aligned_text_passes(self, tmp_path: Path) -> None:
        operand = _DATA_VA + 0x10 + _IMAGE_BASE
        code = b"\xb8" + struct.pack("<I", operand) + b"\xe8\x10\x00\x00\x00\xc3"
        ref = _write(tmp_path, "ref.dll", make_full_pe(code=code, data=bytes(range(0x20))))
        patched, _reports = run_fixers(ref, ref, ["data"])
        assert patched == ref.read_bytes()

    def test_shifted_text_is_refused(self, tmp_path: Path) -> None:
        operand = _DATA_VA + 0x10 + _IMAGE_BASE
        code = b"\xb8" + struct.pack("<I", operand) + b"\xe8\x10\x00\x00\x00\xc3"
        ref = _write(tmp_path, "ref.dll", make_full_pe(code=code, data=bytes(range(0x20))))
        # every function eight bytes later: the map's offsets no longer point
        # at the instructions they describe
        shifted = _write(
            tmp_path,
            "shifted.dll",
            make_full_pe(code=b"\x90" * 8 + code, data=bytes(range(0x20))),
        )

        with pytest.raises(ValueError, match="not position-aligned"):
            run_fixers(shifted, ref, ["data"])

    def test_guard_skipped_when_map_is_empty(self, tmp_path: Path) -> None:
        ref = _write(tmp_path, "ref.dll", make_full_pe(code=b"\xc3"))
        patched, _reports = run_fixers(ref, ref, ["data"])
        assert patched == ref.read_bytes()


class TestPeMetadataFixer:
    def test_converges_stamped_headers(self, tmp_path: Path) -> None:
        ref = _write(tmp_path, "ref.dll", make_full_pe(timestamp=0x60000000, checksum=0x4D328))
        built = _write(tmp_path, "built.dll", make_full_pe(timestamp=0x70000001, checksum=0))
        patched, reports = run_fixers(built, ref, ["pe-metadata"])
        assert patched == ref.read_bytes()
        assert reports[0].changed

    def test_shifted_raw_offsets_are_not_overwritten(self, tmp_path: Path) -> None:
        """The full header copy must require the whole section layout to have
        converged, not just names+RVAs: ``_fix_data`` wrote ``.reloc`` at the
        built file's own raw offset, and copying the reference's raw pointers
        over it would point the header at bytes the fixer never wrote."""
        ref = _write(tmp_path, "ref.dll", make_full_pe(code=b"\xc3", text_pad_byte=0xCC))
        raw = bytearray(make_full_pe(code=b"\xc3", text_pad_byte=0xCC))
        raw[_HEADERS:_HEADERS] = b"\x00" * 0x200
        sec_off = 0x178
        for i in range(4):
            h = sec_off + 40 * i
            ptr = struct.unpack_from("<I", raw, h + 20)[0]
            struct.pack_into("<I", raw, h + 20, ptr + 0x200)
        built = _write(tmp_path, "built.dll", bytes(raw))

        patched, _reports = run_fixers(built, ref, ["data", "pe-metadata"])
        # .data/.reloc raw pointers stay where the built link put them (and
        # where the data fixer wrote the bytes), not the reference's 0x3000 /
        # 0x4000.
        assert struct.unpack_from("<I", patched, sec_off + 40 * 2 + 20)[0] == 0x3000 + 0x200
        assert struct.unpack_from("<I", patched, sec_off + 40 * 3 + 20)[0] == 0x4000 + 0x200

    def test_header_pad_uses_reference_size_of_headers(self, tmp_path: Path) -> None:
        """The DOS-stub relocation pads to the reference's SizeOfHeaders,
        not a hardcoded 0x1000: with a reference claiming SizeOfHeaders
        0x2000 the pad must reach 0x2000 and the tail beyond it must be
        the built bytes (pre-fix the pad stopped at 0x1000)."""
        import dataclasses
        import struct

        from rebrew.binary_loader import load_binary
        from rebrew.layout_meta import extract_layout
        from rebrew.postlink import _fix_pe_metadata

        ref = _write(tmp_path, "ref.dll", make_full_pe())
        meta = extract_layout(ref.read_bytes(), "ref.dll")
        header = bytearray(meta.header)
        struct.pack_into("<I", header, 0x3C, 0x40)  # reference e_lfanew
        struct.pack_into("<I", header, 0x40 + 24 + 60, 0x2000)  # SizeOfHeaders
        meta = dataclasses.replace(meta, header=bytes(header))

        built = _write(tmp_path, "built.dll", make_full_pe())
        blob = bytearray(built.read_bytes())
        _fix_pe_metadata(blob, meta, load_binary(built))
        assert bytes(blob[0x40 + 0x198 : 0x2000]) == b"\x00" * (0x2000 - 0x40 - 0x198)
        assert bytes(blob[0x2000:]) == built.read_bytes()[0x2000:]

    def test_fixers_see_fresh_geometry(self, tmp_path: Path) -> None:
        """Fixers after the first must see the headers earlier fixers wrote,
        not the geometry parsed before the chain ran: the ``data`` fixer
        grows the built ``.reloc`` raw-size header field, and
        ``pe-metadata`` must observe the grown value."""
        import rebrew.postlink as postlink

        reloc = struct.pack("<II", 0x1000, 8)
        ref = _write(
            tmp_path,
            "ref.dll",
            make_full_pe(reloc_bytes=reloc, timestamp=0x60000000, checksum=0x4D328),
        )
        raw = bytearray(make_full_pe(reloc_bytes=reloc, timestamp=0x70000001, checksum=0))
        sec_reloc = 0x178 + 40 * 3  # .reloc section-table entry in the fixture
        struct.pack_into("<I", raw, sec_reloc + 16, 0x100)  # built header understates it
        built = _write(tmp_path, "built.dll", bytes(raw))

        captured: dict[str, int] = {}
        real = postlink._fix_pe_metadata

        def spy(built_buf: bytearray, meta: object, info: object) -> postlink.FixerReport:
            captured["reloc_raw"] = info.sections[".reloc"].raw_size  # type: ignore[union-attr]
            return real(built_buf, meta, info)  # type: ignore[arg-type]

        postlink.FIXERS["pe-metadata"] = spy
        try:
            patched, _reports = run_fixers(built, ref, ["data", "pe-metadata"])
        finally:
            postlink.FIXERS["pe-metadata"] = real
        assert captured["reloc_raw"] == 0x200  # the data fixer's rewrite, not 0x100
        assert patched == ref.read_bytes()


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

    def test_empty_fixer_selection_is_rejected(self, tmp_path: Path) -> None:
        """``--fix ""`` selects nothing; it must not silently run every fixer."""
        ref = _write(tmp_path, "ref.dll", make_full_pe(code=b"\xc3", text_pad_byte=0xCC))
        built_bytes = make_full_pe()
        built = _write(tmp_path, "built.dll", built_bytes)
        result = runner.invoke(app, ["--fix", "", str(built), str(ref)], env={"COLUMNS": "200"})
        assert result.exit_code == 2
        assert "no fixer selected" in result.output
        assert built.read_bytes() == built_bytes


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
