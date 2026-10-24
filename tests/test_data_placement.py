"""Placement needs independent linked-object evidence, not matching zeros."""

import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.data_placement import coff_data_symbols, span_data_placements
from rebrew.data_verify import verify_data_bytes
from rebrew.formats.binary_model import BinaryInfo, SectionInfo
from rebrew.metadata.data import set_data_fields_batch


def _coff(*, addend: int = 0, kind: int = 6, duplicate: bool = False, site: int = 1) -> bytes:
    code = b"\xa1" + struct.pack("<I", addend)
    if duplicate:
        code += b"\xa1" + struct.pack("<I", addend)
    code += b"\xc3"
    code_start = 100
    data_start = code_start + len(code)
    reloc_start = data_start + 16
    relocations = struct.pack("<IIH", site, 1, kind)
    if duplicate:
        relocations += struct.pack("<IIH", 6, 1, kind)
    symbols_start = reloc_start + len(relocations)
    header = struct.pack("<HHIIIHH", 0x14C, 2, 0, symbols_start, 2, 0, 0)
    text = struct.pack(
        "<8sIIIIIIHHI",
        b".text",
        0,
        0,
        len(code),
        code_start,
        reloc_start,
        0,
        2 if duplicate else 1,
        0,
        0x60000020,
    )
    data = struct.pack("<8sIIIIIIHHI", b".data", 0, 0, 16, data_start, 0, 0, 0, 0, 0xC0000040)
    entry = struct.pack("<8sIhHBB", b"_entry", 0, 1, 0x20, 2, 0)
    hidden = struct.pack("<8sIhHBB", b"_hidden", 4, 2, 0, 3, 0)
    return (
        header
        + text
        + data
        + code
        + bytes(16)
        + relocations
        + entry
        + hidden
        + struct.pack("<I", 4)
    )


@pytest.mark.parametrize("base,addend", [(0x4000, 0), (0x5000, 8)])
def test_private_symbol_comes_from_applied_operand(base: int, addend: int) -> None:
    native = b"\xa1" + struct.pack("<I", base + 4 + addend) + b"\xc3"
    result = coff_data_symbols(
        _coff(addend=addend), {"_entry": 0x1000}, lambda va, n: native if va == 0x1000 else b""
    )
    assert result["_hidden"] == base + 4


@pytest.mark.parametrize("change", ["opcode", "anchor", "truncated", "fixup", "no-anchor", "site"])
def test_private_symbol_rejects_unproved_code(change: str) -> None:
    body = _coff(kind=7 if change == "fixup" else 6, site=2 if change == "site" else 1)
    native = b"\xa1" + struct.pack("<I", 0x4004) + b"\xc3"
    anchors = {"_entry": 0x1001 if change == "anchor" else 0x1000}
    if change == "no-anchor":
        anchors = {}
    if change == "opcode":
        native = b"\xa3" + native[1:]
    if change == "truncated":
        native = native[:-1]
    assert coff_data_symbols(body, anchors, lambda va, n: native if va == 0x1000 else b"") == {}


def test_conflicting_section_targets_remain_unresolved() -> None:
    native = b"\xa1" + struct.pack("<I", 0x4004) + b"\xa1" + struct.pack("<I", 0x5004) + b"\xc3"
    assert coff_data_symbols(_coff(duplicate=True), {"_entry": 0x1000}, lambda va, n: native) == {}


def test_alias_inherits_only_a_complete_bounded_backing(tmp_path: Path) -> None:
    set_data_fields_batch(
        tmp_path,
        [
            {
                "module": "M",
                "va": 0x1000,
                "fields": {"name": "owner", "size": 8, "section": ".data"},
            },
            {
                "module": "M",
                "va": 0x1004,
                "fields": {
                    "name": "view",
                    "size": 4,
                    "section": ".data",
                    "storage_kind": "alias",
                    "backing": "owner",
                },
            },
            {
                "module": "M",
                "va": 0x1008,
                "fields": {
                    "name": "past",
                    "size": 4,
                    "section": ".data",
                    "storage_kind": "alias",
                    "backing": "owner",
                },
            },
        ],
    )
    args = {
        "metadata_path": tmp_path / "rebrew-data.toml",
        "expected": {0x1000: bytes(8), 0x1004: bytes(4), 0x1008: bytes(4)},
        "actual": {0x1000: bytes(8), 0x1004: bytes(4), 0x1008: bytes(4)},
        "sizes": {0x1000: 8, 0x1004: 4, 0x1008: 4},
    }
    report = verify_data_bytes(**args, built_symbols={"_owner": 0x1000})
    assert [r["status"] for r in report["results"]] == ["EXACT", "EXACT", "VERIFIED"]
    assert report["results"][1]["placement_method"] == "backing-offset"
    shifted = verify_data_bytes(**args, built_symbols={"_owner": 0x2000})
    assert shifted["results"][1]["built_va"] == "0x2004"
    assert shifted["results"][1]["status"] == "DISPLACED"


def test_span_placement_is_a_section_interval_not_an_allocation(
    tmp_path: Path, monkeypatch
) -> None:
    set_data_fields_batch(
        tmp_path,
        [
            {
                "module": "M",
                "va": 0x1004,
                "fields": {"name": "gap", "size": 4, "section": ".data", "storage_kind": "span"},
            }
        ],
    )
    reference = BinaryInfo(
        path=tmp_path / "original",
        format="pe",
        sections={".data": SectionInfo(".data", 0x1000, 8, 0, 8)},
    )
    image = BinaryInfo(
        path=tmp_path / "built",
        format="pe",
        sections={".data": SectionInfo(".data", 0x2000, 8, 0, 8)},
    )
    monkeypatch.setattr(
        "rebrew.formats.binary_loader.load_binary",
        lambda p: reference if p == reference.path else image,
    )
    cfg = SimpleNamespace(
        target_binary=reference.path, metadata_dir=tmp_path, arch="x86_32", module="M"
    )
    placements = span_data_placements(cfg, image.path)
    assert placements == {("M", 0x1004): 0x2004}
    args = {
        "metadata_path": tmp_path / "rebrew-data.toml",
        "expected": {0x1004: bytes(4)},
        "actual": {0x1004: bytes(4)},
        "sizes": {0x1004: 4},
        "built_symbols": {},
    }
    report = verify_data_bytes(**args, span_placements=placements)
    assert report["results"][0]["status"] == "DISPLACED"
    assert report["results"][0]["placement_method"] == "section-relative-span"
    image.sections[".data"].size = 7
    assert span_data_placements(cfg, image.path) == {}
    assert verify_data_bytes(**args)["results"][0]["status"] == "VERIFIED"


def test_map_name_collision_cannot_place_a_private_symbol() -> None:
    from rebrew.data_verify import link_map_symbols

    text = " 0003:00000000 _local 00403000 one.obj\n 0003:00000004 _local 00403004 two.obj\n"
    assert "_local" not in link_map_symbols(text)
