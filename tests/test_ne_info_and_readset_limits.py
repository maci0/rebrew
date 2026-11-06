"""NE and MZ headers through pe_info, the unsupported-format refusal, and the shared readset limits."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path  # noqa: TC003
from types import SimpleNamespace

import pytest
from bin_util import make_ne
from test_analysis_capture_inventory import _capture
from test_ops import _worker_dirs

import rebrew.ops as ops
from rebrew.formats.binary_loader import UnsupportedBinaryFormat, detect_format_and_arch
from rebrew.ops import WorkerConfig
from rebrew.pe_info import pe_info

NE_OFFSET = 0x100  # e_lfanew of make_ne, as in a Borland-linked Windows 3.x executable
NE_TARGET_OS_OFFSET = 0x36
NE_ENTRY_OFFSET = 0x14
HOLIDAY_STUBS = 2010
HOLIDAY_BYTES = 1_792_401


def _holiday_shaped_ne(tmp_path: Path) -> Path:
    data = bytearray(
        make_ne(
            segments=[(b"\x55\x8b\xec" * 16, 0), (b"\x00" * 64, 1)],
            exports=[("HOLIDAY", 1)],
            modules=["KERNEL", "USER", "GDI"],
        )
    )
    data[NE_OFFSET + NE_TARGET_OS_OFFSET] = 2
    struct.pack_into("<I", data, NE_OFFSET + NE_ENTRY_OFFSET, (1 << 16) | 0x20)
    path = tmp_path / "holiday.exe"
    path.write_bytes(bytes(data))
    return path


def _plain_mz(tmp_path: Path) -> Path:
    head = bytearray(0x80)
    head[0:2] = b"MZ"
    struct.pack_into("<HHH", head, 2, 0x80, 1, 0)  # last page 0x80 bytes, one page, no relocations
    struct.pack_into("<H", head, 0x08, 4)  # four header paragraphs
    path = tmp_path / "plain.exe"
    path.write_bytes(bytes(head))
    return path


def test_ne_headers_are_reported(tmp_path: Path) -> None:
    path = _holiday_shaped_ne(tmp_path)
    assert detect_format_and_arch(path) == ("ne", "x86_16")
    info = pe_info(path)
    assert (info["format"], info["arch"], info["bits"]) == ("ne", "x86_16", 16)
    assert info["dos_stub_size"] == NE_OFFSET
    assert info["module_name"] == "HOLIDAY"
    assert info["target_os"] == "windows"
    assert (info["entry_segment"], info["entry_offset"], info["entry_point"]) == (1, 0x20, 0x20)
    assert info["image_base"] == 0
    assert info["imported_modules"] == ["KERNEL", "USER", "GDI"]
    assert info["segment_count"] == 2
    assert [(s["index"], s["size"], s["kind"]) for s in info["segments"]] == [
        (1, 48, "code"),
        (2, 64, "data"),
    ]
    assert info["resource_count"] == 0
    assert info["size"] == path.stat().st_size


def test_ne_resource_table_is_counted(tmp_path: Path) -> None:
    """Windows NE keeps its resources in a table at +0x24; the +0x34 field is not their count."""
    data = bytearray(_holiday_shaped_ne(tmp_path).read_bytes())
    table = bytearray(struct.pack("<H", 4))  # alignment shift
    for resource_type, count in ((0x8001, 3), (0x8003, 2)):
        table += struct.pack("<HHI", resource_type, count, 0) + b"\x00" * (12 * count)
    table += struct.pack("<H", 0)
    # Place the table after the 0x40-byte header and the segment table, where the resident names start.
    start = struct.unpack_from("<H", data, NE_OFFSET + 0x26)[0]
    struct.pack_into("<H", data, NE_OFFSET + 0x24, start)
    struct.pack_into("<H", data, NE_OFFSET + 0x26, start + len(table))
    names = bytes(data[NE_OFFSET + start : NE_OFFSET + 0x100])
    data[NE_OFFSET + start : NE_OFFSET + start + len(table) + len(names)] = bytes(table) + names
    path = tmp_path / "resources.exe"
    path.write_bytes(bytes(data))
    assert pe_info(path)["resource_count"] == 5


def test_ne_resource_table_with_an_oversize_count_counts_what_fits(tmp_path: Path) -> None:
    data = bytearray(_holiday_shaped_ne(tmp_path).read_bytes())
    start = 0x50  # past the 0x40-byte header, inside the segment and name tables
    table = struct.pack("<H", 4) + struct.pack("<HHI", 0x8001, 60000, 0) + b"\x00" * (12 * 2)
    struct.pack_into("<H", data, NE_OFFSET + 0x24, start)
    struct.pack_into("<H", data, NE_OFFSET + 0x26, start + len(table))
    data[NE_OFFSET + start : NE_OFFSET + start + len(table)] = table
    path = tmp_path / "damaged.exe"
    path.write_bytes(bytes(data))
    assert pe_info(path)["resource_count"] == 2


def test_plain_mz_headers_are_reported(tmp_path: Path) -> None:
    path = _plain_mz(tmp_path)
    assert detect_format_and_arch(path) == ("mz", "x86_16")
    info = pe_info(path)
    assert (info["format"], info["arch"], info["bits"]) == ("mz", "x86_16", 16)
    assert info["dos_stub_size"] == 64
    assert info["code_size"] == 64


def test_unknown_format_is_a_422_naming_the_magic(tmp_path: Path) -> None:
    files, workspace = _worker_dirs(tmp_path)
    content = b"\x01\x02garbage that is no executable"
    sha = hashlib.sha256(content).hexdigest()
    key = f"binaries/{sha}"
    (files / key).write_bytes(content)
    with pytest.raises(UnsupportedBinaryFormat) as raised:
        detect_format_and_arch(files / key)
    assert raised.value.magic == content[:8].hex()
    request = {"binary_id": 1, "sha256": sha, "key": key, "name": "junk.bin"}
    status, body = ops.dispatch(
        WorkerConfig(files.resolve(), workspace.resolve()),
        "rebrew.pe_info",
        json.dumps(request).encode(),
    )
    refusal = json.loads(body)
    assert status == 422, refusal
    assert refusal["error"] == "unsupported-binary-format"
    assert content[:8].hex() in refusal["detail"]


def test_holiday_shaped_manifest_is_within_the_limits() -> None:
    files = [SimpleNamespace(size=HOLIDAY_BYTES // HOLIDAY_STUBS)] * HOLIDAY_STUBS
    ops._check_manifest_size(files)


def test_manifest_over_the_file_limit_names_the_count_and_the_limit() -> None:
    files = [SimpleNamespace(size=1)] * (ops.MAX_READSET_FILES + 1)
    with pytest.raises(ops.OpsError) as raised:
        ops._check_manifest_size(files)
    assert raised.value.code == "readset-too-large" and raised.value.status == 422
    assert f"{ops.MAX_READSET_FILES + 1} files, over the limit of {ops.MAX_READSET_FILES}" in str(
        raised.value
    )


def test_manifest_over_the_byte_limit_is_refused() -> None:
    files = [SimpleNamespace(size=ops.MAX_READSET_BYTES), SimpleNamespace(size=1)]
    with pytest.raises(ops.OpsError) as raised:
        ops._check_manifest_size(files)
    assert raised.value.code == "readset-too-large"
    assert "bytes, over the limit" in str(raised.value)


def test_capture_over_the_file_limit_is_not_an_invalid_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ops, "MAX_READSET_FILES", 2)
    with pytest.raises(ops.OpsError) as raised:
        _capture(tmp_path)
    assert raised.value.code == "readset-too-large" and raised.value.status == 422
    assert "over the limit of 2" in str(raised.value)
