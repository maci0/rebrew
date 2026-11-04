"""PE machine and optional-header metadata must remain independent."""

import struct
lazy from pathlib import Path

import capstone
import pytest
from bin_util import make_pe

from rebrew.formats.binary_loader import capstone_config_for, detect_format_and_arch, load_binary


@pytest.mark.parametrize(
    ("machine", "arch", "plus", "pointer_size"),
    [
        (0x166, "mips32", False, 4),
        (0x1F0, "ppc32", False, 4),
        (0x1F1, "ppc32", False, 4),
        (0x1F2, "ppc32", False, 4),
        (0x184, "alpha", False, 4),
        (0x284, "alpha64", False, 4),
        (0x200, "ia64", True, 8),
        (0x8664, "x86_64", True, 8),
    ],
)
def test_pe_machine_and_pointer_width(
    tmp_path: Path, machine: int, arch: str, plus: bool, pointer_size: int
) -> None:
    raw = bytearray(make_pe(b"\xc3", pe32_plus=plus))
    pe_offset = struct.unpack_from("<I", raw, 0x3C)[0]
    struct.pack_into("<H", raw, pe_offset + 4, machine)
    path = tmp_path / "sample.exe"
    path.write_bytes(raw)
    info = load_binary(path)
    assert (info.arch, info.pointer_size) == (arch, pointer_size)
    assert detect_format_and_arch(path) == ("pe", arch)
    if arch in {"alpha", "alpha64", "ia64"}:
        with pytest.raises(NotImplementedError, match="unsupported"):
            capstone_config_for(info)
    elif arch == "mips32":
        assert capstone_config_for(info) == (
            capstone.CS_ARCH_MIPS,
            capstone.CS_MODE_MIPS32 | capstone.CS_MODE_LITTLE_ENDIAN,
        )
    elif arch == "ppc32":
        endian = capstone.CS_MODE_BIG_ENDIAN if machine == 0x1F2 else capstone.CS_MODE_LITTLE_ENDIAN
        assert capstone_config_for(info) == (capstone.CS_ARCH_PPC, capstone.CS_MODE_32 | endian)


def test_pe_unknown_optional_header_magic_fails_closed(tmp_path: Path) -> None:
    raw = bytearray(make_pe(b"\xc3"))
    pe_offset = struct.unpack_from("<I", raw, 0x3C)[0]
    struct.pack_into("<H", raw, pe_offset + 24, 0x999)
    path = tmp_path / "unknown.exe"
    path.write_bytes(raw)
    with pytest.raises((ValueError, RuntimeError)):
        load_binary(path)
