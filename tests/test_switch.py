"""Tests for rebrew.switch — jump-table switch dispatch decoding."""

import struct
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent))  # tests/ on path for bin_util
from bin_util import make_pe

from rebrew.switch import find_switches

IMAGE_BASE = 0x400000
TEXT_VA = 0x401000


def _switch_pe(table_entries: list[int], bounds: int) -> bytes:
    """PE whose .text starts with a bounds-checked jump-table dispatch.

    Layout: cmp ecx, bounds; ja default; jmp [edx*4 + TABLE]; default: ret;
    then the TABLE of handler VAs.  Returns the PE bytes.
    """
    code = bytearray()
    code += bytes([0x83, 0xF9, bounds])  # cmp ecx, <bounds>
    # ja +0xa → the ret after the jmp (offset 0x0c)
    code += bytes([0x77, 0x0A])
    table_rva = 0x0D  # table sits right after the ret at offset 0x0c
    table_va = TEXT_VA + table_rva  # TEXT_VA is already absolute
    code += bytes([0xFF, 0x24, 0x95]) + struct.pack("<I", table_va)
    code += bytes([0xC3])  # default: ret
    for entry in table_entries:
        code += struct.pack("<I", entry)
    return make_pe(bytes(code))


def _cfg(pe_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        target_binary=pe_path,
        root=pe_path.parent,
        reversed_dir=pe_path.parent / "src" / "SERVER",
        target_name="SERVER",
    )


class TestFindSwitches:
    def test_decodes_bounds_checked_dispatch(self, tmp_path: Path) -> None:
        handlers = [0x401020, 0x401025, 0x401030, 0x401035]
        pe = tmp_path / "switch.exe"
        pe.write_bytes(_switch_pe(handlers, 3))
        switches = find_switches(_cfg(pe), TEXT_VA)
        assert len(switches) == 1
        sw = switches[0]
        assert sw["table_va"] == 0x40100D
        assert sw["bounds"] == 3
        assert sw["entries"] == 4
        assert sw["cases"] == [(i, h) for i, h in enumerate(handlers)]

    def test_bounds_limits_entry_count(self, tmp_path: Path) -> None:
        """The bounds check caps the table read even when more data follows."""
        handlers = [0x401020, 0x401025]
        pe = tmp_path / "switch.exe"
        pe.write_bytes(_switch_pe(handlers, 1))
        sw = find_switches(_cfg(pe), TEXT_VA)[0]
        assert sw["entries"] == 2
        assert sw["cases"] == [(0, 0x401020), (1, 0x401025)]

    def test_no_dispatch_returns_empty(self, tmp_path: Path) -> None:
        """A plain function with no indirect jmp → empty result."""
        code = bytes.fromhex("55 8b ec 83 ec 08 b8 01 00 00 00 c9 c3")
        pe = tmp_path / "plain.exe"
        pe.write_bytes(make_pe(code))
        assert find_switches(_cfg(pe), TEXT_VA) == []

    def test_missing_binary_returns_empty(self, tmp_path: Path) -> None:
        pe = tmp_path / "absent.exe"  # does not exist
        assert find_switches(_cfg(pe), TEXT_VA) == []


class TestScanAll:
    def test_scan_all_console_no_double_prefix(self, tmp_path: Path, monkeypatch, capsys) -> None:
        from rebrew.switch import _scan_all

        func_list = tmp_path / "functions.txt"
        func_list.write_text("0x01031150 fcn.01031150 144\n", encoding="utf-8")
        cfg = SimpleNamespace(
            target_binary=tmp_path / "x.exe",
            root=tmp_path,
            reversed_dir=tmp_path,
            function_list=func_list,
            target_name="SERVER",
        )
        monkeypatch.setattr(
            "rebrew.switch.find_switches",
            lambda c, va, window=512: [{"entries": 3}] if va == 0x1031150 else [],
        )
        import contextlib

        from typer import Exit

        with contextlib.suppress(Exit):
            _scan_all(cfg, 512, False)
        out = capsys.readouterr().err  # console → stderr
        assert "0x01031150" in out
        assert "0x0x" not in out

    def test_stops_at_non_image_entry_despite_bounds(self, tmp_path: Path) -> None:
        """A bounds check that is an over-estimate (sparse table / misread
        bounds) must not drag garbage entries into the case list — the walk
        stops at the first entry that is not a code address in the image."""
        # bounds=5 but only 2 real handlers; entries 2-5 are out-of-image.
        handlers = [0x401020, 0x401025, 0x00000100, 0xDEADBEEF, 0x00000000, 0x00000000]
        pe = tmp_path / "switch.exe"
        pe.write_bytes(_switch_pe(handlers, 5))
        sw = find_switches(_cfg(pe), TEXT_VA)[0]
        assert sw["entries"] == 2
        assert sw["cases"] == [(0, 0x401020), (1, 0x401025)]


class TestMaskBoundedDispatch:
    """MSVC memcpy/memmove byte-tail dispatches bound the index with
    `and reg, mask` (not `cmp`) and leave slot 0 of the table dead (the
    alignment guard makes the index >= 1) — the slot overlaps the preceding
    jmp's displacement and reads as an out-of-image pointer."""

    def _mask_pe(self, mask: int, dead_slot: int) -> bytes:
        code = bytearray()
        code += bytes([0x83, 0xE0, mask])  # and eax, <mask>
        table_va = TEXT_VA + 0x0A  # table right after the jmp
        code += bytes([0xFF, 0x24, 0x85]) + struct.pack("<I", table_va)
        # table: dead slot 0 + three real handlers (code right after the table)
        handlers = [TEXT_VA + 0x1A, TEXT_VA + 0x1B, TEXT_VA + 0x1C]
        code += struct.pack("<I", dead_slot)
        for h in handlers:
            code += struct.pack("<I", h)
        for _ in range(3):
            code += bytes([0xC3])  # handlers: ret
        return make_pe(bytes(code))

    def test_mask_bounds_decode_dead_slot_zero(self, tmp_path: Path) -> None:
        """`and eax, 3` bounds the table and the dead leading slot is
        skipped, not treated as the end of the table.  Regression: these
        dispatches reported `entries: 0` (found across win2k-sndrec32,
        win2k-pinball, win2k-sndvol32)."""
        pe = tmp_path / "mask.exe"
        pe.write_bytes(self._mask_pe(3, 0x900100D1))
        sw = find_switches(_cfg(pe), TEXT_VA)[0]
        assert sw["bounds"] == 3
        assert sw["entries"] == 3
        assert sw["cases"] == [
            (1, TEXT_VA + 0x1A),
            (2, TEXT_VA + 0x1B),
            (3, TEXT_VA + 0x1C),
        ]

    def test_non_mask_and_not_a_bound(self, tmp_path: Path) -> None:
        """`and eax, 0x40` (a flag test, not an index mask) must not bound
        the dispatch — the table read stays unbounded and stops at the
        out-of-image dead slot."""
        pe = tmp_path / "flag.exe"
        pe.write_bytes(self._mask_pe(0x40, 0x900100D1))
        sw = find_switches(_cfg(pe), TEXT_VA)[0]
        assert sw["bounds"] is None
        assert sw["entries"] == 0
