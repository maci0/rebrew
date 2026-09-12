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

    Layout: cmp ecx, bounds; ja default; mov edx, ecx; jmp [edx*4 + TABLE];
    default: ret; then the TABLE of handler VAs.  Returns the PE bytes.
    """
    code = bytearray()
    code += bytes([0x83, 0xF9, bounds])  # cmp ecx, <bounds>
    # ja → the ret after the jmp
    code += bytes([0x77, 0x09])
    code += bytes([0x8B, 0xD1])  # mov edx, ecx (index copy)
    table_va = TEXT_VA + len(code) + 7 + 1  # table sits after the jmp + ret
    code += bytes([0xFF, 0x24, 0x95]) + struct.pack("<I", table_va)
    code += bytes([0xC3])  # default: ret
    for entry in table_entries:
        code += struct.pack("<I", entry)
    # Pad the code so the section's virtual size covers the handler VAs —
    # table entries must point into the image to count as cases.  Capped:
    # out-of-image garbage entries (sparse-table tests) never pad.
    pad_to = max([h - TEXT_VA + 1 for h in table_entries if TEXT_VA <= h < TEXT_VA + 0x1000] + [0])
    if len(code) < pad_to:
        code += bytes([0xC3]) * (pad_to - len(code))
    return make_pe(bytes(code))


def _switch_pe64(table_entries: list[int], bounds: int) -> bytes:
    """64-bit PE with a bounds-checked qword dispatch (cmp rcx; mov rax,rcx; jmp [rax*8+TABLE])."""
    import lief

    code = bytearray()
    code += bytes([0x48, 0x83, 0xF9, bounds])  # cmp rcx, <bounds>
    code += bytes([0x77, 0x0E])  # ja default
    code += bytes([0x48, 0x89, 0xC8])  # mov rax, rcx
    table_va = TEXT_VA + 0x11  # table after cmp + ja + mov + jmp + ret
    code += bytes([0xFF, 0x24, 0xC5]) + struct.pack("<I", table_va)
    code += bytes([0xC3])  # default: ret
    for entry in table_entries:
        code += struct.pack("<Q", entry)
    pe = make_pe(bytes(code))
    # Flip the machine to AMD64 so load_binary reports x86_64.
    blob = bytearray(pe)
    struct.pack_into("<H", blob, 0x80 + 4, 0x8664)
    assert lief.PE.parse(bytes(blob)) is not None
    # Pad so the virtual size covers the handler VAs (entries must point
    # into the image to count as cases).
    pad_to = max([h - TEXT_VA + 1 for h in table_entries if h >= TEXT_VA] + [0])
    if len(code) < pad_to:
        code += bytes([0xC3]) * (pad_to - len(code))
        pe = make_pe(bytes(code))
        blob = bytearray(pe)
        struct.pack_into("<H", blob, 0x80 + 4, 0x8664)
    return bytes(blob)


def _cfg(pe_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        target_binary=pe_path,
        root=pe_path.parent,
        reversed_dir=pe_path.parent / "src" / "SERVER",
        target_name="SERVER",
        arch="x86_32",
    )


def _cfg64(pe_path: Path) -> SimpleNamespace:
    cfg = _cfg(pe_path)
    cfg.arch = "x86_64"
    return cfg


class TestFindSwitches:
    def test_decodes_bounds_checked_dispatch(self, tmp_path: Path) -> None:
        handlers = [0x401020, 0x401025, 0x401030, 0x401035]
        pe = tmp_path / "switch.exe"
        pe.write_bytes(_switch_pe(handlers, 3))
        switches = find_switches(_cfg(pe), TEXT_VA)
        assert len(switches) == 1
        sw = switches[0]
        assert sw["table_va"] == 0x40100F
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


class TestDispatchHeaderWidth:
    """The human header must show the operand the tool actually decoded, not a
    hardcoded dword/*4 (wrong on 64-bit and 16-bit targets)."""

    def _run(self, tmp_path: Path, monkeypatch, entry_width: int, index_reg: str) -> str:
        from typer.testing import CliRunner

        import rebrew.switch as sw_mod

        binary = tmp_path / "x.exe"
        binary.write_bytes(b"MZ")
        cfg = _cfg(binary)
        cfg.arch = "x86_64" if entry_width == 8 else "x86_32"
        monkeypatch.setattr(sw_mod, "require_config", lambda target=None, json_mode=False: cfg)
        monkeypatch.setattr(
            sw_mod,
            "find_switches",
            lambda c, va, window=512: [
                {
                    "jmp_va": 0x401010,
                    "index_reg": index_reg,
                    "table_va": 0x401020,
                    "bounds": 2,
                    "cases": [],
                    "entries": 0,
                    "entry_width": entry_width,
                }
            ],
        )
        return CliRunner().invoke(sw_mod.app, ["0x401000"]).output

    def test_64bit_header_shows_qword_scale(self, tmp_path: Path, monkeypatch) -> None:
        out = self._run(tmp_path, monkeypatch, 8, "rax")
        assert "qword ptr [rax*8 + 0x00401020]" in out
        assert "dword ptr" not in out

    def test_32bit_header_keeps_dword_scale(self, tmp_path: Path, monkeypatch) -> None:
        out = self._run(tmp_path, monkeypatch, 4, "edx")
        assert "dword ptr [edx*4 + 0x00401020]" in out

    def test_16bit_header_shows_base_form(self, tmp_path: Path, monkeypatch) -> None:
        out = self._run(tmp_path, monkeypatch, 2, "bx")
        assert "word ptr [bx + 0x00401020]" in out


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
        handlers = [TEXT_VA + 0x30, TEXT_VA + 0x31, 0x00000100, 0xDEADBEEF, 0, 0]
        pe = tmp_path / "switch.exe"
        pe.write_bytes(_switch_pe(handlers, 5))
        sw = find_switches(_cfg(pe), TEXT_VA)[0]
        assert sw["entries"] == 2
        assert sw["cases"] == [(0, TEXT_VA + 0x30), (1, TEXT_VA + 0x31)]


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


class TestArchDerivedMode:
    """The disassembler mode and entry width follow the target arch."""

    def test_64bit_qword_dispatch(self, tmp_path: Path) -> None:
        handlers = [0x401020, 0x401028, 0x401030]
        pe = tmp_path / "sw64.exe"
        pe.write_bytes(_switch_pe64(handlers, 2))
        switches = find_switches(_cfg64(pe), TEXT_VA)
        assert len(switches) == 1
        sw = switches[0]
        # Dataflow: `cmp rcx, 2` feeds the scaled rax via `mov rax, rcx`.
        assert sw["bounds"] == 2
        assert sw["cases"] == [(i, h) for i, h in enumerate(handlers)]

    def test_32bit_ignores_qword_scale(self, tmp_path: Path) -> None:
        """A *8-scaled dispatch is not a 32-bit jump table."""
        handlers = [0x401020, 0x401028]
        pe = tmp_path / "sw64.exe"
        pe.write_bytes(_switch_pe64(handlers, 1))
        assert find_switches(_cfg(pe), TEXT_VA) == []


class TestBoundDataflow:
    """The bound compare must feed the table index register."""

    def _unrelated_cmp_pe(self) -> bytes:
        code = bytearray()
        code += bytes([0x83, 0xF8, 0x05])  # cmp eax, 5 (unrelated register)
        code += bytes([0x8B, 0xD1])  # mov edx, ecx (index copy)
        table_va = TEXT_VA + 0x0D  # table after cmp + mov + jmp + ret
        code += bytes([0xFF, 0x24, 0x95]) + struct.pack("<I", table_va)
        for h in (TEXT_VA + 0x20, TEXT_VA + 0x21):
            code += struct.pack("<I", h)
        code += bytes([0xC3, 0xC3])
        return make_pe(bytes(code))

    def test_unrelated_cmp_rejected(self, tmp_path: Path) -> None:
        pe = tmp_path / "unrel.exe"
        pe.write_bytes(self._unrelated_cmp_pe())
        sw = find_switches(_cfg(pe), TEXT_VA)[0]
        assert sw["bounds"] is None

    def test_copied_index_cmp_accepted(self, tmp_path: Path) -> None:
        """`cmp ecx, N` + `mov edx, ecx` + `jmp [edx*4+table]` binds."""
        handlers = [TEXT_VA + 0x20, TEXT_VA + 0x21]
        pe = tmp_path / "copy.exe"
        code = bytearray()
        code += bytes([0x83, 0xF9, 0x01])  # cmp ecx, 1
        code += bytes([0x8B, 0xD1])  # mov edx, ecx
        table_va = TEXT_VA + 0x0D  # table after cmp + mov + jmp + ret
        code += bytes([0xFF, 0x24, 0x95]) + struct.pack("<I", table_va)
        code += bytes([0xC3])
        for h in handlers:
            code += struct.pack("<I", h)
        code += bytes([0xC3]) * 0x20  # cover the handler VAs (in-image rule)
        pe.write_bytes(make_pe(bytes(code)))
        sw = find_switches(_cfg(pe), TEXT_VA)[0]
        assert sw["bounds"] == 1
        assert sw["cases"] == [(0, handlers[0]), (1, handlers[1])]


class TestVaInImageVirtualSize:
    def test_virtual_extent_counts(self) -> None:
        """A VA inside the virtual size but past the raw size is in-image."""
        from rebrew.switch import _va_in_image

        info = SimpleNamespace(
            sections={
                ".text": SimpleNamespace(va=0x401000, size=0x1000, raw_size=0x200),
            }
        )
        assert _va_in_image(info, 0x401800) is True
        assert _va_in_image(info, 0x402000) is False

    def test_zero_virtual_falls_back_to_raw(self) -> None:
        from rebrew.switch import _va_in_image

        info = SimpleNamespace(
            sections={
                ".text": SimpleNamespace(va=0x401000, size=0, raw_size=0x200),
            }
        )
        assert _va_in_image(info, 0x401100) is True
        assert _va_in_image(info, 0x401300) is False


class TestNearestBound:
    def test_earlier_cmp_does_not_override_switch_bound(self, tmp_path: Path) -> None:
        """Two compares on the index register: the switch's own (nearest) bound
        must win over an earlier range check on the same register."""
        handlers = [0x401020, 0x401025, 0x401030, 0x401035]
        code = bytearray()
        code += bytes([0x83, 0xF9, 0x0F])  # cmp ecx, 15  (earlier range check)
        code += bytes([0x83, 0xF9, 0x03])  # cmp ecx, 3   (switch bound)
        code += bytes([0x77, 0x09])  # ja default
        code += bytes([0x8B, 0xD1])  # mov edx, ecx
        table_va = TEXT_VA + len(code) + 7 + 1
        code += bytes([0xFF, 0x24, 0x95]) + struct.pack("<I", table_va)
        code += bytes([0xC3])  # default: ret
        for entry in handlers:
            code += struct.pack("<I", entry)
        pad_to = max(h - TEXT_VA + 1 for h in handlers)
        if len(code) < pad_to:
            code += bytes([0xC3]) * (pad_to - len(code))
        pe = tmp_path / "twocmp.exe"
        pe.write_bytes(make_pe(bytes(code)))

        switches = find_switches(_cfg(pe), TEXT_VA)
        assert len(switches) == 1
        sw = switches[0]
        assert sw["bounds"] == 3
        assert len(sw["cases"]) == 4


class TestRegisterCompareIsNotABound:
    def test_register_operand_rejected(self) -> None:
        """`cmp ecx, edx` has no immediate bound; the old pattern read "ed" as
        0xed and pulled unrelated handler addresses into the case list."""
        from rebrew.switch import _CMP_IMM_RE

        assert _CMP_IMM_RE.search("ecx, edx") is None
        assert _CMP_IMM_RE.search("ecx, dword ptr [eax]") is None
        m = _CMP_IMM_RE.search("ecx, 0xf")
        assert m is not None
        assert m.group(2) == "0xf"
