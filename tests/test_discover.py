"""Tests for rebrew.discover — chained function discovery."""

from __future__ import annotations

from pathlib import Path

import pytest

from rebrew.discover import _is_padding, discover_functions


class TestIsPadding:
    def test_int3_padding(self) -> None:
        # extract_bytes is mocked via the autouse fixture — test the byte logic
        assert _is_padding(_mk_info(b"\xcc\xcc\xcc"), 0, 3) is True

    def test_nop_padding(self) -> None:
        assert _is_padding(_mk_info(b"\x90\x90\x90"), 0, 3) is True

    def test_code_is_not_padding(self) -> None:
        assert _is_padding(_mk_info(b"\x55\x8b\xec"), 0, 3) is False

    def test_documented_multibyte_nop_is_padding(self) -> None:
        # 0F 1F 00 — 3-byte NOP (ModRM mod=00, no disp)
        assert _is_padding(_mk_info(b"\x0f\x1f\x00"), 0, 3) is True
        # 0F 1F 40 00 — 4-byte NOP (ModRM mod=01 disp8)
        assert _is_padding(_mk_info(b"\xcc\x0f\x1f\x40\x00"), 0, 5) is True

    def test_bare_0f_is_not_padding(self) -> None:
        # 0F 85 xx xx xx xx — jnz rel32: a real opcode, never padding.
        assert _is_padding(_mk_info(b"\x0f\x85\x10\x00\x00\x00"), 0, 6) is False
        # Truncated 0F 1F with no ModRM byte — not a valid NOP.
        assert _is_padding(_mk_info(b"\x0f\x1f"), 0, 2) is False
        # Register-direct 0F 1F C0 — not documented padding.
        assert _is_padding(_mk_info(b"\x0f\x1f\xc0"), 0, 3) is False

    def test_66_90_nop_is_padding(self) -> None:
        assert _is_padding(_mk_info(b"\x66\x90"), 0, 2) is True


class TestMultibyteNopLen:
    def test_sib_disp_forms(self) -> None:
        from rebrew.discover import _multibyte_nop_len

        # 0F 1F 44 00 00 — ModRM mod=01 rm=100 (SIB) disp8
        assert _multibyte_nop_len(bytes([0x0F, 0x1F, 0x44, 0x00, 0x00]), 0) == 5
        # 0F 1F 84 00 + disp32 — ModRM mod=10 rm=100 (SIB) disp32
        assert _multibyte_nop_len(bytes([0x0F, 0x1F, 0x84, 0x00, 0, 0, 0, 0]), 0) == 8
        # 0F 1F 05 + disp32 — ModRM mod=00 rm=101 (disp32, no base)
        assert _multibyte_nop_len(bytes([0x0F, 0x1F, 0x05, 0, 0, 0, 0]), 0) == 7

    def test_truncated_returns_zero(self) -> None:
        from rebrew.discover import _multibyte_nop_len

        assert _multibyte_nop_len(bytes([0x0F, 0x1F]), 0) == 0
        assert _multibyte_nop_len(bytes([0x0F, 0x1F, 0x44]), 0) == 0


def _mk_info(raw: bytes):
    class Fake:
        pass

    info = Fake()
    info.data = raw
    return info


@pytest.fixture(autouse=True)
def _patch_extract(monkeypatch):
    """Route rebrew.analysis.extract_bytes to the fake info's raw bytes."""
    import rebrew.analysis

    def _extract(info, va, size):
        return info.data[va : va + size]

    monkeypatch.setattr(rebrew.analysis, "extract_bytes", _extract)


class TestDiscoverFunctions:
    def test_ne_uses_native_loader(self, tmp_path: Path, monkeypatch) -> None:
        """Regression: a 16-bit NE binary must route through the native NE
        loader's linear sweep, not rizin — rizin emits garbage file-offset
        "functions" (the 233-function false enumeration that polluted the
        SkiFree intake before the fix)."""
        from test_ne_loader import _build_ne

        code = (
            b"\x01\x00"
            + bytes.fromhex("55 8b ec 5d c3")  # fn @ 0x2
            + b"\x00" * 8
            + bytes.fromhex("55 8b ec 5d c3")  # fn @ 0x10
            + b"\x00" * 8
        )
        raw = _build_ne(segments=[(code, 0x01)])
        p = tmp_path / "app.ne"
        p.write_bytes(raw)
        # rizin must not even be invoked for NE targets.
        called: list = []
        monkeypatch.setattr(
            "rebrew.discover._rizin_functions", lambda *a, **k: called.append(1) or []
        )
        d = discover_functions(p, min_size=1)
        assert d.sources == {"ne loader": 2}
        assert [va for va, _s, _n in d.functions] == [0x10002, 0x1000F]
        assert not called

    def test_merge_and_validation(self, monkeypatch) -> None:
        # rizin aaa gives one garbled huge function; aap gives the real set;
        # the sweep adds an interior false positive that must be dropped.
        aaa = [(0x401000, 1000, "fcn.00401000"), (0x401300, 50, "fcn.00401300")]
        aap = [
            (0x401000, 40, "fcn.00401000"),
            (0x401028, 20, "fcn.00401028"),
            (0x401040, 30, "fcn.00401040"),
            (0x401300, 50, "fcn.00401300"),
        ]
        monkeypatch.setattr(
            "rebrew.discover._rizin_functions", lambda b, c: aaa if c == ["aaa"] else aap
        )
        monkeypatch.setattr(
            "rebrew.discover._capstone_sweep", lambda b: [(0x401000, 0, "x"), (0x401034, 0, "y")]
        )

        # Mock load_binary + iter_instructions for the validation pass: every
        # function ends in a ret right before the next start.
        class Insn:
            def __init__(self, va, size, mnemonic):
                self.va = va
                self.size = size
                self.mnemonic = mnemonic

        def _iter_instructions(info, va, size):
            # one code instruction filling the span, then a ret at the end
            yield Insn(va, max(size - 1, 1), "code")
            yield Insn(va + max(size - 1, 1), 1, "ret")

        monkeypatch.setattr("rebrew.discover.load_binary", lambda b: _mk_info(b""))
        monkeypatch.setattr("rebrew.discover.iter_instructions", _iter_instructions)
        monkeypatch.setattr("rebrew.discover._is_padding", lambda info, va, end: True)

        d = discover_functions(Path("x.exe"))
        # merged candidate VAs: aaa(0x401000,0x401300) + aap(+0x401028,0x401040)
        # + sweep(0x401034 interior) — all present after merge.
        vas = [va for va, _s, _n in d.functions]
        assert 0x401000 in vas
        assert 0x401300 in vas
        assert 0x401028 in vas
        # every function has a positive size
        assert all(size > 0 for _va, size, _n in d.functions)


class TestDiscoverMZ:
    """Plain DOS MZ binaries short-circuit to the 16-bit capstone sweep
    (rizin cannot analyze MZ) — the DOS-game discovery path."""

    def test_mz_detection(self) -> None:
        from rebrew.binary_loader import is_mz

        fixture = Path(__file__).parent / "fixtures" / "tc16_hello.exe"
        assert fixture.exists()
        assert is_mz(fixture) is True
        assert is_mz(Path(__file__).parent / "fixtures" / "tg_msvc16.obj") is False

    def test_mz_sweep_finds_entry_and_functions(self) -> None:
        from rebrew.discover import discover_functions

        fixture = Path(__file__).parent / "fixtures" / "tc16_hello.exe"
        d = discover_functions(fixture)
        assert "mz sweep" in d.sources
        assert len(d.functions) > 0
        vas = {va for va, _size, _name in d.functions}
        # The CS:IP entry is always a candidate — the fixture's tiny-model
        # header has e_cs=0 (entry at image start), so its entry VA is 0.
        assert 0 in vas
        # The cdecl prologue pattern (push bp; mov bp,sp) must fire somewhere.
        assert len(vas) > 3


class TestInteriorFalsePositiveDrop:
    def test_candidate_without_a_boundary_is_dropped(self, monkeypatch) -> None:
        """A candidate whose predecessor decodes straight into it (no ret, no
        decodable boundary) is a call target inside that function.  The old
        `insn.va >= nxt` test could never fire — the disasm window IS the gap —
        so the phantom candidate stayed in the list."""
        from rebrew.discover import _validate_and_refine

        class Insn:
            def __init__(self, va: int, size: int, mnemonic: str) -> None:
                self.va = va
                self.size = size
                self.mnemonic = mnemonic

        def _iter(info, va, size):
            yield Insn(va, 4, "mov")
            yield Insn(va + 4, 2, "jne")

        monkeypatch.setattr("rebrew.discover.iter_instructions", _iter)
        out = _validate_and_refine(None, [(0x401000, 0, "outer"), (0x401034, 0, "interior")])
        assert [va for va, _s, _n in out] == [0x401000]

    def test_tail_call_candidate_is_kept(self, monkeypatch) -> None:
        """A predecessor ending in an unconditional `jmp` is a tail call, not
        code running into the next candidate — do not drop it."""
        from rebrew.discover import _validate_and_refine

        class Insn:
            def __init__(self, va: int, size: int, mnemonic: str) -> None:
                self.va = va
                self.size = size
                self.mnemonic = mnemonic

        def _iter(info, va, size):
            yield Insn(va, 5, "jmp")

        monkeypatch.setattr("rebrew.discover.iter_instructions", _iter)
        out = _validate_and_refine(None, [(0x401000, 0, "outer"), (0x401034, 0, "thunk")])
        assert [va for va, _s, _n in out] == [0x401000, 0x401034]
