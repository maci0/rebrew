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


class TestDiscovererPlugins:
    """Third-party discoverers join every branch via rebrew.discoverers."""

    def test_plugin_results_merge(self, monkeypatch) -> None:
        import rebrew.discover as disc

        monkeypatch.setattr("rebrew.discover._rizin_functions", lambda b, c: [])
        monkeypatch.setattr("rebrew.discover._capstone_sweep", lambda b: [])
        monkeypatch.setitem(disc._DISCOVERER_MAP, "ghidra", lambda b: [(0x401000, 40, "main")])
        monkeypatch.setattr("rebrew.discover.load_binary", lambda b: _mk_info(b""))
        monkeypatch.setattr("rebrew.discover._validate_and_refine", lambda info, funcs: funcs)
        d = disc.discover_functions(Path("x.exe"))
        assert d.sources["ghidra"] == 1
        assert (0x401000, 40, "main") in d.functions

    def test_broken_plugin_skipped(self, monkeypatch) -> None:
        import rebrew.discover as disc

        def _boom(binary: Path) -> list:
            raise RuntimeError("no backend here")

        monkeypatch.setattr("rebrew.discover._rizin_functions", lambda b, c: [])
        monkeypatch.setattr("rebrew.discover._capstone_sweep", lambda b: [])
        monkeypatch.setitem(disc._DISCOVERER_MAP, "broken", _boom)
        monkeypatch.setattr("rebrew.discover.load_binary", lambda b: _mk_info(b""))
        monkeypatch.setattr("rebrew.discover._validate_and_refine", lambda info, funcs: funcs)
        d = disc.discover_functions(Path("x.exe"))
        assert d.sources["broken"] == 0
        assert d.functions == []

    @pytest.mark.parametrize(
        "result",
        [None, "fcn", [(0x401000, 40)], [("0x401000", 40, "f")], [(0x401000, -1, "f")]],
    )
    def test_malformed_plugin_result_skipped(self, monkeypatch, result: object) -> None:
        """A plugin returning the wrong shape is skipped, not a crash in the merge."""
        import rebrew.discover as disc

        monkeypatch.setattr("rebrew.discover._rizin_functions", lambda b, c: [])
        monkeypatch.setattr("rebrew.discover._capstone_sweep", lambda b: [])
        monkeypatch.setitem(disc._DISCOVERER_MAP, "bad", lambda b: result)
        monkeypatch.setattr("rebrew.discover.load_binary", lambda b: _mk_info(b""))
        monkeypatch.setattr("rebrew.discover._validate_and_refine", lambda info, funcs: funcs)
        d = disc.discover_functions(Path("x.exe"))
        assert d.sources["bad"] == 0
        assert d.functions == []

    def test_plugin_entry_point_merge(self, monkeypatch) -> None:
        """Entry-point registrations join the map; conflicts are skipped."""
        import rebrew.discover as disc
        from rebrew.registry import Registration

        reg = Registration(
            name="mine",
            module="nope",
            attr="",
            group="rebrew.discoverers",
            origin="test",
        )
        monkeypatch.setattr("rebrew.registry.entry_point_registrations", lambda group: [reg])
        monkeypatch.setattr(
            "rebrew.registry.load_registration_optional", lambda r, log: lambda b: []
        )
        merged = disc.discoverer_map()
        assert "mine" in merged
        assert "rizin aaa" in merged  # packaged set intact


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
            # The predecessor decodes across its whole window into the candidate.
            yield Insn(va, size - 2, "mov")
            yield Insn(va + size - 2, 2, "jne")

        monkeypatch.setattr("rebrew.discover.iter_instructions", _iter)
        out = _validate_and_refine(None, [(0x401000, 0, "outer"), (0x401034, 0, "interior")])
        assert [va for va, _s, _n in out] == [0x401000]

    def test_a_window_cut_short_keeps_the_candidate(self, monkeypatch) -> None:
        """Decoding that stops before the next candidate (the section's file
        bytes end, as at the end of an ELF ``.plt``) proves nothing about it:
        dropping there cascaded through every later function of a static ELF."""
        from rebrew.discover import _validate_and_refine

        class Insn:
            def __init__(self, va: int, size: int, mnemonic: str) -> None:
                self.va = va
                self.size = size
                self.mnemonic = mnemonic

        def _iter(info, va, size):
            yield Insn(va, 6, "push")

        monkeypatch.setattr("rebrew.discover.iter_instructions", _iter)
        out = _validate_and_refine(None, [(0x401020, 0, "plt"), (0x401100, 0, "main")])
        assert [va for va, _s, _n in out] == [0x401020, 0x401100]

    def test_prefixed_jumps_and_nop_padding_end_a_function(self, monkeypatch) -> None:
        """`bnd jmp` / `notrack jmp` are tail jumps and `nop` is padding: the next
        candidate after either is a function of its own."""
        from rebrew.discover import _validate_and_refine

        class Insn:
            def __init__(self, va: int, size: int, mnemonic: str) -> None:
                self.va = va
                self.size = size
                self.mnemonic = mnemonic

        for last in ("bnd jmp", "notrack jmp", "nop"):
            monkeypatch.setattr(
                "rebrew.discover.iter_instructions",
                lambda info, va, size, last=last: [Insn(va, size, last)],
            )
            out = _validate_and_refine(None, [(0x401020, 0, "stub"), (0x401030, 0, "next")])
            assert [va for va, _s, _n in out] == [0x401020, 0x401030], last

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


def _cie(encoding: int) -> bytes:
    """A version-1 ``zR`` CIE whose FDEs use *encoding*."""
    body = b"\x00\x00\x00\x00" + b"\x01" + b"zR\x00" + b"\x01" + b"\x78" + b"\x10"
    body += b"\x01" + bytes([encoding])
    return len(body).to_bytes(4, "little") + body


def _fde(record_offset: int, cie_offset: int, section_va: int, start: int, size: int) -> bytes:
    """A pc-relative sdata4 FDE at *record_offset* covering ``[start, start + size)``."""
    id_field = record_offset + 4
    begin_field = id_field + 4
    body = (id_field - cie_offset).to_bytes(4, "little")
    body += (start - (section_va + begin_field)).to_bytes(4, "little", signed=True)
    body += size.to_bytes(4, "little") + b"\x00"
    return len(body).to_bytes(4, "little") + body


class TestEhFrame:
    """Function extents from an ELF ``.eh_frame``."""

    SECTION_VA = 0x5000

    def _frame(self, extents: list[tuple[int, int]]) -> bytes:
        data = _cie(0x1B)
        for start, size in extents:
            data += _fde(len(data), 0, self.SECTION_VA, start, size)
        return data

    def test_each_fde_gives_its_start_and_size(self) -> None:
        from rebrew.discover import _parse_eh_frame

        data = self._frame([(0x401000, 0x40), (0x401040, 0x13)]) + b"\x00\x00\x00\x00"
        assert _parse_eh_frame(data, self.SECTION_VA, pointer_size=8, big_endian=False) == [
            (0x401000, 0x40),
            (0x401040, 0x13),
        ]

    def test_a_truncated_record_keeps_what_came_before(self) -> None:
        from rebrew.discover import _parse_eh_frame

        data = self._frame([(0x401000, 0x40), (0x401040, 0x13)])
        extents = _parse_eh_frame(data[:-3], self.SECTION_VA, pointer_size=8, big_endian=False)
        assert extents == [(0x401000, 0x40)]

    def test_an_fde_without_a_known_cie_is_skipped(self) -> None:
        from rebrew.discover import _parse_eh_frame

        data = _cie(0x1B)
        # The FDE's CIE pointer names offset 2, inside the CIE, not its start.
        data += _fde(len(data), 2, self.SECTION_VA, 0x401000, 0x10)
        assert _parse_eh_frame(data, self.SECTION_VA, pointer_size=8, big_endian=False) == []

    def test_any_input_parses_without_raising(self) -> None:
        from hypothesis import given, settings
        from hypothesis import strategies as st

        from rebrew.discover import _parse_eh_frame

        @settings(max_examples=400, deadline=None)
        @given(st.binary(max_size=256), st.sampled_from([4, 8]), st.booleans())
        def parse(data: bytes, pointer_size: int, big_endian: bool) -> None:
            for prefix in (b"", _cie(0x1B), _cie(0x00)):
                result = _parse_eh_frame(
                    prefix + data, 0x1000, pointer_size=pointer_size, big_endian=big_endian
                )
                assert all(size > 0 for _start, size in result)

        parse()

    def test_a_vouched_start_survives_a_noreturn_predecessor(self, monkeypatch) -> None:
        """Code ending in ``call abort`` runs into the next function with no
        ``ret``; the unwind table's word keeps that next function."""
        from rebrew.discover import _validate_and_refine

        class Insn:
            def __init__(self, va: int, size: int, mnemonic: str) -> None:
                self.va = va
                self.size = size
                self.mnemonic = mnemonic

        def _iter(info, va, size):
            yield Insn(va, size - 5, "mov")
            yield Insn(va + size - 5, 5, "call")

        monkeypatch.setattr("rebrew.discover.iter_instructions", _iter)
        funcs = [(0x401000, 0, "dies"), (0x401020, 0, "next")]
        assert [va for va, _s, _n in _validate_and_refine(None, funcs)] == [0x401000]
        kept = _validate_and_refine(None, funcs, vouched=frozenset({0x401020}))
        assert [va for va, _s, _n in kept] == [0x401000, 0x401020]


def test_a_stripped_elf_is_discovered_from_its_unwind_records(tmp_path: Path) -> None:
    """Every function of 8+ bytes of a stripped ELF, at its exact start and size."""
    import shutil
    import subprocess

    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None or shutil.which("nm") is None or shutil.which("strip") is None:
        pytest.skip("needs cc, nm and strip")
    src = tmp_path / "prog.c"
    src.write_text(
        "#include <stdlib.h>\n"
        "__attribute__((noinline)) static void die(int c) { if (c) abort(); }\n"
        "__attribute__((noinline)) static int twice(int x) { die(x < 0); return x * 2; }\n"
        "__attribute__((noinline)) static int table(int x) {\n"
        "  switch (x) { case 1: return 7; case 2: return 11; case 3: return 13; }\n"
        "  return twice(x) + 1; }\n"
        "int main(int argc, char **argv) { (void)argv; return table(argc) + twice(argc); }\n",
        encoding="utf-8",
    )
    full = tmp_path / "prog"
    subprocess.run([cc, "-O2", "-o", str(full), str(src)], check=True, capture_output=True)
    stripped = tmp_path / "prog.stripped"
    subprocess.run(["strip", "-o", str(stripped), str(full)], check=True, capture_output=True)
    symbols = subprocess.run(["nm", "-S", str(full)], check=True, capture_output=True, text=True)
    truth = {}
    for line in symbols.stdout.splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[2] in "tT" and int(parts[1], 16) >= 8:
            truth[int(parts[0], 16)] = int(parts[1], 16)
    found = {va: size for va, size, _name in discover_functions(stripped).functions}
    assert {va: found.get(va) for va in truth} == truth


def test_a_stripped_x64_pe_is_discovered_from_its_pdata(tmp_path: Path) -> None:
    """Every non-leaf function of a stripped x64 PE, at its exact start."""
    import shutil
    import subprocess

    cc = shutil.which("x86_64-w64-mingw32-gcc")
    nm = shutil.which("x86_64-w64-mingw32-nm")
    strip = shutil.which("x86_64-w64-mingw32-strip")
    if cc is None or nm is None or strip is None:
        pytest.skip("needs the x86_64-w64-mingw32 toolchain")
    src = tmp_path / "prog.c"
    src.write_text(
        "#include <stdio.h>\n"
        '__attribute__((noinline)) static int scale(int x) { printf("%d\\n", x); return x * 3; }\n'
        "__attribute__((noinline)) static int both(int x) { return scale(x) + scale(x + 1); }\n"
        "int main(int argc, char **argv) { (void)argv; return both(argc); }\n",
        encoding="utf-8",
    )
    full = tmp_path / "prog.exe"
    subprocess.run([cc, "-O2", "-o", str(full), str(src)], check=True, capture_output=True)
    stripped = tmp_path / "stripped.exe"
    subprocess.run([strip, "-o", str(stripped), str(full)], check=True, capture_output=True)
    symbols = subprocess.run([nm, str(full)], check=True, capture_output=True, text=True).stdout
    wanted = {"scale", "both", "main"}
    truth = {
        int(parts[0], 16)
        for parts in (line.split() for line in symbols.splitlines())
        if len(parts) == 3 and parts[2] in wanted
    }
    assert len(truth) == len(wanted)
    found = {va for va, _size, _name in discover_functions(stripped).functions}
    assert truth <= found
