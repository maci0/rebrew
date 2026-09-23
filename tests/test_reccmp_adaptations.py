"""Tests for the reccmp-adapted modules: pinned diff, asm equivalence,
vtordisp/float-const scans, demangle helpers, cvdump PDB parser, and the
near_diag wiring (pins + jump-swap equivalence)."""

import struct
import sys
from pathlib import Path

import pytest

from rebrew.analysis import disasm_insns
from rebrew.asm_equiv import jump_swap_ok
from rebrew.demangle import (
    InvalidEncodedNumberError,
    demangle_string_const,
    demangle_vtable,
    get_function_arg_string,
    parse_encoded_number,
)
from rebrew.float_const import find_float_consts, find_float_instructions_in_buffer
from rebrew.near_diag import align_and_classify
from rebrew.pdb_cvdump import CvdumpParser
from rebrew.pinned_diff import SequenceMatcherWithPins
from rebrew.vtordisp import find_vtordisps

# ---------------------------------------------------------------------------
# pinned_diff
# ---------------------------------------------------------------------------


class TestSequenceMatcherWithPins:
    def test_pin_blocks_cross_alignment(self) -> None:
        # Without the pin, 'ab' in a could align anywhere; the pin forces
        # the X island to stay between the pinned anchors.
        m = SequenceMatcherWithPins("abXcd", "abYcd", [(1, 1), (3, 3)])
        tags = [op.tag for op in m.get_opcodes()]
        assert tags == ["equal", "equal", "replace", "equal"]
        assert m.ratio() == pytest.approx(0.8)

    def test_no_pins_equals_plain_diff(self) -> None:
        import difflib

        a, b = ["x", "y", "z"], ["x", "q", "z"]
        m = SequenceMatcherWithPins(a, b, [])
        plain = difflib.SequenceMatcher(None, a, b, autojunk=False)
        assert [op.tag for op in m.get_opcodes()] == [op[0] for op in plain.get_opcodes()]

    def test_invalid_pins_dropped(self) -> None:
        m = SequenceMatcherWithPins("ab", "ab", [(99, 0), (0, 99), (1, 1)])
        assert all(op.tag == "equal" for op in m.get_opcodes())

    def test_non_monotonic_pins_raise(self) -> None:
        with pytest.raises(ValueError, match="monotonous"):
            SequenceMatcherWithPins("abc", "abc", [(2, 2), (1, 1)])


# ---------------------------------------------------------------------------
# asm_equiv
# ---------------------------------------------------------------------------


class TestAsmEquiv:
    def test_jump_swap_table(self) -> None:
        assert jump_swap_ok("ja 0x10", "jb 0x10")
        assert jump_swap_ok("jge 0x10", "jle 0x10")
        assert jump_swap_ok("je 0x10", "je 0x10")
        assert not jump_swap_ok("ja 0x10", "jg 0x10")
        assert not jump_swap_ok("mov eax, ebx", "jb 0x10")


# ---------------------------------------------------------------------------
# vtordisp
# ---------------------------------------------------------------------------


class TestVtordisp:
    def test_vtordisp_zero_addend(self) -> None:
        # sub ecx, 0x10 ; jmp rel32 (to base+0x100)
        jmp = struct.pack("<i", 0x100 - 8)
        code = b"\x2b\x49\x10" + b"\xe9" + jmp
        found = list(find_vtordisps(code, 0x401000))
        assert len(found) == 1
        t = found[0]
        assert t.addr == 0x401000
        assert t.disp == 0x10
        assert t.addend == 0
        assert t.size == 8
        assert t.func_addr == 0x401100

    def test_vtordisp_add_addend(self) -> None:
        # sub ecx, 4 ; add ecx, 0x20 ; jmp rel32
        code = (
            b"\x2b\x49\x04\x81\xc1"
            + struct.pack("<i", 0x20)
            + b"\xe9"
            + struct.pack("<i", 0x200 - 14)
        )
        (t,) = find_vtordisps(code, 0x401000)
        assert t.addend == 0x20
        assert t.size == 14
        assert t.func_addr == 0x401200

    def test_vtordisp_sub_addend(self) -> None:
        # sub ecx, 4 ; sub ecx, 8 ; jmp rel32
        code = b"\x2b\x49\x04\x83\xe9\x08\xe9" + struct.pack("<i", 0x300 - 11)
        (t,) = find_vtordisps(code, 0x401000)
        assert t.addend == -8
        assert t.size == 11
        assert t.func_addr == 0x401300

    def test_no_thunks_in_plain_code(self) -> None:
        assert list(find_vtordisps(b"\x90" * 32, 0x401000)) == []


# ---------------------------------------------------------------------------
# float_const
# ---------------------------------------------------------------------------


class TestFloatConst:
    def test_find_float_instructions(self) -> None:
        # fld dword ptr [0x00403000]
        code = b"\xd9\x05" + struct.pack("<I", 0x403000) + b"\x90"
        found = list(find_float_instructions_in_buffer(code, 0x401000))
        assert len(found) == 1
        assert found[0].address == 0x401000
        assert found[0].pointer == 0x403000

    def test_find_float_consts(self) -> None:
        image = struct.pack("<f", 3.5)  # the constant at 0x403000
        # fld [0x403000] from code at 0x401000
        code = b"\xd9\x05" + struct.pack("<I", 0x403000)
        consts = list(
            find_float_consts(
                [(0x401000, code)],
                [(0x403000, 0x403100)],
                lambda va, size: image,
            )
        )
        assert len(consts) == 1
        assert consts[0].address == 0x403000
        assert consts[0].size == 4
        assert consts[0].value == pytest.approx(3.5)

    def test_pointer_to_writable_data_ignored(self) -> None:
        code = b"\xd9\x05" + struct.pack("<I", 0x405000)
        assert (
            list(
                find_float_consts(
                    [(0x401000, code)], [(0x403000, 0x403100)], lambda va, size: b"\x00" * size
                )
            )
            == []
        )

    def test_duplicate_pointer_yielded_once(self) -> None:
        code = (b"\xd9\x05" + struct.pack("<I", 0x403000)) * 2
        consts = list(
            find_float_consts([(0x401000, code)], [(0x403000, 0x403100)], lambda va, s: b"\x00" * s)
        )
        assert len(consts) == 1

    def test_double_straddling_region_end_skipped(self) -> None:
        # fld qword ptr [0x4030fc]: 8 bytes would run past .rdata end 0x403100
        code = b"\xdd\x05" + struct.pack("<I", 0x4030FC)
        consts = list(
            find_float_consts([(0x401000, code)], [(0x403000, 0x403100)], lambda va, s: b"\x00" * 4)
        )
        assert consts == []

    def test_unrelocated_hit_does_not_mask_real_reference(self) -> None:
        ref = b"\xd9\x05" + struct.pack("<I", 0x403000)
        code = ref + ref  # first copy is not a reloc site, second is
        consts = list(
            find_float_consts(
                [(0x401000, code)],
                [(0x403000, 0x403100)],
                lambda va, s: b"\x00" * s,
                reloc_sites={0x401000 + len(ref) + 2},
            )
        )
        assert [c.address for c in consts] == [0x403000]


# ---------------------------------------------------------------------------
# demangle
# ---------------------------------------------------------------------------


class TestDemangle:
    def test_parse_encoded_number(self) -> None:
        assert parse_encoded_number("12@") == 0x12
        assert parse_encoded_number("BC@") == 0x12
        with pytest.raises(InvalidEncodedNumberError):
            parse_encoded_number("ZZ@")

    def test_demangle_string_const(self) -> None:
        info = demangle_string_const("??_C@_0O@FEAOBMAF@some?5text?$AA@")
        assert info is not None
        assert info.length == 14
        assert info.is_utf16 is False

    def test_demangle_string_const_utf16(self) -> None:
        info = demangle_string_const("??_C@_1EK@HASH@text@")
        assert info is not None
        assert info.is_utf16 is True

    def test_demangle_string_const_rejects_other(self) -> None:
        assert demangle_string_const("?fn@@YAHXZ") is None

    def test_demangle_vtable_template(self) -> None:
        name = demangle_vtable("??_7?$Vec@VMat@@@6B@")
        assert name.startswith("Vec<")
        assert "Mat" in name

    def test_demangle_vtable_simple(self) -> None:
        assert demangle_vtable("??_7Foo@@6B@") == "Foo"

    def test_function_arg_string_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Without pydemumble the fallback strips decoration only, leaving no
        # parameter list to extract.
        monkeypatch.setitem(sys.modules, "pydemumble", None)
        assert get_function_arg_string("?fn@@YAXXZ") is None

    def test_function_arg_string_demangled(self) -> None:
        pytest.importorskip("pydemumble")
        assert get_function_arg_string("?fn@@YAXXZ") == "(void)"


# ---------------------------------------------------------------------------
# pdb_cvdump parser
# ---------------------------------------------------------------------------


class TestCvdumpParser:
    def test_publics(self) -> None:
        p = CvdumpParser()
        p.read_section("PUBLICS", "S_PUB32: [0001:0003FF60], Flags: 00000000, __read\n")
        assert len(p.publics) == 1
        entry = p.publics[0]
        assert entry.name == "__read"
        assert entry.section == 1
        assert entry.offset == 0x3FF60

    def test_section_contributions(self) -> None:
        p = CvdumpParser()
        p.read_section(
            "SECTION CONTRIBUTIONS",
            "  00DA  0001:00000000  00000073  60501020\n",
        )
        (ref,) = p.sizerefs
        assert ref.module == 0xDA
        assert ref.size == 0x73

    def test_modules(self) -> None:
        p = CvdumpParser()
        p.read_section(
            "MODULES",
            '0003 "C:\\lib\\foo.lib" "check.obj"\n0004 "CMakeFiles/isle.dir/res/isle.rc.res"\n',
        )
        assert [m.id for m in p.modules] == [3, 4]
        assert p.modules[0].lib.endswith("foo.lib")
        assert p.modules[1].lib == ""

    def test_lines(self) -> None:
        p = CvdumpParser()
        p.read_section(
            "LINES",
            "  Z:\\proj\\view.cpp (None), 0001:00034E90-00034E97, line/addr pairs = 2\n"
            "     27 00034EC0     28 00034EE2\n",
        )
        assert list(p.lines) == ["Z:\\proj\\view.cpp"]
        assert [ln.line_number for ln in p.lines["Z:\\proj\\view.cpp"]] == [27, 28]


class TestCvdumpExePath:
    def test_override_file_wins(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew import pdb_cvdump as pv

        exe = tmp_path / "cvdump.exe"
        exe.write_bytes(b"")
        monkeypatch.setenv("REBREW_CVDUMP", str(exe))
        assert pv.cvdump_exe_path() == str(exe)

    def test_missing_override_fails_loud(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew import pdb_cvdump as pv

        monkeypatch.setenv("REBREW_CVDUMP", str(tmp_path / "typo.exe"))
        monkeypatch.setattr(pv.shutil, "which", lambda _name: "/usr/bin/cvdump.exe")
        with pytest.raises(FileNotFoundError, match="REBREW_CVDUMP"):
            pv.cvdump_exe_path()

    def test_empty_override_uses_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew import pdb_cvdump as pv

        monkeypatch.setenv("REBREW_CVDUMP", "")
        monkeypatch.setattr(pv.shutil, "which", lambda _name: "/usr/bin/cvdump.exe")
        assert pv.cvdump_exe_path() == "/usr/bin/cvdump.exe"


class TestCvdumpRunLifecycle:
    """Cvdump.run owns a cvdump/wine child: an abort mid-parse must reap it,
    and a clean run must not kill an already-exited child."""

    class _FakeProc:
        def __init__(self) -> None:
            import io as _io

            self.stdout = _io.BytesIO(b"")
            self.killed = False
            self.returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        pid = 0

        def killpg(self, pid: int, sig: int) -> None:
            self.killed = True
            self.returncode = -9

        def wait(self, timeout: float | None = None) -> int:
            if self.returncode is None:  # a real wait() reaps the exit code
                self.returncode = 0
            return self.returncode

    def _wire(self, monkeypatch: pytest.MonkeyPatch) -> _FakeProc:
        from rebrew import pdb_cvdump as pv

        proc = self._FakeProc()
        monkeypatch.setattr(pv.Cvdump, "cmd_line", lambda self: ["cvdump"])
        monkeypatch.setattr(pv.subprocess, "Popen", lambda *a, **k: proc)
        monkeypatch.setattr(pv.os, "killpg", proc.killpg)
        return proc

    def test_child_reaped_when_parse_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew import pdb_cvdump as pv

        proc = self._wire(monkeypatch)

        def _boom(*a: object, **k: object) -> None:
            raise RuntimeError("parse exploded")

        monkeypatch.setattr(pv, "iter_cvdump_sections", _boom)
        with pytest.raises(RuntimeError, match="parse exploded"):
            pv.Cvdump("x.pdb").publics().run()
        assert proc.killed, "an abort mid-parse must kill the cvdump child"

    def test_abort_kills_grandchildren(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """wine forks helpers; killing only the loader orphaned them."""
        import io
        import time

        from rebrew import pdb_cvdump as pv

        pidfile = tmp_path / "pid"
        script = f"sleep 60 & echo $! > {pidfile}; echo x; wait"
        monkeypatch.setattr(pv.Cvdump, "cmd_line", lambda self: ["sh", "-c", script])

        def _boom(wrap: io.TextIOWrapper) -> None:
            wrap.readline()  # the pid is written before "x"
            raise RuntimeError("parse exploded")

        monkeypatch.setattr(pv, "iter_cvdump_sections", _boom)
        with pytest.raises(RuntimeError, match="parse exploded"):
            pv.Cvdump("x.pdb").publics().run()
        stat = Path(f"/proc/{int(pidfile.read_text())}/stat")

        def _alive() -> bool:
            try:
                return stat.read_text().rsplit(") ", 1)[1][0] != "Z"
            except FileNotFoundError:
                return False

        deadline = time.monotonic() + 5
        while _alive():
            assert time.monotonic() < deadline, "grandchild survived the abort"
            time.sleep(0.05)

    def test_hung_child_times_out(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A wedged wine must fail the run, not hang the caller."""
        from rebrew import pdb_cvdump as pv

        monkeypatch.setattr(pv.Cvdump, "cmd_line", lambda self: ["sh", "-c", "sleep 60"])
        monkeypatch.setattr(pv, "_CVDUMP_TIMEOUT_S", 0.2)
        with pytest.raises(RuntimeError, match="timed out after 0.2s reading x.pdb"):
            pv.Cvdump("x.pdb").publics().run()

    def test_clean_run_returns_without_killing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew import pdb_cvdump as pv

        proc = self._wire(monkeypatch)
        monkeypatch.setattr(pv, "iter_cvdump_sections", lambda wrap: iter(()))
        parser = pv.Cvdump("x.pdb").publics().run()
        assert isinstance(parser, pv.CvdumpParser)
        assert not proc.killed, "an exited child must not be killed again"

    def test_non_utf8_filenames_stay_distinct(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import io

        from rebrew import pdb_cvdump as pv

        proc = self._wire(monkeypatch)
        # Two Shift-JIS source paths that share every ASCII byte.
        header = b"*** LINES\n"
        rec = b" C:\\%s\\a.c (None), 0001:00001000-00001010, line/addr pairs = 1\n  1 00001000\n"
        proc.stdout = io.BytesIO(
            header + rec % "テスト".encode("shift_jis") + rec % "ゲーム".encode("shift_jis")
        )
        parser = pv.Cvdump("x.pdb").lines().run()
        keys = list(parser.lines)
        assert len(keys) == 2
        assert keys[0].encode("utf-8", "surrogateescape") == b"C:\\%s\\a.c" % "テスト".encode(
            "shift_jis"
        )

    def test_failed_child_raises_instead_of_empty_parse(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew import pdb_cvdump as pv

        proc = self._wire(monkeypatch)
        proc.returncode = 1
        monkeypatch.setattr(pv, "iter_cvdump_sections", lambda wrap: iter(()))
        with pytest.raises(RuntimeError, match="status 1 reading x.pdb"):
            pv.Cvdump("x.pdb").publics().run()


# ---------------------------------------------------------------------------
# near_diag wiring
# ---------------------------------------------------------------------------


class TestNearDiagWiring:
    def test_jump_swap_classified_equivalent(self) -> None:
        # cmp/ja vs cmp/jb with same displacement: mirrored condition pair.
        # ja rel8 (0x77) vs jb rel8 (0x72), same operand.
        target = disasm_insns(b"\x77\x08", 0x401000)
        compiled = disasm_insns(b"\x72\x08", 0x401000)
        counts, _ = align_and_classify(target, compiled, set())
        assert counts["equivalent"] == 2
        assert counts["structural"] == 0

    def test_pins_keep_alignment_across_churn(self) -> None:
        # Shared unique anchor instruction (b8 imm32 = mov eax, imm) on both
        # sides; unique raw pins must produce an equal span at the anchor.
        shared = b"\xb8\xef\xbe\xad\xde"
        target = disasm_insns(b"\x90\x90" + shared, 0x401000)
        compiled = disasm_insns(b"\x90" + shared, 0x401000)
        counts, _ = align_and_classify(target, compiled, set())
        # The anchor's 5 bytes must be classified 'match', not scrambled.
        assert counts["match"] >= 5
