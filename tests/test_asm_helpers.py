"""Tests for asm.py — NASM conversion and disassembly helpers (no nasm/r2 needed)."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from rebrew.asm import capstone_to_nasm, disassemble_to_nasm, verify_roundtrip


class TestCapstoneToNasm:
    def test_with_operands(self) -> None:
        assert capstone_to_nasm("mov", "dword ptr [eax]") == "mov dword [eax]"

    def test_no_operands(self) -> None:
        assert capstone_to_nasm("ret", "") == "ret"

    def test_ptr_only_stripped(self) -> None:
        assert capstone_to_nasm("call", "ptr 0x1000") == "call 0x1000"


class TestDisassembleToNasm:
    def test_ret_function(self) -> None:
        src, stats = disassemble_to_nasm(b"\xc3", 0x1000, label="func_ret")
        assert "ret" in src
        assert stats["total_instructions"] == 1
        assert stats["pct_nasm"] == 100.0

    def test_label_sanitized(self) -> None:
        src, _stats = disassemble_to_nasm(b"\xc3", 0x1000, label="my-func!name")
        # Special chars replaced; "func_" prefix only added for non-alpha starts.
        assert "my_func_name:" in src

    def test_label_leading_digit_prefixed(self) -> None:
        src, _stats = disassemble_to_nasm(b"\xc3", 0x1000, label="1bad")
        assert "func_1bad" in src

    def test_no_label(self) -> None:
        src, _stats = disassemble_to_nasm(b"\xc3", 0x1000)
        assert "ret" in src

    def test_instruction_stats(self) -> None:
        # mov eax, 1; ret
        code = b"\xb8\x01\x00\x00\x00\xc3"
        _src, stats = disassemble_to_nasm(code, 0x1000)
        assert stats["total_instructions"] == 2
        assert stats["total_bytes"] == 6


class TestVerifyRoundtrip:
    def test_verified_roundtrip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.asm as asm_mod

        monkeypatch.setattr(asm_mod, "_run_nasm", lambda _src, tmpdir=None: b"\x55\x89\xe5")
        ok, msg = verify_roundtrip("push ebp\nmov ebp, esp\n", b"\x55\x89\xe5")
        assert ok
        assert "pass" in msg.lower()

    def test_mismatch_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.asm as asm_mod

        monkeypatch.setattr(asm_mod, "_run_nasm", lambda _src, tmpdir=None: b"\x55\x90\x90")
        ok, _msg = verify_roundtrip("push ebp\n", b"\x55\x89\xe5")
        assert not ok

    def test_nasm_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.asm as asm_mod

        monkeypatch.setattr(asm_mod, "_run_nasm", lambda _src, tmpdir=None: None)
        ok, _msg = verify_roundtrip("push ebp\n", b"\x55")
        assert not ok


class TestListSizeFor:
    def test_returns_list_size(self, tmp_path: Path) -> None:
        from rebrew.asm import _list_size_for

        cfg = SimpleNamespace(
            function_list=str(tmp_path / "functions.txt"),
        )
        (tmp_path / "functions.txt").write_text(
            "  0x10001000     42  fcn.10001000\n", encoding="utf-8"
        )
        assert _list_size_for(cfg, 0x10001000) == 42
        assert _list_size_for(cfg, 0x2000) is None

    def test_missing_list_returns_none(self, tmp_path: Path) -> None:
        from rebrew.asm import _list_size_for

        cfg = SimpleNamespace(function_list=str(tmp_path / "nope.txt"))
        assert _list_size_for(cfg, 0x1000) is None


class TestCallingConvention:
    """rebrew asm infers the per-function calling convention from the
    epilogue + this-pointer usage — the answer every manual decompilation
    pass re-derives from the disassembly."""

    @staticmethod
    def _i(mnemonic: str, op: str = "") -> Any:
        from types import SimpleNamespace as NS

        return NS(mnemonic=mnemonic, op_str=op)

    def test_plain_ret_is_cdecl(self) -> None:
        from rebrew.asm import calling_convention

        insns = [self._i("mov", "eax, [esp+4]"), self._i("ret")]
        assert calling_convention(insns) == "cdecl"

    def test_ret_n_without_ecx_is_stdcall(self) -> None:
        from rebrew.asm import calling_convention

        insns = [
            self._i("mov", "eax, [esp+4]"),
            self._i("mov", "ecx, [esp+8]"),
            self._i("ret", "8"),
        ]
        assert calling_convention(insns) == "stdcall"

    def test_ecx_pointer_deref_is_thiscall(self) -> None:
        from rebrew.asm import calling_convention

        insns = [
            self._i("mov", "esi, ecx"),
            self._i("mov", "eax, [ecx+0xd4]"),
            self._i("test", "eax, eax"),
            self._i("ret", "4"),
        ]
        assert calling_convention(insns) == "thiscall"

    def test_ecx_save_is_thiscall_no_stack_args(self) -> None:
        from rebrew.asm import calling_convention

        insns = [
            self._i("push", "esi"),
            self._i("mov", "esi, ecx"),
            self._i("mov", "eax, [esi+0x6c]"),
            self._i("ret"),
        ]
        assert calling_convention(insns) == "thiscall (no stack args)"

    def test_mov_ecx_from_mem_first_is_not_thiscall(self) -> None:
        """mov ecx,[esp+4] passes an ARGUMENT in ecx — not the this pointer."""
        from rebrew.asm import calling_convention

        insns = [
            self._i("mov", "ecx, [esp+4]"),
            self._i("mov", "eax, ecx"),
            self._i("idiv", "esi"),
            self._i("ret", "4"),
        ]
        assert calling_convention(insns) == "stdcall"

    def test_ctor_thunk(self) -> None:
        from rebrew.asm import calling_convention

        insns = [self._i("mov", "ecx, 0x103d9f8"), self._i("jmp", "0x1014469")]
        assert calling_convention(insns) == "thiscall (ctor thunk)"

    def test_eh_guard_thunk(self) -> None:
        from rebrew.asm import calling_convention

        insns = [self._i("mov", "ecx, [ebp-0x10]"), self._i("jmp", "0x102f79c")]
        assert calling_convention(insns) == "thiscall (EH-guard thunk)"

    def test_internal_jmp_before_ret_is_not_thunk(self) -> None:
        """An internal branch (jmp L2) is not a tail call — the LAST ret ends."""
        from rebrew.asm import calling_convention

        insns = [
            self._i("cmp", "[esp+4], 0"),
            self._i("je", "L1"),
            self._i("mov", "eax, [0x103c794]"),
            self._i("jmp", "L2"),
            self._i("mov", "eax, [ecx+0x24]"),
            self._i("push", "eax"),
            self._i("call", "0x101495b"),
            self._i("ret", "4"),
        ]
        assert calling_convention(insns) == "thiscall"

    def test_extraction_past_ret_uses_last_ret(self) -> None:
        """The disassembly can run past the function into the next one."""
        from rebrew.asm import calling_convention

        insns = [
            self._i("push", "esi"),
            self._i("mov", "esi, ecx"),
            self._i("ret"),
            self._i("push", "ebp"),
            self._i("mov", "ebp, esp"),
            self._i("sub", "esp, 0x428"),
        ]
        assert calling_convention(insns) == "thiscall (no stack args)"

    def test_hex_ret_operand(self) -> None:
        from rebrew.asm import calling_convention

        insns = [
            self._i("mov", "eax, [esp+4]"),
            self._i("ret", "0x10"),
        ]
        assert calling_convention(insns) == "stdcall"

    def test_empty_unknown(self) -> None:
        from rebrew.asm import calling_convention

        assert calling_convention([]) == "unknown"
