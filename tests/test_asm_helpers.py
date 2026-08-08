"""Tests for asm.py — NASM conversion and disassembly helpers (no nasm/r2 needed)."""

from pathlib import Path
from types import SimpleNamespace

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
