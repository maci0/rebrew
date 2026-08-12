"""Tests for rebrew.asm decomp-aid annotations.

Covers the ``--imports`` / ``--strings`` / ``--hints`` hex-mode aids:
``_hint_for`` codegen-pattern detection, ``_annotation_for_operand`` address
resolution, and the ``_run_hex_mode`` integration path against a synthetic PE.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent))  # tests/ on path for bin_util
from bin_util import make_pe  # noqa: E402

from rebrew.analysis import _capstone  # noqa: E402
from rebrew.asm import _annotation_for_operand, _hint_for, _run_hex_mode  # noqa: E402

IMAGE_BASE = 0x400000
TEXT_VA = 0x401000


def _insns(hex_bytes: str) -> list[object]:
    md = _capstone(skipdata=True)
    return list(md.disasm(bytes.fromhex(hex_bytes), TEXT_VA))


def _cfg(tmp_path: Path, binary: Path) -> SimpleNamespace:
    from capstone import CS_ARCH_X86, CS_MODE_32

    src = tmp_path / "src" / "SERVER"
    src.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(
        root=tmp_path,
        target_name="SERVER",
        target_binary=binary,
        reversed_dir=src,
        metadata_dir=tmp_path,
        marker="SERVER",
        source_ext=".c",
        compiler_profile="msvc",
        capstone_arch=CS_ARCH_X86,
        capstone_mode=CS_MODE_32,
    )


class TestHintFor:
    def test_switch_dispatch(self) -> None:
        # jmp dword ptr [eax*4 + 0x10313d0] — jump-table switch dispatch
        insns = _insns("ff 24 85 d0 13 03 01")
        hint = _hint_for(insns, 0) or ""
        assert "switch dispatch" in hint
        assert "rebrew switch" in hint

    def test_plain_jmp_no_hint(self) -> None:
        # jmp 0x1009c76 — direct tail call, not a dispatch
        insns = _insns("e9 76 9c 01 00")
        assert _hint_for(insns, 0) is None

    def test_eh_ctor_prolog_hint(self) -> None:
        # mov eax, 0x1033d1e; call 0x1030660 — EH-ctor registration prolog
        insns = _insns("b8 1e 3d 03 01 e8 ce 74 02 00")
        hint = _hint_for(insns, 1) or ""
        assert "EH-ctor" in hint
        assert "not C-reproducible" in hint

    def test_esp_disp8_hint(self) -> None:
        # mov eax, dword ptr [esp + 0x1c] — MASM folds the disp8 encoding
        insns = _insns("8b 44 24 1c")
        hint = _hint_for(insns, 0) or ""
        assert "_emit" in hint
        assert "disp8" in hint

    def test_iat_forwarder_hint(self) -> None:
        """7 reversed pushes + call [IAT] → forwarder hint with the stdcall
        callee lesson (the forwarder itself is cdecl)."""
        code = (
            "8b 44 24 1c 8b 4c 24 18 8b 54 24 14 50 8b 44 24 14 51 "
            "8b 4c 24 14 52 8b 54 24 14 50 8b 44 24 14 51 52 50 "
            "ff 15 5c 12 00 01 c3"
        )
        insns = _insns(code)
        call_idx = next(i for i, x in enumerate(insns) if x.mnemonic == "call")
        hint = _hint_for(insns, call_idx) or ""
        assert "forwarder" in hint
        assert "7-arg" in hint

    def test_iat_forwarder_hint_with_lookbehind_prefix(self) -> None:
        """The backward scan must not be broken by a lookbehind prefix
        (instructions before the function start) — the pushes immediately
        before the call count regardless of what precedes them."""
        # Prefix (previous function tail: `add esp,8; ret`), then the
        # forwarder's 3 pushes + call [IAT].
        code = "83 c4 08 c3 " + "8b 44 24 10 50 8b 44 24 10 50 8b 44 24 10 50 ff 15 5c 12 00 01 c3"
        insns = _insns(code)
        call_idx = next(i for i, x in enumerate(insns) if x.mnemonic == "call")
        hint = _hint_for(insns, call_idx) or ""
        assert "forwarder" in hint

    def test_byte_compressed_switch_hint(self) -> None:
        # mov dl, byte ptr [ecx+0x103125c]; ...; jmp dword ptr [edx*4+0x1031240]
        insns = _insns("8a 91 5c 12 03 01 ff 24 95 40 12 03 01")
        hint = _hint_for(insns, 1) or ""
        assert "byte-compressed switch" in hint
        assert "may not reproduce" in hint

    def test_post_decrement_counter(self) -> None:
        # mov esi,ecx; dec ecx; test esi,esi; jne
        insns = _insns("8bf14985f675f3")
        assert "post-decrement" in (_hint_for(insns, 3) or "")

    def test_post_decrement_needs_old_value_test(self) -> None:
        # Plain dec/test loop without the mov-copy must NOT be flagged.
        insns = _insns("4985c975f3")  # dec ecx; test ecx,ecx; jne
        assert _hint_for(insns, 2) is None

    def test_seh_prologue(self) -> None:
        # push -1; push 0x413220; push 0x410e18; mov eax, fs:[0]; push eax;
        # mov fs:[0], esp
        insns = _insns("6aff682032410068180e410064a1000000005064892500000000")
        hint = _hint_for(insns, 3) or _hint_for(insns, 5)
        assert hint is not None and "SEH prologue" in hint

    def test_crt_strlen_magic(self) -> None:
        insns = _insns("bafffefe7e")
        hint = _hint_for(insns, 0)
        assert hint is not None and "word-at-a-time" in hint

    def test_movsx_hint(self) -> None:
        insns = _insns("0fbe06")
        hint = _hint_for(insns, 0)
        assert hint is not None and "char promoted to int" in hint

    def test_inc_word_hint(self) -> None:
        insns = _insns("66ff05305b4100")
        hint = _hint_for(insns, 0)
        assert hint is not None and "declared global" in hint

    def test_equality_boolean_hint(self) -> None:
        # cmp eax, 1; sbb eax, eax; inc eax — MSVC `!x` lowering; plain C
        # under MSVC5 compiles to a different epilogue (neg/sbb/neg/dec)
        insns = _insns("83 f8 01 1b c0 40")
        hint = _hint_for(insns, 1) or ""
        assert "equality-boolean" in hint
        assert "naked asm" in hint

    def test_equality_boolean_needs_cmp_1(self) -> None:
        # sbb without the preceding `cmp reg,1` — no hint
        insns = _insns("1b c0 40")
        assert _hint_for(insns, 0) is None


class TestAnnotationForOperand:
    def test_plain_immediate(self) -> None:
        assert _annotation_for_operand("0x4130c8", {0x4130C8: "HeapCreate"}) == "HeapCreate"

    def test_bracketed_absolute(self) -> None:
        assert (
            _annotation_for_operand("dword ptr [0x4130c8]", {0x4130C8: "HeapCreate"})
            == "HeapCreate"
        )

    def test_register_relative_not_resolved(self) -> None:
        assert _annotation_for_operand("dword ptr [eax + 0xc]", {0xC: "nope"}) is None
        assert _annotation_for_operand("dword ptr fs:[0]", {0: "nope"}) is None

    def test_no_hex_operand(self) -> None:
        assert _annotation_for_operand("eax", {}) is None

    def test_missing_key(self) -> None:
        assert _annotation_for_operand("0x99999999", {0x4130C8: "HeapCreate"}) is None


class TestRunHexModeAnnotations:
    def _make_probe(self, tmp_path: Path) -> Path:
        """PE whose .text has an IAT call, a string push, and a post-decrement
        loop — the three annotation targets."""
        imports = [("KERNEL32.dll", ["HeapCreate"])]
        pre = bytearray()

        def emit(raw: bytes) -> None:
            pre.extend(raw)

        emit(b"\xff\x15" + b"\x00\x00\x00\x00")  # call [IAT] (patched below)
        emit(b"\x68" + b"\x00\x00\x00\x00")  # push <string va> (patched below)
        emit(b"\x8b\xf1\x49\x85\xf6\x75\xf3")  # mov esi,ecx; dec ecx; test esi,esi; jne
        emit(b"\xc3")  # ret

        blob_start = TEXT_VA + len(pre)
        blob = b"HelloAnnot\x00"

        def patch(at: int, value: int) -> None:
            pre[at + 1 : at + 1 + 4] = struct.pack("<I", value)

        patch(6, blob_start)  # string push immediate (68 at offset 6)
        proto = make_pe(bytes(pre) + blob, imports=imports)
        probe_path = tmp_path / "probe.exe"
        probe_path.write_bytes(proto)

        import lief

        pe = lief.PE.parse(bytes(proto))
        slot = None
        for imp in pe.imports:
            for entry in imp.entries:
                if entry.name == "HeapCreate":
                    slot = IMAGE_BASE + entry.iat_address
        assert slot is not None
        final = bytearray(bytes(pre) + blob)
        final[0 + 2 : 0 + 6] = struct.pack("<I", slot)
        probe_path.write_bytes(make_pe(bytes(final), imports=imports))
        return probe_path

    def test_json_annotations(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        binary = self._make_probe(tmp_path)
        cfg = _cfg(tmp_path, binary)
        _run_hex_mode(
            TEXT_VA,
            64,
            cfg,
            False,
            True,
            resolve_imports=True,
            resolve_strings=True,
            pattern_hints=True,
        )
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        by_mnemonic = {i["mnemonic"]: i for i in payload["instructions"]}
        assert by_mnemonic["call"]["import"] == "HeapCreate"
        assert by_mnemonic["push"]["string"] == "HelloAnnot"
        jne = by_mnemonic["jne"]
        assert jne["hint"] is not None and "post-decrement" in jne["hint"]

    def test_annotations_off_by_default(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        binary = self._make_probe(tmp_path)
        cfg = _cfg(tmp_path, binary)
        _run_hex_mode(TEXT_VA, 64, cfg, False, True)
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        entry = payload["instructions"][0]
        assert "import" not in entry
        assert "string" not in entry
        assert "hint" not in entry
