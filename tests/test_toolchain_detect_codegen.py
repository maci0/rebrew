"""Tests for the codegen fingerprint detectors in rebrew.toolchain_detect.

Covers the pure pattern counter (``_count_codegen_signals``), the evidence
wiring in ``detect_toolchain``, stack-probe symbol detection, and the 16-bit
MZ codegen scan.  Every byte pattern is verified against real toolchain
output — see docs/CODEGEN_REFERENCE.md for the provenance.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.toolchain_detect import (
    CodegenSignals,
    ToolchainInfo,
    _count_codegen_signals,
    _mz_codegen_scan,
    detect_toolchain,
)


class _FakeSection:
    def __init__(self, name: str) -> None:
        self.name = name


def _fake_binary(
    sections: list[str],
    dlls: list[str] | None = None,
    text: bytes = b"",
) -> SimpleNamespace:
    """A BinaryInfo-shaped fake for the heuristics backend."""
    return SimpleNamespace(
        sections={n: _FakeSection(n) for n in sections},
        imports=[SimpleNamespace(dll=d) for d in (dlls or [])],
        text_va=0x1000 if text else 0,
        text_size=len(text),
        data=text,
    )


def _run(
    monkeypatch: pytest.MonkeyPatch,
    text_bytes: bytes,
    family: str = "msvc",
    strings: list[str] | None = None,
    sections: list[str] | None = None,
) -> ToolchainInfo:
    """Run detect_toolchain with die/pdb stubbed and the codegen scan fed
    *text_bytes* (family forced via the die backend unless 'unknown')."""
    import rebrew.toolchain_detect as td

    monkeypatch.setattr(td, "_run_diec", lambda *a, **k: None)
    monkeypatch.setattr(td, "detect_with_pdb", lambda *a, **k: None)
    monkeypatch.setattr(
        td,
        "detect_with_die",
        lambda *a, **k: (
            ToolchainInfo(
                family=family, confidence="high", detected_by="die", version_hint="MSVC 6.0"
            )
            if family != "unknown"
            else ToolchainInfo(family="unknown")
        ),
    )
    monkeypatch.setattr(
        td, "load_binary", lambda *a, **k: _fake_binary(sections or [".text"], text=text_bytes)
    )
    monkeypatch.setattr(
        "rebrew.binary_loader.extract_bytes_at_va", lambda binfo, va, size: text_bytes[:size]
    )
    monkeypatch.setattr(td, "_scan_strings", lambda *a, **k: strings or [])
    return detect_toolchain(Path("/tmp/nonexistent-prog.exe"))


class TestCountCodegenSignals:
    """The pure pattern counter — each pattern family counts independently."""

    def test_lea_esp_nops(self) -> None:
        s = _count_codegen_signals(bytes.fromhex("8d 64 24 00 90 8d 64 24 00"))
        assert s.lea_esp_nops == 2

    def test_rep_string_ops(self) -> None:
        s = _count_codegen_signals(bytes.fromhex("f3 ab 90 f3 a5 90 f3 aa 90 f3 a4"))
        assert s.rep_stosd == 1
        assert s.rep_movsd == 1
        assert s.rep_stosb == 1
        assert s.rep_movsb == 1
        assert s.rep_string_ops == 4

    def test_rep_ret(self) -> None:
        s = _count_codegen_signals(bytes.fromhex("f3 c3 90 f3 c3"))
        assert s.rep_ret == 2

    def test_magic_divs_sums_all_constants(self) -> None:
        s = _count_codegen_signals(bytes.fromhex("aa aa aa ab 90 cd cc cc cc 90 67 66 66 66"))
        assert s.magic_divs == 3

    def test_sse2_fp_ops(self) -> None:
        s = _count_codegen_signals(bytes.fromhex("f2 0f 58 c0 f2 0f 59 c0 f2 0f 5c c0 f2 0f 5e c0"))
        assert s.sse2_fp == 4

    def test_x87_esp_loads(self) -> None:
        s = _count_codegen_signals(bytes.fromhex("dd 44 24 04 d9 44 24 08"))
        assert s.x87_fp == 2

    def test_fp_prologue(self) -> None:
        s = _count_codegen_signals(bytes.fromhex("55 8b ec 90 55 8b ec"))
        assert s.fp_prologues == 2

    def test_mov_edi_edi(self) -> None:
        s = _count_codegen_signals(bytes.fromhex("8b ff 90 8b ff"))
        assert s.mov_edi_edi == 2

    def test_empty(self) -> None:
        assert _count_codegen_signals(b"") == CodegenSignals()


class TestCodegenEvidence:
    """Evidence strings and version-hint refinement from the codegen scan."""

    def test_lea_esp_evidence_and_hint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        info = _run(monkeypatch, bytes.fromhex("8d 64 24 00 8d 64 24 00"))
        assert any("lea esp,[esp]" in e and "VC 7.0+" in e for e in info.evidence)
        assert "VC 7.0+" in info.version_hint

    def test_lea_esp_below_threshold_no_hint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        info = _run(monkeypatch, bytes.fromhex("8d 64 24 00"))
        assert info.version_hint == "MSVC 6.0"

    def test_rep_string_ops_evidence(self, monkeypatch: pytest.MonkeyPatch) -> None:
        info = _run(monkeypatch, bytes.fromhex("f3 ab 90 f3 a5"))
        assert any("rep movs/stos string ops" in e for e in info.evidence)

    def test_magic_division_evidence(self, monkeypatch: pytest.MonkeyPatch) -> None:
        info = _run(monkeypatch, bytes.fromhex("aa aa aa ab"))
        assert any("magic-number division" in e for e in info.evidence)

    def test_sse2_evidence_and_hint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        info = _run(monkeypatch, bytes.fromhex("f2 0f 58 c0"))
        assert any("SSE2 FP ops" in e for e in info.evidence)
        assert "VC 11.0+" in info.version_hint

    def test_x87_evidence(self, monkeypatch: pytest.MonkeyPatch) -> None:
        info = _run(monkeypatch, bytes.fromhex("dd 44 24 04"))
        assert any("x87 FPU loads" in e for e in info.evidence)

    def test_fp_prologue_evidence(self, monkeypatch: pytest.MonkeyPatch) -> None:
        info = _run(monkeypatch, bytes.fromhex("55 8b ec"))
        assert any("frame-pointer prologues" in e for e in info.evidence)

    def test_mov_edi_edi_threshold(self, monkeypatch: pytest.MonkeyPatch) -> None:
        info = _run(monkeypatch, bytes.fromhex("8b ff 8b ff"))
        assert any("mov edi,edi" in e for e in info.evidence)
        no = _run(monkeypatch, bytes.fromhex("8b ff"))
        assert not any("mov edi,edi" in e for e in no.evidence)

    def test_rep_ret_evidence_on_mingw(self, monkeypatch: pytest.MonkeyPatch) -> None:
        info = _run(monkeypatch, bytes.fromhex("f3 c3"), family="mingw")
        assert any("rep-ret idioms" in e for e in info.evidence)

    def test_no_patterns_no_new_evidence(self, monkeypatch: pytest.MonkeyPatch) -> None:
        info = _run(monkeypatch, bytes.fromhex("c3 c3 c3"))
        assert not any(
            "lea esp" in e or "rep " in e or "magic" in e or "FPU" in e or "frame-pointer" in e
            for e in info.evidence
        )


class TestProbeSymbols:
    """Stack-probe / security-cookie symbol names pin the family."""

    def test_chkstk_string_evidence_and_family(self, monkeypatch: pytest.MonkeyPatch) -> None:
        info = _run(monkeypatch, b"", family="unknown", strings=["/work/t.obj", "__chkstk"])
        assert any("__chkstk" in e for e in info.evidence)
        assert info.family == "msvc"

    def test_chkstk_ms_string_family(self, monkeypatch: pytest.MonkeyPatch) -> None:
        info = _run(monkeypatch, b"", family="unknown", strings=["___chkstk_ms"])
        assert info.family == "mingw"

    def test_chkstk_ms_not_misread_as_chkstk(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """___chkstk_ms contains __chkstk as a substring — the longer name
        must win (MinGW, not MSVC)."""
        info = _run(monkeypatch, b"", family="unknown", strings=["___chkstk_ms"])
        assert info.family == "mingw"
        assert not any("32-bit stack probe __chkstk" in e for e in info.evidence)

    def test_an_chkstk_16bit_family(self, monkeypatch: pytest.MonkeyPatch) -> None:
        info = _run(monkeypatch, b"", family="unknown", strings=["__aNchkstk"])
        assert info.family == "msvc"

    def test_watcom_chk_family(self, monkeypatch: pytest.MonkeyPatch) -> None:
        info = _run(monkeypatch, b"", family="unknown", strings=["__CHK"])
        assert info.family == "watcom"

    def test_security_cookie_family(self, monkeypatch: pytest.MonkeyPatch) -> None:
        info = _run(monkeypatch, b"", family="unknown", strings=["__security_check_cookie"])
        assert info.family == "msvc"
        assert any("security-cookie" in e for e in info.evidence)


class TestWeakCodegenFamily:
    """Codegen-only family hints when strings/imports give nothing."""

    def test_rep_ret_plus_gnu_nops_is_mingw(self, monkeypatch: pytest.MonkeyPatch) -> None:
        text = bytes.fromhex("f3 c3") + bytes.fromhex("0f 1f 40 00")
        info = _run(monkeypatch, text, family="unknown", sections=[".text", ".data"])
        assert info.family == "mingw"
        assert info.confidence == "medium"

    def test_rep_string_ops_plus_fp_prologues_is_msvc(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        text = bytes.fromhex("f3 ab") + bytes.fromhex("55 8b ec") * 3
        info = _run(monkeypatch, text, family="unknown", sections=[".text", ".data"])
        assert info.family == "msvc"
        assert info.confidence == "low"

    def test_neither_signal_stays_unknown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        info = _run(monkeypatch, bytes.fromhex("c3 c3"), family="unknown")
        assert info.family == "unknown"


class TestMZCodegenScan:
    """_mz_codegen_scan disassembles a DOS MZ entry point (16-bit)."""

    @staticmethod
    def _mz_with_code(code: bytes) -> bytes:
        data = bytearray(0x400)
        data[0:2] = b"MZ"
        # e_ip=0x100, e_cs=0 -> entry at file offset 0x100
        data[0x14:0x16] = (0x100).to_bytes(2, "little")
        data[0x16:0x18] = (0).to_bytes(2, "little")
        data[0x100 : 0x100 + len(code)] = code
        return bytes(data)

    def test_leave_epilogues(self) -> None:
        # msvc 1.5x style: push bp / mov bp,sp / ... / leave / ret
        code = bytes.fromhex("55 8b ec c9 c3 c9 c3 c9 c3")
        c = _mz_codegen_scan(self._mz_with_code(code))
        assert c["leave"] == 3
        assert c["fp_prologue"] == 1

    def test_loop_instructions(self) -> None:
        code = bytes.fromhex("b8 0a 00 e2 fe e0 02")  # mov ax,10 / loop $-2 / loopne +2
        c = _mz_codegen_scan(self._mz_with_code(code))
        assert c["loop"] == 2

    def test_far_returns(self) -> None:
        c = _mz_codegen_scan(self._mz_with_code(bytes.fromhex("cb cb 90 cb")))
        assert c["retf"] == 3

    def test_not_mz_returns_empty(self) -> None:
        assert _mz_codegen_scan(b"not a binary") == {}
        assert _mz_codegen_scan(b"") == {}

    def test_bad_entry_returns_empty(self) -> None:
        data = bytearray(b"MZ" + b"\x00" * 0x20)
        data[0x14:0x16] = (0xFFFF).to_bytes(2, "little")
        data[0x16:0x18] = (0xFFFF).to_bytes(2, "little")
        assert _mz_codegen_scan(bytes(data)) == {}


class TestMZDetection:
    """End-to-end: 16-bit MZ binaries use probe symbols + codegen evidence."""

    def test_mz_with_an_chkstk_string_is_msvc(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.toolchain_detect as td

        monkeypatch.setattr(td, "_run_diec", lambda *a, **k: None)
        monkeypatch.setattr(td, "detect_with_pdb", lambda *a, **k: None)
        monkeypatch.setattr(td, "detect_with_die", lambda *a, **k: None)
        monkeypatch.setattr(
            td, "load_binary", lambda *a, **k: SimpleNamespace(format="mz", data=b"", imports=[])
        )
        monkeypatch.setattr(td, "_scan_strings", lambda *a, **k: ["__aNchkstk"])
        info = detect_toolchain(Path("/tmp/prog.exe"))
        assert info.family == "msvc"
        assert info.arch == "x86_16"

    def test_mz_codegen_evidence_wired(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.toolchain_detect as td

        data = bytearray(0x400)
        data[0:2] = b"MZ"
        data[0x14:0x16] = (0x100).to_bytes(2, "little")
        data[0x100:0x103] = bytes.fromhex("c9 c9 c9")  # leave x3
        monkeypatch.setattr(td, "_run_diec", lambda *a, **k: None)
        monkeypatch.setattr(td, "detect_with_pdb", lambda *a, **k: None)
        monkeypatch.setattr(td, "detect_with_die", lambda *a, **k: None)
        monkeypatch.setattr(
            td,
            "load_binary",
            lambda *a, **k: SimpleNamespace(format="mz", data=bytes(data), imports=[]),
        )
        monkeypatch.setattr(td, "_scan_strings", lambda *a, **k: [])
        info = detect_toolchain(Path("/tmp/prog.exe"))
        assert any("leave epilogues" in e for e in info.evidence)
