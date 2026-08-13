"""Tests for rebrew.toolchain_detect — layered toolchain detection.

Covers the pure helpers and each backend with mocked subprocess/backends
(the orchestration against real binaries is exercised via `rebrew doctor`'s
alignment check and the decomp projects).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from rebrew.toolchain_detect import (
    ToolchainInfo,
    _diec_version_hint,
    _gcc_era_hint,
    detect_toolchain,
    detect_with_die,
    detect_with_pdb,
    profile_matches_detection,
)


class TestGccEraHint:
    def test_old_style_majority(self) -> None:
        assert "pre-8" in _gcc_era_hint(count_modern=2, count_old=50)

    def test_modern_style_majority(self) -> None:
        assert "modern" in _gcc_era_hint(count_modern=50, count_old=2)

    def test_too_few_samples(self) -> None:
        assert _gcc_era_hint(count_modern=1, count_old=2) == ""


class TestDiecVersionHint:
    def test_msvc_version_mapping(self) -> None:
        dets = [{"values": [{"name": "Microsoft Visual C/C++", "version": "12.00.9782"}]}]
        assert _diec_version_hint(dets) == "MSVC 6.0"

    def test_delphi_version(self) -> None:
        dets = [{"values": [{"name": "Borland Delphi", "version": "2"}]}]
        assert _diec_version_hint(dets) == "Borland Delphi 2"

    def test_mingw_without_version(self) -> None:
        dets = [{"values": [{"name": "MinGW", "version": ""}]}]
        assert _diec_version_hint(dets) == "MinGW GCC"

    def test_no_compiler(self) -> None:
        assert _diec_version_hint([]) == ""

    def test_linker_fallback(self) -> None:
        # explorer.exe on Win2K yields only a Linker record — the era comes
        # from the linker version.
        dets = [{"values": [{"name": "Microsoft Linker", "version": "5.12.9049"}]}]
        assert _diec_version_hint(dets) == "MSVC 5.0 (linker 5.12.9049)"

    def test_linker_fallback_unmapped_era(self) -> None:
        dets = [{"values": [{"name": "Microsoft Linker", "version": "9.00.30729"}]}]
        assert _diec_version_hint(dets) == "MSVC 9.0 (linker 9.00.30729)"


class TestProfileMatches:
    def test_msvc_profile_matches_msvc(self) -> None:
        info = ToolchainInfo(family="msvc")
        aligned, expl = profile_matches_detection("msvc6", info)
        assert aligned is True
        assert expl is None

    def test_msvc5_profile_matches_msvc(self) -> None:
        """Corpus regression: bind-rebrew (VC5.0) must not fail doctor."""
        info = ToolchainInfo(family="msvc")
        aligned, expl = profile_matches_detection("msvc5", info)
        assert aligned is True
        assert expl is None

    def test_gcc_pe_matches_mingw(self) -> None:
        info = ToolchainInfo(family="mingw")
        aligned, expl = profile_matches_detection("gcc-pe", info)
        assert aligned is True

    def test_msvc6_does_not_match_mingw(self) -> None:
        info = ToolchainInfo(family="mingw")
        aligned, expl = profile_matches_detection("msvc6", info)
        assert aligned is False
        assert "gcc-pe" in (expl or "")

    def test_delphi_never_matches(self) -> None:
        info = ToolchainInfo(family="delphi")
        aligned, expl = profile_matches_detection("msvc6", info)
        assert aligned is False

    def test_msvc152_profile_matches_msvc(self) -> None:
        info = ToolchainInfo(family="msvc")
        aligned, expl = profile_matches_detection("msvc1.52", info)
        assert aligned is True

    def test_watcom_profile_matches_watcom(self) -> None:
        """Open Watcom now has a profile — doctor alignment must pass."""
        info = ToolchainInfo(family="watcom")
        aligned, expl = profile_matches_detection("watcom", info)
        assert aligned is True

    def test_symantec_never_matches(self) -> None:
        info = ToolchainInfo(family="symantec")
        aligned, expl = profile_matches_detection("msvc6", info)
        assert aligned is False
        assert "symantec" in (expl or "")

    def test_zig_is_structural_caveat(self) -> None:
        info = ToolchainInfo(family="zig")
        aligned, expl = profile_matches_detection("gcc-pe", info)
        assert aligned is True
        assert expl is not None

    def test_unknown_family_not_second_guessed(self) -> None:
        info = ToolchainInfo(family="unknown")
        aligned, expl = profile_matches_detection("msvc6", info)
        assert aligned is True

    def test_watcom_never_matches(self) -> None:
        info = ToolchainInfo(family="watcom")
        aligned, expl = profile_matches_detection("msvc6", info)
        assert aligned is False
        assert "watcom" in (expl or "")

    def test_borlandc_never_matches(self) -> None:
        info = ToolchainInfo(family="borlandc")
        aligned, expl = profile_matches_detection("gcc-pe", info)
        assert aligned is False
        assert "borlandc" in (expl or "")


class TestDetectWithDie:
    def test_diec_missing_reports_status(self, monkeypatch) -> None:
        monkeypatch.setattr("rebrew.toolchain_detect._find_diec", lambda: None)
        info = detect_with_die(Path("x.exe"))
        assert info is not None
        assert info.family == "unknown"
        assert any("diec not found" in e for e in info.evidence)

    def test_msvc_compiler_detection(self, monkeypatch) -> None:
        dets = [
            {
                "values": [
                    {
                        "type": "Linker",
                        "name": "Microsoft Linker",
                        "string": "Linker: Microsoft Linker(5.12.8034)",
                    },
                    {
                        "type": "Compiler",
                        "name": "Microsoft Visual C/C++",
                        "version": "12.00.9782",
                        "string": "Compiler: Microsoft Visual C/C++(12.00.9782)[C]",
                    },
                ]
            }
        ]
        monkeypatch.setattr("rebrew.toolchain_detect._run_diec", lambda *a, **k: dets)
        info = detect_with_die(Path("x.exe"))
        assert info is not None
        assert info.family == "msvc"
        assert info.confidence == "high"
        assert info.version_hint == "MSVC 6.0"
        assert info.detected_by == "die"

    def test_delphi_detection(self, monkeypatch) -> None:
        dets = [
            {
                "values": [
                    {
                        "type": "Compiler",
                        "name": "Borland Delphi",
                        "version": "2",
                        "string": "Compiler: Borland Delphi(2)",
                    }
                ]
            }
        ]
        monkeypatch.setattr("rebrew.toolchain_detect._run_diec", lambda *a, **k: dets)
        info = detect_with_die(Path("x.exe"))
        assert info is not None
        assert info.family == "delphi"

    def test_no_signature_stays_unknown(self, monkeypatch) -> None:
        dets = [
            {"values": [{"type": "Heur", "name": "Debug data", "string": "Debug data: Contains"}]}
        ]
        monkeypatch.setattr("rebrew.toolchain_detect._run_diec", lambda *a, **k: dets)
        info = detect_with_die(Path("x.exe"))
        assert info is not None
        assert info.family == "unknown"


class TestDetectWithPdb:
    def _mock_pdbutil(self, monkeypatch, output: str, modules: str = "") -> None:
        monkeypatch.setattr(
            "shutil.which", lambda name: "/usr/bin/llvm-pdbutil" if name == "llvm-pdbutil" else None
        )
        monkeypatch.setattr(
            "pathlib.Path.exists", lambda self: str(self).endswith(".pdb"), raising=False
        )

        def _fake_run(cmd: list[str], **kwargs: object) -> SimpleNamespace:
            if "-modules" in cmd:
                return SimpleNamespace(returncode=0, stdout=modules, stderr="")
            return SimpleNamespace(returncode=0, stdout=output, stderr="")

        monkeypatch.setattr("rebrew.toolchain_detect.subprocess.run", _fake_run)

    def test_zig_pdb(self, monkeypatch, tmp_path: Path) -> None:
        self._mock_pdbutil(
            monkeypatch,
            "S_COMPILE3 [size = 132]\n frontend = 20.1.2.0, backend = 20012.0.0.0\n flags = none\n",
            modules="/home/user/.zig-cache/o/abc/prog.obj",
        )
        info = detect_with_pdb(tmp_path / "prog.exe")
        assert info is not None
        assert info.family == "zig"

    def test_msvc_pdb_with_flags(self, monkeypatch, tmp_path: Path) -> None:
        self._mock_pdbutil(
            monkeypatch,
            "S_COMPILE3 [size = 200]\n frontend = 14.00.24210, backend = 14.00.24210\n flags = /O1 /MT /Gd\n",
        )
        info = detect_with_pdb(tmp_path / "prog.exe")
        assert info is not None
        assert info.family == "msvc"
        assert "/O1" in info.flags
        assert "/MT" in info.flags

    def test_no_pdb_returns_none(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.setattr("shutil.which", lambda name: None)
        assert detect_with_pdb(tmp_path / "prog.exe") is None


class TestOrchestration:
    def test_die_wins_over_heuristics(self, monkeypatch, tmp_path: Path) -> None:
        """When DIE identifies the family, heuristics don't override it."""
        dets = [
            {
                "values": [
                    {
                        "type": "Compiler",
                        "name": "Borland Delphi",
                        "version": "2",
                        "string": "Compiler: Borland Delphi(2)",
                    }
                ]
            }
        ]
        monkeypatch.setattr("rebrew.toolchain_detect._run_diec", lambda *a, **k: dets)
        monkeypatch.setattr("rebrew.toolchain_detect.detect_with_pdb", lambda *a, **k: None)

        # fake binary parse: write a minimal file; load_binary will fail,
        # but DIE already decided the family so heuristics are not needed
        exe = tmp_path / "prog.exe"
        exe.write_bytes(b"MZ" + b"\x00" * 128)
        monkeypatch.setattr(
            "rebrew.toolchain_detect.load_binary",
            lambda *a, **k: (_ for _ in ()).throw(Exception("no parse")),
        )
        info = detect_toolchain(exe)
        assert info.family == "delphi"
        assert info.detected_by == "die"

    def test_die_watcom_compiler(self, monkeypatch) -> None:
        dets = [
            {
                "values": [
                    {
                        "type": "Compiler",
                        "name": "Watcom C/C++",
                        "version": "11.0",
                        "string": "Compiler: Watcom C/C++(11.0)[C]",
                    }
                ]
            }
        ]
        monkeypatch.setattr("rebrew.toolchain_detect._run_diec", lambda *a, **k: dets)
        info = detect_with_die(Path("x.exe"))
        assert info.family == "watcom"
        assert "Watcom C/C++" in info.version_hint

    def test_die_borlandc_compiler(self, monkeypatch) -> None:
        dets = [
            {
                "values": [
                    {
                        "type": "Compiler",
                        "name": "Borland C++",
                        "version": "5.5",
                        "string": "Compiler: Borland C++(5.5)[C]",
                    }
                ]
            }
        ]
        monkeypatch.setattr("rebrew.toolchain_detect._run_diec", lambda *a, **k: dets)
        info = detect_with_die(Path("x.exe"))
        assert info.family == "borlandc"


class _FakeSection:
    def __init__(self, name: str) -> None:
        self.name = name


def _fake_binary(
    sections: list[str],
    dlls: list[str] | None = None,
    text: bytes = b"",
) -> SimpleNamespace:
    """A BinaryInfo-shaped fake for the heuristics backend.

    *text* becomes the .text payload (text_va=0x1000, text_size=len(text))
    so the codegen/fingerprint scan has bytes to count.
    """
    return SimpleNamespace(
        sections={n: _FakeSection(n) for n in sections},
        imports=[SimpleNamespace(dll=d) for d in (dlls or [])],
        text_va=0x1000 if text else 0,
        text_size=len(text),
        data=text,
    )


class TestHeuristicsFamilies:
    def test_watcom_sections_and_strings(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.setattr("rebrew.toolchain_detect._run_diec", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.toolchain_detect.detect_with_pdb", lambda *a, **k: None)
        monkeypatch.setattr(
            "rebrew.toolchain_detect.load_binary",
            lambda *a, **k: _fake_binary(["_TEXT", "_DATA", "_BSS"]),
        )
        monkeypatch.setattr(
            "rebrew.toolchain_detect._scan_strings", lambda *a, **k: ["Open Watcom C/C++"]
        )
        info = detect_toolchain(tmp_path / "prog.exe")
        assert info.family == "watcom"
        assert info.confidence == "high"
        assert info.detected_by == "heuristics"

    def test_watcom_sections_without_strings(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.setattr("rebrew.toolchain_detect._run_diec", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.toolchain_detect.detect_with_pdb", lambda *a, **k: None)
        monkeypatch.setattr(
            "rebrew.toolchain_detect.load_binary",
            lambda *a, **k: _fake_binary(["_TEXT", "_DATA"]),
        )
        monkeypatch.setattr("rebrew.toolchain_detect._scan_strings", lambda *a, **k: [])
        info = detect_toolchain(tmp_path / "prog.exe")
        assert info.family == "watcom"
        assert info.confidence == "medium"

    def test_borlandc_runtime_imports(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.setattr("rebrew.toolchain_detect._run_diec", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.toolchain_detect.detect_with_pdb", lambda *a, **k: None)
        # CODE/DATA/BSS without Delphi strings + a C++Builder runtime import.
        monkeypatch.setattr(
            "rebrew.toolchain_detect.load_binary",
            lambda *a, **k: _fake_binary(["CODE", "DATA", "BSS"], dlls=["CW32.DLL"]),
        )
        monkeypatch.setattr("rebrew.toolchain_detect._scan_strings", lambda *a, **k: [])
        info = detect_toolchain(tmp_path / "prog.exe")
        assert info.family == "borlandc"
        assert info.confidence == "medium"

    def test_borlandc_strings_without_delphi(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.setattr("rebrew.toolchain_detect._run_diec", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.toolchain_detect.detect_with_pdb", lambda *a, **k: None)
        monkeypatch.setattr(
            "rebrew.toolchain_detect.load_binary",
            lambda *a, **k: _fake_binary(["CODE", "DATA", "BSS"], dlls=["KERNEL32.dll"]),
        )
        monkeypatch.setattr(
            "rebrew.toolchain_detect._scan_strings", lambda *a, **k: ["Borland C++ Runtime Library"]
        )
        info = detect_toolchain(tmp_path / "prog.exe")
        assert info.family == "borlandc"
        assert info.confidence == "high"

    def test_borland_sections_without_any_strings_stays_unknown(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr("rebrew.toolchain_detect._run_diec", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.toolchain_detect.detect_with_pdb", lambda *a, **k: None)
        monkeypatch.setattr(
            "rebrew.toolchain_detect.load_binary",
            lambda *a, **k: _fake_binary(["CODE", "DATA", "BSS"], dlls=["KERNEL32.dll"]),
        )
        monkeypatch.setattr("rebrew.toolchain_detect._scan_strings", lambda *a, **k: [])
        info = detect_toolchain(tmp_path / "prog.exe")
        assert info.family == "unknown"

    def test_symantec_strings_detected(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.setattr("rebrew.toolchain_detect._run_diec", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.toolchain_detect.detect_with_pdb", lambda *a, **k: None)
        monkeypatch.setattr(
            "rebrew.toolchain_detect.load_binary",
            lambda *a, **k: _fake_binary(["CODE", "DATA"]),
        )
        monkeypatch.setattr(
            "rebrew.toolchain_detect._scan_strings",
            lambda *a, **k: ["Symantec C++ Runtime"],
        )
        info = detect_toolchain(tmp_path / "prog.exe")
        assert info.family == "symantec"
        assert info.confidence == "medium"


class TestNEStringDetection:
    """16-bit NE binaries (unparseable by load_binary) are identified from
    their embedded strings — e.g. the Borland Delphi 1.0 card game family."""

    def test_ne_delphi_detected_from_strings(self, tmp_path: Path) -> None:
        from rebrew.toolchain_detect import detect_toolchain

        # Minimal MZ+NE header + the Delphi copyright string far into the file
        # (beyond _scan_strings' 256-string cap — exercises the byte scan).
        ne = tmp_path / "game.ne"
        data = bytearray(0x4000)
        data[0:2] = b"MZ"
        data[0x3C:0x40] = (0x100).to_bytes(4, "little")
        data[0x100:0x102] = b"NE"
        data[0x2000 : 0x2000 + 16] = b"Borland Delphi"
        ne.write_bytes(bytes(data))

        info = detect_toolchain(ne)
        assert info.family == "delphi"
        assert info.confidence == "medium"
        assert any("Borland Delphi" in e for e in info.evidence)

    def test_ne_without_delphi_stays_unknown(self, tmp_path: Path) -> None:
        from rebrew.toolchain_detect import detect_toolchain

        ne = tmp_path / "plain.ne"
        data = bytearray(0x200)
        data[0:2] = b"MZ"
        data[0x3C:0x40] = (0x100).to_bytes(4, "little")
        data[0x100:0x102] = b"NE"
        data[0x120:0x130] = b"just a 16-bit app"
        ne.write_bytes(bytes(data))

        info = detect_toolchain(ne)
        assert info.family == "unknown"

    def test_ne_borland_markers_detected(self, tmp_path: Path, monkeypatch) -> None:
        """A real Borland NE (segments prefixed ``[index\\x00][name]``) is
        identified from its segment markers — the 16-bit holiday.exe path."""
        from rebrew.toolchain_detect import detect_toolchain

        ne = tmp_path / "app.ne"
        data = bytearray(0x4000)
        data[0:2] = b"MZ"
        data[0x3C:0x40] = (0x100).to_bytes(4, "little")
        data[0x100:0x102] = b"NE"
        # One segment: [index=1][\x00][name="UNIT"][code]
        seg = bytes([1, 0, 4]) + b"UNIT" + bytes.fromhex("55 8b ec 5d c3")
        data[0x200 : 0x200 + len(seg)] = seg
        data[0x11C:0x11E] = (1).to_bytes(2, "little")  # segment count
        data[0x132:0x134] = (4).to_bytes(2, "little")  # sector shift
        data[0x122:0x124] = (0x40).to_bytes(2, "little")  # segment table offset
        data[0x140:0x148] = (
            (0x20).to_bytes(2, "little")  # sector offset of segment data
            + (len(seg)).to_bytes(2, "little")  # length
            + (1).to_bytes(2, "little")  # flags (code)
            + (len(seg)).to_bytes(2, "little")  # minimum allocation
        )
        ne.write_bytes(bytes(data))

        monkeypatch.setattr("rebrew.toolchain_detect._scan_strings", lambda *a, **k: [])
        info = detect_toolchain(ne)
        assert info.family == "delphi"
        assert info.confidence == "high"
        assert "segment markers" in info.version_hint

    def test_ne_markerless_with_segments_is_msvc(self, tmp_path: Path, monkeypatch) -> None:
        """A markerless NE with real segment content (the 16-bit MSVC path —
        e.g. the original 1991 SkiFree) is reported as MSVC-style."""
        from rebrew.toolchain_detect import detect_toolchain

        ne = tmp_path / "app.ne"
        data = bytearray(0x4000)
        data[0:2] = b"MZ"
        data[0x3C:0x40] = (0x100).to_bytes(4, "little")
        data[0x100:0x102] = b"NE"
        seg = bytes.fromhex("1e 58 90 45 55 8b ec 83 ec 02 5d c3")  # MSVC 16-bit entry
        data[0x200 : 0x200 + len(seg)] = seg
        data[0x11C:0x11E] = (1).to_bytes(2, "little")  # segment count
        data[0x132:0x134] = (4).to_bytes(2, "little")  # sector shift
        data[0x122:0x124] = (0x40).to_bytes(2, "little")  # segment table offset
        data[0x140:0x148] = (
            (0x20).to_bytes(2, "little")
            + (len(seg)).to_bytes(2, "little")
            + (1).to_bytes(2, "little")
            + (len(seg)).to_bytes(2, "little")
        )
        ne.write_bytes(bytes(data))

        monkeypatch.setattr("rebrew.toolchain_detect._scan_strings", lambda *a, **k: [])
        info = detect_toolchain(ne)
        assert info.family == "msvc"
        assert "MSVC" in info.version_hint

    def test_16bit_ne_rejects_32bit_profile(self) -> None:
        """skifree16 regression: msvc6 (32-bit) on a 16-bit NE binary must
        NOT pass alignment — every function would be COMPILE_ERROR."""
        info = ToolchainInfo(family="msvc", arch="x86_16")
        aligned, expl = profile_matches_detection("msvc6", info)
        assert aligned is False
        assert "msvc1.52" in (expl or "")

    def test_16bit_ne_accepts_msvc152(self) -> None:
        info = ToolchainInfo(family="msvc", arch="x86_16")
        aligned, _ = profile_matches_detection("msvc1.52", info)
        assert aligned is True

    def test_32bit_pe_rejects_msvc152(self) -> None:
        """msvc1.52 is a 16-bit compiler — it cannot match a 32-bit PE."""
        info = ToolchainInfo(family="msvc", arch="x86_32")
        aligned, expl = profile_matches_detection("msvc1.52", info)
        assert aligned is False
        assert "msvc6" in (expl or "")

    def test_unknown_arch_not_second_guessed(self) -> None:
        """PE/ELF detection does not set arch — existing projects must not
        start failing doctor after this change."""
        info = ToolchainInfo(family="msvc", arch="")
        aligned, _ = profile_matches_detection("msvc6", info)
        assert aligned is True

    def test_watcom_32bit_not_rejected(self) -> None:
        """watcom's wcc386 is a 32-bit compiler — a detected Watcom 32-bit
        binary must pass alignment (regression: watcom was wrongly in the
        16-bit-only set, false-failing doctor on Watcom PE targets)."""
        info = ToolchainInfo(family="watcom", arch="x86_32")
        aligned, expl = profile_matches_detection("watcom", info)
        assert aligned is True, expl

    def test_watcom_unknown_arch_not_rejected(self) -> None:
        info = ToolchainInfo(family="watcom", arch="")
        aligned, expl = profile_matches_detection("watcom", info)
        assert aligned is True, expl


class TestCrtLinkage:
    """CRT-linkage detection from PE imports (msvcrt.dll -> /MD)."""

    _MSVC_DETS = [
        {
            "values": [
                {
                    "type": "Compiler",
                    "name": "Microsoft Visual C/C++",
                    "version": "11.00",
                    "string": "Compiler: Microsoft Visual C/C++(11.00)",
                }
            ]
        }
    ]

    def _detect(self, monkeypatch, tmp_path: Path, dlls: list[str]) -> ToolchainInfo:
        monkeypatch.setattr("rebrew.toolchain_detect._run_diec", lambda *a, **k: self._MSVC_DETS)
        monkeypatch.setattr("rebrew.toolchain_detect.detect_with_pdb", lambda *a, **k: None)
        monkeypatch.setattr(
            "rebrew.toolchain_detect.load_binary",
            lambda *a, **k: _fake_binary([".text", ".data", ".rdata"], dlls=dlls),
        )
        monkeypatch.setattr("rebrew.toolchain_detect._scan_strings", lambda *a, **k: [])
        return detect_toolchain(tmp_path / "prog.exe")

    def test_dynamic_crt_msvcrt(self, monkeypatch, tmp_path: Path) -> None:
        info = self._detect(monkeypatch, tmp_path, ["msvcrt.dll", "KERNEL32.dll", "USER32.dll"])
        assert info.crt == "msvcrt.dll"
        assert info.crt_linkage == "dynamic"
        assert info.base_cflags == "/MD"

    def test_dynamic_crt_crtdll(self, monkeypatch, tmp_path: Path) -> None:
        info = self._detect(monkeypatch, tmp_path, ["crtdll.dll", "KERNEL32.dll"])
        assert info.crt == "crtdll.dll"
        assert info.crt_linkage == "dynamic"
        assert info.base_cflags == "/MD"

    def test_static_crt_libcmt(self, monkeypatch, tmp_path: Path) -> None:
        info = self._detect(monkeypatch, tmp_path, ["KERNEL32.dll", "USER32.dll"])
        assert info.crt == "LIBCMT"
        assert info.crt_linkage == "static"
        assert info.base_cflags == "/MT"

    def test_minimal_imports_no_crt_claim(self, monkeypatch, tmp_path: Path) -> None:
        info = self._detect(monkeypatch, tmp_path, ["KERNEL32.dll"])
        assert info.crt == ""
        assert info.crt_linkage == ""

    def test_standalone_no_crt_claim(self, monkeypatch, tmp_path: Path) -> None:
        info = self._detect(monkeypatch, tmp_path, [])
        assert info.crt == ""
        assert info.base_cflags == ""


class TestOptLevelFingerprint:
    """detect_toolchain must infer MSVC /O1 vs /O2 from wrapper codegen and
    flag genuinely mixed (per-file /O) builds — a project-wide flag cannot be
    right for those."""

    @staticmethod
    def _msvc_die() -> ToolchainInfo:
        return ToolchainInfo(family="msvc", confidence="high", detected_by="die")

    def _run(self, monkeypatch: object, text_bytes: bytes) -> ToolchainInfo:
        import rebrew.toolchain_detect as td

        monkeypatch.setattr(td, "_run_diec", lambda *a, **k: None)
        monkeypatch.setattr(td, "detect_with_pdb", lambda *a, **k: None)
        monkeypatch.setattr(td, "detect_with_die", lambda *a, **k: self._msvc_die())
        monkeypatch.setattr(
            td, "load_binary", lambda *a, **k: _fake_binary([".text"], text=text_bytes)
        )
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_bytes_at_va",
            lambda binfo, va, size: text_bytes[:size],
        )
        from rebrew.toolchain_detect import detect_toolchain

        return detect_toolchain(Path("/tmp/nonexistent-prog.exe"))

    def test_o2_style(self, monkeypatch: object, tmp_path: Path) -> None:
        wrapper = bytes.fromhex("8b 44 24 04 50 e8 00 00 00 00 83 c4 04 c3")
        info = self._run(monkeypatch, wrapper * 6)
        assert info.opt_level == "/O2"

    def test_o1_style(self, monkeypatch: object, tmp_path: Path) -> None:
        wrapper = bytes.fromhex("ff 74 24 04 e8 00 00 00 00 59 c3")
        info = self._run(monkeypatch, wrapper * 6)
        assert info.opt_level == "/O1"

    def test_mixed_flags(self, monkeypatch: object, tmp_path: Path) -> None:
        o1 = bytes.fromhex("ff 74 24 04 e8 00 00 00 00 59 c3")
        o2 = bytes.fromhex("8b 44 24 04 50 e8 00 00 00 00 83 c4 04 c3")
        info = self._run(monkeypatch, (o1 + o2) * 4)
        assert info.opt_level.startswith("mixed")

    def test_no_wrapper_evidence_inconclusive(self, monkeypatch: object, tmp_path: Path) -> None:
        info = self._run(monkeypatch, b"\x55\x8b\xec" * 10)
        assert info.opt_level == ""

    def test_non_msvc_skips_fingerprint(self, monkeypatch: object, tmp_path: Path) -> None:
        import rebrew.toolchain_detect as td

        monkeypatch.setattr(td, "_run_diec", lambda *a, **k: None)
        monkeypatch.setattr(td, "detect_with_pdb", lambda *a, **k: None)
        monkeypatch.setattr(
            td, "detect_with_die", lambda *a, **k: ToolchainInfo(family="mingw", confidence="high")
        )
        monkeypatch.setattr(td, "load_binary", lambda *a, **k: _fake_binary([".text"]))
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_bytes_at_va",
            lambda binfo, va, size: bytes.fromhex("ff 74 24 04 e8") * 6,
        )
        info = detect_toolchain(Path("/tmp/nonexistent-prog.exe"))
        assert info.opt_level == ""


class TestBackendDisplayName:
    """User-facing backend names — doctor/analyze must not leak the internal
    ids ("die" for diec, "pdb", "heuristics")."""

    def test_known_backends(self) -> None:
        from rebrew.toolchain_detect import backend_display_name

        assert "diec" in backend_display_name("die")
        assert backend_display_name("pdb") == "PDB"
        assert "heuristics" in backend_display_name("heuristics")

    def test_unknown_backend_passthrough(self) -> None:
        from rebrew.toolchain_detect import backend_display_name

        assert backend_display_name("mystery") == "mystery"
        assert backend_display_name("") == ""


class TestBorlandAndWatcomProfileCompat:
    """borlandc/watcom families now have byte-matchable profiles."""

    def test_tc16_matches_borlandc(self) -> None:
        info = ToolchainInfo(family="borlandc")
        aligned, expl = profile_matches_detection("tc16", info)
        assert aligned is True
        assert expl is None

    def test_borlandc55_matches_borlandc(self) -> None:
        info = ToolchainInfo(family="borlandc")
        aligned, _ = profile_matches_detection("borlandc55", info)
        assert aligned is True

    def test_watcom16_matches_watcom(self) -> None:
        info = ToolchainInfo(family="watcom")
        aligned, _ = profile_matches_detection("watcom16", info)
        assert aligned is True


class TestTc16BuiltBinary:
    """A real Turbo C++ 3.1 + TLINK-built DOS executable (built under
    DOSBox with the vendored toolchain) must detect as borlandc and align
    with the tc16/borlandc55 profiles."""

    def test_detect_tc16_binary(self) -> None:
        from rebrew.toolchain_detect import detect_toolchain, profile_matches_detection

        binary = Path(__file__).parent / "fixtures" / "tc16_hello.exe"
        if not binary.exists():
            import pytest

            pytest.skip("tc16_hello.exe fixture not present")
        info = detect_toolchain(str(binary))
        assert info.family == "borlandc"
        assert "Borland" in (info.version_hint or "")
        assert info.arch == "x86_16"  # an MZ binary is always 16-bit
        aligned, _ = profile_matches_detection("tc16", info)
        assert aligned is True
        # borlandc55 is the 32-bit bcc32 — it cannot byte-match a 16-bit
        # binary (the arch dimension rejects it), while tc16 can.
        aligned, _ = profile_matches_detection("borlandc55", info)
        assert aligned is False
        aligned, _ = profile_matches_detection("msvc6", info)
        assert aligned is False

    def test_detect_lzexe_packed(self) -> None:
        """An LZEXE-packed MZ reports the packer and warns to unpack first —
        the family must not be misread from the decompressor stub."""
        from rebrew.toolchain_detect import detect_toolchain

        packed = Path(__file__).parent / "fixtures" / "tc16_hello_lzexe.exe"
        if not packed.exists():
            import pytest

            pytest.skip("tc16_hello_lzexe.exe fixture not present")
        info = detect_toolchain(str(packed))
        assert info.packed == "lzexe 0.91"
        assert any("packed with LZEXE" in e for e in info.evidence)

    def test_detect_pklite_packed(self) -> None:
        """A PKLITE-compressed MZ reports the packer (its stub carries the
        PKWARE banner near the header) so the family is not trusted blindly."""
        from rebrew.toolchain_detect import detect_toolchain

        packed = Path(__file__).parent / "fixtures" / "tc16_hello_pklite.exe"
        if not packed.exists():
            import pytest

            pytest.skip("tc16_hello_pklite.exe fixture not present")
        info = detect_toolchain(str(packed))
        assert info.packed == "pklite"
        assert any("PKLITE" in e for e in info.evidence)
