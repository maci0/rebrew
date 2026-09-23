"""Per-version PE-metadata detection tests (Rich header / linker version)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from rebrew.toolchain_detect import (
    _MSVC_LINKER_VERSIONS,
    _MSVCP_IMPORT_VERSIONS,
    _RICH_BUILD_PROFILES,
    ToolchainInfo,
    _is_16bit_target,
    _msvc_version_hint,
    detect_with_pe_meta,
    profile_matches_detection,
    suggest_profile,
)


def _fake_pe(linker: str, rich_builds: list[int] | None = None, imports: list[str] | None = None):
    """A minimal lief.PE stand-in: optional header + rich header + imports."""
    major, minor = linker.split(".")
    oh = SimpleNamespace(major_linker_version=int(major), minor_linker_version=int(minor))
    entries = [SimpleNamespace(build_id=b) for b in (rich_builds or [])]
    rich = SimpleNamespace(entries=entries) if rich_builds else None
    imps = [SimpleNamespace(name=n) for n in (imports or [])]
    return SimpleNamespace(
        optional_header=oh,
        rich_header=rich,
        imports=imps,
    )


class TestVersionTables:
    def test_linker_ladder(self) -> None:
        assert _MSVC_LINKER_VERSIONS["2.50"] == (9, 0)
        assert _MSVC_LINKER_VERSIONS["4.20"] == (10, 20)
        assert _MSVC_LINKER_VERSIONS["6.0"] == (12, 0)
        assert _MSVC_LINKER_VERSIONS["7.10"] == (13, 10)
        assert _MSVC_LINKER_VERSIONS["10.0"] == (16, 0)

    def test_rich_build_profiles_sp_levels(self) -> None:
        """The VC 6.0 SP builds are distinct compilers in the Rich header.
        (Empirically dumped from the rebrew images: 8168 RTM, 8447 SP3,
        8966 SP5, 9782 SP6.)"""
        # 8168 is the C1 build for VC6 RTM through SP2 (SP3 bumped it to
        # 8447) — every profile carrying that build can byte-match.
        assert "msvc-6.0" in _RICH_BUILD_PROFILES[8168]
        assert "msvc-6.0-sp3" not in _RICH_BUILD_PROFILES[8168]
        assert _RICH_BUILD_PROFILES[8447] == ("msvc-6.0-sp3",)
        # 8966 is shared by VC6 SP4 and SP5 (SP4 shipped the 8966 C1;
        # SP5 kept it) - both can byte-match.
        assert "msvc-6.0-sp5" in _RICH_BUILD_PROFILES[8966]
        assert _RICH_BUILD_PROFILES[9782] == ("msvc-6.0-sp6",)
        assert 9466 in _RICH_BUILD_PROFILES and _RICH_BUILD_PROFILES[9466] == (
            "msvc-7.0-rtm",
            "msvc-7.0-sp1",
        )
        assert _RICH_BUILD_PROFILES[21022] == ("msvc-9.0",)

    def test_msvcp_import_binder(self) -> None:
        assert _MSVCP_IMPORT_VERSIONS["msvcp71.dll"] == "7.1"
        assert _MSVCP_IMPORT_VERSIONS["msvcp100.dll"] == "10.0"


class TestMsvcVersionHint:
    def test_with_profiles(self) -> None:
        assert (
            _msvc_version_hint("12.00.8168", ("msvc-6.0",))
            == "MSVC 6.0 (cl 12.00.8168) — matches msvc-6.0"
        )

    def test_without_profiles(self) -> None:
        assert _msvc_version_hint("9.00", None) == "MSVC 9.00"
        assert (
            _msvc_version_hint("11.00.0", ("msvc-5.0",))
            == "MSVC 5.0 (cl 11.00.0) — matches msvc-5.0"
        )


class TestDetectWithPeMeta:
    def test_rich_header_pins_exact_version(self, monkeypatch) -> None:
        """linker 6.0 + C1 8168 -> MSVC 6.0 12.00.8168 (family proven)."""
        monkeypatch.setattr("rebrew.toolchain_detect.lief.parse", lambda p: _fake_pe("6.0", [8168]))
        info = detect_with_pe_meta(Path("x.exe"))
        assert info is not None
        assert info.family == "msvc"
        assert info.confidence == "high"
        assert info.msvc_version == "12.00.8168"
        assert "msvc-6.0" in info.suggested_profiles

    def test_sp6_rich_build(self, monkeypatch) -> None:
        monkeypatch.setattr("rebrew.toolchain_detect.lief.parse", lambda p: _fake_pe("6.0", [9782]))
        info = detect_with_pe_meta(Path("x.exe"))
        assert info.msvc_version == "12.00.9782"
        assert info.suggested_profiles == ["msvc-6.0-sp6"]

    def test_rich_mode_picks_compiler_pair_over_newer_linker(self, monkeypatch) -> None:
        """Rich entries [8168, 8168, 9782] = C1/C2 pair at 8168 plus a
        newer linker build (9782).  The compiler's build is the MODE,
        not the max, so this pins msvc-6.0, not msvc-6.0-sp6."""
        monkeypatch.setattr(
            "rebrew.toolchain_detect.lief.parse",
            lambda p: _fake_pe("6.0", [8168, 8168, 9782]),
        )
        info = detect_with_pe_meta(Path("x.exe"))
        assert info is not None
        assert info.msvc_version == "12.00.8168"
        assert "msvc-6.0" in info.suggested_profiles

    def test_rich_mode_pair_wins_over_single_other(self, monkeypatch) -> None:
        """[9782, 8168, 8168] (order-insensitive): still msvc-6.0."""
        monkeypatch.setattr(
            "rebrew.toolchain_detect.lief.parse",
            lambda p: _fake_pe("6.0", [9782, 8168, 8168]),
        )
        info = detect_with_pe_meta(Path("x.exe"))
        assert info.msvc_version == "12.00.8168"

    def test_no_rich_header_linker_names_era(self, monkeypatch) -> None:
        """VC 4.2: no Rich header, linker 4.20 -> 10.20 msvc-4.2."""
        monkeypatch.setattr("rebrew.toolchain_detect.lief.parse", lambda p: _fake_pe("4.20"))
        info = detect_with_pe_meta(Path("x.exe"))
        assert info.family == "msvc"
        assert info.msvc_version == "10.20"
        assert "msvc-4.2" in info.suggested_profiles

    def test_ambiguous_2x_does_not_force_family(self, monkeypatch) -> None:
        """A bare 2.50 linker could be MinGW GNU ld — evidence only."""
        monkeypatch.setattr("rebrew.toolchain_detect.lief.parse", lambda p: _fake_pe("2.50"))
        info = detect_with_pe_meta(Path("x.exe"))
        assert info.family == "unknown"
        assert info.msvc_version == "9.00"
        assert info.suggested_profiles == ["msvc-2.0"]

    def test_msvcp_import_binder_without_rich(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "rebrew.toolchain_detect.lief.parse", lambda p: _fake_pe("0.0", imports=["msvcp71.dll"])
        )
        info = detect_with_pe_meta(Path("x.exe"))
        assert info.family == "msvc"
        assert info.msvc_version == "7.1"

    def test_unknown_rich_build_falls_back_to_linker_era(self, monkeypatch) -> None:
        """An unrecognized Rich build (e.g. a hotfix like 11.00.9049) still
        suggests the linker-era family instead of the generic default."""
        monkeypatch.setattr(
            "rebrew.toolchain_detect.lief.parse", lambda p: _fake_pe("5.12", [9049])
        )
        info = detect_with_pe_meta(Path("x.exe"))
        assert info.msvc_version == "11.00.9049"
        assert "msvc-5.0" in info.suggested_profiles

    def test_non_msvc_linker_returns_none(self, monkeypatch) -> None:
        monkeypatch.setattr("rebrew.toolchain_detect.lief.parse", lambda p: _fake_pe("2.34"))
        assert detect_with_pe_meta(Path("x.exe")) is None

    def test_unparseable_returns_none(self, monkeypatch) -> None:
        monkeypatch.setattr("rebrew.toolchain_detect.lief.parse", lambda p: None)
        assert detect_with_pe_meta(Path("x.exe")) is None


class TestProfileMatchingVersionExact:
    def _info(
        self, version: str = "12.00.9782", profiles: list[str] | None = None
    ) -> ToolchainInfo:
        info = ToolchainInfo(family="msvc", confidence="high", msvc_version=version)
        info.suggested_profiles = profiles or []
        return info

    def test_exact_profile_aligns(self) -> None:
        ok, why = profile_matches_detection("msvc-6.0-sp6", self._info(profiles=["msvc-6.0-sp6"]))
        assert ok is True and why is None

    def test_wrong_version_profile_flags(self) -> None:
        ok, why = profile_matches_detection("msvc-6.0", self._info(profiles=["msvc-6.0-sp6"]))
        assert ok is False
        assert "12.00.9782" in (why or "")
        assert "msvc-6.0-sp6" in (why or "")

    def test_no_version_info_no_flag(self) -> None:
        ok, _ = profile_matches_detection("msvc-6.0", self._info(profiles=[]))
        assert ok is True


class TestSuggestProfileVersionExact:
    def test_prefers_version_exact(self, tmp_path: Path) -> None:
        info = ToolchainInfo(family="msvc", confidence="high", msvc_version="12.00.9782")
        info.suggested_profiles = ["msvc-6.0-sp6"]
        assert suggest_profile(info, tmp_path) == "msvc-6.0-sp6"

    def test_falls_back_to_family_default(self, tmp_path: Path) -> None:
        info = ToolchainInfo(family="msvc", confidence="high")
        assert suggest_profile(info, tmp_path) == "msvc-6.0"

    def test_16bit_honors_version_exact(self, tmp_path: Path) -> None:
        """A 16-bit target with version-exact evidence (e.g. msvc-1.5 from a
        plugin detector) suggests that profile, not the msvc-1.52 default."""
        info = ToolchainInfo(family="msvc", confidence="high", arch="x86_16")
        info.suggested_profiles = ["msvc-1.5", "msvc-1.0"]
        assert suggest_profile(info, None) == "msvc-1.5"
        borland = ToolchainInfo(family="borlandc", confidence="high", arch="x86_16")
        borland.suggested_profiles = ["borland-2.0", "borland-3.1"]
        assert suggest_profile(borland, None) == "borland-2.0"

    def test_16bit_ignores_32bit_suggestion(self, tmp_path: Path) -> None:
        """A 32-bit suggestion on a 16-bit binary can never byte-match — the
        16-bit default wins instead."""
        info = ToolchainInfo(family="msvc", confidence="high", arch="x86_16")
        info.suggested_profiles = ["msvc-6.0"]
        assert suggest_profile(info, None) == "msvc-1.52"

    def test_32bit_ignores_16bit_suggestion(self, tmp_path: Path) -> None:
        info = ToolchainInfo(family="msvc", confidence="high", arch="x86_32")
        info.suggested_profiles = ["msvc-1.52"]
        assert suggest_profile(info, None) == "msvc-6.0"


class TestIs16bitTarget:
    def _write(self, tmp_path: Path, body: bytes) -> Path:
        p = tmp_path / "bin"
        p.write_bytes(body)
        return p

    def test_plain_pe_is_not_16bit(self, tmp_path: Path) -> None:
        # MZ header + e_lfanew -> "PE\0\0"
        mz = bytearray(b"MZ" + b"\x00" * 0x3A)
        mz += (0x40).to_bytes(4, "little")
        mz += b"\x00" * (0x40 - len(mz))
        mz += b"PE\x00\x00"
        info = ToolchainInfo(family="msvc", arch="x86_32")
        assert _is_16bit_target(info, self._write(tmp_path, bytes(mz))) is False

    def test_plain_dos_mz_is_16bit(self, tmp_path: Path) -> None:
        info = ToolchainInfo(family="unknown")
        assert _is_16bit_target(info, self._write(tmp_path, b"MZ" + b"\x00" * 30)) is True

    def test_arch_x86_16_is_16bit(self, tmp_path: Path) -> None:
        info = ToolchainInfo(family="msvc", arch="x86_16")
        assert _is_16bit_target(info, self._write(tmp_path, b"not-mz")) is True


class TestCodeGeneratorFamily:
    """The VC6 code generator (Processor Pack vs plain), read from game code.

    Every VC6 service pack ships the same cl.exe (12.00.8804) but the
    Processor Pack replaces c2.dll, which rewrites the x87 compare idiom:
    pack code emits `fnstsw ax; test ah,0x44; jp` / `test ah,5`, plain code
    emits `test ah,0x40` / `test ah,0x01`.  A profile check that only compares
    compiler versions accepts the wrong generator silently.
    """

    PP = bytes.fromhex("d9 45 08 d8 5d 08 df e0 f6 c4 44 7a 05")
    PLAIN = bytes.fromhex("d9 45 08 d8 5d 08 df e0 f6 c4 40 75 05")
    PLAIN_01 = bytes.fromhex("d9 45 08 d8 5d 08 df e0 f6 c4 01 75 05")
    # A bare strength-reduced integer test — NOT a compare idiom.
    INTEGER_TEST = bytes.fromhex("a9 00 40 00 00 f6 c4 40 74 05")

    def test_family_classification(self) -> None:
        from rebrew.toolchain_detect import (
            CodegenSignals,
            x87_codegen_family,
        )

        assert x87_codegen_family(CodegenSignals(pp_compares=3)) == "processor-pack"
        assert x87_codegen_family(CodegenSignals(plain_compares=3)) == "plain"
        assert x87_codegen_family(CodegenSignals(pp_compares=1, plain_compares=1)) == "mixed"
        assert x87_codegen_family(CodegenSignals()) == "unknown"

    def test_signal_counter_needs_the_fnstsw_prefix(self) -> None:
        from rebrew.toolchain_detect import _count_codegen_signals

        assert _count_codegen_signals(self.PP).pp_compares == 1
        assert _count_codegen_signals(self.PLAIN).plain_compares == 1
        assert _count_codegen_signals(self.PLAIN_01).plain_compares == 1
        # `f6 c4 40` alone (integer test eax,0x4000 strength reduction) is not
        # a compare and must not be counted.
        assert _count_codegen_signals(self.INTEGER_TEST).plain_compares == 0
        assert _count_codegen_signals(self.INTEGER_TEST).pp_compares == 0

    def test_excluded_band_is_not_counted(self) -> None:
        """Library bands compiled by Microsoft must not decide the family."""
        from rebrew.toolchain_detect import _count_codegen_signals

        base = 0x5E0000
        text = b"\x90" * 0x100 + self.PLAIN + b"\x90" * 0x100 + self.PP
        signals = _count_codegen_signals(text, base, [(base, base + 0x1FF)])
        assert signals.plain_compares == 0  # inside the excluded library band
        assert signals.pp_compares == 1  # game code, outside it

    def test_processor_pack_profiles_come_from_the_registry(self) -> None:
        from rebrew.toolchain_detect import processor_pack_profiles

        assert "msvc-6.0-sp5-pp" in processor_pack_profiles()

    def test_pack_profile_is_family_compatible(self) -> None:
        """A correctly configured pack project must not be reported misaligned."""
        from rebrew.toolchain_detect import _PROFILE_COMPAT

        assert "msvc-6.0-sp5-pp" in (_PROFILE_COMPAT["msvc"] or set())

    def _info(self, codegen: str) -> ToolchainInfo:
        info = ToolchainInfo(family="msvc", codegen=codegen, msvc_version="12.00.8804")
        info.suggested_profiles = ["msvc-6.0-sp6", "msvc-6.0-sp5-pp"]
        return info

    def test_pack_binary_rejects_a_plain_profile(self) -> None:
        ok, why = profile_matches_detection("msvc-6.0-sp6", self._info("processor-pack"))
        assert not ok
        assert why is not None and "Processor-Pack" in why
        assert "msvc-6.0-sp5-pp" in why

    def test_plain_binary_rejects_the_pack_profile(self) -> None:
        ok, why = profile_matches_detection("msvc-6.0-sp5-pp", self._info("plain"))
        assert not ok
        assert why is not None and "plain VC6" in why

    def test_matching_families_align(self) -> None:
        assert profile_matches_detection("msvc-6.0-sp5-pp", self._info("processor-pack"))[0]
        assert profile_matches_detection("msvc-6.0-sp6", self._info("plain"))[0]

    def test_unknown_codegen_never_blocks(self) -> None:
        assert profile_matches_detection("msvc-6.0-sp6", self._info(""))[0]
        assert profile_matches_detection("msvc-6.0-sp5-pp", self._info("mixed"))[0]
