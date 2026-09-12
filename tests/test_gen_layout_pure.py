"""Tests for gen_layout.py / link_sweep.py pure helpers (no docker).

gen_layout's import-lib grep and link_sweep's link loop need the toolchain
image; the PE parser, def/import emitters, option derivation, candidate
enumeration, and header reader are pure and pinned here against the
checked-in mini PE fixture.
"""

from pathlib import Path

import pytest

from rebrew.gen_layout import (
    _resolve_imports,
    derive_link_options,
    gen_crt_imports,
    gen_def,
    parse_pe,
)

_FIXTURE = Path(__file__).parent / "fixtures" / "mini_pe.exe"


class TestParsePe:
    def test_truncated_section_table_raises_valueerror(self) -> None:
        """An unhandled struct.error would escape main's ``except ValueError``
        as a raw traceback; the twin parser already raises ValueError here."""
        import struct

        d = bytearray(0x200)
        d[0:2] = b"MZ"
        struct.pack_into("<I", d, 0x3C, 0x80)
        d[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<H", d, 0x80 + 6, 2)  # NumberOfSections
        struct.pack_into("<H", d, 0x80 + 20, 0xE0)  # SizeOfOptionalHeader
        opt = 0x80 + 24
        struct.pack_into("<H", d, opt, 0x10B)  # PE32 magic
        with pytest.raises(ValueError, match="truncated section table"):
            parse_pe(bytes(d[: opt + 0xE0]))

    def test_zero_stack_reserve_is_not_treated_as_absent(self) -> None:
        """A reference whose SizeOfStackReserve is 0 is a real value, not a
        missing one: the option (and toml key) must still be derived."""
        import struct as _struct  # noqa: F401  (fixture is binary; kept for clarity)

        _, _, _, pe = parse_pe(_FIXTURE.read_bytes())
        pe["stack_reserve"] = 0
        opts, toml = derive_link_options(pe)
        assert any(o.startswith("/STACK:0x0,") for o in opts)
        assert 'stack_reserve = "0x0"' in toml

    def test_ordinal_only_import_does_not_break_crt_imports(self) -> None:
        """An ordinal-only import (no name) must carry the ``include`` key so
        gen_crt_imports' ``imp["include"]`` does not raise KeyError."""
        from rebrew.gen_layout import _Import

        resolved = _resolve_imports([_Import("SHELL32.dll", None, 42)], set())
        assert resolved[0]["include"] is None
        text = gen_crt_imports("T", resolved, 0x2000)
        assert "ordinal 42 of SHELL32.dll" in text

    def test_sections_and_imports(self) -> None:
        sections, exports, imports, pe = parse_pe(_FIXTURE.read_bytes())
        assert [s.name for s in sections] == [".text"]
        assert exports == []
        assert len(imports) == 1
        assert pe["image_base"] == 0x400000

    def test_rejects_non_pe(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="PE"):
            parse_pe(b"\x00" * 64)


class TestEmitters:
    def test_gen_def(self) -> None:
        text = gen_def("game.dll", [{"name": "Init", "ordinal": 1, "va": 0x1000}])
        assert text == "LIBRARY game\nEXPORTS\n    Init @1\n"

    def test_gen_crt_imports(self) -> None:
        text = gen_crt_imports(
            "T",
            [
                {
                    "dll": "KERNEL32.dll",
                    "name": "ExitProcess",
                    "ordinal": None,
                    "include": "__imp__ExitProcess@4",
                }
            ],
            0x2000,
        )
        assert '#pragma comment(linker, "/include:__imp__ExitProcess@4")' in text
        assert "0x2000" in text

    def test_resolve_imports_unknown_suffix(self) -> None:
        from rebrew.gen_layout import _Import

        out = _resolve_imports([_Import("KERNEL32.dll", "Nope", None)], set())
        assert out[0]["include"] is None


class TestDeriveLinkOptions:
    def test_mini_pe_delta_is_subsystem_only(self) -> None:
        _, _, _, pe = parse_pe(_FIXTURE.read_bytes())
        opts, toml = derive_link_options(pe)
        assert opts == ["/SUBSYSTEM:CONSOLE"]
        assert 'timestamp = "0x0"' in toml


class TestLinkSweepHelpers:
    def test_read_fields(self) -> None:
        from rebrew.link_sweep import _read_fields

        fields = _read_fields(_FIXTURE)
        assert fields["Machine"] == 0x14C
        assert fields["NumberOfSections"] == 1
        assert fields["ImageBase"] == 0x400000

    def test_read_fields_reads_minor_versions(self, tmp_path: Path) -> None:
        """OSVersion/SubsystemVersion pack ``major<<8 | minor``; the minor byte
        lives at opt+42 / opt+50 (opt+41 / opt+49 are the major's always-zero
        high byte, so a minor delta was invisible)."""
        import struct

        from rebrew.link_sweep import _read_fields

        d = bytearray(0x200)
        d[0:2] = b"MZ"
        struct.pack_into("<I", d, 0x3C, 0x80)
        d[0x80:0x84] = b"PE\x00\x00"
        opt = 0x80 + 4 + 20
        struct.pack_into("<H", d, opt + 40, 4)  # MajorOperatingSystemVersion
        struct.pack_into("<H", d, opt + 42, 10)  # MinorOperatingSystemVersion
        struct.pack_into("<H", d, opt + 48, 4)  # MajorSubsystemVersion
        struct.pack_into("<H", d, opt + 50, 10)  # MinorSubsystemVersion
        p = tmp_path / "v.exe"
        p.write_bytes(bytes(d))

        fields = _read_fields(p)
        assert fields["OSVersion"] == 0x040A
        assert fields["SubsystemVersion"] == 0x040A

    def test_candidates_cover_alignment_probes(self) -> None:
        from rebrew.link_sweep import _candidates

        _, _, _, pe = parse_pe(_FIXTURE.read_bytes())
        names = [c.name for c in _candidates(pe)]
        assert names[0] == "base"
        assert "align_0x1000" in names
        assert "merge_rdata" in names


class TestOftZeroFallback:
    def test_oft_zero_falls_back_to_iat(self) -> None:
        """A descriptor with OFT == 0 (unbound) carries its names in the IAT.
        Reading only the OFT made the DLL's imports disappear, so the emitted
        crt_imports.c lost its /include pragmas (and layout_config_dict wrote an
        empty `imports` list)."""
        import struct

        data = bytearray(_FIXTURE.read_bytes())
        e = struct.unpack_from("<I", data, 0x3C)[0]
        opt = e + 24
        optsz = struct.unpack_from("<H", data, e + 20)[0]
        sh = opt + optsz
        sec_va = struct.unpack_from("<I", data, sh + 12)[0]
        sec_raw = struct.unpack_from("<I", data, sh + 20)[0]
        imp_rva = struct.unpack_from("<I", data, opt + 96 + 8)[0]
        desc_off = sec_raw + (imp_rva - sec_va)
        assert parse_pe(bytes(data))[2]  # fixture sanity: the OFT is bound
        struct.pack_into("<I", data, desc_off, 0)  # OFT = 0
        assert parse_pe(bytes(data))[2]
