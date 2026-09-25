"""Tests for gen_layout.py / link_sweep.py pure helpers (no docker).

gen_layout's import-lib grep and link_sweep's link loop need the toolchain
image; the PE parser, def/import emitters, option derivation, candidate
enumeration, and header reader are pure and pinned here against the
checked-in mini PE fixture.
"""

import struct
from pathlib import Path

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st

from rebrew.gen_layout import (
    _resolve_imports,
    gen_crt_imports,
    gen_def,
)
from rebrew.pe_image import derive_link_options, parse_pe

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
        _, _, _, pe = parse_pe(_FIXTURE.read_bytes())
        pe["stack_reserve"] = 0
        opts, toml = derive_link_options(pe)
        assert any(o.startswith("/STACK:0x0,") for o in opts)
        assert 'stack_reserve = "0x0"' in toml

    def test_ordinal_only_import_does_not_break_crt_imports(self) -> None:
        """An ordinal-only import (no name) must carry the ``include`` key so
        gen_crt_imports' ``imp["include"]`` does not raise KeyError."""
        from rebrew.pe_image import _Import

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
        from rebrew.pe_image import _Import

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


class TestImportLibSymbolsFromImage:
    """The in-image grep script, run by the host ``sh`` against a temp dir."""

    @staticmethod
    def _run_locally(monkeypatch: pytest.MonkeyPatch, lib_dir: Path) -> list[list[str]]:
        import subprocess

        seen: list[list[str]] = []
        real_run = subprocess.run

        def fake_run(cmd: list[str], **kwargs: object) -> object:
            seen.append(cmd)
            i = cmd.index("-c")
            # Same script and argv, with the image's Lib dir swapped for lib_dir.
            local = ["sh", "-c", cmd[i + 1], cmd[i + 2], str(lib_dir), *cmd[i + 4 :]]
            return real_run(local, **kwargs)  # type: ignore[call-overload]

        monkeypatch.setattr(subprocess, "run", fake_run)
        return seen

    def test_matches_lib_name_case_insensitively(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.gen_layout import _import_lib_symbols_from_image

        (tmp_path / "Kernel32.Lib").write_bytes(b"!<arch>\n\0__imp__Sleep@4\0junk")
        self._run_locally(monkeypatch, tmp_path)
        assert _import_lib_symbols_from_image("kernel32") == {"__imp__Sleep@4"}

    def test_hostile_stem_is_data_not_script(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.gen_layout import _import_lib_symbols_from_image

        marker = tmp_path / "pwned"
        seen = self._run_locally(monkeypatch, tmp_path)
        assert _import_lib_symbols_from_image(f"x; touch {marker}; #") == set()
        assert not marker.exists()
        assert "touch" not in seen[0][seen[0].index("-c") + 1]


# ---------------------------------------------------------------------------
# Hypothesis fuzz — pe_image.parse_pe on untrusted PE bytes
# ---------------------------------------------------------------------------


def _short_optional_header() -> bytes:
    """PE32 whose file ends inside a 2-byte optional header.

    SizeOfOptionalHeader claims those two bytes, so the declared-header
    check used to pass and the image-base read raised ``struct.error``.
    """
    e = 0x40
    opt = e + 24
    optsz = 2
    data = bytearray(opt + optsz)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, e)
    data[e : e + 4] = b"PE\x00\x00"
    struct.pack_into("<H", data, e + 6, 0)
    struct.pack_into("<H", data, e + 20, optsz)
    struct.pack_into("<H", data, opt, 0x10B)
    return bytes(data)


def _deep_pe() -> bytes:
    """PE32 with .text/.data/.rdata, one named export, and two imports.

    A real shape (section table, export directory, import descriptors), not
    a zero-filled header: the export and import walks have something to read.
    """
    e = 0x40
    opt = e + 24
    optsz = 0xE0
    nsec = 3
    sh = opt + optsz
    raw = 0x200
    size = raw + 3 * raw
    data = bytearray(size)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, e)
    data[e : e + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, e + 4, 0x14C, nsec, 0, 0, 0, optsz, 0x0102)
    struct.pack_into("<H", data, opt, 0x10B)
    struct.pack_into("<I", data, opt + 28, 0x400000)  # image base
    # export directory at .rdata; import directory after the export tables
    struct.pack_into("<II", data, opt + 96, 0x3000, 0x40)
    struct.pack_into("<II", data, opt + 104, 0x3080, 0x28)

    def section(index: int, name: bytes, va: int, chars: int) -> None:
        off = sh + 40 * index
        struct.pack_into(
            "<8sIIIIIIHHI",
            data,
            off,
            name,
            raw,
            va,
            raw,
            raw + index * raw,
            0,
            0,
            0,
            0,
            chars,
        )

    section(0, b".text\x00\x00\x00", 0x1000, 0x60000020)
    section(1, b".data\x00\x00\x00", 0x2000, 0xC0000040)
    section(2, b".rdata\x00\x00", 0x3000, 0x40000040)

    # .rdata file offset is 0x600.  Export directory, then tables, then a name.
    exp = 0x600
    struct.pack_into("<I", data, exp + 16, 1)  # ordinal base
    struct.pack_into("<I", data, exp + 20, 2)  # NumberOfFunctions
    struct.pack_into("<I", data, exp + 24, 1)  # NumberOfNames
    struct.pack_into("<I", data, exp + 28, 0x3040)  # AddressOfFunctions
    struct.pack_into("<I", data, exp + 32, 0x3048)  # AddressOfNames
    struct.pack_into("<I", data, exp + 36, 0x304C)  # AddressOfNameOrdinals
    struct.pack_into("<II", data, 0x640, 0x1000, 0x1100)  # function RVAs
    struct.pack_into("<I", data, 0x648, 0x3052)  # name RVA
    struct.pack_into("<H", data, 0x64C, 0)  # name ordinal index
    data[0x652:0x656] = b"Foo\x00"

    # Import descriptor at RVA 0x3080 → file 0x680.  The lookup table, DLL
    # name, and hint/name sit after the descriptor array so they do not
    # overwrite the null terminator.
    struct.pack_into("<IIIII", data, 0x680, 0x30C0, 0, 0, 0x30E0, 0x30C0)
    struct.pack_into("<I", data, 0x6C0, 0x8000002A)  # ordinal 42
    struct.pack_into("<I", data, 0x6C4, 0x3100)  # hint/name RVA
    data[0x6E0:0x6EC] = b"KERNEL32.dll\x00"
    data[0x700:0x70D] = b"\x00\x00ExitProcess\x00"
    return bytes(data)


def test_deep_pe_sample_agrees_across_parsers() -> None:
    """A PE with a real export and import table parses to those entries.

    ``pe_image.parse_pe`` and ``layout_meta.extract_layout`` both walk the
    tables; the sample is the seed that makes the walks reach a name, an
    ordinal, and a forwarder-sized export directory.
    """
    from rebrew.layout_meta import extract_layout

    blob = _deep_pe()
    sections, exports, imports, pe = parse_pe(blob)
    assert [s.name for s in sections] == [".text", ".data", ".rdata"]
    assert pe["image_base"] == 0x400000
    assert exports == [
        {"name": "Foo", "ordinal": 1, "va": 0x401000},
        {"name": None, "ordinal": 2, "va": 0x401100},
    ]
    assert [(i.dll, i.name, i.ordinal) for i in imports] == [
        ("KERNEL32.dll", None, 42),
        ("KERNEL32.dll", "ExitProcess", None),
    ]
    meta = extract_layout(blob, "sample.dll")
    assert meta.exports == exports
    assert [(i.dll, i.name, i.ordinal) for i in meta.imports] == [
        ("KERNEL32.dll", None, 42),
        ("KERNEL32.dll", "ExitProcess", None),
    ]


@st.composite
def _pe_shaped(draw: st.DrawFn) -> bytes:
    """MZ/PE image whose header dimensions and length are drawn.

    Pure random bytes almost never carry an MZ stub plus a PE signature, so
    they never enter the export or import walks.  Drawing e_lfanew, the
    section count, SizeOfOptionalHeader, and a file that may end before the
    fields those claim, does.
    """
    e = draw(st.integers(min_value=0x40, max_value=0x80))
    nsec = draw(st.integers(min_value=0, max_value=4))
    optsz = draw(st.integers(min_value=0, max_value=0x120))
    slack = draw(st.integers(min_value=-80, max_value=96))
    declared = e + 24 + optsz + 40 * nsec
    length = max(0, min(declared + slack, 512))
    blob = bytearray(draw(st.binary(min_size=length, max_size=length)))
    if len(blob) >= 2:
        blob[0:2] = b"MZ"
    if len(blob) >= 0x40:
        struct.pack_into("<I", blob, 0x3C, e)
    if e + 4 <= len(blob):
        blob[e : e + 4] = b"PE\x00\x00"
    if e + 8 <= len(blob):
        struct.pack_into("<H", blob, e + 6, nsec)
    if e + 22 <= len(blob):
        struct.pack_into("<H", blob, e + 20, optsz)
    opt = e + 24
    if draw(st.booleans()) and opt + 2 <= len(blob):
        struct.pack_into("<H", blob, opt, 0x10B)
    if draw(st.booleans()):
        sh = opt + optsz
        for index, name in enumerate(
            (b".text\x00\x00\x00", b".data\x00\x00\x00", b".rdata\x00\x00")
        ):
            off = sh + 40 * index
            if index < nsec and off + 8 <= len(blob):
                blob[off : off + 8] = name
    return bytes(blob)


def _assert_parsed(
    blob: bytes,
    sections: list[object],
    exports: list[dict[str, object]],
    imports: list[object],
    pe: dict[str, object],
) -> None:
    """Invariants of a successful ``parse_pe``, checked against the header parser."""
    from rebrew.layout_meta import parse_pe as parse_header
    from rebrew.pe_headers import sections_at
    from rebrew.pe_image import _MAX_EXPORT_ENTRIES, _Import, _Section

    e, nsec, optsz, opt, image_base = parse_header(blob)
    assert pe["e_lfanew"] == e
    assert pe["image_base"] == image_base
    assert pe["header_size"] == e + 4 + 20 + optsz + nsec * 40
    raw = sections_at(blob, opt + optsz, nsec)
    assert len(sections) == len(raw) == nsec
    for got, src in zip(sections, raw, strict=True):
        assert isinstance(got, _Section)
        assert got.name == src.name
        assert got.va == src.virtual_address
        assert got.vs == src.virtual_size
        assert got.raw_size == src.size_of_raw_data
        assert got.raw_ptr == src.pointer_to_raw_data
        assert got.characteristics == src.characteristics
    assert len(exports) <= _MAX_EXPORT_ENTRIES
    previous = -1
    for ex in exports:
        assert isinstance(ex["name"], str) or ex["name"] is None
        ordinal = ex["ordinal"]
        va = ex["va"]
        assert isinstance(ordinal, int)
        assert isinstance(va, int)
        assert ordinal > previous
        previous = ordinal
        assert va - image_base != 0
    for imp in imports:
        assert isinstance(imp, _Import)
        assert imp.dll
        assert imp.name is None or isinstance(imp.name, str)
        assert imp.ordinal is None or 0 <= imp.ordinal <= 0xFFFF
        if imp.ordinal is not None:
            assert imp.name is None
    for key in (
        "time_date_stamp",
        "checksum",
        "size_of_image",
        "machine",
        "characteristics",
        "section_alignment",
        "file_alignment",
        "subsystem",
        "dll_characteristics",
        "stack_reserve",
        "stack_commit",
        "heap_reserve",
        "heap_commit",
        "reloc_rva",
        "reloc_size",
    ):
        value = pe[key]
        assert isinstance(value, int) and value >= 0
    assert pe["reloc_va"] is None or isinstance(pe["reloc_va"], int)


def _exercise_parse_pe(blob: bytes) -> None:
    """``parse_pe`` returns a checked result or raises ``ValueError`` only."""
    try:
        sections, exports, imports, pe = parse_pe(blob)
    except ValueError:
        return
    _assert_parsed(blob, sections, exports, imports, pe)


@settings(max_examples=60, deadline=None)
@given(_pe_shaped())
@example(_short_optional_header())
@example(_deep_pe())
@example(_FIXTURE.read_bytes())
def test_parse_pe_shaped_bytes_hold_invariants(blob: bytes) -> None:
    """Header dimensions that reach the export and import walks stay well-typed.

    A short optional header must be ``ValueError``, matching ``main``'s
    handler.  A parsed image must agree with ``layout_meta.parse_pe`` and
    ``sections_at`` on the fields both read out of the same bytes.
    """
    _exercise_parse_pe(blob)
