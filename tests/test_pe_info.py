"""Tests for rebrew.pe_info: payload shape, sections, security, CLI, fallbacks."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import lief
import pytest
from typer.testing import CliRunner

import rebrew.main
from rebrew.pe_info import (
    _debug_entries,
    _rich_header,
    _security_flags,
    pe_info,
)

FIXTURES = Path(__file__).parent / "fixtures"
MINI_PE = FIXTURES / "mini_pe.exe"
MINI_ELF = FIXTURES / "mini.elf"

runner = CliRunner()

# mini_pe.exe geometry (image base 0x400000, one .text at RVA 0x1000).
MINI_PE_IMAGE_BASE = 0x400000
MINI_PE_TEXT_VA = 0x1000
MINI_PE_TEXT_VSIZE = 113
MINI_PE_TEXT_RAW_SIZE = 512
MINI_PE_TEXT_RAW_OFFSET = 512


def _fake_pe(**overrides: object) -> SimpleNamespace:
    """A duck-typed PE stand-in: pe_info guards every attribute access."""
    base: dict[str, object] = {
        "header": SimpleNamespace(time_date_stamps=0),
        "optional_header": SimpleNamespace(
            imagebase=MINI_PE_IMAGE_BASE,
            addressof_entrypoint=0x1000,
            subsystem=lief.PE.OptionalHeader.SUBSYSTEM.WINDOWS_CUI,
            checksum=0,
            magic=lief.PE.PE_TYPE.PE32,
            dll_characteristics=0,
        ),
        "sections": [],
        "data_directories": [],
        "signatures": [],
        "debug": [],
        "exported_functions": [],
        "imports": [],
        "relocations": [],
        "rich_header": None,
        "has_rich_header": False,
        "has_configuration": False,
        "load_configuration": None,
        "has_tls": False,
        "has_resources": False,
        "has_relocations": False,
        "has_exports": False,
        "has_imports": False,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class TestPayloadShape:
    def test_top_level_keys(self) -> None:
        info = pe_info(MINI_PE)
        assert set(info) == {
            "format",
            "arch",
            "bits",
            "image_base",
            "entry_point",
            "subsystem",
            "timestamp",
            "checksum",
            "size",
            "sections",
            "security_flags",
            "flags_summary",
            "authenticode",
            "debug",
            "rich_header",
            "presence",
            "counts",
        }

    def test_identity_values(self) -> None:
        info = pe_info(MINI_PE)
        assert info["format"] == "pe"
        assert info["arch"] == "x86_32"
        assert info["bits"] == 32
        assert info["image_base"] == MINI_PE_IMAGE_BASE
        assert info["entry_point"] == MINI_PE_IMAGE_BASE + MINI_PE_TEXT_VA
        assert info["subsystem"] == "WINDOWS_CUI"
        assert info["size"] == MINI_PE.stat().st_size

    def test_json_serializable(self) -> None:
        json.dumps(pe_info(MINI_PE))

    def test_deterministic_two_runs(self) -> None:
        first = json.dumps(pe_info(MINI_PE), sort_keys=True)
        second = json.dumps(pe_info(MINI_PE), sort_keys=True)
        assert first == second


class TestSections:
    def test_section_list_and_keys(self) -> None:
        sections = pe_info(MINI_PE)["sections"]
        assert isinstance(sections, list)
        assert sections
        assert set(sections[0]) == {
            "name",
            "virtual_address",
            "virtual_size",
            "raw_size",
            "raw_offset",
            "read",
            "write",
            "execute",
        }

    def test_text_protection_is_read_execute(self) -> None:
        section = pe_info(MINI_PE)["sections"][0]
        assert section["name"] == ".text"
        assert section["read"] is True
        assert section["write"] is False
        assert section["execute"] is True

    def test_text_geometry(self) -> None:
        section = pe_info(MINI_PE)["sections"][0]
        assert section["virtual_address"] == MINI_PE_TEXT_VA
        assert section["virtual_size"] == MINI_PE_TEXT_VSIZE
        assert section["raw_size"] == MINI_PE_TEXT_RAW_SIZE
        assert section["raw_offset"] == MINI_PE_TEXT_RAW_OFFSET


class TestSecurityFlags:
    def test_keys_and_types(self) -> None:
        flags = pe_info(MINI_PE)["security_flags"]
        assert set(flags) == {
            "dll_characteristics",
            "aslr",
            "nx",
            "cfg",
            "gs",
            "safe_seh",
            "seh",
            "high_entropy_va",
            "force_integrity",
            "isolation",
            "certificate_table",
        }
        for key, value in flags.items():
            if key != "dll_characteristics":
                assert isinstance(value, bool), key
        assert isinstance(flags["dll_characteristics"], int)

    def test_raw_dll_characteristics_roundtrips(self) -> None:
        # mini_pe has DllCharacteristics 0; the raw value is still reported.
        assert pe_info(MINI_PE)["security_flags"]["dll_characteristics"] == 0

    def test_flags_summary_only_enabled(self) -> None:
        info = pe_info(MINI_PE)
        summary = info["flags_summary"]
        assert isinstance(summary, list)
        flags = info["security_flags"]
        assert ("ASLR" in summary) is bool(flags["aslr"])
        assert ("DEP" in summary) is bool(flags["nx"])

    def test_dllcharacteristics_bits_map_to_flags(self) -> None:
        dllc = 0x0040 | 0x0100 | 0x4000  # DYNAMIC_BASE | NX_COMPAT | GUARD_CF
        flags = _security_flags(
            _fake_pe(
                optional_header=SimpleNamespace(dll_characteristics=dllc),
                has_configuration=False,
                load_configuration=None,
            )
        )
        assert flags["dll_characteristics"] == dllc
        assert flags["aslr"] is True
        assert flags["nx"] is True
        assert flags["cfg"] is True
        assert flags["gs"] is False
        assert flags["safe_seh"] is False

    def test_no_seh_and_no_isolation_bits(self) -> None:
        dllc = 0x0400 | 0x0200  # NO_SEH | NO_ISOLATION
        flags = _security_flags(
            _fake_pe(
                optional_header=SimpleNamespace(dll_characteristics=dllc),
                has_configuration=False,
                load_configuration=None,
            )
        )
        assert flags["seh"] is False
        assert flags["isolation"] is False

    def test_gs_and_safe_seh_from_load_config(self) -> None:
        config = SimpleNamespace(security_cookie=0x40B000, se_handler_table=0x40C000)
        flags = _security_flags(_fake_pe(has_configuration=True, load_configuration=config))
        assert flags["gs"] is True
        assert flags["safe_seh"] is True

    def test_certificate_table_false_without_directory(self) -> None:
        assert pe_info(MINI_PE)["security_flags"]["certificate_table"] is False


class TestNonPe:
    def test_elf_identity(self) -> None:
        info = pe_info(MINI_ELF)
        assert info["format"] == "elf"
        assert info["arch"] == "x86_32"
        assert info["bits"] == 32
        assert info["image_base"] == 0x400000
        assert info["entry_point"] == 0x401000
        assert info["size"] == MINI_ELF.stat().st_size

    def test_elf_note_mentions_pe_only(self) -> None:
        note = pe_info(MINI_ELF)["note"]
        assert isinstance(note, str)
        assert "PE-only" in note

    def test_elf_omits_pe_only_blocks(self) -> None:
        info = pe_info(MINI_ELF)
        for key in ("sections", "security_flags", "debug", "rich_header", "presence"):
            assert key not in info


class TestRichHeader:
    def test_absent_on_mini_pe(self) -> None:
        rich = pe_info(MINI_PE)["rich_header"]
        assert rich == {"present": False}

    def test_key_and_entries_reported(self) -> None:
        rich = SimpleNamespace(
            key=0x1234,
            entries=[SimpleNamespace(id=1, build_id=2090, count=3)],
        )
        payload = _rich_header(_fake_pe(rich_header=rich, has_rich_header=True))
        assert payload == {
            "present": True,
            "key": 0x1234,
            "entries": [{"id": 1, "build_id": 2090, "count": 3}],
        }

    def test_entries_omitted_when_unexposed(self) -> None:
        rich = SimpleNamespace(key=0x99)
        payload = _rich_header(_fake_pe(rich_header=rich, has_rich_header=True))
        assert payload == {"present": True, "key": 0x99}
        assert "entries" not in payload


class TestDebug:
    def test_empty_on_mini_pe(self) -> None:
        assert pe_info(MINI_PE)["debug"] == []

    def test_codeview_fields_reported(self) -> None:
        entry = SimpleNamespace(
            type=lief.PE.Debug.TYPES.CODEVIEW,
            pdb_path="C:\\src\\notepad.pdb",
            guid=list(range(16)),
            age=7,
        )
        payload = _debug_entries(_fake_pe(debug=[entry]))
        assert payload == [
            {
                "type": "CODEVIEW",
                "pdb_path": "C:\\src\\notepad.pdb",
                "guid": "000102030405060708090a0b0c0d0e0f",
                "age": 7,
            }
        ]

    def test_missing_codeview_attribute_omitted(self) -> None:
        entry = SimpleNamespace(type=lief.PE.Debug.TYPES.CODEVIEW)
        assert _debug_entries(_fake_pe(debug=[entry])) == [{"type": "CODEVIEW"}]


class TestPresence:
    def test_presence_flags_on_mini_pe(self) -> None:
        presence = pe_info(MINI_PE)["presence"]
        assert presence == {
            "tls_directory": False,
            "load_config": False,
            "resources": False,
            "relocations": False,
            "exports": False,
            "imports": True,
        }

    def test_counts_on_mini_pe(self) -> None:
        counts = pe_info(MINI_PE)["counts"]
        assert counts["exports"] == 0
        assert counts["import_dlls"] == 1
        assert counts["imports"] >= 1


class TestAuthenticode:
    def test_unsigned_shape(self) -> None:
        auth = pe_info(MINI_PE)["authenticode"]
        assert auth == {"present": False, "signature_count": 0, "signers": []}


class TestErrors:
    def test_missing_file_raises_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            pe_info(tmp_path / "absent.exe")

    def test_unsupported_format_raises_value_error(self, tmp_path: Path) -> None:
        path = tmp_path / "notes.txt"
        path.write_text("not a binary", encoding="utf-8")
        with pytest.raises(ValueError):
            pe_info(path)

    def test_truncated_pe_does_not_crash(self, tmp_path: Path) -> None:
        path = tmp_path / "truncated.exe"
        path.write_bytes(MINI_PE.read_bytes()[:600])
        try:
            info = pe_info(path)
        except ValueError:
            return
        assert info["format"] == "pe"

    def test_header_only_pe_raises_value_error(self, tmp_path: Path) -> None:
        path = tmp_path / "stub.exe"
        path.write_bytes(MINI_PE.read_bytes()[:200])
        with pytest.raises(ValueError):
            pe_info(path)


class TestPeInfoCli:
    def test_json_output(self) -> None:
        result = runner.invoke(rebrew.main.app, ["pe-info", str(MINI_PE), "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["format"] == "pe"
        assert payload["sections"][0]["name"] == ".text"

    def test_human_output(self) -> None:
        result = runner.invoke(rebrew.main.app, ["pe-info", str(MINI_PE)])
        assert result.exit_code == 0
        assert "Sections" in result.output
        assert ".text" in result.output
        assert "Security flags" in result.output

    def test_missing_binary_exits_two(self, tmp_path: Path) -> None:
        result = runner.invoke(rebrew.main.app, ["pe-info", str(tmp_path / "absent.exe"), "--json"])
        assert result.exit_code == 2
        payload = json.loads(result.stdout)
        assert "error" in payload

    def test_unsupported_binary_exits_two(self, tmp_path: Path) -> None:
        path = tmp_path / "notes.txt"
        path.write_text("not a binary", encoding="utf-8")
        result = runner.invoke(rebrew.main.app, ["pe-info", str(path), "--json"])
        assert result.exit_code == 2
        payload = json.loads(result.stdout)
        assert "error" in payload
