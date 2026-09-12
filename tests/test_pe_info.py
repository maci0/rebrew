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
    _exports,
    _pe_type,
    _resource_count,
    _rich_header,
    _section_characteristic_names,
    _section_entropy,
    _security,
    _security_flags,
    _security_score,
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
            "type",
            "image_base",
            "entry_point",
            "subsystem",
            "timestamp",
            "checksum",
            "size",
            "sections",
            "security_flags",
            "security",
            "security_score",
            "flags_summary",
            "exports",
            "export_count",
            "resource_count",
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
        assert info["type"] == "exe"
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


class TestPeType:
    def test_dll_bit_wins(self) -> None:
        header = SimpleNamespace(characteristics=0x0002 | 0x2000)
        assert _pe_type(header) == "dll"

    def test_executable_image_is_exe(self) -> None:
        assert _pe_type(SimpleNamespace(characteristics=0x0002)) == "exe"

    def test_neither_bit_is_unknown(self) -> None:
        assert _pe_type(SimpleNamespace(characteristics=0x0100)) is None

    def test_missing_characteristics_is_unknown(self) -> None:
        assert _pe_type(SimpleNamespace()) is None


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
            "entropy",
            "characteristics_value",
            "characteristics",
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

    def test_characteristics_names_and_raw_value(self) -> None:
        section = pe_info(MINI_PE)["sections"][0]
        assert section["characteristics_value"] == 0x60000020
        assert section["characteristics"] == [
            "IMAGE_SCN_CNT_CODE",
            "IMAGE_SCN_MEM_EXECUTE",
            "IMAGE_SCN_MEM_READ",
        ]

    def test_entropy_is_bits_per_byte(self) -> None:
        entropy = pe_info(MINI_PE)["sections"][0]["entropy"]
        assert isinstance(entropy, float)
        assert 0.0 <= entropy <= 8.0

    def test_align_nibble_named(self) -> None:
        assert _section_characteristic_names(0x00300000) == ["IMAGE_SCN_ALIGN_4BYTES"]
        assert _section_characteristic_names(0x80000000) == ["IMAGE_SCN_MEM_WRITE"]

    def test_unknown_bits_are_ignored(self) -> None:
        assert _section_characteristic_names(0x00000001) == []

    def test_entropy_none_for_unusable_value(self) -> None:
        assert _section_entropy(SimpleNamespace(entropy=None)) is None
        assert _section_entropy(SimpleNamespace(entropy=float("nan"))) is None
        assert _section_entropy(SimpleNamespace()) is None
        assert _section_entropy(SimpleNamespace(entropy=6.0)) == 6.0


class TestExports:
    def test_missing_get_export_is_empty(self) -> None:
        assert _exports(_fake_pe()) == []

    def test_export_entry_va_is_absolute(self) -> None:
        entry = SimpleNamespace(name="Exported", address=0x1234, ordinal=7, is_forwarded=False)
        pe = _fake_pe(get_export=lambda: SimpleNamespace(entries=[entry]))
        assert _exports(pe) == [
            {"name": "Exported", "va": MINI_PE_IMAGE_BASE + 0x1234, "ordinal": 7, "forwarder": None}
        ]

    def test_forwarder_kept_with_target_and_null_va(self) -> None:
        info = SimpleNamespace(library="NTDLL", function="RtlFoo")
        entry = SimpleNamespace(
            name="Foo",
            address=0,
            ordinal=3,
            is_forwarded=True,
            forward_information=info,
        )
        pe = _fake_pe(get_export=lambda: SimpleNamespace(entries=[entry]))
        assert _exports(pe) == [
            {"name": "Foo", "va": None, "ordinal": 3, "forwarder": "NTDLL.RtlFoo"}
        ]

    def test_ordinal_only_export_keeps_empty_name(self) -> None:
        entry = SimpleNamespace(name="", address=0x20, ordinal=1, is_forwarded=False)
        pe = _fake_pe(get_export=lambda: SimpleNamespace(entries=[entry]))
        assert _exports(pe)[0]["name"] == ""
        assert _exports(pe)[0]["ordinal"] == 1

    def test_forwarder_without_target_keeps_record(self) -> None:
        entry = SimpleNamespace(name="Foo", address=0, ordinal=3, is_forwarded=True)
        pe = _fake_pe(get_export=lambda: SimpleNamespace(entries=[entry]))
        assert _exports(pe) == [{"name": "Foo", "va": None, "ordinal": 3, "forwarder": None}]

    def test_export_count_on_mini_pe(self) -> None:
        info = pe_info(MINI_PE)
        assert info["exports"] == []
        assert info["export_count"] == 0


class TestResourceCount:
    def test_absent_resources_is_zero(self) -> None:
        assert _resource_count(_fake_pe()) == 0

    def test_leaf_nodes_are_counted(self) -> None:
        leaf = SimpleNamespace(name="icon")
        directory = SimpleNamespace(childs=[leaf, leaf])
        root = SimpleNamespace(childs=[directory])
        assert _resource_count(SimpleNamespace(resources=root)) == 2

    def test_empty_directory_is_not_a_resource(self) -> None:
        assert _resource_count(SimpleNamespace(resources=SimpleNamespace(childs=[]))) == 0

    def test_mini_pe_has_no_resources(self) -> None:
        assert pe_info(MINI_PE)["resource_count"] == 0


class TestSecurityChecklist:
    def test_eleven_items_in_portal_order(self) -> None:
        checklist = _security(_fake_pe())
        assert list(checklist) == [
            "aslr",
            "dep",
            "cfg",
            "driver_model",
            "app_container",
            "terminal_server_aware",
            "image_isolation",
            "code_integrity",
            "high_entropy",
            "seh",
            "bound_image",
        ]

    def test_each_item_carries_enabled_and_flag(self) -> None:
        for item in _security(_fake_pe()).values():
            assert set(item) == {"enabled", "flag", "flag_name"}

    def test_dllc_bits_map_to_items(self) -> None:
        dllc = 0x0040 | 0x0100 | 0x4000 | 0x1000 | 0x2000 | 0x8000 | 0x0080 | 0x0020
        checklist = _security(_fake_pe(optional_header=SimpleNamespace(dll_characteristics=dllc)))
        for key in (
            "aslr",
            "dep",
            "cfg",
            "driver_model",
            "app_container",
            "terminal_server_aware",
            "code_integrity",
            "high_entropy",
        ):
            assert checklist[key]["enabled"] is True, key

    def test_inverted_bits_disable_the_item(self) -> None:
        dllc = 0x0400 | 0x0200  # NO_SEH | NO_ISOLATION
        checklist = _security(_fake_pe(optional_header=SimpleNamespace(dll_characteristics=dllc)))
        assert checklist["seh"]["enabled"] is False
        assert checklist["image_isolation"]["enabled"] is False
        assert checklist["seh"]["flag"] == 0x0400

    def test_unknown_dll_characteristics_is_null_not_false(self) -> None:
        checklist = _security(_fake_pe(optional_header=SimpleNamespace()))
        for key in ("aslr", "dep", "cfg", "seh", "image_isolation"):
            assert checklist[key]["enabled"] is None, key

    def test_bound_image_from_directory_size(self) -> None:
        directories = [SimpleNamespace(type="BOUND_IMPORT", size=168)]
        checklist = _security(_fake_pe(data_directories=directories))
        assert checklist["bound_image"]["enabled"] is True
        assert checklist["bound_image"]["flag"] == 168
        empty = [SimpleNamespace(type="BOUND_IMPORT", size=0)]
        assert _security(_fake_pe(data_directories=empty))["bound_image"]["enabled"] is False

    def test_bound_image_unknown_without_directories(self) -> None:
        assert _security(_fake_pe(data_directories=[]))["bound_image"]["enabled"] is None

    def test_score_counts_enabled_over_eleven(self) -> None:
        score = pe_info(MINI_PE)["security_score"]
        assert score == {"enabled": 2, "total": 11}

    def test_score_excludes_unknown_items(self) -> None:
        checklist = _security(_fake_pe(optional_header=SimpleNamespace()))
        assert _security_score(checklist) == {"enabled": 0, "total": 11}

    def test_score_counts_true_items(self) -> None:
        directories = [SimpleNamespace(type="BOUND_IMPORT", size=8)]
        checklist = _security(
            _fake_pe(
                optional_header=SimpleNamespace(dll_characteristics=0x0040),
                data_directories=directories,
            )
        )
        assert _security_score(checklist)["enabled"] == 4


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
        for key in (
            "sections",
            "security_flags",
            "security",
            "security_score",
            "exports",
            "resource_count",
            "type",
            "debug",
            "rich_header",
            "presence",
        ):
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
        assert "Security checklist" in result.output

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
