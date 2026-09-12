"""Tests for rebrew.fingerprints: hashes, imphash, Rich header, entropy, CLI."""

from __future__ import annotations

import hashlib
import json
import zlib
from pathlib import Path

import pytest
from typer.testing import CliRunner

import rebrew.main
from rebrew.fingerprints import (
    export_hash,
    export_hash_from_pairs,
    file_hashes,
    fingerprint_bundle,
    function_boundaries_hash,
    imphash,
    imphash_from_pairs,
    rich_header_bytes_from_parts,
    rich_header_hash,
    rich_header_hash_from_parts,
    section_entropies,
)

FIXTURES = Path(__file__).parent / "fixtures"
MINI_PE = FIXTURES / "mini_pe.exe"
MINI_ELF = FIXTURES / "mini.elf"

# sha256 of tests/fixtures/mini_pe.exe, computed independently from the raw bytes.
MINI_PE_SHA256 = "bda21f387f7d53bd188a1fd91179efbd688723d18c26e78465c2ced8fb75463f"
MINI_PE_IMPHASH = "27abfd9cfda7519d5efb3f08a2a4f3ce"

runner = CliRunner()


class TestFileHashes:
    def test_keys(self) -> None:
        assert set(file_hashes(MINI_PE)) == {
            "md5",
            "sha1",
            "sha256",
            "sha512",
            "sha3_224",
            "sha3_256",
            "sha3_384",
            "sha3_512",
            "crc32",
        }

    def test_mini_pe_sha256_golden(self) -> None:
        assert file_hashes(MINI_PE)["sha256"] == MINI_PE_SHA256

    def test_tmp_file_matches_hashlib(self, tmp_path: Path) -> None:
        payload = b"rebrew fingerprints test payload\n" * 97
        path = tmp_path / "blob.bin"
        path.write_bytes(payload)
        digest = file_hashes(path)
        assert digest["md5"] == hashlib.md5(payload).hexdigest()
        assert digest["sha1"] == hashlib.sha1(payload).hexdigest()
        assert digest["sha256"] == hashlib.sha256(payload).hexdigest()
        assert digest["sha512"] == hashlib.sha512(payload).hexdigest()
        assert digest["sha3_224"] == hashlib.sha3_224(payload).hexdigest()
        assert digest["sha3_256"] == hashlib.sha3_256(payload).hexdigest()
        assert digest["sha3_384"] == hashlib.sha3_384(payload).hexdigest()
        assert digest["sha3_512"] == hashlib.sha3_512(payload).hexdigest()

    def test_digest_lengths(self) -> None:
        digest = file_hashes(MINI_PE)
        assert len(digest["md5"]) == 32
        assert len(digest["sha1"]) == 40
        assert len(digest["sha256"]) == 64
        assert len(digest["sha512"]) == 128
        assert len(digest["sha3_224"]) == 56
        assert len(digest["sha3_256"]) == 64
        assert len(digest["sha3_384"]) == 96
        assert len(digest["sha3_512"]) == 128

    def test_crc32_is_eight_hex_digits(self, tmp_path: Path) -> None:
        payload = b"crc"
        path = tmp_path / "blob.bin"
        path.write_bytes(payload)
        crc = file_hashes(path)["crc32"]
        assert len(crc) == 8
        assert crc == f"{zlib.crc32(payload) & 0xFFFFFFFF:08x}"

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            file_hashes(tmp_path / "absent.exe")


class TestImphash:
    def test_pairs_golden(self) -> None:
        assert imphash_from_pairs([("KERNEL32.dll", "GetTickCount")]) == MINI_PE_IMPHASH

    def test_dll_basename_before_first_dot(self) -> None:
        pairs = [("ADVAPI32.dll", "RegOpenKeyA")]
        assert imphash_from_pairs(pairs) == hashlib.md5(b"advapi32.regopenkeya").hexdigest()

    def test_ordinal_form(self) -> None:
        pairs = [("WS2_32.dll", "ord5")]
        assert imphash_from_pairs(pairs) == hashlib.md5(b"ws2_32.ord5").hexdigest()

    def test_record_order_matters(self) -> None:
        a = imphash_from_pairs([("KERNEL32.dll", "GetTickCount"), ("USER32.dll", "MessageBoxA")])
        b = imphash_from_pairs([("USER32.dll", "MessageBoxA"), ("KERNEL32.dll", "GetTickCount")])
        assert a != b

    def test_mini_pe_golden(self) -> None:
        assert imphash(MINI_PE) == MINI_PE_IMPHASH

    def test_non_pe_returns_none(self) -> None:
        assert imphash(MINI_ELF) is None

    def test_missing_returns_none(self, tmp_path: Path) -> None:
        assert imphash(tmp_path / "absent.exe") is None


class TestRichHeader:
    def test_golden_hash_from_parts(self) -> None:
        assert (
            rich_header_hash_from_parts(0x12345678, [(0x00010002, 0x00000003)])
            == "e1a957081533ffddd336f5914b795def"
        )

    def test_bytes_layout(self) -> None:
        key = 0x12345678
        blob = rich_header_bytes_from_parts(key, [(0x00010002, 0x00000003)])
        assert blob.startswith(b"DanS" + b"\x00" * 12)
        assert blob.endswith(b"Rich" + key.to_bytes(4, "little"))
        assert len(blob) == 16 + 8 + 4 + 4

    def test_absent_returns_none(self) -> None:
        assert rich_header_hash(MINI_PE) is None

    def test_dos_stub_round_trip(self, tmp_path: Path) -> None:
        key = 0xDEADBEEF
        entries = [(0x00010002, 0x00000003), (0x00020004, 0x00000001)]
        path = tmp_path / "rich.bin"
        path.write_bytes(b"MZ" + b"\x00" * 0x40 + rich_header_bytes_from_parts(key, entries))
        assert rich_header_hash(path) == rich_header_hash_from_parts(key, entries)

    def test_missing_returns_none(self, tmp_path: Path) -> None:
        assert rich_header_hash(tmp_path / "absent.exe") is None


class TestExportHash:
    def test_golden_single_record(self) -> None:
        assert (
            export_hash_from_pairs([(1, "AddAtomA")]) == hashlib.sha256(b"1:addatoma").hexdigest()
        )

    def test_names_lowercased(self) -> None:
        assert export_hash_from_pairs([(5, "MessageBoxA")]) == export_hash_from_pairs(
            [(5, "messageboxa")]
        )

    def test_order_independent(self) -> None:
        a = export_hash_from_pairs([(2, "Bravo"), (1, "Alpha")])
        b = export_hash_from_pairs([(1, "Alpha"), (2, "Bravo")])
        assert a == b

    def test_ordinal_change_changes_hash(self) -> None:
        assert export_hash_from_pairs([(1, "Alpha")]) != export_hash_from_pairs([(2, "Alpha")])

    def test_empty_table_hashes_empty_string(self) -> None:
        assert export_hash_from_pairs([]) == hashlib.sha256(b"").hexdigest()

    def test_mini_pe_has_no_exports(self) -> None:
        # mini_pe.exe carries no export directory, so the table is empty.
        assert export_hash(MINI_PE) == hashlib.sha256(b"").hexdigest()

    def test_non_pe_returns_none(self) -> None:
        assert export_hash(MINI_ELF) is None

    def test_missing_returns_none(self, tmp_path: Path) -> None:
        assert export_hash(tmp_path / "absent.dll") is None


class TestFunctionBoundariesHash:
    def test_order_independent(self) -> None:
        a = function_boundaries_hash([(0x1000, 0x20), (0x2000, 0x10)])
        b = function_boundaries_hash([(0x2000, 0x10), (0x1000, 0x20)])
        assert a == b

    def test_size_change_changes_hash(self) -> None:
        a = function_boundaries_hash([(0x1000, 0x20)])
        b = function_boundaries_hash([(0x1000, 0x21)])
        assert a != b

    def test_va_change_changes_size(self) -> None:
        a = function_boundaries_hash([(0x1000, 0x20)])
        b = function_boundaries_hash([(0x1001, 0x20)])
        assert a != b


class TestSectionEntropies:
    def test_mini_pe_text_section(self) -> None:
        sections = section_entropies(MINI_PE)
        assert len(sections) == 1
        section = sections[0]
        assert section["name"] == ".text"
        assert section["vsize"] == 113
        assert section["raw_size"] == 512
        assert 0.0 <= float(section["entropy"]) <= 8.0

    def test_mini_elf_has_text(self) -> None:
        names = [section["name"] for section in section_entropies(MINI_ELF)]
        assert ".text" in names

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        assert section_entropies(tmp_path / "absent.exe") == []

    def test_non_binary_returns_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "notes.txt"
        path.write_text("not a binary\n", encoding="utf-8")
        assert section_entropies(path) == []


class TestFingerprintBundle:
    def test_required_keys(self) -> None:
        bundle = fingerprint_bundle(MINI_PE)
        assert {
            "md5",
            "sha1",
            "sha256",
            "sha512",
            "sha3_224",
            "sha3_256",
            "sha3_384",
            "sha3_512",
            "crc32",
            "format",
            "arch",
            "size",
            "imphash",
            "export_hash",
            "rich_header_hash",
            "section_entropies",
        } <= set(bundle)
        assert "tlsh" not in bundle or isinstance(bundle["tlsh"], str)
        assert "ssdeep" not in bundle or isinstance(bundle["ssdeep"], str)

    def test_mini_pe_values(self) -> None:
        bundle = fingerprint_bundle(MINI_PE)
        assert bundle["sha256"] == MINI_PE_SHA256
        assert bundle["sha512"] == file_hashes(MINI_PE)["sha512"]
        assert bundle["imphash"] == MINI_PE_IMPHASH
        assert bundle["export_hash"] == hashlib.sha256(b"").hexdigest()
        assert bundle["format"] == "pe"
        assert bundle["size"] == 1024

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            fingerprint_bundle(tmp_path / "absent.exe")

    def test_non_binary_degrades(self, tmp_path: Path) -> None:
        path = tmp_path / "notes.txt"
        path.write_text("not a binary\n", encoding="utf-8")
        bundle = fingerprint_bundle(path)
        assert bundle["format"] is None
        assert bundle["arch"] is None
        assert bundle["imphash"] is None
        assert bundle["export_hash"] is None
        assert bundle["rich_header_hash"] is None
        assert bundle["section_entropies"] == []


class TestFingerprintsCli:
    def test_json_output(self) -> None:
        result = runner.invoke(rebrew.main.app, ["fingerprints", str(MINI_PE), "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["sha256"] == MINI_PE_SHA256
        assert payload["imphash"] == MINI_PE_IMPHASH

    def test_human_output(self) -> None:
        result = runner.invoke(rebrew.main.app, ["fingerprints", str(MINI_PE)])
        assert result.exit_code == 0
        assert "sha256" in result.output
        assert "imphash" in result.output
        assert ".text" in result.output

    def test_missing_binary_exits_error(self, tmp_path: Path) -> None:
        result = runner.invoke(
            rebrew.main.app,
            ["fingerprints", str(tmp_path / "absent.exe"), "--json"],
        )
        assert result.exit_code == 2
        payload = json.loads(result.stdout)
        assert "error" in payload
