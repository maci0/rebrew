"""Tests for rebrew.crypto_scan: constant tables, name patterns, CLI."""

from __future__ import annotations

import json
import math
import random
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import rebrew.main
from rebrew.binary_loader import BinaryInfo, SectionInfo
from rebrew.crypto_scan import (
    _AES_INV_SBOX,
    _AES_SBOX,
    _MD5_T,
    _SHA1_H,
    _SHA256_H,
    _SHA256_K,
    constant_findings,
    crypto_scan,
    name_findings,
)

FIXTURES = Path(__file__).parent / "fixtures"
MINI_PE = FIXTURES / "mini_pe.exe"

runner = CliRunner()


def _le(words: tuple[int, ...]) -> bytes:
    return b"".join(word.to_bytes(4, "little") for word in words)


def _be(words: tuple[int, ...]) -> bytes:
    return b"".join(word.to_bytes(4, "big") for word in words)


def _primes(count: int) -> list[int]:
    out: list[int] = []
    candidate = 2
    while len(out) < count:
        if all(candidate % prime for prime in out if prime * prime <= candidate):
            out.append(candidate)
        candidate += 1
    return out


def _fractional_bits(value: float) -> int:
    return int((value - int(value)) * (1 << 32))


class TestConstantTables:
    """The embedded literals are the real algorithm constants.

    Each word table is derived independently (cube roots, square roots, sine)
    and compared against the module constant, so a corrupted literal cannot
    pass the detector tests by being embedded in the synthetic input too.
    """

    def test_aes_inverse_sbox_is_forward_sbox_inverse(self) -> None:
        inverse = [0] * 256
        for index, value in enumerate(_AES_SBOX):
            inverse[value] = index
        assert bytes(inverse) == _AES_INV_SBOX

    def test_sha256_k_derivation(self) -> None:
        derived = tuple(_fractional_bits(prime ** (1.0 / 3.0)) for prime in _primes(64))
        assert derived == _SHA256_K

    def test_sha256_h_derivation(self) -> None:
        derived = tuple(_fractional_bits(float(prime) ** 0.5) for prime in _primes(8))
        assert derived == _SHA256_H

    def test_md5_t_derivation(self) -> None:
        derived = tuple(int(abs(math.sin(i + 1)) * (1 << 32)) for i in range(64))
        assert derived == _MD5_T

    def test_sha1_h_known(self) -> None:
        assert _SHA1_H == (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)


class TestConstantFindings:
    def test_aes_sbox_va(self) -> None:
        prefix = b"\x00" * 24
        blob = prefix + _AES_SBOX + b"\x00" * 8
        findings = constant_findings([("rdata", 0x1000, blob)])
        assert len(findings) == 1
        finding = findings[0]
        assert finding["kind"] == "constant"
        assert finding["name"] == "AES S-box"
        assert finding["va"] == 0x1000 + len(prefix)
        assert finding["section"] == "rdata"
        assert finding["confidence"] == "high"

    def test_aes_inverse_sbox_found(self) -> None:
        findings = constant_findings([("rdata", 0x2000, _AES_INV_SBOX)])
        assert [f["name"] for f in findings] == ["AES inverse S-box"]
        assert findings[0]["va"] == 0x2000

    def test_sha256_k_little_endian(self) -> None:
        blob = b"\xaa" * 7 + _le(_SHA256_K)
        findings = constant_findings([("data", 0x3000, blob)])
        assert len(findings) == 1
        assert findings[0]["name"] == "SHA-256 round constants K"
        assert findings[0]["va"] == 0x3000 + 7

    def test_sha256_k_big_endian(self) -> None:
        blob = b"\xbb" * 3 + _be(_SHA256_K)
        findings = constant_findings([("data", 0x4000, blob)])
        assert len(findings) == 1
        assert findings[0]["name"] == "SHA-256 round constants K"
        assert findings[0]["va"] == 0x4000 + 3

    def test_sha256_h_found(self) -> None:
        findings = constant_findings([("rdata", 0x5000, _le(_SHA256_H))])
        assert [f["name"] for f in findings] == ["SHA-256 initial hash H"]

    def test_sha1_h_found(self) -> None:
        findings = constant_findings([("rdata", 0x6000, _le(_SHA1_H))])
        assert [f["name"] for f in findings] == ["SHA-1 initial hash H"]

    def test_md5_t_found(self) -> None:
        findings = constant_findings([("rdata", 0x7000, _le(_MD5_T))])
        assert [f["name"] for f in findings] == ["MD5 T table"]

    def test_no_false_positive_on_random_bytes(self) -> None:
        blob = random.Random(0xC0FFEE).randbytes(4096)
        assert constant_findings([("data", 0x8000, blob)]) == []

    def test_two_sections_reported_separately(self) -> None:
        findings = constant_findings(
            [
                ("rdata", 0x9000, _AES_SBOX),
                ("data", 0xA000, b"\x00" * 4 + _AES_SBOX),
            ]
        )
        assert sorted(f["va"] for f in findings) == [0x9000, 0xA004]

    def test_single_encoding_not_double_reported(self) -> None:
        findings = constant_findings([("data", 0xB000, _le(_SHA256_K))])
        assert len(findings) == 1

    def test_empty_input(self) -> None:
        assert constant_findings([]) == []


class TestNameFindings:
    def test_cryptoapi_imports_high(self) -> None:
        imports = [
            {"dll": "ADVAPI32.dll", "name": "CryptGenRandom", "iat_va": 0x1000},
            {"dll": "BCRYPT.dll", "name": "BCryptGenRandom", "iat_va": 0x1004},
            {"dll": "NCrypt.dll", "name": "NCryptOpenStorageProvider", "iat_va": 0x1008},
        ]
        findings = name_findings(imports, [])
        assert len(findings) == 3
        assert all(f["kind"] == "import" and f["confidence"] == "high" for f in findings)
        assert {f["name"] for f in findings} == {
            "CryptGenRandom",
            "BCryptGenRandom",
            "NCryptOpenStorageProvider",
        }

    def test_openssl_imports_high(self) -> None:
        imports = [
            {"name": "EVP_EncryptInit_ex"},
            {"name": "RSA_new"},
            {"name": "AES_set_encrypt_key"},
            {"name": "DES_set_key"},
            {"name": "SHA256_Init"},
            {"name": "MD5_Init"},
            {"name": "HMAC_Init_ex"},
        ]
        findings = name_findings(imports, [])
        assert len(findings) == 7
        assert all(f["confidence"] == "high" for f in findings)

    def test_common_ciphers_and_libs(self) -> None:
        names = [
            "ChaCha20_xor",
            "Poly1305_auth",
            "Salsa20_xor",
            "Blowfish_encrypt",
            "mbedtls_sha256",
            "wolfSSL_Init",
            "CRC32",
        ]
        findings = name_findings([{"name": n} for n in names], [])
        assert {f["name"] for f in findings} == set(names)

    def test_function_names_medium(self) -> None:
        findings = name_findings([], ["CryptAcquireContextA", "md5_init"])
        assert len(findings) == 2
        assert all(f["kind"] == "name" and f["confidence"] == "medium" for f in findings)

    def test_duplicate_imports_deduped(self) -> None:
        imports = [{"name": "MD5_Init"}, {"name": "MD5_Init"}, {"name": "MD5_Init"}]
        findings = name_findings(imports, [])
        assert len(findings) == 1

    def test_function_name_duplicate_of_import_skipped(self) -> None:
        findings = name_findings([{"name": "SHA256_Init"}], ["SHA256_Init", "SHA256_Init"])
        assert len(findings) == 1
        assert findings[0]["kind"] == "import"
        assert findings[0]["confidence"] == "high"

    def test_unrelated_names_no_match(self) -> None:
        assert name_findings([{"name": "MessageBoxA"}, {"name": "malloc"}], ["strlen"]) == []

    def test_libsodium_substring_match(self) -> None:
        findings = name_findings([{"name": "libsodium_version_string"}], [])
        assert len(findings) == 1


class TestCryptoScan:
    def test_mini_pe_well_formed_empty(self) -> None:
        result = crypto_scan(MINI_PE)
        assert result["binary"] == str(MINI_PE)
        assert result["findings"] == []
        assert result["count"] == 0
        assert result["by_confidence"] == {"high": 0, "medium": 0}

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            crypto_scan(tmp_path / "absent.exe")

    def test_synthetic_data_section_constant(self, tmp_path: Path, monkeypatch: Any) -> None:
        blob = b"\x00" * 16 + _AES_SBOX + b"\x00" * 16
        path = tmp_path / "fake.bin"
        path.write_bytes(blob)
        info = BinaryInfo(
            path=path,
            format="pe",
            sections={
                ".rdata": SectionInfo(
                    name=".rdata", va=0x401000, size=len(blob), file_offset=0, raw_size=len(blob)
                )
            },
            _data=blob,
        )
        monkeypatch.setattr("rebrew.binary_loader.load_binary", lambda *a, **k: info)
        monkeypatch.setattr("rebrew.imports.parse_imports", lambda *a, **k: [])
        result = crypto_scan(path)
        assert result["count"] == 1
        finding = result["findings"][0]
        assert finding["name"] == "AES S-box"
        assert finding["va"] == 0x401010
        assert result["by_confidence"] == {"high": 1, "medium": 0}

    def test_findings_sorted_by_confidence_then_name(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        blob = _AES_SBOX
        path = tmp_path / "fake.bin"
        path.write_bytes(blob)
        info = BinaryInfo(
            path=path,
            format="pe",
            sections={
                ".rdata": SectionInfo(
                    name=".rdata", va=0x402000, size=len(blob), file_offset=0, raw_size=len(blob)
                )
            },
            _data=blob,
        )
        monkeypatch.setattr("rebrew.binary_loader.load_binary", lambda *a, **k: info)
        monkeypatch.setattr(
            "rebrew.imports.parse_imports",
            lambda *a, **k: [{"name": "CryptGenRandom"}, {"name": "MD5_Init"}],
        )
        result = crypto_scan(path, ["md5_helper"])
        keys = [(f["confidence"], f["name"]) for f in result["findings"]]
        assert keys == sorted(keys)
        assert keys[0][0] == "high"


class TestCryptoScanCli:
    def test_json_output(self) -> None:
        result = runner.invoke(rebrew.main.app, ["crypto-scan", str(MINI_PE), "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert set(payload) == {"binary", "findings", "count", "by_confidence"}
        assert payload["binary"] == str(MINI_PE)
        assert payload["count"] == len(payload["findings"])
        assert set(payload["by_confidence"]) == {"high", "medium"}

    def test_human_output(self) -> None:
        result = runner.invoke(rebrew.main.app, ["crypto-scan", str(MINI_PE)])
        assert result.exit_code == 0
        assert "crypto" in result.output.lower()

    def test_missing_binary_exits_error(self, tmp_path: Path) -> None:
        result = runner.invoke(
            rebrew.main.app,
            ["crypto-scan", str(tmp_path / "absent.exe"), "--json"],
        )
        assert result.exit_code == 2
        payload = json.loads(result.stdout)
        assert "error" in payload
