"""Strict relocation proof over independently compiled PE/COFF fixtures."""

import hashlib
from pathlib import Path

import pytest

from rebrew.strict_relocation import StrictRelocationError, strict_pe_relocation

FIXTURE = Path(__file__).parent / "fixtures" / "coverage"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def prove(object_name: str, *, binary: bytes | None = None, binary_sha: str = ""):
    image = binary if binary is not None else (FIXTURE / "reloc-reference.exe").read_bytes()
    obj = FIXTURE / object_name
    return strict_pe_relocation(
        image, binary_sha or sha(image), obj, sha(obj.read_bytes()), "read_value", 0x401560, 6
    )


def test_real_coff_relocation_binds_symbol_to_retained_pe():
    proof = prove("reloc-candidate.o")
    assert proof["policy"] == "pe-coff-strict-v1"
    assert proof["va"] == 0x401560 and proof["size"] == 6
    assert proof["bindings"] == [{"offset": 1, "type": 6, "symbol": "_value", "address": 0x403008}]


@pytest.mark.parametrize("object_name", ["reloc-wrong.o", "reloc-unknown.o"])
def test_wrong_or_unknown_real_coff_symbol_is_refused(object_name):
    with pytest.raises(StrictRelocationError):
        prove(object_name)


def test_wrong_target_and_binary_or_object_digests_are_refused():
    binary = (FIXTURE / "reloc-reference.exe").read_bytes()
    obj = FIXTURE / "reloc-candidate.o"
    with pytest.raises(StrictRelocationError):
        prove("reloc-candidate.o", binary_sha="0" * 64)
    with pytest.raises(StrictRelocationError):
        strict_pe_relocation(binary, sha(binary), obj, "0" * 64, "read_value", 0x401560, 6)
    with pytest.raises(StrictRelocationError):
        strict_pe_relocation(
            binary, sha(binary), obj, sha(obj.read_bytes()), "read_value", 0x401560, 5
        )
    with pytest.raises(StrictRelocationError):
        strict_pe_relocation(binary, sha(binary), obj, sha(obj.read_bytes()), "other", 0x401560, 6)


def test_real_import_relocation_remains_refused():
    image = (FIXTURE / "reloc-import-reference.exe").read_bytes()
    obj = FIXTURE / "reloc-import-candidate.o"
    with pytest.raises(StrictRelocationError, match="import relocation"):
        strict_pe_relocation(
            image, sha(image), obj, sha(obj.read_bytes()), "read_import", 0x401560, 28
        )


def test_ambiguous_symbol_in_retained_pe_is_refused():
    image = (FIXTURE / "reloc-reference.exe").read_bytes()
    assert image.count(b"_other\0\0") == 1
    ambiguous = image.replace(b"_other\0\0", b"_value\0\0")
    with pytest.raises(StrictRelocationError, match="ambiguous"):
        prove("reloc-candidate.o", binary=ambiguous)


def test_compiler_service_objects_have_the_same_strict_binding():
    proof = prove("reloc-remote-candidate.o")
    assert (
        proof["object_sha256"] == "9e63ebed0af157746260f9b9674750809397312a71ba8fd5be971ed04b6a10bd"
    )
    assert proof["bindings"][0]["address"] == 0x403008
    for name in ("reloc-remote-wrong.o", "reloc-remote-unknown.o"):
        with pytest.raises(StrictRelocationError):
            prove(name)


def test_real_coff_relative_call_binds_the_correct_function():
    binary = (FIXTURE / "reloc-call-reference.exe").read_bytes()
    good = FIXTURE / "reloc-call-candidate.o"
    proof = strict_pe_relocation(
        binary, sha(binary), good, sha(good.read_bytes()), "apply", 0x401570, 22
    )
    assert proof["bindings"] == [
        {"offset": 11, "type": 20, "symbol": "_helper", "address": 0x401560}
    ]
    bad = FIXTURE / "reloc-call-wrong.o"
    with pytest.raises(StrictRelocationError):
        strict_pe_relocation(binary, sha(binary), bad, sha(bad.read_bytes()), "apply", 0x401570, 22)


def test_recorded_worker_relocation_has_independent_strict_binary_proof():
    import json

    recorded = json.loads((FIXTURE / "worker-comparisons.json").read_text())[
        "unqualified_relocation"
    ]
    binary = (FIXTURE / "reloc-worker-reference.exe").read_bytes()
    obj = FIXTURE / "reloc-remote-candidate.o"
    assert sha(binary) == recorded["binary_sha256"]
    assert (FIXTURE / "reloc-candidate.c").read_text() == recorded["candidate"]
    result = recorded["result"]
    proof = strict_pe_relocation(
        binary,
        sha(binary),
        obj,
        sha(obj.read_bytes()),
        result["symbol"],
        int(result["va"], 0),
        result["size"],
    )
    assert proof["bindings"] == [{"offset": 1, "type": 6, "symbol": "_value", "address": 0x403004}]
    assert result["status"] == "RELOC" and result["reloc_count"] == len(proof["bindings"])
