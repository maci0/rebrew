"""Coverage input contract preserves custody, readset and match evidence."""

import hashlib

import pytest

from rebrew.coverage_input_contract import (
    CoverageInputError,
    canonical_coverage_input,
    coverage_input_digest,
    verification_records_digest,
    verify_coverage_readset,
)


def contract():
    return {
        "version": 1,
        "analysis_manifest": "d" * 64,
        "verification_digest": hashlib.sha256(b"[]").hexdigest(),
        "source_revision": "a" * 64,
        "generation": "c" * 32,
        "binary_sha256": "b" * 64,
        "target": "target",
        "readset": [
            {
                "path": "src/a.c",
                "present": True,
                "origin": "source",
                "digest": hashlib.sha256(b"source").hexdigest(),
                "size": 6,
            },
            {
                "path": "src/missing.json",
                "present": False,
                "origin": "analysis",
                "digest": "",
                "size": 0,
            },
        ],
    }


def test_cross_engine_canonical_vector():
    value = contract()
    assert (
        coverage_input_digest(value)
        == "16c6bceb08f19082905aafe9dcbdd6f59f05ef3d9cb26caaaab972d8aa201fff"
    )
    assert verification_records_digest([]) == hashlib.sha256(b"[]").hexdigest()
    value["readset"][0]["path"] = "src/<&é\u2028.c"
    assert (
        coverage_input_digest(value)
        == "c48c80a624439e1401f06c6b3dcf2faef39b2dad7a800ead041ad32e6b2c0574"
    )
    value["readset"][0]["path"] = "src/e\u0301.c"
    with pytest.raises(CoverageInputError):
        canonical_coverage_input(value)


def test_readset_requires_exact_paths_and_bytes(tmp_path):
    value = contract()
    (tmp_path / "src").mkdir()
    path = tmp_path / "src/a.c"
    path.write_bytes(b"source")
    names = {entry["path"] for entry in value["readset"]}
    verify_coverage_readset(tmp_path, value, names)
    with pytest.raises(CoverageInputError):
        verify_coverage_readset(tmp_path, value, {"src/a.c"})
    path.write_bytes(b"forged")
    with pytest.raises(CoverageInputError):
        verify_coverage_readset(tmp_path, value, names)


def test_real_size_mismatch_projection_is_preserved():
    result = {
        "source": "src/add.c",
        "symbol": "add",
        "va": "0x401120",
        "size": 4,
        "status": "SIZE_MISMATCH",
        "match_count": 0,
        "total": 5,
        "reloc_count": 0,
        "obj_size": 5,
        "context_hash": None,
        "mismatches": [
            {"offset": 0, "target": "0x8d", "got": "0x89"},
            {"offset": 1, "target": "0x04", "got": "0xf8"},
            {"offset": 2, "target": "0x37", "got": "0x29"},
            {"offset": 3, "target": "0xc3", "got": "0xf0"},
        ],
    }
    import json

    payload = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    row = {
        "verification_id": "v",
        "source": result["source"],
        "source_sha256": "a" * 64,
        "va": int(result["va"], 0),
        "size": result["size"],
        "status": result["status"],
        "match_count": result["match_count"],
        "total": result["total"],
        "obj_size": result["obj_size"],
        "reloc_count": result["reloc_count"],
        "result_digest": hashlib.sha256(payload).hexdigest(),
    }
    assert len(verification_records_digest([row])) == 64
    for forged in (
        {**row, "total": 4},
        {**row, "obj_size": 4},
        {**row, "match_count": 5},
        {**row, "reloc_count": 1},
    ):
        with pytest.raises(CoverageInputError):
            verification_records_digest([forged])


def test_real_nonmatch_shapes_preserve_status():
    base = {
        "verification_id": "v",
        "source": "src/add.c",
        "source_sha256": "a" * 64,
        "va": 0x401120,
        "size": 4,
        "status": "NEAR_MATCHING",
        "match_count": 3,
        "total": 4,
        "obj_size": 4,
        "reloc_count": 0,
        "result_digest": "b" * 64,
    }
    assert verification_records_digest([base])
    stub = {
        **base,
        "source": "src/main.c",
        "va": 0x401020,
        "size": 15,
        "status": "STUB",
        "match_count": 0,
        "total": 15,
        "obj_size": 3,
    }
    assert verification_records_digest([stub])
    for forged in (
        {**base, "match_count": 4},
        {**base, "obj_size": 5, "total": 5},
        {**stub, "match_count": 4},
        {**stub, "reloc_count": 1},
    ):
        with pytest.raises(CoverageInputError):
            verification_records_digest([forged])


def test_recorded_worker_comparisons_project_without_losing_status():
    import json
    from pathlib import Path

    fixture = json.loads(
        (Path(__file__).parent / "fixtures/coverage/worker-comparisons.json").read_text()
    )
    assert fixture["compiler"] == "gcc-14.2.0"
    binary = (Path(__file__).parent / "fixtures/coverage/comparison-reference.elf").read_bytes()
    assert hashlib.sha256(binary).hexdigest() == fixture["binary_sha256"]
    assert {item["result"]["status"] for item in fixture["outcomes"]} == {
        "EXACT",
        "SIZE_MISMATCH",
        "NEAR_MATCHING",
        "STUB",
    }
    for item in fixture["outcomes"]:
        result = item["result"]
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        row = {
            "verification_id": "v",
            "source": result["source"],
            "source_sha256": hashlib.sha256(item["candidate"].encode()).hexdigest(),
            "va": int(result["va"], 0),
            "size": result["size"],
            "status": result["status"],
            "match_count": result["match_count"],
            "total": result["total"],
            "obj_size": result["obj_size"],
            "reloc_count": result["reloc_count"],
            "result_digest": hashlib.sha256(encoded).hexdigest(),
        }
        assert len(verification_records_digest([row])) == 64


def test_recorded_relocation_remains_unqualified_without_strict_binding():
    import json
    from pathlib import Path

    fixture = json.loads(
        (Path(__file__).parent / "fixtures/coverage/worker-comparisons.json").read_text()
    )
    observed = fixture["unqualified_relocation"]
    result = observed["result"]
    binary = (Path(__file__).parent / "fixtures/coverage/reloc-worker-reference.exe").read_bytes()
    assert hashlib.sha256(binary).hexdigest() == observed["binary_sha256"]
    assert result["status"] == "RELOC" and result["reloc_count"] == 1
    payload = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    row = {
        "verification_id": "v",
        "source": result["source"],
        "source_sha256": hashlib.sha256(observed["candidate"].encode()).hexdigest(),
        "va": int(result["va"], 0),
        "size": result["size"],
        "status": result["status"],
        "match_count": result["match_count"],
        "total": result["total"],
        "obj_size": result["obj_size"],
        "reloc_count": result["reloc_count"],
        "result_digest": hashlib.sha256(payload).hexdigest(),
    }
    with pytest.raises(CoverageInputError):
        verification_records_digest([row])
