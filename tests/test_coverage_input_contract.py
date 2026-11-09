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
    value["readset"][0]["path"] = "src/&é\u2028.c"
    assert (
        coverage_input_digest(value)
        == "5c3ba9e424a3aa380fc5457e53aa9ba8a34729e40d15de7d13a768060f99e72c"
    )
    value["readset"][0]["path"] = "src/<.c"
    with pytest.raises(CoverageInputError):
        canonical_coverage_input(value)
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


def test_recorded_relocation_is_qualified_as_matched():
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
    assert len(verification_records_digest([row])) == 64
    for forged in (
        {**row, "reloc_count": 0},
        {**row, "match_count": 3},
        {**row, "obj_size": 5, "total": 5},
    ):
        with pytest.raises(CoverageInputError):
            verification_records_digest([forged])


def _project_without_shared(root):
    (root / "rebrew-project.toml").write_text(
        '[project]\ndefault_target = "A"\n[targets.A]\nbinary = "A.exe"\n', encoding="utf-8"
    )
    (root / "src").mkdir()
    (root / "src" / "a.c").write_text("int a(void) { return 1; }\n", encoding="utf-8")


def test_readset_of_a_project_without_shared_sources_ignores_the_absent_shared_dir(tmp_path):
    from rebrew.coverage_input_contract import plan_coverage_readset, rebrew_coverage_paths

    _project_without_shared(tmp_path)
    required = rebrew_coverage_paths(tmp_path, "A")
    assert "src/shared" not in required
    # An envelope captured before the absent shared_dir was added to the inputs
    # (rebrew 6.24.0) names exactly these paths and must still verify.
    envelope = contract()
    envelope["readset"] = [
        {**row, "origin": "source"} for row in plan_coverage_readset(tmp_path, "A")
    ]
    verify_coverage_readset(tmp_path, envelope, required)


def test_readset_gains_shared_sources_when_src_shared_appears(tmp_path):
    from rebrew.coverage_input_contract import rebrew_coverage_paths

    _project_without_shared(tmp_path)
    before = rebrew_coverage_paths(tmp_path, "A")
    (tmp_path / "src" / "shared").mkdir()
    (tmp_path / "src" / "shared" / "common.h").write_text("int x;\n", encoding="utf-8")
    assert rebrew_coverage_paths(tmp_path, "A") - before == {"src/shared/common.h"}
