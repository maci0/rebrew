"""Similarity is protected comparison evidence, independent of byte coverage."""

from typing import Any
lazy from pathlib import Path

import pytest
from bin_util import make_pe
from source_util import write_source

from rebrew.compiler.overrides import resolve_compile_overrides_cached
from rebrew.config import load_config
from rebrew.coverage_project import load_project_coverage
from rebrew.lint import _check_W031_metadata_store
from rebrew.metadata.functions import (
    get_entry,
    remove_field,
    set_fields,
    update_field,
    update_source_status,
    update_statuses_batch,
    validate_metadata_field,
)
from rebrew.status import collect_status
from rebrew.verify_hash import comparison_inputs


def _evidence(status: str = "SIZE_MISMATCH", **extra: Any) -> dict[str, Any]:
    return {"status": status, "writer": "test", "input_hash": "a" * 64, **extra}


def _record(root: Path, **extra: Any) -> None:
    update_source_status(
        root,
        "SIZE_MISMATCH",
        "GOOD",
        0x401000,
        updated_by="test",
        force=True,
        verification=_evidence(**extra),
    )


def test_records_and_replaces_similarity(tmp_path: Path) -> None:
    _record(
        tmp_path,
        similarity=87.5,
        aligned_pairs=7,
        target_instructions=8,
        candidate_instructions=8,
        hunks=2,
    )
    row = get_entry(tmp_path, 0x401000, "GOOD")
    assert row["similarity"] == 87.5
    assert row["verification"]["aligned_pairs"] == 7
    update_field(tmp_path, 0x401000, "note", "reviewed", "GOOD")
    assert get_entry(tmp_path, 0x401000, "GOOD")["similarity"] == 87.5
    _record(tmp_path)
    assert "similarity" not in get_entry(tmp_path, 0x401000, "GOOD")


@pytest.mark.parametrize("value", [True, "90", -1, 101, float("nan"), float("inf")])
def test_rejects_invalid_similarity(value: Any) -> None:
    with pytest.raises(ValueError, match="similarity"):
        validate_metadata_field("similarity", value)


@pytest.mark.parametrize("value", [0, 100, 87.5])
def test_accepts_percentage(value: Any) -> None:
    assert validate_metadata_field("similarity", value) == value


@pytest.mark.parametrize("operation", ["update", "set", "remove", "verdict_fields"])
def test_generic_writers_cannot_forge_similarity(tmp_path: Path, operation: str) -> None:
    with pytest.raises(ValueError, match="similarity"):
        if operation == "update":
            update_field(tmp_path, 0x401000, "similarity", 90, "GOOD")
        elif operation == "set":
            set_fields(tmp_path, 0x401000, {"similarity": 90}, "GOOD")
        elif operation == "remove":
            remove_field(tmp_path, 0x401000, "similarity", "GOOD")
        else:
            update_statuses_batch(
                tmp_path,
                [
                    {
                        "module": "GOOD",
                        "va": 0x401000,
                        "new_status": "EXACT",
                        "fields": {"similarity": 90},
                    }
                ],
            )


def test_new_verdict_without_measurement_clears_similarity(tmp_path: Path) -> None:
    _record(tmp_path, similarity=50)
    update_source_status(tmp_path, "COMPILE_ERROR", "GOOD", 0x401000, force=True)
    assert "similarity" not in get_entry(tmp_path, 0x401000, "GOOD")


def _project(root: Path) -> Any:
    (root / "rebrew-project.toml").write_text(
        '[project]\nname="similarity"\ndefault_target="good"\nshared_dir=""\n'
        '[compiler]\nprofile="msvc-6.0"\nincludes=""\nlibs=""\n'
        '[targets.good]\nbinary="game.exe"\nreversed_dir="src"\nmodule="GOOD"\n'
    )
    (root / "game.exe").write_bytes(make_pe(b"\xc3"))
    source = root / "src" / "function.c"
    source.parent.mkdir()
    write_source(
        source,
        "/* ADDRESS: GOOD 0x401000 */\nint foo(void) { return 0; }\n",
        metadata_dir=root,
        metadata_fields={"GOOD.0x401000": {"kind": "FUNCTION", "name": "foo", "size": 1}},
    )
    cfg = load_config(root, target="good")
    toolchain, cflags = resolve_compile_overrides_cached(cfg, source.parent, "", "", "GOOD")
    inputs = comparison_inputs(
        cfg,
        source,
        b"\xc3",
        toolchain=toolchain,
        cflags=cflags,
        module="GOOD",
        va=0x401000,
    )
    assert inputs
    _record(root, **{k: v for k, v in inputs.items() if k != "input_hash"}, similarity=75)
    return cfg


def test_status_and_coverage_use_current_similarity(tmp_path: Path) -> None:
    cfg = _project(tmp_path)
    report = collect_status(cfg)
    assert report.to_dict()["similarity"]["SIZE_MISMATCH"] == {"count": 1, "mean": 75.0}
    assert report.matched_bytes == 0
    view = load_project_coverage(tmp_path)
    assert view.snapshots["good"].verify_results[0]["similarity"] == 0.75
    assert view.snapshots["good"].functions[0].similarity == 0.75
    source = tmp_path / "src" / "function.c"
    source.write_text(source.read_text().replace("return 0", "return 1"))
    assert collect_status(cfg).to_dict()["similarity"] == {}
    assert load_project_coverage(tmp_path, refresh=True).snapshots["good"].verify_results == ()


def test_lint_requires_a_verdict_for_similarity(tmp_path: Path) -> None:
    cfg = _project(tmp_path)
    path = tmp_path / "rebrew-functions.toml"
    path.chmod(0o644)
    path.write_text('format=3\n["GOOD.0x401000"]\nsimilarity=50\n')
    findings = _check_W031_metadata_store(cfg)
    assert any(
        "similarity" in message and "verdict" in message
        for result in findings
        for _, code, message in result.warnings
        if code == "W031"
    )


@pytest.mark.parametrize(
    "field,value", [("cflags", "/Od"), ("size", 2), ("toolchain", "msvc-6.0-sp5")]
)
def test_compile_override_changes_hide_similarity(tmp_path: Path, field: str, value: Any) -> None:
    cfg = _project(tmp_path)
    update_field(tmp_path, 0x401000, field, value, "GOOD")
    assert collect_status(cfg).to_dict()["similarity"] == {}


@pytest.mark.parametrize(
    "count", ["aligned_pairs", "target_instructions", "candidate_instructions", "hunks"]
)
@pytest.mark.parametrize("value", [-1, True, 1.5, "7"])
def test_rejects_invalid_alignment_counts(tmp_path: Path, count: str, value: Any) -> None:
    with pytest.raises(ValueError, match=count):
        _record(tmp_path, similarity=50, **{count: value})
    assert get_entry(tmp_path, 0x401000, "GOOD") == {}
