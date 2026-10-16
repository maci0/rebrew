"""Organization previews preserve inputs and expose cross-target link constraints."""

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from bin_util import append_pe_section, make_pe

from rebrew.config import ProjectConfig
from rebrew.metadata.functions import record_function_identity, set_fields
from rebrew.source_organization import check_reorganization, review_organization


def _project(tmp_path: Path) -> tuple[ProjectConfig, ProjectConfig, list[Path]]:
    source = tmp_path / "src"
    source.mkdir()
    files = [source / "a.c", source / "b.c"]
    for path, name in zip(files, ["a", "b"], strict=True):
        path.write_text(f"int {name}(void) {{ return 1; }}\n")
    configs = [
        ProjectConfig(root=tmp_path, reversed_dir=source, module=marker, target_name=marker)
        for marker in ("A", "B")
    ]
    for marker, addresses in [("A", [0x401000, 0x401100]), ("B", [0x501100, 0x501000])]:
        for path, name, va in zip(files, ["a", "b"], addresses, strict=True):
            record_function_identity(
                tmp_path,
                module=marker,
                va=va,
                file=f"src/{path.name}",
                name=name,
                symbol=f"_{name}",
                kind="FUNCTION",
                size=4,
            )
    return configs[0], configs[1], files


class TestOrganizationReview:
    def test_conflicting_orders_are_explicit_and_preview_writes_nothing(
        self, tmp_path: Path
    ) -> None:
        a, b, files = _project(tmp_path)
        before = {p: (p.read_bytes(), p.stat()) for p in tmp_path.rglob("*") if p.is_file()}
        report = review_organization([a, b], files, destination=Path("src/merged.c"))
        assert report["cycle"] and not report["common_definition_order"]
        assert any(p["kind"] == "conflicting_target_orders" for p in report["problems"])
        assert not report["safe_to_reorganize"] and not report["source_changed"]
        assert before == {p: (p.read_bytes(), p.stat()) for p in tmp_path.rglob("*") if p.is_file()}

    def test_one_target_order_does_not_claim_link_safety(self, tmp_path: Path) -> None:
        a, _b, files = _project(tmp_path)
        report = review_organization([a], files)
        assert report["common_definition_order"] == ["src/a.c::a", "src/b.c::b"]
        assert not report["problems"] and not report["unknown"]
        assert not report["safe_to_reorganize"]
        assert not report["targets"][0]["raw_link_before"]["available"]
        assert "raw" in report["targets"][0]["raw_link_after"]

    def test_foreign_bodies_and_original_settings_are_not_silently_combined(
        self, tmp_path: Path
    ) -> None:
        a, b, files = _project(tmp_path)
        foreign = a.reversed_dir / "foreign.c"
        foreign.write_text("int foreign(void) { return 2; }\n")
        record_function_identity(
            tmp_path,
            module="B",
            va=0x501200,
            file="src/foreign.c",
            name="foreign",
            symbol="_foreign",
            kind="FUNCTION",
            size=4,
        )
        set_fields(tmp_path, 0x501200, {"cflags": "/Od /Gd"}, module="B")
        report = review_organization([a, b], [*files, foreign], destination=Path("src/merged.c"))
        assert any(
            p["kind"] == "foreign_definitions_in_merged_tu" and p["target"] == "A"
            for p in report["problems"]
        )
        assert any(p["kind"] == "incompatible_tu_compile_settings" for p in report["problems"])
        assert len(report["targets"][1]["contexts"]) == 3

    def test_inputs_include_headers_and_raw_baselines(self, tmp_path: Path) -> None:
        a, _b, files = _project(tmp_path)
        header = a.reversed_dir / "api.h"
        header.write_text("int shared(void);\n")
        files[0].write_text('#include "api.h"\n' + files[0].read_text())
        raw = tmp_path / "raw.exe"
        raw.write_bytes(make_pe(b"\xc3"))
        a.raw_link = raw
        report = review_organization([a], files)
        assert str(header) in report["input_hashes"] and str(raw) in report["input_hashes"]
        first = report["input_digest"]
        header.write_text("int shared(int x);\n")
        assert review_organization([a], files)["input_digest"] != first

    def test_shared_candidates_preserve_distinct_native_bindings(self, tmp_path: Path) -> None:
        a, b, files = _project(tmp_path)
        files[1].write_text(files[0].read_text())
        # Review deliberately reports metadata whose b binding now lacks its definition.
        report = review_organization([a, b], files, shared=True)
        assert len(report["definitions"]) == 1
        assert any(row.get("name") == "b" for row in report["unknown"])


class TestRawOrganizationCheck:
    def test_complete_unchanged_images_keep_source_verdicts_separate(self, tmp_path: Path) -> None:
        before, after = tmp_path / "before.exe", tmp_path / "after.exe"
        before.write_bytes(make_pe(b"\xc3\xcc\xcc\xcc"))
        after.write_bytes(before.read_bytes())
        result = check_reorganization(before, after)
        assert result["match"] and result["regions"][0]["different_or_missing"] == 0
        assert not result["reference_verified"] and not result["verdicts_changed"]

    def test_initialized_data_drift_fails_even_when_text_is_identical(self, tmp_path: Path) -> None:
        before, after = tmp_path / "before.exe", tmp_path / "after.exe"
        code = make_pe(b"\xc3\xcc\xcc\xcc")
        before.write_bytes(append_pe_section(code, ".data", b"\x01\x02\x03\x04" + bytes(508)))
        after.write_bytes(append_pe_section(code, ".data", b"\x01\x02\x03\x05" + bytes(508)))
        result = check_reorganization(before, after)
        assert not result["match"]
        regions = {row["section"]: row for row in result["regions"]}
        assert regions[".text"]["different_or_missing"] == 0
        assert regions[".data"]["different_or_missing"] == 1

    def test_invalid_images_cannot_pass_by_matching_errors(self, tmp_path: Path) -> None:
        before, after = tmp_path / "before.exe", tmp_path / "after.exe"
        before.write_bytes(b"garbage")
        after.write_bytes(b"garbage")
        with pytest.raises(ValueError, match="complete PE"):
            check_reorganization(before, after)

    def test_actual_truncated_section_does_not_claim_a_full_byte_check(
        self, tmp_path: Path
    ) -> None:
        before, after = tmp_path / "before.exe", tmp_path / "after.exe"
        before.write_bytes(make_pe(b"\xc3\xcc\xcc\xcc"))
        after.write_bytes(before.read_bytes()[:513])
        with pytest.raises(ValueError, match="fully file-backed"):
            check_reorganization(before, after)


class TestOrganizationRejectingControls:
    def test_missing_declared_section_table_cannot_pass(self, tmp_path: Path) -> None:
        before, after = tmp_path / "before.exe", tmp_path / "after.exe"
        before.write_bytes(make_pe(b"\xc3")[:0x178])
        after.write_bytes(before.read_bytes())
        with pytest.raises(ValueError, match="section table"):
            check_reorganization(before, after)

    def test_local_function_and_storage_collisions_are_visible(self, tmp_path: Path) -> None:
        a, _b, files = _project(tmp_path)
        for path, name in zip(files, ["a", "b"], strict=True):
            path.write_text(
                f"static int counter;\nstatic int helper(void) {{ return counter; }}\nint {name}(void) {{ return helper(); }}\n"
            )
        for index, file in enumerate(files):
            record_function_identity(
                tmp_path,
                module="A",
                va=0x402000 + index * 0x100,
                file=f"src/{file.name}",
                name="helper",
                symbol="_helper",
                kind="FUNCTION",
                size=4,
            )
        report = review_organization([a], files, destination=Path("src/merged.c"))
        collisions = {
            problem["name"]
            for problem in report["problems"]
            if problem["kind"] == "merged_ordinary_namespace_collision"
        }
        assert collisions == {"helper", "counter"}
        assert {item["name"] for item in report["storage_definitions"]} == {"counter"}
        assert all(item["static"] for item in report["storage_definitions"])

    def test_check_cannot_compare_one_artifact_to_itself(self, tmp_path: Path) -> None:
        image = tmp_path / "raw.exe"
        image.write_bytes(make_pe(b"\xc3"))
        with pytest.raises(ValueError, match="independent before"):
            check_reorganization(image, image)

    def test_guarded_header_storage_does_not_collapse_silently(self, tmp_path: Path) -> None:
        a, _b, files = _project(tmp_path)
        header = a.reversed_dir / "state.h"
        header.write_text("#ifndef STATE_H\n#define STATE_H\nstatic int counter;\n#endif\n")
        for path, name in zip(files, ["a", "b"], strict=True):
            path.write_text(f'#include "state.h"\nint {name}(void) {{ return ++counter; }}\n')
        report = review_organization([a], files, destination=Path("src/merged.c"))
        assert any(
            problem["kind"] == "header_local_instances_would_change"
            and problem["name"] == "counter"
            for problem in report["problems"]
        )
        instances = report["targets"][0]["header_local_instances"]
        assert len(instances) == 1 and len(instances[0]["contexts"]) == 2

    def test_replacement_between_validation_and_snapshot_cannot_pass(self, tmp_path: Path) -> None:
        from rebrew.binary_gate import snapshot_binary

        before, after = tmp_path / "before.exe", tmp_path / "after.exe"
        original = make_pe(b"\xc3")
        before.write_bytes(original)
        after.write_bytes(original)
        changed = False

        def swapped(path: Path) -> dict[str, Any]:
            nonlocal changed
            if not changed:
                changed = True
                before.write_bytes(original[:0x178])
                after.write_bytes(original[:0x178])
            return snapshot_binary(path)

        with (
            patch("rebrew.source_organization.snapshot_binary", side_effect=swapped),
            pytest.raises(ValueError, match="changed after"),
        ):
            check_reorganization(before, after)


class TestIncompleteOrganizationSources:
    @pytest.mark.parametrize("header", [False, True])
    def test_parse_recovery_is_reported_as_unknown(self, tmp_path: Path, header: bool) -> None:
        cfg, _other, files = _project(tmp_path)
        malformed = files[0]
        if header:
            malformed = cfg.reversed_dir / "broken.h"
            files[0].write_text('#include "broken.h"\nint a(void) { return 1; }\n')
        malformed.write_text("int broken(void) { if (\n")
        report = review_organization([cfg], files)
        assert any(
            row.get("file") == str(malformed) and "parse errors" in row["reason"]
            for row in report["unknown"]
        )
        assert not report["safe_to_reorganize"]
