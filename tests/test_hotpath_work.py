"""Correctness and deterministic work budgets for the twenty hot-path rounds."""

import copy
import math
import os
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, ClassVar, override

import pytest

from rebrew import utils, verify_cache
from rebrew.catalog import grid
from rebrew.compiler import cache
from rebrew.metadata.bindings import SourceBinding
from rebrew.metadata.document import load_metadata_doc
from rebrew.metadata.functions import save_metadata
from rebrew.verify_cache import VerifyCacheEntry


class TestFlagWork:
    def test_unknown_anchors_do_not_sort_empty_groups(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sorts = []

        def ordered(values: Any) -> Any:
            sorts.append(1)
            return sorted(values)

        monkeypatch.setattr(cache, "sorted", ordered, raising=False)
        anchors = ["/D", "A=1", "/I", "include", "/D", "A=2"]
        assert cache.canonicalize_cflags(anchors) == anchors
        assert sorts == []
        assert cache.canonicalize_cflags(["/O1", "/O2", *anchors, "/O1"]) == [
            "/O2",
            *anchors,
            "/O1",
        ]
        assert len(sorts) == 2

    def test_quote_normalization_keeps_interior_spaces(self) -> None:
        assert cache.canonicalize_cflags(['" /O2 "', "'/Gd'", " /MT "]) == [
            " /O2 ",
            *cache.canonicalize_cflags(["/Gd", "/MT"]),
        ]

    def test_no_directive_marker_skips_line_splitting(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def unexpected(*args: Any, **kwargs: Any) -> Any:
            pytest.fail("split a source that cannot contain an include directive")

        monkeypatch.setattr(cache, "split_source_lines", unexpected)
        assert list(cache._iter_include_specs("int f(void) { return 0; }\n" * 100)) == []

    def test_spaced_and_macro_include_directives_still_reach_the_resolver(self) -> None:
        assert list(
            cache._iter_include_specs(
                '/* prefix */ # include "a.h"\r\n#include_next <b.h>\n#include LIB_H\n'
            )
        ) == [("quote", "a.h"), ("angle", "b.h"), ("nonliteral", "")]


class TestVerifyShapeWork:
    def test_repeated_rows_share_field_discovery_and_keep_subclass_fields(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        @dataclass
        class Extended(VerifyCacheEntry):
            extra: int = 0
            class_only: ClassVar[str] = "class default"

        verify_cache._entry_field_names.cache_clear()
        reads = []

        def discover(entry_type: Any) -> Any:
            reads.append(entry_type)
            return fields(entry_type)

        monkeypatch.setattr(verify_cache, "fields", discover)
        for _ in range(50):
            assert VerifyCacheEntry.from_dict({"va": 0x1000}).va == 0x1000
            row = Extended.from_dict({"extra": 9, "class_only": "ignored", "unknown": 1})
            assert isinstance(row, Extended)
            assert row.extra == 9
            assert row.class_only == "class default"
        assert reads.count(VerifyCacheEntry) == 1
        assert reads.count(Extended) == 50
        assert verify_cache._entry_field_names.cache_info().maxsize == 1
        verify_cache._entry_field_names.cache_clear()

    def test_transient_attributes_do_not_enter_the_serialized_schema(self) -> None:
        row = VerifyCacheEntry(va=0x1000, status="EXACT")
        vars(row)["transient"] = "not a cache field"
        result = verify_cache.VerifyCache(2, "compiler", "S", {"one": row}).to_dict()
        assert "transient" not in result["entries"]["one"]
        assert result["entries"]["one"]["va"] == 0x1000

    @pytest.mark.parametrize(
        "value,expected",
        [
            (-0.0, 0.0),
            (0.0, 0.0),
            (-1.0, 0.0),
            (101.0, 100.0),
            (57.3, 57.3),
            (float("nan"), 0.0),
            (float("inf"), 0.0),
            (-float("inf"), 0.0),
        ],
    )
    def test_clamping_preserves_finite_range_and_positive_zero(
        self, value: float, expected: float
    ) -> None:
        actual = verify_cache._clamp_percent(value)
        assert actual == expected
        if actual == 0.0:
            assert math.copysign(1.0, actual) == 1.0


class TestBindingWork:
    def test_fast_get_keeps_aliases_properties_defaults_and_subclass_overrides(self) -> None:
        class Extended(SourceBinding):
            @override
            def __getitem__(self, key: str) -> Any:
                return "custom" if key == "derived" else super().__getitem__(key)

        row = SourceBinding(kind="FUNCTION", globals_list=["g"])
        missing = object()
        assert row.get("globals") is row.globals_list
        assert row.get("is_function") is True
        assert row.get("missing", missing) is missing
        assert Extended().get("derived") == "custom"
        assert Extended().get("missing", missing) is missing

    def test_get_preserves_missing_property_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def missing(row: SourceBinding) -> Any:
            raise KeyError("unavailable property")

        monkeypatch.setattr(SourceBinding, "temporary", property(missing), raising=False)
        assert SourceBinding().get("temporary", "default") == "default"

    def test_copy_does_not_test_arbitrary_truth_values_and_preserves_cycles(self) -> None:
        class Untruthable:
            def __bool__(self) -> bool:
                raise AssertionError("deepcopy must not ask whether this object is empty")

        row = SourceBinding(locals={"shared": [1]})
        row.origins["shared"] = row.locals["shared"]
        row.locals["self"] = row
        vars(row)["extra"] = Untruthable()
        twin = copy.deepcopy(row)
        assert twin.locals["self"] is twin
        assert twin.locals["shared"] is twin.origins["shared"]
        assert twin.locals["shared"] is not row.locals["shared"]
        assert vars(twin)["extra"] is not vars(row)["extra"]


class TestTextAndAccountingWork:
    @pytest.mark.parametrize("literal", ["١٢", "１２", "1_0", "0x_10", "0x１２", "1 2"])
    def test_integer_validation_stays_ascii_and_contiguous(self, literal: str) -> None:
        with pytest.raises(ValueError):
            utils.parse_int_literal(literal)
        with pytest.raises(ValueError):
            utils.parse_c_integer_literal(literal)

    @pytest.mark.parametrize(
        "literal,expected", [("0x10ULL", 16), ("010u", 8), ("08L", 8), ("- 42LL", -42)]
    )
    def test_c_suffixes_keep_base_and_sign_rules(self, literal: str, expected: int) -> None:
        assert utils.parse_c_integer_literal(literal) == expected

    def test_prototypes_and_comment_escaping_keep_quoted_braces_and_controls(self) -> None:
        assert utils.strip_body(" int f(void); ") == "int f(void);"
        assert utils.strip_body('char *f(char *x = "{") { return x; }') == 'char *f(char *x = "{")'
        assert utils.c_comment_safe("café ☃ */\n\x00\u202e") == "café ☃ * /   "
        assert utils.c_comment_safe("plain symbol") == "plain symbol"

    def test_cell_ceiling_is_exact_above_float_precision(self) -> None:
        unit = 2**53
        cells = grid._build_cells([(0, unit + 1, "exact", [], None, None)], unit, 64)
        assert len(cells) == 1
        assert cells[0]["span"] == 2
        assert cells[0]["end"] == unit + 1

    def test_status_priority_handles_singletons_duplicates_unknown_and_data(self) -> None:
        rows = {
            1: [SourceBinding(status="STUB", kind="FUNCTION")],
            2: [
                SourceBinding(status="PROVEN", kind="FUNCTION"),
                SourceBinding(status="RELOC", kind="FUNCTION"),
            ],
            3: [SourceBinding(status="EXACT", kind="DATA")],
            4: [SourceBinding(status="SIZE_MISMATCH", kind="FUNCTION")],
            5: [SourceBinding(status="NEAR_MATCHING", kind="FUNCTION")],
        }
        assert grid.count_statuses(rows) == {
            "EXACT": 0,
            "RELOC": 1,
            "PROVEN": 0,
            "NEAR_MATCHING": 1,
            "STUB": 1,
        }

    def test_clipping_computes_one_upper_bound_per_input_without_mutation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        reads = []

        def minimum(*values: int) -> int:
            reads.append(1)
            return min(values)

        monkeypatch.setattr(utils, "min", minimum, raising=False)
        ranges = [(-5, 3), (2, 8), (7, 20), (5, 5)]
        assert utils.merged_span_bytes(ranges, (0, 10)) == 10
        assert len(reads) == len(ranges)
        assert ranges == [(-5, 3), (2, 8), (7, 20), (5, 5)]


class TestRejectedPathCache:
    @pytest.mark.skipif(os.name != "posix", reason="requires hard-linked relative symlinks")
    def test_metadata_follows_retargeted_ancestors_even_with_shared_link_inodes(
        self, tmp_path: Path
    ) -> None:
        a, b = tmp_path / "a", tmp_path / "b"
        save_metadata(a / "store", {("S", 0x1000): {"size": 16}})
        save_metadata(b / "store", {("S", 0x1000): {"size": 32}})
        link = a / "rebrew-functions.toml"
        link.symlink_to("store/rebrew-functions.toml")
        os.link(link, b / link.name, follow_symlinks=False)
        alias = tmp_path / "current"
        alias.symlink_to(a, target_is_directory=True)
        path = alias / link.name
        cache: Any = {}
        assert load_metadata_doc(path, cache, "test")[("S", 0x1000)]["size"] == 16
        alias.unlink()
        alias.symlink_to(b, target_is_directory=True)
        assert load_metadata_doc(path, cache, "test")[("S", 0x1000)]["size"] == 32
