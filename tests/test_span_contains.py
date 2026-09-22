"""Tests for the shared annotated-span predicate (span_contains_factory)."""

from rebrew.annotation import span_contains_factory


class TestSpanContainsFactory:
    def test_strict_interior(self) -> None:
        contains = span_contains_factory([(0x1000, 0x1100)])
        assert contains(0x1005)
        assert contains(0x10FF)
        assert not contains(0x1000)  # start itself is not "inside"
        assert not contains(0x1100)
        assert not contains(0x2000)

    def test_unsorted_input_ok(self) -> None:
        contains = span_contains_factory([(0x2000, 0x2100), (0x1000, 0x1100)])
        assert contains(0x1050)
        assert contains(0x2050)

    def test_overlapping_spans(self) -> None:
        contains = span_contains_factory([(0x1000, 0x1200), (0x1100, 0x1300)])
        assert contains(0x1250)  # second span covers it
        assert not contains(0x1350)

    def test_empty(self) -> None:
        assert not span_contains_factory([])(0x1000)
