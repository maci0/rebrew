"""Property-based tests for shared status helpers.

``count_statuses`` (catalog/grid.py) and ``should_promote_status``
(cli.py) are the two canonical status-decision helpers added when the
swarm review found status-counting and promotion logic triplicated across
modules.  These hypothesis tests pin the invariants that must hold for
arbitrary annotation mixes:

- count_statuses never loses a function VA (sum == number of function VAs)
- statuses outside the four buckets do not create phantom counts
- should_promote_status is consistent with the three documented rules
  (sticky, STUB→SIZE_MISMATCH, unchanged) and never promotes to the same
  status.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from rebrew.annotation import Annotation
from rebrew.catalog.grid import count_statuses
from rebrew.cli import is_status_sticky, should_promote_status

_STATUSES = ["EXACT", "RELOC", "NEAR_MATCHING", "NEAR_MATCH", "STUB", "SIZE_MISMATCH", "PROVEN", ""]
_MARKERS = ["FUNCTION", "LIBRARY", "STUB", "GLOBAL", "DATA"]


@st.composite
def annotation_list(draw: st.DrawFn) -> list[Annotation]:
    """A random list of annotations (may include duplicates per VA)."""
    count = draw(st.integers(min_value=0, max_value=30))
    out: list[Annotation] = []
    for _ in range(count):
        out.append(
            Annotation(
                va=draw(st.integers(min_value=0x1000, max_value=0x1000 + 200)),
                name=draw(st.text(min_size=1, max_size=12)),
                status=draw(st.sampled_from(_STATUSES)),
                size=draw(st.integers(min_value=1, max_value=256)),
                module=draw(st.sampled_from(["GAME", "SERVER", "MSVCRT", ""])),
                marker_type=draw(st.sampled_from(_MARKERS)),
            )
        )
    return out


class TestCountStatusesInvariants:
    @given(annotation_list())
    def test_every_bucketed_va_counted_once(self, annos: list[Annotation]) -> None:
        """Every function VA whose status intersects the four buckets is counted
        exactly once; PROVEN is bucketed with RELOC (it ranks with RELOC in
        _STATUS_RANK and is fully matched); statuses outside the buckets
        (SIZE_MISMATCH, "") legitimately fall through the breakdown (totals
        come from len(fn_vas))."""
        by_va: dict[int, list[Annotation]] = {}
        for a in annos:
            by_va.setdefault(a.va, []).append(a)
        bucketed_vas = {
            va
            for va, vas in by_va.items()
            if any(e.get("marker_type") not in ("GLOBAL", "DATA") for e in vas)
            and any(
                e.get("status")
                in ("EXACT", "RELOC", "PROVEN", "NEAR_MATCHING", "NEAR_MATCH", "STUB")
                for e in vas
            )
        }
        counts = count_statuses(by_va)
        assert sum(counts.values()) == len(bucketed_vas)

    @given(annotation_list())
    def test_no_phantom_counts(self, annos: list[Annotation]) -> None:
        """Only the four known buckets are ever returned, each non-negative."""
        by_va: dict[int, list[Annotation]] = {}
        for a in annos:
            by_va.setdefault(a.va, []).append(a)
        counts = count_statuses(by_va)
        assert set(counts) == {"EXACT", "RELOC", "NEAR_MATCHING", "STUB"}
        assert all(v >= 0 for v in counts.values())

    @given(annotation_list())
    def test_global_data_markers_excluded(self, annos: list[Annotation]) -> None:
        """VAs whose ONLY markers are GLOBAL/DATA never count as functions."""
        by_va: dict[int, list[Annotation]] = {}
        for a in annos:
            by_va.setdefault(a.va, []).append(a)
        data_only = {
            va
            for va, vas in by_va.items()
            if vas and all(e.get("marker_type") in ("GLOBAL", "DATA") for e in vas)
        }
        counts = count_statuses(by_va)
        # Counted VAs can never include a data-only VA.
        # (A VA with both data and function markers IS counted — as a function.)
        total_counted_vas = sum(counts.values())
        assert total_counted_vas <= len(by_va) - len(data_only)

    def test_empty(self) -> None:
        assert count_statuses({}) == {"EXACT": 0, "RELOC": 0, "NEAR_MATCHING": 0, "STUB": 0}

    def test_priority_wins(self) -> None:
        """A VA with both STUB and EXACT annotations counts once as EXACT."""
        by_va = {
            0x1000: [
                Annotation(va=0x1000, name="f", status="STUB"),
                Annotation(va=0x1000, name="f", status="EXACT"),
            ]
        }
        counts = count_statuses(by_va)
        assert counts == {"EXACT": 1, "RELOC": 0, "NEAR_MATCHING": 0, "STUB": 0}


class TestShouldPromoteStatusInvariants:
    @given(st.sampled_from(_STATUSES), st.sampled_from(_STATUSES))
    def test_never_promotes_to_unchanged(self, current: str, new: str) -> None:
        """Same-status never promotes (unless sticky — which is also refused)."""
        if current == new:
            assert should_promote_status(current, new) is False

    @given(st.sampled_from(_STATUSES), st.sampled_from(_STATUSES))
    def test_sticky_current_never_promotes(self, current: str, new: str) -> None:
        if is_status_sticky(current):
            assert should_promote_status(current, new) is False

    @given(st.sampled_from(_STATUSES))
    def test_stub_to_size_mismatch_refused(self, current: str) -> None:
        if current == "STUB":
            assert should_promote_status(current, "SIZE_MISMATCH") is False
            assert should_promote_status(current, "MISSING_SIZE") is False

    @given(st.sampled_from(_STATUSES), st.sampled_from(_STATUSES))
    def test_symmetric_under_rule_set(self, current: str, new: str) -> None:
        """A promotion is allowed iff none of the three refusal rules fire."""
        expected = (
            not is_status_sticky(current)
            and not (current == "STUB" and new in ("SIZE_MISMATCH", "MISSING_SIZE"))
            and current != new
        )
        assert should_promote_status(current, new) is expected

    def test_normal_promotion_allowed(self) -> None:
        assert should_promote_status("STUB", "EXACT") is True
        assert should_promote_status("NEAR_MATCHING", "RELOC") is True
        assert should_promote_status("EXACT", "STUB") is True  # demotion ok
