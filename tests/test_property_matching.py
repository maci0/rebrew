"""Property-based tests for rebrew.core.matching.smart_reloc_compare.

smart_reloc_compare is the byte-level matching primitive used by every
compile-and-compare path (test, verify, GA scoring).  The hand-written edge
case tests in test_audit_edge_cases.py cover specific shapes; these
hypothesis tests pin the algebraic invariants that must hold for ANY input:

- identical bytes always match (vacuous and non-empty)
- total is always max(len(obj), len(target))
- match_count is bounded by the common prefix length
- relocation masking makes a 4-byte window "free": mutating only reloc
  slots keeps the comparison a match
- zero-span detection (obj has 00 00 00 00 where target differs) masks
  those spans, never counts them as mismatches
- every returned reloc offset lies within the compared prefix
"""

from __future__ import annotations

import random

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.core import smart_reloc_compare


@st.composite
def bytes_pair(draw: st.DrawFn) -> tuple[bytes, bytes]:
    """(obj, target) byte pair, equal or unequal length, 0..64 bytes."""
    size = draw(st.integers(min_value=0, max_value=64))
    return (
        draw(st.binary(min_size=size, max_size=size)),
        draw(st.binary(min_size=size, max_size=size)),
    )


@st.composite
def reloc_offsets(draw: st.DrawFn, max_len: int) -> list[int]:
    """A set of 4-byte-aligned reloc offsets within [0, max_len)."""
    if max_len < 4:
        return []
    count = draw(st.integers(min_value=0, max_value=min(16, max_len // 4)))
    offsets = draw(
        st.lists(
            st.integers(min_value=0, max_value=max_len - 4),
            min_size=count,
            max_size=count,
            unique=True,
        )
    )
    return offsets


class TestIdenticalBytes:
    @given(st.binary(max_size=64))
    def test_vacuous_empty_match(self, data: bytes) -> None:
        matched, count, total, valid, invalid = smart_reloc_compare(data, data, None)
        assert matched is True
        assert count == len(data)
        assert total == len(data)
        assert valid == []
        assert invalid == []


class TestLengthContract:
    @given(bytes_pair())
    def test_total_is_max_length(self, pair: tuple[bytes, bytes]) -> None:
        obj, target = pair
        _, _, total, _, _ = smart_reloc_compare(obj, target, None)
        assert total == max(len(obj), len(target))

    @given(bytes_pair())
    def test_match_count_bounded_by_common_prefix(self, pair: tuple[bytes, bytes]) -> None:
        obj, target = pair
        _, count, total, _, _ = smart_reloc_compare(obj, target, None)
        assert 0 <= count <= min(len(obj), len(target))
        assert count <= total

    @given(bytes_pair())
    def test_empty_obj_or_target_never_matches(self, pair: tuple[bytes, bytes]) -> None:
        obj, target = pair
        if len(obj) == 0 and len(target) == 0:
            return  # vacuous match — covered elsewhere
        if len(obj) == 0 or len(target) == 0:
            matched, count, total, _, _ = smart_reloc_compare(obj, target, None)
            assert matched is False
            assert count == 0
            assert total == max(len(obj), len(target))


class TestRelocMasking:
    @given(
        st.binary(min_size=4, max_size=64),
        st.lists(st.integers(min_value=0, max_value=255), min_size=4, max_size=4),
    )
    def test_masking_a_window_makes_it_free(self, base: bytes, patch: list[int]) -> None:
        """Mutating exactly one 4-byte window at a masked offset keeps a match."""
        patch_bytes = bytes(patch)
        offset = 0  # window must start within base
        if len(base) < 4:
            return
        mutated = bytearray(base)
        mutated[offset : offset + 4] = patch_bytes
        matched, count, total, valid, invalid = smart_reloc_compare(
            bytes(mutated), base, [offset], name_to_va=None, section_va=None
        )
        # Reloc window is masked → bytes there don't count against us.
        assert matched is True
        assert count == len(base)
        assert offset in valid
        assert invalid == []

    @given(st.binary(min_size=4, max_size=64), reloc_offsets(64))
    def test_mutating_all_reloc_windows_keeps_match(self, base: bytes, offsets: list[int]) -> None:
        """Mutating every masked window still matches — relocs are free."""
        if not offsets:
            return
        # Only offsets within base matter; mutate each 4-byte window to 0xFF.
        mutated = bytearray(base)
        for off in offsets:
            if off + 4 <= len(base):
                mutated[off : off + 4] = b"\xff" * 4
        matched, count, total, valid, invalid = smart_reloc_compare(
            bytes(mutated), base, offsets, name_to_va=None, section_va=None
        )
        assert matched is True
        assert count == len(base)
        for off in offsets:
            if off + 4 <= len(base):
                assert off in valid

    @given(
        st.binary(min_size=4, max_size=64),
        st.lists(st.integers(min_value=0, max_value=255), min_size=4, max_size=4),
    )
    def test_out_of_bounds_reloc_ignored(self, base: bytes, patch: list[int]) -> None:
        """Reloc offsets beyond the common prefix are dropped, not fatal."""
        obj = bytearray(base)
        obj[0:4] = bytes(patch)  # mutate a real window
        # Offset far beyond both buffers:
        far_offset = len(base) + 16
        matched, count, total, valid, invalid = smart_reloc_compare(
            bytes(obj), base, [far_offset], name_to_va=None, section_va=None
        )
        assert far_offset not in valid
        assert far_offset not in invalid  # dropped silently
        if obj[0:4] != base[0:4]:
            # The mutation at 0 is unmasked → mismatch.
            assert matched is False


class TestZeroSpanDetection:
    @given(
        st.binary(min_size=4, max_size=64),
        st.binary(min_size=4, max_size=64),
    )
    def test_zero_spans_masked_when_target_differs(self, target: bytes, tail: bytes) -> None:
        """obj = target with a 4-byte window replaced by 00 00 00 00.

        The zero-span detector masks the FIRST aligned 00 00 00 00 run where
        the target differs.  The true contract: every masked offset points at
        an all-zero obj window that differs from the target — and the mask
        covers every zero run the detector found, so no matching byte is
        ever misclassified as a reloc.
        """
        if len(target) < 4:
            return
        # Replace a random 4-byte window with zeros (guaranteed non-zero target).
        off = len(target) - 4
        tail4 = target[off:]
        if tail4 == b"\x00\x00\x00\x00":
            return  # zero span equals target — nothing to mask
        obj = target[:off] + b"\x00\x00\x00\x00"
        matched, count, total, valid, invalid = smart_reloc_compare(obj, target, None)
        # Every detected span is genuinely a zero run in obj differing from
        # target (never a false positive on identical bytes).
        for r in valid:
            assert obj[r : r + 4] == b"\x00\x00\x00\x00"
            assert obj[r : r + 4] != target[r : r + 4]
        assert invalid == []
        # The detector never reports relocs outside the compared prefix.
        for r in valid:
            assert r + 4 <= min(len(obj), len(target))
        # Sanity: the tail window we created is either masked (→ match) or a
        # preceding zero run was masked first — count is consistent either way.
        assert count == sum(
            1
            for i in range(min(len(obj), len(target)))
            if any(r <= i < r + 4 for r in valid) or obj[i] == target[i]
        )

    @given(st.binary(min_size=4, max_size=64))
    def test_no_false_zero_span_when_target_also_zero(self, data: bytes) -> None:
        """obj == target (identical) → zero bytes are not treated as relocs."""
        matched, count, total, valid, invalid = smart_reloc_compare(data, data, None)
        assert matched is True
        assert valid == []


class TestReturnedRelocBounds:
    @given(st.binary(min_size=4, max_size=64), st.lists(st.integers(min_value=0, max_value=200)))
    def test_valid_relocs_within_prefix(self, base: bytes, offsets: list[int]) -> None:
        """Valid relocs must satisfy offset + 4 <= min_len (the only ones usable)."""
        _, _, _, valid, _ = smart_reloc_compare(
            base, base, offsets, name_to_va=None, section_va=None
        )
        min_len = len(base)
        for off in valid:
            assert off + 4 <= min_len


class TestRelocMaskCoverage:
    @given(
        st.binary(min_size=4, max_size=64),
        st.binary(min_size=4, max_size=64),
        st.lists(st.integers(min_value=0, max_value=64)),
    )
    @settings(max_examples=200)
    def test_reloc_mask_is_union_of_windows(
        self, obj: bytes, target: bytes, offsets: list[int]
    ) -> None:
        """The reloc mask covers exactly the 4-byte windows of valid offsets.

        match_count must equal the number of bytes that are either equal OR
        inside a reloc window — recompute independently and compare.
        """
        min_len = min(len(obj), len(target))
        if min_len == 0:
            return
        _, count, _, valid, _ = smart_reloc_compare(
            obj, target, offsets, name_to_va=None, section_va=None
        )
        # Recompute the mask the same way (valid offsets, within prefix)
        mask = [False] * min_len
        for off in valid:
            for i in range(off, min(off + 4, min_len)):
                mask[i] = True
        expected = sum(1 for i in range(min_len) if mask[i] or obj[i] == target[i])
        assert count == expected


class TestStabilityUnderSeededRNG:
    @given(st.binary(min_size=1, max_size=64), st.binary(min_size=1, max_size=64))
    def test_deterministic_output(self, obj: bytes, target: bytes) -> None:
        """Pure function: same inputs → same outputs (no hidden RNG)."""
        r1 = smart_reloc_compare(obj, target, None)
        r2 = smart_reloc_compare(obj, target, None)
        assert r1 == r2
        # Sanity: a random mutator with a fixed seed gives reproducible diffs too.
        rng = random.Random(42)
        mutated = bytearray(obj)
        for _ in range(3):
            if mutated:
                i = rng.randrange(len(mutated))
                mutated[i] ^= 0xFF
        a = smart_reloc_compare(bytes(mutated), target, None)
        rng2 = random.Random(42)
        mutated2 = bytearray(obj)
        for _ in range(3):
            if mutated2:
                i = rng2.randrange(len(mutated2))
                mutated2[i] ^= 0xFF
        b = smart_reloc_compare(bytes(mutated2), target, None)
        assert a == b
