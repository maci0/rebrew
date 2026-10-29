"""Parity of the table-driven mnemonic matcher with difflib (measured by tools/bench_perf10_matcher.py)."""

import difflib
import itertools
import random
from typing import Any

import numpy as np
import pytest

from rebrew.matcher import scoring
from rebrew.matcher.scoring import _mnemonic_matcher, _RunTableMatcher

_Sig = dict[str, Any]


def _assert_same(a: list[str], b: list[str]) -> None:
    ref = difflib.SequenceMatcher(None, a, b, autojunk=False)
    got = _RunTableMatcher(a, b)
    assert got.get_matching_blocks() == ref.get_matching_blocks(), (a, b)
    assert got.get_opcodes() == ref.get_opcodes(), (a, b)


def _sequences(alphabet: str, max_len: int) -> list[list[str]]:
    return [list(t) for n in range(max_len + 1) for t in itertools.product(alphabet, repeat=n)]


class TestRunTableMatcher:
    def test_exhaustive_binary_alphabet(self) -> None:
        seqs = _sequences("ab", 7)
        for a in seqs:
            for b in seqs:
                _assert_same(a, b)

    def test_exhaustive_ternary_alphabet(self) -> None:
        seqs = _sequences("abc", 4)
        for a in seqs:
            for b in seqs:
                _assert_same(a, b)

    @pytest.mark.parametrize("alphabet", [2, 6, 25, 400])
    def test_random_edited_copies(self, alphabet: int) -> None:
        rng = random.Random(alphabet)
        vocab = [f"op{i}" for i in range(alphabet)]
        for _ in range(150):
            a = [rng.choice(vocab) for _ in range(rng.randint(0, 90))]
            b = list(a)
            for _m in range(rng.randint(0, 20)):
                pos = rng.randint(0, len(b))
                kind = rng.randrange(3)
                if kind == 0:
                    b.insert(pos, rng.choice(vocab))
                elif b and kind == 1:
                    del b[min(pos, len(b) - 1)]
                elif b:
                    b[min(pos, len(b) - 1)] = rng.choice(vocab)
            _assert_same(a, b)
            _assert_same(a, [rng.choice(vocab) for _ in range(rng.randint(0, 90))])

    def test_ties_prefer_earliest_in_both_sequences(self) -> None:
        # three equal-length candidates: the block must start at a[0] and b[1]
        _assert_same(list("xyzxyz"), list("qxyzxyz"))
        _assert_same(list("abab"), list("abab"[::-1]))

    def test_adjacent_blocks_report_one_equal_opcode(self) -> None:
        a = list("aabbaabb")
        got = _RunTableMatcher(a, a + ["z"])
        assert [op for op in got.get_opcodes() if op[0] == "equal"] == [("equal", 0, 8, 0, 8)]


class TestRunTableMatcherState:
    def test_replacing_a_sequence_drops_the_cached_table(self) -> None:
        m = _RunTableMatcher(list("abcabc"), list("abcabc"))
        assert m.get_matching_blocks()[0] == (0, 0, 6)
        m.set_seq2(list("xabcabcx"))
        ref = difflib.SequenceMatcher(None, list("abcabc"), list("xabcabcx"), autojunk=False)
        assert m.get_matching_blocks() == ref.get_matching_blocks()
        m.set_seq1(list("abcx"))
        ref.set_seq1(list("abcx"))
        assert m.get_matching_blocks() == ref.get_matching_blocks()

    def test_explicit_window_bounds_match_difflib(self) -> None:
        a, b = list("abcabcabd"), list("zabcabdabc")
        ref = difflib.SequenceMatcher(None, a, b, autojunk=False)
        got = _RunTableMatcher(a, b)
        for window in [(0, 9, 0, 10), (2, 9, 3, 10), (0, 4, 0, 4), (5, 5, 0, 3), (1, 8, 4, 4)]:
            assert got.find_longest_match(*window) == ref.find_longest_match(*window)
        assert got.find_longest_match() == ref.find_longest_match()


class TestMatcherSelection:
    @staticmethod
    def _repetitive(n: int) -> list[str]:
        return ["mov", "push"] * (n // 2)

    def test_small_or_dissimilar_pairs_use_difflib(self) -> None:
        # too few matching pairs per row of the target
        assert type(_mnemonic_matcher(["mov"] * 10, ["mov"] * 10)) is difflib.SequenceMatcher
        # no matching pair at all
        assert type(_mnemonic_matcher(["mov"] * 200, ["push"] * 200)) is difflib.SequenceMatcher

    def test_repetitive_pairs_use_the_run_table(self) -> None:
        a = self._repetitive(200)
        m = _mnemonic_matcher(a, a[:150] + ["call"] + a[150:])
        assert type(m) is _RunTableMatcher

    def test_cell_cap_falls_back_to_difflib(self) -> None:
        side = int(scoring._ALIGN_TABLE_MAX_CELLS**0.5)
        assert type(_mnemonic_matcher(["mov"] * side, ["mov"] * side)) is _RunTableMatcher
        assert (
            type(_mnemonic_matcher(["mov"] * side, ["mov"] * (side + 2))) is difflib.SequenceMatcher
        )

    def test_length_cap_falls_back_to_difflib(self) -> None:
        n = scoring._ALIGN_TABLE_MAX_LEN + 1
        assert type(_mnemonic_matcher(["mov"] * 20, ["mov"] * n)) is difflib.SequenceMatcher

    def test_both_matchers_give_the_same_score(self, monkeypatch: pytest.MonkeyPatch) -> None:
        body = b"\x8b\xc1\x50\x8b\xd8\x53" * 50  # repetitive: mov/push/mov/push
        target = b"\x55\x8b\xec" + body + b"\x5d\xc3"
        spaced = b"".join(
            body[i : i + 6] + (b"\x90" if i % 18 == 0 else b"") for i in range(0, 300, 6)
        )
        cand = b"\x55\x8b\xec" + spaced + b"\x5d\xc3"
        table_calls: list[int] = []
        real = _RunTableMatcher.find_longest_match

        def spy(self: _RunTableMatcher, *args: int) -> difflib.Match:
            table_calls.append(1)
            return real(self, *args)

        monkeypatch.setattr(_RunTableMatcher, "find_longest_match", spy)
        with_table = scoring.score_candidate(target, cand)
        assert table_calls
        table_calls.clear()
        monkeypatch.setattr(scoring, "_ALIGN_TABLE_MAX_CELLS", 0)
        with_difflib = scoring.score_candidate(target, cand)
        assert not table_calls
        assert with_table == with_difflib
        assert with_table.mnemonic_score > 0


def _old_score_matrix(sigs_a: list[_Sig], sigs_b: list[_Sig]) -> np.ndarray:
    """The pre-rewrite arithmetic, kept as the bit-exact reference."""
    from rebrew.binary_similarity import _pair_ratio

    vocab = sorted(
        {m for s in sigs_a for m in s["histogram"]} | {m for s in sigs_b for m in s["histogram"]}
    )
    vmap = {m: i for i, m in enumerate(vocab)}

    def rows(sigs: list[_Sig]) -> np.ndarray:
        out = np.zeros((len(sigs), len(vocab)), dtype=float)
        for i, s in enumerate(sigs):
            for m, c in s["histogram"].items():
                out[i, vmap[m]] = c
        return out

    ha, hb = rows(sigs_a), rows(sigs_b)
    na, nb = np.linalg.norm(ha, axis=1), np.linalg.norm(hb, axis=1)
    cos = np.divide(
        ha @ hb.T,
        na[:, None] * nb[None, :],
        out=np.zeros((len(sigs_a), len(sigs_b)), dtype=float),
        where=(na[:, None] > 0) & (nb[None, :] > 0),
    )
    np.clip(cos, 0.0, 1.0, out=cos)
    ca = np.array([s["calls"] for s in sigs_a], dtype=float)[:, None]
    cb = np.array([s["calls"] for s in sigs_b], dtype=float)[None, :]
    ba = np.array([s["branches"] for s in sigs_a], dtype=float)[:, None]
    bb = np.array([s["branches"] for s in sigs_b], dtype=float)[None, :]
    scores: np.ndarray = np.round(
        0.6 * cos * 100.0 + 0.2 * _pair_ratio(ca, cb) * 100.0 + 0.2 * _pair_ratio(ba, bb) * 100.0,
        6,
    )
    return scores


class TestScoreMatrixParity:
    def test_matches_the_reference_bit_for_bit(self) -> None:
        from rebrew.binary_similarity import score_matrix

        rng = random.Random(3)
        vocab = [f"op{i}" for i in range(40)]

        def sig() -> _Sig:
            names = rng.sample(vocab, rng.randint(0, 12))  # includes empty histograms
            return {
                "histogram": {m: rng.randint(1, 6) for m in names},
                "calls": rng.choice([0, 0, 1, 2, 5, 9]),
                "branches": rng.choice([0, 1, 3, 3, 8]),
            }

        a = [sig() for _ in range(70)]
        b = [sig() for _ in range(55)]
        a.append({"histogram": {}, "calls": 0, "branches": 0})
        b.append({"histogram": {}, "calls": 0, "branches": 0})
        got = score_matrix(a, b)
        assert got.shape == (71, 56)
        assert got[-1, -1] == pytest.approx(40.0)  # both empty: cosine 0, counts agree
        assert np.array_equal(got, _old_score_matrix(a, b))

    @pytest.mark.parametrize(("na", "nb"), [(0, 3), (3, 0), (1, 1)])
    def test_degenerate_shapes(self, na: int, nb: int) -> None:
        from rebrew.binary_similarity import score_matrix

        sig = {"histogram": {"mov": 2}, "calls": 1, "branches": 0}
        got = score_matrix([sig] * na, [sig] * nb)
        assert got.shape == (na, nb)
        assert (got == 100.0).all()
