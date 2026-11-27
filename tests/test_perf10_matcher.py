"""Invariants of the LCS mnemonic matcher (measured by tools/bench_perf10_matcher.py)."""

import difflib
import itertools
import random
from typing import Any

import numpy as np
import pytest
from rapidfuzz.distance import LCSseq

from rebrew.matcher import scoring
from rebrew.matcher.scoring import _LcsMatcher, _mnemonic_matcher

_Sig = dict[str, Any]


def _assert_valid_lcs(a: list[str], b: list[str]) -> None:
    got = _LcsMatcher(a, b)
    blocks = got.get_matching_blocks()
    assert blocks[-1] == difflib.Match(len(a), len(b), 0), (a, b)
    prev_i = prev_j = -1
    for blk in blocks[:-1]:
        assert blk.size > 0
        assert blk.a >= prev_i and blk.b >= prev_j
        assert not (blk.a == prev_i and blk.b == prev_j), f"adjacent blocks not merged: {blocks}"
        assert a[blk.a : blk.a + blk.size] == b[blk.b : blk.b + blk.size]
        prev_i = blk.a + blk.size
        prev_j = blk.b + blk.size
    matched = sum(blk.size for blk in blocks)
    assert matched == LCSseq.similarity(a, b), (a, b)
    ref_matched = sum(
        blk.size
        for blk in difflib.SequenceMatcher(None, a, b, autojunk=False).get_matching_blocks()
    )
    assert matched >= ref_matched, (a, b)

    opcodes = got.get_opcodes()
    ai = bj = 0
    rebuilt: list[str] = []
    prev_tag = ""
    for tag, i1, i2, j1, j2 in opcodes:
        assert (i1, j1) == (ai, bj), (a, b, opcodes)
        assert not (tag == "equal" and prev_tag == "equal"), opcodes
        if tag == "equal":
            assert a[i1:i2] == b[j1:j2]
            rebuilt.extend(a[i1:i2])
        elif tag in ("replace", "insert"):
            rebuilt.extend(b[j1:j2])
        elif tag == "delete":
            assert j1 == j2
        else:
            raise AssertionError(f"unexpected tag {tag!r}")
        ai, bj = i2, j2
        prev_tag = tag
    assert (ai, bj) == (len(a), len(b)), (a, b, opcodes)
    assert rebuilt == b, (a, b, opcodes)


def _sequences(alphabet: str, max_len: int) -> list[list[str]]:
    return [list(t) for n in range(max_len + 1) for t in itertools.product(alphabet, repeat=n)]


def _assert_valid_up_to_renaming(alphabet: str, max_len: int) -> None:
    """Every pair over *alphabet* up to *max_len*, one pair per renaming of the symbols."""
    seqs = _sequences(alphabet, max_len)
    for a in seqs:
        for b in seqs:
            used = list(dict.fromkeys(a + b))
            if used == list(alphabet[: len(used)]):
                _assert_valid_lcs(a, b)


class TestLcsMatcher:
    def test_exhaustive_binary_alphabet(self) -> None:
        _assert_valid_up_to_renaming("ab", 7)

    def test_exhaustive_ternary_alphabet(self) -> None:
        _assert_valid_up_to_renaming("abc", 4)

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
            _assert_valid_lcs(a, b)
            _assert_valid_lcs(a, [rng.choice(vocab) for _ in range(rng.randint(0, 90))])

    def test_single_replacement_emits_replace_not_insert_and_delete(self) -> None:
        got = _LcsMatcher(["mov", "push", "pop"], ["mov", "xor", "pop"])
        assert got.get_opcodes() == [
            ("equal", 0, 1, 0, 1),
            ("replace", 1, 2, 1, 2),
            ("equal", 2, 3, 2, 3),
        ]

    def test_adjacent_blocks_report_one_equal_opcode(self) -> None:
        a = list("aabbaabb")
        got = _LcsMatcher(a, a + ["z"])
        assert [op for op in got.get_opcodes() if op[0] == "equal"] == [("equal", 0, 8, 0, 8)]


class TestLcsMatcherState:
    def test_replacing_a_sequence_drops_the_cached_blocks(self) -> None:
        m = _LcsMatcher(list("abcabc"), list("abcabc"))
        assert m.get_matching_blocks()[0] == (0, 0, 6)
        m.set_seq2(list("xabcabcx"))
        assert m.get_matching_blocks() == [
            difflib.Match(0, 1, 6),
            difflib.Match(6, 8, 0),
        ]
        m.set_seq1(list("abcx"))
        assert sum(b.size for b in m.get_matching_blocks()) == 4


class TestMatcherSelection:
    def test_mnemonic_matcher_uses_lcs_matcher(self) -> None:
        assert type(_mnemonic_matcher(["mov"] * 10, ["mov"] * 10)) is _LcsMatcher
        assert type(_mnemonic_matcher(["mov"] * 200, ["push"] * 200)) is _LcsMatcher

    def test_score_candidate_uses_lcs_matcher_on_repetitive_streams(self) -> None:
        body = b"\x8b\xc1\x50\x8b\xd8\x53" * 50  # repetitive: mov/push/mov/push
        target = b"\x55\x8b\xec" + body + b"\x5d\xc3"
        spaced = b"".join(
            body[i : i + 6] + (b"\x90" if i % 18 == 0 else b"") for i in range(0, 300, 6)
        )
        cand = b"\x55\x8b\xec" + spaced + b"\x5d\xc3"
        score = scoring.score_candidate(target, cand)
        assert score.mnemonic_score > 0
        # Exact copy scores 0 mnemonic diff.
        assert scoring.score_candidate(target, target).mnemonic_score == 0.0


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


class TestNormalizationWork:
    """Work and parity gates for raw disp32 normalization."""

    def test_standard_modrm_disp32_skips_capstone_detail_and_matches_detail_bytes(self) -> None:
        import struct

        import capstone

        from rebrew.matcher import scoring

        md_det = scoring.get_cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32, detail=True)

        class _FailDetail:
            def disasm(self, *_args: object, **_kwargs: object) -> object:
                raise AssertionError("standard ModR/M+SIB disp32 must not fall back to detail mode")

        disps = (
            0,
            0x10000,
            0x10001,
            0x7FFFFFFF,
            0x80000000,
            0xFFFEFFFF,
            0xFFFF0000,
            0xFFFFF000,
        )
        for disp_u32 in disps:
            dbytes = struct.pack("<I", disp_u32)
            samples = (
                b"\x8d\x05" + dbytes,  # lea eax, [disp32]
                b"\x8d\x04\x85" + dbytes,  # lea eax, [eax*4 + disp32]
                b"\x8d\x85" + dbytes,  # lea eax, [ebp + disp32]
                b"\x8b\x80" + dbytes,  # mov eax, [eax + disp32]
                b"\x89\x84\x85" + dbytes,  # mov [ebp + eax*4 + disp32], eax
                b"\x03\x05" + dbytes,  # add eax, [disp32]
                b"\x3b\x04\x85" + dbytes,  # cmp eax, [eax*4 + disp32]
                b"\xc7\x85" + dbytes + b"\x11\x22\x33\x44",  # mov dword ptr [ebp+disp32], imm32
                b"\x81\x85" + dbytes + b"\x11\x22\x33\x44",  # add dword ptr [ebp+disp32], imm32
                b"\x83\x85" + dbytes + b"\x11",  # add dword ptr [ebp+disp32], imm8
            )
            for code in samples:
                out_raw = bytearray(code)
                scoring._zero_reloc_fields_raw(0, len(code), code, out_raw, _FailDetail())  # type: ignore[arg-type]
                out_det = bytearray(code)
                for insn in md_det.disasm(code, 0):
                    scoring._zero_reloc_fields(insn, out_det)
                assert out_raw == out_det, (code.hex(), out_raw.hex(), out_det.hex())
