"""Tests for the binary similarity search (`rebrew similar`)."""

from pathlib import Path
from typing import Any

import pytest

import rebrew.similar as similar_mod

# Hand-crafted 32-bit x86 blobs.
_CALL_RET = b"\xe8\x00\x00\x00\x00\xc3"  # call +0; ret
_RET = b"\xc3"  # ret
_JMP_RET = b"\xeb\x00\xc3"  # jmp short +0; ret
_THREE_RETS = b"\xc3\xc3\xc3"  # ret; ret; ret


class TestDisasmSignature:
    def test_ret(self) -> None:
        sig = similar_mod._disasm_signature(_RET, 0x1000, "CS_ARCH_X86", "CS_MODE_32")
        assert sig is not None
        assert sig["histogram"] == {"ret": 1}
        assert sig["calls"] == 0
        assert sig["branches"] == 0

    def test_call_and_branch_counts(self) -> None:
        sig = similar_mod._disasm_signature(_CALL_RET, 0x1000, "CS_ARCH_X86", "CS_MODE_32")
        assert sig is not None
        assert sig["calls"] == 1
        assert sig["histogram"]["ret"] == 1

        jmp_sig = similar_mod._disasm_signature(_JMP_RET, 0x1000, "CS_ARCH_X86", "CS_MODE_32")
        assert jmp_sig is not None
        assert jmp_sig["branches"] == 1

    def test_empty_returns_none(self) -> None:
        assert similar_mod._disasm_signature(b"", 0x1000, "CS_ARCH_X86", "CS_MODE_32") is None


class TestCosine:
    def test_identical(self) -> None:
        assert similar_mod._cosine({"mov": 3, "ret": 1}, {"mov": 3, "ret": 1}) == pytest.approx(1.0)

    def test_disjoint(self) -> None:
        assert similar_mod._cosine({"mov": 1}, {"ret": 1}) == pytest.approx(0.0)

    def test_partial(self) -> None:
        score = similar_mod._cosine({"a": 1, "b": 1}, {"a": 1})
        assert 0.0 < score < 1.0


class TestSimilarityScore:
    def test_identical_sigs_score_100(self) -> None:
        sig = similar_mod._disasm_signature(_CALL_RET, 0, "CS_ARCH_X86", "CS_MODE_32")
        assert similar_mod.similarity_score(sig, sig) == 100.0

    def test_none_returns_zero(self) -> None:
        sig = similar_mod._disasm_signature(_CALL_RET, 0, "CS_ARCH_X86", "CS_MODE_32")
        assert similar_mod.similarity_score(sig, None) == 0.0
        assert similar_mod.similarity_score(None, sig) == 0.0

    def test_different_sigs_score_lower(self) -> None:
        a = similar_mod._disasm_signature(_CALL_RET, 0, "CS_ARCH_X86", "CS_MODE_32")
        b = similar_mod._disasm_signature(_THREE_RETS, 0, "CS_ARCH_X86", "CS_MODE_32")
        assert 0.0 < similar_mod.similarity_score(a, b) < 100.0


class TestFindSimilar:
    def _setup(
        self, monkeypatch: pytest.MonkeyPatch, extract: dict[int, bytes]
    ) -> list[dict[str, Any]]:
        registry: dict[int, dict[str, Any]] = {
            0x1000: {"canonical_size": 6, "list_name": "_query", "ghidra_name": ""},
            0x2000: {"canonical_size": 6, "list_name": "_twin", "ghidra_name": ""},
            0x3000: {"canonical_size": 3, "list_name": "_other", "ghidra_name": ""},
        }
        monkeypatch.setattr("rebrew.catalog.parse_function_list", lambda path: [])
        monkeypatch.setattr(
            "rebrew.catalog.build_function_registry",
            lambda funcs, cfg, ghidra, bin_path: registry,
        )
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_raw_bytes",
            lambda binary, va, size: extract.get(va, b""),
        )
        cfg = type(
            "Cfg",
            (),
            {
                "capstone_arch": "CS_ARCH_X86",
                "capstone_mode": "CS_MODE_32",
                "function_list": "functions.txt",
                "reversed_dir": Path("/tmp"),
                "target_binary": Path("/tmp/target.dll"),
            },
        )()

        def run(**kw: Any) -> list[dict[str, Any]]:
            return similar_mod.find_similar(cfg, 0x1000, **kw)

        return [run, registry]

    def test_ranks_and_excludes_query(self, monkeypatch: pytest.MonkeyPatch) -> None:
        run, _reg = self._setup(
            monkeypatch,
            {
                0x1000: _CALL_RET,
                0x2000: _CALL_RET,  # identical to query
                0x3000: _THREE_RETS,  # different
            },
        )
        results = run()
        vas = [r["va"] for r in results]
        assert vas == ["0x00002000", "0x00003000"]
        assert "0x00001000" not in vas
        assert results[0]["score"] == 100.0
        assert results[0]["name"] == "_twin"
        assert results[0]["size"] == 6

    def test_min_score_filters(self, monkeypatch: pytest.MonkeyPatch) -> None:
        run, _reg = self._setup(
            monkeypatch,
            {
                0x1000: _CALL_RET,
                0x2000: _CALL_RET,
                0x3000: _THREE_RETS,
            },
        )
        results = run(min_score=70.0)
        assert [r["va"] for r in results] == ["0x00002000"]

    def test_top_limits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        run, _reg = self._setup(
            monkeypatch,
            {
                0x1000: _CALL_RET,
                0x2000: _CALL_RET,
                0x3000: _THREE_RETS,
            },
        )
        results = run(top=1)
        assert [r["va"] for r in results] == ["0x00002000"]


class TestFindSimilarEdgeCases:
    def test_query_extract_none_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Empty bytes → _disasm_signature returns None → no results.
        run, _ = TestFindSimilar()._setup(monkeypatch, {0x1000: b""})
        assert run() == []

    def test_query_sig_none_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.similar as similar_mod

        run, _ = TestFindSimilar()._setup(monkeypatch, {0x1000: b"\x90" * 6})
        monkeypatch.setattr(similar_mod, "_disasm_signature", lambda *a, **k: None)
        assert run() == []

    def test_zero_size_candidates_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        run, registry = TestFindSimilar()._setup(monkeypatch, {0x1000: b"\x90" * 6})
        registry[0x2000]["canonical_size"] = 0
        results = run()
        # 0x3000 (canonical 3) still compares; 0x2000 is skipped.
        assert all(r["va"] != "0x00002000" for r in results)

    def test_candidate_sig_none_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.similar as similar_mod

        run, _ = TestFindSimilar()._setup(monkeypatch, {0x1000: b"\x90" * 6, 0x2000: b"\x90" * 6})
        real_sig = similar_mod._disasm_signature

        def _sig(code, va, cs_arch, cs_mode):
            if va == 0x2000:
                return None
            return real_sig(code, va, cs_arch, cs_mode)

        monkeypatch.setattr(similar_mod, "_disasm_signature", _sig)
        results = run()
        assert all(r["va"] != "0x00002000" for r in results)

    def test_cosine_zero_denominator(self) -> None:
        from rebrew.similar import _cosine

        assert _cosine({}, {}) == 0.0
        assert _cosine({"push": 2}, {}) == 0.0

    def test_ratio_zero_side(self) -> None:
        from rebrew.similar import _ratio

        assert _ratio(0, 5) == 0.0
        assert _ratio(5, 0) == 0.0
        assert _ratio(0, 0) == 1.0  # a == b
        assert _ratio(4, 2) == 0.5


class TestDisasmSignatureIntConstants:
    def test_accepts_int_constants(self) -> None:
        """cfg.capstone_arch/capstone_mode return ints; Cs must accept them."""
        import capstone

        sig = similar_mod._disasm_signature(
            _CALL_RET, 0x1000, capstone.CS_ARCH_X86, capstone.CS_MODE_32
        )
        assert sig is not None
        assert sig["calls"] == 1
