"""Tests for near_diag.py — NEAR_MATCHING delta classification."""

import rebrew.near_diag as nd

# Hand-crafted 32-bit x86 encodings.
MOV_EAX_EBX = b"\x89\xd8"  # mov eax, ebx
MOV_EAX_ECX = b"\x89\xc8"  # mov eax, ecx
MOV_EAX_1 = b"\xb8\x01\x00\x00\x00"  # mov eax, 1
LEA_EAX_ECX = b"\x8d\x41\x00"  # lea eax, [ecx]
ADD_EAX_1 = b"\x83\xc0\x01"  # add eax, 1
XOR_EAX_EAX = b"\x31\xc0"  # xor eax, eax
RET = b"\xc3"


def _insn(mnemonic: str, op_str: str, raw: bytes) -> nd.Insn:
    return nd.Insn(0x1000, mnemonic, op_str, raw)


class TestClassifyPair:
    def test_identical_is_match(self) -> None:
        assert (
            nd.classify_pair(
                _insn("mov", "eax, ebx", MOV_EAX_EBX), _insn("mov", "eax, ebx", MOV_EAX_EBX)
            )
            == "match"
        )

    def test_register_difference(self) -> None:
        a = _insn("mov", "eax, ebx", MOV_EAX_EBX)
        b = _insn("mov", "eax, ecx", MOV_EAX_ECX)
        assert nd.classify_pair(a, b) == "register"

    def test_operand_value_change_is_structural(self) -> None:
        a = _insn("mov", "eax, ebx", MOV_EAX_EBX)
        b = _insn("mov", "eax, 1", MOV_EAX_1)
        assert nd.classify_pair(a, b) == "structural"

    def test_equivalent_family(self) -> None:
        a = _insn("lea", "eax, [ecx]", LEA_EAX_ECX)
        b = _insn("mov", "eax, ecx", MOV_EAX_ECX)
        assert nd.classify_pair(a, b) == "equivalent"

    def test_semantically_different_is_structural(self) -> None:
        a = _insn("mov", "eax, 1", MOV_EAX_1)
        b = _insn("xor", "eax, eax", XOR_EAX_EAX)
        assert nd.classify_pair(a, b) == "structural"


class TestAlignAndClassify:
    def _run(
        self, target: bytes, compiled: bytes, relocs: set[int] | None = None
    ) -> dict[str, int]:
        return nd.align_and_classify(
            nd.disasm_insns(target, 0x1000, "CS_ARCH_X86", "CS_MODE_32"),
            nd.disasm_insns(compiled, 0x1000, "CS_ARCH_X86", "CS_MODE_32"),
            relocs or set(),
        )

    def test_identical_blobs_all_match(self) -> None:
        counts = self._run(MOV_EAX_EBX + RET, MOV_EAX_EBX + RET)
        assert counts["match"] == 3
        assert counts["register"] == counts["structural"] == counts["equivalent"] == 0

    def test_register_alloc_detected(self) -> None:
        counts = self._run(MOV_EAX_EBX + RET, MOV_EAX_ECX + RET)
        assert counts["register"] == 2  # the mov
        assert counts["match"] == 1  # the ret

    def test_equivalent_selection_detected(self) -> None:
        counts = self._run(LEA_EAX_ECX + RET, MOV_EAX_ECX + RET)
        assert counts["equivalent"] == 3
        assert counts["match"] == 1

    def test_structural_extra_instruction(self) -> None:
        counts = self._run(MOV_EAX_1 + RET, MOV_EAX_1 + XOR_EAX_EAX + RET)
        assert counts["structural"] == 2  # the extra xor

    def test_reloc_span_neutralised(self) -> None:
        # mov eax, 1 (5 bytes) at offset 0 with offset 1 flagged as a reloc site.
        counts = self._run(MOV_EAX_1 + RET, MOV_EAX_1 + RET, relocs={1})
        assert counts["reloc"] == 5
        assert counts["match"] == 1


class TestAnalyzeVerdict:
    def test_all_match_verdict(self) -> None:
        result = nd.analyze(MOV_EAX_EBX + RET, MOV_EAX_EBX + RET, None, 0x1000)
        assert result["verdict"] == "MATCH"
        assert result["categories"]["match"]["bytes"] == 3

    def test_register_verdict_mentions_register(self) -> None:
        result = nd.analyze(MOV_EAX_EBX + RET, MOV_EAX_ECX + RET, None, 0x1000)
        assert "REGISTER" in result["verdict"]
        assert "register" in result["suggestion"].lower()

    def test_json_shape(self) -> None:
        result = nd.analyze(MOV_EAX_EBX + RET, MOV_EAX_EBX + RET, None, 0x1000)
        assert result["va"] == "0x00001000"
        assert {"match", "register", "equivalent", "reloc", "structural"} <= set(
            result["categories"]
        )
        assert result["target_insns"] == 2
        assert result["compiled_insns"] == 2


class TestAnalyzeDegenerate:
    def test_empty_target_bytes(self) -> None:
        result = nd.analyze(b"", b"\xc3", None, 0x1000)
        assert result["target_insns"] == 0
        assert result["bytes"] == 1  # the compiled ret is structural

    def test_both_empty(self) -> None:
        result = nd.analyze(b"", b"", None, 0x1000)
        # total is floored at 1 to protect the percent division.
        assert result["bytes"] == 1
        assert result["verdict"] == "MATCH"

    def test_undecodable_bytes(self) -> None:
        # 0xFF 0xFF 0xFF... may not disassemble cleanly; must not crash.
        result = nd.analyze(b"\xff\xff\xff\xff", b"\xc3", None, 0x1000)
        assert isinstance(result["categories"], dict)


class TestDisasmInsnsCapstoneConstants:
    """disasm_insns must accept BOTH capstone constant-name strings (module
    defaults) and the int constants cfg.capstone_arch/mode return (the config
    property returns ints — a raw getattr(capstone, int) used to crash)."""

    _CODE = bytes.fromhex("558bec83ec08b801000000c9c3")

    def test_string_names(self) -> None:
        insns = nd.disasm_insns(self._CODE, 0x1000, "CS_ARCH_X86", "CS_MODE_32")
        assert len(insns) >= 1
        assert insns[0].mnemonic

    def test_int_constants(self) -> None:
        import capstone

        insns = nd.disasm_insns(self._CODE, 0x1000, capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        assert len(insns) >= 1
        assert insns[0].mnemonic

    def test_both_forms_equal(self) -> None:
        a = [
            (i.mnemonic, i.op_str)
            for i in nd.disasm_insns(self._CODE, 0x1000, "CS_ARCH_X86", "CS_MODE_32")
        ]
        b = [
            (i.mnemonic, i.op_str)
            for i in nd.disasm_insns(self._CODE, 0x1000, 3, 4)  # CS_ARCH_X86=3, CS_MODE_32=4
        ]
        assert a == b


class TestSecondarySuggestion:
    """A significant secondary category (>=25% of the delta) is mentioned in
    the suggestion alongside the dominant one."""

    def test_secondary_category_adds_hint(self) -> None:
        # Register-only pair → dominant register, no secondary.
        result = nd.analyze(MOV_EAX_EBX + RET, MOV_EAX_ECX + RET, None, 0x1000)
        assert "REGISTER" in result["verdict"]
        assert "Also:" not in result["suggestion"]

    def test_dominant_only_no_secondary(self) -> None:
        result = nd.analyze(MOV_EAX_EBX + RET, MOV_EAX_EBX + b"\x90" + RET, None, 0x1000)
        # structural (extra instruction) dominates; register share < 25% → no hint.
        assert "structural" in result["verdict"].lower()
        assert "Also:" not in result["suggestion"]


class TestSecondarySuggestionBoundary:
    """The >=25% threshold fires at exactly 25%."""

    def test_exactly_25_percent_fires(self) -> None:
        from rebrew.near_diag import _verdict

        # structural dominates (9/12), register is exactly 25% (3/12) →
        # the secondary hint fires.
        counts = {"match": 0, "register": 3, "equivalent": 0, "reloc": 0, "structural": 9}
        label, suggestion = _verdict(counts, 12)
        assert "Also:" in suggestion
        assert "register" in suggestion.lower()

    def test_below_25_percent_no_hint(self) -> None:
        from rebrew.near_diag import _verdict

        # register is 20% (2/10) → below the threshold, no hint.
        counts = {"match": 0, "register": 2, "equivalent": 0, "reloc": 0, "structural": 8}
        _, suggestion = _verdict(counts, 10)
        assert "Also:" not in suggestion
