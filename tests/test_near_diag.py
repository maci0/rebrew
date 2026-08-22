"""Tests for near_diag.py — NEAR_MATCHING delta classification."""

from pathlib import Path
from typing import Any

import rebrew.near_diag as nd

# Hand-crafted 32-bit x86 encodings.
MOV_EAX_EBX = b"\x89\xd8"  # mov eax, ebx
MOV_EAX_ECX = b"\x89\xc8"  # mov eax, ecx
MOV_EAX_1 = b"\xb8\x01\x00\x00\x00"  # mov eax, 1
MOV_EAX_2 = b"\xb8\x02\x00\x00\x00"  # mov eax, 2
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
        # Register-dominant WITH structural churn → REGISTER verdict (the
        # register-only case is the EFFECTIVE verdict, tested separately).
        result = nd.analyze(MOV_EAX_EBX + RET, MOV_EAX_ECX + XOR_EAX_EAX + RET, None, 0x1000)
        assert "REGISTER" in result["verdict"]
        assert "register" in result["suggestion"].lower()

    def test_register_only_is_effective(self) -> None:
        """A delta that is ENTIRELY register allocation is reccmp's 100%
        effective match — the verdict must name it (not byte-identical, but
        the cause is register allocation, and the register mutations are the
        actionable list)."""
        result = nd.analyze(MOV_EAX_EBX + RET, MOV_EAX_ECX + RET, None, 0x1000)
        assert result["verdict"].startswith("EFFECTIVE")
        assert "register-allocation" in result["suggestion"]
        assert "not byte-identical" in result["suggestion"].lower()
        assert "mut_reorder_register_vars" in result["mutations"]

    def test_register_dominant_mixed_is_not_effective(self) -> None:
        """Register-dominant with structural churn is a REGISTER verdict, not
        EFFECTIVE — real bytes differ structurally."""
        # mov eax,ebx; ret  vs  mov eax,ecx; xor eax,eax; ret  (extra xor)
        result = nd.analyze(MOV_EAX_EBX + RET, MOV_EAX_ECX + XOR_EAX_EAX + RET, None, 0x1000)
        assert result["verdict"].startswith("REGISTER")
        assert not result["verdict"].startswith("EFFECTIVE")

    def test_equivalent_only_is_not_effective(self) -> None:
        """Instruction-selection swaps (lea vs mov) are equivalent, not
        register allocation — no EFFECTIVE verdict."""
        result = nd.analyze(LEA_EAX_ECX + RET, MOV_EAX_ECX + RET, None, 0x1000)
        assert not result["verdict"].startswith("EFFECTIVE")

    def test_json_shape(self) -> None:
        result = nd.analyze(MOV_EAX_EBX + RET, MOV_EAX_EBX + RET, None, 0x1000)
        assert result["va"] == "0x00001000"
        assert {"match", "register", "equivalent", "reloc", "structural"} <= set(
            result["categories"]
        )
        assert result["target_insns"] == 2
        assert result["compiled_insns"] == 2

    def test_frame_field_present(self) -> None:
        """analyze() must carry the stack-frame comparison (stack-cmp) as a
        best-effort frame dict — no stack ops → frames match."""
        result = nd.analyze(MOV_EAX_EBX + RET, MOV_EAX_ECX + RET, None, 0x1000)
        frame = result["frame"]
        assert isinstance(frame, dict)
        assert frame["frame_match"] is True
        assert frame["slots"]["target"] == []

    def test_cfg_field_present(self) -> None:
        """analyze() must carry the CFG structural similarity (cfg_ged) as a
        best-effort cfg dict."""
        result = nd.analyze(MOV_EAX_EBX + RET, MOV_EAX_ECX + RET, None, 0x1000)
        cfg = result["cfg"]
        assert isinstance(cfg, dict)
        assert "overall" in cfg
        assert cfg["overall"] == 100.0  # straight-line flow, register swap only

    def test_catalog_markdown_has_all_categories(self) -> None:
        md = nd.catalog_markdown()
        for cat in ("register", "equivalent", "structural", "reloc", "effective", "match"):
            assert f"`{cat}`" in md
        assert "mut_reorder_register_vars" in md  # a real operator name
        assert "|" in md


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
        # Register-dominant with a negligible structural component (1 nop) →
        # dominant register, secondary below the 25% threshold → no hint.
        result = nd.analyze(
            MOV_EAX_EBX + MOV_EAX_EBX + RET,
            MOV_EAX_ECX + MOV_EAX_ECX + b"\x90" + RET,
            None,
            0x1000,
        )
        assert "REGISTER" in result["verdict"]
        assert "Also:" not in result["suggestion"]

    def test_dominant_only_no_secondary(self) -> None:
        result = nd.analyze(MOV_EAX_EBX + RET, MOV_EAX_EBX + b"\x90" + RET, None, 0x1000)
        # structural (extra instruction) dominates; register share < 25% → no hint.
        assert "structural" in result["verdict"].lower()
        assert "Also:" not in result["suggestion"]


class TestRelocVerdictHonesty:
    """A RELOC-dominant verdict must not claim "RELOC-level" when real
    (invalid-reloc) bytes differ — the canonical status is then NEAR_MATCHING."""

    def _verdict(self, counts: dict[str, int], total: int) -> tuple[str, str]:
        from rebrew.near_diag import _verdict

        return _verdict(counts, total)

    def test_reloc_with_real_bytes_names_them(self) -> None:
        label, suggestion = self._verdict(
            {"match": 0, "register": 0, "equivalent": 0, "reloc": 90, "structural": 10},
            100,
        )
        assert "RELOC" in label
        assert "NEAR_MATCHING-level" in suggestion
        assert "RELOC-level" not in suggestion
        assert "10 real byte(s)" in suggestion

    def test_reloc_without_real_bytes_stays_reloc_level(self) -> None:
        _, suggestion = self._verdict(
            {"match": 0, "register": 0, "equivalent": 0, "reloc": 100, "structural": 0},
            100,
        )
        assert "RELOC-level" in suggestion


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


class TestMutationSuggestions:
    """H6: every verdict category maps to GA mutation operators."""

    def test_every_category_has_suggestions_or_is_reloc(self) -> None:
        from rebrew.near_diag import _MUTATION_SUGGESTIONS

        for category in ("register", "equivalent", "structural"):
            assert _MUTATION_SUGGESTIONS[category], f"{category} has no suggestions"
        # reloc is RELOC-level — deliberately no mutation suggestions.
        assert _MUTATION_SUGGESTIONS["reloc"] == []

    def test_operators_exist_in_mutator(self) -> None:
        """Every suggested operator must be a real mut_* in mutator.py."""
        import re
        from pathlib import Path

        from rebrew.matcher import mutator
        from rebrew.near_diag import _MUTATION_SUGGESTIONS

        source = Path(mutator.__file__).read_text(encoding="utf-8")
        defined = set(re.findall(r"^def (mut_\w+)\(", source, re.M))
        for category, ops in _MUTATION_SUGGESTIONS.items():
            for op in ops:
                assert op in defined, f"{op} (for {category}) not in mutator.py"

    def test_analyze_returns_mutations(self) -> None:
        from rebrew.near_diag import analyze

        target = bytes.fromhex("55 8b ec 8b 45 08 5d c3")  # mov eax, [ebp+8]
        compiled = bytes.fromhex("55 8b ec 8b 45 0c 5d c3")  # mov eax, [ebp+0xc]
        result = analyze(target, compiled, {}, 0x401000)
        assert "mutations" in result
        # register-dominant verdict → register operators suggested.
        if result["verdict"].startswith("REGISTER"):
            assert result["mutations"]

    def test_secondary_category_adds_operators(self) -> None:
        """A structural-dominant delta with a >=15% register component must
        suggest BOTH categories' operators — the register fix is otherwise
        invisible."""
        from rebrew.near_diag import analyze, mutation_suggestions

        target = MOV_EAX_1 * 3 + MOV_EAX_EBX * 2 + RET
        compiled = MOV_EAX_2 * 3 + MOV_EAX_ECX * 2 + RET
        result = analyze(target, compiled, {}, 0x1000)
        # 3x mov eax,1 vs mov eax,2 → structural (immediates differ); the
        # register pair is the 2 same-mnemonic movs with different registers.
        assert result["verdict"].startswith("STRUCTURAL"), result["verdict"]
        mutations = result["mutations"]
        reg_ops = mutation_suggestions("register")
        struct_ops = mutation_suggestions("structural")
        assert any(op in mutations for op in struct_ops)
        # The register component must contribute its operators too.
        assert any(op in mutations for op in reg_ops)


class TestFixBlocker:
    """near-diag --fix-blocker writes the verdict as BLOCKER metadata."""

    def test_blocker_text_non_match(self) -> None:
        from rebrew.near_diag import _blocker_text

        text = _blocker_text(
            {"verdict": "REGISTER (90% of delta)", "suggestion": "Register allocation differs."}
        )
        assert text.startswith("NEAR_MATCHING — REGISTER")
        assert "Register allocation" in text

    def test_blocker_text_short(self) -> None:
        from rebrew.near_diag import _blocker_text

        assert len(_blocker_text({"verdict": "STRUCTURAL", "suggestion": "x" * 500})) <= 200

    def test_blocker_text_includes_mutations(self) -> None:
        from rebrew.near_diag import _blocker_text

        text = _blocker_text(
            {
                "verdict": "REGISTER (75% of delta)",
                "suggestion": "Register allocation differs.",
                "mutations": ["mut_swap_register_keywords", "mut_add_register_keyword"],
            }
        )
        assert "try: mut_swap_register_keywords, mut_add_register_keyword" in text
        assert "Register allocation" in text
        assert len(text) <= 200

    def test_blocker_text_mutations_outrank_suggestion_tail(self) -> None:
        from rebrew.near_diag import _blocker_text

        # A huge mutation list + long suggestion must keep the mutations and
        # the suggestion's first sentence (or drop the tail), never exceed 200.
        text = _blocker_text(
            {
                "verdict": "STRUCTURAL (99% of delta)",
                "suggestion": "Control flow / block layout differs. " + "x" * 400,
                "mutations": [f"mut_m{i}" for i in range(16)],
            }
        )
        assert "try: mut_m0, mut_m1, mut_m2, mut_m3, mut_m4" in text
        assert len(text) <= 200

    def test_cli_writes_blocker(self, tmp_path: Path, monkeypatch, capsys) -> None:
        from types import SimpleNamespace as NS

        from typer.testing import CliRunner

        from rebrew.near_diag import app

        cfg = NS(
            root=tmp_path,
            reversed_dir=tmp_path,
            metadata_dir=tmp_path,
            marker="S",
            source_ext=".c",
            target_name="S",
            target_binary=tmp_path / "x.exe",
        )
        monkeypatch.setattr(
            "rebrew.near_diag.require_config", lambda target=None, json_mode=False: cfg
        )
        monkeypatch.setattr("rebrew.cli.resolve_source_arg", lambda cfg, s: s)
        src = tmp_path / "f.c"
        src.write_text(
            "// FUNCTION: S 0x1000\n// SIZE: 8\nint f(void) { return 0; }\n",
            encoding="utf-8",
        )
        calls: list[object] = []
        monkeypatch.setattr(
            "rebrew.metadata.set_field",
            lambda *a, **k: calls.append((a, k)),
        )
        # Mock the analysis pipeline so no compile is needed.
        monkeypatch.setattr(
            "rebrew.near_diag.analyze",
            lambda *a, **k: {
                "verdict": "REGISTER (90% of delta)",
                "suggestion": "Register allocation differs.",
                "mutations": [],
                "categories": {},
            },
        )
        monkeypatch.setattr(
            "rebrew.annotation.parse_c_file_multi",
            lambda *a, **k: [NS(va=0x1000, size=8, symbol="_f", module="S", cflags="")],
        )
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_raw_bytes", lambda *a, **k: b"\x55\x8b\xec\x5d\xc3"
        )
        monkeypatch.setattr("rebrew.compile.compile_to_obj", lambda *a, **k: (Path("o.obj"), ""))
        monkeypatch.setattr(
            "rebrew.matcher.parsers.parse_obj_symbol_and_relocs",
            lambda *a, **k: (b"\x90" * 8, {}, []),
        )
        result = CliRunner().invoke(app, ["--fix-blocker", str(src)])
        assert result.exit_code == 0, result.output
        assert len(calls) == 1
        args, kwargs = calls[0]
        assert args[1] == 0x1000  # va
        assert args[2] == "blocker"
        assert "NEAR_MATCHING — REGISTER" in args[3]


class TestAllBatch:
    """near-diag --all classifies every NEAR_MATCHING function."""

    def _invoke(
        self,
        monkeypatch,
        tmp_path: Path,
        args: list[str],
        annos,
        compile_fn=None,
    ) -> Any:
        from types import SimpleNamespace as NS

        from typer.testing import CliRunner

        from rebrew.near_diag import app

        cfg = NS(
            root=tmp_path,
            reversed_dir=tmp_path,
            metadata_dir=tmp_path,
            marker="S",
            source_ext=".c",
            target_name="S",
            target_binary=tmp_path / "x.exe",
        )
        monkeypatch.setattr(
            "rebrew.near_diag.require_config", lambda target=None, json_mode=False: cfg
        )
        monkeypatch.setattr("rebrew.cli.iter_sources", lambda *a, **k: [tmp_path / "f.c"])
        monkeypatch.setattr("rebrew.annotation.parse_c_file_multi", lambda *a, **k: annos)
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_raw_bytes", lambda *a, **k: b"\x55\x8b\xec\x5d\xc3"
        )
        monkeypatch.setattr(
            "rebrew.compile.compile_to_obj",
            compile_fn or (lambda *a, **k: (Path("o.obj"), "")),
        )
        monkeypatch.setattr(
            "rebrew.matcher.parsers.parse_obj_symbol_and_relocs",
            lambda *a, **k: (b"\x90" * 8, {}, []),
        )
        monkeypatch.setattr(
            "rebrew.near_diag.analyze",
            lambda *a, **k: {
                "verdict": "REGISTER (90% of delta)",
                "suggestion": "Register allocation differs.",
                "mutations": ["mut_swap_register_keywords"],
                "categories": {"register": {"bytes": 7, "percent": 90.0}},
            },
        )
        calls: list[object] = []
        monkeypatch.setattr("rebrew.metadata.set_field", lambda *a, **k: calls.append((a, k)))
        result = CliRunner().invoke(app, args)
        return result, calls

    def test_all_with_source_arg_errors(self, monkeypatch, tmp_path: Path) -> None:
        from types import SimpleNamespace as NS

        from typer.testing import CliRunner

        from rebrew.near_diag import app

        monkeypatch.setattr(
            "rebrew.near_diag.require_config",
            lambda target=None, json_mode=False: NS(
                root=tmp_path,
                reversed_dir=tmp_path,
                metadata_dir=tmp_path,
                marker="S",
                source_ext=".c",
                target_name="S",
                target_binary=tmp_path / "x.exe",
            ),
        )
        result = CliRunner().invoke(app, ["--all", "somefile.c"])
        assert result.exit_code == 2
        assert "cannot be combined with --all" in result.output

    def test_all_with_va_errors(self, monkeypatch, tmp_path: Path) -> None:
        from types import SimpleNamespace as NS

        from typer.testing import CliRunner

        from rebrew.near_diag import app

        monkeypatch.setattr(
            "rebrew.near_diag.require_config",
            lambda target=None, json_mode=False: NS(
                root=tmp_path,
                reversed_dir=tmp_path,
                metadata_dir=tmp_path,
                marker="S",
                source_ext=".c",
                target_name="S",
                target_binary=tmp_path / "x.exe",
            ),
        )
        result = CliRunner().invoke(app, ["--all", "--va", "0x1000"])
        assert result.exit_code == 2
        assert "--va cannot be combined with --all" in result.output

    def test_batch_writes_blockers_for_each(self, monkeypatch, tmp_path: Path) -> None:
        from types import SimpleNamespace as NS

        annos = [
            NS(va=0x1000, size=8, symbol="_f", module="S", cflags="", status="NEAR_MATCHING"),
            NS(va=0x2000, size=8, symbol="_g", module="S", cflags="", status="NEAR_MATCHING"),
        ]
        result, calls = self._invoke(
            monkeypatch, tmp_path, ["--all", "--fix-blocker", "--json"], annos
        )
        assert result.exit_code == 0, result.output
        assert len(calls) == 2
        assert calls[0][0][1] == 0x1000
        assert calls[1][0][1] == 0x2000
        import json

        payload = json.loads(result.output)
        assert payload["total"] == 2
        assert payload["classified"] == 2
        assert payload["failed"] == 0
        assert payload["results"][0]["blocker_written"] is True

    def test_batch_includes_size_mismatch(self, monkeypatch, tmp_path: Path) -> None:
        """--all must also classify SIZE_MISMATCH functions (mirror prove --all)."""
        import json
        from types import SimpleNamespace as NS

        annos = [
            NS(va=0x1000, size=8, symbol="_f", module="S", cflags="", status="NEAR_MATCHING"),
            NS(va=0x2000, size=8, symbol="_g", module="S", cflags="", status="SIZE_MISMATCH"),
        ]
        result, calls = self._invoke(
            monkeypatch, tmp_path, ["--all", "--fix-blocker", "--json"], annos
        )
        assert result.exit_code == 0, result.output
        assert len(calls) == 2
        payload = json.loads(result.output)
        assert payload["total"] == 2
        assert payload["classified"] == 2
        assert payload["results"][1]["blocker_written"] is True

    def test_batch_no_candidates(self, monkeypatch, tmp_path: Path) -> None:
        from types import SimpleNamespace as NS

        # Only a STUB annotation — nothing NEAR_MATCHING to diagnose.
        annos = [NS(va=0x1000, size=8, symbol="_f", module="S", cflags="", status="STUB")]
        result, calls = self._invoke(monkeypatch, tmp_path, ["--all", "--json"], annos)
        assert result.exit_code == 0, result.output
        assert calls == []
        import json

        payload = json.loads(result.output)
        assert payload["total"] == 0
        assert payload["results"] == []

    def test_batch_compile_error_continues(self, monkeypatch, tmp_path: Path) -> None:
        from types import SimpleNamespace as NS

        annos = [
            NS(va=0x1000, size=8, symbol="_f", module="S", cflags="", status="NEAR_MATCHING"),
            NS(va=0x2000, size=8, symbol="_g", module="S", cflags="", status="NEAR_MATCHING"),
        ]
        # The FIRST function fails to compile; the batch must continue and
        # still diagnose the second one.
        failures = {"fail": True}

        def fake_compile(*a, **k):
            if failures["fail"]:
                failures["fail"] = False
                return None, "syntax error"
            return Path("o.obj"), ""

        result, calls = self._invoke(
            monkeypatch,
            tmp_path,
            ["--all", "--fix-blocker", "--json"],
            annos,
            compile_fn=fake_compile,
        )
        assert result.exit_code == 0, result.output
        assert len(calls) == 1  # only the second function got its blocker
        assert calls[0][0][1] == 0x2000
        import json

        payload = json.loads(result.output)
        assert payload["total"] == 2
        assert payload["classified"] == 1
        assert payload["failed"] == 1
        assert payload["results"][0]["error"] is not None
        assert payload["results"][1]["verdict"].startswith("REGISTER")


class TestValidatedRelocMasking:
    """near-diag must mask ONLY relocation sites that survive the same
    DIR32/REL32 address validation as rebrew test/verify (H: near-diag
    reported "RELOC-level" for functions test classifies NEAR_MATCHING)."""

    MOV_EAX_1 = b"\xb8\x01\x00\x00\x00"  # mov eax, 1
    MOV_EAX_2 = b"\xb8\x02\x00\x00\x00"  # mov eax, 2
    MOV_EAX_3 = b"\xb8\x03\x00\x00\x00"  # mov eax, 3

    def _invoke_diag(
        self, monkeypatch, tmp_path: Path, compiled: bytes, target: bytes, reloc_fn=None
    ) -> dict:
        import json
        from types import SimpleNamespace as NS

        from typer.testing import CliRunner

        from rebrew.near_diag import app

        cfg = NS(
            root=tmp_path,
            reversed_dir=tmp_path,
            metadata_dir=tmp_path,
            marker="S",
            source_ext=".c",
            target_name="S",
            target_binary=tmp_path / "x.exe",
        )
        monkeypatch.setattr(
            "rebrew.near_diag.require_config", lambda target=None, json_mode=False: cfg
        )
        monkeypatch.setattr("rebrew.cli.resolve_source_arg", lambda cfg, s: s)
        src = tmp_path / "f.c"
        src.write_text(
            "// FUNCTION: S 0x1000\n// SIZE: 10\nint f(void) { return 0; }\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(
            "rebrew.annotation.parse_c_file_multi",
            lambda *a, **k: [NS(va=0x1000, size=10, symbol="_f", module="S", cflags="")],
        )
        monkeypatch.setattr("rebrew.binary_loader.extract_raw_bytes", lambda *a, **k: target)
        monkeypatch.setattr("rebrew.compile.compile_to_obj", lambda *a, **k: (Path("o.obj"), ""))
        monkeypatch.setattr(
            "rebrew.matcher.parsers.parse_obj_symbol_and_relocs",
            lambda *a, **k: (compiled, {0: "_g", 5: "_h"}, []),
        )
        monkeypatch.setattr("rebrew.core.build_name_to_va", lambda cfg: {"_g": 0x5000})
        monkeypatch.setattr(
            "rebrew.core.smart_reloc_compare",
            reloc_fn or (lambda *a, **k: (False, 0, 10, [0], [5])),
        )
        result = CliRunner().invoke(app, ["--json", str(src)])
        assert result.exit_code == 0, result.output
        return json.loads(result.output)

    def test_invalid_reloc_classified_as_structural(self, monkeypatch, tmp_path: Path) -> None:
        # Compiled bytes 1,2 vs target 1,3: site 0 validates (masked), site 5
        # does not — the second mov must be classified (structural), not masked.
        payload = self._invoke_diag(
            monkeypatch,
            tmp_path,
            self.MOV_EAX_1 + self.MOV_EAX_2,
            self.MOV_EAX_1 + self.MOV_EAX_3,
        )
        cats = payload["categories"]
        assert cats["reloc"]["bytes"] == 5
        assert cats["structural"]["bytes"] == 5

    def test_valid_reloc_still_masked(self, monkeypatch, tmp_path: Path) -> None:
        # Both sites validate → both instructions masked → reloc dominates.
        payload = self._invoke_diag(
            monkeypatch,
            tmp_path,
            self.MOV_EAX_1 + self.MOV_EAX_2,
            self.MOV_EAX_1 + self.MOV_EAX_3,
            reloc_fn=lambda *a, **k: (False, 0, 10, [0, 5], []),
        )
        cats = payload["categories"]
        assert cats["reloc"]["bytes"] == 10
        assert cats["structural"]["bytes"] == 0

    def test_analyze_accepts_set_offsets(self) -> None:
        # The widened reloc_offsets annotation must accept a plain set.
        result = nd.analyze(MOV_EAX_1 + RET, MOV_EAX_1 + RET, {1}, 0x1000)
        assert result["categories"]["reloc"]["bytes"] == 5
        assert result["categories"]["match"]["bytes"] == 1


class TestFixBlockerDryRun:
    """near-diag --fix-blocker --dry-run previews the write without touching
    metadata (project convention: every file-modifying CLI honors --dry-run)."""

    def test_dry_run_skips_write(self, tmp_path: Path, monkeypatch) -> None:
        from types import SimpleNamespace as NS

        from typer.testing import CliRunner

        from rebrew.near_diag import app

        cfg = NS(
            root=tmp_path,
            reversed_dir=tmp_path,
            metadata_dir=tmp_path,
            marker="S",
            source_ext=".c",
            target_name="S",
            target_binary=tmp_path / "x.exe",
        )
        monkeypatch.setattr(
            "rebrew.near_diag.require_config", lambda target=None, json_mode=False: cfg
        )
        monkeypatch.setattr("rebrew.cli.resolve_source_arg", lambda cfg, s: s)
        src = tmp_path / "f.c"
        src.write_text(
            "// FUNCTION: S 0x1000\n// SIZE: 8\nint f(void) { return 0; }\n",
            encoding="utf-8",
        )
        calls: list[object] = []
        monkeypatch.setattr("rebrew.metadata.set_field", lambda *a, **k: calls.append(1))
        monkeypatch.setattr(
            "rebrew.near_diag.analyze",
            lambda *a, **k: {
                "verdict": "STRUCTURAL (90% of delta)",
                "suggestion": "Different layout.",
                "mutations": [],
                "categories": {},
            },
        )
        monkeypatch.setattr(
            "rebrew.annotation.parse_c_file_multi",
            lambda *a, **k: [NS(va=0x1000, size=8, symbol="_f", module="S", cflags="")],
        )
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_raw_bytes", lambda *a, **k: b"\x55\x8b\xec\x5d\xc3"
        )
        monkeypatch.setattr("rebrew.compile.compile_to_obj", lambda *a, **k: (Path("o.obj"), ""))
        monkeypatch.setattr(
            "rebrew.matcher.parsers.parse_obj_symbol_and_relocs",
            lambda *a, **k: (b"\x90" * 8, {}, []),
        )
        result = CliRunner().invoke(app, ["--fix-blocker", "--dry-run", str(src)])
        assert result.exit_code == 0, result.output
        assert calls == []  # set_field never invoked under --dry-run

    def test_dry_run_reports_would_write_in_json(self, tmp_path: Path, monkeypatch) -> None:
        import json
        from types import SimpleNamespace as NS

        from typer.testing import CliRunner

        from rebrew.near_diag import app

        cfg = NS(
            root=tmp_path,
            reversed_dir=tmp_path,
            metadata_dir=tmp_path,
            marker="S",
            source_ext=".c",
            target_name="S",
            target_binary=tmp_path / "x.exe",
        )
        monkeypatch.setattr(
            "rebrew.near_diag.require_config", lambda target=None, json_mode=False: cfg
        )
        monkeypatch.setattr("rebrew.cli.resolve_source_arg", lambda cfg, s: s)
        src = tmp_path / "f.c"
        src.write_text(
            "// FUNCTION: S 0x1000\n// SIZE: 8\nint f(void) { return 0; }\n",
            encoding="utf-8",
        )
        monkeypatch.setattr("rebrew.metadata.set_field", lambda *a, **k: None)
        monkeypatch.setattr(
            "rebrew.near_diag.analyze",
            lambda *a, **k: {
                "verdict": "STRUCTURAL (90% of delta)",
                "suggestion": "Different layout.",
                "mutations": [],
                "categories": {},
            },
        )
        monkeypatch.setattr(
            "rebrew.annotation.parse_c_file_multi",
            lambda *a, **k: [NS(va=0x1000, size=8, symbol="_f", module="S", cflags="")],
        )
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_raw_bytes", lambda *a, **k: b"\x55\x8b\xec\x5d\xc3"
        )
        monkeypatch.setattr("rebrew.compile.compile_to_obj", lambda *a, **k: (Path("o.obj"), ""))
        monkeypatch.setattr(
            "rebrew.matcher.parsers.parse_obj_symbol_and_relocs",
            lambda *a, **k: (b"\x90" * 8, {}, []),
        )
        result = CliRunner().invoke(app, ["--fix-blocker", "--dry-run", "--json", str(src)])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["blocker_written"] is True  # would write, but dry-run skipped it


class TestFixBlockerStatus:
    """`near-diag --fix-blocker` must also promote STATUS to NEAR_MATCHING —
    a blocker note implies the classification, and leaving the status
    missing/STUB made status reports count documented functions as stubs."""

    def _invoke_fix(self, monkeypatch, tmp_path: Path) -> None:
        from types import SimpleNamespace as NS

        from typer.testing import CliRunner

        from rebrew.near_diag import app

        cfg = NS(
            root=tmp_path,
            reversed_dir=tmp_path,
            metadata_dir=tmp_path,
            marker="S",
            source_ext=".c",
            target_name="S",
            target_binary=tmp_path / "x.exe",
        )
        monkeypatch.setattr(
            "rebrew.near_diag.require_config", lambda target=None, json_mode=False: cfg
        )
        monkeypatch.setattr("rebrew.cli.resolve_source_arg", lambda cfg, s: s)
        src = tmp_path / "f.c"
        src.write_text(
            "// FUNCTION: S 0x1000\n// SIZE: 10\nint f(void) { return 0; }\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(
            "rebrew.annotation.parse_c_file_multi",
            lambda *a, **k: [NS(va=0x1000, size=10, symbol="_f", module="S", cflags="")],
        )
        monkeypatch.setattr("rebrew.binary_loader.extract_raw_bytes", lambda *a, **k: b"\x01\x03")
        monkeypatch.setattr("rebrew.compile.compile_to_obj", lambda *a, **k: (Path("o.obj"), ""))
        monkeypatch.setattr(
            "rebrew.matcher.parsers.parse_obj_symbol_and_relocs",
            lambda *a, **k: (b"\x01\x02", {}, []),
        )
        result = CliRunner().invoke(app, ["--fix-blocker", "--json", str(src)])
        assert result.exit_code == 0, result.output

    def test_fix_blocker_writes_status(self, monkeypatch, tmp_path: Path) -> None:
        self._invoke_fix(monkeypatch, tmp_path)
        meta = (tmp_path / "rebrew-function.toml").read_text(encoding="utf-8")
        assert 'status = "NEAR_MATCHING"' in meta
        assert "blocker" in meta

    def test_fix_blocker_dry_run_skips_status(self, monkeypatch, tmp_path: Path) -> None:
        from types import SimpleNamespace as NS

        from typer.testing import CliRunner

        from rebrew.near_diag import app

        cfg = NS(
            root=tmp_path,
            reversed_dir=tmp_path,
            metadata_dir=tmp_path,
            marker="S",
            source_ext=".c",
            target_name="S",
            target_binary=tmp_path / "x.exe",
        )
        monkeypatch.setattr(
            "rebrew.near_diag.require_config", lambda target=None, json_mode=False: cfg
        )
        monkeypatch.setattr("rebrew.cli.resolve_source_arg", lambda cfg, s: s)
        src = tmp_path / "f.c"
        src.write_text(
            "// FUNCTION: S 0x1000\n// SIZE: 10\nint f(void) { return 0; }\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(
            "rebrew.annotation.parse_c_file_multi",
            lambda *a, **k: [NS(va=0x1000, size=10, symbol="_f", module="S", cflags="")],
        )
        monkeypatch.setattr("rebrew.binary_loader.extract_raw_bytes", lambda *a, **k: b"\x01\x03")
        monkeypatch.setattr("rebrew.compile.compile_to_obj", lambda *a, **k: (Path("o.obj"), ""))
        monkeypatch.setattr(
            "rebrew.matcher.parsers.parse_obj_symbol_and_relocs",
            lambda *a, **k: (b"\x01\x02", {}, []),
        )
        result = CliRunner().invoke(app, ["--fix-blocker", "--dry-run", "--json", str(src)])
        assert result.exit_code == 0, result.output
        meta_path = tmp_path / "rebrew-function.toml"
        assert not meta_path.exists() or "status" not in meta_path.read_text(encoding="utf-8")
