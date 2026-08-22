"""Tests for diff.py — blocker classification and similarity printing."""

from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console

from rebrew.diff import classify_blockers
from rebrew.match import print_structural_similarity


def _row(match: str, t_asm: str, c_asm: str) -> dict:
    return {"match": match, "target": {"disasm": t_asm}, "candidate": {"disasm": c_asm}}


class TestClassifyBlockers:
    def test_empty_summary(self) -> None:
        assert classify_blockers({}) == []

    def test_non_list_instructions(self) -> None:
        assert classify_blockers({"instructions": "nope"}) == []

    def test_register_allocation(self) -> None:
        blockers = classify_blockers({"instructions": [_row("RR", "mov eax, ebx", "mov eax, ecx")]})
        assert blockers == ["register allocation"]

    def test_jump_condition_swap(self) -> None:
        blockers = classify_blockers({"instructions": [_row("**", "jz 0x100", "je 0x100")]})
        assert blockers == ["jump condition swap"]

    def test_loop_rotation_with_jmp(self) -> None:
        blockers = classify_blockers({"instructions": [_row("**", "jz 0x100", "jmp 0x100")]})
        assert blockers == ["loop rotation / branch layout"]

    def test_xor_vs_mov_zeroing(self) -> None:
        blockers = classify_blockers({"instructions": [_row("**", "xor eax, eax", "mov eax, 0")]})
        assert blockers == ["zero-extend pattern (xor vs mov)"]

    def test_cmp_direction_swap(self) -> None:
        blockers = classify_blockers({"instructions": [_row("**", "cmp eax, ebx", "cmp ebx, eax")]})
        assert blockers == ["comparison direction swap"]

    def test_push_vs_sub_esp(self) -> None:
        blockers = classify_blockers({"instructions": [_row("**", "push eax", "sub esp, 4")]})
        assert blockers == ["stack frame choice (push vs sub esp)"]

    def test_lea_vs_mov_folding(self) -> None:
        blockers = classify_blockers(
            {"instructions": [_row("**", "lea eax, [ecx]", "mov eax, ecx")]}
        )
        assert blockers == ["instruction folding (lea vs mov)"]

    def test_unrecognized_star_star_no_blockers(self) -> None:
        blockers = classify_blockers({"instructions": [_row("**", "int3", "nop")]})
        assert blockers == []

    def test_non_dict_row_skipped(self) -> None:
        blockers = classify_blockers({"instructions": [42, {"match": "ok"}]})
        assert blockers == []


class TestPrintStructuralSimilarity:
    def test_flag_sensitive_wording(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.match as match_mod

        buf = StringIO()
        monkeypatch.setattr(
            match_mod,
            "console",
            Console(file=buf, force_terminal=True, width=120, no_color=True, highlight=False),
        )
        sim = SimpleNamespace(
            flag_sensitive=True,
            exact=10,
            reloc_only=2,
            register_only=3,
            structural=1,
            total_insns=16,
            mnemonic_match_ratio=0.75,
            structural_ratio=0.25,
        )
        print_structural_similarity(sim)
        out = buf.getvalue()
        assert "flag sweep MAY help" in out
        assert "10 exact" in out
        assert "2 reloc" in out
        assert "3 register" in out
        assert "1 structural" in out
        assert "of 16 total" in out
        assert "75.0%" in out
        assert "25.0%" in out

    def test_flag_insensitive_wording(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.match as match_mod

        buf = StringIO()
        monkeypatch.setattr(
            match_mod,
            "console",
            Console(file=buf, force_terminal=True, width=120, no_color=True, highlight=False),
        )
        sim = SimpleNamespace(
            flag_sensitive=False,
            exact=0,
            reloc_only=0,
            register_only=0,
            structural=0,
            total_insns=0,
            mnemonic_match_ratio=0.0,
            structural_ratio=0.0,
        )
        print_structural_similarity(sim)
        out = buf.getvalue()
        assert "flags unlikely to help" in out
        assert "0 exact" in out
        assert "0.0%" in out


# ---------------------------------------------------------------------------
# Source-argument resolution (VA / symbol → .c path)
# ---------------------------------------------------------------------------


class TestDiffSourceResolution:
    def test_va_resolves_to_source_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`rebrew diff 0x1000` resolves the VA to the matching .c seed."""
        from types import SimpleNamespace

        from typer.testing import CliRunner

        src = tmp_path / "target_func.c"
        src.write_text(
            "// FUNCTION: GAME 0x1000\n// STATUS: NEAR_MATCHING\nint f(void) { return 0; }\n",
            encoding="utf-8",
        )
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=tmp_path,
            metadata_dir=tmp_path.parent,
            marker="GAME",
            source_ext=".c",
            compile_timeout=30,
        )
        monkeypatch.setattr("rebrew.diff.require_config", lambda target=None, json_mode=False: cfg)

        captured: dict[str, object] = {}

        def fake_resolve_build_params(*args: object, **kwargs: object) -> object:
            captured["seed_c"] = args[1]
            return SimpleNamespace(
                seed_src=args[1],
                cl="cl",
                inc="inc",
                cflags="/O2",
                symbol="_f",
                msvc_env={},
                cc=None,
                cfg=cfg,
                seed_c=src,
                target_bytes=b"\x00" * 8,
                va_int=0x1000,
            )

        monkeypatch.setattr("rebrew.match.resolve_build_params", fake_resolve_build_params)
        monkeypatch.setattr(
            "rebrew.diff.run_diff", lambda *a, **k: None
        )  # skip compile/diff pipeline

        from rebrew.diff import app

        result = CliRunner().invoke(app, ["0x1000"])
        assert result.exit_code == 0
        assert captured["seed_c"] == str(src), (
            f"expected VA→{src} resolution, got {captured['seed_c']}"
        )

    def test_unresolvable_passthrough_preserves_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An unresolvable seed reaches resolve_build_params unchanged."""
        from types import SimpleNamespace

        from typer.testing import CliRunner

        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=tmp_path,
            metadata_dir=tmp_path.parent,
            marker="GAME",
            source_ext=".c",
            compile_timeout=30,
        )
        monkeypatch.setattr("rebrew.diff.require_config", lambda target=None, json_mode=False: cfg)
        captured: dict[str, object] = {}

        def fake_resolve_build_params(*args: object, **kwargs: object) -> object:
            captured["seed_c"] = args[1]
            return SimpleNamespace(
                seed_src=args[1],
                cl="cl",
                inc="inc",
                cflags="/O2",
                symbol="_f",
                msvc_env={},
                cc=None,
                cfg=cfg,
                seed_c=args[1],
                target_bytes=b"\x00",
                va_int=0,
            )

        monkeypatch.setattr("rebrew.match.resolve_build_params", fake_resolve_build_params)
        monkeypatch.setattr("rebrew.diff.run_diff", lambda *a, **k: None)

        from rebrew.diff import app

        result = CliRunner().invoke(app, ["no_such_thing_anywhere"])
        assert result.exit_code == 0
        assert captured["seed_c"] == "no_such_thing_anywhere"


def test_cs_mode_for_16bit_target() -> None:
    """rebrew diff must disassemble 16-bit DOS code in 16-bit mode — a
    32-bit disasm renders `4a` (dec dx) as `dec edx` and mis-aligns the
    whole byte diff."""
    from types import SimpleNamespace

    import capstone

    from rebrew.diff import _cs_mode_for_cfg

    assert _cs_mode_for_cfg(SimpleNamespace(arch="x86_16")) == capstone.CS_MODE_16
    assert _cs_mode_for_cfg(SimpleNamespace(arch="x86_32")) == capstone.CS_MODE_32
    assert _cs_mode_for_cfg(SimpleNamespace(arch="x86_64")) == capstone.CS_MODE_32
