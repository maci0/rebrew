"""Tests for stack_cmp.py — stack-frame comparison (reccmp stackcmp adaptation)."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from rebrew.cli import EXIT_ERROR, EXIT_MISMATCH
from rebrew.stack_cmp import analyze_frame, app, compare_frames

# Hand-crafted 32-bit x86 encodings.
# push ebp; mov ebp,esp; sub esp,0x28; mov [ebp-4],eax; mov eax,[ebp-4]; leave; ret
EBP_FRAME_0X28 = bytes.fromhex("55 8b ec 83 ec 28 89 45 fc 8b 45 fc c9 c3")
# push esi; sub esp,0x20; mov [esp],eax; pop eax; add esp,0x20; pop esi; ret  (esp-based /Oy)
ESP_FRAME_0X20 = bytes.fromhex("56 83 ec 20 89 04 24 58 83 c4 20 5e c3")
# push ebp; mov ebp,esp; sub esp,0x28; mov [ebp-8],eax; leave; ret 4  (stdcall)
EBP_STDCALL_RET4 = bytes.fromhex("55 8b ec 83 ec 28 89 45 f8 c9 c2 04 00")
RET = b"\xc3"
NOFRAME = b"\x90\x90\xc3"  # nop; nop; ret — no stack activity


class TestAnalyzeFrame:
    def test_ebp_frame_size_and_slots(self) -> None:
        f = analyze_frame(EBP_FRAME_0X28, 0x1000, 4)
        assert f["frame_size"] == 0x2C  # push ebp (4) + sub esp 0x28 (40)
        assert f["frame_pointer"] is True
        assert f["ret_popping"] == 0
        assert f["slots"] == [-4]

    def test_esp_based_frame(self) -> None:
        f = analyze_frame(ESP_FRAME_0X20, 0x1000, 4)
        assert f["frame_size"] == 0x24  # push esi (4) + sub esp 0x20 (32)
        assert f["frame_pointer"] is False
        assert f["slots"] == []

    def test_stdcall_ret_popping(self) -> None:
        f = analyze_frame(EBP_STDCALL_RET4, 0x1000, 4)
        assert f["ret_popping"] == 4
        assert f["frame_pointer"] is True

    def test_no_frame(self) -> None:
        f = analyze_frame(NOFRAME, 0x1000, 4)
        assert f["frame_size"] == 0
        assert f["frame_pointer"] is False
        assert f["ret_popping"] == 0

    def test_push_pop_net_zero(self) -> None:
        # push eax; push ecx; pop ecx; pop eax; ret — net frame 0.
        code = bytes.fromhex("50 51 59 58 c3")
        f = analyze_frame(code, 0x1000, 4)
        assert f["frame_size"] == 8  # peak depth, not net
        assert f["frame_pointer"] is False

    def test_enter_instruction(self) -> None:
        # enter 0x10, 0 ; leave ; ret
        code = bytes.fromhex("c8 10 00 00 c9 c3")
        f = analyze_frame(code, 0x1000, 4)
        assert f["frame_size"] == 0x14  # saved bp (4) + 0x10
        assert f["frame_pointer"] is True

    def test_16bit_word_size(self) -> None:
        # push bp; mov bp,sp; sub sp,0x10; mov [bp-4],ax; leave; ret
        code = bytes.fromhex("55 89 e5 83 ec 10 89 46 fc c9 c3")
        f = analyze_frame(code, 0x1000, 2)
        assert f["frame_size"] == 0x12  # push bp (2) + sub sp 0x10 (16)
        assert f["frame_pointer"] is True
        assert f["slots"] == [-4]

    def test_garbage_does_not_raise(self) -> None:
        f = analyze_frame(b"\xff\xff\xff\xff\xff", 0x1000, 4)
        assert isinstance(f["frame_size"], int)
        assert isinstance(f["slots"], list)


class TestCompareFrames:
    def test_match(self) -> None:
        a = analyze_frame(EBP_FRAME_0X28, 0x1000, 4)
        b = analyze_frame(EBP_FRAME_0X28, 0x1000, 4)  # identical frame usage
        r = compare_frames(a, b)
        assert r["frame_match"] is True
        assert r["diffs"] == []

    def test_frame_size_diff(self) -> None:
        r = compare_frames(
            analyze_frame(EBP_FRAME_0X28, 0x1000, 4),
            analyze_frame(ESP_FRAME_0X20, 0x1000, 4),
        )
        assert r["frame_match"] is False
        assert any("frame size" in d for d in r["diffs"])
        assert any("frame pointer" in d for d in r["diffs"])
        assert r["hints"]  # flag-focused hints accompany the diffs

    def test_slot_diff_with_fp(self) -> None:
        a = analyze_frame(EBP_FRAME_0X28, 0x1000, 4)  # [ebp-4]
        b = analyze_frame(EBP_STDCALL_RET4, 0x1000, 4)  # [ebp-8], ret 4
        r = compare_frames(a, b)
        assert r["frame_match"] is False
        assert any("stack slots" in d for d in r["diffs"])
        assert any("ret-popping" in d for d in r["diffs"])

    def test_slot_diff_without_fp_skipped(self) -> None:
        # esp-based sides have no comparable displacement set — no slot diff.
        a = analyze_frame(ESP_FRAME_0X20, 0x1000, 4)
        b = analyze_frame(NOFRAME, 0x1000, 4)
        r = compare_frames(a, b)
        assert not any("stack slots" in d for d in r["diffs"])


class TestRunStackCmp:
    def _patch(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, obj_bytes: bytes
    ) -> SimpleNamespace:
        import rebrew.match
        import rebrew.matcher

        cfg = SimpleNamespace(arch="x86_32", compile_timeout=None)
        src = tmp_path / "f.c"
        src.write_text("// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n", encoding="utf-8")
        monkeypatch.setattr("rebrew.stack_cmp.require_config", lambda **kw: cfg)
        params = SimpleNamespace(
            cfg=cfg,
            seed_c=src,
            seed_src="f",
            cl="cl",
            inc="",
            cflags="/O2",
            symbol="_f",
            target_bytes=EBP_FRAME_0X28,
            va_int=0x1000,
            target_size=len(EBP_FRAME_0X28),
            msvc_env=None,
            cc=None,
        )
        # run_stack_cmp imports these inside the function — patch the modules
        # they are imported from.
        monkeypatch.setattr(rebrew.match, "resolve_build_params", lambda *a, **k: params)

        res_cls = type("_Res", (), {"ok": True, "obj_bytes": obj_bytes, "error_msg": ""})
        monkeypatch.setattr(rebrew.matcher, "build_candidate_obj_only", lambda *a, **k: res_cls())
        return src

    def test_frames_match_exit_zero(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        src = self._patch(monkeypatch, tmp_path, EBP_FRAME_0X28)
        result = CliRunner().invoke(app, [str(src)])
        assert result.exit_code == 0
        assert "frames match" in result.stderr.lower()

    def test_frames_differ_exit_mismatch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        src = self._patch(monkeypatch, tmp_path, ESP_FRAME_0X20)
        result = CliRunner().invoke(app, [str(src)])
        assert result.exit_code == EXIT_MISMATCH
        assert "frame differs" in result.stderr.lower()

    def test_json_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        src = self._patch(monkeypatch, tmp_path, EBP_FRAME_0X28)
        result = CliRunner().invoke(app, ["--json", str(src)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["frame_match"] is True
        assert data["target"]["frame_size"] == 0x2C
        assert data["va"] == "0x00001000"

    def test_build_failure_exits_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.matcher

        src = self._patch(monkeypatch, tmp_path, b"")

        bad_cls = type("_Bad", (), {"ok": False, "obj_bytes": None, "error_msg": "cl.exe failed"})
        monkeypatch.setattr(rebrew.matcher, "build_candidate_obj_only", lambda *a, **k: bad_cls())
        result = CliRunner().invoke(app, [str(src)])
        assert result.exit_code == EXIT_ERROR
