"""Tests for rebrew asm.py — disasm, NASM conversion, inline C, batch extraction."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.asm import (
    _parse_annotations,
    build_function_lookup,
    capstone_to_nasm,
    disasm_bytes,
    disassemble_to_nasm,
    generate_inline_c,
    verify_roundtrip,
)

# push ebp; mov ebp, esp; sub esp, 8; mov eax, 1; leave; ret
_CODE = bytes.fromhex("558bec83ec08b801000000c9c3")


def _cfg(tmp_path: Path, **overrides: object) -> SimpleNamespace:
    src = tmp_path / "src" / "SERVER"
    src.mkdir(parents=True, exist_ok=True)
    defaults: dict = {
        "root": tmp_path,
        "target_name": "SERVER",
        "target_binary": tmp_path / "fake.dll",
        "reversed_dir": src,
        "metadata_dir": tmp_path,
        "marker": "SERVER",
        "source_ext": ".c",
        "compiler_profile": "msvc",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class TestDisasmBytes:
    def test_basic(self) -> None:
        out = disasm_bytes(_CODE, 0x1000)
        assert "55" in out
        assert "push" in out
        assert "00001000" in out

    def test_capstone_missing_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys

        monkeypatch.setitem(sys.modules, "capstone", None)
        with pytest.raises(RuntimeError, match="capstone not installed"):
            disasm_bytes(_CODE, 0x1000)


class TestCapstoneToNasm:
    def test_with_operands(self) -> None:
        assert capstone_to_nasm("mov", "dword ptr [eax]") == "mov dword [eax]"

    def test_no_operands(self) -> None:
        assert capstone_to_nasm("ret", "") == "ret"


class TestDisassembleToNasm:
    def test_roundtrip_simple(self) -> None:
        src, stats = disassemble_to_nasm(_CODE, 0x1000, "my_func")
        assert stats["total_instructions"] == 6
        assert stats["nasm_ok"] >= 5  # most instructions survive NASM
        assert "bits 32" in src
        assert "org 0x00001000" in src

    def test_verify_roundtrip(self) -> None:
        src, _ = disassemble_to_nasm(_CODE, 0x1000)
        passed, msg = verify_roundtrip(src, _CODE)
        assert passed, msg


class TestGenerateInlineC:
    def test_msvc_default(self) -> None:
        cfg = _cfg(Path("/tmp"), compiler_profile="msvc")
        out = generate_inline_c(
            "bits 32\norg 0x1000\n\nmy_func:\n    push ebp ; comment\n    db 0x90\n",
            cfg,
            0x1000,
            "_my_func",
        )
        assert "// FUNCTION: SERVER 0x00001000" in out
        assert "void __declspec(naked) my_func(void)" in out
        assert "__asm {" in out
        assert "push ebp" in out
        assert "_emit 0x90" in out
        # comment stripped from the mov line
        assert "push ebp ; comment" not in out

    def test_gcc_clang(self) -> None:
        cfg = _cfg(Path("/tmp"), compiler_profile="clang")
        out = generate_inline_c("bits 32\norg 0x1000\nlbl:\n    mov eax, 1\n", cfg, 0x1000, None)
        assert "__asm__(" in out
        assert '"mov eax, 1\\n"' in out
        assert "func_00001000" in out  # default symbol fallback


class TestParseAnnotations:
    def test_filters_statuses_and_sizes(self, tmp_path: Path) -> None:
        src = tmp_path / "f.c"
        src.write_text(
            "// FUNCTION: SERVER 0x1000\n// SIZE: 10\n// STATUS: EXACT\nint f(void) { return 0; }\n"
            "// FUNCTION: SERVER 0x2000\nint g(void) { return 0; }\n",  # no size → skipped
            encoding="utf-8",
        )
        results = _parse_annotations(src)
        assert len(results) == 1
        assert results[0]["va"] == 0x1000
        assert results[0]["size"] == 10

    def test_metadata_dir_passthrough(self, tmp_path: Path) -> None:
        from rebrew.metadata import update_source_status

        src = tmp_path / "f.c"
        src.write_text("// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n", encoding="utf-8")
        update_source_status(tmp_path, "STUB", "SERVER", 0x1000)
        update_field_guard = __import__("rebrew.metadata", fromlist=["update_field"])
        update_field_guard.update_field(tmp_path, 0x1000, "size", 12, "SERVER")
        results = _parse_annotations(src, metadata_dir=tmp_path)
        assert len(results) == 1
        assert results[0]["size"] == 12
        assert results[0]["status"] == "STUB"


class TestBuildFunctionLookup:
    def test_from_sources_and_ghidra(self, tmp_path: Path) -> None:
        import json

        from rebrew.config import FUNCTION_STRUCTURE_JSON

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / FUNCTION_STRUCTURE_JSON).write_text(
            json.dumps([{"va": "0x1000", "name": "ghidra_fn", "size": 10}]),
            encoding="utf-8",
        )
        (cfg.reversed_dir / "f.c").write_text(
            "// FUNCTION: SERVER 0x2000\n// SYMBOL: _local_fn\nint local_fn(void) { return 0; }\n",
            encoding="utf-8",
        )
        lookup = build_function_lookup(cfg)  # type: ignore[arg-type]
        assert lookup[0x1000] == ("ghidra_fn", "")
        assert lookup[0x2000] == ("local_fn", "STUB")

    def test_bad_file_skipped(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        # A .c file that raises OSError on read (directory named *.c).
        (cfg.reversed_dir / "bad.c").mkdir()
        lookup = build_function_lookup(cfg)  # type: ignore[arg-type]
        assert lookup == {}


class TestBatchExtractNasm:
    def test_batch_writes_asm_files(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.asm import batch_extract_nasm

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text(
            "// FUNCTION: SERVER 0x1000\n// SIZE: 12\n// STATUS: STUB\nint f(void) { return 0; }\n",
            encoding="utf-8",
        )
        monkeypatch.setattr("rebrew.asm.extract_raw_bytes", lambda *a, **k: _CODE)
        out_dir = tmp_path / "nasm"
        batch_extract_nasm(cfg, out_dir, verify_flag=True)  # type: ignore[arg-type]
        # Multi-function sources share a stem — output names carry the VA.
        assert (out_dir / "f.c.00001000.asm").exists()

    def test_batch_skips_stubs_only_filter(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.asm import batch_extract_nasm

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text(
            "// FUNCTION: SERVER 0x1000\n// SIZE: 12\n// STATUS: EXACT\nint f(void) { return 0; }\n",
            encoding="utf-8",
        )
        monkeypatch.setattr("rebrew.asm.extract_raw_bytes", lambda *a, **k: _CODE)
        out_dir = tmp_path / "nasm"
        batch_extract_nasm(cfg, out_dir, stubs_only=True)  # type: ignore[arg-type]
        assert not (out_dir / "f.c.asm").exists()

    def test_batch_extraction_error_skips(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.asm import batch_extract_nasm

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text(
            "// FUNCTION: SERVER 0x1000\n// SIZE: 12\n// STATUS: STUB\nint f(void) { return 0; }\n",
            encoding="utf-8",
        )

        def _none(*a: object, **k: object) -> None:
            return None

        monkeypatch.setattr("rebrew.asm.extract_raw_bytes", _none)
        out_dir = tmp_path / "nasm"
        batch_extract_nasm(cfg, out_dir)  # type: ignore[arg-type]
        assert not (out_dir / "f.c.asm").exists()


class TestBatchOutDirResolution:
    """--out-dir in batch mode must resolve against the project root, not the
    CWD (running from a project subdirectory must not leak output there)."""

    def _setup(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
        captured: dict[str, object] = {}

        def fake_require_config(target=None, json_mode=False):
            return SimpleNamespace(root=tmp_path, target_binary=tmp_path / "x.dll")

        def fake_batch(cfg, out_dir, verify_flag=False, stubs_only=False):
            captured["out_dir"] = out_dir

        monkeypatch.setattr("rebrew.asm.require_config", fake_require_config)
        monkeypatch.setattr("rebrew.asm.batch_extract_nasm", fake_batch)
        return captured

    def test_relative_out_dir_resolves_against_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.asm import app

        captured = self._setup(tmp_path, monkeypatch)
        result = CliRunner().invoke(app, ["--format", "nasm", "--all", "--out-dir", "output/asm"])
        assert result.exit_code == 0
        assert captured["out_dir"] == tmp_path / "output" / "asm"

    def test_default_out_dir_resolves_against_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.asm import app

        captured = self._setup(tmp_path, monkeypatch)
        result = CliRunner().invoke(app, ["--format", "nasm", "--all"])
        assert result.exit_code == 0
        assert captured["out_dir"] == tmp_path / "output" / "asm"

    def test_absolute_out_dir_unchanged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.asm import app

        captured = self._setup(tmp_path, monkeypatch)
        result = CliRunner().invoke(app, ["--format", "nasm", "--all", "--out-dir", "/tmp/nasm"])
        assert result.exit_code == 0
        assert captured["out_dir"] == Path("/tmp/nasm")
