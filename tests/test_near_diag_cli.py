"""CLI tests for rebrew near_diag — main() with stubbed compile/extract."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from rebrew.near_diag import app

_CODE = bytes.fromhex("558bec83ec08b801000000c9c3")


def _cfg(tmp_path: Path) -> SimpleNamespace:
    src = tmp_path / "src" / "SERVER"
    src.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(
        root=tmp_path,
        target_name="SERVER",
        target_binary=tmp_path / "fake.dll",
        reversed_dir=src,
        metadata_dir=tmp_path,
        marker="SERVER",
        source_ext=".c",
        capstone_arch="CS_ARCH_X86",
        capstone_mode="CS_MODE_32",
    )


def _setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    compile_error: str | None = None,
    symbol_found: bool = True,
) -> SimpleNamespace:
    cfg = _cfg(tmp_path)
    monkeypatch.setattr("rebrew.near_diag.require_config", lambda **kw: cfg)
    monkeypatch.setattr("rebrew.binary_loader.extract_raw_bytes", lambda *a, **k: _CODE)
    obj = tmp_path / "out.obj"
    obj.write_bytes(b"x")

    def _compile(cfg, src, cflags, workdir, **kwargs):
        if compile_error is not None:
            return None, compile_error
        return obj, None

    monkeypatch.setattr("rebrew.compile.compile_to_obj", _compile)

    def _symbols(obj_path, symbol):
        if symbol_found:
            return _CODE, {}, []
        return None, {}, []

    monkeypatch.setattr("rebrew.matcher.parsers.parse_obj_symbol_and_relocs", _symbols)
    return cfg


def _write_src(cfg: SimpleNamespace, text: str) -> Path:
    # Ensure a SIZE annotation so size_val is non-zero (insert after the marker).
    if "SIZE:" not in text:
        lines = text.splitlines()
        out = []
        for line in lines:
            out.append(line)
            if line.startswith("// FUNCTION:"):
                out.append("// SIZE: 12")
        text = "\n".join(out)
    p = cfg.reversed_dir / "f.c"
    p.write_text(text, encoding="utf-8")
    return p


class TestNearDiagCli:
    def test_json_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _setup(tmp_path, monkeypatch)
        _write_src(cfg, "// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n")
        result = CliRunner().invoke(app, ["--json", str(cfg.reversed_dir / "f.c")])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "verdict" in data
        assert "categories" in data

    def test_va_size_flags(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _setup(tmp_path, monkeypatch)
        _write_src(cfg, "// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n")
        result = CliRunner().invoke(
            app, ["--json", "--va", "0x2000", "--size", "16", str(cfg.reversed_dir / "f.c")]
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["va"] == "0x00002000"

    def test_no_annotations_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _setup(tmp_path, monkeypatch)
        p = _write_src(cfg, "int f(void) { return 0; }\n")
        result = CliRunner().invoke(app, ["--json", str(p)])
        assert result.exit_code != 0
        assert "No annotations found" in result.output

    def test_missing_va_size_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _setup(tmp_path, monkeypatch)
        # VA present but no SIZE annotation (write directly to bypass the
        # _write_src SIZE helper).
        p = cfg.reversed_dir / "f.c"
        p.write_text("// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n", encoding="utf-8")
        result = CliRunner().invoke(app, ["--json", str(p)])
        assert result.exit_code != 0
        assert "Cannot determine target VA/size" in result.output

    def test_extract_failure_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _setup(tmp_path, monkeypatch)
        monkeypatch.setattr("rebrew.binary_loader.extract_raw_bytes", lambda *a, **k: None)
        p = _write_src(cfg, "// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n")
        result = CliRunner().invoke(app, ["--json", str(p)])
        assert result.exit_code != 0
        assert "Failed to extract target bytes" in result.output

    def test_compile_error_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _setup(tmp_path, monkeypatch, compile_error="cl crashed")
        p = _write_src(cfg, "// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n")
        result = CliRunner().invoke(app, ["--json", str(p)])
        assert result.exit_code != 0
        assert "cl crashed" in result.output

    def test_symbol_missing_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _setup(tmp_path, monkeypatch, symbol_found=False)
        p = _write_src(cfg, "// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n")
        result = CliRunner().invoke(app, ["--json", str(p)])
        assert result.exit_code != 0
        assert "not found in compiled .obj" in result.output

    def test_terminal_table(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _setup(tmp_path, monkeypatch)
        p = _write_src(cfg, "// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n")
        result = CliRunner().invoke(app, [str(p)])
        assert result.exit_code == 0
        assert "Delta classification" in result.output


class TestVAPositionalResolution:
    """A hex VA positional must resolve to its source file AND select the
    matching annotation in a multi-function file (was: annos[0])."""

    def test_va_positional_selects_matching_annotation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _setup(tmp_path, monkeypatch)
        p = cfg.reversed_dir / "multi.c"
        p.write_text(
            "// FUNCTION: SERVER 0x1000\n// SIZE: 12\nint f1(void) { return 0; }\n"
            "// FUNCTION: SERVER 0x2000\n// SIZE: 12\nint f2(void) { return 0; }\n",
            encoding="utf-8",
        )
        monkeypatch.setattr("rebrew.cli.resolve_source_arg", lambda cfg, src: str(p))
        result = CliRunner().invoke(app, ["--json", "0x2000"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["va"] == "0x00002000"

    def test_symbol_positional_resolves_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _setup(tmp_path, monkeypatch)
        p = _write_src(cfg, "// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n")
        monkeypatch.setattr("rebrew.cli.resolve_source_arg", lambda cfg, src: str(p))
        result = CliRunner().invoke(app, ["--json", "some_symbol"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["va"] == "0x00001000"


class TestVANoMatchErrors:
    """Requesting a VA the resolved file does not cover must error, not
    silently diagnose annos[0] with the wrong function's flags."""

    def test_va_not_in_file_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _setup(tmp_path, monkeypatch)
        p = cfg.reversed_dir / "multi.c"
        p.write_text(
            "// FUNCTION: SERVER 0x1000\n// SIZE: 12\nint f1(void) { return 0; }\n",
            encoding="utf-8",
        )
        monkeypatch.setattr("rebrew.cli.resolve_source_arg", lambda cfg, src: str(p))
        result = CliRunner().invoke(app, ["--json", "0x9999"])
        assert result.exit_code != 0
        assert "No annotation for VA 0x00009999" in result.output
