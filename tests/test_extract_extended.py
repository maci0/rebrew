"""Tests for rebrew extract.py — load_functions, cmd_extract/batch, CLI."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import typer
from typer.testing import CliRunner

from rebrew.extract import cmd_batch, cmd_extract, load_functions


def _cfg(tmp_path: Path, **overrides: object) -> SimpleNamespace:
    defaults: dict = {
        "root": tmp_path,
        "target_name": "SERVER",
        "target_binary": tmp_path / "fake.dll",
        "reversed_dir": tmp_path / "src" / "SERVER",
        "metadata_dir": tmp_path,
        "marker": "SERVER",
        "source_ext": ".c",
        "bin_dir": tmp_path / "bin",
        "function_list": tmp_path / "functions.txt",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class TestLoadFunctions:
    def test_txt_preferred(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        (tmp_path / "functions.txt").write_text("0x1000 64 func_a\n", encoding="utf-8")
        funcs = load_functions(cfg)  # type: ignore[arg-type]
        assert funcs[0]["va"] == 0x1000

    def test_json_fallback(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        (tmp_path / "functions.json").write_text(
            json.dumps([{"offset": "0x2000", "realsz": 128, "name": "fn_b"}]),
            encoding="utf-8",
        )
        funcs = load_functions(cfg)  # type: ignore[arg-type]
        assert funcs == [{"va": 0x2000, "size": 128, "name": "fn_b"}]

    def test_json_size_fallback_key(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        (tmp_path / "functions.json").write_text(
            json.dumps([{"offset": 0x3000, "size": 32, "name": "fn_c"}]),
            encoding="utf-8",
        )
        funcs = load_functions(cfg)  # type: ignore[arg-type]
        assert funcs == [{"va": 0x3000, "size": 32, "name": "fn_c"}]

    def test_missing_raises(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        with pytest.raises(FileNotFoundError):
            load_functions(cfg)  # type: ignore[arg-type]

    def test_json_missing_field_raises_value_error(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        (tmp_path / "functions.json").write_text(
            json.dumps([{"realsz": 128, "name": "fn_b"}]), encoding="utf-8"
        )
        with pytest.raises(ValueError, match="Malformed function list"):
            load_functions(cfg)  # type: ignore[arg-type]

    def test_json_corrupt_raises_value_error(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        (tmp_path / "functions.json").write_text("[{", encoding="utf-8")
        with pytest.raises(ValueError):
            load_functions(cfg)  # type: ignore[arg-type]


def _patch_disasm(monkeypatch: pytest.MonkeyPatch, text: str = "push ebp") -> None:
    monkeypatch.setattr("rebrew.extract.disasm_bytes", lambda code, va, cfg=None: text)


class TestCmdExtract:
    def test_json_extract_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        binary = SimpleNamespace(data=b"", sections={})
        monkeypatch.setattr("rebrew.extract.extract_bytes_at_va", lambda *a, **k: b"")
        with pytest.raises(typer.Exit) as exc:
            cmd_extract(binary, [(0x1000, 8, "f")], 0x1000, tmp_path, json_output=True)  # type: ignore[arg-type]
        assert exc.value.exit_code == 1
        out = json.loads(capsys.readouterr().out)
        assert out["status"] == "ERROR"

    def test_json_disasm_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        binary = SimpleNamespace(data=b"\x90" * 8, sections={})
        monkeypatch.setattr("rebrew.extract.extract_bytes_at_va", lambda *a, **k: b"\x90" * 8)

        def _boom(code, va, cfg=None):
            raise RuntimeError("no capstone")

        monkeypatch.setattr("rebrew.extract.disasm_bytes", _boom)
        with pytest.raises(typer.Exit) as exc:
            cmd_extract(binary, [(0x1000, 8, "f")], 0x1000, tmp_path, json_output=True)  # type: ignore[arg-type]
        assert exc.value.exit_code == 1
        out = json.loads(capsys.readouterr().out)
        assert out["status"] == "ERROR"
        assert "no capstone" in out["error"]

    def test_va_not_found_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        binary = SimpleNamespace(data=b"", sections={})
        with pytest.raises(typer.Exit) as exc:
            cmd_extract(binary, [], 0x9999, tmp_path, json_output=True)  # type: ignore[arg-type]
        assert exc.value.exit_code == 1
        out = json.loads(capsys.readouterr().out)
        assert "not found" in out["error"]

    def test_success_writes_bin(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        binary = SimpleNamespace(data=b"", sections={})
        monkeypatch.setattr("rebrew.extract.extract_bytes_at_va", lambda *a, **k: b"\x55\x8b\xec")
        _patch_disasm(monkeypatch)
        cmd_extract(binary, [(0x1000, 3, "f")], 0x1000, tmp_path)  # type: ignore[arg-type]
        assert (tmp_path / "func_0x00001000.bin").read_bytes() == b"\x55\x8b\xec"


class TestCmdBatch:
    def test_json_batch_with_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        binary = SimpleNamespace(data=b"", sections={})

        def _extract(bi, va, size):
            if va == 0x1000:
                return b"\x90\x90"
            return None

        monkeypatch.setattr("rebrew.extract.extract_bytes_at_va", _extract)
        _patch_disasm(monkeypatch)
        candidates = [(0x1000, 2, "good"), (0x2000, 8, "bad")]
        cmd_batch(binary, candidates, 2, 0, tmp_path, json_output=True)  # type: ignore[arg-type]
        out = json.loads(capsys.readouterr().out)
        assert out["count"] == 2
        statuses = {r["name"]: r["status"] for r in out["results"]}
        assert statuses == {"good": "OK", "bad": "ERROR"}

    def test_json_disasm_error_batch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        binary = SimpleNamespace(data=b"", sections={})
        monkeypatch.setattr("rebrew.extract.extract_bytes_at_va", lambda *a, **k: b"\x90\x90")

        def _boom(code, va, cfg=None):
            raise RuntimeError("no capstone")

        monkeypatch.setattr("rebrew.extract.disasm_bytes", _boom)
        cmd_batch(binary, [(0x1000, 2, "f")], 1, 0, tmp_path, json_output=True)  # type: ignore[arg-type]
        out = json.loads(capsys.readouterr().out)
        assert out["results"][0]["status"] == "ERROR"

    def test_non_json_extract_error_continues(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        binary = SimpleNamespace(data=b"", sections={})
        monkeypatch.setattr("rebrew.extract.extract_bytes_at_va", lambda *a, **k: None)
        cmd_batch(binary, [(0x1000, 8, "bad")], 1, 0, tmp_path)  # type: ignore[arg-type]
        # Non-JSON: prints error, continues without raising.
        assert "Failed to extract bytes" in capsys.readouterr().err


class TestExtractCli:
    def _setup(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        cfg = _cfg(tmp_path)
        monkeypatch.setattr("rebrew.extract.require_config", lambda **kw: cfg)
        monkeypatch.setattr(
            "rebrew.extract.load_binary", lambda p: SimpleNamespace(data=b"", sections={})
        )
        return cfg

    def test_list_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.extract import app

        self._setup(tmp_path, monkeypatch)
        (tmp_path / "functions.txt").write_text("0x1000 64 func_a\n", encoding="utf-8")
        result = CliRunner().invoke(app, ["list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["count"] == 1
        assert data["candidates"][0]["name"] == "func_a"

    def test_list_size_filter(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.extract import app

        self._setup(tmp_path, monkeypatch)
        (tmp_path / "functions.txt").write_text(
            "0x1000 64 func_a\n0x2000 200 func_b\n", encoding="utf-8"
        )
        result = CliRunner().invoke(app, ["list", "--json", "--min-size", "100"])
        data = json.loads(result.output)
        assert data["count"] == 1
        assert data["candidates"][0]["name"] == "func_b"

    def test_show_with_size_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.extract import app

        self._setup(tmp_path, monkeypatch)
        (tmp_path / "functions.txt").write_text("0x1000 64 func_a\n", encoding="utf-8")
        monkeypatch.setattr("rebrew.extract.extract_bytes_at_va", lambda *a, **k: b"\x90" * 16)
        monkeypatch.setattr("rebrew.extract.disasm_bytes", lambda *a, **k: "nop")
        result = CliRunner().invoke(app, ["show", "0x1000", "--size", "16", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "OK"
        assert data["size"] == 16

    def test_batch_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.extract import app

        self._setup(tmp_path, monkeypatch)
        (tmp_path / "functions.txt").write_text(
            "0x1000 64 func_a\n0x2000 32 func_b\n", encoding="utf-8"
        )
        monkeypatch.setattr("rebrew.extract.extract_bytes_at_va", lambda *a, **k: b"\x90" * 8)
        monkeypatch.setattr("rebrew.extract.disasm_bytes", lambda *a, **k: "nop")
        result = CliRunner().invoke(app, ["batch", "2", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["count"] == 2

    def test_missing_function_list_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.extract import app

        self._setup(tmp_path, monkeypatch)
        result = CliRunner().invoke(app, ["list", "--json"])
        assert result.exit_code != 0
        assert "No function list found" in result.output
