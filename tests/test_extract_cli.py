"""Tests for extract.py CLI paths (list/show) with mocked pipeline."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import rebrew.extract as extract_mod

runner = CliRunner()


def _patch(
    monkeypatch: pytest.MonkeyPatch, candidates: list[tuple[int, int, str]]
) -> SimpleNamespace:
    cfg = SimpleNamespace(bin_dir=Path("/tmp/bin"), target_binary=Path("/tmp/x.dll"))
    monkeypatch.setattr(
        extract_mod,
        "_setup_candidates",
        lambda target, json_output, exe, min_size, max_size: (cfg, candidates, Path("/tmp/x.dll")),
    )
    return cfg


class TestExtractCli:
    def test_list_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, [(0x1000, 64, "f")])
        r = runner.invoke(extract_mod.app, ["list", "--json"])
        assert r.exit_code == 0
        payload = json.loads(r.stdout)
        assert payload["count"] == 1
        assert payload["candidates"][0]["va"] == "0x00001000"

    def test_show_size_override_injects_candidate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, [(0x2000, 32, "existing")])
        seen: dict[str, object] = {}
        monkeypatch.setattr(extract_mod, "load_binary", lambda p: SimpleNamespace())

        def fake_cmd_extract(binary_info, candidates, va, bin_dir, cfg=None, json_output=False):
            seen["candidates"] = candidates
            seen["va"] = va

        monkeypatch.setattr(extract_mod, "cmd_extract", fake_cmd_extract)
        r = runner.invoke(extract_mod.app, ["show", "0x1000", "--size", "16"])
        assert r.exit_code == 0
        # --size injects a synthetic entry at the requested VA.
        assert seen["va"] == 0x1000
        assert seen["candidates"][0] == (0x1000, 16, "0x00001000")

    def test_show_json_passthrough(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, [])
        monkeypatch.setattr(extract_mod, "load_binary", lambda p: SimpleNamespace())
        seen: dict[str, object] = {}

        def fake_cmd_extract(*a: object, **k: object) -> None:
            seen["va"] = a[2]
            seen["json_output"] = k.get("json_output")

        monkeypatch.setattr(extract_mod, "cmd_extract", fake_cmd_extract)
        r = runner.invoke(extract_mod.app, ["show", "0x1000", "--json"])
        assert r.exit_code == 0
        # --json must reach cmd_extract as json_output=True at the right VA.
        assert seen["va"] == 0x1000
        assert seen["json_output"] is True


class TestCmdExtract:
    def _info(self) -> SimpleNamespace:
        return SimpleNamespace()

    def test_success_writes_bin(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.extract as extract_mod

        monkeypatch.setattr(extract_mod, "extract_bytes_at_va", lambda _info, va, size: b"\x55\xc3")
        monkeypatch.setattr(extract_mod, "disasm_bytes", lambda code, va, cfg=None: "push ebp\nret")
        extract_mod.cmd_extract(self._info(), [(0x1000, 4, "f")], 0x1000, tmp_path)
        assert (tmp_path / "func_0x00001000.bin").exists()

    def test_empty_extraction_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import typer

        import rebrew.extract as extract_mod

        monkeypatch.setattr(extract_mod, "extract_bytes_at_va", lambda *a, **k: b"")
        with pytest.raises(typer.Exit) as exc:
            extract_mod.cmd_extract(self._info(), [(0x1000, 4, "f")], 0x1000, tmp_path)
        assert exc.value.exit_code == 1

    def test_va_not_found_errors(self, tmp_path: Path) -> None:
        import typer

        import rebrew.extract as extract_mod

        with pytest.raises(typer.Exit) as exc:
            extract_mod.cmd_extract(self._info(), [(0x2000, 4, "f")], 0x1000, tmp_path)
        assert exc.value.exit_code == 1

    def test_disasm_failure_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import typer

        import rebrew.extract as extract_mod

        monkeypatch.setattr(extract_mod, "extract_bytes_at_va", lambda *a, **k: b"\x55")
        monkeypatch.setattr(
            extract_mod,
            "disasm_bytes",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no capstone")),
        )
        with pytest.raises(typer.Exit) as exc:
            extract_mod.cmd_extract(self._info(), [(0x1000, 4, "f")], 0x1000, tmp_path)
        assert exc.value.exit_code == 1

    def test_json_success(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: object
    ) -> None:
        import json

        import rebrew.extract as extract_mod

        monkeypatch.setattr(extract_mod, "extract_bytes_at_va", lambda *a, **k: b"\x55")
        monkeypatch.setattr(extract_mod, "disasm_bytes", lambda *a, **k: "push ebp")
        extract_mod.cmd_extract(
            self._info(), [(0x1000, 4, "f")], 0x1000, tmp_path, json_output=True
        )
        # json_print writes to stdout — capture via capsys.
        out, _err = capsys.readouterr()
        payload = json.loads(out)
        assert payload["status"] == "OK"
        assert payload["va"] == "0x00001000"


class TestCmdBatch:
    def _info(self) -> SimpleNamespace:
        return SimpleNamespace()

    def test_batch_json_items(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: object
    ) -> None:
        import json

        import rebrew.extract as extract_mod

        monkeypatch.setattr(
            extract_mod,
            "extract_bytes_at_va",
            lambda info, va, size: b"\x55" if va == 0x1000 else b"",
        )
        monkeypatch.setattr(extract_mod, "disasm_bytes", lambda *a, **k: "push ebp")
        candidates = [(0x1000, 4, "f1"), (0x2000, 4, "f2")]
        extract_mod.cmd_batch(
            self._info(), candidates, count=2, start=0, bin_dir=tmp_path, json_output=True
        )
        out, _err = capsys.readouterr()
        payload = json.loads(out)
        statuses = {i["va"]: i["status"] for i in payload["results"]}
        assert statuses["0x00001000"] == "OK"
        assert statuses["0x00002000"] == "ERROR"

    def test_batch_writes_bins(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.extract as extract_mod

        monkeypatch.setattr(extract_mod, "extract_bytes_at_va", lambda *a, **k: b"\x55")
        monkeypatch.setattr(extract_mod, "disasm_bytes", lambda *a, **k: "push ebp")
        extract_mod.cmd_batch(self._info(), [(0x1000, 4, "f")], count=1, start=0, bin_dir=tmp_path)
        assert (tmp_path / "func_0x00001000.bin").exists()

    def test_batch_start_offset(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.extract as extract_mod

        seen: list[int] = []
        monkeypatch.setattr(
            extract_mod,
            "extract_bytes_at_va",
            lambda info, va, size: seen.append(va) or b"\x55",
        )
        monkeypatch.setattr(extract_mod, "disasm_bytes", lambda *a, **k: "nop")
        candidates = [(0x1000, 4, "a"), (0x2000, 4, "b"), (0x3000, 4, "c")]
        extract_mod.cmd_batch(self._info(), candidates, count=2, start=1, bin_dir=tmp_path)
        assert seen == [0x2000, 0x3000]  # start offset skips the first
