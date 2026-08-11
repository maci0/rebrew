"""Tests for rebrew.delphi16 — Delphi 1.0 (16-bit NE) compilation support."""

from __future__ import annotations

from pathlib import Path

import pytest

from rebrew.delphi16 import Delphi16Error, compile_ne


def _fake_compile(monkeypatch, sandbox: Path) -> None:
    """Simulate a successful DOSBox run: write the compiler log + a compiled
    NE executable (built with the shared NE test helper) into the sandbox."""

    def _run(args, **kwargs):  # noqa: ARG001
        from test_ne_loader import _build_ne

        code = b"\x01\x00" + bytes.fromhex("55 8b ec 5d c3") + b"\x00" * 8
        (sandbox / "DCCOUT.TXT").write_text(
            "Delphi Compiler  Version 8.0  Copyright (c) 1983,95 Borland International\n"
            "HELLO.DPR(1)\n5 lines, 100 bytes code.\n",
            encoding="utf-8",
        )
        (sandbox / "HELLO.EXE").write_bytes(_build_ne(segments=[(code, 0x01)]))
        return type("R", (), {"returncode": 0})()

    monkeypatch.setattr("rebrew.dosbox.subprocess.run", _run)


class TestCompileNe:
    def test_compiles_and_parses(self, tmp_path: Path, monkeypatch) -> None:
        """A successful DOSBox compile yields a parsed NE with its functions
        (DOSBox uppercases the output names — HELLO.EXE / DCCOUT.TXT)."""
        src = tmp_path / "hello.dpr"
        src.write_text("program Hello;\nbegin\nend.\n", encoding="utf-8")
        workdir = tmp_path / "sandbox"
        _fake_compile(monkeypatch, workdir)
        r = compile_ne(src, workdir, units_dir=tmp_path / "units")
        assert r.exe_path.name == "HELLO.EXE"
        assert "5 lines" in r.log
        assert len(r.funcs) >= 1
        assert r.funcs[0].va == 0x10002

    def test_stages_toolchain_and_cfg(self, tmp_path: Path, monkeypatch) -> None:
        """The sandbox gets the compiler trio + RTM.EXE + DCC.CFG (with the
        staged units path)."""
        src = tmp_path / "hello.dpr"
        src.write_text("program Hello;\n", encoding="utf-8")
        units = tmp_path / "units"
        units.mkdir()
        (units / "SYSUTILS.DCU").write_bytes(b"DCU1")
        workdir = tmp_path / "sandbox"
        _fake_compile(monkeypatch, workdir)
        compile_ne(src, workdir, units_dir=units)
        for f in ("DCC.EXE", "DELPHI.DSL", "DPMI16BI.OVL", "RTM.EXE", "DCC.CFG"):
            assert (workdir / f).exists(), f
        assert (workdir / "DELPHI" / "LIB" / "SYSUTILS.DCU").exists()
        cfg = (workdir / "DCC.CFG").read_text(encoding="utf-8")
        assert "/uC:\\DELPHI\\LIB" in cfg

    def test_no_executable_raises(self, tmp_path: Path, monkeypatch) -> None:
        src = tmp_path / "hello.dpr"
        src.write_text("program Hello;\n", encoding="utf-8")

        def _run_no_output(args, **kwargs):  # noqa: ARG001
            return type("R", (), {"returncode": 0})()

        monkeypatch.setattr("rebrew.dosbox.subprocess.run", _run_no_output)
        with pytest.raises(Delphi16Error, match="no executable"):
            compile_ne(src, tmp_path / "sandbox", units_dir=tmp_path / "u")

    def test_missing_dosbox_raises(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr("rebrew.delphi16.shutil.which", lambda *a, **k: None)
        src = tmp_path / "hello.dpr"
        src.write_text("program Hello;\n", encoding="utf-8")
        with pytest.raises(Delphi16Error, match="dosbox"):
            compile_ne(src, tmp_path / "sandbox", units_dir=tmp_path / "u")

    def test_dosbox_timeout_raises(self, tmp_path: Path, monkeypatch) -> None:
        import subprocess

        def _run_timeout(args, **kwargs):  # noqa: ARG001
            raise subprocess.TimeoutExpired("dosbox", 5)

        monkeypatch.setattr("rebrew.dosbox.subprocess.run", _run_timeout)
        src = tmp_path / "hello.dpr"
        src.write_text("program Hello;\n", encoding="utf-8")
        with pytest.raises(Delphi16Error, match="DOSBox"):
            compile_ne(src, tmp_path / "sandbox", units_dir=tmp_path / "u")
