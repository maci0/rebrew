"""Tests for rebrew.msvc16 — MSVC 1.52 (16-bit) compilation support."""

from __future__ import annotations

from pathlib import Path

import pytest

from rebrew.msvc16 import Msvc16Error, compile_c


def _fake_cl(monkeypatch, sandbox: Path) -> None:
    """Simulate a successful DOSBox run: write the CL log + a .OBJ."""

    def _run(args, **kwargs):  # noqa: ARG001
        (sandbox / "CLOUT.TXT").write_text("test.c\n", encoding="utf-8")
        (sandbox / "TEST.OBJ").write_bytes(b"\x80\x08\x00fake")
        return type("R", (), {"returncode": 0})()

    monkeypatch.setattr("rebrew.dosbox.subprocess.run", _run)


class TestCompileC:
    def test_compiles_and_finds_obj(self, tmp_path: Path, monkeypatch) -> None:
        src = tmp_path / "test.c"
        src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
        workdir = tmp_path / "sandbox"
        _fake_cl(monkeypatch, workdir)
        r = compile_c(src, workdir)
        assert r.obj_path.name == "TEST.OBJ"  # FAT-uppercased
        assert "test.c" in r.log

    def test_stages_toolchain_symlinks(self, tmp_path: Path, monkeypatch) -> None:
        src = tmp_path / "test.c"
        src.write_text("int f(void) { return 1; }\n", encoding="utf-8")
        workdir = tmp_path / "sandbox"
        _fake_cl(monkeypatch, workdir)
        compile_c(src, workdir)
        assert (workdir / "BIN" / "CL.EXE").exists()
        assert (workdir / "INCLUDE").is_dir()
        assert (workdir / "LIB").is_dir()

    def test_no_obj_raises(self, tmp_path: Path, monkeypatch) -> None:
        src = tmp_path / "test.c"
        src.write_text("int f(void) { return 1; }\n", encoding="utf-8")

        def _run_no_output(args, **kwargs):  # noqa: ARG001
            return type("R", (), {"returncode": 0})()

        monkeypatch.setattr("rebrew.dosbox.subprocess.run", _run_no_output)
        with pytest.raises(Msvc16Error, match="no object"):
            compile_c(src, tmp_path / "sandbox")

    def test_missing_toolchain_raises(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(
            "rebrew.msvc16._find_vc152", lambda: (_ for _ in ()).throw(Msvc16Error("not found"))
        )
        src = tmp_path / "test.c"
        src.write_text("int f(void) { return 1; }\n", encoding="utf-8")
        with pytest.raises(Msvc16Error, match="not found"):
            compile_c(src, tmp_path / "sandbox")


class TestDosboxRunner:
    def test_run_dosbox_writes_conf(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.dosbox import run_dosbox

        calls: list[list[str]] = []

        def _run(cmd, **kwargs):
            calls.append(cmd)
            return type("R", (), {"returncode": 0})()

        monkeypatch.setattr("rebrew.dosbox.shutil.which", lambda *a, **k: "/usr/bin/dosbox")
        monkeypatch.setattr("rebrew.dosbox.subprocess.run", _run)
        run_dosbox(tmp_path, ["C:\\DCC.EXE hello.dpr"])
        conf = (tmp_path / "run.conf").read_text(encoding="utf-8")
        assert "mount c " + str(tmp_path) in conf
        assert "C:\\DCC.EXE hello.dpr" in conf
        assert calls[0][0] == "dosbox"

    def test_missing_dosbox_raises(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.dosbox import DosboxError, run_dosbox

        monkeypatch.setattr("rebrew.dosbox.shutil.which", lambda *a, **k: None)
        with pytest.raises(DosboxError, match="dosbox"):
            run_dosbox(tmp_path, [])
