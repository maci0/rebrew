"""Tests for rebrew.pdb_info — PDB compiler/flags/function extraction."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from rebrew.pdb_info import _parse_compile3, _parse_procs, extract_pdb_info


class TestParseCompile3:
    def test_msvc_flags(self) -> None:
        text = (
            " 123 | S_COMPILE3 [size = 200]\n"
            "        frontend = 14.00.24210, backend = 14.00.24210\n"
            "        flags = /O1 /MT /Gd\n"
        )
        frontend, backend, flags = _parse_compile3(text)
        assert frontend == "14.00.24210"
        assert backend == "14.00.24210"
        assert flags == ["/O1", "/MT", "/Gd"]

    def test_no_flags(self) -> None:
        text = (
            "S_COMPILE3 [size = 132]\n frontend = 20.1.2.0, backend = 20012.0.0.0\n flags = none\n"
        )
        frontend, backend, flags = _parse_compile3(text)
        assert frontend == "20.1.2.0"
        assert flags == []

    def test_no_record(self) -> None:
        assert _parse_compile3("no records here") == ("", "", [])


class TestParseProcs:
    def test_detail_block_names(self) -> None:
        text = (
            " 100 | S_GPROC32 [size = 64]\n"
            "        type = 0x1001 (int ()), debug start = 0x401000, debug end = 0x401020\n"
            "        flags = none, name = 'do_thing'\n"
            " 200 | S_LPROC32 [size = 32]\n"
            "        type = 0x1002, debug start = 0x401020, debug end = 0x401040\n"
            "        flags = none, name = 'helper'\n"
        )
        funcs = _parse_procs(text)
        assert len(funcs) == 2
        assert funcs[0]["name"] == "do_thing"
        assert funcs[0]["start"] == "0x401000"
        assert funcs[1]["name"] == "helper"

    def test_inline_names(self) -> None:
        text = "S_LPROC32 [size = 20] `main`\n"
        funcs = _parse_procs(text)
        assert len(funcs) == 1
        assert funcs[0]["name"] == "main"

    def test_none(self) -> None:
        assert _parse_procs("nothing") == []


class TestExtract:
    def _mock(self, monkeypatch, syms: str = "", mods: str = "") -> None:
        monkeypatch.setattr(
            "shutil.which", lambda name: "/usr/bin/llvm-pdbutil" if name == "llvm-pdbutil" else None
        )
        monkeypatch.setattr(
            "pathlib.Path.exists", lambda self: str(self).endswith(".pdb"), raising=False
        )

        def _fake_run(cmd: list[str], **kwargs: object) -> SimpleNamespace:
            if "-modules" in cmd:
                return SimpleNamespace(returncode=0, stdout=mods, stderr="")
            return SimpleNamespace(returncode=0, stdout=syms, stderr="")

        monkeypatch.setattr("rebrew.pdb_info.subprocess.run", _fake_run)

    def test_no_pdb_returns_none(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.setattr("shutil.which", lambda name: None)
        assert extract_pdb_info(tmp_path / "prog.exe") is None

    def test_zig_pdb(self, monkeypatch, tmp_path: Path) -> None:
        self._mock(
            monkeypatch,
            syms="S_COMPILE3 [size = 132]\n frontend = 20.1.2.0, backend = 20012.0.0.0\n flags = none\n",
            mods="/home/user/.zig-cache/o/abc/prog.obj",
        )
        info = extract_pdb_info(tmp_path / "prog.exe")
        assert info is not None
        assert info.toolchain == "zig"
        assert info.frontend == "20.1.2.0"

    def test_msvc_pdb(self, monkeypatch, tmp_path: Path) -> None:
        self._mock(
            monkeypatch,
            syms=(
                "S_COMPILE3 [size = 200]\n frontend = 14.00.24210, backend = 14.00.24210\n flags = /O1 /MT\n"
                "S_GPROC32 [size = 64]\n type = 0x1001, debug start = 0x401000, debug end = 0x401020\n"
                " flags = none, name = 'main'\n"
            ),
        )
        info = extract_pdb_info(tmp_path / "prog.exe")
        assert info is not None
        assert info.toolchain == "MSVC 8.0"  # 14.00 frontend
        assert info.flags == ["/O1", "/MT"]
        assert len(info.functions) == 1
        assert info.functions[0]["name"] == "main"

    def test_pdbutil_crash_graceful(self, monkeypatch, tmp_path: Path) -> None:
        def _boom(cmd: list[str], **kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(
            "shutil.which", lambda name: "/usr/bin/llvm-pdbutil" if name == "llvm-pdbutil" else None
        )
        monkeypatch.setattr(
            "pathlib.Path.exists", lambda self: str(self).endswith(".pdb"), raising=False
        )
        monkeypatch.setattr("rebrew.pdb_info.subprocess.run", _boom)
        info = extract_pdb_info(tmp_path / "prog.exe")
        assert info is not None
        assert info.error  # reported unsupported, not raised
