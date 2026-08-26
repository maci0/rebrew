"""Tests for objdiff_project.py — COFF target-object synthesis + objdiff config."""

import json
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import rebrew.objdiff_project as objdiff_project

runner = CliRunner()


def _fake_ann(
    va: int, size: int, name: str, symbol: str = "", marker: str = "FUNCTION"
) -> SimpleNamespace:
    return SimpleNamespace(va=va, size=size, name=name, symbol=symbol, marker_type=marker)


class TestWriteCoffObject:
    def test_roundtrip_i386(self, tmp_path: Path) -> None:
        """The synthesized object must be a parseable i386 COFF with the
        expected symbols and section content."""
        path = tmp_path / "f.o"
        objdiff_project.write_coff_object(
            path,
            [
                ("_first", 0, b"\x55\x8b\xec"),
                ("_second", 16, b"\xb8\x01\x00\x00\x00"),
            ],
        )
        data = path.read_bytes()
        machine, nsec, _ts, sym_off, n_syms, _optsz, _chars = struct.unpack_from("<HHIIIHH", data)
        assert machine == 0x014C
        assert nsec == 1
        assert n_syms == 2
        # Section raw data starts at 60 and holds the two blobs with padding.
        assert data[60:63] == b"\x55\x8b\xec"
        assert data[76:81] == b"\xb8\x01\x00\x00\x00"
        # Symbols: value = section offset, section 1, EXTERNAL.
        first_sym = struct.unpack_from("<8sIHHBB", data, sym_off)
        assert first_sym[1] == 0  # value
        assert first_sym[2] == 1  # section 1
        assert first_sym[4] == 2  # EXTERNAL
        assert first_sym[0].rstrip(b"\x00") == b"_first"

    def test_parseable_by_objdump(self, tmp_path: Path) -> None:
        """The object must be readable by an independent COFF parser (the
        same class of reader objdiff uses).  binutils objdump is the
        closest available proxy."""
        import shutil
        import subprocess

        if shutil.which("objdump") is None:
            pytest.skip("objdump not available")
        path = tmp_path / "f.o"
        objdiff_project.write_coff_object(
            path,
            [("_first", 0, b"\xc3"), ("_long_function_name_over_8", 16, b"\x90")],
        )
        r = subprocess.run(["objdump", "-t", str(path)], capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr
        assert "_first" in r.stdout
        assert "_long_function_name_over_8" in r.stdout

    def test_arm_machine_parameter(self, tmp_path: Path) -> None:
        """The multi-arch path is a machine parameter, not a fork."""
        path = tmp_path / "arm.o"
        objdiff_project.write_coff_object(path, [("arm_fn", 0, b"\x00")], machine=0x01C0)
        machine = struct.unpack_from("<H", path.read_bytes(), 0)[0]
        assert machine == 0x01C0


class TestObjdiffProject:
    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        src = tmp_path / "src"
        src.mkdir(exist_ok=True)
        return SimpleNamespace(
            target_binary=tmp_path / "x.dll",
            reversed_dir=src,
            root=tmp_path,
            target_name="T",
            metadata_dir=tmp_path,
            function_list=tmp_path / "functions.txt",
            source_ext=".c",
            marker="T",
        )

    def test_generates_units_and_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = self._cfg(tmp_path)
        (cfg.reversed_dir / "funcs").mkdir(exist_ok=True)
        src_file = cfg.reversed_dir / "funcs" / "a.c"
        src_file.write_text("// FUNCTION: T 0x1000\nint a(void){return 0;}\n", encoding="utf-8")

        monkeypatch.setattr(
            objdiff_project, "require_config", lambda target=None, json_mode=False: cfg
        )
        monkeypatch.setattr(
            objdiff_project,
            "iter_annotations",
            lambda sources, target=None, metadata_dir=None: [
                (src_file, [_fake_ann(0x1000, 5, "a", "_a")])
            ],
        )
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_raw_bytes", lambda p, va, size: b"\x55\x8b\xec\x5d\xc3"
        )
        out = tmp_path / "objdiff.json"
        r = runner.invoke(
            objdiff_project.app,
            ["--out", str(out), "--target-dir", str(tmp_path / "target")],
        )
        assert r.exit_code == 0
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert doc["custom_make"] == "rebrew-objdiff-build"
        assert doc["custom_args"] == ["T"]
        assert len(doc["units"]) == 1
        unit = doc["units"][0]
        assert unit["name"] == "funcs/a.c"
        assert unit["base_path"] == "build/objdiff/current/funcs/a.c.o"
        # Target object exists and is a valid COFF.
        target = Path(unit["target_path"])
        assert target.exists()
        assert struct.unpack_from("<H", target.read_bytes(), 0)[0] == 0x014C

    def test_build_entry_maps_object_to_source(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = self._cfg(tmp_path)
        (cfg.reversed_dir / "funcs").mkdir(exist_ok=True)
        src_file = cfg.reversed_dir / "funcs" / "a.c"
        src_file.write_text("int a(void){return 0;}\n", encoding="utf-8")
        monkeypatch.setattr(
            objdiff_project, "require_config", lambda target=None, json_mode=False: cfg
        )
        base = tmp_path / "build" / "objdiff" / "current" / "funcs" / "a.c.o"
        base.parent.mkdir(parents=True, exist_ok=True)
        calls: list[tuple] = []

        def _fake_compile(cfg_, source, cflags, workdir, **kw):
            calls.append((source, cflags, workdir, kw.get("obj_name")))
            return str(workdir / (kw.get("obj_name") or "x.o")), ""

        monkeypatch.setattr("rebrew.compile.compile_to_obj", _fake_compile)
        monkeypatch.setattr(
            "rebrew.cli.resolve_compile_overrides", lambda cfg, d, a, b, c: (None, "")
        )
        import sys

        monkeypatch.setattr(sys, "argv", ["rebrew-objdiff-build", "T", str(base)])
        objdiff_project.objdiff_build_entry()
        assert len(calls) == 1
        assert calls[0][0] == src_file
        assert calls[0][3] == base.name
