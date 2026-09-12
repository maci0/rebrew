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

    def test_overlapping_placements_raise(self, tmp_path: Path) -> None:
        """Overlapping placements must fail loud, never emit a corrupt
        object (the old code skipped `symbols.append`, desyncing the symbol
        table from the section bytes)."""
        path = tmp_path / "overlap.o"
        with pytest.raises(ValueError, match="overlapping placement"):
            objdiff_project.write_coff_object(
                path,
                [("_first", 0, b"\x55\x8b\xec"), ("_overlap", 1, b"\xb8\x01")],
            )


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
            ["--output", str(out), "--target-dir", str(tmp_path / "target")],
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

    def test_extract_failure_skips_function_with_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One bad function must not abort the project: it is skipped with a
        warning while good functions still synthesize (binary_similarity
        `_load_side` parity)."""
        cfg = self._cfg(tmp_path)
        (cfg.reversed_dir / "funcs").mkdir(exist_ok=True)
        src_file = cfg.reversed_dir / "funcs" / "a.c"
        src_file.write_text("// FUNCTION: T 0x1000\nint a(void){return 0;}\n", encoding="utf-8")

        monkeypatch.setattr(
            objdiff_project,
            "iter_annotations",
            lambda sources, target=None, metadata_dir=None: [
                (
                    src_file,
                    [
                        _fake_ann(0x1000, 5, "good", "_good"),
                        _fake_ann(0x2000, 5, "bad", "_bad"),
                    ],
                )
            ],
        )

        def _fake_extract(p: object, va: int, size: int) -> bytes:
            if va == 0x2000:
                raise RuntimeError("bad section")
            return b"\x55\x8b\xec\x5d\xc3"

        monkeypatch.setattr("rebrew.binary_loader.extract_raw_bytes", _fake_extract)
        units = objdiff_project._synthesize_target_objects(cfg, tmp_path / "target")
        assert len(units) == 1
        target = Path(units[0]["target_path"])
        assert target.exists()

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

    def test_build_entry_uses_annotation_overrides(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The shim must resolve the file's own TOOLCHAIN/CFLAGS and module;
        passing empty strings compiled the base object with different flags
        than test/verify (objdiff showed a mismatch for an EXACT function)."""
        cfg = self._cfg(tmp_path)
        (cfg.reversed_dir / "funcs").mkdir(exist_ok=True)
        src_file = cfg.reversed_dir / "funcs" / "a.c"
        src_file.write_text(
            "// FUNCTION: T 0x1000\n// SIZE: 5\n// TOOLCHAIN: msvc-5.0\n// CFLAGS: /O1\n"
            "int a(void){return 0;}\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(
            objdiff_project, "require_config", lambda target=None, json_mode=False: cfg
        )
        base = tmp_path / "build" / "objdiff" / "current" / "funcs" / "a.c.o"
        base.parent.mkdir(parents=True, exist_ok=True)
        seen: dict[str, str] = {}
        monkeypatch.setattr(
            "rebrew.cli.resolve_compile_overrides",
            lambda cfg_, d, tool, cfl, mod: (
                seen.update(tool=tool, cflags=cfl, module=mod),
                ("msvc-5.0", "/O1"),
            )[1],
        )
        monkeypatch.setattr(
            "rebrew.compile.compile_to_obj",
            lambda cfg_, source, cflags, workdir, **kw: (str(workdir / kw["obj_name"]), ""),
        )
        import sys

        monkeypatch.setattr(sys, "argv", ["rebrew-objdiff-build", "T", str(base)])
        objdiff_project.objdiff_build_entry()
        assert seen == {"tool": "msvc-5.0", "cflags": "/O1", "module": "T"}

    def test_watch_patterns_follow_reversed_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The config's watch globs come from cfg.reversed_dir, not a literal
        ``src/``: a project under ``reversed/`` never triggered a rebuild."""
        cfg = self._cfg(tmp_path)
        cfg.reversed_dir = tmp_path / "reversed"
        cfg.reversed_dir.mkdir(exist_ok=True)
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
            ["--output", str(out), "--target-dir", str(tmp_path / "target")],
        )
        assert r.exit_code == 0
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert doc["watch_patterns"] == ["reversed/**/*.c", "reversed/**/*.h"]

    def test_watch_patterns_default_src_layout(self, tmp_path: Path) -> None:
        """The default src/ layout keeps the historical globs."""
        cfg = self._cfg(tmp_path)
        assert objdiff_project._watch_patterns(cfg) == ["src/**/*.c", "src/**/*.h"]


class TestSynthesizeOrdering(TestObjdiffProject):
    def test_out_of_va_order_functions_do_not_overlap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Annotations arrive in source order; a file listing a higher VA first
        must still synthesize (write_coff_object rejects decreasing offsets)."""
        cfg = self._cfg(tmp_path)
        (cfg.reversed_dir / "funcs").mkdir(exist_ok=True)
        src_file = cfg.reversed_dir / "funcs" / "a.c"
        src_file.write_text("// FUNCTION: T 0x2000\nint b(void){return 0;}\n", encoding="utf-8")
        monkeypatch.setattr(
            objdiff_project,
            "iter_annotations",
            lambda sources, target=None, metadata_dir=None: [
                (
                    src_file,
                    [_fake_ann(0x2000, 5, "b", "_b"), _fake_ann(0x1000, 5, "a", "_a")],
                )
            ],
        )
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_raw_bytes", lambda p, va, size: b"\x55\x8b\xec\x5d\xc3"
        )
        units = objdiff_project._synthesize_target_objects(cfg, tmp_path / "target")
        assert len(units) == 1
        assert Path(units[0]["target_path"]).read_bytes()[:2] == b"\x4c\x01"
