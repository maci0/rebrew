"""Tests for rebrew lib-match — byte-compare reversed functions vs .lib archives."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from bin_util import make_coff_obj, make_lib_archive, make_pe
from typer.testing import CliRunner

CODE = bytes(range(1, 41))  # 40 distinct bytes; same in lib and target
LIB_CODE = CODE


def _write_project(tmp_path: Path) -> tuple[Path, Path, int]:
    """Write a fake project: target PE + reversed source + a library.

    Returns (pe_path, lib_path, va).
    """
    image_base = 0x400000
    text_va = 0x1000
    va = image_base + text_va
    pe_path = tmp_path / "target.dll"
    pe_path.write_bytes(make_pe(CODE, image_base=image_base, text_va=text_va))

    obj = make_coff_obj(LIB_CODE, func_symbol="_mylibfn")
    lib_path = tmp_path / "mylib.lib"
    lib_path.write_bytes(make_lib_archive([("mylib.obj", obj)]))

    src = tmp_path / "reversed"
    src.mkdir(exist_ok=True)
    (src / "foo.c").write_text(
        f"// FUNCTION: SERVER 0x{va:x}\nint foo(void) {{ return 0; }}\n",
        encoding="utf-8",
    )
    return pe_path, lib_path, va


def _mock_cfg(tmp_path: Path, pe_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    cfg = SimpleNamespace(
        root=tmp_path,
        reversed_dir=tmp_path / "reversed",
        metadata_dir=tmp_path,
        marker="SERVER",
        source_ext=".c",
        shared_dir=None,
        target_binary=pe_path,
    )
    import rebrew.cli as cli_mod
    import rebrew.lib_match as lm

    monkeypatch.setattr(cli_mod, "require_config", lambda **kw: cfg)
    monkeypatch.setattr(lm, "require_config", lambda **kw: cfg)
    return cfg


class TestLibMatch:
    def test_flags_reversed_library_function(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.lib_match import app

        pe_path, lib_path, _ = _write_project(tmp_path)
        _mock_cfg(tmp_path, pe_path, monkeypatch)
        res = CliRunner().invoke(app, ["--lib", str(lib_path)])
        assert res.exit_code == 1, res.output
        assert "_mylibfn" in res.output

    def test_clean_function_not_flagged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.lib_match import app

        pe_path, lib_path, va = _write_project(tmp_path)
        # overwrite the reversed source's function region check: point the
        # binary at different bytes so nothing in the lib matches.
        other = bytes(range(0x80, 0xA8))
        pe_path.write_bytes(make_pe(other, image_base=0x400000, text_va=0x1000))
        assert va == 0x401000
        _mock_cfg(tmp_path, pe_path, monkeypatch)
        res = CliRunner().invoke(app, ["--lib", str(lib_path)])
        assert res.exit_code == 0, res.output

    def test_allowlist_suppresses(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.lib_match import app

        pe_path, lib_path, va = _write_project(tmp_path)
        _mock_cfg(tmp_path, pe_path, monkeypatch)
        allow = tmp_path / "allow.txt"
        allow.write_text(f"# displaced for the link\n0x{va:x}\n", encoding="utf-8")
        res = CliRunner().invoke(app, ["--lib", str(lib_path), "--allow", str(allow)])
        assert res.exit_code == 0, res.output

    def test_va_verdict(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.lib_match import app

        pe_path, lib_path, va = _write_project(tmp_path)
        _mock_cfg(tmp_path, pe_path, monkeypatch)
        res = CliRunner().invoke(app, ["--lib", str(lib_path), "--va", f"0x{va:x}"])
        assert res.exit_code == 1, res.output
        assert "_mylibfn" in res.output

    def test_json_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        from rebrew.lib_match import app

        pe_path, lib_path, _ = _write_project(tmp_path)
        _mock_cfg(tmp_path, pe_path, monkeypatch)
        res = CliRunner().invoke(app, ["--lib", str(lib_path), "--json"])
        assert res.exit_code == 1, res.output
        out = json.loads(res.output)
        assert out["count"] == 1
        assert out["findings"][0]["symbol"] == "_mylibfn"

    def test_static_helper_symbol_detected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression: MSVC marks helpers like _initterm STATIC; they are
        absent from the archive symbol index and must still be matched."""
        from rebrew.lib_match import app

        image_base = 0x400000
        text_va = 0x1000
        code = bytes(range(0x30, 0x58))  # helper body at offset 0
        pe = tmp_path / "target.dll"
        pe.write_bytes(make_pe(code, image_base=image_base, text_va=text_va))
        lib = tmp_path / "mylib.lib"
        # external _myfunc occupies offset 0..3; the STATIC helper follows.
        blob = make_coff_obj(
            b"\x90\x90\x90\x90" + code,
            func_symbol="_myfunc",
            section_symbols=[("_static_helper", 4)],
        )
        lib.write_bytes(make_lib_archive([("lib.obj", blob)]))
        src = tmp_path / "reversed"
        src.mkdir(exist_ok=True)
        va = image_base + text_va
        (src / "foo.c").write_text(
            f"// FUNCTION: SERVER 0x{va:x}\nint foo(void) {{ return 0; }}\n",
            encoding="utf-8",
        )
        _mock_cfg(tmp_path, pe, monkeypatch)
        res = CliRunner().invoke(app, ["--lib", str(lib)])
        assert res.exit_code == 1, res.output
        assert "_static_helper" in res.output

    def test_missing_lib_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.lib_match import app

        pe_path, _, _ = _write_project(tmp_path)
        _mock_cfg(tmp_path, pe_path, monkeypatch)
        res = CliRunner().invoke(app, [])
        assert res.exit_code == 2, res.output
