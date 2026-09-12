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


class TestLoadAllowlist:
    def test_none_is_empty(self) -> None:
        from rebrew.lib_match import load_allowlist

        assert load_allowlist(None) == set()

    def test_hex_entries_comments_and_blanks(self, tmp_path: Path) -> None:
        from rebrew.lib_match import load_allowlist

        p = tmp_path / "allow.txt"
        p.write_text("# known CRT\n0x401000\n\n  0x401010  # inline\n", encoding="utf-8")
        assert load_allowlist(p) == {0x401000, 0x401010}

    def test_utf8_bom_is_tolerated(self, tmp_path: Path) -> None:
        from rebrew.lib_match import load_allowlist

        p = tmp_path / "allow.txt"
        p.write_bytes("\ufeff0x401000\n".encode())
        assert load_allowlist(p) == {0x401000}

    def test_malformed_entry_exits_cleanly(self, tmp_path: Path) -> None:
        import typer

        from rebrew.lib_match import load_allowlist

        p = tmp_path / "allow.txt"
        p.write_text("0x401000\nnot-a-va\n", encoding="utf-8")
        with pytest.raises(typer.Exit):
            load_allowlist(p, json_mode=True)


class TestMatchBytesRelocGuard:
    def test_relocs_beyond_window_do_not_reject_a_match(self) -> None:
        """Reloc offsets past the compared window must not tighten the
        mostly-relocation guard: only masks inside [0, len(data)) matter."""
        from rebrew.lib_match import match_bytes

        body = bytes(range(20))
        data = body[:16]
        # 8 in-range relocs (bytes 0..7) and one far past the window.
        relocs = {0, 1, 2, 3, 4, 5, 6, 7, 100}
        index = {"sym": [("obj", body, relocs)]}
        # In-range fixed bytes = 16 - 8 = 8 == 0.5 * 16, so the match stands;
        # the old `len(data) - len(relocs)` guard computed 7 and skipped it.
        assert match_bytes(index, data) == ("sym", "obj")


class TestIndexObjects:
    """Loose .obj indexing for libraries vendored as source (no .LIB)."""

    def test_matches_a_named_object(self, tmp_path: Path) -> None:
        from rebrew.lib_match import index_objects

        obj = tmp_path / "mylib.obj"
        obj.write_bytes(make_coff_obj(LIB_CODE, func_symbol="_mylibfn"))
        index = index_objects([obj])
        assert "_mylibfn" in index
        name, body, _relocs = index["_mylibfn"][0]
        assert name == "mylib.obj"
        assert body == LIB_CODE

    def test_short_file_is_skipped(self, tmp_path: Path) -> None:
        """A truncated object is skipped with a note, not a crash."""
        from rebrew.lib_match import index_objects

        obj = tmp_path / "stub.obj"
        obj.write_bytes(b"\x00\x00\x00\x00")
        assert index_objects([obj]) == {}


class TestVendoredObjects:
    """Which objects in a build database come from a source-vendored tree."""

    def _db(self, tmp_path: Path, entries: list[dict[str, str]]) -> Path:
        import json

        db = tmp_path / "build" / "compile_commands.json"
        db.parent.mkdir(parents=True, exist_ok=True)
        db.write_text(json.dumps(entries), encoding="utf-8")
        return db

    def test_picks_only_references_entries(self, tmp_path: Path) -> None:
        from rebrew.lib_match import vendored_objects

        vendored_obj = tmp_path / "build" / "ref.obj"
        own_obj = tmp_path / "build" / "own.obj"
        vendored_obj.parent.mkdir(parents=True, exist_ok=True)
        vendored_obj.write_bytes(b"x")
        own_obj.write_bytes(b"x")
        db = self._db(
            tmp_path,
            [
                {
                    "directory": str(tmp_path),
                    "file": "/proj/references/zlib/adler32.c",
                    "command": f"cl /c /Fo{vendored_obj} /proj/references/zlib/adler32.c",
                },
                {
                    "directory": str(tmp_path),
                    "file": "/proj/src/main.c",
                    "command": f"cl /c /Fo{own_obj} /proj/src/main.c",
                },
            ],
        )
        assert vendored_objects(db, tmp_path) == [vendored_obj]

    def test_missing_database_is_empty(self, tmp_path: Path) -> None:
        from rebrew.lib_match import vendored_objects

        assert vendored_objects(tmp_path / "nope.json", tmp_path) == []

    def test_relative_output_resolves_against_directory(self, tmp_path: Path) -> None:
        from rebrew.lib_match import vendored_objects

        (tmp_path / "build").mkdir()
        (tmp_path / "build" / "ref.obj").write_bytes(b"x")
        db = self._db(
            tmp_path,
            [
                {
                    "directory": str(tmp_path),
                    "file": "/proj/references/x.c",
                    "command": "cl /c /Fobuild/ref.obj /proj/references/x.c",
                }
            ],
        )
        assert vendored_objects(db, tmp_path) == [tmp_path / "build" / "ref.obj"]


class TestStockLib:
    """Docker stock-LIB extraction plus the md5 stock check."""

    def _runtime(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import shutil

        import rebrew.lib_match as lm

        monkeypatch.setattr(lm, "container_runtime", lambda: "docker")
        monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")

    def test_ensure_stock_lib_extracts_from_registry_image(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.lib_match as lm

        self._runtime(monkeypatch)
        dest = tmp_path / ".scratch" / "libcmt_stock.LIB"
        seen: list[list[str]] = []

        def fake_run(argv: list[str], **kwargs: object) -> SimpleNamespace:
            seen.append(list(argv))
            dest.write_bytes(b"STOCK")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(lm.subprocess, "run", fake_run)
        assert lm.ensure_stock_lib(dest, profile="msvc-6.0-sp6", name="LIBCMT.LIB") is True
        argv = seen[0]
        assert "rebrew/msvc:6.0-sp6-win32" in argv
        assert "/opt/msvc6.0-sp6/VC98/Lib/LIBCMT.LIB" in argv

    def test_assert_library_is_stock_rejects_divergent_copy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import typer

        import rebrew.lib_match as lm

        self._runtime(monkeypatch)
        path = tmp_path / "libcmt_stock.LIB"
        path.write_bytes(b"EDITED")
        monkeypatch.setattr(
            lm.subprocess,
            "run",
            lambda argv, **kw: SimpleNamespace(
                returncode=0, stdout="aaaa  stock\nbbbb  /out/x\n", stderr=""
            ),
        )
        with pytest.raises(typer.Exit) as exc:
            lm.assert_library_is_stock(path, profile="msvc-6.0-sp6", name="LIBCMT.LIB")
        assert exc.value.exit_code == 2

    def test_assert_library_is_stock_errors_on_one_digest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A run that hashes fewer than two files is an error, not a pass."""
        import typer

        import rebrew.lib_match as lm

        self._runtime(monkeypatch)
        path = tmp_path / "libcmt_stock.LIB"
        path.write_bytes(b"STOCK")
        monkeypatch.setattr(
            lm.subprocess,
            "run",
            lambda argv, **kw: SimpleNamespace(returncode=0, stdout="aaaa  stock\n", stderr=""),
        )
        with pytest.raises(typer.Exit) as exc:
            lm.assert_library_is_stock(path, profile="msvc-6.0-sp6", name="LIBCMT.LIB")
        assert exc.value.exit_code == 2
