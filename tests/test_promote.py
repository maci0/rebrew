"""Tests for the rebrew promote command."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from typer.testing import CliRunner

from rebrew.promote import _STATUS_RANK, _promote_file, app

runner = CliRunner()


def _make_source(tmp_path: Path, content: str, filename: str = "test.c") -> Path:
    source = tmp_path / filename
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(content, encoding="utf-8")
    return source


class TestPromoteFile:
    def _make_cfg(self, tmp_path: Path) -> Any:
        return SimpleNamespace(
            marker="test.dll",
            reversed_dir=tmp_path,
            source_ext=".c",
            extract_dll_bytes=lambda _va, _size: b"\x55\x8b\xec\xc3",
            for_origin=lambda _origin: None,
        )

    def test_never_demotes(self, tmp_path: Path, monkeypatch: Any) -> None:
        source = _make_source(
            tmp_path,
            "// FUNCTION: test.dll 0x10001000\n"
            "// STATUS: EXACT\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 4\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _func\n"
            "void func(void) {}\n",
        )
        cfg = self._make_cfg(tmp_path)
        cfg.for_origin = lambda _origin: cfg

        calls: list[tuple[Any, ...]] = []

        def _fake_update(*args: Any, **kwargs: Any) -> None:
            calls.append((args, kwargs))

        monkeypatch.setattr("rebrew.promote.compile_obj", lambda *_args: ("fake.obj", ""))
        monkeypatch.setattr(
            "rebrew.promote.parse_obj_symbol_bytes", lambda *_args: (b"\x90\x90\x90\x90", [])
        )
        monkeypatch.setattr(
            "rebrew.promote.smart_reloc_compare", lambda *_args: (False, 1, 4, [], [])
        )
        monkeypatch.setattr("rebrew.promote.update_source_status", _fake_update)

        results = _promote_file(source, cfg, dry_run=False)
        assert calls == []
        assert results[0]["previous_status"] == "EXACT"
        assert results[0]["new_status"] == "EXACT"
        assert results[0]["action"] == "none"

    def test_promotes_stub_to_exact(self, tmp_path: Path, monkeypatch: Any) -> None:
        source = _make_source(
            tmp_path,
            "// FUNCTION: test.dll 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 4\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _func\n"
            "void func(void) {}\n",
        )
        cfg = self._make_cfg(tmp_path)
        cfg.for_origin = lambda _origin: cfg

        monkeypatch.setattr("rebrew.promote.compile_obj", lambda *_args: ("fake.obj", ""))
        monkeypatch.setattr(
            "rebrew.promote.parse_obj_symbol_bytes", lambda *_args: (b"\x55\x8b\xec\xc3", [])
        )
        monkeypatch.setattr(
            "rebrew.promote.smart_reloc_compare", lambda *_args: (True, 4, 4, [], [])
        )

        results = _promote_file(source, cfg, dry_run=False)
        assert results[0]["new_status"] == "EXACT"
        assert results[0]["action"] == "updated"
        assert "// STATUS: EXACT\n" in source.read_text(encoding="utf-8")

    def test_promotes_matching_to_exact(self, tmp_path: Path, monkeypatch: Any) -> None:
        source = _make_source(
            tmp_path,
            "// FUNCTION: test.dll 0x10001000\n"
            "// STATUS: MATCHING\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 4\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _func\n"
            "void func(void) {}\n",
        )
        cfg = self._make_cfg(tmp_path)
        cfg.for_origin = lambda _origin: cfg

        monkeypatch.setattr("rebrew.promote.compile_obj", lambda *_args: ("fake.obj", ""))
        monkeypatch.setattr(
            "rebrew.promote.parse_obj_symbol_bytes", lambda *_args: (b"\x55\x8b\xec\xc3", [])
        )
        monkeypatch.setattr(
            "rebrew.promote.smart_reloc_compare", lambda *_args: (True, 4, 4, [], [])
        )

        results = _promote_file(source, cfg, dry_run=False)
        assert results[0]["new_status"] == "EXACT"
        assert results[0]["action"] == "updated"
        assert "// STATUS: EXACT\n" in source.read_text(encoding="utf-8")

    def test_origin_filter_skips(self, tmp_path: Path, monkeypatch: Any) -> None:
        source = _make_source(
            tmp_path,
            "// FUNCTION: test.dll 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 4\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _func\n"
            "void func(void) {}\n",
        )
        cfg = self._make_cfg(tmp_path)

        calls: list[tuple[Any, ...]] = []

        def _fake_compile(*args: Any, **kwargs: Any) -> tuple[str | None, str]:
            calls.append((args, kwargs))
            return "fake.obj", ""

        monkeypatch.setattr("rebrew.promote.compile_obj", _fake_compile)

        results = _promote_file(source, cfg, dry_run=False, origin_filter="MSVCRT")
        assert calls == []
        assert len(results) == 1
        assert results[0]["status"] == "SKIPPED"

    def test_origin_filter_matches(self, tmp_path: Path, monkeypatch: Any) -> None:
        source = _make_source(
            tmp_path,
            "// FUNCTION: test.dll 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 4\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _func\n"
            "void func(void) {}\n",
        )
        cfg = self._make_cfg(tmp_path)
        cfg.for_origin = lambda _origin: cfg

        calls: list[tuple[Any, ...]] = []

        def _fake_compile(*args: Any, **kwargs: Any) -> tuple[str | None, str]:
            calls.append((args, kwargs))
            return "fake.obj", ""

        monkeypatch.setattr("rebrew.promote.compile_obj", _fake_compile)
        monkeypatch.setattr(
            "rebrew.promote.parse_obj_symbol_bytes", lambda *_args: (b"\x55\x8b\xec\xc3", [])
        )
        monkeypatch.setattr(
            "rebrew.promote.smart_reloc_compare", lambda *_args: (True, 4, 4, [], [])
        )

        results = _promote_file(source, cfg, dry_run=False, origin_filter="GAME")
        assert len(calls) == 1
        assert results[0]["status"] == "EXACT"

    def test_dry_run_no_write(self, tmp_path: Path, monkeypatch: Any) -> None:
        source = _make_source(
            tmp_path,
            "// FUNCTION: test.dll 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 4\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _func\n"
            "void func(void) {}\n",
        )
        cfg = self._make_cfg(tmp_path)
        cfg.for_origin = lambda _origin: cfg

        monkeypatch.setattr("rebrew.promote.compile_obj", lambda *_args: ("fake.obj", ""))
        monkeypatch.setattr(
            "rebrew.promote.parse_obj_symbol_bytes", lambda *_args: (b"\x55\x8b\xec\xc3", [])
        )
        monkeypatch.setattr(
            "rebrew.promote.smart_reloc_compare", lambda *_args: (True, 4, 4, [], [])
        )

        before = source.read_text(encoding="utf-8")
        results = _promote_file(source, cfg, dry_run=True)
        after = source.read_text(encoding="utf-8")
        assert results[0]["action"] == "would_update"
        assert before == after


class TestBatchPromote:
    def _make_cfg(self, tmp_path: Path) -> Any:
        return SimpleNamespace(
            marker="test.dll",
            reversed_dir=tmp_path,
            source_ext=".c",
            for_origin=lambda _origin: None,
            extract_dll_bytes=lambda _va, _size: b"",
        )

    def test_discovers_all_files(self, tmp_path: Path, monkeypatch: Any) -> None:
        _make_source(tmp_path, "int a;\n", "a.c")
        _make_source(tmp_path, "int b;\n", "nested/b.c")
        _make_source(tmp_path, "int c;\n", "nested/deeper/c.c")
        cfg = self._make_cfg(tmp_path)

        seen: list[str] = []

        def _fake_promote(
            source_path: Path,
            _cfg: Any,
            _dry_run: bool,
            _origin_filter: str | None = None,
        ) -> list[dict[str, Any]]:
            seen.append(str(source_path.relative_to(tmp_path)))
            return []

        monkeypatch.setattr("rebrew.promote.get_config", lambda target=None: cfg)
        monkeypatch.setattr("rebrew.promote._promote_file", _fake_promote)

        result = runner.invoke(app, ["--all"])
        assert result.exit_code == 0
        assert sorted(seen) == ["a.c", "nested/b.c", "nested/deeper/c.c"]

    def test_dir_filter(self, tmp_path: Path, monkeypatch: Any) -> None:
        _make_source(tmp_path, "int a;\n", "sub/a.c")
        _make_source(tmp_path, "int b;\n", "other/b.c")
        cfg = self._make_cfg(tmp_path)

        seen: list[str] = []

        def _fake_promote(
            source_path: Path,
            _cfg: Any,
            _dry_run: bool,
            _origin_filter: str | None = None,
        ) -> list[dict[str, Any]]:
            seen.append(str(source_path.relative_to(tmp_path)))
            return []

        monkeypatch.setattr("rebrew.promote.get_config", lambda target=None: cfg)
        monkeypatch.setattr("rebrew.promote._promote_file", _fake_promote)

        result = runner.invoke(app, ["--all", "--dir", str(tmp_path / "sub")])
        assert result.exit_code == 0
        assert seen == ["sub/a.c"]

    def test_json_output_structure(self, tmp_path: Path, monkeypatch: Any) -> None:
        _make_source(tmp_path, "int a;\n", "a.c")
        cfg = self._make_cfg(tmp_path)
        payloads: list[dict[str, Any]] = []

        def _fake_promote(
            source_path: Path,
            _cfg: Any,
            _dry_run: bool,
            _origin_filter: str | None = None,
        ) -> list[dict[str, Any]]:
            return [
                {
                    "source": str(source_path),
                    "symbol": "_func",
                    "status": "EXACT",
                    "previous_status": "STUB",
                    "new_status": "EXACT",
                    "action": "updated",
                }
            ]

        monkeypatch.setattr("rebrew.promote.get_config", lambda target=None: cfg)
        monkeypatch.setattr("rebrew.promote._promote_file", _fake_promote)
        monkeypatch.setattr("rebrew.promote.json_print", lambda data: payloads.append(data))

        result = runner.invoke(app, ["--all", "--json"])
        assert result.exit_code == 0
        assert len(payloads) == 1
        payload = payloads[0]
        assert payload["batch"] is True
        assert "directory" in payload
        assert "summary" in payload
        assert "results" in payload


class TestStatusRank:
    def test_rank_ordering(self) -> None:
        assert _STATUS_RANK["EXACT"] < _STATUS_RANK["RELOC"]
        assert _STATUS_RANK["RELOC"] < _STATUS_RANK["MATCHING"]
        assert _STATUS_RANK["MATCHING"] < _STATUS_RANK["STUB"]
        assert _STATUS_RANK["STUB"] < _STATUS_RANK[""]

    def test_promotion_logic(self) -> None:
        def _is_promotion(old: str, new: str) -> bool:
            if new in ("EXACT", "RELOC"):
                return new != old
            return _STATUS_RANK.get(new, 99) < _STATUS_RANK.get(old, 99)

        assert _is_promotion("STUB", "EXACT")
        assert _is_promotion("STUB", "MATCHING")
        assert not _is_promotion("MATCHING", "STUB")
        assert not _is_promotion("EXACT", "MATCHING")
        assert not _is_promotion("STUB", "STUB")
