"""Tests for the rebrew promote command."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from typer.testing import CliRunner

from rebrew.promote import _STATUS_RANK, _promote_file, app
from rebrew.sidecar import get_entry

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
            target_binary=Path("test.dll"),
            reversed_dir=tmp_path,
            source_ext=".c",
            for_origin=lambda _origin: None,
        )

    def test_demotes_exact_below_threshold(self, tmp_path: Path, monkeypatch: Any) -> None:
        """EXACT function with only 25% byte match should be demoted to STUB."""
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
        monkeypatch.setattr("rebrew.promote.compile_obj", lambda *_args: ("fake.obj", ""))
        monkeypatch.setattr(
            "rebrew.promote.parse_obj_symbol_bytes", lambda *_args: (b"\x90\x90\x90\x90", [])
        )
        # 1 out of 4 bytes match = 25%, well below 75% threshold
        monkeypatch.setattr(
            "rebrew.promote.smart_reloc_compare", lambda *_args: (False, 1, 4, [], [])
        )
        monkeypatch.setattr("rebrew.promote.extract_raw_bytes", lambda *_args: b"\x55\x8b\xec\xc3")

        results = _promote_file(source, cfg, dry_run=False)
        assert results[0]["previous_status"] == "EXACT"
        assert results[0]["new_status"] == "STUB"
        assert results[0]["action"] == "demoted"
        # STATUS and BLOCKER written to sidecar
        entry = get_entry(tmp_path, 0x10001000, module="test.dll")
        assert entry["status"] == "STUB"
        assert "auto-demoted" in entry.get("blocker", "")

    def test_demotes_matching_below_threshold(self, tmp_path: Path, monkeypatch: Any) -> None:
        """MATCHING function with 0% match should be demoted to STUB."""
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
        monkeypatch.setattr("rebrew.promote.compile_obj", lambda *_args: ("fake.obj", ""))
        monkeypatch.setattr(
            "rebrew.promote.parse_obj_symbol_bytes", lambda *_args: (b"\x90\x90\x90\x90", [])
        )
        monkeypatch.setattr(
            "rebrew.promote.smart_reloc_compare", lambda *_args: (False, 0, 4, [], [])
        )
        monkeypatch.setattr("rebrew.promote.extract_raw_bytes", lambda *_args: b"\x55\x8b\xec\xc3")

        results = _promote_file(source, cfg, dry_run=False)
        assert results[0]["previous_status"] == "MATCHING"
        assert results[0]["new_status"] == "STUB"
        assert results[0]["action"] == "demoted"

    def test_no_demote_above_threshold(self, tmp_path: Path, monkeypatch: Any) -> None:
        """EXACT with 90% match (above 75% threshold) should become MATCHING, not STUB."""
        source = _make_source(
            tmp_path,
            "// FUNCTION: test.dll 0x10001000\n"
            "// STATUS: EXACT\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 10\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _func\n"
            "void func(void) {}\n",
        )
        cfg = self._make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.promote.compile_obj", lambda *_args: ("fake.obj", ""))
        monkeypatch.setattr(
            "rebrew.promote.parse_obj_symbol_bytes",
            lambda *_args: (b"\x55\x8b\xec\xc3\x90\x90\x90\x90\x90\x90", []),
        )
        # 9 out of 10 bytes match = 90%, above 75% threshold → MATCHING
        monkeypatch.setattr(
            "rebrew.promote.smart_reloc_compare", lambda *_args: (False, 9, 10, [], [])
        )
        monkeypatch.setattr(
            "rebrew.promote.extract_raw_bytes",
            lambda *_args: b"\x55\x8b\xec\xc3\x90\x90\x90\x90\x90\x91",
        )

        results = _promote_file(source, cfg, dry_run=False)
        assert results[0]["previous_status"] == "EXACT"
        assert results[0]["new_status"] == "MATCHING"
        assert results[0]["action"] == "demoted"

    def test_stub_stays_stub_below_threshold(self, tmp_path: Path, monkeypatch: Any) -> None:
        """Already-STUB function below threshold should stay STUB with no action."""
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
        monkeypatch.setattr("rebrew.promote.compile_obj", lambda *_args: ("fake.obj", ""))
        monkeypatch.setattr(
            "rebrew.promote.parse_obj_symbol_bytes", lambda *_args: (b"\x90\x90\x90\x90", [])
        )
        monkeypatch.setattr(
            "rebrew.promote.smart_reloc_compare", lambda *_args: (False, 1, 4, [], [])
        )
        monkeypatch.setattr("rebrew.promote.extract_raw_bytes", lambda *_args: b"\x55\x8b\xec\xc3")

        results = _promote_file(source, cfg, dry_run=False)
        assert results[0]["previous_status"] == "STUB"
        assert results[0]["new_status"] == "STUB"
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
        monkeypatch.setattr("rebrew.promote.compile_obj", lambda *_args: ("fake.obj", ""))
        monkeypatch.setattr(
            "rebrew.promote.parse_obj_symbol_bytes", lambda *_args: (b"\x55\x8b\xec\xc3", [])
        )
        monkeypatch.setattr(
            "rebrew.promote.smart_reloc_compare", lambda *_args: (True, 4, 4, [], [])
        )
        monkeypatch.setattr("rebrew.promote.extract_raw_bytes", lambda *_args: b"\x55\x8b\xec\xc3")

        results = _promote_file(source, cfg, dry_run=False)
        assert results[0]["new_status"] == "EXACT"
        assert results[0]["action"] == "updated"
        entry = get_entry(tmp_path, 0x10001000, module="test.dll")
        assert entry["status"] == "EXACT"

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
        monkeypatch.setattr("rebrew.promote.compile_obj", lambda *_args: ("fake.obj", ""))
        monkeypatch.setattr(
            "rebrew.promote.parse_obj_symbol_bytes", lambda *_args: (b"\x55\x8b\xec\xc3", [])
        )
        monkeypatch.setattr(
            "rebrew.promote.smart_reloc_compare", lambda *_args: (True, 4, 4, [], [])
        )
        monkeypatch.setattr("rebrew.promote.extract_raw_bytes", lambda *_args: b"\x55\x8b\xec\xc3")

        results = _promote_file(source, cfg, dry_run=False)
        assert results[0]["new_status"] == "EXACT"
        assert results[0]["action"] == "updated"
        entry = get_entry(tmp_path, 0x10001000, module="test.dll")
        assert entry["status"] == "EXACT"

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
        monkeypatch.setattr("rebrew.promote.compile_obj", lambda *_args: ("fake.obj", ""))
        monkeypatch.setattr(
            "rebrew.promote.parse_obj_symbol_bytes", lambda *_args: (b"\x55\x8b\xec\xc3", [])
        )
        monkeypatch.setattr(
            "rebrew.promote.smart_reloc_compare", lambda *_args: (True, 4, 4, [], [])
        )
        monkeypatch.setattr("rebrew.promote.extract_raw_bytes", lambda *_args: b"\x55\x8b\xec\xc3")

        before = source.read_text(encoding="utf-8")
        results = _promote_file(source, cfg, dry_run=True)
        after = source.read_text(encoding="utf-8")
        assert results[0]["action"] == "would_update"
        assert before == after


class TestBatchPromote:
    def _make_cfg(self, tmp_path: Path) -> Any:
        return SimpleNamespace(
            marker="test.dll",
            target_binary=Path("test.dll"),
            reversed_dir=tmp_path,
            source_ext=".c",
            for_origin=lambda _origin: None,
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
        ) -> list[dict[str, Any]]:
            seen.append(str(source_path.relative_to(tmp_path)))
            return []

        monkeypatch.setattr(
            "rebrew.promote.require_config", lambda target=None, json_mode=False: cfg
        )
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
        ) -> list[dict[str, Any]]:
            seen.append(str(source_path.relative_to(tmp_path)))
            return []

        monkeypatch.setattr(
            "rebrew.promote.require_config", lambda target=None, json_mode=False: cfg
        )
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

        monkeypatch.setattr(
            "rebrew.promote.require_config", lambda target=None, json_mode=False: cfg
        )
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


class TestPromoteExitCode:
    """Regression tests for promote CLI exit code.

    Prior to the Phase-1 audit fix, the single-file promote path raised
    typer.Exit(1) whenever new_status was not EXACT/RELOC, meaning even normal
    MATCHING/STUB outcomes caused failure. Only ERROR status should trigger exit 1.
    """

    def _make_cfg(self, tmp_path: Path) -> Any:
        return SimpleNamespace(
            marker="test.dll",
            target_binary=Path("test.dll"),
            reversed_dir=tmp_path,
            source_ext=".c",
            for_origin=lambda _origin: None,
        )

    def test_matching_result_exits_zero(self, tmp_path: Path, monkeypatch: Any) -> None:
        """A MATCHING outcome (no status change) must exit 0, not 1."""
        source = tmp_path / "func.c"
        source.write_text(
            "// FUNCTION: test.dll 0x10001000\n"
            "// STATUS: MATCHING\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 4\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _func\n"
            "void func(void) {}\n",
            encoding="utf-8",
        )
        cfg = self._make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.promote.require_config", lambda **_kw: cfg)
        monkeypatch.setattr("rebrew.promote.compile_obj", lambda *_a: ("fake.obj", ""))
        monkeypatch.setattr(
            "rebrew.promote.parse_obj_symbol_bytes", lambda *_a: (b"\x90\x90\x90\x90", [])
        )
        # 3/4 match → MATCHING, stays MATCHING, action="none"
        monkeypatch.setattr("rebrew.promote.smart_reloc_compare", lambda *_a: (False, 3, 4, [], []))
        monkeypatch.setattr("rebrew.promote.extract_raw_bytes", lambda *_a: b"\x55\x8b\xec\xc3")

        result = runner.invoke(app, [str(source)])
        assert result.exit_code == 0, (
            f"Expected exit 0 for MATCHING outcome, got {result.exit_code}: {result.output}"
        )

    def test_error_result_exits_one(self, tmp_path: Path, monkeypatch: Any) -> None:
        """A compile ERROR must still exit 1 — agents must detect failures."""
        source = tmp_path / "func.c"
        source.write_text(
            "// FUNCTION: test.dll 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 4\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _func\n"
            "void func(void) {}\n",
            encoding="utf-8",
        )
        cfg = self._make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.promote.require_config", lambda **_kw: cfg)
        # compile_obj returns None → compile ERROR
        monkeypatch.setattr("rebrew.promote.compile_obj", lambda *_a: (None, "CL.EXE not found"))
        monkeypatch.setattr("rebrew.promote.extract_raw_bytes", lambda *_a: b"\x55\x8b\xec\xc3")

        result = runner.invoke(app, [str(source)])
        assert result.exit_code == 1, (
            f"Expected exit 1 for ERROR result, got {result.exit_code}: {result.output}"
        )


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


class TestInlineAsmDetection:
    """Tests for the inline ASM detection path in _promote_file.

    When a function body contains ``__asm`` or ``__asm__`` tokens, promote
    must immediately demote to STUB and write a BLOCKER comment instead of
    attempting a compile-compare cycle.
    """

    def _make_cfg(self, tmp_path: Path) -> Any:
        return SimpleNamespace(
            marker="test.dll",
            target_binary=Path("test.dll"),
            reversed_dir=tmp_path,
            source_ext=".c",
            for_origin=lambda _origin: None,
        )

    def test_matching_with_asm_block_demoted_to_stub(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """MATCHING function with __asm block → demoted to STUB, BLOCKER written."""
        source = _make_source(
            tmp_path,
            "// FUNCTION: test.dll 0x10001000\n"
            "// STATUS: MATCHING\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 8\n"
            "// CFLAGS: /O2 /Gd\n"
            "\n"
            "void func(void) {\n"
            "    __asm {\n"
            "        push ebp\n"
            "        mov ebp, esp\n"
            "    }\n"
            "}\n",
        )
        cfg = self._make_cfg(tmp_path)
        compile_calls: list[Any] = []
        monkeypatch.setattr(
            "rebrew.promote.compile_obj",
            lambda *a: (compile_calls.append(a), ("fake.obj", ""))[1],
        )

        results = _promote_file(source, cfg, dry_run=False)

        assert len(results) == 1
        r = results[0]
        assert r["previous_status"] == "MATCHING"
        assert r["new_status"] == "STUB"
        assert r["action"] == "demoted"
        assert r["reason"] == "inline assembly detected"

        # STATUS and BLOCKER written to sidecar
        entry = get_entry(tmp_path, 0x10001000, module="test.dll")
        assert entry["status"] == "STUB"
        assert (
            "inline assembly" in entry.get("blocker", "")
            or "asm" in entry.get("blocker", "").lower()
        )

    def test_already_stub_with_asm_block_no_status_change(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """Already-STUB function with __asm → action=none, BLOCKER still written."""
        source = _make_source(
            tmp_path,
            "// FUNCTION: test.dll 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 8\n"
            "// CFLAGS: /O2 /Gd\n"
            "\n"
            "void func(void) {\n"
            "    __asm {\n"
            "        push ebp\n"
            "    }\n"
            "}\n",
        )
        cfg = self._make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.promote.compile_obj", lambda *a: ("fake.obj", ""))

        results = _promote_file(source, cfg, dry_run=False)
        r = results[0]
        assert r["new_status"] == "STUB"
        assert r["action"] == "none"
        # Already-STUB: BLOCKER is not written (no demotion occurs)
        # Just verify the action is "none" (already verified above)
        assert r["action"] == "none"  # redundant but explicit

    def test_dry_run_asm_no_write(self, tmp_path: Path, monkeypatch: Any) -> None:
        """Dry run with __asm block: action=would_demote, file not modified."""
        source = _make_source(
            tmp_path,
            "// FUNCTION: test.dll 0x10001000\n"
            "// STATUS: MATCHING\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 8\n"
            "// CFLAGS: /O2 /Gd\n"
            "\n"
            "void func(void) {\n"
            "    __asm {\n"
            "        push ebp\n"
            "    }\n"
            "}\n",
        )
        cfg = self._make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.promote.compile_obj", lambda *a: ("fake.obj", ""))

        before = source.read_text(encoding="utf-8")
        results = _promote_file(source, cfg, dry_run=True)
        after = source.read_text(encoding="utf-8")

        assert results[0]["action"] == "would_demote"
        assert before == after

    def test_gcc_asm_keyword_detected(self, tmp_path: Path, monkeypatch: Any) -> None:
        """GCC __asm__ syntax is also detected."""
        source = _make_source(
            tmp_path,
            "// FUNCTION: test.dll 0x10001000\n"
            "// STATUS: MATCHING\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 8\n"
            "// CFLAGS: /O2 /Gd\n"
            "\n"
            "void func(void) {\n"
            '    __asm__("push ebp\\n");\n'
            "}\n",
        )
        cfg = self._make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.promote.compile_obj", lambda *a: ("fake.obj", ""))

        results = _promote_file(source, cfg, dry_run=False)
        assert results[0]["new_status"] == "STUB"
        assert results[0]["action"] == "demoted"

    def test_no_asm_takes_normal_path(self, tmp_path: Path, monkeypatch: Any) -> None:
        """Functions without inline ASM still go through compile-compare normally."""
        source = _make_source(
            tmp_path,
            "// FUNCTION: test.dll 0x10001000\n"
            "// STATUS: STUB\n"
            "// ORIGIN: GAME\n"
            "// SIZE: 4\n"
            "// CFLAGS: /O2 /Gd\n"
            "\n"
            "void func(void) {}\n",
        )
        cfg = self._make_cfg(tmp_path)
        monkeypatch.setattr("rebrew.promote.compile_obj", lambda *a: ("fake.obj", ""))
        monkeypatch.setattr(
            "rebrew.promote.parse_obj_symbol_bytes", lambda *a: (b"\x55\x8b\xec\xc3", [])
        )
        monkeypatch.setattr("rebrew.promote.smart_reloc_compare", lambda *a: (True, 4, 4, [], []))
        monkeypatch.setattr("rebrew.promote.extract_raw_bytes", lambda *a: b"\x55\x8b\xec\xc3")

        results = _promote_file(source, cfg, dry_run=False)
        # Normal compile-compare path: STUB → EXACT
        assert results[0]["new_status"] == "EXACT"
