"""Tests for lint.py individual rule checks."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from rebrew.lint import (
    LintResult,
    _check_E001_kind,
    _check_E002_va,
    _check_E013_duplicate_va,
    _check_E015_kind_consistency,
    _check_W005_blocker,
    _check_W015_va_case,
    _check_W018_cflags,
)


def _result() -> LintResult:
    r = LintResult(filepath=Path("x.c"))
    r.binding_line = 3
    return r


class TestRuleChecks:
    def test_E001_invalid_marker(self) -> None:
        r = _result()
        _check_E001_kind(r, "NOTAMARKER")
        assert any(e[1] == "E001" for e in r.errors)

    def test_E002_valid_va(self) -> None:
        r = _result()
        va = _check_E002_va(r, "10001000")
        assert va == 0x10001000
        assert r.errors == []

    def test_E002_invalid_va(self) -> None:
        r = _result()
        va = _check_E002_va(r, "zzz")
        assert va is None
        assert any(e[1] == "E002" for e in r.errors)

    def test_E002_suspicious_va(self) -> None:
        r = _result()
        _check_E002_va(r, "10")  # below 0x1000
        assert any(e[1] == "E002" for e in r.errors)

    def test_E013_duplicate_va(self) -> None:
        r = _result()
        seen: dict[int, str] = {}
        _check_E013_duplicate_va(r, 0x1000, "1000", Path("a.c"), seen)
        assert r.errors == []
        _check_E013_duplicate_va(r, 0x1000, "1000", Path("b.c"), seen)
        assert any(e[1] == "E013" for e in r.errors)

    def test_W018_missing_cflags_warns(self) -> None:
        r = _result()
        _check_W018_cflags(r, {}, SimpleNamespace(base_cflags=""))
        assert any(w[1] == "W018" for w in r.warnings)

    def test_W018_annotation_suppresses(self) -> None:
        r = _result()
        _check_W018_cflags(r, {"CFLAGS": "/O2"}, SimpleNamespace(base_cflags=""))
        assert r.warnings == []

    def test_E015_library_target_module_mismatch(self) -> None:
        r = _result()
        cfg = SimpleNamespace(library_modules={"MSVCRT"})
        _check_E015_kind_consistency(r, "FUNCTION", "MSVCRT", "EXACT", cfg)
        # A LIBRARY-origin module with a FUNCTION marker is inconsistent.
        assert any(e[1] == "E015" for e in r.errors)

    def test_W005_blocker_without_blocker_key(self) -> None:
        r = _result()
        _check_W005_blocker(r, "STUB", {})
        # W005 fires when STUB/blocked status lacks a BLOCKER annotation.
        assert any(w[1] == "W005" for w in r.warnings)

    def test_W015_va_lowercase(self) -> None:
        r = _result()
        _check_W015_va_case(r, "0x1000Ab")  # mixed-case hex → warn
        assert any(w[1] == "W015" for w in r.warnings)


class TestE015StubStatus:
    """E015's intent is library attribution — FUNCTION+STUB is valid."""

    def _cfg(self) -> Any:
        return SimpleNamespace(library_modules=set())

    def test_function_marker_with_stub_status_ok(self) -> None:
        r = LintResult(filepath=Path("x.c"))
        _check_E015_kind_consistency(r, "FUNCTION", "SERVER", "STUB", self._cfg())
        assert r.errors == []

    def test_stub_marker_with_stub_status_ok(self) -> None:
        r = LintResult(filepath=Path("x.c"))
        _check_E015_kind_consistency(r, "STUB", "SERVER", "STUB", self._cfg())
        assert r.errors == []

    def test_function_marker_with_library_module_fires(self) -> None:
        r = LintResult(filepath=Path("x.c"))
        cfg = SimpleNamespace(library_modules={"MSVCRT"})
        _check_E015_kind_consistency(r, "FUNCTION", "MSVCRT", "EXACT", cfg)
        assert any(e[1] == "E015" for e in r.errors)


class TestW023DefaultFunctionNames:
    """W023 flags exactly the names the shared placeholder rule accepts."""

    def _warnings(self, tmp_path: Path, source: str, *, pedantic: bool = True) -> list[str]:
        from rebrew.lint import lint_file

        path = tmp_path / "f.c"
        path.write_text(source, encoding="utf-8")
        return [w[2] for w in lint_file(path, pedantic=pedantic).warnings if w[1] == "W023"]

    def test_placeholder_definitions_warn(self, tmp_path: Path) -> None:
        source = (
            "int FUN_00401000(void) { return 0; }\n"
            "int fcn_00401010(void) { return 0; }\n"
            "int thunk_CreateWindowA(void) { return 0; }\n"
            "int real_name(void) { return 0; }\n"
            "int sub_menu(void) { return 0; }\n"
        )
        warnings = self._warnings(tmp_path, source)
        assert len(warnings) == 3
        assert all("default name" in w for w in warnings)
        assert any("'fcn_00401010'" in w for w in warnings)
        assert not any("real_name" in w or "sub_menu" in w for w in warnings)

    def test_not_pedantic_is_silent(self, tmp_path: Path) -> None:
        assert self._warnings(tmp_path, "int fcn(void) { return 0; }\n", pedantic=False) == []
