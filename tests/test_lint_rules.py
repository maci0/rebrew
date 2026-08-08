"""Tests for lint.py individual rule checks."""

from pathlib import Path
from types import SimpleNamespace

from rebrew.lint import (
    LintResult,
    _check_E001_marker,
    _check_E002_va,
    _check_E013_duplicate_va,
    _check_E015_marker_consistency,
    _check_W005_blocker,
    _check_W010_unknown_keys,
    _check_W015_va_case,
    _check_W018_cflags,
)


def _result() -> LintResult:
    r = LintResult(filepath=Path("x.c"))
    r.marker_line = 3
    return r


class TestRuleChecks:
    def test_E001_invalid_marker(self) -> None:
        r = _result()
        _check_E001_marker(r, "NOTAMARKER")
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

    def test_W010_unknown_key(self) -> None:
        r = _result()
        _check_W010_unknown_keys(r, {"BOGUS_KEY": "1"})
        assert any(w[1] == "W010" for w in r.warnings)

    def test_E015_library_module_marker_mismatch(self) -> None:
        r = _result()
        cfg = SimpleNamespace(library_modules={"MSVCRT"})
        _check_E015_marker_consistency(r, "FUNCTION", "MSVCRT", "EXACT", cfg)
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
