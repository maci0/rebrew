"""Tests for rebrew.security_scan: rule matching, path scanning, CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

import rebrew.main
from rebrew.security_scan import (
    _SNIPPET_MAX_CHARS,
    scan_paths,
    scan_source,
    security_scan,
)

runner = CliRunner()


def _write(directory: Path, name: str, text: str) -> Path:
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _scan(text: str) -> list[dict[str, Any]]:
    return scan_source(text, file="test.c")


class TestUnboundedCopy:
    def test_strcpy_finding_fields(self) -> None:
        findings = _scan("void copy_it(char *d, char *s) {\n    strcpy(d, s);\n}\n")
        assert len(findings) == 1
        finding = findings[0]
        assert finding["rule"] == "unbounded-copy"
        assert finding["cwe"] == "CWE-120"
        assert finding["severity"] == "high"
        assert finding["confidence"] == "high"
        assert finding["line"] == 2
        assert finding["function"] == "copy_it"
        assert finding["snippet"] == "strcpy(d, s);"

    def test_safe_strcpy_s_not_flagged(self) -> None:
        assert _scan("void f(char *d, char *s, unsigned n) {\n    strcpy_s(d, n, s);\n}\n") == []

    def test_windows_and_wide_variants(self) -> None:
        source = (
            "void f(char *a, char *b) {\n"
            "    lstrcpyW(a, b);\n"
            "    lstrcatA(a, b);\n"
            "    wcscpy(a, b);\n"
            "    wcscat(a, b);\n"
            "}\n"
        )
        assert [f["rule"] for f in _scan(source)] == ["unbounded-copy"] * 4

    def test_get_and_vsprintf(self) -> None:
        source = "void f(char *d, char *fmt) {\n    gets(d);\n    vsprintf(d, fmt, ap);\n}\n"
        found = {(f["line"], f["rule"]) for f in _scan(source)}
        assert found == {(2, "unbounded-copy"), (3, "unbounded-copy")}


class TestFormatString:
    def test_non_literal_format_flagged(self) -> None:
        findings = _scan("void f(char *fmt) {\n    printf(fmt, x);\n}\n")
        assert [f["rule"] for f in findings] == ["format-string"]
        assert findings[0]["cwe"] == "CWE-134"
        assert findings[0]["severity"] == "medium"
        assert findings[0]["confidence"] == "medium"

    def test_literal_format_not_flagged(self) -> None:
        assert _scan('void f(char *s) {\n    printf("%s", s);\n}\n') == []

    def test_fprintf_format_is_second_argument(self) -> None:
        flagged = _scan("void f(FILE *fp, char *fmt) {\n    fprintf(fp, fmt, n);\n}\n")
        assert [f["rule"] for f in flagged] == ["format-string"]
        assert _scan('void f(FILE *fp) {\n    fprintf(fp, "%d", n);\n}\n') == []

    def test_snprintf_format_is_third_argument(self) -> None:
        flagged = _scan("void f(char *b, unsigned n, char *fmt) {\n    snprintf(b, n, fmt);\n}\n")
        assert [f["rule"] for f in flagged] == ["format-string"]
        assert _scan('void f(char *b, unsigned n) {\n    snprintf(b, n, "%s", s);\n}\n') == []

    def test_vprintf_and_vsnprintf_indexes(self) -> None:
        source = (
            "void f(char *b, unsigned n, char *fmt) {\n"
            "    vprintf(fmt, ap);\n"
            "    vsnprintf(b, n, fmt, ap);\n"
            "}\n"
        )
        assert [(f["line"], f["rule"]) for f in _scan(source)] == [
            (2, "format-string"),
            (3, "format-string"),
        ]

    def test_sprintf_reports_both_rules_sorted(self) -> None:
        findings = _scan("void f(char *d, char *fmt) {\n    sprintf(d, fmt, x);\n}\n")
        assert [(f["line"], f["rule"]) for f in findings] == [
            (2, "format-string"),
            (2, "unbounded-copy"),
        ]


class TestCommandExec:
    def test_system_flagged(self) -> None:
        findings = _scan("void f(char *cmd) {\n    system(cmd);\n}\n")
        assert [f["rule"] for f in findings] == ["command-exec"]
        assert findings[0]["cwe"] == "CWE-78"
        assert findings[0]["severity"] == "medium"

    def test_create_process_flagged(self) -> None:
        source = "void f(void) {\n    CreateProcessA(a, b, c, d, e, f, g, h, i, j);\n}\n"
        assert [f["rule"] for f in _scan(source)] == ["command-exec"]

    def test_shell_execute_flagged(self) -> None:
        source = "void f(void) {\n    ShellExecuteW(h, op, file, params, dir, cmd);\n}\n"
        assert [f["rule"] for f in _scan(source)] == ["command-exec"]

    def test_safe_call_not_flagged(self) -> None:
        assert _scan("void f(void) {\n    MessageBoxA(h, msg, title, 0);\n}\n") == []


class TestUncheckedMemcpy:
    def test_variable_size_flagged(self) -> None:
        findings = _scan("void f(char *d, char *s, unsigned n) {\n    memcpy(d, s, n);\n}\n")
        assert [f["rule"] for f in findings] == ["unchecked-memcpy"]
        assert findings[0]["cwe"] == "CWE-787"
        assert findings[0]["severity"] == "low"
        assert findings[0]["confidence"] == "low"

    def test_literal_size_not_flagged(self) -> None:
        assert _scan("void f(char *d, char *s) {\n    memcpy(d, s, 16);\n}\n") == []

    def test_alias_and_sizeof_size_flagged(self) -> None:
        source = (
            "void f(char *d, char *s, unsigned n) {\n"
            "    CopyMemory(d, s, n);\n"
            "    RtlCopyMemory(d, s, sizeof(int));\n"
            "}\n"
        )
        assert [(f["line"], f["rule"]) for f in _scan(source)] == [
            (2, "unchecked-memcpy"),
            (3, "unchecked-memcpy"),
        ]


class TestInsecureRandom:
    def test_assigned_rand_flagged(self) -> None:
        findings = _scan("int f(void) {\n    int r = rand();\n    return r;\n}\n")
        assert [f["rule"] for f in findings] == ["insecure-random"]
        assert findings[0]["cwe"] == "CWE-338"
        assert findings[0]["function"] == "f"

    def test_seed_statement_not_flagged(self) -> None:
        assert _scan("void f(void) {\n    srand(1);\n}\n") == []

    def test_random_in_condition_flagged(self) -> None:
        findings = _scan(
            "int f(void) {\n    if (random() % 2)\n        return 1;\n    return 0;\n}\n"
        )
        assert [f["rule"] for f in findings] == ["insecure-random"]


class TestStackAlloc:
    def test_variable_size_flagged(self) -> None:
        findings = _scan("void *f(unsigned n) {\n    return alloca(n);\n}\n")
        assert [f["rule"] for f in findings] == ["stack-alloc"]
        assert findings[0]["cwe"] == "CWE-770"

    def test_literal_size_not_flagged(self) -> None:
        assert _scan("void *f(void) {\n    return alloca(16);\n}\n") == []

    def test_underscore_variant_flagged(self) -> None:
        findings = _scan("void *f(unsigned n) {\n    return _alloca(n);\n}\n")
        assert [f["rule"] for f in findings] == ["stack-alloc"]


class TestFindings:
    def test_sorted_across_lines(self) -> None:
        source = (
            "void f(char *d, char *s, unsigned n) {\n    strcpy(d, s);\n    memcpy(d, s, n);\n}\n"
        )
        assert [(f["line"], f["rule"]) for f in _scan(source)] == [
            (2, "unbounded-copy"),
            (3, "unchecked-memcpy"),
        ]

    def test_snippet_capped(self) -> None:
        source = "void f(char *d, char *s) { " + " " * 300 + "strcpy(d, s); }\n"
        findings = _scan(source)
        assert len(findings) == 1
        assert len(findings[0]["snippet"]) == _SNIPPET_MAX_CHARS

    def test_syntax_error_does_not_raise(self) -> None:
        findings = scan_source("void broken( {\n    strcpy(x);\n", file="bad.c")
        assert isinstance(findings, list)

    def test_empty_source_yields_nothing(self) -> None:
        assert scan_source("", file="e.c") == []
        assert scan_source("   \n\t\n", file="e.c") == []

    def test_message_names_callee(self) -> None:
        findings = _scan("void f(char *d, char *s) {\n    strcpy(d, s);\n}\n")
        assert findings[0]["message"].startswith("strcpy():")


class TestScanPaths:
    def test_empty_sequence(self) -> None:
        assert scan_paths([]) == []

    def test_ordering_across_files(self, tmp_path: Path) -> None:
        first = _write(tmp_path, "a.c", "void f(char *d, char *s) {\n    strcpy(d, s);\n}\n")
        second = _write(tmp_path, "b.c", "void g(char *d, char *s) {\n    strcat(d, s);\n}\n")
        findings = scan_paths([second, first])
        assert [f["file"] for f in findings] == [str(first), str(second)]


class TestSecurityScan:
    def test_result_shape_and_counts(self, tmp_path: Path) -> None:
        _write(tmp_path, "one.c", "void f(char *d, char *s) {\n    strcpy(d, s);\n}\n")
        result = security_scan(tmp_path)
        assert set(result) == {"root", "files_scanned", "findings", "count", "by_severity"}
        assert result["root"] == str(tmp_path)
        assert result["files_scanned"] == 1
        assert result["count"] == 1
        assert result["by_severity"] == {"high": 1, "medium": 0, "low": 0}

    def test_empty_tree(self, tmp_path: Path) -> None:
        result = security_scan(tmp_path)
        assert result["files_scanned"] == 0
        assert result["findings"] == []
        assert result["count"] == 0
        assert result["by_severity"] == {"high": 0, "medium": 0, "low": 0}

    def test_by_severity_counts(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "mixed.c",
            "void f(char *d, char *s, unsigned n) {\n    strcpy(d, s);\n    printf(fmt);\n"
            "    memcpy(d, s, n);\n}\n",
        )
        result = security_scan(tmp_path)
        assert result["by_severity"] == {"high": 1, "medium": 1, "low": 1}

    def test_non_recursive_skips_subdirectories(self, tmp_path: Path) -> None:
        _write(tmp_path, "top.c", "void f(char *d, char *s) {\n    strcpy(d, s);\n}\n")
        _write(tmp_path, "sub/deep.c", "void g(char *d, char *s) {\n    strcpy(d, s);\n}\n")
        assert security_scan(tmp_path)["files_scanned"] == 2
        shallow = security_scan(tmp_path, recursive=False)
        assert shallow["files_scanned"] == 1
        assert shallow["count"] == 1

    def test_missing_directory_empty(self, tmp_path: Path) -> None:
        result = security_scan(tmp_path / "absent")
        assert result["files_scanned"] == 0
        assert result["count"] == 0


class TestSecurityScanCli:
    def test_json_output(self, tmp_path: Path) -> None:
        _write(tmp_path, "one.c", "void f(char *d, char *s) {\n    strcpy(d, s);\n}\n")
        result = runner.invoke(rebrew.main.app, ["security-scan", str(tmp_path), "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert set(payload) == {"root", "files_scanned", "findings", "count", "by_severity"}
        assert payload["count"] == 1
        assert payload["findings"][0]["rule"] == "unbounded-copy"

    def test_human_output(self, tmp_path: Path) -> None:
        _write(tmp_path, "one.c", "void f(char *d, char *s) {\n    strcpy(d, s);\n}\n")
        result = runner.invoke(
            rebrew.main.app, ["security-scan", str(tmp_path)], env={"COLUMNS": "200"}
        )
        assert result.exit_code == 0
        assert "unbounded-copy" in result.output
        assert "CWE-120" in result.output
        assert "one.c:2" in result.output

    def test_no_findings_message(self, tmp_path: Path) -> None:
        _write(tmp_path, "safe.c", 'void f(char *s) {\n    printf("%s", s);\n}\n')
        result = runner.invoke(rebrew.main.app, ["security-scan", str(tmp_path)])
        assert result.exit_code == 0
        assert "no security findings" in result.output.lower()

    def test_min_severity_filters(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "mixed.c",
            "void f(char *d, char *s, unsigned n) {\n    strcpy(d, s);\n    memcpy(d, s, n);\n}\n",
        )
        result = runner.invoke(
            rebrew.main.app,
            ["security-scan", str(tmp_path), "--min-severity", "high", "--json"],
        )
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["count"] == 1
        assert payload["by_severity"] == {"high": 1, "medium": 0, "low": 0}
        assert [f["rule"] for f in payload["findings"]] == ["unbounded-copy"]

    def test_invalid_min_severity_errors(self, tmp_path: Path) -> None:
        result = runner.invoke(
            rebrew.main.app,
            ["security-scan", str(tmp_path), "--min-severity", "bogus", "--json"],
        )
        assert result.exit_code == 2
        assert "error" in json.loads(result.stdout)

    def test_missing_directory_errors(self, tmp_path: Path) -> None:
        result = runner.invoke(
            rebrew.main.app,
            ["security-scan", str(tmp_path / "absent"), "--json"],
        )
        assert result.exit_code == 2
        assert "error" in json.loads(result.stdout)

    def test_default_directory_from_project(self, tmp_path: Path, monkeypatch: Any) -> None:
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "T"\n\n'
            '[targets.T]\nbinary = "bin/T/game.exe"\nreversed_dir = "src/T"\n',
            encoding="utf-8",
        )
        _write(tmp_path, "src/T/one.c", "void f(char *d, char *s) {\n    strcpy(d, s);\n}\n")
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(rebrew.main.app, ["security-scan", "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["count"] == 1
        assert payload["findings"][0]["file"].endswith("src/T/one.c")
