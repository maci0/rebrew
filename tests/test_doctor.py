"""Tests for rebrew doctor diagnostic command."""

from pathlib import Path
from types import SimpleNamespace

from rebrew.doctor import (
    _FAIL,
    _PASS,
    _WARN,
    CheckResult,
    DoctorReport,
    check_arch_format,
    check_bin_dir,
    check_config_parse,
    check_function_list,
    check_includes,
    check_libs,
    check_source_files,
    check_target_binary,
    run_doctor,
)


def _make_project(tmp_path: Path, toml: str) -> Path:
    (tmp_path / "rebrew-project.toml").write_text(toml, encoding="utf-8")
    return tmp_path


def _make_cfg(tmp_path: Path, **overrides: object) -> SimpleNamespace:
    defaults = {
        "root": tmp_path,
        "target_name": "test",
        "target_binary": tmp_path / "test.exe",
        "binary_format": "pe",
        "arch": "x86_32",
        "compiler_command": "gcc",
        "compiler_includes": tmp_path / "includes",
        "compiler_libs": tmp_path / "libs",
        "function_list": tmp_path / "funcs.txt",
        "reversed_dir": tmp_path / "src",
        "bin_dir": tmp_path / "bin",
        "source_ext": ".c",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class TestCheckResult:
    def test_to_dict_minimal(self) -> None:
        r = CheckResult(name="test", status=_PASS, message="ok")
        d = r.to_dict()
        assert d["name"] == "test"
        assert d["status"] == _PASS
        assert d["message"] == "ok"
        assert "fix" not in d

    def test_to_dict_with_fix(self) -> None:
        r = CheckResult(name="test", status=_FAIL, message="bad", fix="do X")
        d = r.to_dict()
        assert d["fix"] == "do X"


class TestDoctorReport:
    def test_empty_report_passes(self) -> None:
        r = DoctorReport()
        assert r.passed is True
        assert r.pass_count == 0
        assert r.fail_count == 0

    def test_all_pass(self) -> None:
        r = DoctorReport(
            checks=[
                CheckResult(name="a", status=_PASS, message="ok"),
                CheckResult(name="b", status=_PASS, message="ok"),
            ]
        )
        assert r.passed is True
        assert r.pass_count == 2

    def test_one_fail(self) -> None:
        r = DoctorReport(
            checks=[
                CheckResult(name="a", status=_PASS, message="ok"),
                CheckResult(name="b", status=_FAIL, message="bad"),
            ]
        )
        assert r.passed is False
        assert r.fail_count == 1

    def test_warn_still_passes(self) -> None:
        r = DoctorReport(
            checks=[
                CheckResult(name="a", status=_WARN, message="hmm"),
            ]
        )
        assert r.passed is True
        assert r.warn_count == 1

    def test_to_dict(self) -> None:
        r = DoctorReport(
            target="test",
            checks=[
                CheckResult(name="a", status=_PASS, message="ok"),
            ],
        )
        d = r.to_dict()
        assert d["target"] == "test"
        assert d["passed"] is True
        assert d["summary"]["pass"] == 1
        assert len(d["checks"]) == 1


class TestCheckConfigParse:
    def test_valid_config(self, tmp_path: Path) -> None:
        import os

        _make_project(tmp_path, "[targets.main]\nbinary = 'test.exe'\n")
        old = os.getcwd()
        try:
            os.chdir(tmp_path)
            result, cfg = check_config_parse(root=None, target=None)
            assert result.status == _PASS
            assert cfg is not None
        finally:
            os.chdir(old)

    def test_missing_config(self, tmp_path: Path) -> None:
        import os

        old = os.getcwd()
        try:
            os.chdir(tmp_path)
            result, cfg = check_config_parse(root=None, target=None)
            assert result.status == _FAIL
            assert cfg is None
            assert result.fix
        finally:
            os.chdir(old)


class TestCheckTargetBinary:
    def test_missing_binary(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        result = check_target_binary(cfg)
        assert result.status == _FAIL
        assert "Not found" in result.message

    def test_existing_non_pe(self, tmp_path: Path) -> None:
        binary = tmp_path / "test.exe"
        binary.write_bytes(b"not a real binary")
        cfg = _make_cfg(tmp_path)
        result = check_target_binary(cfg)
        assert result.status == _FAIL


class TestCheckArchFormat:
    def test_valid(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        result = check_arch_format(cfg)
        assert result.status == _PASS

    def test_unknown_arch(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path, arch="mips64")
        result = check_arch_format(cfg)
        assert result.status == _WARN

    def test_unknown_format(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path, binary_format="coff")
        result = check_arch_format(cfg)
        assert result.status == _WARN


class TestCheckIncludes:
    def test_exists(self, tmp_path: Path) -> None:
        inc = tmp_path / "includes"
        inc.mkdir()
        (inc / "stdio.h").write_text("", encoding="utf-8")
        cfg = _make_cfg(tmp_path)
        result = check_includes(cfg)
        assert result.status == _PASS
        assert "1 headers" in result.message

    def test_missing(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        result = check_includes(cfg)
        assert result.status == _FAIL


class TestCheckLibs:
    def test_exists(self, tmp_path: Path) -> None:
        lib = tmp_path / "libs"
        lib.mkdir()
        cfg = _make_cfg(tmp_path)
        result = check_libs(cfg)
        assert result.status == _PASS

    def test_missing_is_warn(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        result = check_libs(cfg)
        assert result.status == _WARN


class TestCheckFunctionList:
    def test_exists(self, tmp_path: Path) -> None:
        fl = tmp_path / "funcs.txt"
        fl.write_text("0x1000 func_a\n0x2000 func_b\n", encoding="utf-8")
        cfg = _make_cfg(tmp_path)
        result = check_function_list(cfg)
        assert result.status == _PASS
        assert "2 entries" in result.message

    def test_missing_is_warn(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        result = check_function_list(cfg)
        assert result.status == _WARN


class TestCheckSourceFiles:
    def test_has_sources(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "func_a.c").write_text("// FUNCTION: SERVER 0x1000\n", encoding="utf-8")
        cfg = _make_cfg(tmp_path)
        result = check_source_files(cfg)
        assert result.status == _PASS
        assert "1 source" in result.message

    def test_no_sources(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        cfg = _make_cfg(tmp_path)
        result = check_source_files(cfg)
        assert result.status == _WARN

    def test_missing_dir(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        result = check_source_files(cfg)
        assert result.status == _WARN


class TestCheckBinDir:
    def test_exists(self, tmp_path: Path) -> None:
        (tmp_path / "bin").mkdir()
        cfg = _make_cfg(tmp_path)
        result = check_bin_dir(cfg)
        assert result.status == _PASS

    def test_missing_still_passes(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        result = check_bin_dir(cfg)
        assert result.status == _PASS
        assert "will be created" in result.message


class TestRunDoctor:
    def test_full_run_missing_toml(self, tmp_path: Path) -> None:
        import os

        old = os.getcwd()
        try:
            os.chdir(tmp_path)
            report = run_doctor()
            assert not report.passed
            assert report.fail_count >= 1
        finally:
            os.chdir(old)

    def test_full_run_with_toml(self, tmp_path: Path) -> None:
        import os

        _make_project(tmp_path, "[targets.main]\nbinary = 'test.exe'\n")
        old = os.getcwd()
        try:
            os.chdir(tmp_path)
            report = run_doctor()
            assert report.target == "main"
            assert len(report.checks) >= 5
            d = report.to_dict()
            assert "checks" in d
            assert "summary" in d
        finally:
            os.chdir(old)
