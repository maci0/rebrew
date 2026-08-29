"""Tests for rebrew doctor diagnostic command."""

from pathlib import Path
from types import SimpleNamespace

import pytest

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
        "metadata_dir": tmp_path,
        "bin_dir": tmp_path / "bin",
        "source_ext": ".c",
        "marker": None,
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
    def test_valid_config(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path, "[project]\ndefault_target = 'main'\n\n[targets.main]\nbinary = 'test.exe'\n"
        )
        monkeypatch.chdir(tmp_path)
        result, cfg = check_config_parse(target=None)
        assert result.status == _PASS
        assert cfg is not None

    def test_missing_config(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result, cfg = check_config_parse(target=None)
        assert result.status == _FAIL
        assert cfg is None
        assert result.fix


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
        cfg = _make_cfg(tmp_path, arch="riscv32")
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


class TestDockerIncludeLibs:
    """Docker-backed profiles get includes/libs from their image — a dangling
    host path (a fresh intake's placeholder) must not fail doctor."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return _make_cfg(
            tmp_path,
            compiler_profile="msvc6",
            compiler_includes=tmp_path / "nope" / "include",
            compiler_libs=tmp_path / "nope" / "lib",
        )

    def test_docker_profile_with_image_passes(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr("rebrew.toolchain.image_present", lambda img: True)
        inc = check_includes(self._cfg(tmp_path))
        assert inc.status == _PASS
        assert "docker image" in inc.message
        lib = check_libs(self._cfg(tmp_path))
        assert lib.status == _PASS
        assert "docker image" in lib.message

    def test_docker_profile_without_image_warns_with_fix(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr("rebrew.toolchain.image_present", lambda img: False)
        inc = check_includes(self._cfg(tmp_path))
        assert inc.status == _WARN
        assert "toolchain build" in inc.fix
        lib = check_libs(self._cfg(tmp_path))
        assert lib.status == _WARN

    def test_native_profile_still_checks_host_path(self, tmp_path: Path, monkeypatch) -> None:
        # gcc-pe has no docker image — the host path check applies as before.
        cfg = _make_cfg(
            tmp_path,
            compiler_profile="gcc-pe",
            compiler_includes=tmp_path / "nope" / "include",
        )
        result = check_includes(cfg)
        assert result.status == _FAIL
        assert "compiler.includes" in result.fix


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
    def test_full_run_missing_toml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        report = run_doctor()
        assert not report.passed
        assert report.fail_count >= 1

    def test_full_run_with_toml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path, "[project]\ndefault_target = 'main'\n\n[targets.main]\nbinary = 'test.exe'\n"
        )
        monkeypatch.chdir(tmp_path)
        report = run_doctor()
        assert report.target == "main"
        assert len(report.checks) >= 5
        d = report.to_dict()
        assert "checks" in d
        assert "summary" in d

    def test_no_delphi_row_for_x86_32(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The Delphi 1.0 check is 16-bit-only — a 32-bit project must not
        show the 'not a 16-bit target' skip row (doctor is environment
        health; structurally inapplicable checks stay hidden)."""
        _make_project(
            tmp_path,
            "[project]\ndefault_target = 'main'\n\n"
            "[targets.main]\nbinary = 'test.exe'\nformat = 'pe'\narch = 'x86_32'\n",
        )
        monkeypatch.chdir(tmp_path)
        report = run_doctor()
        assert "Delphi 1.0 toolchain" not in [c.name for c in report.checks]

    def test_delphi_row_present_for_x86_16(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            "[project]\ndefault_target = 'main'\n\n"
            "[targets.main]\nbinary = 'test.exe'\nformat = 'ne'\narch = 'x86_16'\n",
        )
        monkeypatch.chdir(tmp_path)
        report = run_doctor()
        assert "Delphi 1.0 toolchain" in [c.name for c in report.checks]


class TestExtraBranches:
    def test_config_parse_keyerror(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.doctor as doctor

        def boom(target=None):
            raise KeyError("no [targets]")

        monkeypatch.setattr(doctor, "load_config", boom)
        result, cfg = doctor.check_config_parse("x")
        assert result.status == doctor._FAIL
        assert cfg is None

    def test_config_parse_valueerror(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.doctor as doctor

        monkeypatch.setattr(
            doctor, "load_config", lambda target=None: (_ for _ in ()).throw(ValueError("bad toml"))
        )
        result, cfg = doctor.check_config_parse("x")
        assert result.status == doctor._FAIL
        assert "Unexpected error" in result.message

    def test_target_binary_load_success(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.doctor as doctor

        f = tmp_path / "x.dll"
        f.write_bytes(b"MZ")
        cfg = SimpleNamespace(target_binary=f, binary_format="pe")
        monkeypatch.setattr(
            "rebrew.binary_loader.load_binary",
            lambda p, fmt=None: SimpleNamespace(
                image_base=0x400000, text_va=0x401000, sections={".text": 1, ".data": 1}
            ),
        )
        result = doctor.check_target_binary(cfg)
        assert result.status == doctor._PASS
        assert "2 sections" in result.message

    def test_target_binary_load_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.doctor as doctor

        f = tmp_path / "x.dll"
        f.write_bytes(b"MZ")
        cfg = SimpleNamespace(target_binary=f, binary_format="pe")

        def boom(p, fmt=None):
            raise ValueError("bad format")

        monkeypatch.setattr("rebrew.binary_loader.load_binary", boom)
        result = doctor.check_target_binary(cfg)
        assert result.status == doctor._FAIL
        assert "Failed to load" in result.message

    def test_runner_checked_by_compiler(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.doctor as doctor

        monkeypatch.setattr("rebrew.doctor.shutil.which", lambda _name: None)
        cfg = SimpleNamespace(compiler_runner="wine", root=tmp_path)
        result = doctor.check_runner(cfg)
        assert result.status == doctor._PASS
        assert "checked by compiler check" in result.message


class TestCheckFlirtSigs:
    """check_flirt_sigs: presence + parseability of .pat/.sig files."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(root=tmp_path)

    def test_missing_dir_warns(self, tmp_path: Path) -> None:
        from rebrew.doctor import check_flirt_sigs

        result = check_flirt_sigs(self._cfg(tmp_path))
        assert result.status == _WARN
        assert "not found" in result.message
        assert "gen-flirt-pat" in result.fix

    def test_empty_dir_warns(self, tmp_path: Path) -> None:
        from rebrew.doctor import check_flirt_sigs

        (tmp_path / "flirt_sigs").mkdir()
        result = check_flirt_sigs(self._cfg(tmp_path))
        assert result.status == _WARN
        assert "no .pat/.sig" in result.message

    def test_valid_pat_passes(self, tmp_path: Path) -> None:
        from rebrew.doctor import check_flirt_sigs
        from rebrew.gen_flirt_pat import bytes_to_pat_line

        sig_dir = tmp_path / "flirt_sigs"
        sig_dir.mkdir()
        line = bytes_to_pat_line("_f", bytes(range(40)), set())
        (sig_dir / "test.pat").write_text(line + "\n---\n", encoding="utf-8")
        result = check_flirt_sigs(self._cfg(tmp_path))
        assert result.status == _PASS
        assert "1 signatures" in result.message

    def test_corrupt_pat_warns(self, tmp_path: Path) -> None:
        from rebrew.doctor import check_flirt_sigs

        sig_dir = tmp_path / "flirt_sigs"
        sig_dir.mkdir()
        (sig_dir / "broken.pat").write_text("this is not a pat file", encoding="utf-8")
        result = check_flirt_sigs(self._cfg(tmp_path))
        assert result.status == _WARN
        assert "problem file(s)" in result.message
        assert "broken.pat" in result.fix

    def test_zero_signature_pat_warns(self, tmp_path: Path) -> None:
        from rebrew.doctor import check_flirt_sigs

        sig_dir = tmp_path / "flirt_sigs"
        sig_dir.mkdir()
        (sig_dir / "empty.pat").write_text("---\n", encoding="utf-8")
        result = check_flirt_sigs(self._cfg(tmp_path))
        assert result.status == _WARN
        assert "0 sigs" in result.message
        assert "0 signatures" in result.fix

    def test_missing_python_flirt_skips(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sys

        from rebrew.doctor import check_flirt_sigs

        sig_dir = tmp_path / "flirt_sigs"
        sig_dir.mkdir()
        (sig_dir / "a.pat").write_text("---\n", encoding="utf-8")
        monkeypatch.setitem(sys.modules, "flirt", None)  # make `import flirt` fail
        result = check_flirt_sigs(self._cfg(tmp_path))
        assert result.status == "skip"
        assert "python-flirt" in result.message


class TestCheckOptionalToolsClaripy:
    """angr/claripy pairing — half-installed pairs must be flagged."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(root=tmp_path)

    def test_both_present_passes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        from types import ModuleType

        from rebrew.doctor import check_optional_tools

        for name in ("angr", "claripy"):
            monkeypatch.setitem(sys.modules, name, ModuleType(name))
        result = check_optional_tools(self._cfg(tmp_path))
        assert result.status == _PASS

    def test_angr_without_claripy_warns(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sys
        from types import ModuleType

        from rebrew.doctor import check_optional_tools

        monkeypatch.setitem(sys.modules, "angr", ModuleType("angr"))
        monkeypatch.setitem(sys.modules, "claripy", None)
        result = check_optional_tools(self._cfg(tmp_path))
        assert result.status == _WARN
        assert "claripy" in result.message

    def test_claripy_without_angr_warns(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sys
        from types import ModuleType

        from rebrew.doctor import check_optional_tools

        monkeypatch.setitem(sys.modules, "claripy", ModuleType("claripy"))
        monkeypatch.setitem(sys.modules, "angr", None)
        result = check_optional_tools(self._cfg(tmp_path))
        assert result.status == _WARN
        assert "both" in result.message

    def test_neither_warns(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys

        from rebrew.doctor import check_optional_tools

        monkeypatch.setitem(sys.modules, "angr", None)
        monkeypatch.setitem(sys.modules, "claripy", None)
        result = check_optional_tools(self._cfg(tmp_path))
        assert result.status == _WARN
        assert "missing" in result.message


class TestCheckGhidraSync:
    def _cfg(self, tmp_path: Path, **overrides: object) -> SimpleNamespace:
        d: dict[str, object] = {
            "root": tmp_path,
            "ghidra_backend": "reva",
            "ghidra_program_path": "/server.dll",
        }
        d.update(overrides)
        return SimpleNamespace(**d)

    def test_reva_backend_ready(self, tmp_path: Path) -> None:
        from rebrew.doctor import check_ghidra_sync

        result = check_ghidra_sync(self._cfg(tmp_path))  # type: ignore[arg-type]
        assert result.status == _PASS

    def test_reva_without_program_path_warns(self, tmp_path: Path) -> None:
        from rebrew.doctor import check_ghidra_sync

        result = check_ghidra_sync(
            self._cfg(tmp_path, ghidra_program_path="")  # type: ignore[arg-type]
        )
        assert result.status == _WARN
        assert "ghidra_program_path" in result.message

    def test_cli_backend_binary_missing_warns(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.ghidra.cli_backend as cb

        monkeypatch.setattr(cb.shutil, "which", staticmethod(lambda n: None))
        cfg = self._cfg(tmp_path, ghidra_backend="cli")  # type: ignore[arg-type]
        assert cb.resolve_ghidra_cli(cfg) is None  # type: ignore[arg-type]

    def test_cli_backend_binary_in_tools(self, tmp_path: Path) -> None:
        from rebrew.doctor import check_ghidra_sync

        tools_bin = tmp_path / "tools"
        tools_bin.mkdir()
        bin_file = tools_bin / "ghidra-cli"
        bin_file.write_bytes(b"#!/bin/sh\n")
        bin_file.chmod(0o755)
        cfg = self._cfg(tmp_path, ghidra_backend="cli")  # type: ignore[arg-type]
        result = check_ghidra_sync(cfg)  # type: ignore[arg-type]
        assert result.status == _PASS
        assert "ghidra-cli" in result.message

    def test_cli_backend_non_executable_tools_warns(self, tmp_path: Path) -> None:
        from rebrew.doctor import check_ghidra_sync

        tools_bin = tmp_path / "tools"
        tools_bin.mkdir()
        (tools_bin / "ghidra-cli").write_bytes(b"not executable")  # no chmod
        cfg = self._cfg(tmp_path, ghidra_backend="cli")  # type: ignore[arg-type]
        result = check_ghidra_sync(cfg)  # type: ignore[arg-type]
        assert result.status == _WARN
        assert "no ghidra-cli binary" in result.message


class TestCheckArchFormat16Bit:
    """ne/x86_16 are valid for 16-bit NE targets (msvc1.52 pipeline live)."""

    def test_ne_format_valid(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path, binary_format="ne", arch="x86_16")
        result = check_arch_format(cfg)
        assert result.status == _PASS

    def test_x86_16_arch_valid(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path, binary_format="pe", arch="x86_16")
        result = check_arch_format(cfg)
        assert result.status == _PASS


class TestCrtLinkage:
    def _cfg(self, tmp_path: Path, **overrides: object) -> SimpleNamespace:
        from rebrew.doctor import check_crt_linkage

        self.check = check_crt_linkage
        exe = tmp_path / "test.exe"
        exe.write_bytes(b"MZ")
        return SimpleNamespace(
            root=tmp_path,
            target_binary=exe,
            compiler_profile=overrides.pop("compiler_profile", "msvc6"),
            base_cflags=overrides.pop("base_cflags", "/nologo /c /MT"),
        )

    def test_matching_md(self, tmp_path: Path, monkeypatch) -> None:
        import rebrew.toolchain_detect as td

        monkeypatch.setattr(
            td,
            "detect_toolchain",
            lambda *a, **k: SimpleNamespace(
                crt="msvcrt.dll", crt_linkage="dynamic", base_cflags="/MD"
            ),
        )
        cfg = self._cfg(tmp_path, base_cflags="/nologo /c /MD")
        res = self.check(cfg)
        assert res.status == _PASS

    def test_mismatch_md_vs_mt(self, tmp_path: Path, monkeypatch) -> None:
        import rebrew.toolchain_detect as td

        monkeypatch.setattr(
            td,
            "detect_toolchain",
            lambda *a, **k: SimpleNamespace(
                crt="msvcrt.dll", crt_linkage="dynamic", base_cflags="/MD"
            ),
        )
        cfg = self._cfg(tmp_path, base_cflags="/nologo /c /MT")
        res = self.check(cfg)
        assert res.status == _WARN
        assert "/MD" in res.fix

    def test_non_msvc_skips(self, tmp_path: Path) -> None:
        cfg = self._cfg(tmp_path, compiler_profile="gcc-pe")
        res = self.check(cfg)
        assert res.status == "skip"

    def test_unknown_crt_skips(self, tmp_path: Path, monkeypatch) -> None:
        import rebrew.toolchain_detect as td

        monkeypatch.setattr(
            td,
            "detect_toolchain",
            lambda *a, **k: SimpleNamespace(crt="", crt_linkage="", base_cflags=""),
        )
        cfg = self._cfg(tmp_path)
        res = self.check(cfg)
        assert res.status == "skip"


class TestOptLevel:
    """doctor must warn when the project optimization flag disagrees with the
    binary's codegen fingerprint — /O1 vs /O2 change wrapper codegen."""

    def _cfg(self, tmp_path: Path, **overrides: object) -> SimpleNamespace:
        from rebrew.doctor import check_opt_level

        self.check = check_opt_level
        exe = tmp_path / "test.exe"
        exe.write_bytes(b"MZ")
        return SimpleNamespace(
            root=tmp_path,
            target_binary=exe,
            compiler_profile=overrides.pop("compiler_profile", "msvc6"),
            cflags=overrides.pop("cflags", "/O2 /Gd"),
        )

    def test_matching_o2(self, tmp_path: Path, monkeypatch: object) -> None:
        import rebrew.toolchain_detect as td

        monkeypatch.setattr(
            td, "detect_toolchain", lambda *a, **k: SimpleNamespace(opt_level="/O2")
        )
        cfg = self._cfg(tmp_path)
        res = self.check(cfg)
        assert res.status == _PASS

    def test_mismatch_o1_vs_o2_warns(self, tmp_path: Path, monkeypatch: object) -> None:
        import rebrew.toolchain_detect as td

        monkeypatch.setattr(
            td, "detect_toolchain", lambda *a, **k: SimpleNamespace(opt_level="/O1")
        )
        cfg = self._cfg(tmp_path, cflags="/O2 /Gd")
        res = self.check(cfg)
        assert res.status == _WARN
        assert "/O1" in res.fix

    def test_mixed_with_pinned_flag_pass_hint(self, tmp_path: Path, monkeypatch: object) -> None:
        import rebrew.toolchain_detect as td

        monkeypatch.setattr(
            td, "detect_toolchain", lambda *a, **k: SimpleNamespace(opt_level="mixed (/O1 + /O2)")
        )
        cfg = self._cfg(tmp_path, cflags="/O2 /Gd")
        res = self.check(cfg)
        assert res.status == _PASS
        assert "flag-sweep" in (res.fix or "")

    def test_inconclusive_skips(self, tmp_path: Path, monkeypatch: object) -> None:
        import rebrew.toolchain_detect as td

        monkeypatch.setattr(td, "detect_toolchain", lambda *a, **k: SimpleNamespace(opt_level=""))
        cfg = self._cfg(tmp_path)
        res = self.check(cfg)
        assert res.status == "skip"

    def test_non_msvc_skips(self, tmp_path: Path) -> None:
        cfg = self._cfg(tmp_path, compiler_profile="gcc-pe")
        res = self.check(cfg)
        assert res.status == "skip"


class TestRedundantCflagsMoved:
    """check_redundant_cflags now lives in lint as W029 — smoke the new home."""

    def test_w029_importable_from_lint(self) -> None:
        from rebrew.lint import check_redundant_cflags as lint_cflags

        assert callable(lint_cflags)

    def test_no_longer_in_doctor(self) -> None:
        import rebrew.doctor as _d

        assert not hasattr(_d, "check_redundant_cflags")


class TestCheckBinsyncState:
    """The BinSync field-sync relay health check."""

    def _check(self, tmp_path: Path, **cfg_overrides: object):
        from rebrew.doctor import check_binsync_state

        return check_binsync_state(_make_cfg(tmp_path, **cfg_overrides))

    def test_no_config_warns(self, tmp_path: Path) -> None:
        r = self._check(tmp_path)
        assert r.status == _WARN
        assert "binsync_state_dir" in r.message

    def test_configured_missing_warns(self, tmp_path: Path) -> None:
        r = self._check(tmp_path, binsync_state_dir=str(tmp_path / "state"))
        assert r.status == _WARN
        assert "not found" in r.message

    def test_not_git_warns(self, tmp_path: Path) -> None:
        state = tmp_path / "state"
        state.mkdir()
        r = self._check(tmp_path, binsync_state_dir=str(state))
        assert r.status == _WARN
        assert "git repository" in r.message

    def test_git_recent_passes(self, tmp_path: Path) -> None:
        import subprocess

        state = tmp_path / "state"
        state.mkdir()
        subprocess.run(["git", "init", "-q", str(state)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(state),
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "init",
            ],
            check=True,
        )
        r = self._check(tmp_path, binsync_state_dir=str(state))
        assert r.status == _PASS

    def test_git_stale_warns(self, tmp_path: Path) -> None:
        import subprocess

        state = tmp_path / "state"
        state.mkdir()
        subprocess.run(["git", "init", "-q", str(state)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(state),
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "init",
            ],
            check=True,
        )
        import datetime

        old = int(datetime.datetime.now(datetime.UTC).timestamp() - 30 * 86400)
        subprocess.run(
            ["git", "-C", str(state), "commit", "-q", "--amend", "--no-edit", "--allow-empty"],
            check=True,
            env={
                **__import__("os").environ,
                "GIT_AUTHOR_DATE": f"@{old}",
                "GIT_COMMITTER_DATE": f"@{old}",
            },
        )
        r = self._check(tmp_path, binsync_state_dir=str(state))
        assert r.status == _WARN
        assert "not been committed" in r.message
