"""Tests for rebrew doctor diagnostic command."""

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.doctor import (
    _FAIL,
    _PASS,
    _SKIP,
    _WARN,
    CheckResult,
    DoctorReport,
    check_annotation_staleness,
    check_arch_format,
    check_bin_dir,
    check_config_parse,
    check_function_list,
    check_includes,
    check_libs,
    check_redundant_cflags,
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
        monkeypatch.setattr("rebrew.toolchain._image_present", lambda img: True)
        inc = check_includes(self._cfg(tmp_path))
        assert inc.status == _PASS
        assert "docker image" in inc.message
        lib = check_libs(self._cfg(tmp_path))
        assert lib.status == _PASS
        assert "docker image" in lib.message

    def test_docker_profile_without_image_warns_with_fix(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr("rebrew.toolchain._image_present", lambda img: False)
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


class TestCheckAnnotationStaleness:
    """Cross-checking FUNCTION/STUB annotations against the current function
    list — a stale annotation (binary updated, VA moved/removed) must be
    reported so test/verify stop compiling against the wrong bytes."""

    def _src(self, tmp_path: Path, name: str, body: str) -> None:
        (tmp_path / "src").mkdir(exist_ok=True)
        (tmp_path / "src" / name).write_text(body, encoding="utf-8")

    def test_all_match_passes(self, tmp_path: Path) -> None:
        (tmp_path / "funcs.txt").write_text(
            "0x1000 256 func_a\n0x2000 128 func_b\n", encoding="utf-8"
        )
        self._src(
            tmp_path, "func_a.c", "// FUNCTION: SERVER 0x1000\nint func_a(void) { return 0; }\n"
        )
        self._src(
            tmp_path, "func_b.c", "// FUNCTION: SERVER 0x2000\nint func_b(void) { return 0; }\n"
        )
        result = check_annotation_staleness(_make_cfg(tmp_path))
        assert result.status == _PASS
        assert "2 FUNCTION/STUB annotation(s) match" in result.message

    def test_dangling_va_warns(self, tmp_path: Path) -> None:
        # Function list changed: 0x1000 no longer exists there.
        (tmp_path / "funcs.txt").write_text("0x2000 128 func_b\n", encoding="utf-8")
        self._src(
            tmp_path, "func_a.c", "// FUNCTION: SERVER 0x1000\nint func_a(void) { return 0; }\n"
        )
        result = check_annotation_staleness(_make_cfg(tmp_path))
        assert result.status == _WARN
        assert "1 of 1 FUNCTION/STUB annotation(s) stale" in result.message
        assert "func_a.c:1 → 0x1000 has no function" in result.message
        assert "rebrew intake" in result.fix

    def test_fix_blames_binary_when_binary_newer(self, tmp_path: Path) -> None:
        # Binary written after the list: it plausibly changed, so the fix
        # should recommend refreshing the list via intake/discover.
        (tmp_path / "funcs.txt").write_text("0x2000 128 func_b\n", encoding="utf-8")
        bin_path = tmp_path / "test.exe"
        bin_path.write_bytes(b"MZ")
        os.utime(tmp_path / "funcs.txt", (1_000_000, 1_000_000))
        os.utime(bin_path, (2_000_000, 2_000_000))
        self._src(
            tmp_path, "func_a.c", "// FUNCTION: SERVER 0x1000\nint func_a(void) { return 0; }\n"
        )
        result = check_annotation_staleness(_make_cfg(tmp_path))
        assert result.status == _WARN
        assert "rebrew intake" in result.fix
        assert "it likely changed" in result.fix

    def test_fix_blames_annotations_when_list_newer(self, tmp_path: Path) -> None:
        # List at least as new as the binary: the binary cannot have changed
        # since the list was written, so the fix must NOT claim it did and
        # must not lead with `rebrew intake`.
        (tmp_path / "funcs.txt").write_text("0x2000 128 func_b\n", encoding="utf-8")
        bin_path = tmp_path / "test.exe"
        bin_path.write_bytes(b"MZ")
        os.utime(bin_path, (1_000_000, 1_000_000))
        os.utime(tmp_path / "funcs.txt", (2_000_000, 2_000_000))
        self._src(
            tmp_path, "func_a.c", "// FUNCTION: SERVER 0x1000\nint func_a(void) { return 0; }\n"
        )
        result = check_annotation_staleness(_make_cfg(tmp_path))
        assert result.status == _WARN
        assert "did not change" in result.fix
        assert "rebrew intake" not in result.fix
        assert "rebrew skeleton" in result.fix

    def test_va_inside_another_function_warns(self, tmp_path: Path) -> None:
        # The function moved: 0x1050 now falls inside func_a's span.
        (tmp_path / "funcs.txt").write_text("0x1000 256 func_a\n", encoding="utf-8")
        self._src(tmp_path, "old.c", "// FUNCTION: SERVER 0x1050\nint old(void) { return 0; }\n")
        result = check_annotation_staleness(_make_cfg(tmp_path))
        assert result.status == _WARN
        assert "now inside func_a" in result.message

    def test_missing_function_list_skips(self, tmp_path: Path) -> None:
        self._src(
            tmp_path, "func_a.c", "// FUNCTION: SERVER 0x1000\nint func_a(void) { return 0; }\n"
        )
        result = check_annotation_staleness(_make_cfg(tmp_path))
        assert result.status == _SKIP

    def test_data_and_library_markers_ignored(self, tmp_path: Path) -> None:
        # DATA/LIBRARY markers can point at non-function VAs legitimately
        # (data labels, import stubs that the parser filters out) — never
        # flag them as stale.
        (tmp_path / "funcs.txt").write_text("0x1000 256 func_a\n", encoding="utf-8")
        self._src(
            tmp_path,
            "data.c",
            "// DATA: SERVER 0x2000\n// SECTION: .rdata\n// LIBRARY: SERVER 0x3000\n",
        )
        result = check_annotation_staleness(_make_cfg(tmp_path))
        assert result.status == _PASS
        assert "0 FUNCTION/STUB annotation(s)" in result.message

    def test_other_target_marker_filtered(self, tmp_path: Path) -> None:
        # A shared source carries a marker for a DIFFERENT target — the
        # per-target filter must drop it before the staleness cross-check.
        (tmp_path / "funcs.txt").write_text("0x1000 256 func_a\n", encoding="utf-8")
        self._src(
            tmp_path, "shared.c", "// FUNCTION: CLIENT 0x3000\nint shared(void) { return 0; }\n"
        )
        cfg = _make_cfg(tmp_path, marker="SERVER")
        result = check_annotation_staleness(cfg)
        assert result.status == _PASS
        assert "0 FUNCTION/STUB annotation(s)" in result.message

    def test_capped_samples(self, tmp_path: Path) -> None:
        # More than 5 stale annotations — the report caps the sample list.
        (tmp_path / "funcs.txt").write_text("0x1000 256 func_a\n", encoding="utf-8")
        lines = "\n".join(f"// FUNCTION: SERVER 0x{n:x}\n" for n in range(0x2000, 0x2008))
        self._src(tmp_path, "many.c", lines)
        result = check_annotation_staleness(_make_cfg(tmp_path))
        assert result.status == _WARN
        assert "8 of 8 FUNCTION/STUB annotation(s) stale (showing 5 of 8)" in result.message


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


class TestRedundantCflags:
    """check_redundant_cflags: flag settings that only repeat a wider level's value."""

    def _cfg(self, tmp_path: Path, **overrides: object) -> SimpleNamespace:
        base = {
            "root": tmp_path,
            "metadata_dir": tmp_path,
            "cflags": "/O2 /Gd",
            "cflags_presets": {},
            "cflags_explicit": True,
        }
        base.update(overrides)
        return SimpleNamespace(**base)

    def test_clean_project_passes(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-function.toml").write_text(
            '["SERVER.0x1000"]\nstatus = "EXACT"\nsize = 42\n', encoding="utf-8"
        )
        res = check_redundant_cflags(self._cfg(tmp_path))
        assert res.status == _PASS

    def test_function_override_redundant(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-function.toml").write_text(
            '["SERVER.0x1000"]\nstatus = "EXACT"\ncflags = "/O2 /Gd"\n', encoding="utf-8"
        )
        res = check_redundant_cflags(self._cfg(tmp_path))
        assert res.status == _WARN
        assert "0x1000" in res.message
        assert "Drop" in res.fix

    def test_flag_order_does_not_matter(self, tmp_path: Path) -> None:
        # /Gd /O2 is the same set as /O2 /Gd — still redundant.
        (tmp_path / "rebrew-function.toml").write_text(
            '["SERVER.0x1000"]\ncflags = "/Gd /O2"\n', encoding="utf-8"
        )
        res = check_redundant_cflags(self._cfg(tmp_path))
        assert res.status == _WARN

    def test_extra_flags_not_redundant(self, tmp_path: Path) -> None:
        # Adds /DREBREW_ALLOW_NAKED on top of the default — carries new info.
        (tmp_path / "rebrew-function.toml").write_text(
            '["SERVER.0x1000"]\ncflags = "/O2 /Gd /DREBREW_ALLOW_NAKED"\n', encoding="utf-8"
        )
        res = check_redundant_cflags(self._cfg(tmp_path))
        assert res.status == _PASS

    def test_function_override_matching_module_preset_is_redundant(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-function.toml").write_text(
            '["GAME.0x1000"]\ncflags = "/O2 /Gd"\n', encoding="utf-8"
        )
        cfg = self._cfg(tmp_path, cflags="/O1 /Gd", cflags_presets={"GAME": "/O2 /Gd"})
        res = check_redundant_cflags(cfg)
        assert res.status == _WARN
        assert "GAME 0x1000" in res.message

    def test_module_preset_redundant_with_project(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-function.toml").write_text("", encoding="utf-8")
        cfg = self._cfg(tmp_path, cflags_presets={"GAME": "/O2 /Gd", "MSVCRT": "/O1"})
        res = check_redundant_cflags(cfg)
        assert res.status == _WARN
        assert "cflags_presets.GAME" in res.message
        assert "MSVCRT" not in res.message

    def test_no_metadata_file_passes(self, tmp_path: Path) -> None:
        res = check_redundant_cflags(self._cfg(tmp_path))
        assert res.status == _PASS
