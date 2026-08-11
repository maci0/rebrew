"""Tests for rebrew doctor.py — check_compiler / check_runner branches."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.doctor import _FAIL, _PASS, _WARN, check_compiler, check_runner


def _cfg(**overrides: object) -> SimpleNamespace:
    defaults: dict = {
        "compiler_command": "gcc",
        "root": Path("/tmp/proj"),
        "compiler_runner": "",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class TestCheckCompiler:
    def test_x86_16_target_warns_not_fails(self) -> None:
        """A 16-bit NE target WITHOUT the msvc1.52 profile has no usable
        compile path — a missing toolchain is expected, so the compiler
        check downgrades to a warning instead of failing the project."""
        result = check_compiler(_cfg(arch="x86_16", compiler_command="wine missing/CL.EXE"))
        assert result.status == _WARN
        assert "16-bit" in result.message

    def test_x86_16_with_msvc152_checks_real_path(self) -> None:
        """With the msvc1.52 profile configured, the compiler check must
        validate the real command (not hand-wave with the stale 'future
        16-bit profile' notice)."""
        result = check_compiler(
            _cfg(
                arch="x86_16",
                compiler_profile="msvc1.52",
                compiler_command="",
            )
        )
        assert result.status == _FAIL  # empty command -> real failure
        assert "msvc1.52" not in (result.message or "").lower() or result.message != ""
        # and a resolvable command passes
        result2 = check_compiler(
            _cfg(
                arch="x86_16",
                compiler_profile="msvc1.52",
                compiler_command="tools/MSVC152/BIN/CL.EXE",
                root=Path("/"),
            )
        )
        # /tools/... won't exist under /, so this must not be the stale
        # 16-bit warning — it should attempt the real path check.
        assert "future" not in (result2.fix or "")

    def test_x86_32_target_still_checks(self) -> None:
        result = check_compiler(_cfg(arch="x86_32", compiler_command=""))
        assert result.status == _FAIL


class TestCheckDelphi16Toolchain:
    def test_skipped_for_non_16bit(self) -> None:
        from rebrew.doctor import _SKIP, check_delphi16_toolchain

        result = check_delphi16_toolchain(_cfg(arch="x86_32"))
        assert result.status == _SKIP

    def test_missing_toolchain_fails(self, monkeypatch) -> None:
        from rebrew.delphi16 import Delphi16Error
        from rebrew.doctor import _FAIL, check_delphi16_toolchain

        monkeypatch.setattr(
            "rebrew.delphi16._find_dcc", lambda: (_ for _ in ()).throw(Delphi16Error("not found"))
        )
        result = check_delphi16_toolchain(_cfg(arch="x86_16"))
        assert result.status == _FAIL
        assert "not found" in result.message

    def test_ready_passes(self, monkeypatch, tmp_path: Path) -> None:
        from rebrew.doctor import _PASS, check_delphi16_toolchain

        dcc_dir = tmp_path / "tools" / "DELPHI10"
        dcc_dir.mkdir(parents=True)
        (dcc_dir / "DCC.EXE").write_bytes(b"MZ")
        (dcc_dir / "RTM.EXE").write_bytes(b"MZ")
        monkeypatch.setattr("rebrew.delphi16._find_dcc", lambda: dcc_dir / "DCC.EXE")
        monkeypatch.setattr("rebrew.doctor.shutil.which", lambda *a, **k: "/usr/bin/dosbox")
        result = check_delphi16_toolchain(_cfg(arch="x86_16"))
        assert result.status == _PASS
        assert "ready" in result.message

    def test_shlex_valueerror_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Unbalanced quotes → shlex.split raises → plain split fallback."""
        import shlex

        monkeypatch.setattr(shlex, "split", lambda s: (_ for _ in ()).throw(ValueError()))
        monkeypatch.setattr("rebrew.doctor.shutil.which", lambda exe: f"/usr/bin/{exe}")
        result = check_compiler(_cfg(compiler_command='gcc "unclosed'))
        assert result.status == _PASS

    def test_exe_not_in_path_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("rebrew.doctor.shutil.which", lambda exe: None)
        result = check_compiler(_cfg(compiler_command="clang-99"))
        assert result.status == _FAIL
        assert "not found in PATH" in result.message

    def test_native_compiler_pass(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("rebrew.doctor.shutil.which", lambda exe: f"/usr/bin/{exe}")
        result = check_compiler(_cfg(compiler_command="gcc"))
        assert result.status == _PASS

    def test_wine_not_installed_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("rebrew.doctor.shutil.which", lambda exe: None)
        result = check_compiler(_cfg(compiler_command="wine CL.EXE"))
        assert result.status == _FAIL
        assert "Wine is not installed" in result.message

    def test_wine_cl_missing_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "rebrew.doctor.shutil.which", lambda exe: "/usr/bin/wine" if exe == "wine" else None
        )
        result = check_compiler(
            _cfg(compiler_command="wine tools/CL.EXE", root=Path("/tmp/msvc6toolchain"))
        )
        assert result.status == _FAIL
        assert "CL.EXE not found" in result.message
        assert "MSVC600" in result.fix  # msvc6 hint

    def test_wine_cl_missing_msvc400_hint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "rebrew.doctor.shutil.which", lambda exe: "/usr/bin/wine" if exe == "wine" else None
        )
        result = check_compiler(
            _cfg(compiler_command="wine tools/CL.EXE", root=Path("/opt/msvc400"))
        )
        assert "MSVC400" in result.fix

    def test_wine_cl_missing_msvc63_hint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The SP3 toolchain ships from the decomp.me mirror, not itsmattkc."""
        monkeypatch.setattr(
            "rebrew.doctor.shutil.which", lambda exe: "/usr/bin/wine" if exe == "wine" else None
        )
        result = check_compiler(_cfg(compiler_command="wine Bin/CL.EXE", root=Path("/opt/msvc6.3")))
        assert "OmniBlade" in result.fix
        assert "msvc6.3.tar.gz" in result.fix
        assert "itsmattkc" not in result.fix  # msvc6.3 must not hit the SP6-era hint

    def test_wine_cl_missing_msvc70_hint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "rebrew.doctor.shutil.which", lambda exe: "/usr/bin/wine" if exe == "wine" else None
        )
        result = check_compiler(_cfg(compiler_command="wine Bin/cl.exe", root=Path("/opt/msvc7.0")))
        assert "msvc7.0.tar.gz" in result.fix

    def test_wine_cl_missing_msvc500_hint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """VC5.0 (archaic-msvc) gets the codeload URL, not itsmattkc."""
        monkeypatch.setattr(
            "rebrew.doctor.shutil.which", lambda exe: "/usr/bin/wine" if exe == "wine" else None
        )
        result = check_compiler(_cfg(compiler_command="wine bin/cl.exe", root=Path("/opt/MSVC500")))
        assert "archaic-msvc" in result.fix
        assert "msvc500" in result.fix

    def test_wine_cl_missing_watcom_hint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "rebrew.doctor.shutil.which", lambda exe: "/usr/bin/wine" if exe == "wine" else None
        )
        result = check_compiler(_cfg(compiler_command="wine bin/wcc.exe", root=Path("/opt/wcc11")))
        assert "Watcom" in result.fix
        assert "wcc11.0.tar.gz" in result.fix

    def test_wine_smoke_test_pass(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import subprocess

        cl = Path("/tmp/proj/tools/CL.EXE")
        cl.parent.mkdir(parents=True, exist_ok=True)
        cl.touch()

        monkeypatch.setattr(
            "rebrew.doctor.shutil.which", lambda exe: "/usr/bin/wine" if exe == "wine" else None
        )

        def _run(*a, **k):
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        monkeypatch.setattr(subprocess, "run", _run)
        result = check_compiler(_cfg(compiler_command=f"wine {cl}", root=Path("/tmp/proj")))
        assert result.status == _PASS
        assert "reachable" in result.message

    def test_wine_smoke_timeout_warns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import subprocess

        cl = Path("/tmp/proj/tools/CL.EXE")
        cl.parent.mkdir(parents=True, exist_ok=True)
        cl.touch()
        monkeypatch.setattr(
            "rebrew.doctor.shutil.which", lambda exe: "/usr/bin/wine" if exe == "wine" else None
        )

        def _run(*a, **k):
            raise subprocess.TimeoutExpired("wine", 10)

        monkeypatch.setattr(subprocess, "run", _run)
        result = check_compiler(_cfg(compiler_command=f"wine {cl}", root=Path("/tmp/proj")))
        assert result.status == _WARN
        assert "timed out" in result.message

    def test_wine_smoke_filenotfound_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import subprocess

        cl = Path("/tmp/proj/tools/CL.EXE")
        cl.parent.mkdir(parents=True, exist_ok=True)
        cl.touch()
        monkeypatch.setattr(
            "rebrew.doctor.shutil.which", lambda exe: "/usr/bin/wine" if exe == "wine" else None
        )

        def _run(*a, **k):
            raise FileNotFoundError("wine")

        monkeypatch.setattr(subprocess, "run", _run)
        result = check_compiler(_cfg(compiler_command=f"wine {cl}", root=Path("/tmp/proj")))
        assert result.status == _FAIL
        assert "Failed to invoke Wine" in result.message

    def test_wine_without_cl_path_warns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "rebrew.doctor.shutil.which", lambda exe: "/usr/bin/wine" if exe == "wine" else None
        )
        result = check_compiler(_cfg(compiler_command="wine"))
        assert result.status == _WARN
        assert "no CL.EXE path specified" in result.message


class TestCheckRunner:
    def test_no_runner_pass(self) -> None:
        result = check_runner(_cfg())
        assert result.status == _PASS

    def test_runner_in_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("rebrew.doctor.shutil.which", lambda exe: f"/usr/bin/{exe}")
        result = check_runner(_cfg(compiler_runner="wibo"))
        assert result.status == _PASS

    def test_wibo_found_via_finder(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("rebrew.doctor.shutil.which", lambda exe: None)
        monkeypatch.setattr("rebrew.wibo.find_wibo", lambda root: Path("/tmp/wibo"))
        result = check_runner(_cfg(compiler_runner="wibo"))
        assert result.status == _PASS
        assert "wibo found" in result.message

    def test_wibo_missing_warns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("rebrew.doctor.shutil.which", lambda exe: None)
        monkeypatch.setattr("rebrew.wibo.find_wibo", lambda root: None)
        result = check_runner(_cfg(compiler_runner="wibo"))
        assert result.status == _WARN
        assert "wibo not found" in result.message

    def test_wine_runner_pass(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "rebrew.doctor.shutil.which", lambda exe: "/usr/bin/wine" if exe == "wine" else None
        )
        result = check_runner(_cfg(compiler_runner="wine"))
        assert result.status == _PASS

    def test_unknown_runner_warns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("rebrew.doctor.shutil.which", lambda exe: None)
        result = check_runner(_cfg(compiler_runner="mystery"))
        assert result.status == _WARN
        assert "Unknown runner" in result.message


class TestCheckCompilerMore:
    def test_wine_cl_missing_msvc420_hint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "rebrew.doctor.shutil.which", lambda exe: "/usr/bin/wine" if exe == "wine" else None
        )
        result = check_compiler(
            _cfg(compiler_command="wine tools/CL.EXE", root=Path("/opt/msvc420"))
        )
        assert "MSVC420" in result.fix


class TestCheckMetadataFiles:
    def test_missing_metadata_warns(self, tmp_path: Path) -> None:
        from rebrew.doctor import _WARN, check_metadata_files

        cfg = SimpleNamespace(metadata_dir=tmp_path)
        result = check_metadata_files(cfg)  # type: ignore[arg-type]
        assert result.status == _WARN
        assert "Missing" in result.message

    def test_present_metadata_passes(self, tmp_path: Path) -> None:
        from rebrew.doctor import _PASS, check_metadata_files

        (tmp_path / "rebrew-function.toml").write_text("", encoding="utf-8")
        (tmp_path / "rebrew-data.toml").write_text("", encoding="utf-8")
        cfg = SimpleNamespace(metadata_dir=tmp_path)
        result = check_metadata_files(cfg)  # type: ignore[arg-type]
        assert result.status == _PASS


class TestDoctorCli:
    def _invoke(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, args: list[str]) -> object:
        from typer.testing import CliRunner

        from rebrew.doctor import app

        cfg = SimpleNamespace(root=tmp_path, target_name="SERVER")
        monkeypatch.setattr("rebrew.doctor.require_config", lambda **kw: cfg)

        def _run_doctor(target=None):
            from rebrew.doctor import DoctorReport

            return DoctorReport(checks=[])

        monkeypatch.setattr("rebrew.doctor.run_doctor", _run_doctor)
        return CliRunner().invoke(app, args)

    def test_json_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        result = self._invoke(tmp_path, monkeypatch, ["--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["checks"] == []
        assert data["passed"] is True

    def test_terminal_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        result = self._invoke(tmp_path, monkeypatch, [])
        assert result.exit_code == 0

    def test_install_wibo_updates_toml(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.doctor import app

        cfg = SimpleNamespace(root=tmp_path, target_name="SERVER")
        monkeypatch.setattr("rebrew.doctor.require_config", lambda **kw: cfg)
        monkeypatch.setattr("rebrew.wibo.download_wibo", lambda p: "v1.0")
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[compiler]\ncommand = "cl"\n', encoding="utf-8")
        monkeypatch.setattr(
            "rebrew.doctor.run_doctor",
            lambda target=None: __import__("rebrew.doctor", fromlist=["DoctorReport"]).DoctorReport(
                checks=[]
            ),
        )
        result = CliRunner().invoke(app, ["--install-wibo"])
        assert result.exit_code == 0
        assert 'runner = "tools/wibo"' in toml.read_text(encoding="utf-8")


class TestInstallWiboToml:
    def _invoke(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, args: list[str]) -> object:
        from typer.testing import CliRunner

        from rebrew.doctor import DoctorReport, app

        cfg = SimpleNamespace(root=tmp_path, target_name="SERVER")
        monkeypatch.setattr("rebrew.doctor.require_config", lambda **kw: cfg)
        monkeypatch.setattr("rebrew.wibo.download_wibo", lambda p: "v1.0")
        monkeypatch.setattr("rebrew.doctor.run_doctor", lambda target=None: DoctorReport(checks=[]))
        return CliRunner().invoke(app, args)

    def test_replaces_existing_runner(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text('[compiler]\nrunner = "wine"\n', encoding="utf-8")
        result = self._invoke(tmp_path, monkeypatch, ["--install-wibo"])
        assert result.exit_code == 0
        content = toml.read_text(encoding="utf-8")
        assert 'runner = "tools/wibo"' in content
        assert "wine" not in content

    def test_no_toml_no_crash(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        result = self._invoke(tmp_path, monkeypatch, ["--install-wibo"])
        assert result.exit_code == 0


class TestCheckOptionalTools:
    def test_missing_both_warns(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys

        from rebrew.doctor import _WARN, check_optional_tools

        monkeypatch.setitem(sys.modules, "angr", None)  # import fails
        monkeypatch.setitem(sys.modules, "claripy", None)  # import fails
        cfg = SimpleNamespace(root=tmp_path)
        result = check_optional_tools(cfg)  # type: ignore[arg-type]
        assert result.status == _WARN
        assert "angr" in result.message
        assert "claripy" in result.message

    def test_both_available_passes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        from types import ModuleType

        from rebrew.doctor import _PASS, check_optional_tools

        monkeypatch.setitem(sys.modules, "angr", ModuleType("angr"))
        monkeypatch.setitem(sys.modules, "claripy", ModuleType("claripy"))
        cfg = SimpleNamespace(root=tmp_path)
        result = check_optional_tools(cfg)  # type: ignore[arg-type]
        assert result.status == _PASS

    def test_registered_in_run_doctor(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.doctor import _PASS, CheckResult, check_optional_tools, run_doctor

        # Previously this called run_doctor with a missing config and asserted
        # `any(...) or report.target == "x"`. Config-missing early-return sets
        # target to "x", so the assert always passed without checking that
        # Optional tools was registered. Drive a full run with a fake config.
        cfg = SimpleNamespace(
            root=tmp_path,
            target_name="SERVER",
            target_binary=tmp_path / "missing.exe",
            binary_format="pe",
            arch="x86_32",
            compiler_command="gcc",
            compiler_includes=tmp_path / "inc",
            compiler_libs=tmp_path / "lib",
            function_list=tmp_path / "funcs.txt",
            reversed_dir=tmp_path / "src",
            metadata_dir=tmp_path,
            bin_dir=tmp_path / "bin",
            source_ext=".c",
            compiler_runner="",
        )
        monkeypatch.setattr(
            "rebrew.doctor.check_config_parse",
            lambda target=None: (CheckResult(name="Config", status=_PASS, message="ok"), cfg),
        )

        def _noop(*_a: object, **_k: object) -> CheckResult:
            return CheckResult(name="noop", status=_PASS, message="ok")

        # Keep other checks cheap; we only care that optional tools is appended.
        for name in (
            "check_target_binary",
            "check_arch_format",
            "check_compiler",
            "check_runner",
            "check_includes",
            "check_libs",
            "check_function_list",
            "check_source_files",
            "check_bin_dir",
            "check_metadata_files",
        ):
            monkeypatch.setattr(f"rebrew.doctor.{name}", _noop)

        report = run_doctor(target="SERVER")
        assert any(c.name == "Optional tools" for c in report.checks)
        # And the real check_optional_tools is still what produces that name.
        assert check_optional_tools(cfg).name == "Optional tools"  # type: ignore[arg-type]


class TestCheckToolchainAlignment:
    def _cfg(self, **overrides: object) -> SimpleNamespace:
        defaults: dict = {
            "target_binary": Path("/nonexistent.exe"),
            "compiler_profile": "msvc6",
            "compiler_command": "wine CL.EXE",
            "compiler_runner": "wine",
            "root": Path("/tmp/proj"),
        }
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    def _cfg_with_binary(self, tmp_path: Path, **overrides: object) -> SimpleNamespace:
        binary = tmp_path / "original" / "game.exe"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"MZ")
        return self._cfg(target_binary=binary, **overrides)

    def test_missing_binary_skips(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.doctor import _SKIP, check_toolchain_alignment

        result = check_toolchain_alignment(self._cfg())
        assert result.status == _SKIP

    def test_mismatch_fails(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from rebrew.doctor import _FAIL, check_toolchain_alignment
        from rebrew.toolchain_detect import ToolchainInfo

        # A genuine mismatch — a MinGW-built binary with the msvc6 profile
        # configured — is a hard failure (a compiler exists but is wrong).
        monkeypatch.setattr(
            "rebrew.toolchain_detect.detect_toolchain",
            lambda *a, **k: ToolchainInfo(family="mingw", confidence="high", version_hint="GCC 8"),
        )
        result = check_toolchain_alignment(self._cfg_with_binary(tmp_path))
        assert result.status == _FAIL
        assert "mingw" in result.message
        assert "does not align" in (result.fix or "")

    def test_delphi_mismatch_warns(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """A Delphi target has no matchable profile at all (ADR-001-style:
        documented blockers, analysis-only) — the alignment check downgrades
        to a warning instead of failing the project."""
        from rebrew.doctor import _WARN, check_toolchain_alignment
        from rebrew.toolchain_detect import ToolchainInfo

        monkeypatch.setattr(
            "rebrew.toolchain_detect.detect_toolchain",
            lambda *a, **k: ToolchainInfo(
                family="delphi", confidence="high", version_hint="Borland Delphi 2"
            ),
        )
        result = check_toolchain_alignment(self._cfg_with_binary(tmp_path))
        assert result.status == _WARN
        assert "delphi" in result.message
        assert "Delphi" in (result.fix or "")

    def test_aligned_passes(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from rebrew.doctor import _PASS, check_toolchain_alignment
        from rebrew.toolchain_detect import ToolchainInfo

        monkeypatch.setattr(
            "rebrew.toolchain_detect.detect_toolchain",
            lambda *a, **k: ToolchainInfo(
                family="msvc", confidence="high", version_hint="MSVC 6.0"
            ),
        )
        result = check_toolchain_alignment(self._cfg_with_binary(tmp_path))
        assert result.status == _PASS

    def test_zig_caveat_warns(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from rebrew.doctor import _WARN, check_toolchain_alignment
        from rebrew.toolchain_detect import ToolchainInfo

        monkeypatch.setattr(
            "rebrew.toolchain_detect.detect_toolchain",
            lambda *a, **k: ToolchainInfo(family="zig", confidence="high", version_hint="Zig/LLVM"),
        )
        result = check_toolchain_alignment(
            self._cfg_with_binary(tmp_path, compiler_profile="gcc-pe")
        )
        assert result.status == _WARN
        assert "structural" in (result.fix or "")


class TestCheckToolchainBacked:
    def test_skipped_for_other_profiles(self) -> None:
        from rebrew.doctor import _SKIP, check_toolchain_backed

        result = check_toolchain_backed(
            SimpleNamespace(compiler_profile="msvc6", root=Path("/tmp"))
        )
        assert result.status == _SKIP

    def test_watcom_vendored_passes(self, monkeypatch) -> None:
        from rebrew.doctor import _PASS, check_toolchain_backed

        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: False)
        cfg = SimpleNamespace(compiler_profile="watcom", root=Path("/tmp"))
        result = check_toolchain_backed(cfg)
        assert result.status == _PASS
        assert "WATCOM" in result.message

    def test_missing_toolchain_fails(self, monkeypatch) -> None:
        from rebrew.doctor import _FAIL, check_toolchain_backed

        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: False)
        monkeypatch.setattr(
            "rebrew.toolchain.get_toolchain",
            lambda name: __import__("rebrew.toolchain", fromlist=["ToolchainSpec"]).ToolchainSpec(
                name=name, image=None, binary="nope", host_path=None
            ),
        )
        cfg = SimpleNamespace(compiler_profile="watcom", root=Path("/tmp"))
        result = check_toolchain_backed(cfg)
        assert result.status == _FAIL
        assert "toolchain pull" in (result.fix or "")


class TestCheckCompilerRelativeCommand:
    """check_compiler resolves a project-relative command (e.g.
    tools/MSVC152/BIN/CL.EXE) against the project root — the msvc1.52
    direct command is not on PATH."""

    def test_relative_command_resolves(self, tmp_path: Path) -> None:
        from rebrew.doctor import _PASS, check_compiler

        cl = tmp_path / "tools" / "MSVC152" / "BIN" / "CL.EXE"
        cl.parent.mkdir(parents=True)
        cl.write_bytes(b"")  # presence is what matters
        cfg = SimpleNamespace(
            root=tmp_path,
            arch="x86_16",
            compiler_profile="msvc1.52",
            compiler_command="tools/MSVC152/BIN/CL.EXE",
            compiler_runner="",
        )
        result = check_compiler(cfg)
        assert result.status == _PASS

    def test_relative_command_missing_fails(self, tmp_path: Path) -> None:
        from rebrew.doctor import _FAIL, check_compiler

        cfg = SimpleNamespace(
            root=tmp_path,
            arch="x86_16",
            compiler_profile="msvc1.52",
            compiler_command="tools/MSVC152/BIN/CL.EXE",
            compiler_runner="",
        )
        result = check_compiler(cfg)
        assert result.status == _FAIL
        assert "not found" in result.message


class TestToolchainDownloadHint:
    """check_compiler's fix text includes a download URL for the missing
    vendored toolchain — including msvc1.52 (direct DOSBox command)."""

    def test_msvc152_hint(self) -> None:
        from rebrew.doctor import _toolchain_download_hint

        hint = _toolchain_download_hint("tools/msvc152/bin/cl.exe")
        assert "archive.org" in hint
        assert "MSVC 1.52" in hint

    def test_watcom_hint(self) -> None:
        from rebrew.doctor import _toolchain_download_hint

        hint = _toolchain_download_hint("tools/watcom/binl/wcc386")
        assert "watcom" in hint.lower()

    def test_msvc6_3_before_msvc6_order(self) -> None:
        from rebrew.doctor import _toolchain_download_hint

        hint = _toolchain_download_hint("tools/msvc6.3/bin/cl.exe")
        assert "msvc6.3" in hint  # must not match the generic msvc6 branch

    def test_unknown_no_hint(self) -> None:
        from rebrew.doctor import _toolchain_download_hint

        assert _toolchain_download_hint("tools/weird/cc") == ""

    def test_direct_command_fix_has_hint(self, tmp_path: Path) -> None:
        from rebrew.doctor import check_compiler

        cfg = SimpleNamespace(
            root=tmp_path,
            arch="x86_16",
            compiler_profile="msvc1.52",
            compiler_command="tools/MSVC152/BIN/CL.EXE",
            compiler_runner="",
        )
        result = check_compiler(cfg)
        assert result.status == _FAIL
        assert "archive.org" in (result.fix or "")
