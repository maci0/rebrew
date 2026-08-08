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
    def test_empty_command_fails(self) -> None:
        result = check_compiler(_cfg(compiler_command=""))
        assert result.status == _FAIL
        assert "No compiler command" in result.message

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
