"""Tests for rebrew doctor.py — check_compiler / check_runner branches."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.doctor import _FAIL, _PASS, _WARN, check_compiler, check_runner


def _vendored_ok(profile: str) -> bool:
    """True when the profile's vendored host compiler is actually present
    (binaries are gitignored, so a fresh clone has the tree but not them)."""
    from rebrew.toolchain import get_toolchain, vendored_binary

    try:
        return vendored_binary(get_toolchain(profile)) is not None
    except Exception:
        return False


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

    def test_x86_16_with_msvc152_checks_image(self, monkeypatch) -> None:
        """With the msvc1.52 profile configured, the compiler check must
        validate the docker image (execution is docker-only), not hand-wave
        with the stale 'future 16-bit profile' notice."""
        monkeypatch.setattr("rebrew.toolchain.image_present", lambda tag: False)
        result = check_compiler(
            _cfg(
                arch="x86_16",
                compiler_profile="msvc1.52",
                compiler_command="",
            )
        )
        assert result.status == _FAIL  # image not built -> real failure
        assert "not built" in result.message
        assert "toolchain build" in (result.fix or "")
        # and a built image passes
        monkeypatch.setattr("rebrew.toolchain.image_present", lambda tag: True)
        result2 = check_compiler(
            _cfg(
                arch="x86_16",
                compiler_profile="msvc1.52",
                compiler_command="toolchain/msvc/1.52-win16/BIN/CL.EXE",
                root=Path("/"),
            )
        )
        assert result2.status == _PASS
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
            "rebrew.delphi16.find_dcc", lambda: (_ for _ in ()).throw(Delphi16Error("not found"))
        )
        result = check_delphi16_toolchain(_cfg(arch="x86_16"))
        assert result.status == _FAIL
        assert "not found" in result.message

    def test_ready_passes(self, monkeypatch, tmp_path: Path) -> None:
        from rebrew.doctor import _PASS, check_delphi16_toolchain

        dcc_dir = tmp_path / "tools" / "delphi-1.0-win16"
        dcc_dir.mkdir(parents=True)
        (dcc_dir / "DCC.EXE").write_bytes(b"MZ")
        (dcc_dir / "RTM.EXE").write_bytes(b"MZ")
        monkeypatch.setattr("rebrew.delphi16.find_dcc", lambda: dcc_dir / "DCC.EXE")
        monkeypatch.setattr("rebrew.doctor.shutil.which", lambda *a, **k: "/usr/bin/dosbox")
        result = check_delphi16_toolchain(_cfg(arch="x86_16"))
        assert result.status == _PASS
        assert "ready" in result.message

    def test_image_profile_ready(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("rebrew.toolchain.image_present", lambda tag: True)
        result = check_compiler(_cfg(compiler_profile="msvc6"))
        assert result.status == _PASS
        assert "msvc6" in result.message

    def test_image_missing_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("rebrew.toolchain.image_present", lambda tag: False)
        result = check_compiler(_cfg(compiler_profile="msvc6"))
        assert result.status == _FAIL
        assert "not built" in result.message
        assert "toolchain build" in result.fix

    def test_unknown_profile_fails(self) -> None:
        result = check_compiler(_cfg(compiler_profile="no-such-tc"))
        assert result.status == _FAIL
        assert "no docker image" in result.message

    def test_remote_backend_passes(self) -> None:
        cfg = _cfg(compiler_profile="msvc6", recompile_url="http://localhost:8000")
        result = check_compiler(cfg)
        assert result.status == _PASS
        assert "recompile" in result.message


class TestCheckRunner:
    def test_image_ready_pass(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("rebrew.toolchain.image_present", lambda tag: True)
        result = check_runner(_cfg(compiler_profile="msvc6"))
        assert result.status == _PASS

    def test_image_missing_warns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("rebrew.toolchain.image_present", lambda tag: False)
        result = check_runner(_cfg(compiler_profile="msvc6"))
        from rebrew.doctor import _WARN

        assert result.status == _WARN
        assert "not built" in result.message

    def test_unknown_profile_fails(self) -> None:
        result = check_runner(_cfg(compiler_profile="no-such-tc"))
        assert result.status == _FAIL

    def test_remote_backend_passes(self) -> None:
        cfg = _cfg(compiler_profile="msvc6", recompile_url="http://localhost:8000")
        result = check_runner(cfg)
        assert result.status == _PASS
        assert "recompile" in result.message


class TestCheckCompilerMore:
    def test_remote_url_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://remote:9000")
        result = check_compiler(_cfg(compiler_profile="msvc6"))
        assert result.status == _PASS
        assert "remote:9000" in result.message


class TestCheckMetadataFiles:
    def test_missing_metadata_warns(self, tmp_path: Path) -> None:
        from rebrew.doctor import _WARN, check_metadata_files

        cfg = SimpleNamespace(metadata_dir=tmp_path)
        result = check_metadata_files(cfg)  # type: ignore[arg-type]
        assert result.status == _WARN
        assert "Missing" in result.message

    def test_present_metadata_passes(self, tmp_path: Path) -> None:
        from rebrew.doctor import _PASS, check_metadata_files

        (tmp_path / "rebrew-functions.toml").write_text("", encoding="utf-8")
        (tmp_path / "rebrew-data.toml").write_text("", encoding="utf-8")
        cfg = SimpleNamespace(metadata_dir=tmp_path)
        result = check_metadata_files(cfg)  # type: ignore[arg-type]
        assert result.status == _PASS


class TestDoctorCli:
    def _invoke(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, args: list[str]) -> object:
        from typer.testing import CliRunner

        from rebrew.doctor import app

        cfg = SimpleNamespace(root=tmp_path, target_name="SERVER")
        monkeypatch.setattr("rebrew.cli.require_config", lambda **kw: cfg)

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


class TestInstallWiboRetired:
    """--install-wibo is retired (host runners are gone)."""

    def _invoke(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, args: list[str]) -> object:
        from typer.testing import CliRunner

        from rebrew.doctor import DoctorReport, app

        monkeypatch.setattr("rebrew.doctor.run_doctor", lambda target=None: DoctorReport(checks=[]))
        return CliRunner().invoke(app, args)

    def test_install_wibo_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        result = self._invoke(tmp_path, monkeypatch, ["--install-wibo"])
        assert result.exit_code != 0


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
    def test_image_profile_checked(self, monkeypatch) -> None:
        from rebrew.doctor import _FAIL, check_toolchain_backed

        monkeypatch.setattr("rebrew.toolchain.image_present", lambda tag: False)
        result = check_toolchain_backed(
            SimpleNamespace(compiler_profile="gcc-pe", root=Path("/tmp"))
        )
        assert result.status == _FAIL

    def test_watcom_image_present_passes(self, monkeypatch) -> None:
        from rebrew.doctor import _PASS, check_toolchain_backed

        monkeypatch.setattr("rebrew.toolchain.image_present", lambda tag: True)
        cfg = SimpleNamespace(compiler_profile="watcom", root=Path("/tmp"))
        result = check_toolchain_backed(cfg)
        assert result.status == _PASS
        assert "pulled" in result.message

    def test_missing_image_fails(self, monkeypatch) -> None:
        from rebrew.doctor import _FAIL, check_toolchain_backed

        monkeypatch.setattr("rebrew.toolchain.image_present", lambda tag: False)
        cfg = SimpleNamespace(compiler_profile="watcom", root=Path("/tmp"))
        result = check_toolchain_backed(cfg)
        assert result.status == _FAIL
        assert "toolchain build" in (result.fix or "")


class TestCheckCompilerRelativeCommand:
    """check_compiler resolves a project-relative command (e.g.
    toolchain/msvc/1.52-win16/BIN/CL.EXE) against the project root — the msvc1.52
    direct command is not on PATH."""

    def test_relative_command_resolves(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.doctor import _PASS, check_compiler

        monkeypatch.setattr("rebrew.toolchain.image_present", lambda tag: True)
        cl = tmp_path / "toolchain" / "msvc" / "1.52-win16" / "BIN" / "CL.EXE"
        cl.parent.mkdir(parents=True)
        cl.write_bytes(b"")  # presence is what matters
        cfg = SimpleNamespace(
            root=tmp_path,
            arch="x86_16",
            compiler_profile="msvc1.52",
            compiler_command="toolchain/msvc/1.52-win16/BIN/CL.EXE",
            compiler_runner="",
        )
        result = check_compiler(cfg)
        assert result.status == _PASS

    def test_missing_image_fails(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.doctor import _FAIL, check_compiler

        monkeypatch.setattr("rebrew.toolchain.image_present", lambda tag: False)
        cfg = SimpleNamespace(
            root=tmp_path,
            arch="x86_16",
            compiler_profile="msvc1.52",
            compiler_command="toolchain/msvc/1.52-win16/BIN/CL.EXE",
            compiler_runner="",
        )
        result = check_compiler(cfg)
        assert result.status == _FAIL
        assert "not built" in result.message


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

        hint = _toolchain_download_hint("toolchain/msvc/6.0-sp3-win32/bin/cl.exe")
        assert "msvc-6.0-sp3-win32" in hint  # must not match the generic msvc6 branch

    def test_unknown_no_hint(self) -> None:
        from rebrew.doctor import _toolchain_download_hint

        assert _toolchain_download_hint("tools/weird/cc") == ""

    def test_missing_image_fix_has_build_hint(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.doctor import _FAIL, check_compiler

        monkeypatch.setattr("rebrew.toolchain.image_present", lambda tag: False)
        cfg = SimpleNamespace(
            root=tmp_path,
            arch="x86_16",
            compiler_profile="msvc1.52",
            compiler_command="toolchain/msvc/1.52-win16/BIN/CL.EXE",
            compiler_runner="",
        )
        result = check_compiler(cfg)
        assert result.status == _FAIL
        assert "toolchain build" in (result.fix or "")


class TestCheckToolchainBackedNewProfiles:
    def test_tc16_image_present_passes(self, monkeypatch) -> None:
        from rebrew.doctor import _PASS, check_toolchain_backed

        monkeypatch.setattr("rebrew.toolchain.image_present", lambda tag: True)
        cfg = SimpleNamespace(compiler_profile="tc16", root=Path("/tmp"))
        result = check_toolchain_backed(cfg)
        assert result.status == _PASS
        assert "pulled" in result.message

    def test_borlandc55_image_present_passes(self, monkeypatch) -> None:
        from rebrew.doctor import _PASS, check_toolchain_backed

        monkeypatch.setattr("rebrew.toolchain.image_present", lambda tag: True)
        cfg = SimpleNamespace(compiler_profile="borlandc55", root=Path("/tmp"))
        result = check_toolchain_backed(cfg)
        assert result.status == _PASS

    def test_watcom16_image_checked(self, monkeypatch) -> None:
        """watcom16 now has a docker image — the backed check applies."""
        from rebrew.doctor import _PASS, check_toolchain_backed

        monkeypatch.setattr("rebrew.toolchain.image_present", lambda tag: True)
        result = check_toolchain_backed(
            SimpleNamespace(compiler_profile="watcom16", root=Path("/tmp"))
        )
        assert result.status == _PASS


class TestCheckCompiler16BitProfiles:
    """The 16-bit compiler check accepts any 16-bit-capable profile
    (msvc1.52, tc16, watcom16) and suggests the right one via the
    detector for 32-bit profiles on 16-bit targets."""

    def test_tc16_profile_not_warned(self, monkeypatch) -> None:
        monkeypatch.setattr("rebrew.toolchain.image_present", lambda tag: False)
        result = check_compiler(_cfg(arch="x86_16", compiler_profile="tc16", compiler_command=""))
        assert result.status == _FAIL  # image not built -> real failure, not the 16-bit warn
        assert "16-bit" not in (result.message or "")

    def test_watcom16_profile_not_warned(self) -> None:
        result = check_compiler(
            _cfg(arch="x86_16", compiler_profile="watcom16", compiler_command="")
        )
        assert "16-bit" not in (result.message or "")

    def test_borland_mz_suggests_tc16(self, monkeypatch) -> None:
        from rebrew.toolchain_detect import ToolchainInfo

        monkeypatch.setattr(
            "rebrew.toolchain_detect.detect_toolchain",
            lambda p: ToolchainInfo(
                family="borlandc",
                version_hint="Borland C/C++ 1991",
                confidence="high",
                detected_by="die",
            ),
        )
        result = check_compiler(
            _cfg(arch="x86_16", compiler_profile="msvc6", compiler_command="missing")
        )
        assert result.status == _WARN
        assert "tc16" in (result.message or "") + (result.fix or "")
