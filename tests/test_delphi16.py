"""The Delphi build stages fresh inputs and runs only its Docker toolchain."""

from pathlib import Path
from typing import Any

import pytest
from bin_util import make_ne

from rebrew.compiler.delphi16 import Delphi16Error, compile_ne
from rebrew.compiler.toolchain import RunResult, ToolchainError, image_present

_IMAGE = "rebrew/delphi:1.0-win16"


def _runtime_can_bind_mount(directory: Path) -> bool:
    """True when the container runtime can see a host directory's files.

    A rootless or namespace-sandboxed daemon may resolve a bind-mount source
    in its own mount namespace: pytest's tmp directory then mounts empty and
    the compiler reports a missing source. That is an environment limit, not
    a compiler result, so the integration below skips instead of failing.
    """
    import subprocess

    from rebrew.compiler.toolchain import container_runtime

    marker = directory / "mount-probe"
    marker.write_text("probe", encoding="utf-8")
    try:
        proc = subprocess.run(
            [
                container_runtime(),
                "run",
                "--rm",
                "--network=none",
                "-v",
                f"{directory}:/probe",
                "--entrypoint",
                "/bin/sh",
                _IMAGE,
                "-c",
                f"test -f /probe/{marker.name}",
            ],
            capture_output=True,
            timeout=120,
            check=False,
        )
    except OSError, subprocess.SubprocessError:
        return False
    finally:
        marker.unlink(missing_ok=True)
    return proc.returncode == 0


def _fake_runner(
    monkeypatch: pytest.MonkeyPatch, *, produce_map: bool = True
) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def run(spec: Any, args: list[str], *, workdir: Path, timeout: int) -> RunResult:
        calls.append({"spec": spec, "args": args, "workdir": workdir, "timeout": timeout})
        stem = Path(args[-1]).stem.upper()
        code = b"\x01\x00\x55\x8b\xec\x5d\xc3" + b"\x90" * 8
        (workdir / f"{stem}.EXE").write_bytes(make_ne(segments=[(code, 1)]))
        (workdir / "DCCOUT.TXT").write_text("compiled fresh units\n")
        if produce_map and "-GS" in args:
            (workdir / f"{stem}.MAP").write_text("fresh map\n")
        return RunResult(0, "", "", backend="docker")

    monkeypatch.setattr("rebrew.compiler.delphi16.run_toolchain", run)
    return calls


class TestCompileNe:
    def test_docker_build_preserves_source_and_map_switches(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        source = tmp_path / "HELLO.DPR"
        source.write_bytes(b"program Hello; begin end.\r\n")
        calls = _fake_runner(monkeypatch)
        result = compile_ne(source, tmp_path / "work", extra_args=("-$S-",), map_file=True)
        assert calls[0]["spec"].image == "rebrew/delphi:1.0-win16"
        assert calls[0]["args"] == ["-B", "-$S-", "-GS", "HELLO.DPR"]
        assert (result.exe_path.parent / "HELLO.DPR").read_bytes() == source.read_bytes()
        assert result.map_path is not None and result.map_path.read_text() == "fresh map\n"
        assert result.funcs[0].va == 0x10002
        assert "compiled fresh" in result.log

    def test_stages_units_resources_and_custom_library(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        source = tmp_path / "HELLO.DPR"
        source.write_text("program Hello; uses Mine; begin end.")
        for name in ("MINE.PAS", "MINE.DFM", "HELLO.RES", "MINE.INC"):
            (tmp_path / name).write_bytes(b"\xfflegacy bytes\r\n")
        (tmp_path / "UNRELATED_PROGRAM.DPR").write_text("program Other; begin end.")
        units = tmp_path / "lib"
        units.mkdir()
        (units / "SYSUTILS.DCU").write_bytes(b"unit revision")
        _fake_runner(monkeypatch)
        result = compile_ne(
            source,
            tmp_path / "work",
            units_dir=units,
            dcc_cfg=b"/uC:\\DELPHI\\LIB\r\n;\xff legacy configuration\r\n",
        )
        sandbox = result.exe_path.parent
        assert (sandbox / "MINE.PAS").read_bytes() == b"\xfflegacy bytes\r\n"
        assert (sandbox / "HELLO.RES").is_file()
        assert not (sandbox / "UNRELATED_PROGRAM.DPR").exists()
        assert (sandbox / "DELPHI/LIB/SYSUTILS.DCU").read_bytes() == b"unit revision"
        assert (
            sandbox / "DCC.CFG"
        ).read_bytes() == b"/uC:\\DELPHI\\LIB\r\n;\xff legacy configuration\r\n"
        assert not (sandbox / "DCC.EXE").exists()

    def test_each_call_has_fresh_inputs_and_outputs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        source = tmp_path / "HELLO.DPR"
        source.write_text("program Hello; begin end.")
        unit = tmp_path / "MINE.PAS"
        unit.write_text("unit Mine; interface implementation end.")
        _fake_runner(monkeypatch)
        first = compile_ne(source, tmp_path / "work", map_file=True)
        unit.unlink()
        calls = _fake_runner(monkeypatch, produce_map=False)
        with pytest.raises(Delphi16Error, match="no requested map"):
            compile_ne(source, tmp_path / "work", map_file=True)
        assert calls[0]["workdir"] != first.exe_path.parent
        assert not (calls[0]["workdir"] / "MINE.PAS").exists()
        assert first.map_path is not None and first.map_path.is_file()

    def test_stale_executable_cannot_satisfy_a_failed_build(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "PROBE.EXE").write_bytes(make_ne())
        monkeypatch.setattr(
            "rebrew.compiler.delphi16.run_toolchain",
            lambda *_a, **_kw: RunResult(0, "failed to compile", "", backend="docker"),
        )
        with pytest.raises(Delphi16Error, match="no executable"):
            compile_ne("program Probe; begin end.", tmp_path)

    def test_missing_image_has_no_host_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def run(*_args: Any, **_kwargs: Any) -> RunResult:
            raise ToolchainError(
                "docker image missing; run rebrew toolchain build delphi-1.0", kind="missing"
            )

        monkeypatch.setattr("rebrew.compiler.delphi16.run_toolchain", run)
        monkeypatch.setattr(
            "rebrew.compiler.dosbox.run_dosbox", lambda *_a, **_kw: pytest.fail("host fallback")
        )
        with pytest.raises(Delphi16Error, match="docker image missing"):
            compile_ne("program Probe; begin end.", tmp_path)

    @pytest.mark.parametrize(
        "name,wanted",
        [("hello.dpr", "hello.dpr"), ("longername.dpr", "SRC.DPR"), ("a+b.dpr", "SRC.DPR")],
    )
    def test_program_basename_contract(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, wanted: str
    ) -> None:
        source = tmp_path / name
        source.write_text("program Hello; begin end.")
        calls = _fake_runner(monkeypatch)
        compile_ne(source, tmp_path / "work")
        assert calls[0]["args"][-1] == wanted

    def test_refuses_non_dos_unit_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        source = tmp_path / "HELLO.DPR"
        source.write_text("program Hello; begin end.")
        (tmp_path / "longerunit.pas").write_text("unit LongerUnit; interface implementation end.")
        _fake_runner(monkeypatch)
        with pytest.raises(Delphi16Error, match="8.3-truncate"):
            compile_ne(source, tmp_path / "work")
        assert compile_ne(source, tmp_path / "work", stage_siblings=False).exe_path.is_file()

    def test_refuses_case_colliding_units(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        source = tmp_path / "HELLO.DPR"
        source.write_text("program Hello; begin end.")
        for name in ("MINE.PAS", "mine.pas"):
            (tmp_path / name).write_text("unit Mine; interface implementation end.")
        _fake_runner(monkeypatch)
        with pytest.raises(Delphi16Error, match="collides"):
            compile_ne(source, tmp_path / "work")

    @pytest.mark.parametrize("argument", ["-$S-\nexit", "-$S-&echo", "%PATH%", "|exit"])
    def test_refuses_dos_command_injection(self, tmp_path: Path, argument: str) -> None:
        with pytest.raises(Delphi16Error, match="command separators"):
            compile_ne("program Probe; begin end.", tmp_path, extra_args=(argument,))

    def test_missing_explicit_inputs_are_errors(self, tmp_path: Path) -> None:
        with pytest.raises(Delphi16Error, match="source not found"):
            compile_ne(tmp_path / "missing.dpr", tmp_path / "work")
        with pytest.raises(Delphi16Error, match="units directory not found"):
            compile_ne(
                "program Probe; begin end.", tmp_path / "work", units_dir=tmp_path / "missing"
            )


try:
    _image_available = image_present(_IMAGE)
except ToolchainError:
    _image_available = False


class TestDockerIntegration:
    @pytest.mark.skipif(not _image_available, reason="delphi-1.0 image unavailable")
    def test_real_multi_unit_program_and_map(self, tmp_path: Path) -> None:
        (tmp_path / "MINE.PAS").write_text(
            "unit Mine; interface procedure Touch; implementation procedure Touch; begin end; end.\n"
        )
        if not _runtime_can_bind_mount(tmp_path):
            pytest.skip(
                "container runtime cannot bind-mount the pytest tmp directory "
                "(sandboxed /tmp); run the suite with TMPDIR on a shared filesystem"
            )
        source = tmp_path / "HELLO.DPR"
        source.write_text("program Hello; uses Mine; begin Touch; end.\n")
        result = compile_ne(source, tmp_path / "work", extra_args=("-$S-",), map_file=True)
        assert result.exe_path.is_file()
        assert result.map_path is not None and result.map_path.stat().st_size > 0
        assert result.funcs
