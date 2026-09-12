"""Tests for rebrew.calibrate_bss pure helpers (no docker).

The calibrate loop itself relinks through the toolchain image, so only the
layout-metadata lookup and the PE section reader are pinned here.
"""

from pathlib import Path
from typing import Any

import pytest

from rebrew.calibrate_bss import _layout_data_vs, read_data_vs

_FIXTURE = Path(__file__).parent / "fixtures" / "mini_pe.exe"


class TestLayoutDataVs:
    def _project(self, root: Path, toml: str) -> Path:
        (root / "rebrew-project.toml").write_text(toml, encoding="utf-8")
        return root

    def test_reads_default_target_data_vs(self, tmp_path: Path) -> None:
        self._project(
            tmp_path,
            '[project]\ndefault_target = "A"\n'
            "[targets.A]\n[targets.A.layout]\n[[targets.A.layout.sections]]\n"
            'name = ".data"\nvs = 4096\n',
        )
        assert _layout_data_vs(tmp_path) == 4096

    def test_missing_layout_returns_none(self, tmp_path: Path) -> None:
        self._project(tmp_path, '[project]\ndefault_target = "A"\n[targets.A]\n')
        assert _layout_data_vs(tmp_path) is None

    def test_missing_toml_returns_none(self, tmp_path: Path) -> None:
        assert _layout_data_vs(tmp_path) is None

    def test_no_data_section_returns_none(self, tmp_path: Path) -> None:
        self._project(
            tmp_path,
            '[project]\ndefault_target = "A"\n'
            "[targets.A]\n[targets.A.layout]\n[[targets.A.layout.sections]]\n"
            'name = ".text"\nvs = 128\n',
        )
        assert _layout_data_vs(tmp_path) is None


class TestReadDataVs:
    def test_missing_data_section_raises(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="no .data section"):
            read_data_vs(_FIXTURE)


class TestCalibrateLoop:
    """The in-place stub rewrite must be reverted when calibration fails."""

    def _project(self, tmp_path: Path) -> Path:
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "A"\n[targets.A]\n', encoding="utf-8"
        )
        stub = tmp_path / "src" / "link_stubs.c"
        stub.parent.mkdir(parents=True)
        stub.write_text("char g_bss_tail[0x10];\n", encoding="utf-8")
        return stub

    def _invoke(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *args: str) -> Any:
        from typer.testing import CliRunner

        from rebrew.main import app

        monkeypatch.chdir(tmp_path)
        return CliRunner().invoke(app, ["calibrate-bss", *args])

    def test_failed_compile_restores_stub(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import subprocess

        from rebrew import calibrate_bss as cb

        stub = self._project(tmp_path)
        original = stub.read_text(encoding="utf-8")

        monkeypatch.setattr(cb, "find_link_cmd", lambda root: (tmp_path, "true {out}", tmp_path))
        # Raw .data VS is 0x10 against a 0x20 target, so the tail is rewritten
        # before the compile that then fails.
        monkeypatch.setattr(cb, "read_data_vs", lambda path: 0x10)

        def fake_run(cmd: object, **kwargs: object) -> None:
            if isinstance(cmd, list):
                raise subprocess.CalledProcessError(1, cmd, stderr=b"boom")
            return None

        monkeypatch.setattr(cb.subprocess, "run", fake_run)

        result = self._invoke(
            tmp_path, monkeypatch, "--stub", str(stub), "--target-vs", "0x20", "--json"
        )
        assert result.exit_code != 0
        assert stub.read_text(encoding="utf-8") == original

    def test_max_iters_must_be_positive(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stub = self._project(tmp_path)
        result = self._invoke(
            tmp_path, monkeypatch, "--stub", str(stub), "--target-vs", "0x20", "--max-iters", "0"
        )
        assert result.exit_code != 0
        assert "max-iters" in result.output

    def test_bad_target_vs_errors_cleanly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stub = self._project(tmp_path)
        result = self._invoke(tmp_path, monkeypatch, "--stub", str(stub), "--target-vs", "nope")
        assert result.exit_code != 0
        assert "target-vs" in result.output


class TestDefaultTargetUnderProjectTable:
    def test_default_target_read_from_project_table(self, tmp_path: Path) -> None:
        """`default_target` lives under [project]; reading it at the top level
        always missed it and fell back to the FIRST declared target, so a
        multi-target project calibrated the wrong binary."""
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "B"\n'
            "[targets.A]\n[targets.A.layout]\n[[targets.A.layout.sections]]\n"
            'name = ".data"\nvs = 111\n'
            "[targets.B]\n[targets.B.layout]\n[[targets.B.layout.sections]]\n"
            'name = ".data"\nvs = 4096\n',
            encoding="utf-8",
        )
        assert _layout_data_vs(tmp_path) == 4096
