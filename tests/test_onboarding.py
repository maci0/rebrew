"""tests/test_onboarding.py — scripted first-run onboarding on a real fixture.

Runs the REAL `rebrew intake` journey (init + toolchain + functions + document)
on the checked-in ``tests/fixtures/mini_pe.exe`` and asserts the onboarding
contract: a fresh project with a populated function list, documented skeletons
with valid rebrew markers, a healthy ``rebrew doctor`` report (all
toolchain-INDEPENDENT checks non-fail — compiler/toolchain checks depend on
docker images / native compilers and are excluded), and a concrete next-steps
summary.  Rizin's subprocess is stubbed for determinism (its output is
environment-dependent); everything else — binary, detection, scaffold,
doctor — is real.

Also asserts that `rebrew init`'s "Next steps" points at docs/ONBOARDING.md.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

import rebrew.main as main_mod

FIXTURE = Path(__file__).parent / "fixtures" / "mini_pe.exe"

# The real rizin output for the fixture (recorded once; stubbed for
# determinism so the test passes on machines without rizin).
FAKE_FUNCS: list[tuple[int, int, str]] = [
    (0x00401000, 11, "entry0"),
    (0x00401018, 2, "fcn.00401018"),
]

# Doctor checks that must never fail on a fresh intake regardless of the
# machine's docker images / native compilers.
_TOOLCHAIN_INDEPENDENT = {
    "rebrew-project.toml",
    "Target binary",
    "Arch / Format",
    "Function list",
    "Annotation staleness",
    "Source files",
    "Bin directory",
    "Metadata TOML",
}

_MARKER_RE = re.compile(r"// (FUNCTION|STUB|LIBRARY): [A-Za-z0-9_]+ 0x[0-9a-fA-F]+")


class TestOnboardingJourney:
    def _patch_env(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> CliRunner:
        runner = CliRunner()
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("rebrew.intake._run_rizin_functions", lambda b: FAKE_FUNCS)
        return runner

    def test_intake_produces_documented_project(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = self._patch_env(monkeypatch, tmp_path)
        result = runner.invoke(main_mod.app, ["intake", str(FIXTURE), "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["target"] == "mini_pe"
        assert data["functions"] == 2
        assert data["documented"] == 2
        assert "doctor" in data["next"]

        # functions.txt populated from the binary.
        funcs = (tmp_path / "src" / "mini_pe" / "functions.txt").read_text(encoding="utf-8")
        assert "0x00401000" in funcs
        assert "0x00401018" in funcs

        # Documented skeletons carry valid rebrew markers.
        skeletons = sorted((tmp_path / "src" / "mini_pe").glob("*.c"))
        assert len(skeletons) == 2
        markers = [
            line
            for f in skeletons
            for line in f.read_text(encoding="utf-8").splitlines()
            if _MARKER_RE.match(line.strip())
        ]
        assert len(markers) == 2

        # Binary copied into original/.
        assert (tmp_path / "original" / "mini_pe.exe").exists()

    def test_doctor_clean_on_fresh_intake(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = self._patch_env(monkeypatch, tmp_path)
        intake = runner.invoke(main_mod.app, ["intake", str(FIXTURE), "--json"])
        assert intake.exit_code == 0, intake.output

        doctor = runner.invoke(main_mod.app, ["doctor", "--json"])
        assert doctor.exit_code == 0, doctor.output
        report = json.loads(doctor.output)
        fails = [c for c in report["checks"] if c["status"] == "fail"]
        # No toolchain-independent check may fail on a fresh intake.
        assert all(c["name"] not in _TOOLCHAIN_INDEPENDENT for c in fails), fails

    def test_intake_terminal_output_lists_next_steps(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = self._patch_env(monkeypatch, tmp_path)
        result = runner.invoke(main_mod.app, ["intake", str(FIXTURE)])
        assert result.exit_code == 0, result.output
        combined = result.stdout + result.stderr
        assert "Intake complete" in combined
        assert "next: rebrew doctor" in combined
        assert "ONBOARDING.md" in combined

    def test_rerun_intake_is_idempotent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Re-running intake on an existing project must succeed (re-discovery)."""
        runner = self._patch_env(monkeypatch, tmp_path)
        first = runner.invoke(main_mod.app, ["intake", str(FIXTURE), "--json"])
        assert first.exit_code == 0, first.output
        second = runner.invoke(main_mod.app, ["intake", str(FIXTURE), "--json"])
        assert second.exit_code == 0, second.output
        data = json.loads(second.output)
        assert data["functions"] == 2


class TestInitOutput:
    def test_init_next_steps_link_onboarding_doc(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = CliRunner()
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(main_mod.app, ["init", "--target", "demo", "--binary", "demo.exe"])
        assert result.exit_code == 0, result.output
        combined = result.stdout + result.stderr
        assert "Initialization complete" in combined
        assert "ONBOARDING.md" in combined
        assert (tmp_path / "rebrew-project.toml").exists()
