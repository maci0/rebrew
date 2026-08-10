"""tests/test_document_unmatched.py — ``rebrew document-unmatched``.

Standalone version of intake's document-unmatched step: STUB .c + blocker
for every function in the function list that isn't already documented.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rebrew.main import app

FIXTURES = Path(__file__).parent / "fixtures"

_PROJECT_TOML = """\
[project]
name = "docprobe"
default_target = "SERVER"
jobs = 1

[targets."SERVER"]
binary = "original/mini_pe.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src/SERVER"
function_list = "src/SERVER/functions.txt"
bin_dir = "bin/SERVER"
source_ext = ".c"
marker = "SERVER"

[compiler]
profile = "gcc-pe"
runner = ""
command = "i686-w64-mingw32-gcc"
includes = ""
libs = ""
cflags = "-O2"
base_cflags = ""
timeout = 60
"""

_FUNCTIONS = "0x00401000 11 _func1\n0x00401010 10 _func2\n0x00401020 8 _func3\n"


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Assemble a project where only func3 is undocumented.

    - func1: matched (renamed file ``func1.c`` with a FUNCTION marker)
    - func2: stub file present (``fcn_00401010.c``)
    - func3: no file, no marker — the only unmatched VA
    """
    root = tmp_path / "project"
    (root / "original").mkdir(parents=True)
    (root / "src" / "SERVER").mkdir(parents=True)
    (root / "bin" / "SERVER").mkdir(parents=True)
    shutil.copy(FIXTURES / "mini_pe.exe", root / "original" / "mini_pe.exe")
    (root / "rebrew-project.toml").write_text(_PROJECT_TOML, encoding="utf-8")
    (root / "src" / "SERVER" / "functions.txt").write_text(_FUNCTIONS, encoding="utf-8")
    (root / "src" / "SERVER" / "func1.c").write_text(
        "// FUNCTION: SERVER 0x00401000\nint __cdecl _func1(void) { return 0; }\n",
        encoding="utf-8",
    )
    (root / "src" / "SERVER" / "fcn_00401010.c").write_text(
        "// STUB: SERVER 0x00401010\nvoid fcn_00401010(void) {}\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(root)
    return root


class TestDocumentUnmatched:
    def test_documents_only_unmatched(self, project: Path) -> None:
        """Only func3 (no file, no marker) gets a STUB skeleton + blocker."""
        result = CliRunner().invoke(app, ["document-unmatched"])
        assert result.exit_code == 0, result.output
        stub = project / "src" / "SERVER" / "fcn_00401020.c"
        assert stub.exists(), "undocumented function must get a stub file"
        assert "STUB: SERVER 0x00401020" in stub.read_text(encoding="utf-8")
        # func1/func2 must NOT be re-documented
        assert not (project / "src" / "SERVER" / "fcn_00401000.c").exists()
        assert (project / "src" / "SERVER" / "fcn_00401010.c").read_text(
            encoding="utf-8"
        ) == "// STUB: SERVER 0x00401010\nvoid fcn_00401010(void) {}\n"
        # blocker metadata written for the new function (metadata root = src/)
        meta = project / "src" / "rebrew-function.toml"
        assert "0x00401020" in meta.read_text(encoding="utf-8")

    def test_idempotent_rerun(self, project: Path) -> None:
        """Second run documents nothing (all VAs covered)."""
        r1 = CliRunner().invoke(app, ["document-unmatched", "--json"])
        assert r1.exit_code == 0, r1.output
        assert json.loads(r1.stdout)["written"] == 1
        r2 = CliRunner().invoke(app, ["document-unmatched", "--json"])
        assert r2.exit_code == 0, r2.output
        payload = json.loads(r2.stdout)
        assert payload["written"] == 0
        assert payload["unmatched"] == 0

    def test_dry_run_writes_nothing(self, project: Path) -> None:
        """--dry-run reports the count without creating files or metadata."""
        result = CliRunner().invoke(app, ["document-unmatched", "--dry-run", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["written"] == 0
        assert payload["unmatched"] == 1
        assert payload["dry_run"] is True
        assert not (project / "src" / "SERVER" / "fcn_00401020.c").exists()
        assert not (project / "src" / "rebrew-function.toml").exists()

    def test_json_purity(self, project: Path) -> None:
        """stdout is exactly one JSON document."""
        result = CliRunner().invoke(app, ["document-unmatched", "--json"])
        assert result.exit_code == 0, result.output
        json.loads(result.stdout)  # pure JSON — no preamble
