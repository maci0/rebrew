"""Coverage input envelopes retained from earlier releases still verify.

The backend keeps envelopes captured by the rebrew version running at the time
and later verifies them with a newer one. Fixtures under
``tests/fixtures/coverage_input_compat/`` were produced by released code (see the
README there). A deliberate contract change must add a migration note to the
CHANGELOG and update the fixtures in the same commit; do not edit a committed
envelope to turn this test green.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from rebrew.coverage_input_contract import (
    coverage_input_digest,
    rebrew_coverage_paths,
    verify_coverage_readset,
)

_ROOT = Path(__file__).parent / "fixtures" / "coverage_input_compat"
_CASES = sorted(path.parent for path in _ROOT.glob("v*/*/envelope.json"))


def test_fixtures_exist() -> None:
    assert _CASES, "no retained coverage input fixtures found"


@pytest.mark.parametrize("case", _CASES, ids=lambda path: f"{path.parent.name}/{path.name}")
def test_retained_envelope_verifies_under_current_code(case: Path, tmp_path: Path) -> None:
    recorded = json.loads((case / "envelope.json").read_text(encoding="utf-8"))
    envelope = recorded["envelope"]
    project = tmp_path / "project"
    shutil.copytree(case / "project", project)
    assert coverage_input_digest(envelope) == recorded["digest"]
    verify_coverage_readset(project, envelope, rebrew_coverage_paths(project, envelope["target"]))
