"""Shared helper: W3C Nu validation of the generated HTML surfaces.

The dashboard shell and the report pages are read by a screen reader, which
parses the same tree the browser does.  Invalid nesting is therefore not
cosmetic: a misnested table, a stray attribute or an unclosed element changes
the accessibility tree, and no assertion on the source string can see it.  The
strings are correct-looking by construction here, so the check has to come
from a real parser — ``vnu`` is the offline validator the project rules name.

``vnu`` is a jar, not a declared dependency, so callers skip when it is not on
PATH, the way the dashboard interaction tests skip without node.

Imports from a tests/ file work because pytest inserts the test directory
into ``sys.path``.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path

#: Seconds one validation run may take.  A cold JVM start is a second or two;
#: a run over a whole report site is a handful.
_TIMEOUT_S = 180


def assert_valid(paths: Sequence[Path]) -> None:
    """Assert every file in *paths* is error- and warning-free HTML/CSS.

    ``--also-check-css`` covers the inline ``<style>`` block both surfaces
    ship, which is where a retuned token lands first.  A warning fails the
    assertion too: a validator that only gates on errors lets the deprecated
    and borderline constructs pile up until they become the errors.
    """
    import pytest

    if not paths:
        return
    vnu = shutil.which("vnu")
    if vnu is None:
        pytest.skip("vnu is required to validate the generated HTML surfaces")
    result = subprocess.run(
        [vnu, "--format", "text", "--also-check-css", *[str(path) for path in paths]],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=_TIMEOUT_S,
        check=False,
    )
    report = result.stdout + result.stderr
    # ``--format text`` prints one finding per block, headed ``Error:`` or
    # ``Warning:``.  Only errors set the exit status, so the warning pass is
    # what keeps deprecated and borderline constructs from piling up.
    findings = [
        line
        for line in report.splitlines()
        if line.startswith(("Error:", "Warning:")) or ": error:" in line or ": warning:" in line
    ]
    assert not findings, "vnu reported:\n" + "\n".join(findings)
    assert result.returncode == 0, f"vnu exited {result.returncode}:\n{report}"
