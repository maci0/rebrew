"""``rebrew source rename-batch``: a plan file of ``rebrew source rename`` lines in one process.

Every test drives the umbrella CLI on the three-target fixture project of
``test_rename_targets`` and asserts the written sources, the function store or
the JSON report.
"""

from __future__ import annotations

from typing import Any
lazy from pathlib import Path

import pytest
from cli_json import cli_payload
from test_rename_targets import _functions, _project, _row, _text, _umbrella
from tree_snapshot import snapshot as _snapshot

_PLAN = """\
# renames of one review round

srv_Tick srv_Step
srv_Step srv_Loop
no_such_function whatever
GOLDTL.0x00402100 tl_Apply --shared-definition
cm_Dispatch 9bad
"""


def _batch(root: Path, monkeypatch: pytest.MonkeyPatch, plan: str, *args: str) -> Any:
    from click.testing import CliRunner

    monkeypatch.chdir(root)
    plan_file = root / "renames.txt"
    plan_file.write_text(plan, encoding="utf-8")
    return CliRunner().invoke(_umbrella(), ["source", "rename-batch", str(plan_file), *args])


def test_rename_batch_is_mounted() -> None:
    from click.testing import CliRunner

    result = CliRunner().invoke(_umbrella(), ["source", "rename-batch", "--help"])
    assert result.exit_code == 0, result.output
    assert "plan_file" in result.output


def test_lines_apply_in_order_and_a_refused_line_does_not_stop_the_rest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _project(tmp_path)
    result = _batch(root, monkeypatch, _PLAN, "--json")
    assert result.exit_code == 1, result.output
    report = cli_payload(result)
    assert (report["dry_run"], report["renamed"], report["refused"]) == (False, 3, 2)
    assert [item["line"] for item in report["items"]] == [3, 4, 5, 6, 7]
    assert [item["arguments"] for item in report["items"]][3] == [
        "GOLDTL.0x00402100",
        "tl_Apply",
        "--shared-definition",
    ]
    assert ["error" in item for item in report["items"]] == [False, False, True, False, True]
    # Line 4 renames the name line 3 wrote.
    assert (report["items"][1]["old_name"], report["items"][1]["new_name"]) == (
        "srv_Step",
        "srv_Loop",
    )
    assert "9bad" in report["items"][4]["error"]
    assert "void srv_Loop(OfficeSlot* slot, PlayerSlot* player)" in _text(root, "server.c")
    assert "void tl_Apply(void)" in _text(root, "GOLDTL.citizen.c")
    assert "void cm_Dispatch(void)" in _text(root, "command.c")
    rows = _functions(root)
    assert _row(rows, "SERVER", 0x10003000)["name"] == "srv_Loop"
    assert _row(rows, "GOLDTL", 0x00402100)["name"] == "tl_Apply"
    assert _row(rows, "SERVER", 0x10004100)["name"] == "cm_Dispatch"


def test_dry_run_previews_each_line_against_the_unchanged_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _project(tmp_path)
    (root / "renames.txt").write_text(_PLAN, encoding="utf-8")
    before = _snapshot(root)
    result = _batch(root, monkeypatch, _PLAN, "--dry-run", "--json")
    assert result.exit_code == 1, result.output
    report = cli_payload(result)
    # Nothing was written, so line 4 finds no srv_Step to rename.
    assert (report["dry_run"], report["renamed"], report["refused"]) == (True, 2, 3)
    assert "error" in report["items"][1]
    assert _snapshot(root) == before


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ("srv_Tick srv_Step --json", "--json is not allowed in a plan line"),
        ("srv_Tick srv_Step --dry-run", "--dry-run is not allowed in a plan line"),
        ("srv_Tick --help", "--help is not allowed in a plan line"),
        ("srv_Tick", "Missing argument"),
        ("srv_Tick 'srv_Step", "unparsable line"),
        ("srv_Tick srv_Step --no-such-option", "No such option"),
    ],
)
def test_a_line_that_is_not_one_rename_is_refused_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, line: str, message: str
) -> None:
    root = _project(tmp_path)
    result = _batch(root, monkeypatch, line + "\n", "--json")
    assert result.exit_code == 1, result.output
    report = cli_payload(result)
    assert (report["renamed"], report["refused"]) == (0, 1)
    assert message in report["items"][0]["error"]
    assert "void srv_Tick(OfficeSlot* slot, PlayerSlot* player)" in _text(root, "server.c")


def test_text_report_names_each_line_and_the_totals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _project(tmp_path)
    result = _batch(root, monkeypatch, "srv_Tick srv_Step\nno_such_function whatever\n")
    assert result.exit_code == 1, result.output
    assert "line 1: renamed srv_Tick → srv_Step (1 files)" in result.output
    assert "line 2: refused" in result.output
    assert "1 renamed, 1 refused" in result.output


def test_an_empty_plan_renames_nothing_and_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _project(tmp_path)
    result = _batch(root, monkeypatch, "# nothing yet\n\n", "--json")
    assert result.exit_code == 0, result.output
    assert cli_payload(result) == {"dry_run": False, "renamed": 0, "refused": 0, "items": []}


def test_a_missing_plan_file_is_a_usage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from click.testing import CliRunner

    root = _project(tmp_path)
    monkeypatch.chdir(root)
    result = CliRunner().invoke(
        _umbrella(), ["source", "rename-batch", str(root / "absent.txt"), "--json"]
    )
    assert result.exit_code == 2, result.output
    assert "cannot read plan file" in (result.stderr or result.output)
