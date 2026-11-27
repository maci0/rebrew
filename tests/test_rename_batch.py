"""``rebrew source rename-batch``: a plan file of ``rebrew source rename`` lines in one process.

Every test drives the umbrella CLI on the three-target fixture project of
``test_rename_targets`` and asserts the written sources, the function store or
the JSON report.
"""

from __future__ import annotations

import json
import shlex
import sqlite3
import subprocess
import sys
from typing import Any
lazy from pathlib import Path

import pytest
from cli_json import cli_payload
from test_rename_targets import _functions, _project, _row, _text, _umbrella
from tree_snapshot import snapshot as _snapshot

from rebrew.metadata import lazydoc

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


_REPLICATED = (
    '\n[metadata]\nread_backends = ["sqlite", "toml"]\nwrite_backends = ["sqlite", "toml"]\n'
)
#: Below the fixture's function store: its writes and digests go record by record.
_RECORD_WISE_MIN_CHARS = 512
#: Line 2 renames the name line 1 wrote; line 3 is refused for the name line 2 wrote.
_DEPENDENT_PLAN = """\
srv_Tick srv_Step
srv_Step srv_Loop
cm_Dispatch srv_Loop
GOLDTL.0x00402100 tl_Apply --shared-definition
cm_Dispatch cm_Route
"""
#: Store documents, whose input hashes cover edit stamps.
_STORES = frozenset({"rebrew-functions.toml", "rebrew-data.toml", "rebrew-types.toml"})
#: Seconds one ``rebrew source rename`` child may take before the test fails.
_RENAME_TIMEOUT = 120


def _replicated_project(tmp_path: Path, name: str) -> Path:
    """The fixture project with a SQLite primary beside the TOML replica."""
    root = _project(tmp_path / name)
    with (root / "rebrew-project.toml").open("a", encoding="utf-8") as config:
        config.write(_REPLICATED)
    return root


def _documents(root: Path) -> dict[str, str]:
    """Each store document of the SQLite primary, without edit stamps.

    Asserts that the TOML replica holds the same text.
    """
    with sqlite3.connect(f"file:{root / 'rebrew-metadata.sqlite3'}?mode=ro", uri=True) as db:
        rows = db.execute(
            "SELECT path, content FROM metadata_documents WHERE path NOT LIKE '.rebrew/%'"
        ).fetchall()
    documents = {}
    for path, content in rows:
        assert (root / path).read_text(encoding="utf-8") == content, path
        documents[path] = "".join(
            line
            for line in content.splitlines(keepends=True)
            if not line.startswith("updated_at = ")
        )
    return documents


def test_a_batch_on_replicated_stores_matches_one_rename_command_per_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Later lines reuse the parsed records and digests; each line still sees the ones before it."""
    monkeypatch.setattr(lazydoc, "LAZY_MIN_CHARS", _RECORD_WISE_MIN_CHARS)
    batch = _replicated_project(tmp_path, "batch")
    separate = _replicated_project(tmp_path, "separate")
    assert (batch / "rebrew-functions.toml").stat().st_size > _RECORD_WISE_MIN_CHARS
    result = _batch(batch, monkeypatch, _DEPENDENT_PLAN, "--json")
    assert result.exit_code == 1, result.output
    items = cli_payload(result)["items"]
    assert ["error" in item for item in items] == [False, False, True, False, False]
    assert "srv_Loop" in items[2]["error"]
    for item, line in zip(items, _DEPENDENT_PLAN.splitlines(), strict=True):
        # A fresh process per line: no record, split or digest cache carries over.
        single = subprocess.run(
            [sys.executable, "-m", "rebrew.rename", *shlex.split(line), "--json"],
            cwd=separate,
            capture_output=True,
            text=True,
            timeout=_RENAME_TIMEOUT,
            check=False,
        )
        if "error" in item:
            assert single.returncode != 0, single.stdout
            assert json.loads(single.stderr.splitlines()[-1])["error"]["message"] == item["error"]
            continue
        assert single.returncode == 0, single.stderr
        expected = json.loads(single.stdout)
        expected.pop("dry_run")
        # Input hashes are keyed by absolute path, and the input digest hashes those
        # keys. The stores' hashes cover edit stamps; _documents compares the stores.
        reported = json.loads(json.dumps(item).replace(str(batch), str(separate)))
        for report in (reported, expected):
            report.pop("input_digest", None)
            for key in list(report.get("input_hashes", {})):
                if Path(key).name in _STORES:
                    del report["input_hashes"][key]
        assert {k: v for k, v in reported.items() if k not in ("line", "arguments")} == expected
    assert _snapshot(batch / "src") == {
        batch / path.relative_to(separate): data
        for path, data in _snapshot(separate / "src").items()
    }
    assert _documents(batch) == _documents(separate)
    rows = _functions(batch)
    assert _row(rows, "SERVER", 0x10003000)["name"] == "srv_Loop"
    assert _row(rows, "SERVER", 0x10004100)["name"] == "cm_Route"
    assert _row(rows, "GOLDTL", 0x00402100)["name"] == "tl_Apply"


def test_a_line_whose_metadata_write_fails_leaves_no_trace_and_the_rest_still_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each line commits on its own: a failed line restores its sources and commits no row."""
    from rebrew.metadata import functions

    monkeypatch.setattr(lazydoc, "LAZY_MIN_CHARS", _RECORD_WISE_MIN_CHARS)
    root = _replicated_project(tmp_path, "batch")
    command_c = _text(root, "command.c")
    real = functions.record_function_rows
    writes: list[int] = []

    def fail_second(*args: Any, **kwargs: Any) -> Any:
        writes.append(len(writes))
        if len(writes) == 2:
            raise OSError("disk full")
        return real(*args, **kwargs)

    monkeypatch.setattr(functions, "record_function_rows", fail_second)
    plan = (
        "srv_Tick srv_Step\ncm_Dispatch cm_Route\nGOLDTL.0x00402100 tl_Apply --shared-definition\n"
    )
    result = _batch(root, monkeypatch, plan, "--json")
    assert result.exit_code == 1, result.output
    items = cli_payload(result)["items"]
    assert ["error" in item for item in items] == [False, True, False]
    assert "rename transaction failed: disk full" in items[1]["error"]
    assert "void srv_Step(OfficeSlot* slot, PlayerSlot* player)" in _text(root, "server.c")
    assert _text(root, "command.c") == command_c
    assert "void tl_Apply(void)" in _text(root, "GOLDTL.citizen.c")
    rows = _functions(root)
    assert _row(rows, "SERVER", 0x10003000)["name"] == "srv_Step"
    assert _row(rows, "SERVER", 0x10004100)["name"] == "cm_Dispatch"
    assert _row(rows, "GOLDTL", 0x00402100)["name"] == "tl_Apply"
    documents = _documents(root)
    assert 'name = "cm_Route"' not in documents["rebrew-functions.toml"]
