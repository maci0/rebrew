"""rebrew.rename_identifier renames C identifiers in one text, C-aware and in order."""

from __future__ import annotations

import json
from typing import Any
lazy from pathlib import Path

from test_metadata_sets import _call
from test_ops import _worker_dirs

from rebrew.ops import MAX_IDENTIFIER_RENAMES, WorkerConfig, dispatch

SOURCE = (
    "/* local_10 counts */\n"
    "int FUN_00401000(int param_1) {\n"
    "  int local_10 = param_1;\n"
    '  puts("local_10");\n'
    "  s.local_10 = local_10 + 1;\n"
    "  return FUN_00401000(local_10);\n"
    "}\n"
)


def _config(directory: Path) -> WorkerConfig:
    filestore, workspace = _worker_dirs(directory)
    return WorkerConfig(filestore.resolve(), workspace.resolve())


def _rename(tmp_path: Path, source: str, *pairs: tuple[str, str]) -> dict[str, Any]:
    renames = [{"old": old, "new": new} for old, new in pairs]
    status, reply = _call(
        _config(tmp_path), "rebrew.rename_identifier", {"source": source, "renames": renames}
    )
    assert status == 200, reply
    return reply


def test_identifiers_are_renamed_and_other_namespaces_kept(tmp_path: Path) -> None:
    reply = _rename(tmp_path, SOURCE, ("local_10", "count"))
    assert reply["source"] == (
        "/* local_10 counts */\n"
        "int FUN_00401000(int param_1) {\n"
        "  int count = param_1;\n"
        '  puts("local_10");\n'
        "  s.local_10 = count + 1;\n"
        "  return FUN_00401000(count);\n"
        "}\n"
    )
    (result,) = reply["renames"]
    data = SOURCE.encode()
    assert result["applied"] is True and result["reason"] == ""
    assert len(result["offsets"]) == 3
    for offset in result["offsets"]:
        assert data[offset : offset + len(b"local_10")] == b"local_10"


def test_offsets_are_utf8_bytes(tmp_path: Path) -> None:
    source = '/* é */ char *s = "ü"; int abc = 1; int f(void) { return abc; }\n'
    reply = _rename(tmp_path, source, ("abc", "total"))
    (result,) = reply["renames"]
    data = source.encode()
    assert [data[o : o + 3] for o in result["offsets"]] == [b"abc", b"abc"]
    assert reply["source"] == source.replace("abc", "total")


def test_renames_apply_in_order_against_the_previous_result(tmp_path: Path) -> None:
    reply = _rename(
        tmp_path,
        SOURCE,
        ("local_10", "count"),
        ("param_1", "count"),
        ("count", "total"),
        ("param_1", "seed"),
    )
    applied = [r["applied"] for r in reply["renames"]]
    assert applied == [True, False, True, True]
    assert reply["renames"][1]["reason"] == "new name is already used in the source"
    assert reply["renames"][1]["offsets"] == []
    assert "int total = seed;" in reply["source"]
    assert "return FUN_00401000(total);" in reply["source"]


def test_skipped_renames_say_why_and_leave_the_text(tmp_path: Path) -> None:
    reply = _rename(
        tmp_path,
        SOURCE,
        ("absent_name", "other"),
        ("local_10", "local_10"),
        ("local_10", "int"),
        ("local_10", "9lives"),
        ("puts_text", "x"),
    )
    reasons = [r["reason"] for r in reply["renames"]]
    assert reasons == [
        "old name is not an identifier in the source",
        "name unchanged",
        "not a C identifier",
        "not a C identifier",
        "old name is not an identifier in the source",
    ]
    assert not any(r["applied"] for r in reply["renames"])
    assert reply["source"] == SOURCE


def test_a_name_only_in_comments_or_literals_is_absent(tmp_path: Path) -> None:
    source = '/* counter */ const char *s = "counter"; int x;\n'
    reply = _rename(tmp_path, source, ("counter", "tally"))
    assert reply["renames"][0]["reason"] == "old name is not an identifier in the source"
    assert reply["source"] == source


def test_the_rename_list_is_bounded(tmp_path: Path) -> None:
    config = _config(tmp_path)
    for renames in ([], [{"old": "a_name", "new": "b_name"}] * (MAX_IDENTIFIER_RENAMES + 1)):
        body = json.dumps({"source": "int a_name;\n", "renames": renames}).encode()
        status, reply = dispatch(config, "rebrew.rename_identifier", body)
        assert status == 400, reply
        assert json.loads(reply)["error"] == "invalid-request"
