"""rebrew.check_cflags answers the compiler flag rule every compiling op applies."""

from __future__ import annotations

import json
lazy from pathlib import Path

import pytest
from test_metadata_sets import _call
from test_ops import _worker_dirs

from rebrew.ops import CFLAGS_MAX_CHARS, WorkerConfig, dispatch


def _config(directory: Path) -> WorkerConfig:
    filestore, workspace = _worker_dirs(directory)
    return WorkerConfig(filestore.resolve(), workspace.resolve())


def test_plain_flags_come_back_normalized(tmp_path: Path) -> None:
    status, reply = _call(_config(tmp_path), "rebrew.check_cflags", {"cflags": "  /O1\t/Gd  -O2 "})
    assert status == 200, reply
    assert reply == {"cflags": "/O1 /Gd -O2"}


def test_empty_flags_are_accepted(tmp_path: Path) -> None:
    status, reply = _call(_config(tmp_path), "rebrew.check_cflags", {"cflags": ""})
    assert status == 200, reply
    assert reply == {"cflags": ""}


@pytest.mark.parametrize(
    ("cflags", "reason"),
    [
        ("/Fo", "names a file or changes the command"),
        ("/O1 /Fdx.pdb", "names a file or changes the command"),
        ("-o", "names a file or changes the command"),
        ("/link", "names a file or changes the command"),
        ("@rsp", "is not a plain option token"),
        ("/tmp/x", "is not a plain option token"),
        ("O2", "is not a plain option token"),
        ("/O1" + " /O2" * CFLAGS_MAX_CHARS, f"longer than {CFLAGS_MAX_CHARS} characters"),
    ],
)
def test_refusals_name_the_reason(tmp_path: Path, cflags: str, reason: str) -> None:
    status, reply = _call(_config(tmp_path), "rebrew.check_cflags", {"cflags": cflags})
    assert status == 400
    assert reply["error"] == "invalid-request"
    assert reply["detail"].startswith("invalid-cflags: ")
    assert reason in reply["detail"]


def test_the_request_needs_cflags(tmp_path: Path) -> None:
    status, body = dispatch(_config(tmp_path), "rebrew.check_cflags", b"{}")
    assert status == 400
    assert "missing cflags" in json.loads(body)["detail"]
