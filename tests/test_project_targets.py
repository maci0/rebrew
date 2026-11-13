"""rebrew.project_targets lists the targets of a supplied project config."""

from __future__ import annotations

import json
import unicodedata
from typing import Any
lazy from pathlib import Path

import pytest
from test_metadata_sets import _call, _ref
from test_ops import _worker_dirs

from rebrew.ops import WorkerConfig

CONFIG = """[project]
default_target = "server"

[targets]
legacy = "not a table"

[targets.server]
binary = "original/server.exe"

[targets.client]
binary = "original/client.exe"

[targets."{name}"]
binary = "original/other.exe"
"""


def _config(directory: Path) -> WorkerConfig:
    filestore, workspace = _worker_dirs(directory)
    return WorkerConfig(filestore.resolve(), workspace.resolve())


def test_the_targets_are_the_config_tables_in_their_loader_spelling(tmp_path: Path) -> None:
    config = _config(tmp_path)
    decomposed = unicodedata.normalize("NFD", "café")
    project = CONFIG.format(name=decomposed).encode()
    files = [
        _ref(config, "rebrew-project.toml", project),
        _ref(config, "src/main.c", b"int main(void) { return 0; }\n"),
    ]
    status, reply = _call(config, "rebrew.project_targets", {"files": files})
    assert status == 200, reply
    assert reply == {"targets": ["café", "client", "server"]}


@pytest.mark.parametrize(
    ("files", "detail"),
    [
        ({"src/main.c": b"int x;\n"}, "a file set requires rebrew-project.toml"),
        ({"rebrew-project.toml": b"[targets\n"}, "invalid project config: "),
    ],
)
def test_a_config_rebrew_cannot_read_is_refused(
    tmp_path: Path, files: dict[str, bytes], detail: str
) -> None:
    config = _config(tmp_path)
    request: dict[str, Any] = {"files": [_ref(config, p, d) for p, d in files.items()]}
    status, reply = _call(config, "rebrew.project_targets", request)
    assert status == 400, json.dumps(reply)
    assert reply["detail"].startswith(detail)
