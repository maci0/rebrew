"""Flag-search dispatch builds a verified private source and binary snapshot."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest
from test_ops import _op_schema, _validate

from rebrew import ops

if TYPE_CHECKING:
    from pathlib import Path


def test_flag_search_snapshot(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path / "live"
    root.mkdir()
    source = root / "f.c"
    source.write_text("int f(void) { return 1; }")
    config = root / "rebrew-project.toml"
    config.write_text('[targets.main]\nbinary = "original/game.exe"\n')
    binary = tmp_path / "binary"
    binary.write_bytes(b"MZ example")

    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    files = [
        ops.FlagSearchFile(p.name, digest(p), p.stat().st_size, key="live/" + p.name)
        for p in (source, config)
    ]
    req = ops.FlagSearchRequest(
        "f.c",
        digest(source),
        1,
        files,
        "main",
        sha256=digest(binary),
        binary_key="binary",
    )
    worker = ops.WorkerConfig(filestore=tmp_path, workspace=tmp_path)
    monkeypatch.setattr("rebrew.config.load_config", lambda *_, **__: SimpleNamespace())
    monkeypatch.setattr(ops, "remote_header_refusal", lambda *_: None)

    seen = []

    def run(args, project, timeout, *, outcome_exit=False):
        assert project != root
        assert (project / "f.c").read_bytes() == source.read_bytes()
        assert (project / "original/game.exe").read_bytes() == binary.read_bytes()
        seen.append((args, timeout, outcome_exit))
        return {"matched": False}

    monkeypatch.setattr(ops, "run_rebrew", run)
    assert ops.flag_search(worker, req) == {"matched": False}
    assert seen[0][0][:2] == ["match", "flags"]
    assert "--jobs=2" in seen[0][0] and "--target=main" in seen[0][0]
    assert seen[0][1:] == (ops.SEARCH_TIMEOUT_SECONDS, True)
    payload = {
        "source": "f.c",
        "source_sha256": digest(source),
        "va": 1,
        "files": [
            {"path": f.path, "digest": f.digest, "size": f.size, "key": f.key} for f in files
        ],
        "rebrew_target": "main",
        "sha256": digest(binary),
        "binary_key": "binary",
    }
    _validate(_op_schema("rebrew.flag_search", "request"), payload)
    status, reply = ops.dispatch(worker, "rebrew.flag_search", json.dumps(payload).encode())
    assert status == 200 and json.loads(reply) == {"matched": False}
    _validate(_op_schema("rebrew.flag_search", "response"), json.loads(reply))
    comparison = dataclasses.replace(
        req, compare_toolchains=True, with_flags=True, tier="quick", toolchains="msvc-6.0"
    )
    assert ops.flag_search(worker, comparison) == {"matched": False}
    assert seen[-1][0][1] == "toolchains" and "--flags" in seen[-1][0]
    assert "--toolchains=msvc-6.0" in seen[-1][0]
    escaped = dataclasses.replace(
        req,
        files=files
        + [ops.FlagSearchFile("../outside", digest(source), source.stat().st_size, key="live/f.c")],
    )
    with pytest.raises(ops.OpsError):
        ops.flag_search(worker, escaped)
    source.write_text("changed")
    with pytest.raises(ops.OpsError, match="sha256"):
        ops.flag_search(worker, req)
