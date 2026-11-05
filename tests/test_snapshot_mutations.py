"""Retained source operations keep the original snapshot and live tree isolated."""

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from source_util import write_source

from rebrew import ops
from rebrew.metadata.data import set_data_fields_batch


def test_retained_proposals_and_candidate(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://127.0.0.1:18953")
    filestore, workspace = tmp_path / "objects", tmp_path / "workspace"
    filestore.mkdir()
    workspace.mkdir()
    binary = (Path(__file__).parent / "fixtures" / "mini_pe.exe").read_bytes()
    binary_sha = hashlib.sha256(binary).hexdigest()

    def store(data: bytes) -> tuple[str, str]:
        digest = hashlib.sha256(data).hexdigest()
        key = f"objects/{digest}"
        path = filestore / key
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(data)
        return digest, key

    _, binary_key = store(binary)
    project = b'[project]\ndefault_target="mini"\n[targets.mini]\nbinary="original/mini"\nformat="pe"\narch="x86_32"\nreversed_dir="src"\n'
    source = b"/* ADDRESS: mini 0x00401000 */\nint add(int a, int b) { return a-b; }\n"
    fixture = tmp_path / "source-fixture"
    (fixture / "src").mkdir(parents=True)
    write_source(
        fixture / "src/add.c",
        source.decode(),
        metadata_dir=fixture,
        metadata_fields={"mini.0x00401000": {"kind": "FUNCTION", "size": 11}},
    )
    metadata = (fixture / "rebrew-functions.toml").read_bytes()
    set_data_fields_batch(
        fixture, [{"module": "mini", "va": 0x401000, "fields": {"name": "g_old", "size": 4}}]
    )
    data_metadata = (fixture / "rebrew-data.toml").read_bytes()
    files = []
    for name, data in (
        ("rebrew-project.toml", project),
        ("src/add.c", source),
        ("src/function_structure.json", b'{"functions": []}'),
        ("rebrew-functions.toml", metadata),
        ("rebrew-data.toml", data_metadata),
    ):
        digest, key = store(data)
        files.append({"path": name, "digest": digest, "size": len(data), "key": key})
    live = workspace / "live"
    live.mkdir()
    (live / "sentinel").write_text("unchanged")
    seen = []

    def run(args: Any, root: Path, *unused: Any, **kwargs: Any) -> dict[str, Any]:
        assert root != live and "--target=mini" in args
        seen.append(root)
        if args[:2] == ["source", "rename"]:
            (root / "src/add.c").write_text("int renamed;\n")
        elif args[:2] == ["export", "decompme"]:
            assert "--dry-run" in args
            assert (root / "src/add.c").read_text() == "int candidate;\n"
        elif args[:2] == ["match", "run"]:
            best = root / "output/ga_runs/best.c"
            best.parent.mkdir(parents=True)
            best.write_text("int best;\n")
            return {"best_source_path": str(best), "source": str(root / "src/add.c")}
        return {"ok": True}

    real_run = ops.run_rebrew
    monkeypatch.setattr(ops, "run_rebrew", run)
    monkeypatch.setattr(ops, "remote_header_refusal", lambda *args: None)
    config = ops.WorkerConfig(filestore.resolve(), workspace.resolve())
    request = {
        "files": files,
        "rebrew_target": "mini",
        "sha256": binary_sha,
        "binary_key": binary_key,
        "operation": "rename",
        "kind": "function",
        "old_name": "add",
        "new_name": "renamed",
    }
    status, body = ops.dispatch(
        config, "rebrew.retained_source_operation", json.dumps(request).encode()
    )
    assert status == 200, body
    proposal = json.loads(body)
    changed = next(item for item in proposal["files"] if item["path"] == "src/add.c")
    assert base64.b64decode(changed["content"]) == b"int renamed;\n"
    assert (filestore / files[1]["key"]).read_bytes() == source
    assert (live / "sentinel").read_text() == "unchanged"
    candidate = "int candidate;\n"
    request.update(
        operation="decompme",
        va=0x401000,
        size=11,
        source="src/add.c",
        candidate=candidate,
        candidate_sha256=hashlib.sha256(candidate.encode()).hexdigest(),
        dry_run=True,
    )
    status, body = ops.dispatch(
        config, "rebrew.retained_source_operation", json.dumps(request).encode()
    )
    assert status == 200, body
    assert json.loads(body) == {"result": {"ok": True}}
    request.update(operation="variants", generations=1, population=1)
    status, body = ops.dispatch(
        config, "rebrew.retained_source_operation", json.dumps(request).encode()
    )
    assert status == 200, body
    variant = json.loads(body)["result"]
    assert variant["best_source"] == "int best;\n"
    assert variant["best_source_sha256"] == hashlib.sha256(b"int best;\n").hexdigest()
    assert variant["source"] == "src/add.c" and "best_source_path" not in variant
    stale = b"int stale;\n"
    digest, key = store(stale)
    request["files"] = [
        *files,
        {"path": "output/ga_runs/best.c", "digest": digest, "size": len(stale), "key": key},
    ]
    status, _ = ops.dispatch(
        config, "rebrew.retained_source_operation", json.dumps(request).encode()
    )
    assert status == 400
    request["files"] = files
    request["operation"] = "decompme"
    request["candidate_sha256"] = "0" * 64
    status, _ = ops.dispatch(
        config, "rebrew.retained_source_operation", json.dumps(request).encode()
    )
    assert status == 400
    request["candidate_sha256"] = hashlib.sha256(candidate.encode()).hexdigest()
    request["source"] = "../outside.c"
    status, _ = ops.dispatch(
        config, "rebrew.retained_source_operation", json.dumps(request).encode()
    )
    assert status == 400
    request["source"] = "src/add.c"

    def mutate_other(args: Any, root: Path, *unused: Any, **kwargs: Any) -> dict[str, Any]:
        (root / "src/function_structure.json").write_text("tampered")
        return {"ok": True}

    monkeypatch.setattr(ops, "run_rebrew", mutate_other)
    status, _ = ops.dispatch(
        config, "rebrew.retained_source_operation", json.dumps(request).encode()
    )
    assert status == 400
    assert all(not root.exists() for root in seen)
    monkeypatch.setattr(ops, "run_rebrew", real_run)
    request.update(
        operation="rename", kind="function", old_name="add", new_name="plus", dry_run=True
    )
    status, body = ops.dispatch(
        config, "rebrew.retained_source_operation", json.dumps(request).encode()
    )
    assert status == 200, body
    preview = json.loads(body)["files"]
    assert str(workspace) not in json.dumps(json.loads(body)["result"])
    assert {item["path"]: item["digest"] for item in preview} == {
        item["path"]: item["digest"] for item in files
    }
    assert (filestore / files[1]["key"]).read_bytes() == source
    request["dry_run"] = False
    status, body = ops.dispatch(
        config, "rebrew.retained_source_operation", json.dumps(request).encode()
    )
    assert status == 200, body
    proposal = json.loads(body)
    assert str(workspace) not in json.dumps(proposal["result"])
    assert any(b"plus" in base64.b64decode(item["content"]) for item in proposal["files"])
    assert (filestore / files[1]["key"]).read_bytes() == source
    annotated = "/* ADDRESS: mini 0x00401000 */\nint add(int a, int b) { return a+b; }\n"
    request.update(
        operation="decompme",
        dry_run=True,
        source="src/add.c",
        candidate=annotated,
        candidate_sha256=hashlib.sha256(annotated.encode()).hexdigest(),
    )
    status, body = ops.dispatch(
        config, "rebrew.retained_source_operation", json.dumps(request).encode()
    )
    assert status == 200, body
    assert json.loads(body)["result"]["dry_run"] is True
    assert str(workspace) not in json.dumps(json.loads(body)["result"])
    request.update(operation="data-set", va=0x401000, size=0, kind="", name="g_new", dry_run=True)
    status, body = ops.dispatch(
        config, "rebrew.retained_source_operation", json.dumps(request).encode()
    )
    assert status == 200, body
    preview = json.loads(body)["files"]
    assert {item["path"]: item["digest"] for item in preview} == {
        item["path"]: item["digest"] for item in files
    }
    request["dry_run"] = False
    status, body = ops.dispatch(
        config, "rebrew.retained_source_operation", json.dumps(request).encode()
    )
    assert status == 200, body
    proposal = json.loads(body)["files"]
    entry = next(item for item in proposal if item["path"] == "rebrew-data.toml")
    assert b"g_new" in base64.b64decode(entry["content"])
