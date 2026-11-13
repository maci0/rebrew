"""Re-analysis carries a target's published function registry onto the fresh capture."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any
lazy from pathlib import Path

import pytest
from test_ops import KEY, SHA256, _analyse_request, _op_schema, _store, _validate, _worker_dirs

import rebrew.ops as ops
from rebrew.config import load_config
from rebrew.metadata.sqlite import DATABASE_FILENAME, SqliteStore, metadata_database_documents
from rebrew.ops import FlagSearchFile, WorkerConfig, dispatch

APPLIED = "applied_name"
RENAMED_VA = 0x401010
DATA_VA = 0x402000
REGISTRY = "rebrew-functions.toml"
CONFIG = "rebrew-project.toml"


def _call(config: WorkerConfig, op: str, request: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    _validate(_op_schema(op, "request"), request)
    status, raw = dispatch(config, op, json.dumps(request).encode())
    reply: dict[str, Any] = json.loads(raw)
    if status == 200:
        _validate(_op_schema(op, "response"), reply)
    return status, reply


def _analyse(config: WorkerConfig) -> dict[str, Any]:
    """Analyse without the contract check: the version 1 helper patches the metadata out."""
    status, raw = dispatch(config, "rebrew.analyse", json.dumps(_analyse_request()).encode())
    reply: dict[str, Any] = json.loads(raw)
    assert status == 200, reply
    return reply


def _captured(capture: dict[str, Any]) -> dict[str, bytes]:
    return {
        entry["path"]: base64.b64decode(entry["data"], validate=True)
        for entry in capture["entries"]
        if entry["kind"] == "file"
    }


def _ref(config: WorkerConfig, path: str, data: bytes) -> dict[str, Any]:
    assert config.filestore is not None
    digest, key = _store(config.filestore, data)
    return {"path": path, "digest": digest, "size": len(data), "key": key}


def _refs(config: WorkerConfig, files: dict[str, bytes]) -> list[dict[str, Any]]:
    return [_ref(config, path, data) for path, data in sorted(files.items())]


def _merged(capture: dict[str, Any], published: dict[str, bytes]) -> dict[str, bytes]:
    """The backend's coverageStageSets: captured analysis files under the published tree.

    An attested store in the tree replaces the captured one.
    """
    analysis = {
        entry["path"]
        for entry in capture["entries"]
        if entry["kind"] == "file" and entry["role"] == "analysis" and entry["path"] != CONFIG
    }
    return {
        **{path: data for path, data in _captured(capture).items() if path in analysis},
        **published,
    }


def _documents(store: bytes, directory: Path) -> dict[str, bytes]:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / DATABASE_FILENAME).write_bytes(store)
    return {
        path: SqliteStore(directory / path, directory).snapshot() or b""
        for path in metadata_database_documents(directory / DATABASE_FILENAME)
    }


def _carry(
    config: WorkerConfig, published: dict[str, bytes], capture: dict[str, Any], registry: str
) -> tuple[int, dict[str, Any]]:
    """Call the op as the backend does: capture and target files, named by the descriptors."""
    captured = _captured(capture)
    metadata = [item["path"] for item in capture["metadata"]["files"]]
    target = [CONFIG, registry] if registry else [CONFIG]
    request = {
        "capture": _refs(config, {path: captured[path] for path in (CONFIG, *metadata)}),
        "target": _refs(config, {path: published[path] for path in target}),
    }
    return _call(config, "rebrew.metadata_carry", request)


def _applied_files(reply: dict[str, Any]) -> dict[str, bytes]:
    files = {}
    for row in reply["files"]:
        data = base64.b64decode(row["data"], validate=True)
        assert (len(data), hashlib.sha256(data).hexdigest()) == (row["size"], row["digest"])
        files[row["path"]] = data
    return files


def _v1_target_with_applied_name(config: WorkerConfig) -> dict[str, bytes]:
    """The tree of a target published from a version 1 capture, after a rename was applied."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(ops, "_fresh_sqlite_metadata", lambda *_args: None)
        capture = _analyse(config)["analysis_capture"]
    captured = _captured(capture)
    assert DATABASE_FILENAME not in captured and REGISTRY in captured
    status, proposal = _call(
        config,
        "rebrew.retained_source_operation",
        {
            "files": _refs(config, captured),
            "rebrew_target": capture["target"],
            "sha256": SHA256,
            "binary_key": KEY,
            "operation": "rename",
            "kind": "function",
            "old_name": f"0x{RENAMED_VA:x}",
            "new_name": APPLIED,
        },
    )
    assert status == 200, proposal
    renamed = {
        row["path"]: base64.b64decode(row["content"], validate=True) for row in proposal["files"]
    }
    tree = {
        path: data
        for path, data in renamed.items()
        if path in {CONFIG, REGISTRY} or path.endswith((".c", ".h"))
    }
    assert APPLIED.encode() in tree[REGISTRY] and f"src/mini/{APPLIED}.c" in tree
    return tree


def _with_fresh_data(note: str) -> Any:
    """An intake that also records one data row, so a re-analysis brings a changed data document."""
    from rebrew.metadata.data import set_data_field

    intake = ops._run_intake

    def seed(binary: Path, root: Path, target: str) -> Any:
        result = intake(binary, root, target)
        cfg = load_config(root, target=target)
        set_data_field(cfg.metadata_dir, DATA_VA, "note", note, "MINI", updated_by="intake")
        return result

    return seed


def _read_names(
    config: WorkerConfig,
    reanalysed: dict[str, Any],
    tree: dict[str, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Coverage, named decompilation and verification of the retained target read the applied name."""
    from rebrew.coverage_input_contract import coverage_input_digest, plan_coverage_readset

    capture = reanalysed["analysis_capture"]
    target = capture["target"]
    files = _refs(config, _merged(capture, tree))
    retained = [FlagSearchFile(**row) for row in files]
    with ops.retained_target_snapshot(config, retained, target, SHA256, KEY, "") as staged:
        assert load_config(staged, target=target).metadata_backend == "sqlite"
        assert APPLIED.encode() in (SqliteStore(staged / REGISTRY, staged).snapshot() or b"")
        plan = plan_coverage_readset(staged, target)
    envelope = {
        "version": 1,
        "source_revision": "a" * 64,
        "generation": "b" * 32,
        "binary_sha256": SHA256,
        "target": target,
        "analysis_manifest": "c" * 64,
        "verification_digest": hashlib.sha256(b"[]").hexdigest(),
        "readset": [
            {**row, "origin": "source" if row["path"] in tree else "analysis"} for row in plan
        ],
    }
    status, coverage = _call(
        config,
        "rebrew.coverage_report",
        {
            "project_dir": reanalysed["project"],
            "sha256": SHA256,
            "files": files,
            "rebrew_target": target,
            "binary_key": KEY,
            "coverage_input": envelope,
            "coverage_input_digest": coverage_input_digest(envelope),
            "verification_records": [],
        },
    )
    assert status == 200, coverage
    assert APPLIED in json.dumps(coverage["report"])

    tree_refs = [row for row in files if row["path"] in tree]
    source_manifest = json.dumps(
        {
            "complete": True,
            "exclusions": [],
            "files": [{key: row[key] for key in ("digest", "path", "size")} for row in tree_refs],
            "origin": "files",
            "version": 1,
        },
        separators=(",", ":"),
    )
    analysis_files = _refs(config, _captured(capture))
    keys = {row["path"]: row["key"] for row in analysis_files}
    analysis_manifest = json.dumps(
        {
            "version": 3,
            "binary_sha256": SHA256,
            "target": target,
            **{key: capture[key] for key in ("inventory_path", "report_path") if key in capture},
            "metadata": capture["metadata"],
            "entries": [
                {
                    **{key: entry[key] for key in ("path", "kind")},
                    **({"role": entry["role"]} if entry.get("role") else {}),
                    "size": entry["size"],
                    "digest": entry["digest"],
                    **({"object_key": keys[entry["path"]]} if entry["kind"] == "file" else {}),
                }
                for entry in capture["entries"]
            ],
        },
        separators=(",", ":"),
    )
    registries: list[bytes] = []

    def decompile(_backend: str, binary: Path, va: int, root: Path) -> tuple[str, str]:
        assert binary.resolve().is_relative_to(root)
        registries.append(SqliteStore(root / REGISTRY, root).snapshot() or b"")
        return f"void fcn_{va:08x}(void) {{}}\n", "kuna"

    with monkeypatch.context() as patch:
        patch.setattr("rebrew.decompiler.fetch_decompilation", decompile)
        status, named = _call(
            config,
            "rebrew.decompile_snapshot",
            {
                "project_dir": reanalysed["project"],
                "sha256": SHA256,
                "va": RENAMED_VA,
                "backend": "kuna",
                "rebrew_target": target,
                "source_revision": "source-head",
                "source_snapshot_sha256": hashlib.sha256(source_manifest.encode()).hexdigest(),
                "source_manifest": source_manifest,
                "files": tree_refs,
                "generation": "a" * 32,
                "analysis_manifest_sha256": hashlib.sha256(analysis_manifest.encode()).hexdigest(),
                "analysis_manifest": analysis_manifest,
                "analysis_files": analysis_files,
                "binary_key": KEY,
                "attested_registry_digest": hashlib.sha256(tree[DATABASE_FILENAME]).hexdigest(),
            },
        )
    assert status == 200, named
    assert len(registries) == 1 and APPLIED.encode() in registries[0]

    def verify(arguments: list[str], root: Path, *args: Any, **kwargs: Any) -> dict[str, Any]:
        from typer.testing import CliRunner

        from rebrew.compiler import compile as compiler
        from rebrew.verify import app

        def compare(
            cfg: Any, source: Path, symbol: str, target_bytes: bytes, *rest: Any, **named: Any
        ) -> Any:
            assert cfg.metadata_backend == "sqlite"
            return compiler.CompareResult(
                matched=True,
                status="EXACT",
                match_percent=100.0,
                delta=0,
                obj_bytes=target_bytes,
                reloc_offsets=[],
                match_count=len(target_bytes),
            )

        assert arguments[0] == "verify" and "--no-promote" in arguments
        with monkeypatch.context() as patch:
            patch.setattr(compiler, "precompile_batch", lambda *a, **k: {})
            patch.setattr(compiler, "compile_and_compare", compare)
            result = CliRunner().invoke(
                app, [*arguments[1:], "--root", str(root), "--jobs", "1", "--no-cache"]
            )
        assert result.exit_code == 0, (result.output, result.exception)
        report: dict[str, Any] = json.loads(result.stdout)
        return report

    with monkeypatch.context() as patch:
        patch.setenv("REBREW_RECOMPILE_URL", "http://127.0.0.1:1")
        patch.setattr(ops, "run_rebrew", verify)
        verified = ops.verify_target(
            config,
            ops.VerifyTargetRequest(
                project_dir=reanalysed["project"],
                sha256=SHA256,
                no_promote=True,
                files=retained,
                rebrew_target=target,
                binary_key=KEY,
            ),
        )
    assert verified["summary"]["exact"] == 2
    assert APPLIED in json.dumps(verified)


def test_carry_moves_a_toml_target_with_applied_names_to_sqlite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    filestore, workspace = _worker_dirs(tmp_path)
    config = WorkerConfig(filestore.resolve(), workspace.resolve())
    tree = _v1_target_with_applied_name(config)

    # Re-analysis returns a SQLite capture, which the TOML tree cannot read.
    with monkeypatch.context() as patch:
        patch.setattr(ops, "_run_intake", _with_fresh_data("fresh"))
        reanalysed = _analyse(config)
    capture = reanalysed["analysis_capture"]
    assert capture["version"] == 3
    unread = [FlagSearchFile(**row) for row in _refs(config, _merged(capture, tree))]
    with (
        pytest.raises(ops.OpsError),
        ops.retained_target_snapshot(config, unread, capture["target"], SHA256, KEY, ""),
    ):
        pytest.fail("a TOML target read a SQLite capture")

    status, reply = _carry(config, tree, capture, REGISTRY)
    assert status == 200, reply
    carried = _applied_files(reply)
    assert set(carried) == {CONFIG, DATABASE_FILENAME}
    assert b'backend = "sqlite"' in carried[CONFIG]
    documents = _documents(carried[DATABASE_FILENAME], tmp_path / "carried")
    fresh = _documents(_captured(capture)[DATABASE_FILENAME], tmp_path / "fresh")
    assert documents[REGISTRY] == tree[REGISTRY]
    assert {p: d for p, d in documents.items() if p != REGISTRY} == {
        p: d for p, d in fresh.items() if p != REGISTRY
    }
    assert b"fresh" in documents["rebrew-data.toml"]
    assert reply["remove"] == [REGISTRY]
    assert reply["metadata"] == {
        "files": [
            {
                "path": DATABASE_FILENAME,
                "sha256": hashlib.sha256(carried[DATABASE_FILENAME]).hexdigest(),
            }
        ],
        "documents": [
            {"path": path, "logical_sha256": hashlib.sha256(documents[path]).hexdigest()}
            for path in sorted(documents)
        ],
    }

    migrated = {path: data for path, data in tree.items() if path != REGISTRY} | carried
    _read_names(config, reanalysed, migrated, monkeypatch)


def test_carry_keeps_an_attested_store_on_a_new_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    filestore, workspace = _worker_dirs(tmp_path)
    config = WorkerConfig(filestore.resolve(), workspace.resolve())
    tree = _v1_target_with_applied_name(config)
    first = _analyse(config)
    status, reply = _carry(config, tree, first["analysis_capture"], REGISTRY)
    assert status == 200, reply
    sqlite_tree = {path: data for path, data in tree.items() if path != REGISTRY}
    sqlite_tree |= _applied_files(reply)

    # A later re-analysis brings a changed data document; the attested store keeps the applied rows.
    with monkeypatch.context() as patch:
        patch.setattr(ops, "_run_intake", _with_fresh_data("later"))
        reanalysed = _analyse(config)
    capture = reanalysed["analysis_capture"]
    status, reply = _carry(config, sqlite_tree, capture, DATABASE_FILENAME)
    assert status == 200, reply
    carried = _applied_files(reply)
    assert carried[CONFIG] == sqlite_tree[CONFIG] and reply["remove"] == []
    documents = _documents(carried[DATABASE_FILENAME], tmp_path / "carried")
    assert documents[REGISTRY] == tree[REGISTRY]
    assert b"later" in documents["rebrew-data.toml"]
    _read_names(config, reanalysed, sqlite_tree | carried, monkeypatch)


def test_carry_of_a_toml_target_without_applied_proposals_moves_only_its_config(
    tmp_path: Path,
) -> None:
    filestore, workspace = _worker_dirs(tmp_path)
    config = WorkerConfig(filestore.resolve(), workspace.resolve())
    tree = _v1_target_with_applied_name(config)
    capture = _analyse(config)["analysis_capture"]
    status, reply = _carry(config, tree, capture, "")
    assert status == 200, reply
    carried = _applied_files(reply)
    assert set(carried) == {CONFIG} and reply["remove"] == []
    assert b'backend = "sqlite"' in carried[CONFIG]
    assert reply["metadata"] == capture["metadata"]


@pytest.mark.parametrize(
    ("damage", "detail"),
    [
        (
            "registry-backend",
            f"invalid metadata set: {DATABASE_FILENAME} is not read by this project's"
            " toml metadata",
        ),
        (
            "config-routes",
            "invalid metadata set: metadata requires one local backend, toml or sqlite",
        ),
        ("no-functions", f"invalid metadata set: carried metadata holds no {REGISTRY}"),
    ],
)
def test_carry_refuses_inconsistent_inputs(tmp_path: Path, damage: str, detail: str) -> None:
    import sqlite3

    filestore, workspace = _worker_dirs(tmp_path)
    config = WorkerConfig(filestore.resolve(), workspace.resolve())
    tree = _v1_target_with_applied_name(config)
    capture = _analyse(config)["analysis_capture"]
    registry = REGISTRY
    if damage == "registry-backend":
        # A TOML config does not read an attested SQLite store.
        tree[DATABASE_FILENAME] = _captured(capture)[DATABASE_FILENAME]
        registry = DATABASE_FILENAME
    elif damage == "config-routes":
        tree[CONFIG] += b'\n[metadata]\nread_backends = ["sqlite", "toml"]\n'
    else:
        database = tmp_path / DATABASE_FILENAME
        database.write_bytes(_captured(capture)[DATABASE_FILENAME])
        with sqlite3.connect(database) as connection:
            connection.execute("DELETE FROM metadata_documents WHERE path = ?", (REGISTRY,))
        connection.close()
        for entry in capture["entries"]:
            if entry["path"] == DATABASE_FILENAME:
                entry["data"] = base64.b64encode(database.read_bytes()).decode("ascii")
        # The target published no registry to carry in its place.
        registry = ""
    status, reply = _carry(config, tree, capture, registry)
    assert (status, reply["detail"]) == (400, detail)
