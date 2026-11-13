"""Fresh SQLite capture and retained snapshots preserve producer metadata."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest
from test_analysis_capture_inventory import _capture
from test_ops import BINARY, KEY, SHA256, _store, _worker_dirs

import rebrew.metadata_transfer as transfer
import rebrew.ops as ops
from rebrew.config import load_config
from rebrew.coverage_project import coverage_inputs
from rebrew.metadata.functions import record_function_rows
from rebrew.metadata.sqlite import DATABASE_FILENAME, SqliteStore
from rebrew.metadata.storage import project_metadata_stores
from rebrew.ops import FlagSearchFile, WorkerConfig


def _verify_cli(
    root: Path, arguments: list[str], monkeypatch: pytest.MonkeyPatch
) -> dict[str, Any]:
    """Run the real whole-target verifier with only the compiler boundary doubled."""
    from typer.testing import CliRunner

    from rebrew.compiler import compile as compiler
    from rebrew.verify import app

    compiled: list[int] = []

    def compare(
        cfg: Any, source: Path, symbol: str, target: bytes, *args: Any, **kwargs: Any
    ) -> Any:
        assert cfg.metadata_backend == "sqlite" and source.is_file()
        compiled.append(kwargs["section_va"])
        return compiler.CompareResult(
            matched=True,
            status="EXACT",
            match_percent=100.0,
            delta=0,
            obj_bytes=target,
            reloc_offsets=[],
            match_count=len(target),
        )

    with monkeypatch.context() as patch:
        patch.setattr(compiler, "precompile_batch", lambda *args, **kwargs: {})
        patch.setattr(compiler, "compile_and_compare", compare)
        result = CliRunner().invoke(
            app, [*arguments, "--root", str(root), "--jobs", "1", "--no-cache"]
        )
    assert result.exit_code == 0, (result.output, result.exception)
    assert set(compiled) == {0x401000, 0x401010}
    report: dict[str, Any] = json.loads(result.stdout)
    return report


def test_fresh_capture_has_verified_self_contained_sqlite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    intake = ops._run_intake
    migrate = transfer.migrate_metadata
    calls: list[dict[str, Any]] = []
    original = b""
    expected_documents: dict[str, str | None] = {}

    def seed(binary: Path, root: Path, target: str) -> Any:
        nonlocal original, expected_documents
        result = intake(binary, root, target)
        cfg = load_config(root, target=target)
        record_function_rows(
            cfg.metadata_dir,
            [
                {
                    "module": "MINI",
                    "va": 0x500000 + index * 16,
                    "identity": {"name": f"synthetic_function_{index:05d}"},
                    "fields": {
                        "size": 16,
                        "blocker": f"Synthetic function {index:05d}: recover argument types, control flow and data references before compiling the implementation.",
                    },
                }
                for index in range(6144)
            ],
            updated_by="intake",
        )
        original = (cfg.metadata_dir / "rebrew-functions.toml").read_bytes()
        assert 1024 * 1024 < len(original) < ops.MAX_READSET_FILE_BYTES
        expected_documents = {
            store.path.relative_to(root).as_posix(): store.digest()
            for store in project_metadata_stores(root, recursive=True)
        }
        return result

    def observe(cfg: Any, backend: str, **kwargs: Any) -> dict[str, Any]:
        report = migrate(cfg, backend, **kwargs)
        calls.append({"backend": backend, **kwargs, "report": report})
        assert (cfg.metadata_dir / "rebrew-functions.toml").read_bytes() == original
        return report

    monkeypatch.setattr(ops, "_run_intake", seed)
    monkeypatch.setattr(transfer, "migrate_metadata", observe)
    capture, report = _capture(tmp_path)
    assert capture["version"] == 2
    assert len(calls) == 2
    assert calls[0]["backend"] == calls[1]["backend"] == "sqlite"
    assert calls[0]["dry_run"] is True
    assert calls[1]["expected_digest"] == calls[0]["report"]["input_digest"]
    descriptor = capture["metadata"]
    assert descriptor == {
        "backend": "sqlite",
        "path": DATABASE_FILENAME,
        "documents": [
            {"path": path, "logical_sha256": expected_documents[path]}
            for path in sorted(expected_documents)
        ],
        "migration_input_digest": calls[0]["report"]["input_digest"],
    }
    assert re.fullmatch(r"[0-9a-f]{64}", descriptor["migration_input_digest"])
    (entry,) = [item for item in capture["entries"] if item["path"] == DATABASE_FILENAME]
    payload = base64.b64decode(entry["data"], validate=True)
    assert len(payload) == entry["size"] > 1024 * 1024
    assert hashlib.sha256(payload).hexdigest() == entry["digest"]
    assert entry["kind"] == "file" and entry["role"] == "analysis"
    assert not any(
        item["kind"] != "absent" and item["path"].endswith(("-journal", "-wal", "-shm"))
        for item in capture["entries"]
    )
    staged = tmp_path / "standalone"
    staged.mkdir()
    (staged / DATABASE_FILENAME).write_bytes(payload)
    store = SqliteStore(staged / "rebrew-functions.toml", staged)
    assert store.snapshot() == original
    assert store.read("metadata")["MINI.0x00500000"]["updated_by"] == "intake"
    assert report["targets"][0]["name"] == "mini"
    files = tmp_path / "files"
    workspace = tmp_path / "workspace"
    live = workspace / "project"
    live.mkdir()
    retained = []
    for captured in capture["entries"]:
        if captured["kind"] != "file":
            continue
        data = base64.b64decode(captured["data"], validate=True)
        digest, key = _store(files, data)
        retained.append(FlagSearchFile(captured["path"], digest, len(data), key))
        if captured["path"] == "rebrew-project.toml":
            (live / captured["path"]).write_bytes(data)

    def verify(arguments: list[str], root: Path, *args: Any, **kwargs: Any) -> dict[str, Any]:
        assert arguments[0] == "verify" and "--no-promote" in arguments
        return _verify_cli(root, arguments[1:], monkeypatch)

    monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://127.0.0.1:1")
    monkeypatch.setattr(ops, "run_rebrew", verify)
    verified = ops.verify_target(
        WorkerConfig(files.resolve(), workspace.resolve()),
        ops.VerifyTargetRequest(
            project_dir=str(live.resolve()),
            sha256=SHA256,
            no_promote=True,
            files=retained,
            rebrew_target="mini",
            binary_key=KEY,
        ),
    )
    assert verified["summary"]["exact"] == 2


def _sqlite_manifest(tmp_path: Path) -> tuple[WorkerConfig, list[FlagSearchFile], Path]:
    files, workspace = _worker_dirs(tmp_path)
    project = tmp_path / "producer"
    project.mkdir()
    ops._run_intake(BINARY, project, "mini")
    cfg = load_config(project, target="mini")
    original = (cfg.metadata_dir / "rebrew-functions.toml").read_bytes()
    sources = {path: path.read_bytes() for path in cfg.reversed_dir.rglob("*.c")}
    preview = transfer.migrate_metadata(cfg, "sqlite", dry_run=True)
    transfer.migrate_metadata(cfg, "sqlite", expected_digest=preview["input_digest"])
    assert (cfg.metadata_dir / "rebrew-functions.toml").read_bytes() == original
    assert all(path.read_bytes() == data for path, data in sources.items())
    cfg = load_config(project, target="mini")
    entries = []
    for item in coverage_inputs(cfg):
        path = Path(item[0])
        if not path.is_file() or path == cfg.target_binary:
            continue
        digest, key = _store(files, path.read_bytes())
        entries.append(
            FlagSearchFile(path.relative_to(project).as_posix(), digest, path.stat().st_size, key)
        )
    _store(files, BINARY.read_bytes())
    return WorkerConfig(files.resolve(), workspace.resolve()), entries, project


def test_retained_sqlite_snapshot_is_readable_and_unchanged(tmp_path: Path) -> None:
    config, entries, project = _sqlite_manifest(tmp_path)
    original_toml = (project / "rebrew-functions.toml").read_bytes()
    payload = (project / DATABASE_FILENAME).read_bytes()
    with ops.retained_target_snapshot(config, entries, "mini", SHA256, KEY, "") as root:
        assert load_config(root, target="mini").metadata_backend == "sqlite"
        assert ops.project_report(root, None)["targets"][0]["sha256"] == SHA256
        assert SqliteStore(root / "rebrew-functions.toml", root).snapshot() == original_toml
        assert (root / DATABASE_FILENAME).read_bytes() == payload
    assert (project / DATABASE_FILENAME).read_bytes() == payload
    assert (project / "rebrew-functions.toml").read_bytes() == original_toml


@pytest.mark.parametrize(
    "damage",
    ["missing", "digest", "schema", "unknown-document", "journal", "wal", "routed", "pgsql"],
)
def test_retained_sqlite_refuses_invalid_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    import sqlite3

    import tomlkit

    import rebrew.metadata.pgsql as pgsql

    config, entries, project = _sqlite_manifest(tmp_path)
    path = DATABASE_FILENAME
    if damage == "missing":
        entries = [entry for entry in entries if entry.path != path]
    else:
        payload = (project / path).read_bytes()
        if damage in {"schema", "unknown-document"}:
            db = project / path
            db.chmod(0o644)
            with sqlite3.connect(db) as connection:
                if damage == "schema":
                    connection.execute("PRAGMA user_version = 1")
                else:
                    connection.execute(
                        "INSERT INTO metadata_documents(path, revision, content) VALUES (?, 1, ?)",
                        ("src/game.c", "value = 1\n"),
                    )
            payload = db.read_bytes()
        elif damage in {"journal", "wal"}:
            path += "-journal" if damage == "journal" else "-wal"
            payload = b"not a committed database"
        elif damage in {"routed", "pgsql"}:
            path = "rebrew-project.toml"
            doc = tomlkit.parse((project / path).read_text())
            doc["metadata"] = (
                {"read_backends": ["sqlite", "toml"]}
                if damage == "routed"
                else {
                    "backend": "pgsql",
                    "pgsql": {"dsn": "postgresql://127.0.0.1:1/test", "project": "fixture"},
                }
            )
            payload = tomlkit.dumps(doc).encode()
        assert config.filestore is not None
        digest, key = _store(config.filestore, payload)
        entries = [entry for entry in entries if entry.path != path]
        entries.append(
            FlagSearchFile(path, "0" * 64 if damage == "digest" else digest, len(payload), key)
        )

    def forbidden_driver() -> None:
        pytest.fail("a retained snapshot must not open PostgreSQL")

    monkeypatch.setattr(pgsql, "_driver", forbidden_driver)
    with (
        pytest.raises(ops.OpsError),
        ops.retained_target_snapshot(config, entries, "mini", SHA256, KEY, ""),
    ):
        pytest.fail("invalid retained metadata was accepted")


@pytest.mark.parametrize("backend", ["sqlite", "toml"])
def test_retained_target_refuses_the_registry_its_backend_ignores(
    tmp_path: Path, backend: str
) -> None:
    import tomlkit

    config, entries, project = _sqlite_manifest(tmp_path)
    assert config.filestore is not None
    extra = {"rebrew-functions.toml": (project / "rebrew-functions.toml").read_bytes()}
    if backend == "toml":
        doc = tomlkit.parse((project / "rebrew-project.toml").read_text())
        del doc["metadata"]
        extra["rebrew-project.toml"] = tomlkit.dumps(doc).encode()
    entries = [entry for entry in entries if entry.path not in extra]
    for path, data in extra.items():
        digest, key = _store(config.filestore, data)
        entries.append(FlagSearchFile(path, digest, len(data), key))
    if backend == "toml":
        readable = [entry for entry in entries if entry.path != DATABASE_FILENAME]
        with ops.retained_target_snapshot(config, readable, "mini", SHA256, KEY, "") as root:
            assert load_config(root, target="mini").metadata_backend == "toml"
    ignored = "rebrew-functions.toml" if backend == "sqlite" else DATABASE_FILENAME
    with (
        pytest.raises(ops.OpsError, match=f"carries {ignored}, which its {backend} metadata"),
        ops.retained_target_snapshot(config, entries, "mini", SHA256, KEY, ""),
    ):
        pytest.fail("an unread registry was accepted")


def test_changed_sqlite_metadata_during_retained_read_is_refused(tmp_path: Path) -> None:
    from rebrew.metadata.functions import update_field

    config, entries, _ = _sqlite_manifest(tmp_path)
    with (
        pytest.raises(ops.OpsError, match="snapshot source changed"),
        ops.retained_target_snapshot(config, entries, "mini", SHA256, KEY, "") as root,
    ):
        update_field(root, 0x401000, "blocker", "changed during verification", "MINI")


def test_fresh_capture_stale_migration_never_selects_sqlite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rebrew.metadata.functions import update_field

    migrate = transfer.migrate_metadata
    preview_digest = ""

    def change(cfg: Any, backend: str, **kwargs: Any) -> dict[str, Any]:
        nonlocal preview_digest
        if kwargs.get("dry_run"):
            report = migrate(cfg, backend, **kwargs)
            preview_digest = report["input_digest"]
            update_field(cfg.metadata_dir, 0x401000, "blocker", "changed after preview", "MINI")
            return report
        assert kwargs["expected_digest"] == preview_digest
        sources = {path: path.read_bytes() for path in cfg.reversed_dir.rglob("*.c")}
        try:
            return migrate(cfg, backend, **kwargs)
        finally:
            assert load_config(cfg.root).metadata_backend == "toml"
            assert not (cfg.root / DATABASE_FILENAME).exists()
            assert all(path.read_bytes() == data for path, data in sources.items())

    monkeypatch.setattr(transfer, "migrate_metadata", change)
    with pytest.raises(ops.OpsError, match="metadata inputs changed since preview"):
        _capture(tmp_path)


def test_fresh_capture_refuses_missing_function_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rebrew.metadata.storage import metadata_store

    intake = ops._run_intake

    def missing(binary: Path, root: Path, target: str) -> Any:
        result = intake(binary, root, target)
        metadata_store(root / "rebrew-functions.toml").remove()
        return result

    monkeypatch.setattr(ops, "_run_intake", missing)
    with pytest.raises(ops.OpsError, match="requires function metadata before import"):
        _capture(tmp_path)
