"""Re-analysis of a SQLite project whose function record names no C identifier.

An imported project can hold a record whose ``name`` is free text. The intake's
re-discovery writes a stub for it; the record and the stub must agree afterwards, a
store that already disagrees is repaired, and the project's reads keep answering.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import io
import json
import logging
import shutil
import sys
import threading
import zipfile
from typing import Any
lazy from collections.abc import Iterator
lazy from pathlib import Path

import pytest
from test_ops import _analyse_request, _copy_analysed
from test_ops import fresh_analysis as fresh_analysis

from rebrew.config import load_config
from rebrew.metadata.document import load_metadata_for_write
from rebrew.metadata.functions import (
    METADATA_FILENAME,
    clear_identity_fields,
    clear_metadata_cache,
    import_status_history,
    load_metadata,
)
from rebrew.metadata.storage import metadata_store
from rebrew.metadata_transfer import migrate_metadata, migration_input_digest
from rebrew.ops import BINDING_CONFLICT_DETAIL, OPS, SKIPPED_RECORD_OPS, WorkerConfig, dispatch

MODULE = "MINI"
VA = 0x401010
KEY = f"{MODULE}.0x{VA:08x}"
PLACEHOLDER = f"fcn_{VA:08x}"
FREE_TEXT = "lib_cont (split from a merged entry; round 1)"
HISTORY = {
    "old_status": "EXACT",
    "new_status": "UNKNOWN",
    "changed_at": "2026-01-02T03:04:05+00:00",
    "updated_by": "",
}


def _analyse(config: WorkerConfig) -> dict[str, Any]:
    status, raw = dispatch(config, "rebrew.analyse", json.dumps(_analyse_request()).encode())
    reply: dict[str, Any] = json.loads(raw)
    assert status == 200, reply
    return reply


def _store_name(metadata_dir: Path, name: str) -> None:
    """Write *name* into the record as an older engine did, past today's identity writer."""
    path = metadata_dir / METADATA_FILENAME
    document = load_metadata_for_write(path, "metadata")
    document[KEY]["name"] = name
    metadata_store(path).write(document, "metadata")
    clear_metadata_cache()


#: ``(worker root, project path relative to it)`` of a session-built project.
Template = tuple[Path, Path]


@pytest.fixture(scope="module")
def _analysed(
    tmp_path_factory: pytest.TempPathFactory, fresh_analysis: tuple[Path, dict[str, Any]]
) -> Template:
    """An analysed project moved to SQLite, whose 0x401010 record has comparison history.

    Built once per session from the shared analysis. Tests work on
    :func:`_sqlite_project`'s copy.
    """
    from session_cache import build_once

    def build(root: Path) -> str:
        _, project = _copy_analysed(fresh_analysis, root)
        cfg = load_config(project, target="mini")
        migrate_metadata(cfg, "sqlite", expected_digest=migration_input_digest(cfg, "sqlite"))
        cfg = load_config(project, target="mini")
        import_status_history(cfg.metadata_dir, MODULE, [{"va": VA, **HISTORY}])
        return project.resolve().relative_to(root.resolve()).as_posix()

    root, rel = build_once(tmp_path_factory, "reanalysis-sqlite-project", build)
    return root, Path(rel)


def _sqlite_project(analysed: Template, root: Path) -> tuple[WorkerConfig, Path, Any]:
    """A worker over a copy of *analysed* at *root*, the copy's project and its config.

    The ``.rebrew`` caches are left behind; they name the template's paths.
    """
    template, rel = analysed
    shutil.copytree(template, root, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".rebrew"))
    clear_metadata_cache()
    root = root.resolve()
    project = root / rel
    cfg = load_config(project, target="mini")
    assert cfg.metadata_backend == "sqlite"
    return WorkerConfig(root / "files", root / "workspace"), project, cfg


def _unbound_free_text(analysed: Template, root: Path) -> tuple[WorkerConfig, Path]:
    """Before production's re-analysis: the record names free text and has no source."""
    config, project, cfg = _sqlite_project(analysed, root)
    (cfg.reversed_dir / f"{PLACEHOLDER}.c").unlink()
    clear_identity_fields(cfg.metadata_dir, VA, MODULE, "file", "symbol", "kind")
    _store_name(cfg.metadata_dir, FREE_TEXT)
    return config, project


def _disagreeing_stub(analysed: Template, root: Path) -> tuple[WorkerConfig, Path]:
    """After production's re-analysis: the stub defines the placeholder, the record names free text."""
    config, project, cfg = _sqlite_project(analysed, root)
    _store_name(cfg.metadata_dir, FREE_TEXT)
    return config, project


def _record(project: Path) -> dict[str, Any]:
    clear_metadata_cache()
    cfg = load_config(project, target="mini")
    return dict(load_metadata(cfg.metadata_dir)[(MODULE, VA)])


def _stub_name(project: Path) -> str:
    cfg = load_config(project, target="mini")
    text = (cfg.reversed_dir / f"{PLACEHOLDER}.c").read_text()
    (line,) = [line for line in text.splitlines() if line.startswith("void ")]
    return line.removeprefix("void ").split("(")[0]


def _assert_consistent(project: Path) -> dict[str, Any]:
    record = _record(project)
    assert _stub_name(project) == PLACEHOLDER
    assert (record["file"], record["symbol"], record["name"], record["kind"]) == (
        f"src/mini/{PLACEHOLDER}.c",
        f"_{PLACEHOLDER}",
        PLACEHOLDER,
        "STUB",
    )
    # The earlier text is kept in the note, and the comparison history stays.
    assert record["note"] == f"earlier name: {FREE_TEXT}"
    assert [dict(event) for event in record["status_history"]] == [HISTORY]
    return record


def test_a_tests_project_is_a_copy_and_runs_no_op(
    tmp_path: Path,
    _analysed: Template,
    fresh_analysis: tuple[Path, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Building private inputs from the shared analysis requires no dispatch."""

    def no_op(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError(f"project setup ran an op: {args[1]}")

    monkeypatch.setattr(sys.modules[__name__], "dispatch", no_op)
    config, first = _disagreeing_stub(_analysed, tmp_path / "a")
    _, second = _unbound_free_text(_analysed, tmp_path / "b")
    _make_snapshot_fields(config, first, fresh_analysis[1]["analysis_capture"])
    # A write to one copy reaches neither the other nor the template.
    assert (first / "src/mini" / f"{PLACEHOLDER}.c").is_file()
    assert not (second / "src/mini" / f"{PLACEHOLDER}.c").exists()
    template, rel = _analysed
    assert _record(template / rel)["name"] == PLACEHOLDER


def test_reanalysis_leaves_a_record_its_stub_agrees_with(
    tmp_path: Path, _analysed: Template
) -> None:
    config, project = _unbound_free_text(_analysed, tmp_path)
    _analyse(config)
    _assert_consistent(project)


def test_reanalysis_reports_an_unrepaired_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _analysed: Template
) -> None:
    config, project = _disagreeing_stub(_analysed, tmp_path)
    cfg = load_config(project, target="mini")
    _store_name(cfg.metadata_dir, "wrong_handler")
    monkeypatch.setenv("REBREW_OPS_STRICT_REPLIES", "1")

    assert _analyse(config).get("skipped_records") == {
        "count": 1,
        "keys": [KEY],
        "truncated": False,
    }
    assert _record(project)["name"] == "wrong_handler"


def test_reanalysis_keeps_an_identifier_name_in_the_stub(
    tmp_path: Path, _analysed: Template
) -> None:
    config, project, cfg = _sqlite_project(_analysed, tmp_path)
    (cfg.reversed_dir / f"{PLACEHOLDER}.c").unlink()
    clear_identity_fields(cfg.metadata_dir, VA, MODULE, "file", "symbol", "kind")
    _store_name(cfg.metadata_dir, "lib_cont")
    _analyse(config)
    record = _record(project)
    assert _stub_name(project) == "lib_cont"
    assert (record["name"], record["symbol"]) == ("lib_cont", "_lib_cont")
    assert "note" not in record


def test_reanalysis_repairs_a_record_its_stub_disagrees_with(
    tmp_path: Path, _analysed: Template
) -> None:
    from rebrew.metadata.bindings import binding_conflicts

    config, project = _disagreeing_stub(_analysed, tmp_path)
    with binding_conflicts() as skipped:
        assert "skipped_records" not in _analyse(config)
    # The intake repairs the record before it reads the bindings: no read skipped it.
    assert skipped == set()
    repaired = _assert_consistent(project)
    # A second run finds nothing to repair and changes nothing.
    with binding_conflicts() as second_skipped:
        _analyse(config)
    assert second_skipped == set()
    assert _record(project) == repaired


def test_reanalysis_repairs_the_anchor_for_its_own_module(
    tmp_path: Path, _analysed: Template
) -> None:
    from rebrew.metadata.bindings import binding_conflicts, read_source_bindings

    config, project = _disagreeing_stub(_analysed, tmp_path)
    cfg = load_config(project, target="mini")
    source = cfg.reversed_dir / f"{PLACEHOLDER}.c"
    source.write_text(
        f"/* ADDRESS: OTHER 0x{VA:08x} */\nvoid other_handler(void) {{}}\n\n"
        + source.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    with binding_conflicts() as skipped:
        _analyse(config)
    record = _record(project)
    assert (record["name"], record["symbol"]) == (PLACEHOLDER, f"_{PLACEHOLDER}")
    assert record["note"] == f"earlier name: {FREE_TEXT}"
    assert skipped == set()
    [binding] = read_source_bindings(source, target_name=MODULE, metadata_dir=cfg.metadata_dir)
    assert binding.va == VA
    assert binding.name == PLACEHOLDER


@pytest.mark.parametrize("op", ["rebrew.data_list", "rebrew.identify_library"])
def test_project_reads_skip_a_disagreeing_record(
    tmp_path: Path, _analysed: Template, caplog: pytest.LogCaptureFixture, op: str
) -> None:
    config, project = _disagreeing_stub(_analysed, tmp_path)
    with caplog.at_level(logging.WARNING):
        status, raw = dispatch(config, op, json.dumps({"project_dir": str(project)}).encode())
    assert status == 200, json.loads(raw)
    # The reply says which records it left out, by key, never by name.
    assert json.loads(raw)["skipped_records"] == {"count": 1, "keys": [KEY], "truncated": False}
    if op == "rebrew.identify_library":
        # Logged in process: once, by the record's key, never its text.
        skipped = [r.getMessage() for r in caplog.records if KEY in r.getMessage()]
        assert len(skipped) == 1
        assert FREE_TEXT not in caplog.text
    # The read wrote nothing over the skipped record.
    assert _record(project)["name"] == FREE_TEXT


def test_doctor_reports_a_disagreeing_record(tmp_path: Path, _analysed: Template) -> None:
    from rebrew.doctor import check_function_bindings

    _, project = _disagreeing_stub(_analysed, tmp_path)
    result = check_function_bindings(load_config(project, target="mini"))
    assert result.status == "warn"
    assert KEY in result.message and FREE_TEXT not in result.message


def _retained_files(config: WorkerConfig, project: Path) -> list[dict[str, Any]]:
    """*project*'s files stored in the worker's filestore, as a retained op's ``files``."""
    from test_ops import _store

    assert config.filestore is not None
    files = []
    for path in sorted(project.rglob("*")):
        relative = path.relative_to(project).as_posix()
        if not path.is_file() or relative.split("/")[0] in {".rebrew", "original"}:
            continue
        if path.suffix == ".toml" and path.name != "rebrew-project.toml":
            continue  # the TOML documents the migration to SQLite retained
        digest, key = _store(config.filestore, path.read_bytes())
        files.append({"path": relative, "digest": digest, "size": path.stat().st_size, "key": key})
    return files


def test_a_write_touching_a_disagreeing_record_refuses_as_invalid_project(
    tmp_path: Path, _analysed: Template
) -> None:
    from test_ops import KEY as BINARY_KEY
    from test_ops import SHA256

    config, project = _disagreeing_stub(_analysed, tmp_path)
    request = {
        "files": _retained_files(config, project),
        "rebrew_target": "mini",
        "sha256": SHA256,
        "binary_key": BINARY_KEY,
        "operation": "rename",
        "kind": "function",
        "old_name": f"0x{VA:x}",
        "new_name": "renamed",
    }
    status, raw = dispatch(config, "rebrew.retained_source_operation", json.dumps(request).encode())
    assert (status, json.loads(raw)) == (
        400,
        {
            "error": "invalid-project-config",
            "status": 400,
            "detail": BINDING_CONFLICT_DETAIL,
        },
    )
    assert _record(project)["name"] == FREE_TEXT


@pytest.mark.parametrize("op", ["rebrew.data_list", "rebrew.identify_library"])
def test_a_clean_projects_read_names_no_skipped_record(
    tmp_path: Path, _analysed: Template, op: str
) -> None:
    config, project, _cfg = _sqlite_project(_analysed, tmp_path)
    status, raw = dispatch(config, op, json.dumps({"project_dir": str(project)}).encode())
    assert status == 200, json.loads(raw)
    assert "skipped_records" not in json.loads(raw)


def test_skipped_records_past_the_bound_keep_their_count() -> None:
    from rebrew.ops import MAX_SKIPPED_RECORD_KEYS, _skipped_records

    skipped = {(MODULE, 0x401000 + 16 * i) for i in range(MAX_SKIPPED_RECORD_KEYS + 3)}
    reply = _skipped_records(skipped)
    assert reply["count"] == MAX_SKIPPED_RECORD_KEYS + 3 and reply["truncated"] is True
    assert (
        reply["keys"]
        == sorted(f"{MODULE}.0x{va:08x}" for _m, va in skipped)[:MAX_SKIPPED_RECORD_KEYS]
    )
    assert _skipped_records({(MODULE, VA)}) == {"count": 1, "keys": [KEY], "truncated": False}


def test_note_skipped_records_fills_every_open_collector_from_a_generator(
    tmp_path: Path, _analysed: Template
) -> None:
    from rebrew.metadata.bindings import binding_conflicts, note_skipped_records

    with binding_conflicts() as outer, binding_conflicts() as inner:
        note_skipped_records(item for item in [(MODULE, VA)])
    assert outer == inner == {(MODULE, VA)}

    config, project = _disagreeing_stub(_analysed, tmp_path)
    with binding_conflicts() as caller:
        status, raw = dispatch(
            config, "rebrew.data_list", json.dumps({"project_dir": str(project)}).encode()
        )
    assert status == 200
    assert caller == {(MODULE, VA)}
    assert json.loads(raw)["skipped_records"] == {"count": 1, "keys": [KEY], "truncated": False}


def test_undeclared_skipped_records_guard(
    tmp_path: Path,
    _analysed: Template,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An op outside ``SKIPPED_RECORD_OPS`` that skips a record fails under strict replies."""
    from rebrew import ops

    config, project = _disagreeing_stub(_analysed, tmp_path)
    monkeypatch.setattr(ops, "SKIPPED_RECORD_OPS", ops.SKIPPED_RECORD_OPS - {"rebrew.data_list"})
    body = json.dumps({"project_dir": str(project)}).encode()

    monkeypatch.setenv("REBREW_OPS_STRICT_REPLIES", "1")
    status, raw = dispatch(config, "rebrew.data_list", body)
    assert status == 500
    assert json.loads(raw)["error"] == "engine-error"

    monkeypatch.setenv("REBREW_OPS_STRICT_REPLIES", "0")
    with caplog.at_level(logging.WARNING):
        status, raw = dispatch(config, "rebrew.data_list", body)
    assert status == 200
    assert "skipped_records" not in json.loads(raw)
    assert any(
        "skipped records outside SKIPPED_RECORD_OPS" in r.getMessage() for r in caplog.records
    )


@pytest.fixture(scope="module")
def _contradicted_template(
    tmp_path_factory: pytest.TempPathFactory, _analysed: Template
) -> tuple[Path, Path]:
    from session_cache import build_once

    def build(root: Path) -> str:
        _cfg, project = _disagreeing_stub(_analysed, root)
        return project.resolve().relative_to(root.resolve()).as_posix()

    root, rel = build_once(tmp_path_factory, "contradicted-project-walk", build)
    return root, Path(rel)


@pytest.fixture(scope="module")
def _exact_recompile_url() -> Iterator[str]:
    """Local recompile stub advertising ``msvc-8.0`` and serving an exact ``0x401000`` object."""
    from bin_util import make_coff_obj
    from test_ops import BINARY

    from rebrew.formats.binary_loader import extract_raw_bytes

    target_bytes = extract_raw_bytes(BINARY, 0x401000, 11)
    assert target_bytes is not None
    obj = make_coff_obj(
        target_bytes,
        func_symbol="_x",
        extra_funcs=[("_fcn_00401000", 0), ("_end", len(target_bytes))],
    )

    class _Service(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            return

        def _reply(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/api/v1/features":
                self._reply(200, b'{"features": []}', "application/json")
            elif self.path == "/api/v1/compilers":
                self._reply(
                    200,
                    json.dumps([{"id": "msvc-8.0", "execution_status": "admitted"}]).encode(),
                    "application/json",
                )
            elif self.path.startswith("/api/v1/artifacts/"):
                self._reply(200, obj, "application/octet-stream")
            else:
                self._reply(404, b'{"detail": "not found"}', "application/json")

        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            body = {
                "id": "0" * 12,
                "compiler": "msvc-8.0",
                "log": "",
                "status": "ok",
                "artifact_url": "/api/v1/artifacts/000000000000.obj",
            }
            self._reply(200, json.dumps(body).encode(), "application/json")

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Service)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join(30)
        server.server_close()


def _make_toml_archive(config: WorkerConfig, project: Path) -> tuple[str, str]:
    """Zip a TOML copy of *project* (whose 0x401010 record disagrees with its stub) into filestore."""
    from test_ops import _store

    assert config.filestore is not None
    toml_proj = project.parent / "_toml_archive_src"
    shutil.copytree(
        project,
        toml_proj,
        ignore=shutil.ignore_patterns(".rebrew", "rebrew-metadata.sqlite3"),
    )
    project_toml = toml_proj / "rebrew-project.toml"
    project_toml.write_text(
        project_toml.read_text().replace('backend = "sqlite"', 'backend = "toml"')
    )
    cfg = load_config(toml_proj, target="mini")
    _store_name(cfg.metadata_dir, FREE_TEXT)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path in sorted(toml_proj.rglob("*")):
            if path.is_file():
                zf.writestr(path.relative_to(toml_proj).as_posix(), path.read_bytes())
    return _store(config.filestore, buf.getvalue())


def _make_snapshot_fields(
    config: WorkerConfig, project: Path, capture: dict[str, Any]
) -> dict[str, Any]:
    """Build verified capture and source manifests from the shared fresh analysis."""
    from test_ops import KEY as BINARY_KEY
    from test_ops import SHA256, _store

    assert config.filestore is not None
    analysis_entries = []
    analysis_files = []
    source_files = []
    for item in capture["entries"]:
        row = {k: item[k] for k in ("path", "kind")}
        if item.get("role"):
            row["role"] = item["role"]
        row.update(size=item["size"], digest=item["digest"])
        if item["kind"] == "file":
            data = base64.b64decode(item["data"])
            digest, key = _store(config.filestore, data)
            row["object_key"] = key
            ref = {"path": item["path"], "digest": digest, "size": len(data), "key": key}
            analysis_files.append(ref)
            if item.get("role") == "source" or item["path"] == "rebrew-project.toml":
                source_files.append(ref)
        analysis_entries.append(row)
    source_files.sort(key=lambda r: r["path"])
    source_doc = {
        "complete": True,
        "exclusions": [],
        "files": [{k: f[k] for k in ("digest", "path", "size")} for f in source_files],
        "origin": "files",
        "version": 1,
    }
    source_manifest = json.dumps(source_doc, separators=(",", ":")).encode()
    analysis_manifest = json.dumps(
        {
            "version": 3,
            "binary_sha256": SHA256,
            "target": capture["target"],
            **{k: capture[k] for k in ("inventory_path", "report_path") if k in capture},
            "metadata": capture["metadata"],
            "entries": analysis_entries,
        },
        separators=(",", ":"),
    ).encode()
    return {
        "project_dir": str(project),
        "sha256": SHA256,
        "rebrew_target": capture["target"],
        "source_revision": "rev-1",
        "source_snapshot_sha256": hashlib.sha256(source_manifest).hexdigest(),
        "source_manifest": source_manifest.decode(),
        "files": source_files,
        "generation": "a" * 32,
        "analysis_manifest": analysis_manifest.decode(),
        "analysis_manifest_sha256": hashlib.sha256(analysis_manifest).hexdigest(),
        "analysis_files": analysis_files,
        "binary_key": BINARY_KEY,
    }


def _walk_requests(config: WorkerConfig, project: Path, capture: dict[str, Any]) -> dict[str, Any]:
    """Smallest request builder per op in ``OPS`` that reaches its project/input read."""
    from test_ops import KEY as BINARY_KEY
    from test_ops import SHA256, SPLAT_YAML, _binary_file, _store

    assert config.filestore is not None
    cached_files: list[dict[str, Any]] | None = None

    def files() -> list[dict[str, Any]]:
        nonlocal cached_files
        if cached_files is None:
            cached_files = _retained_files(config, project)
        return cached_files

    def pat_file() -> dict[str, Any]:
        digest, key = _store(config.filestore, b"558BEC83EC08 00 0000 0000 :0000 _demo\n---\n")
        return {"sha256": digest, "file": key}

    def lib_file() -> dict[str, Any]:
        digest, key = _store(config.filestore, b"!<arch>\n")
        return {"sha256": digest, "file": key}

    def archive_fields() -> dict[str, Any]:
        digest, key = _make_toml_archive(config, project)
        return {"binary_id": 1, "sha256": SHA256, "archive_sha256": digest, "archive_key": key}

    def src_401000_sha() -> str:
        return hashlib.sha256((project / "src/mini/fcn_00401000.c").read_bytes()).hexdigest()

    return {
        "rebrew.disassemble": lambda: {
            "project_dir": str(project),
            "sha256": SHA256,
            "va": VA,
            "size": 10,
            "format": "asm",
        },
        "rebrew.disassemble_bytes": lambda: {
            "code": base64.b64encode(b"\xc3").decode(),
            "va": VA,
            "arch": "x86_32",
        },
        "rebrew.instruction_listing": lambda: {
            "project_dir": str(project),
            "sha256": SHA256,
            "va": VA,
            "size": 10,
        },
        "rebrew.control_flow_graph": lambda: {
            "project_dir": str(project),
            "sha256": SHA256,
            "va": VA,
        },
        "rebrew.xrefs": lambda: {"project_dir": str(project), "sha256": SHA256, "va": VA},
        "rebrew.call_references": lambda: {"project_dir": str(project)},
        "rebrew.describe": lambda: {"project_dir": str(project), "sha256": SHA256, "va": VA},
        "rebrew.decompile": lambda: {
            "project_dir": str(project),
            "sha256": SHA256,
            "va": VA,
            "backend": "auto",
            "named": True,
        },
        "rebrew.decompile_snapshot": lambda: {
            **_make_snapshot_fields(config, project, capture),
            "va": 0x401000,
            "backend": "kuna",
        },
        "rebrew.identify_library": lambda: {"project_dir": str(project)},
        "rebrew.structs": lambda: {
            "binary_id": 1,
            "project_dir": str(project),
            "decompiler": "auto",
            "limit": 0,
        },
        "rebrew.binary_operand_locations": lambda: {
            "sha256": SHA256,
            "file": BINARY_KEY,
            "functions": [{"va": VA, "size": 10, "locations": [[0, 0]]}],
        },
        "rebrew.binary_function_digests": lambda: {
            "sha256": SHA256,
            "file": BINARY_KEY,
            "functions": [{"va": VA, "size": 10}],
        },
        "rebrew.imports": _binary_file,
        "rebrew.strings": _binary_file,
        "rebrew.fingerprint": _binary_file,
        "rebrew.analyze": _binary_file,
        "rebrew.crypto_scan": _binary_file,
        "rebrew.pe_info": _binary_file,
        "rebrew.identify_compiler": _binary_file,
        "rebrew.library_functions": lib_file,
        "rebrew.splat_parse": lambda: {"config": SPLAT_YAML},
        "rebrew.report": lambda: {
            "binary_id": 1,
            "project_dir": str(project),
            "output_dir": "reports/walk",
        },
        "rebrew.security_scan": lambda: {
            "binary_id": 1,
            "project_dir": str(project),
            "min_severity": "low",
        },
        "rebrew.security_scan_snapshot": lambda: {
            **_make_snapshot_fields(config, project, capture),
            "min_severity": "low",
        },
        "rebrew.analyse": _analyse_request,
        "rebrew.import-project": lambda: {"project_dir": str(project)},
        "rebrew.import_archive": archive_fields,
        "rebrew.project_targets": lambda: {"files": files()},
        "rebrew.metadata_carry": lambda: {"capture": files(), "target": files()},
        "rebrew.metadata_describe": lambda: {"files": files()},
        "rebrew.metadata_diff": lambda: {"before": files(), "after": files()},
        "rebrew.reference_flirt": lambda: {
            "project_dir": str(project),
            "format": "pat",
            "signatures": pat_file(),
            "min_size": 4,
        },
        "rebrew.verify_function": lambda: {
            "project_dir": str(project),
            "source": "src/mini/fcn_00401000.c",
            "no_promote": True,
        },
        "rebrew.apply_candidate": lambda: {
            "project_dir": str(project),
            "source": "src/mini/fcn_00401000.c",
            "source_sha256": src_401000_sha(),
            "candidate": "/* ADDRESS: MINI 0x00401000 */\nvoid fcn_00401000(void) {}\n",
            "va": 0x401000,
            "size": 11,
            "files": files(),
            "rebrew_target": "mini",
            "sha256": SHA256,
            "binary_key": BINARY_KEY,
        },
        "rebrew.verify_target": lambda: {"project_dir": str(project), "no_promote": True},
        "rebrew.build": lambda: {"project_dir": str(project)},
        "rebrew.skeleton": lambda: {"project_dir": str(project), "va": VA},
        "rebrew.coverage_report": lambda: {"project_dir": str(project)},
        "rebrew.flag_search": lambda: {
            "source": "src/mini/fcn_00401000.c",
            "source_sha256": src_401000_sha(),
            "va": 0x401000,
            "files": files(),
            "rebrew_target": "mini",
            "sha256": SHA256,
            "binary_key": BINARY_KEY,
            "compare_toolchains": True,
            "toolchains": "msvc-8.0",
        },
        "rebrew.data_list": lambda: {"project_dir": str(project)},
        "rebrew.data_set": lambda: {
            "project_dir": str(project),
            "va": 0x402000,
            "note": "x",
            "dry_run": True,
        },
        "rebrew.vocabulary": dict,
        "rebrew.release": dict,
        "rebrew.check_cflags": lambda: {"cflags": "/O2"},
        "rebrew.rename_identifier": lambda: {
            "source": "int a(void) { return 0; }\n",
            "renames": [{"old": "a", "new": "b"}],
        },
        "rebrew.retained_source_operation": lambda: {
            "files": files(),
            "rebrew_target": "mini",
            "sha256": SHA256,
            "binary_key": BINARY_KEY,
            "operation": "merge",
            "sources": ["src/mini/fcn_00401000.c", f"src/mini/{PLACEHOLDER}.c"],
            "output": "src/mini/merged.c",
            "dry_run": True,
        },
    }


@pytest.mark.parametrize("op", sorted(OPS))
def test_every_ops_read_of_a_contradicted_project_names_what_it_skipped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _contradicted_template: tuple[Path, Path],
    _exact_recompile_url: str,
    fresh_analysis: tuple[Path, dict[str, Any]],
    op: str,
) -> None:
    """Every op in ``OPS`` either names the skipped record in ``skipped_records`` or skips nothing."""
    from decompiler_engine import offer_decompilers
    from test_ops import _op_schema, _validate

    from rebrew.metadata.bindings import binding_conflicts

    tmpl_root, tmpl_rel = _contradicted_template
    work = tmp_path / "work"
    shutil.copytree(tmpl_root, work, ignore=shutil.ignore_patterns(".rebrew"))
    clear_metadata_cache()
    config = WorkerConfig((work / "files").resolve(), (work / "workspace").resolve())
    project = (work / tmpl_rel).resolve()

    monkeypatch.setenv("REBREW_RECOMPILE_URL", _exact_recompile_url)
    offer_decompilers(monkeypatch, "kuna")
    monkeypatch.setattr(
        "rebrew.decompiler.fetch_decompilation",
        lambda *_a, **_k: ("void fcn_00401010(void) {}\n", "kuna"),
    )

    requests = _walk_requests(config, project, fresh_analysis[1]["analysis_capture"])
    assert set(requests) == set(OPS)

    with binding_conflicts() as skipped:
        status, raw = dispatch(config, op, json.dumps(requests[op]()).encode())
    reply = json.loads(raw)
    assert status == 200, reply
    _validate(_op_schema(op, "response"), reply)
    # Analyse repairs this particular generated stub before reading bindings.
    if op in SKIPPED_RECORD_OPS and op != "rebrew.analyse":
        assert skipped == {(MODULE, VA)}
        assert reply["skipped_records"] == {"count": 1, "keys": [KEY], "truncated": False}
    else:
        assert skipped == set()
        assert "skipped_records" not in reply
