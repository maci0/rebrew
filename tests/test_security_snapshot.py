"""Security scan against the source and analysis receipts, never the live project."""

from __future__ import annotations

import copy
import http.client
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from test_named_snapshot import _digest, _json
from test_named_snapshot import sample as sample
from test_ops import _free_port, _store

from rebrew.ops import OPS, WorkerConfig, dispatch


@pytest.fixture
def scan_request(sample: tuple[WorkerConfig, dict]) -> tuple[WorkerConfig, dict]:
    config, original = sample
    req = copy.deepcopy(original)
    req.pop("va")
    req.pop("backend")
    req["min_severity"] = "low"
    source = b"void vulnerable(char *dst, const char *src) { strcpy(dst, src); }\n"
    digest, key = _store(config.filestore, source)
    req["files"].append(
        {"path": "src/mini/vulnerable.c", "digest": digest, "size": len(source), "key": key}
    )
    req["files"].sort(key=lambda row: row["path"])
    doc = {
        "complete": True,
        "exclusions": [],
        "files": [{k: f[k] for k in ("digest", "path", "size")} for f in req["files"]],
        "origin": "files",
        "version": 1,
    }
    req["source_manifest"] = _json(doc)
    req["source_snapshot_sha256"] = _digest(req["source_manifest"])
    return config, req


def _call(config: WorkerConfig, req: dict) -> tuple[int, dict]:
    status, raw = dispatch(config, "rebrew.security_scan_snapshot", json.dumps(req).encode())
    return status, json.loads(raw)


def test_real_scan_uses_snapshot_and_relative_paths(
    scan_request: tuple[WorkerConfig, dict],
) -> None:
    config, req = scan_request
    live = Path(req["project_dir"]) / "src/mini/live-poison.c"
    live.parent.mkdir(parents=True, exist_ok=True)
    live.write_text("void poison(char *s) { gets(s); }\n")
    status, reply = _call(config, req)
    assert status == 200, reply
    result = reply["result"]
    assert result["root"] == "src/mini"
    assert result["count"] == len(result["findings"]) > 0
    assert any(
        f["rule"] == "unbounded-copy" and f["file"] == "src/mini/vulnerable.c"
        for f in result["findings"]
    )
    assert all(
        not f["file"].startswith("/") and "live-poison" not in f["file"] for f in result["findings"]
    )
    assert all(
        reply[k] == req[k]
        for k in (
            "source_revision",
            "source_snapshot_sha256",
            "generation",
            "analysis_manifest_sha256",
        )
    )
    assert req["project_dir"] not in json.dumps(reply)


def test_severity_filter_and_refusal(scan_request: tuple[WorkerConfig, dict]) -> None:
    config, req = scan_request
    req["min_severity"] = "high"
    status, reply = _call(config, req)
    assert status == 200, reply
    assert reply["result"]["findings"] and all(
        finding["severity"] == "high" for finding in reply["result"]["findings"]
    )
    req["min_severity"] = "unknown"
    status, _ = _call(config, req)
    assert status == 400


def test_real_exec_and_http_transport(scan_request: tuple[WorkerConfig, dict]) -> None:
    config, req = scan_request
    argv = [sys.executable, "-m", "rebrew.app.main", "ops"]
    worker_args = ["--filestore", str(config.filestore), "--workspace", str(config.workspace)]
    body = json.dumps(req).encode()
    result = subprocess.run(
        [*argv, "call", *worker_args, "rebrew.security_scan_snapshot"],
        input=body,
        capture_output=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout
    assert json.loads(result.stdout)["result"]["count"] > 0
    port, token = _free_port(), secrets.token_hex(16)
    process = subprocess.Popen(
        [*argv, "serve", *worker_args, "--port", str(port), "--allowed-hosts", f"127.0.0.1:{port}"],
        env={**os.environ, "REBREW_OPS_TOKEN": token},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 30
        while True:
            assert process.poll() is None and time.monotonic() < deadline
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                time.sleep(0.05)
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
        try:
            connection.request(
                "POST",
                "/rebrew.security_scan_snapshot",
                body,
                {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )
            response = connection.getresponse()
            payload = json.loads(response.read())
            assert response.status == 200 and payload["result"]["count"] > 0, payload
            assert payload["source_snapshot_sha256"] == req["source_snapshot_sha256"]
        finally:
            connection.close()
    finally:
        process.terminate()
        process.wait(timeout=30)


@pytest.mark.parametrize(
    "field", ["source_snapshot_sha256", "analysis_manifest_sha256", "generation"]
)
def test_refuses_mismatched_receipts(scan_request: tuple[WorkerConfig, dict], field: str) -> None:
    config, req = scan_request
    req[field] = "0" * 64
    status, _ = _call(config, req)
    assert status == 400


def test_refuses_changed_source_during_scan(
    scan_request: tuple[WorkerConfig, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    import rebrew.security_scan as scanner

    config, req = scan_request
    original = scanner.scan_paths

    def mutate(paths: list[Path], *, strict: bool = False) -> list[dict]:
        findings = original(paths, strict=strict)
        next(path for path in paths if path.name == "vulnerable.c").write_text("changed")
        return findings

    monkeypatch.setattr(scanner, "scan_paths", mutate)
    status, _ = _call(config, req)
    assert status == 400


def test_refuses_unreadable_source(
    scan_request: tuple[WorkerConfig, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    import rebrew.utils as utils

    config, req = scan_request
    original = utils.read_source_text

    def unreadable(path: Path) -> tuple[str, str]:
        if path.name == "vulnerable.c":
            raise OSError("unreadable")
        return original(path)

    monkeypatch.setattr(utils, "read_source_text", unreadable)
    status, _ = _call(config, req)
    assert status == 400


def test_refuses_parser_disappearing_during_scan(
    scan_request: tuple[WorkerConfig, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    import rebrew.security_scan as scanner

    config, req = scan_request
    original = scanner.get_ts_parser
    calls = 0

    def disappearing():
        nonlocal calls
        calls += 1
        return original() if calls == 1 else None

    monkeypatch.setattr(scanner, "get_ts_parser", disappearing)
    status, _ = _call(config, req)
    assert status != 200


def test_refuses_parser_import_failure_during_scan(
    scan_request: tuple[WorkerConfig, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    import rebrew.security_scan as scanner

    config, req = scan_request

    def unavailable(_text: str):
        raise ImportError("parser missing")

    monkeypatch.setattr(scanner, "parse_c_source", unavailable)
    status, _ = _call(config, req)
    assert status != 200


def test_refuses_unscanned_retained_file(
    scan_request: tuple[WorkerConfig, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    import rebrew.sources as sources

    config, req = scan_request
    monkeypatch.setattr(sources, "iter_sources", lambda *_args: [])
    status, _ = _call(config, req)
    assert status == 400


def test_refuses_analysis_only_source_in_scan_tree(scan_request: tuple[WorkerConfig, dict]) -> None:
    config, req = scan_request
    data = b"void internal(char *p) { gets(p); }\n"
    digest, key = _store(config.filestore, data)
    path = "src/mini/internal-analysis.c"
    capture = json.loads(req["analysis_manifest"])
    capture["entries"].append(
        {
            "path": path,
            "kind": "file",
            "role": "analysis",
            "size": len(data),
            "digest": digest,
            "object_key": key,
        }
    )
    capture["entries"].sort(key=lambda row: row["path"])
    req["analysis_files"].append({"path": path, "digest": digest, "size": len(data), "key": key})
    req["analysis_files"].sort(key=lambda row: row["path"])
    req["analysis_manifest"] = _json(capture)
    req["analysis_manifest_sha256"] = _digest(req["analysis_manifest"])
    status, _ = _call(config, req)
    assert status == 400


def test_old_worker_refuses_new_op(
    scan_request: tuple[WorkerConfig, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    config, req = scan_request
    monkeypatch.delitem(OPS, "rebrew.security_scan_snapshot")
    status, _ = _call(config, req)
    assert status == 404
