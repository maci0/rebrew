"""Fresh analysis binds the actual selected, captured inventory."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from test_ops import BINARY, SHA256, _analyse_request, _store, _worker_dirs

import rebrew.ops as ops
from rebrew.config import inventory_path_for, load_config
from rebrew.ops import WorkerConfig


def _capture(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    files, workspace = _worker_dirs(tmp_path)
    return ops.capture_fresh_analysis(
        WorkerConfig(files.resolve(), workspace.resolve()), BINARY, SHA256, "mini"
    )


def _selected(capture: dict[str, Any], path: str) -> None:
    assert capture["inventory_path"] == path
    (entry,) = [item for item in capture["entries"] if item["path"] == path]
    assert (entry["kind"], entry["role"]) == ("file", "analysis")
    data = base64.b64decode(entry["data"], validate=True)
    assert len(data) == entry["size"]
    assert hashlib.sha256(data).hexdigest() == entry["digest"]
    rows = sorted(json.loads(data), key=lambda row: row["va"])
    assert [(row["va"], row["size"]) for row in rows] == [(0x401000, 11), (0x401010, 10)]
    assert rows[0]["name"] in {"entry0", "fcn.00401000"}
    assert rows[1]["name"] == "fcn.00401010"


def _report(capture: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    assert capture["report_path"] == ".relumea/analysis-report.json"
    (entry,) = [item for item in capture["entries"] if item["path"] == capture["report_path"]]
    assert (entry["kind"], entry["role"]) == ("file", "analysis")
    raw = base64.b64decode(entry["data"], validate=True)
    assert len(raw) == entry["size"] and hashlib.sha256(raw).hexdigest() == entry["digest"]
    artifact = json.loads(raw)
    assert (
        raw
        == json.dumps(artifact, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    )
    (target,) = report["targets"]
    assert artifact == {
        "version": 1,
        "binary_sha256": capture["binary_sha256"],
        "target": capture["target"],
        "functions": [
            {key: row[key] for key in ("va", "size", "name")} for row in target["functions"]
        ],
        "stubs": [{key: row[key] for key in ("va", "name")} for row in target["stubs"]],
    }
    return artifact


def test_large_producer_metadata_is_captured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rebrew.metadata.functions import record_function_rows

    intake = ops._run_intake
    produced = b""

    def run(binary: Path, root: Path, target: str) -> Any:
        nonlocal produced
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
        )
        produced = (cfg.metadata_dir / "rebrew-functions.toml").read_bytes()
        assert 1024 * 1024 < len(produced) < 8 * 1024 * 1024
        return result

    monkeypatch.setattr(ops, "_run_intake", run)
    capture, _ = _capture(tmp_path)
    from rebrew.metadata.sqlite import DATABASE_FILENAME, SqliteStore

    (entry,) = [item for item in capture["entries"] if item["path"] == DATABASE_FILENAME]
    payload = base64.b64decode(entry["data"], validate=True)
    assert entry["size"] == len(payload) > 1024 * 1024
    assert entry["digest"] == hashlib.sha256(payload).hexdigest()
    staged = tmp_path / "captured-metadata"
    staged.mkdir()
    (staged / DATABASE_FILENAME).write_bytes(payload)
    assert SqliteStore(staged / "rebrew-functions.toml", staged).snapshot() == produced
    assert {
        "path": "rebrew-functions.toml",
        "logical_sha256": hashlib.sha256(produced).hexdigest(),
    } in capture["metadata"]["documents"]


def test_capture_refuses_file_over_eight_mib(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    intake = ops._run_intake
    limit = 8 * 1024 * 1024

    def run(binary: Path, root: Path, target: str) -> Any:
        result = intake(binary, root, target)
        cfg = load_config(root, target=target)
        (cfg.reversed_dir / "too-large.h").write_bytes(b" " * (limit + 1))
        return result

    monkeypatch.setattr(ops, "_run_intake", run)
    with pytest.raises(ops.OpsError, match=f"over the limit of {limit}") as caught:
        _capture(tmp_path)
    assert caught.value.code == ops.READSET_TOO_LARGE
    assert caught.value.status == 422


def test_default_inventory_and_real_worker_dispatch(tmp_path: Path) -> None:
    files, workspace = _worker_dirs(tmp_path)
    status, raw = ops.dispatch(
        WorkerConfig(files.resolve(), workspace.resolve()),
        "rebrew.analyse",
        json.dumps(_analyse_request()).encode(),
    )
    assert status == 200, raw
    report = json.loads(raw)
    _selected(report["analysis_capture"], "src/mini/function_structure.json")
    normalized = _report(report["analysis_capture"], report)
    assert [row["name"] for row in normalized["functions"]] == ["fcn_00401000", "fcn_00401010"]


def test_elf_symbol_names_are_bound_to_normalized_report(tmp_path: Path) -> None:
    import shutil

    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("needs a C compiler")
    source = tmp_path / "fixture.c"
    source.write_text(
        "__attribute__((noinline)) int checksum(int x) { return x*17+3; }\nint main(void) { return checksum(2); }\n"
    )
    binary = tmp_path / "fixture.elf"
    subprocess.run([compiler, "-O0", "-no-pie", "-o", str(binary), str(source)], check=True)
    files, workspace = _worker_dirs(tmp_path)
    digest, key = _store(files, binary.read_bytes())
    status, raw = ops.dispatch(
        WorkerConfig(files.resolve(), workspace.resolve()),
        "rebrew.analyse",
        json.dumps({"binary_id": 1, "sha256": digest, "name": "fixture", "file_key": key}).encode(),
    )
    assert status == 200, raw
    report = json.loads(raw)
    artifact = _report(report["analysis_capture"], report)
    assert {row["name"] for row in artifact["functions"]} >= {"checksum", "main"}


def test_installed_http_worker_captures_inventory(tmp_path: Path) -> None:
    files, workspace = _worker_dirs(tmp_path)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    token = secrets.token_hex(16)
    worker = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "rebrew.app.main",
            "ops",
            "serve",
            "--port",
            str(port),
            "--filestore",
            str(files),
            "--workspace",
            str(workspace),
        ],
        env={**os.environ, "REBREW_OPS_TOKEN": token},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 30
        while True:
            assert worker.poll() is None and time.monotonic() < deadline
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
        try:
            conn.request(
                "POST",
                "/rebrew.analyse",
                body=json.dumps(_analyse_request()),
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )
            reply = conn.getresponse()
            raw = reply.read()
            assert reply.status == 200, raw
            report = json.loads(raw)
            _selected(report["analysis_capture"], "src/mini/function_structure.json")
            _report(report["analysis_capture"], report)
        finally:
            conn.close()
    finally:
        worker.terminate()
        worker.wait(timeout=30)


def test_configured_inventory_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    intake = ops._run_intake

    def run(binary: Path, root: Path, target: str) -> dict[str, Any]:
        result = intake(binary, root, target)
        cfg = load_config(root, target=target)
        original = inventory_path_for(cfg.reversed_dir, cfg)
        override = root / "src/mini/custom-functions.json"
        original.rename(override)
        config = root / "rebrew-project.toml"
        config.write_text(
            config.read_text().replace(
                '[targets."mini"]\n',
                '[targets."mini"]\ninventory_file = "src/mini/custom-functions.json"\n',
            )
        )
        return result

    monkeypatch.setattr(ops, "_run_intake", run)
    capture, _ = _capture(tmp_path)
    _selected(capture, "src/mini/custom-functions.json")
    # The default inventory path is not captured once the override is set:
    # a capture that lists both would double-count one inventory (the
    # input that triggers it: capture logic appending the default path
    # alongside the configured one; the wrong value: a second
    # function_structure.json entry).
    assert all(entry["path"] != "src/mini/function_structure.json" for entry in capture["entries"])


def test_missing_selected_inventory_has_no_name_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    intake = ops._run_intake

    def run(binary: Path, root: Path, target: str) -> dict[str, Any]:
        result = intake(binary, root, target)
        cfg = load_config(root, target=target)
        inventory_path_for(cfg.reversed_dir, cfg).unlink()
        return result

    monkeypatch.setattr(ops, "_run_intake", run)
    capture, _ = _capture(tmp_path)
    assert "inventory_path" not in capture


@pytest.mark.parametrize(
    "kind", ["duplicate-function", "stub-collision", "reserved-path", "reserved-symlink"]
)
def test_ambiguous_normalized_report_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    report = ops.project_report

    def mutate(root: Path, *args: Any, **kwargs: Any) -> dict[str, Any]:
        result = report(root, *args, **kwargs)
        target = result["targets"][0]
        if kind == "duplicate-function":
            target["functions"].append(dict(target["functions"][0]))
        elif kind == "stub-collision":
            target["stubs"].append({"va": target["functions"][0]["va"], "name": "collision"})
        elif kind == "reserved-path":
            reserved = root / ".relumea/analysis-report.json"
            reserved.parent.mkdir(parents=True, exist_ok=True)
            reserved.write_text("{}")
        else:
            (root / ".relumea").symlink_to(root / "src", target_is_directory=True)
        return result

    monkeypatch.setattr(ops, "project_report", mutate)
    with pytest.raises(ops.OpsError):
        _capture(tmp_path)


def test_oversized_report_has_no_producer_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = ops.project_report

    def oversized(root: Path, *args: Any, **kwargs: Any) -> dict[str, Any]:
        result = report(root, *args, **kwargs)
        result["targets"][0]["functions"] = [
            {"va": index, "size": 1, "name": "x" * 4096, "status": "STUB"}
            for index in range(ops.MAX_READSET_FILE_BYTES // 4096 + 1)
        ]
        return result

    monkeypatch.setattr(ops, "project_report", oversized)
    capture, _ = _capture(tmp_path)
    assert "report_path" not in capture
    assert all(entry["path"] != ".relumea/analysis-report.json" for entry in capture["entries"])


@pytest.mark.parametrize(
    "changed", ["inventory", "config", "binary", "source", "metadata", "absence", "new-source"]
)
def test_changed_input_during_report_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed: str
) -> None:
    report = ops.project_report

    def mutate(root: Path, *args: Any, **kwargs: Any) -> dict[str, Any]:
        result = report(root, *args, **kwargs)
        if changed == "metadata":
            from rebrew.metadata.functions import update_field

            update_field(root, 0x401000, "blocker", "changed", "MINI")
            return result
        path = (
            root
            / {
                "inventory": "src/mini/function_structure.json",
                "config": "rebrew-project.toml",
                "binary": "original/mini.exe",
                "source": "src/mini/fcn_00401000.c",
                "absence": ".rebrew/verify_cache.toml",
                "new-source": "src/mini/new-source.c",
            }[changed]
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((path.read_bytes() if path.exists() else b"") + b" ")
        return result

    monkeypatch.setattr(ops, "project_report", mutate)
    with pytest.raises(ops.OpsError, match="changed during reporting") as raised:
        _capture(tmp_path)
    assert (raised.value.code, raised.value.status) == ("analysis-capture-failed", 500)


NOTEPAD = (
    Path(__file__).resolve().parents[2] / "rebrew-test-projects/win2k-notepad-rebrew/notepad.exe"
)
NOTEPAD_SHA256 = "d765da6b0ad1a3f1a4b0a0beadc854b9b12d76ccf73d3855e7a5409bb6b42916"


def test_notepad_function_and_import_stub_share_no_report_identity(tmp_path: Path) -> None:
    """Windows 2000 Notepad analyses without `invalid fresh analysis report identity`.

    Offending row: VA 0x10065dc is both the function row `fcn_010065dc` (size 20,
    a `jmp [iat]` thunk) and the import stub `_initterm`; functions and stubs share
    one `seen` set, so the stub row was refused. The function row now wins.
    The fixture is a sibling checkout (rebrew-test-projects), skipped when absent.
    """
    if not NOTEPAD.is_file() or hashlib.sha256(NOTEPAD.read_bytes()).hexdigest() != NOTEPAD_SHA256:
        pytest.skip("needs rebrew-test-projects/win2k-notepad-rebrew/notepad.exe")
    files, workspace = _worker_dirs(tmp_path)
    digest, key = _store(files, NOTEPAD.read_bytes())
    status, raw = ops.dispatch(
        WorkerConfig(files.resolve(), workspace.resolve()),
        "rebrew.analyse",
        json.dumps({"binary_id": 1, "sha256": digest, "name": "notepad", "file_key": key}).encode(),
    )
    assert status == 200, raw
    (target,) = json.loads(raw)["targets"]
    assert target["stubs"]
    assert not {row["va"] for row in target["functions"]} & {row["va"] for row in target["stubs"]}
