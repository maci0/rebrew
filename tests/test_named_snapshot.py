"""The named worker reads only source and analysis objects bound by both manifests."""

from __future__ import annotations

import base64
import copy
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

import pytest
from test_ops import ENTRY_VA, KEY, SHA256, _analyse_request, _free_port, _store, _worker_dirs

from rebrew.named_snapshot import unique_json_object
from rebrew.ops import OPS, WorkerConfig, dispatch


def test_unique_json_object_rejects_duplicate_keys() -> None:
    assert json.loads('{"name":1}', object_pairs_hook=unique_json_object) == {"name": 1}
    with pytest.raises(ValueError, match="duplicate manifest key"):
        json.loads('{"name":1,"name":2}', object_pairs_hook=unique_json_object)


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture(scope="module")
def sample(tmp_path_factory: pytest.TempPathFactory) -> tuple[WorkerConfig, dict]:
    filestore, workspace = _worker_dirs(tmp_path_factory.mktemp("named-snapshot"))
    config = WorkerConfig(filestore.resolve(), workspace.resolve())
    status, body = dispatch(config, "rebrew.analyse", json.dumps(_analyse_request()).encode())
    assert status == 200, body
    result = json.loads(body)
    capture = result["analysis_capture"]
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
            digest, key = _store(filestore, data)
            row["object_key"] = key
            ref = {"path": item["path"], "digest": digest, "size": len(data), "key": key}
            analysis_files.append(ref)
            if item["role"] == "source" or item["path"] == "rebrew-project.toml":
                source_files.append(ref)
        analysis_entries.append(row)
    source = b"typedef struct command_s { char gap[16]; char named; } command_s;\n"
    digest, key = _store(filestore, source)
    source_files.append(
        {"path": "src/mini/named.c", "digest": digest, "size": len(source), "key": key}
    )
    source_files.sort(key=lambda row: row["path"])
    source_document = {
        "complete": True,
        "exclusions": [],
        "files": [{k: f[k] for k in ("digest", "path", "size")} for f in source_files],
        "origin": "files",
        "version": 1,
    }
    source_manifest = _json(source_document)
    analysis_manifest = _json(
        {
            "version": 1,
            "binary_sha256": SHA256,
            "target": capture["target"],
            **{key: capture[key] for key in ("inventory_path", "report_path") if key in capture},
            "entries": analysis_entries,
        }
    )
    request = {
        "project_dir": result["project"],
        "sha256": SHA256,
        "va": ENTRY_VA,
        "backend": "kuna",
        "rebrew_target": capture["target"],
        "source_revision": "source-head",
        "source_snapshot_sha256": _digest(source_manifest),
        "source_manifest": source_manifest,
        "files": source_files,
        "generation": "a" * 32,
        "analysis_manifest_sha256": _digest(analysis_manifest),
        "analysis_manifest": analysis_manifest,
        "analysis_files": analysis_files,
        "binary_key": KEY,
    }
    return config, request


def _call(config: WorkerConfig, request: dict) -> tuple[int, dict]:
    status, raw = dispatch(config, "rebrew.decompile_snapshot", json.dumps(request).encode())
    return status, json.loads(raw)


def test_named_decompile_uses_only_snapshot(
    sample: tuple[WorkerConfig, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    config, request = sample
    live = Path(request["project_dir"]) / "src" / "mini" / "named.c"
    live.parent.mkdir(parents=True, exist_ok=True)
    live.write_text("typedef struct unrelated { char x; } unrelated;\n")

    def decompile(_backend: str, binary: Path, _va: int, root: Path) -> tuple[str, str]:
        assert root != Path(request["project_dir"])
        assert binary.resolve().is_relative_to(root)
        return "int a0;\n*(char *)(a0 + 0x10) = 1;\n", "kuna"

    monkeypatch.setattr("rebrew.decompiler.fetch_decompilation", decompile)
    status, result = _call(config, request)
    assert status == 200, result
    assert "a0->named = 1;" in result["code"]
    assert result["source_snapshot_sha256"] == request["source_snapshot_sha256"]
    assert result["analysis_manifest_sha256"] == request["analysis_manifest_sha256"]
    assert result["generation"] == request["generation"]


def test_legacy_capture_without_selected_paths_remains_readable(
    sample: tuple[WorkerConfig, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    config, original = sample
    request = copy.deepcopy(original)
    capture = json.loads(request["analysis_manifest"])
    capture.pop("inventory_path", None)
    capture.pop("report_path", None)
    request["analysis_manifest"] = _json(capture)
    request["analysis_manifest_sha256"] = _digest(request["analysis_manifest"])
    monkeypatch.setattr(
        "rebrew.decompiler.fetch_decompilation",
        lambda *_args: ("int a0;\n*(char *)(a0 + 0x10) = 1;\n", "kuna"),
    )
    status, result = _call(config, request)
    assert status == 200, result


def test_real_decompiler_from_snapshot(sample: tuple[WorkerConfig, dict]) -> None:
    config, request = sample
    status, result = _call(config, request)
    assert status == 200, result
    assert result["code"] and result["backend"] == "kuna"
    assert result["source_snapshot_sha256"] == request["source_snapshot_sha256"]


def test_kuna_cast_index_names_preserve_access_type() -> None:
    from rebrew.name_decomp import apply_known_names

    definitions = {"command_s": "typedef struct command_s { char gap[16]; int named; } command_s;"}
    text = "unsigned int named_sample(void *a0)\n{\n  return ((unsigned int *)a0)[4];\n}\n"
    result = apply_known_names(text, definitions, pointer_width=8)
    assert "command_s *a0" in result.code
    assert "unsigned int *" in result.code and "a0->named" in result.code
    assert apply_known_names(text, definitions, pointer_width=2).code == text
    assert (
        apply_known_names(
            text.replace("unsigned int *)", "unsigned long *)"), definitions, pointer_width=8
        ).applied
        == []
    )
    extra_use = text.replace("return ", "a0 = a0 + 1; return ")
    assert apply_known_names(extra_use, definitions, pointer_width=8).code == extra_use
    address = text.replace("return ((", "return &((")
    assert (
        "(unsigned int *)&a0->named"
        in apply_known_names(address, definitions, pointer_width=8).code
    )


def test_real_kuna_elf_applies_retained_name(tmp_path: Path) -> None:
    from rebrew.decompiler import fetch_decompilation
    from rebrew.name_decomp import apply_known_names

    source = tmp_path / "input.c"
    binary = tmp_path / "input"
    source.write_text(
        "__attribute__((noinline)) int named_sample(int *p) { return p[4]; }\n"
        "void _start(void) { volatile int x = named_sample((void *)0); (void)x; for (;;) {} }\n"
    )
    subprocess.run(
        [
            "cc",
            "-nostdlib",
            "-static",
            "-O0",
            "-fno-pie",
            "-no-pie",
            "-Wl,-e,_start",
            "-o",
            str(binary),
            str(source),
        ],
        check=True,
    )
    symbols = subprocess.check_output(["nm", "-n", str(binary)], text=True)
    va = next(
        int(line.split()[0], 16) for line in symbols.splitlines() if line.endswith(" named_sample")
    )
    code, backend = fetch_decompilation("kuna", binary, va, tmp_path)
    assert backend == "kuna" and code
    definitions = {"command_s": "typedef struct command_s { char gap[16]; int named; } command_s;"}
    result = apply_known_names(code, definitions, pointer_width=8)
    assert "a0->named" in result.code, (code, result.code)


def test_exec_and_http_transport(sample: tuple[WorkerConfig, dict]) -> None:
    config, request = sample
    argv = [sys.executable, "-m", "rebrew.app.main", "ops"]
    worker_args = ["--filestore", str(config.filestore), "--workspace", str(config.workspace)]
    body = json.dumps(request).encode()
    result = subprocess.run(
        [*argv, "call", *worker_args, "rebrew.decompile_snapshot"],
        input=body,
        capture_output=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout
    assert json.loads(result.stdout)["source_snapshot_sha256"] == request["source_snapshot_sha256"]
    port = _free_port()
    token = secrets.token_hex(16)
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
                "/rebrew.decompile_snapshot",
                body,
                {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )
            response = connection.getresponse()
            payload = json.loads(response.read())
            assert response.status == 200, payload
            assert payload["analysis_manifest_sha256"] == request["analysis_manifest_sha256"]
            assert payload["code"]
        finally:
            connection.close()
    finally:
        process.terminate()
        process.wait(timeout=30)


def test_refuses_source_changed_during_decompilation(
    sample: tuple[WorkerConfig, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    config, request = sample

    def change_source(_backend: str, _binary: Path, _va: int, root: Path) -> tuple[str, str]:
        (root / "src/mini/named.c").write_text("changed")
        return "int a0;\n*(char *)(a0 + 0x10) = 1;\n", "kuna"

    monkeypatch.setattr("rebrew.decompiler.fetch_decompilation", change_source)
    status, result = _call(config, request)
    assert status == 400, result


def test_refuses_symlink_introduced_during_decompilation(
    sample: tuple[WorkerConfig, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    config, request = sample

    def change_source(_backend: str, _binary: Path, _va: int, root: Path) -> tuple[str, str]:
        source = root / "src/mini/named.c"
        source.unlink()
        source.symlink_to(root / "rebrew-project.toml")
        return "int f(void) { return 0; }", "kuna"

    monkeypatch.setattr("rebrew.decompiler.fetch_decompilation", change_source)
    status, result = _call(config, request)
    assert status == 400, result


def test_refuses_duplicate_request_key(sample: tuple[WorkerConfig, dict]) -> None:
    config, req = sample
    body = json.dumps(req).encode()
    body = body[:-1] + b',"backend":"kuna"}'
    status, _ = dispatch(config, "rebrew.decompile_snapshot", body)
    assert status == 400


def test_refuses_incomplete_source_manifest(sample: tuple[WorkerConfig, dict]) -> None:
    config, original = sample
    req = copy.deepcopy(original)
    manifest = json.loads(req["source_manifest"])
    manifest["complete"] = False
    req["source_manifest"] = _json(manifest)
    req["source_snapshot_sha256"] = _digest(req["source_manifest"])
    status, _ = _call(config, req)
    assert status == 400


@pytest.mark.parametrize(
    "field,value",
    [
        ("inventory_path", "missing.json"),
        ("report_path", "src/mini/function_structure.json"),
        ("unknown", "value"),
    ],
)
def test_refuses_unqualified_selected_capture_path(
    sample: tuple[WorkerConfig, dict], monkeypatch: pytest.MonkeyPatch, field: str, value: str
) -> None:
    config, original = sample
    req = copy.deepcopy(original)
    capture = json.loads(req["analysis_manifest"])
    capture[field] = value
    req["analysis_manifest"] = _json(capture)
    req["analysis_manifest_sha256"] = _digest(req["analysis_manifest"])

    def forbidden(*_args: object) -> tuple[str, str]:
        raise AssertionError("decompiler must not run")

    monkeypatch.setattr("rebrew.decompiler.fetch_decompilation", forbidden)
    status, _ = _call(config, req)
    assert status == 400


@pytest.mark.parametrize(
    "mutation",
    [
        "source_hash",
        "capture_hash",
        "generation",
        "source_file",
        "capture_file",
        "binary",
        "unknown",
    ],
)
def test_refuses_changed_inputs_before_decompiling(
    sample: tuple[WorkerConfig, dict], monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    config, original = sample
    req = copy.deepcopy(original)
    if mutation == "source_hash":
        req["source_snapshot_sha256"] = "0" * 64
    elif mutation == "capture_hash":
        req["analysis_manifest_sha256"] = "0" * 64
    elif mutation == "generation":
        req["generation"] = "other"
    elif mutation == "source_file":
        req["files"][0]["size"] += 1
    elif mutation == "capture_file":
        req["analysis_files"][0]["digest"] = "0" * 64
    elif mutation == "binary":
        req["sha256"] = "0" * 64
    else:
        req["unexpected"] = True

    def forbidden(*_args: object) -> tuple[str, str]:
        raise AssertionError("decompiler must not run")

    monkeypatch.setattr("rebrew.decompiler.fetch_decompilation", forbidden)
    status, result = _call(config, req)
    assert status == 400, result


def test_old_worker_refuses_new_operation(
    sample: tuple[WorkerConfig, dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    config, req = sample
    monkeypatch.delitem(OPS, "rebrew.decompile_snapshot")
    status, _ = _call(config, req)
    assert status == 404
