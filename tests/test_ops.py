"""Tests for ops.py: the relumea backend's rebrew op worker.

Every request and reply is checked against the backend's generated contract
(``tests/fixtures/dispatch/rebrew.schema.json``, provenance in ``NOTE.txt``
beside it).  The project the function and project ops read is the one
``rebrew.analyse`` generates from ``tests/fixtures/mini_pe.exe``.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import http.server
import json
import logging
import os
import secrets
import select
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, override

import pytest
from bin_util import append_pe_section

from rebrew.ops import OPS, WorkerConfig, dispatch, target_name

FIXTURES = Path(__file__).parent / "fixtures"
BINARY = FIXTURES / "mini_pe.exe"
SHA256 = hashlib.sha256(BINARY.read_bytes()).hexdigest()
KEY = f"binaries/{SHA256}"
ENTRY_VA = 0x401000
ENTRY_SIZE = 11
TOKEN = secrets.token_hex(16)
#: Bound on any child process or HTTP wait, so a wedged worker fails the test.
WAIT_SECONDS = 120

_CONTRACT = json.loads((FIXTURES / "dispatch" / "rebrew.schema.json").read_text())

# ---------------------------------------------------------------------------
# A strict JSON Schema subset: exactly the keywords the contract uses.  An
# unknown keyword fails, so a contract that grows one is noticed here.
# ---------------------------------------------------------------------------

_KEYWORDS = {
    "$schema",
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "minItems",
    "maxItems",
    "contentEncoding",
    "oneOf",
}
_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


def _validate(schema: Any, value: Any, where: str = "$") -> None:
    if schema is True:
        return
    unknown = set(schema) - _KEYWORDS
    assert not unknown, f"{where}: validator does not implement {sorted(unknown)}"
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        assert any(_TYPES[t](value) for t in types), f"{where}: {value!r} is not {types}"
    if "oneOf" in schema:
        matched = 0
        for option in schema["oneOf"]:
            try:
                _validate(option, value, where)
            except AssertionError:
                continue
            matched += 1
        assert matched == 1, f"{where}: {value!r} matches {matched} oneOf options"
    if schema.get("contentEncoding") is not None:
        assert schema["contentEncoding"] == "base64"
        base64.b64decode(value, validate=True)
    if isinstance(value, dict):
        missing = set(schema.get("required", ())) - set(value)
        assert not missing, f"{where}: missing {sorted(missing)}"
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(properties)
            assert not extra, f"{where}: unexpected {sorted(extra)}"
        for name, item in value.items():
            if name in properties:
                _validate(properties[name], item, f"{where}.{name}")
    if isinstance(value, list):
        assert len(value) >= schema.get("minItems", 0), where
        assert len(value) <= schema.get("maxItems", len(value)), where
        if "items" in schema:
            for index, item in enumerate(value):
                _validate(schema["items"], item, f"{where}[{index}]")


def _op_schema(op: str, part: str) -> Any:
    return _CONTRACT["ops"][op][part]


def _call(config: WorkerConfig, op: str, request: dict[str, Any]) -> Any:
    """Validate *request*, dispatch it in process, validate and return the reply."""
    _validate(_op_schema(op, "request"), request)
    status, body = dispatch(config, op, json.dumps(request).encode())
    reply = json.loads(body)
    assert status == 200, reply
    _validate(_op_schema(op, "response"), reply)
    return reply


def _refusal(config: WorkerConfig, op: str, body: bytes) -> dict[str, Any]:
    status, reply = dispatch(config, op, body)
    refusal = json.loads(reply)
    assert set(refusal) == {"error", "detail", "status"}
    assert refusal["status"] == status != 200
    return refusal


def _worker_dirs(root: Path) -> tuple[Path, Path]:
    """A filestore holding the fixture under its content key, and an empty workspace."""
    filestore = root / "files"
    (filestore / "binaries").mkdir(parents=True)
    shutil.copyfile(BINARY, filestore / KEY)
    workspace = root / "workspace"
    workspace.mkdir()
    return filestore, workspace


def _analyse_request() -> dict[str, Any]:
    return {"binary_id": 1, "sha256": SHA256, "name": "mini.exe", "file_key": KEY}


def _binary_file() -> dict[str, Any]:
    return {"binary_id": 1, "sha256": SHA256, "key": KEY, "name": "mini.exe"}


def _check_analysed(reply: dict[str, Any], workspace: Path) -> Path:
    project = workspace / "projects" / SHA256
    assert reply["project"] == str(project)
    assert reply["coverage_dir"] is None
    (target,) = reply["targets"]
    assert (target["name"], target["arch"], target["format"]) == ("mini", "x86_32", "pe")
    assert [(f["va"], f["size"], f["status"]) for f in target["functions"]] == [
        (0x401000, 11, "STUB"),
        (0x401010, 10, "STUB"),
    ]
    assert target["sha256"] == SHA256
    assert reply["intake"]["functions"] == 2
    return project


@pytest.fixture(scope="module")
def world(tmp_path_factory: pytest.TempPathFactory) -> tuple[WorkerConfig, Path]:
    """A worker configuration and the project ``analyse`` generated in it."""
    filestore, workspace = _worker_dirs(tmp_path_factory.mktemp("ops"))
    config = WorkerConfig(filestore.resolve(), workspace.resolve())
    reply = _call(config, "rebrew.analyse", _analyse_request())
    return config, _check_analysed(reply, workspace.resolve())


class TestTargetName:
    def test_nfd_and_nfc_spellings_share_one_name(self) -> None:
        # A macOS volume hands back NFD; the backend NFC spelling must
        # not mint a second target.
        assert target_name("Café.exe") == target_name("Café.exe")

    def test_ascii_names_are_unchanged(self) -> None:
        assert target_name("2k-calc.exe") == "t_2k_calc"
        assert target_name("mini.exe") == "mini"


class TestContract:
    def test_every_contract_op_is_served(self) -> None:
        assert set(OPS) == set(_CONTRACT["ops"])

    def test_request_fields_match_contract(self) -> None:
        import dataclasses

        for name, op in OPS.items():
            code = {f.name for f in dataclasses.fields(op.request)}
            contract = set(_CONTRACT["ops"][name]["request"].get("properties", {}))
            assert code == contract, name


class TestCallReferences:
    def test_binary_call_scan(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        reply = _call(config, "rebrew.call_references", {"project_dir": str(project)})
        assert isinstance(reply["references"], list)
        assert all(
            row["kind"] in {"call", "jmp", "iat_call", "iat_jmp"} for row in reply["references"]
        )
        assert reply["references"] == sorted(
            reply["references"], key=lambda row: (row["from_va"], row["to_va"], row["kind"])
        )
        assert reply["import_slots"] == sorted(reply["import_slots"], key=lambda row: row["va"])


class TestListingOps:
    @pytest.mark.parametrize(
        ("fmt", "first"),
        [
            ("asm", "push ebp\nmov ebp, esp\n"),
            ("nasm", "bits 32\norg 0x00401000\n"),
            ("hex", "  0x00401000:  55"),
        ],
    )
    def test_disassemble(self, world: tuple[WorkerConfig, Path], fmt: str, first: str) -> None:
        config, project = world
        request = {"project_dir": str(project), "va": ENTRY_VA, "size": ENTRY_SIZE, "format": fmt}
        assert _call(config, "rebrew.disassemble", request)["text"].startswith(first)

    def test_disassemble_selects_the_target_by_sha256(
        self, world: tuple[WorkerConfig, Path]
    ) -> None:
        config, project = world
        request = {
            "project_dir": str(project),
            "sha256": SHA256,
            "arch": "x86_32",
            "va": ENTRY_VA,
            "size": 1,
            "format": "asm",
        }
        assert _call(config, "rebrew.disassemble", request) == {"text": "push ebp\n"}
        request["sha256"] = "0" * 64
        refusal = _refusal(config, "rebrew.disassemble", json.dumps(request).encode())
        assert refusal["detail"] == "no target of project_dir has a binary with that sha256"

    def test_nasm_refuses_another_arch(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        request = {
            "project_dir": str(project),
            "arch": "x86_64",
            "va": ENTRY_VA,
            "size": ENTRY_SIZE,
            "format": "nasm",
        }
        refusal = _refusal(config, "rebrew.disassemble", json.dumps(request).encode())
        assert refusal["status"] == 400

    @pytest.mark.parametrize("fmt", ["hex", "asm"])
    def test_arch_override_applies_to_every_format(
        self, world: tuple[WorkerConfig, Path], fmt: str
    ) -> None:
        config, project = world
        request = {
            "project_dir": str(project),
            "arch": "x86_16",
            "va": ENTRY_VA,
            "size": 1,
            "format": fmt,
        }
        first = _call(config, "rebrew.disassemble", request)["text"].splitlines()[0]
        assert first.split()[-2:] == ["push", "bp"]

    def test_unknown_arch_is_refused(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        request = {
            "project_dir": str(project),
            "arch": "vax",
            "va": ENTRY_VA,
            "size": 1,
            "format": "hex",
        }
        refusal = _refusal(config, "rebrew.disassemble", json.dumps(request).encode())
        assert (refusal["status"], refusal["detail"]) == (400, "unsupported arch: vax")

    def test_disassemble_bytes(self) -> None:
        code = base64.b64encode(b"\x55\x48\x89\xe5\xc3").decode()
        reply = _call(
            WorkerConfig(), "rebrew.disassemble_bytes", {"code": code, "va": 0, "arch": "x86_64"}
        )
        assert reply == {"text": "push rbp\nmov rbp, rsp\nret\n"}


class TestFunctionOps:
    def _address(self, project: Path, **extra: Any) -> dict[str, Any]:
        return {"project_dir": str(project), "sha256": SHA256, "va": ENTRY_VA, **extra}

    def test_control_flow_graph(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        reply = _call(config, "rebrew.control_flow_graph", self._address(project, size=11))
        assert (reply["block_count"], reply["blocks"][0]["last"]) == (1, "ret")

    def test_xrefs(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        reply = _call(config, "rebrew.xrefs", self._address(project, kinds=["call"]))
        assert (reply["target"], reply["count"]) == (ENTRY_VA, 0)

    def test_describe(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        reply = _call(config, "rebrew.describe", self._address(project))
        assert (reply["name"], reply["size"], reply["status"]) == ("fcn_00401000", 11, "STUB")

    def test_describe_refuses_an_address_outside_the_image(
        self, world: tuple[WorkerConfig, Path]
    ) -> None:
        config, project = world
        body = json.dumps({**self._address(project), "va": 0x10}).encode()
        assert _refusal(config, "rebrew.describe", body)["detail"] == (
            "VA 0x10 is outside the binary image"
        )

    def test_decompile_refuses_an_address_outside_the_image(
        self, world: tuple[WorkerConfig, Path]
    ) -> None:
        # Same 400 the describe op gives for the same client mistake; the
        # engine error (500) is reserved for a valid address the backend
        # cannot decompile, not for an address outside the image.
        config, project = world
        request = {**self._address(project), "va": 0x10, "backend": "auto", "named": False}
        refusal = _refusal(config, "rebrew.decompile", json.dumps(request).encode())
        assert (refusal["error"], refusal["status"], refusal["detail"]) == (
            "invalid-request",
            400,
            "VA 0x10 is outside the binary image",
        )

    def test_decompile(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        request = {**self._address(project), "backend": "auto", "named": True}
        status, body = dispatch(config, "rebrew.decompile", json.dumps(request).encode())
        reply = json.loads(body)
        if status != 200 and reply["detail"].startswith("no decompilation via"):
            pytest.skip("no decompiler backend is installed")
        assert status == 200, reply
        _validate(_op_schema("rebrew.decompile", "response"), reply)
        assert reply["code"]

    def test_identify_library(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        reply = _call(config, "rebrew.identify_library", {"project_dir": str(project)})
        assert (reply["identified"], reply["written"]) == (0, 0)

    @pytest.mark.parametrize(("limit", "decompiled"), [(0, 2), (1, 1), (5, 2)])
    def test_structs_limit_zero_means_no_cap(
        self,
        world: tuple[WorkerConfig, Path],
        monkeypatch: pytest.MonkeyPatch,
        limit: int,
        decompiled: int,
    ) -> None:
        # The decompiler is an external engine; a fake one records the calls.
        calls: list[int] = []

        def fake_decompiler(_backend: str, _binary: Path, va: int, _root: Path) -> tuple[str, str]:
            calls.append(va)
            return "int f(int *p) { return p[1]; }", "kuna"

        monkeypatch.setattr("rebrew.decompiler.fetch_decompilation", fake_decompiler)
        config, project = world
        request = {
            "binary_id": 1,
            "project_dir": str(project),
            "decompiler": "kuna",
            "limit": limit,
        }
        reply = _call(config, "rebrew.structs", request)
        assert (reply["decompiled"], len(calls)) == (decompiled, decompiled)

    def test_structs_without_a_decompilation_is_refused(
        self, world: tuple[WorkerConfig, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("rebrew.decompiler.fetch_decompilation", lambda *_args: ("", "kuna"))
        config, project = world
        request = {"binary_id": 1, "project_dir": str(project), "decompiler": "kuna", "limit": 0}
        detail = _refusal(config, "rebrew.structs", json.dumps(request).encode())["detail"]
        assert detail.startswith("no decompilation obtained via 'kuna' (2 function(s) skipped)")

    def test_operand_locations(self, world: tuple[WorkerConfig, Path]) -> None:
        config, _project = world
        # push ebp (offset 0, one operand), mov ebp, esp (offset 1, two operands);
        # offset 2 is inside the mov.
        function = {"va": ENTRY_VA, "size": ENTRY_SIZE, "locations": [[0, 0], [1, 1], [2, 0]]}
        request = {"sha256": SHA256, "file": KEY, "functions": [function]}
        reply = _call(config, "rebrew.binary_operand_locations", request)
        assert reply == {"locations": [[[0, 0], [1, 1]]]}


class TestScanOps:
    @pytest.mark.parametrize(
        ("op", "field", "expected"),
        [
            ("rebrew.fingerprint", "sha256", SHA256),
            ("rebrew.strings", "count", 0),
            ("rebrew.crypto_scan", "count", 0),
            ("rebrew.pe_info", "format", "pe"),
        ],
    )
    def test_scan(
        self, world: tuple[WorkerConfig, Path], op: str, field: str, expected: Any
    ) -> None:
        config, _project = world
        assert _call(config, op, _binary_file())[field] == expected

    def test_imports(self, world: tuple[WorkerConfig, Path]) -> None:
        config, _project = world
        reply = _call(config, "rebrew.imports", _binary_file())
        assert [(i["dll"], i["name"]) for i in reply["imports"]] == [
            ("KERNEL32.dll", "GetTickCount")
        ]

    def test_analyze(self, world: tuple[WorkerConfig, Path]) -> None:
        config, _project = world
        assert _call(config, "rebrew.analyze", _binary_file())["meta"]["format"] == "pe"

    def test_crypto_scan_names_each_constant(self, tmp_path: Path) -> None:
        sha1_h = struct.pack("<5I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
        pe = append_pe_section(BINARY.read_bytes(), ".rdata", sha1_h)
        filestore, workspace = _worker_dirs(tmp_path)
        digest = hashlib.sha256(pe).hexdigest()
        (filestore / "binaries" / digest).write_bytes(pe)
        request = {**_binary_file(), "sha256": digest, "key": f"binaries/{digest}"}
        reply = _call(WorkerConfig(filestore, workspace), "rebrew.crypto_scan", request)
        assert [(f["kind"], f["name"], f["section"]) for f in reply["findings"]] == [
            ("constant", "SHA-1 initial hash H", ".rdata")
        ]


class TestProjectOps:
    def test_report_writes_under_the_workspace(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        request = {"binary_id": 1, "project_dir": str(project), "output_dir": "reports/1"}
        reply = _call(config, "rebrew.report", request)
        assert config.workspace is not None
        assert reply["out"] == str(config.workspace / "reports" / "1")
        assert (config.workspace / "reports" / "1" / "index.html").is_file()

    @pytest.mark.parametrize("output_dir", ["/tmp/out", "../out", "reports/../.."])
    def test_report_refuses_an_output_outside_the_workspace(
        self, world: tuple[WorkerConfig, Path], output_dir: str
    ) -> None:
        config, project = world
        body = {"binary_id": 1, "project_dir": str(project), "output_dir": output_dir}
        assert _refusal(config, "rebrew.report", json.dumps(body).encode())["status"] == 400

    def test_security_scan(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        request = {"binary_id": 1, "project_dir": str(project), "min_severity": "low"}
        reply = _call(config, "rebrew.security_scan", request)
        assert (reply["files_scanned"], reply["count"]) == (2, 0)

    def test_import_project_live(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        reply = _call(config, "rebrew.import-project", {"project_dir": str(project)})
        assert (reply["project"], reply["coverage_dir"]) == (str(project), None)
        assert [f["name"] for f in reply["targets"][0]["functions"]] == [
            "fcn_00401000",
            "fcn_00401010",
        ]

    def test_import_project_build_db_reads_live_coverage(
        self, world: tuple[WorkerConfig, Path]
    ) -> None:
        config, project = world
        request = {"project_dir": str(project), "build_db": True}
        reply = _call(config, "rebrew.import-project", request)
        assert (reply["coverage_dir"], len(reply["targets"][0]["functions"])) == (None, 2)

    def test_import_project_from_snapshots(
        self, world: tuple[WorkerConfig, Path], tmp_path: Path
    ) -> None:
        from rebrew.coverage_db import write_coverage

        config, project = world
        assert config.workspace is not None
        exports = config.workspace / "exports" / tmp_path.name
        exports.mkdir(parents=True)
        write_coverage(project, exports, target=None, json_output=True)
        request = {"project_dir": str(project), "snapshots": str(exports)}
        reply = _call(config, "rebrew.import-project", request)
        assert reply["coverage_dir"] == str(exports)
        assert reply["targets"][0]["document"] == str(exports / "coverage-mini.toml")
        assert len(reply["targets"][0]["functions"]) == 2
        request["build_db"] = True
        assert _refusal(config, "rebrew.import-project", json.dumps(request).encode())[
            "detail"
        ] == ("snapshots and build_db exclude each other")

        write_coverage(project, tmp_path, target=None, json_output=True)
        outside = {"project_dir": str(project), "snapshots": str(tmp_path)}
        assert _refusal(config, "rebrew.import-project", json.dumps(outside).encode())[
            "detail"
        ] == ("snapshots must be inside the worker workspace")


class TestProjectPaths:
    """project_dir is absolute and, with a workspace, resolves inside it."""

    def test_relative_project_dir_is_refused(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        relative = os.path.relpath(project)
        body = json.dumps({"project_dir": relative}).encode()
        assert _refusal(config, "rebrew.identify_library", body)["detail"] == (
            "project_dir must be an absolute path"
        )

    def test_dotdot_inside_the_workspace_is_resolved(
        self, world: tuple[WorkerConfig, Path]
    ) -> None:
        config, project = world
        dotted = project / ".." / project.name
        reply = _call(config, "rebrew.import-project", {"project_dir": str(dotted)})
        assert reply["project"] == str(project)

    def test_project_outside_the_workspace_is_refused(
        self, world: tuple[WorkerConfig, Path], tmp_path: Path
    ) -> None:
        config, project = world
        outside = tmp_path / "copy"
        shutil.copytree(project, outside, symlinks=True)
        assert config.workspace is not None
        link = config.workspace / f"link-{tmp_path.name}"
        link.symlink_to(outside)
        for path in (outside, link, config.workspace / ".." / tmp_path.name / "copy"):
            body = json.dumps({"project_dir": str(path)}).encode()
            assert _refusal(config, "rebrew.import-project", body)["detail"] == (
                "project_dir must be inside the worker workspace"
            )
        # Without a workspace (a local `ops call` worker) the copy is readable.
        reply = _call(WorkerConfig(), "rebrew.import-project", {"project_dir": str(outside)})
        assert reply["project"] == str(outside.resolve())


# ---------------------------------------------------------------------------
# Binaries named by a presigned HTTPS url
# ---------------------------------------------------------------------------


class _OriginHandler(http.server.BaseHTTPRequestHandler):
    """Serves the fixture at /mini.exe, without a length at /unsized.exe."""

    def do_GET(self) -> None:
        body = BINARY.read_bytes()
        if self.path not in ("/mini.exe?X-Signature=s3cret", "/unsized.exe"):
            self.send_error(404)
            return
        self.send_response(200)
        if self.path != "/unsized.exe":
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @override
    def log_message(self, format: str, *args: Any) -> None:
        pass


@pytest.fixture
def https_origin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """An HTTPS server with a self-signed certificate the worker trusts."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
            "-keyout", str(key), "-out", str(cert),
        ],
        check=True,
        capture_output=True,
        timeout=WAIT_SECONDS,
    )  # fmt: skip
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(cert, key)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _OriginHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    monkeypatch.setenv("REBREW_OPS_ALLOW_PRIVATE_DOWNLOAD", "1")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


class TestUrlBinaries:
    def _config(self, tmp_path: Path, **extra: Any) -> WorkerConfig:
        filestore, workspace = _worker_dirs(tmp_path)
        return WorkerConfig(filestore.resolve(), workspace.resolve(), **extra)

    def _url_file(self, origin: str, path: str = "/mini.exe?X-Signature=s3cret") -> dict[str, Any]:
        request = {**_binary_file(), "url": origin + path}
        del request["key"]
        return request

    def _scratch_is_empty(self, config: WorkerConfig) -> bool:
        assert config.workspace is not None
        return not any((config.workspace / ".scratch").iterdir())

    def test_scan_ops_read_a_url(self, tmp_path: Path, https_origin: str) -> None:
        config = self._config(tmp_path)
        for path in ("/mini.exe?X-Signature=s3cret", "/unsized.exe"):
            request = self._url_file(https_origin, path)
            assert _call(config, "rebrew.fingerprint", request)["sha256"] == SHA256
        assert self._scratch_is_empty(config)

    def test_operand_locations_read_a_url(self, tmp_path: Path, https_origin: str) -> None:
        config = self._config(tmp_path)
        function = {"va": ENTRY_VA, "size": ENTRY_SIZE, "locations": [[0, 0]]}
        request = {
            "sha256": SHA256,
            "url": https_origin + "/mini.exe?X-Signature=s3cret",
            "functions": [function],
        }
        assert _call(config, "rebrew.binary_operand_locations", request) == {
            "locations": [[[0, 0]]]
        }

    def test_analyse_reads_a_url(self, tmp_path: Path, https_origin: str) -> None:
        config = self._config(tmp_path)
        request = {**_analyse_request(), "url": https_origin + "/mini.exe?X-Signature=s3cret"}
        del request["file_key"]
        assert config.workspace is not None
        _check_analysed(_call(config, "rebrew.analyse", request), config.workspace)
        assert self._scratch_is_empty(config)

    @pytest.mark.parametrize(
        ("change", "limit", "detail"),
        [
            ({"key": KEY}, None, "exactly one of key and url must be set"),
            ({"url": ""}, None, "exactly one of key and url must be set"),
            ({"url": "http://127.0.0.1/mini.exe"}, None, "url must be an https URL"),
            ({"url": "file:///etc/passwd"}, None, "url must be an https URL"),
            ({"path": "/missing.exe"}, None, "url answered HTTP 404"),
            ({}, 64, "url names more than 64 bytes"),
            ({"path": "/unsized.exe"}, 64, "url names more than 64 bytes"),
            ({"sha256": "0" * 64}, None, "the downloaded file does not match its sha256"),
        ],
    )
    def test_refusals(
        self,
        tmp_path: Path,
        https_origin: str,
        change: dict[str, Any],
        limit: int | None,
        detail: str,
    ) -> None:
        config = self._config(tmp_path, **({} if limit is None else {"max_download_bytes": limit}))
        request = self._url_file(https_origin, change.pop("path", "/mini.exe?X-Signature=s3cret"))
        request.update(change)
        refusal = _refusal(config, "rebrew.fingerprint", json.dumps(request).encode())
        assert (refusal["status"], refusal["detail"]) == (400, detail)
        assert "s3cret" not in refusal["detail"]
        scratch = tmp_path / "workspace" / ".scratch"
        assert not scratch.exists() or not any(scratch.iterdir())

    def test_a_url_needs_a_workspace(self, https_origin: str) -> None:
        request = self._url_file(https_origin)
        refusal = _refusal(WorkerConfig(), "rebrew.fingerprint", json.dumps(request).encode())
        assert refusal["detail"] == "the rebrew worker has no workspace configured (--workspace)"

    def test_hung_dns_does_not_pin_the_worker(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from unittest import mock

        import rebrew.ops as ops

        monkeypatch.setattr(ops, "DNS_TIMEOUT_SECONDS", 0.2)

        # Block until the test ends, so the resolver is hung on any machine.
        release = threading.Event()

        def _hung(*args: Any, **kwargs: Any) -> Any:
            release.wait()
            return []

        try:
            with mock.patch.object(socket, "getaddrinfo", _hung):
                started = time.monotonic()
                refusal = _refusal(
                    self._config(tmp_path),
                    "rebrew.fingerprint",
                    json.dumps(self._url_file("https://example.com")).encode(),
                )
                assert refusal["detail"] == "url host cannot be resolved"
                assert time.monotonic() - started < 1.0
                assert (refusal["status"], refusal["error"]) == (500, "engine-error")
        finally:
            release.set()

    def test_private_dns_answer_is_refused(self, tmp_path: Path) -> None:
        from unittest import mock

        def _private(*args: Any, **kwargs: Any) -> Any:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

        with mock.patch.object(socket, "getaddrinfo", _private):
            refusal = _refusal(
                self._config(tmp_path),
                "rebrew.fingerprint",
                json.dumps(self._url_file("https://evil.example.com/mini.exe")).encode(),
            )
            assert refusal["detail"] == "url host must be a public address"

    def test_download_fetches_the_validated_address_not_a_second_lookup(
        self, tmp_path: Path
    ) -> None:
        from unittest import mock

        import httpx

        seen: dict[str, Any] = {}
        mini = BINARY.read_bytes()

        class _PinnedResponse:
            status_code: int = 200
            headers: dict[str, str]

            def __init__(self) -> None:
                self.headers = {"Content-Length": str(len(mini))}

            def iter_bytes(self, size: int) -> Any:
                yield mini

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *args: Any) -> None:
                return None

        def _fake_client(*args: Any, **kwargs: Any) -> Any:
            class _Client:
                def __init__(self, **kw: Any) -> None:
                    pass

                def __enter__(self) -> Any:
                    return self

                def __exit__(self, *args: Any) -> None:
                    return None

                def stream(self, method: str, url: str, **kw: Any) -> Any:
                    seen["url"] = url
                    seen["headers"] = kw.get("headers") or {}
                    seen["extensions"] = kw.get("extensions") or {}
                    return _PinnedResponse()

            return _Client()

        def _public(*args: Any, **kwargs: Any) -> Any:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

        with (
            mock.patch.object(socket, "getaddrinfo", _public),
            mock.patch.object(httpx, "Client", _fake_client),
            mock.patch.dict("os.environ", {"REBREW_OPS_ALLOW_PRIVATE_DOWNLOAD": "0"}),
        ):
            result = _call(
                self._config(tmp_path),
                "rebrew.fingerprint",
                self._url_file("https://example.com/mini.exe"),
            )
            assert result["sha256"] == SHA256
            assert seen["url"].startswith("https://93.184.216.34/")
            assert seen["headers"]["Host"] == "example.com"
            assert seen["extensions"]["sni_hostname"] == "example.com"

    def test_a_failed_lookup_is_retryable(self, tmp_path: Path) -> None:
        from unittest import mock

        def _down(*args: Any, **kwargs: Any) -> Any:
            raise socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")

        with mock.patch.object(socket, "getaddrinfo", _down):
            refusal = _refusal(
                self._config(tmp_path),
                "rebrew.fingerprint",
                json.dumps(self._url_file("https://example.com")).encode(),
            )
        assert (refusal["status"], refusal["error"], refusal["detail"]) == (
            500,
            "engine-error",
            "url host cannot be resolved",
        )


class TestRefusals:
    @pytest.mark.parametrize(
        ("op", "body", "code", "status"),
        [
            ("rebrew.nope", b"{}", "unknown-op", 404),
            ("rebrew.fingerprint", b"not json", "invalid-request", 400),
            ("rebrew.fingerprint", b"[]", "invalid-request", 400),
            ("rebrew.import-project", b'{"project_dir": "/x", "extra": 1}', "invalid-request", 400),
            ("rebrew.import-project", b"{}", "invalid-request", 400),
            ("rebrew.import-project", b'{"project_dir": "relative"}', "invalid-request", 400),
            (
                "rebrew.import-project",
                b'{"project_dir": "/x", "build_db": 1}',
                "invalid-request",
                400,
            ),
            (
                "rebrew.disassemble_bytes",
                b'{"code": "@@", "va": 0, "arch": ""}',
                "invalid-request",
                400,
            ),
            # A JSON string may carry an unpaired surrogate as an escape;
            # every downstream .encode("utf-8") would raise and surface as
            # a 500, so the boundary rejects it with a 400.
            (
                "rebrew.import-project",
                b'{"project_dir": "x\\ud800y"}',
                "invalid-request",
                400,
            ),
        ],
    )
    def test_malformed_requests(self, op: str, body: bytes, code: str, status: int) -> None:
        refusal = _refusal(WorkerConfig(), op, body)
        assert (refusal["error"], refusal["status"]) == (code, status)

    def test_oversized_request(self) -> None:
        from rebrew.ops import MAX_REQUEST_BYTES

        refusal = _refusal(WorkerConfig(), "rebrew.fingerprint", b" " * (MAX_REQUEST_BYTES + 1))
        assert refusal["status"] == 413

    def test_unconfigured_filestore(self) -> None:
        refusal = _refusal(
            WorkerConfig(), "rebrew.fingerprint", json.dumps(_binary_file()).encode()
        )
        assert (refusal["error"], refusal["detail"]) == (
            "engine-error",
            "the rebrew worker has no filestore configured (--filestore)",
        )

    @pytest.mark.parametrize(
        ("key", "sha256", "detail"),
        [
            ("../escape", SHA256, "file key must be a clean relative filestore key"),
            ("/abs", SHA256, "file key must be a clean relative filestore key"),
            ("binaries/missing", SHA256, "no stored file for the key"),
            (KEY, "0" * 64, "the stored file does not match its sha256"),
            (KEY, "ABC", "sha256 must be 64 lowercase hex digits"),
        ],
    )
    def test_stored_file_references(
        self, world: tuple[WorkerConfig, Path], key: str, sha256: str, detail: str
    ) -> None:
        config, _project = world
        body = json.dumps({**_binary_file(), "key": key, "sha256": sha256}).encode()
        assert _refusal(config, "rebrew.fingerprint", body)["detail"] == detail

    def test_symlink_out_of_the_filestore(self, tmp_path: Path) -> None:
        filestore, _workspace = _worker_dirs(tmp_path)
        (filestore / "binaries" / "link").symlink_to(BINARY.resolve())
        body = json.dumps({**_binary_file(), "key": "binaries/link"}).encode()
        refusal = _refusal(WorkerConfig(filestore.resolve()), "rebrew.fingerprint", body)
        assert refusal["detail"] == "the key does not name a stored file"


# ---------------------------------------------------------------------------
# Function digests, library functions, compiler identification, splat configs
# ---------------------------------------------------------------------------

#: The fixture's first function: ``push ebp; mov ebp, esp; mov eax, [0]; pop ebp; ret``.
ENTRY_CODE = bytes.fromhex("55 8b ec 8b 05 00 00 00 00 5d c3")

SPLAT_YAML = """\
options:
  basename: fixture.exe
  target_path: "fixture.exe"
  platform: win32
  compiler: MSVC6
  symbol_addrs_path: symbol_addrs.txt
segments:
  - name: text
    type: code
    start: 0x200
    vram: 0x00401000
    subsegments:
      - [0x200, text, main_text]
  - [0x400]
"""


def _store(filestore: Path, data: bytes) -> tuple[str, str]:
    """Store *data* under its content key; return ``(sha256, key)``."""
    digest = hashlib.sha256(data).hexdigest()
    (filestore / "binaries" / digest).write_bytes(data)
    return digest, f"binaries/{digest}"


def _relocated_fixture(directory: Path) -> bytes:
    """The fixture with one HIGHLOW fixup on the entry function's ``[0]`` operand."""
    import lief

    binary = lief.PE.parse(BINARY)
    assert binary is not None
    block = lief.PE.Relocation()
    block.virtual_address = 0x1000
    block.add_entry(lief.PE.RelocationEntry(5, lief.PE.RelocationEntry.BASE_TYPES.HIGHLOW))
    binary.add_relocation(block)
    path = directory / "relocated.exe"
    binary.write(str(path))
    return path.read_bytes()


class TestFunctionDigests:
    def _request(self, sha256: str, key: str, *extents: tuple[int, int]) -> dict[str, Any]:
        functions = [{"va": va, "size": size} for va, size in extents]
        return {"sha256": sha256, "file": key, "functions": functions}

    def test_unrelocated_bytes_hash_whole(self, tmp_path: Path) -> None:
        filestore, workspace = _worker_dirs(tmp_path)
        config = WorkerConfig(filestore.resolve(), workspace.resolve())
        request = self._request(SHA256, KEY, (ENTRY_VA, ENTRY_SIZE))
        reply = _call(config, "rebrew.binary_function_digests", request)
        assert reply == {
            "identities": [
                {
                    "algorithm": "sha256-relocations-v1",
                    "arch": "x86_32",
                    "size": ENTRY_SIZE,
                    "digest": hashlib.sha256(ENTRY_CODE).hexdigest(),
                }
            ]
        }

    def test_fixups_are_masked(self, tmp_path: Path) -> None:
        filestore, workspace = _worker_dirs(tmp_path)
        config = WorkerConfig(filestore.resolve(), workspace.resolve())
        digest, key = _store(filestore, _relocated_fixture(tmp_path))
        reply = _call(
            config,
            "rebrew.binary_function_digests",
            self._request(digest, key, (ENTRY_VA, ENTRY_SIZE)),
        )
        masked = ENTRY_CODE[:5] + b"\0\0\0\0" + ENTRY_CODE[9:]
        assert reply["identities"][0]["digest"] == hashlib.sha256(masked).hexdigest()

    @pytest.mark.parametrize(
        ("extents", "detail"),
        [
            ((), "functions must hold 1 to 128 entries"),
            (((ENTRY_VA, 0),), "function extent is outside its bounds"),
            (((-1, 4),), "function extent is outside its bounds"),
            (((0x10, 4),), "function digest extent is not file backed"),
        ],
    )
    def test_refusals(
        self, tmp_path: Path, extents: tuple[tuple[int, int], ...], detail: str
    ) -> None:
        filestore, workspace = _worker_dirs(tmp_path)
        config = WorkerConfig(filestore.resolve(), workspace.resolve())
        body = json.dumps(self._request(SHA256, KEY, *extents)).encode()
        refusal = _refusal(config, "rebrew.binary_function_digests", body)
        assert (refusal["status"], refusal["detail"]) == (400, detail)


class TestStoredFileOps:
    def test_library_functions(self, tmp_path: Path) -> None:
        filestore, workspace = _worker_dirs(tmp_path)
        digest, key = _store(filestore, (FIXTURES / "mini.lib").read_bytes())
        config = WorkerConfig(filestore.resolve(), workspace.resolve())
        reply = _call(config, "rebrew.library_functions", {"sha256": digest, "file": key})
        functions = {f["name"]: f for f in reply["functions"]}
        assert set(functions) == {"_func1", "_func2"}
        assert (functions["_func1"]["arch"], functions["_func1"]["size"]) == ("x86_32", 16)
        assert "push ebp" in functions["_func1"]["listing"]

    def test_library_functions_refuses_a_non_archive(self, tmp_path: Path) -> None:
        filestore, workspace = _worker_dirs(tmp_path)
        config = WorkerConfig(filestore.resolve(), workspace.resolve())
        body = json.dumps({"sha256": SHA256, "file": KEY}).encode()
        refusal = _refusal(config, "rebrew.library_functions", body)
        assert refusal["detail"] == "the file is not an ar archive"

    def test_identify_compiler(self, tmp_path: Path) -> None:
        filestore, workspace = _worker_dirs(tmp_path)
        config = WorkerConfig(filestore.resolve(), workspace.resolve())
        reply = _call(config, "rebrew.identify_compiler", _binary_file())
        assert {"family", "confidence", "evidence", "detected_by", "profile"} <= set(reply)
        assert isinstance(reply["evidence"], list)

    def test_splat_parse(self) -> None:
        reply = _call(WorkerConfig(), "rebrew.splat_parse", {"config": SPLAT_YAML})
        assert (reply["platform"], reply["compiler"], reply["target_path"]) == (
            "win32",
            "MSVC6",
            "fixture.exe",
        )
        assert reply["symbol_addrs_paths"] == ["symbol_addrs.txt"]
        (segment,) = reply["segments"]
        assert (segment["rom_start"], segment["rom_end"], segment["vram"]) == (
            0x200,
            0x400,
            0x401000,
        )
        assert segment["subsegments"] == [{"rom_start": 0x200, "kind": "text", "name": "main_text"}]

    def test_splat_parse_refuses_unreadable_text(self) -> None:
        body = json.dumps({"config": "segments: [unclosed"}).encode()
        refusal = _refusal(WorkerConfig(), "rebrew.splat_parse", body)
        assert refusal["status"] == 400
        assert "/splat" not in refusal["detail"]


# ---------------------------------------------------------------------------
# Reconstruction ops on a project
# ---------------------------------------------------------------------------


def _project_copy(world: tuple[WorkerConfig, Path], name: str) -> tuple[WorkerConfig, Path]:
    """A copy of the analysed project inside the workspace, for ops that write."""
    config, project = world
    assert config.workspace is not None
    copy = config.workspace / "copies" / name
    shutil.copytree(project, copy)
    return config, copy


def _with_project_header(project: Path) -> str:
    """Add a source that includes a project header; return its project-relative path."""
    (project / "src" / "mini" / "local.h").write_text("#define ONE 1\n")
    source = project / "src" / "mini" / "uses_header.c"
    source.write_text('#include "local.h"\nint uses_header(void) { return ONE; }\n')
    return "src/mini/uses_header.c"


class TestReconstructionOps:
    def test_retained_reports_require_and_use_verified_readset(self, tmp_path: Path) -> None:
        from rebrew.coverage_input_contract import (
            coverage_input_digest,
            plan_coverage_readset,
            verification_records_digest,
        )
        from rebrew.ops import FlagSearchFile, retained_target_snapshot

        filestore, workspace = _worker_dirs(tmp_path)
        config = WorkerConfig(filestore.resolve(), workspace.resolve())
        status, raw = dispatch(config, "rebrew.analyse", json.dumps(_analyse_request()).encode())
        assert status == 200, raw
        analysed = json.loads(raw)
        capture = analysed["analysis_capture"]
        files = []
        source_paths = {
            entry["path"] for entry in capture["entries"] if entry.get("role") == "source"
        }
        for entry in capture["entries"]:
            if entry["kind"] != "file":
                continue
            data = base64.b64decode(entry["data"])
            digest, key = _store(filestore, data)
            files.append({"path": entry["path"], "size": len(data), "digest": digest, "key": key})
        target = capture["target"]
        with retained_target_snapshot(
            config, [FlagSearchFile(**item) for item in files], target, SHA256, KEY, ""
        ) as staged:
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
                {
                    **row,
                    "origin": "source"
                    if row["path"] in source_paths or row["path"] == "rebrew-project.toml"
                    else "analysis",
                }
                for row in plan
            ],
        }
        request = {
            "project_dir": analysed["project"],
            "sha256": SHA256,
            "files": files,
            "rebrew_target": target,
            "binary_key": KEY,
            "coverage_input": envelope,
            "coverage_input_digest": coverage_input_digest(envelope),
            "verification_records": [],
        }
        status, body = dispatch(config, "rebrew.coverage_report", json.dumps(request).encode())
        assert status == 200, body
        assert json.loads(body)["report"]["measures"]["matched_functions"] == 0
        missing_records = {
            key: value for key, value in request.items() if key != "verification_records"
        }
        status, _ = dispatch(config, "rebrew.coverage_report", json.dumps(missing_records).encode())
        assert status == 409
        status, _ = dispatch(
            config,
            "rebrew.coverage_report",
            json.dumps({"project_dir": analysed["project"], "coverage_input": {}}).encode(),
        )
        assert status == 400
        site = {**request, "binary_id": 1, "output_dir": "reports/generated/" + "a" * 32}
        status, body = dispatch(config, "rebrew.report", json.dumps(site).encode())
        assert status == 200, body
        assert json.loads(body)["manifest"]
        function = analysed["targets"][0]["functions"][0]
        source = next(row for row in envelope["readset"] if row["path"] == function["source_path"])
        record = {
            "verification_id": "modeled",
            "source": source["path"],
            "source_sha256": source["digest"],
            "va": function["va"],
            "size": function["size"],
            "status": "EXACT",
            "match_count": function["size"],
            "total": function["size"],
            "obj_size": function["size"],
            "reloc_count": 0,
            "result_digest": "e" * 64,
        }
        envelope["verification_digest"] = verification_records_digest([record])
        request["coverage_input_digest"] = coverage_input_digest(envelope)
        request["verification_records"] = [record]
        status, body = dispatch(config, "rebrew.coverage_report", json.dumps(request).encode())
        assert status == 200, body
        assert json.loads(body)["report"]["measures"]["matched_functions"] == 1
        record.update(
            status="SIZE_MISMATCH",
            match_count=0,
            obj_size=function["size"] + 1,
            total=function["size"] + 1,
        )
        envelope["verification_digest"] = verification_records_digest([record])
        request["coverage_input_digest"] = coverage_input_digest(envelope)
        status, body = dispatch(config, "rebrew.coverage_report", json.dumps(request).encode())
        assert status == 200, body
        assert json.loads(body)["report"]["measures"]["matched_functions"] == 0
        request["coverage_input_digest"] = "d" * 64
        status, body = dispatch(config, "rebrew.coverage_report", json.dumps(request).encode())
        assert status == 409, body

    def test_analyse_same_binary_has_isolated_project_workspaces(self, tmp_path: Path) -> None:
        filestore, workspace = _worker_dirs(tmp_path)
        config = WorkerConfig(filestore.resolve(), workspace.resolve())

        def analyse(project_id: str) -> Path:
            request = {**_analyse_request(), "project_id": project_id}
            status, body = dispatch(config, "rebrew.analyse", json.dumps(request).encode())
            assert status == 200, body
            report = json.loads(body)
            capture = report["analysis_capture"]
            assert capture["version"] == 1
            assert capture["binary_sha256"] == SHA256
            assert capture["target"] == report["targets"][0]["name"]
            assert report["targets"][0]["sha256"] == SHA256
            assert sum(entry["kind"] == "binary" for entry in capture["entries"]) == 1
            assert any(entry["kind"] == "file" for entry in capture["entries"])
            source_paths = {
                entry["path"] for entry in capture["entries"] if entry.get("role") == "source"
            }
            for function in report["targets"][0]["functions"]:
                if "source_path" in function:
                    assert function["source_path"] in source_paths
            return Path(report["project"])

        first = analyse("tenant-a")
        second = analyse("tenant-b")
        assert first != second
        (first / "isolation-marker").write_text("tenant-a")
        assert not (second / "isolation-marker").exists()
        assert analyse("tenant-b") == second
        assert (first / "isolation-marker").read_text() == "tenant-a"
        default = analyse("default")
        assert (
            default
            == workspace.resolve()
            / "projects"
            / "scopes"
            / hashlib.sha256(b"default").hexdigest()
            / SHA256
        )
        assert default not in (first, second)
        status, body = dispatch(config, "rebrew.analyse", json.dumps(_analyse_request()).encode())
        assert status == 200, body
        assert Path(json.loads(body)["project"]) == workspace.resolve() / "projects" / SHA256
        status, _ = dispatch(
            config, "rebrew.analyse", json.dumps({**_analyse_request(), "project_id": ""}).encode()
        )
        assert status == 400

    def test_analyse_rejects_scope_symlink_to_another_project(self, tmp_path: Path) -> None:
        filestore, workspace = _worker_dirs(tmp_path)
        target = workspace / "other"
        target.mkdir()
        scope = hashlib.sha256(b"project-a").hexdigest()
        parent = workspace / "projects" / "scopes"
        parent.mkdir(parents=True)
        (parent / scope).symlink_to(target, target_is_directory=True)
        request = {**_analyse_request(), "project_id": "project-a"}
        status, _body = dispatch(
            WorkerConfig(filestore.resolve(), workspace.resolve()),
            "rebrew.analyse",
            json.dumps(request).encode(),
        )
        assert status == 400
        assert not list(target.iterdir())

    def test_import_refuses_scoped_analysis_path(self, tmp_path: Path) -> None:
        filestore, workspace = _worker_dirs(tmp_path)
        project = workspace / "projects" / "scopes" / "scope-a" / SHA256
        project.mkdir(parents=True)
        (project / "rebrew-project.toml").write_text("")
        status, _ = dispatch(
            WorkerConfig(filestore.resolve(), workspace.resolve()),
            "rebrew.import-project",
            json.dumps({"project_dir": str(project)}).encode(),
        )
        assert status == 400

    def test_analysed_elf_reports_defined_symbol_names_and_sizes(self, tmp_path: Path) -> None:
        import lief

        compiler = shutil.which("cc")
        if compiler is None:
            pytest.skip("needs a C compiler")
        source = tmp_path / "fixture.c"
        source.write_text(
            "__attribute__((noinline)) int checksum(int x) { return x*17+3; }\nint main(void) { return checksum(2); }\n"
        )
        binary = tmp_path / "fixture.elf"
        subprocess.run([compiler, "-O0", "-no-pie", "-o", str(binary), str(source)], check=True)
        filestore, workspace = _worker_dirs(tmp_path)
        digest, key = _store(filestore, binary.read_bytes())
        status, body = dispatch(
            WorkerConfig(filestore.resolve(), workspace.resolve()),
            "rebrew.analyse",
            json.dumps(
                {"binary_id": 1, "sha256": digest, "name": "fixture", "file_key": key}
            ).encode(),
        )
        assert status == 200, body
        elf = lief.ELF.parse(str(binary))
        assert elf is not None
        expected = {
            s.name: (s.value, s.size)
            for s in elf.symbols
            if s.name in {"checksum", "main", "_start"}
        }
        found = {
            f["name"]: (f["va"], f["size"]) for f in json.loads(body)["targets"][0]["functions"]
        }
        assert {name: found.get(name) for name in expected} == expected

    def test_candidate_uses_private_retained_snapshot(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        from rebrew import ops

        monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://127.0.0.1:18953")
        filestore, workspace = _worker_dirs(tmp_path)
        original = b"int add(int a, int b) { return a - b; }\n"
        project = b'[project]\ndefault_target="mini"\n[targets.mini]\nbinary="original/mini"\nformat="pe"\narch="x86_32"\nreversed_dir="src"\n'
        entries = []
        for name, data in (("rebrew-project.toml", project), ("src/add.c", original)):
            digest, key = _store(filestore, data)
            entries.append({"path": name, "digest": digest, "size": len(data), "key": key})
        seen: list[Path] = []

        def run(args: Any, root: Path, *unused: Any, **kwargs: Any) -> dict[str, Any]:
            assert (root / "src/add.c").read_text() == "int add(int a, int b) { return a+b; }\n"
            assert "--va=0x401000" in args and "--size=11" in args and "--no-promote" in args
            seen.append(root)
            return {"status": "EXACT"}

        monkeypatch.setattr(ops, "run_rebrew", run)
        config = WorkerConfig(filestore.resolve(), workspace.resolve())
        request = {
            "project_dir": "/unused",
            "source": "src/add.c",
            "candidate": "int add(int a, int b) { return a+b; }\n",
            "sha256": SHA256,
            "va": ENTRY_VA,
            "size": ENTRY_SIZE,
            "files": entries,
            "source_sha256": hashlib.sha256(original).hexdigest(),
            "rebrew_target": "mini",
            "binary_key": KEY,
        }
        status, body = dispatch(config, "rebrew.verify_function", json.dumps(request).encode())
        assert status == 200, body
        assert json.loads(body)["status"] == "EXACT" and len(seen) == 1 and not seen[0].exists()
        assert (filestore / entries[1]["key"]).read_bytes() == original
        request["source_sha256"] = "0" * 64
        status, _body = dispatch(config, "rebrew.verify_function", json.dumps(request).encode())
        assert status == 400
        request["source_sha256"] = hashlib.sha256(original).hexdigest()

        # cflags reach `rebrew test` as one --cflags argument; none means the project's.
        argv: list[list[str]] = []

        def record(args: Any, root: Path, *unused: Any, **kwargs: Any) -> dict[str, Any]:
            argv.append(list(args))
            return {"status": "EXACT"}

        monkeypatch.setattr(ops, "run_rebrew", record)
        status, _ = dispatch(config, "rebrew.verify_function", json.dumps(request).encode())
        assert status == 200 and not any(a.startswith("--cflags") for a in argv[-1])
        flagged = {**request, "cflags": "/O1   /Gd"}
        status, _ = dispatch(config, "rebrew.verify_function", json.dumps(flagged).encode())
        assert status == 200 and "--cflags=/O1 /Gd" in argv[-1]
        # The target's flags become the snapshot's project cflags: no --cflags, and the check that the
        # retained config is unchanged accepts the rewrite it made itself.
        seen_project: list[str] = []

        def project_run(args: Any, root: Path, *unused: Any, **kwargs: Any) -> dict[str, Any]:
            seen_project.append((root / "rebrew-project.toml").read_text())
            assert not any(a.startswith("--cflags") for a in args)
            return {"status": "EXACT"}

        monkeypatch.setattr(ops, "run_rebrew", project_run)
        status, body = dispatch(
            config,
            "rebrew.verify_function",
            json.dumps({**request, "project_cflags": "/O1 /Gd"}).encode(),
        )
        assert status == 200, body
        assert 'cflags = "/O1 /Gd"' in seen_project[0]
        monkeypatch.setattr(ops, "run_rebrew", record)
        for bad in ("/Fo", "/O1 /Fdx.pdb", "-o", "@rsp", "/tmp/x", "/link"):
            status, body = dispatch(
                config, "rebrew.verify_function", json.dumps({**request, "cflags": bad}).encode()
            )
            assert status == 400 and "invalid-cflags" in body.decode(), (bad, body)
        monkeypatch.setattr(ops, "run_rebrew", run)

        def mutate(_args: Any, root: Path, *unused: Any, **kwargs: Any) -> dict[str, Any]:
            (root / "rebrew-project.toml").write_text("changed")
            return {"status": "EXACT"}

        monkeypatch.setattr(ops, "run_rebrew", mutate)
        status, _ = dispatch(config, "rebrew.verify_function", json.dumps(request).encode())
        assert status == 400

    def test_target_flags_become_the_snapshots_project_cflags(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        import tomllib

        from rebrew import ops

        monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://127.0.0.1:18953")
        filestore, workspace = _worker_dirs(tmp_path)
        live = workspace / "live"
        live.mkdir()
        project = b'[project]\ndefault_target="mini"\n[targets.mini]\nbinary="original/mini"\nformat="pe"\narch="x86_32"\nreversed_dir="src"\n[compiler]\ncflags="/O2 /Gd"\n'
        (live / "rebrew-project.toml").write_bytes(project)
        source = b"int add(int a, int b) { return a-b; }\n"
        entries = []
        for name, data in (
            ("rebrew-project.toml", project),
            ("src/add.c", source),
            ("src/function_structure.json", b'{"functions": []}'),
            ("rebrew-functions.toml", b""),
        ):
            digest, key = _store(filestore, data)
            entries.append({"path": name, "digest": digest, "size": len(data), "key": key})
        configs: list[str] = []

        def run(args: Any, root: Path, *unused: Any, **kwargs: Any) -> dict[str, Any]:
            configs.append(
                tomllib.loads((root / "rebrew-project.toml").read_text())["compiler"]["cflags"]
            )
            assert not any(a.startswith("--cflags") for a in args)
            return {"status": "ok"}

        monkeypatch.setattr(ops, "run_rebrew", run)
        monkeypatch.setattr(ops, "remote_header_refusal", lambda *args: None)
        config = WorkerConfig(filestore.resolve(), workspace.resolve())
        request = {
            "project_dir": str(live),
            "sha256": SHA256,
            "files": entries,
            "rebrew_target": "mini",
            "binary_key": KEY,
            "no_promote": True,
        }
        for op in ("rebrew.build", "rebrew.verify_target"):
            body = {**request, "project_cflags": "/O1   /Gd"}
            if op == "rebrew.build":
                body.pop("no_promote")
            status, reply = dispatch(config, op, json.dumps(body).encode())
            assert status == 200, reply
            status, reply = dispatch(
                config, op, json.dumps({**body, "project_cflags": ""}).encode()
            )
            assert status == 200, reply
        assert configs == ["/O1 /Gd", "/O2 /Gd", "/O1 /Gd", "/O2 /Gd"]
        for bad in ("/Fo", "-o", "/tmp/x"):
            refused = {k: v for k, v in request.items() if k != "no_promote"}
            status, reply = dispatch(
                config, "rebrew.build", json.dumps({**refused, "project_cflags": bad}).encode()
            )
            assert status == 400 and "invalid-cflags" in reply.decode(), (bad, reply)
        live_only = {k: v for k, v in request.items() if k not in {"files", "binary_key"}}
        status, reply = dispatch(
            config,
            "rebrew.verify_target",
            json.dumps({**live_only, "project_cflags": "/O1"}).encode(),
        )
        assert status == 400 and "retained" in reply.decode()

    def test_target_operations_use_retained_snapshot(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        from rebrew import ops

        monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://127.0.0.1:18953")
        filestore, workspace = _worker_dirs(tmp_path)
        live = workspace / "live"
        live.mkdir()
        project = b'[project]\ndefault_target="mini"\n[targets.mini]\nbinary="original/mini"\nformat="pe"\narch="x86_32"\nreversed_dir="src"\n'
        (live / "rebrew-project.toml").write_bytes(project)
        source = b"int add(int a, int b) { return a-b; }\n"
        entries = []
        for name, data in (
            ("rebrew-project.toml", project),
            ("src/add.c", source),
            ("src/function_structure.json", b'{"functions": []}'),
            ("rebrew-functions.toml", b""),
        ):
            digest, key = _store(filestore, data)
            entries.append({"path": name, "digest": digest, "size": len(data), "key": key})
        seen: list[Path] = []

        def run(args: Any, root: Path, *unused: Any, **kwargs: Any) -> dict[str, Any]:
            assert root != live and (root / "src/add.c").read_bytes() == source
            assert "--target=mini" in args
            seen.append(root)
            return {"status": "ok"}

        monkeypatch.setattr(ops, "run_rebrew", run)
        monkeypatch.setattr(ops, "remote_header_refusal", lambda *args: None)
        config = WorkerConfig(filestore.resolve(), workspace.resolve())
        request = {
            "project_dir": str(live),
            "sha256": SHA256,
            "files": entries,
            "rebrew_target": "mini",
            "binary_key": KEY,
        }
        for op in ("rebrew.build", "rebrew.verify_target"):
            body = {**request, **({"no_promote": True} if op.endswith("verify_target") else {})}
            status, reply = dispatch(config, op, json.dumps(body).encode())
            assert status == 200, reply
        assert len(seen) == 2 and all(not path.exists() for path in seen)
        bad = {**request, "files": [*entries, entries[0]]}
        status, _ = dispatch(config, "rebrew.build", json.dumps(bad).encode())
        assert status == 400
        alias = {**entries[1], "path": "src/../src/add.c"}
        bad = {**request, "files": [*entries, alias]}
        status, _ = dispatch(config, "rebrew.build", json.dumps(bad).encode())
        assert status == 400
        escape = project.replace(b'reversed_dir="src"', b'reversed_dir="/etc"')
        digest, key = _store(filestore, escape)
        bad_config = {
            "path": "rebrew-project.toml",
            "digest": digest,
            "size": len(escape),
            "key": key,
        }
        status, _ = dispatch(
            config,
            "rebrew.build",
            json.dumps({**request, "files": [bad_config, *entries[1:]]}).encode(),
        )
        assert status == 400
        outside_library = workspace / "rebrew-libraries.toml"
        outside_library.write_text('library = "foreign"\n')
        status, _ = dispatch(config, "rebrew.build", json.dumps(request).encode())
        assert status == 400
        outside_library.unlink()
        status, _ = dispatch(config, "rebrew.verify_target", json.dumps(request).encode())
        assert status == 400

        def mutate(args: Any, root: Path, *unused: Any, **kwargs: Any) -> dict[str, Any]:
            (root / "src/add.c").write_text("changed")
            return {"status": "ok"}

        monkeypatch.setattr(ops, "run_rebrew", mutate)
        status, _ = dispatch(config, "rebrew.build", json.dumps(request).encode())
        assert status == 400

        from rebrew import report

        def render(_cfg: Any, out: Path) -> dict[str, Any]:
            (out / "index.html").write_text("safe report")
            return {"out": str(out), "pages": 1, "summary": {}}

        monkeypatch.setattr(report, "generate_report", render)
        report_request = {**request, "binary_id": 1, "output_dir": "reports/generated/" + "a" * 32}
        status, reply = dispatch(config, "rebrew.report", json.dumps(report_request).encode())
        assert status == 409, reply
        status, _ = dispatch(config, "rebrew.coverage_report", json.dumps(request).encode())
        assert status == 409

    def test_skeleton(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        request = {"project_dir": str(project), "va": 0x401010, "name": "second"}
        source = _call(config, "rebrew.skeleton", request)["source"]
        assert "second" in source and "0x00401010" in source.lower()
        request["va"] = 0x10
        assert _refusal(config, "rebrew.skeleton", json.dumps(request).encode())["status"] == 400

    def test_reference_flirt(self, world: tuple[WorkerConfig, Path]) -> None:
        from rebrew.gen_flirt_pat import bytes_to_pat_line

        config, project = world
        assert config.filestore is not None
        pat = (bytes_to_pat_line("_func1", ENTRY_CODE, {5, 6, 7, 8}) + "\n---\n").encode()
        digest, key = _store(config.filestore, pat)
        request = {
            "project_dir": str(project),
            "sha256": SHA256,
            "format": "pat",
            "signatures": {"sha256": digest, "file": key},
            "min_size": 0,
        }
        reply = _call(config, "rebrew.reference_flirt", request)
        assert [(m["va"], m["names"]) for m in reply["matches"]] == [("0x00401000", ["_func1"])]
        request["format"] = "idb"
        assert _refusal(config, "rebrew.reference_flirt", json.dumps(request).encode())[
            "status"
        ] == (400)

    def test_coverage_export_round_trips_through_import(
        self, world: tuple[WorkerConfig, Path]
    ) -> None:
        config, project = world
        assert config.workspace is not None
        request = {"project_dir": str(project), "sha256": SHA256, "output_dir": "exports/cov"}
        reply = _call(config, "rebrew.coverage_export", request)
        out = config.workspace / "exports" / "cov"
        assert reply == {"output_dir": str(out), "documents": [str(out / "coverage-mini.toml")]}
        imported = _call(
            config, "rebrew.import-project", {"project_dir": str(project), "snapshots": str(out)}
        )
        assert len(imported["targets"][0]["functions"]) == 2

    def test_coverage_report(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        reply = _call(config, "rebrew.coverage_report", {"project_dir": str(project)})
        assert reply["report"]["version"] == 2
        assert (reply["summary"]["total_functions"], reply["summary"]["matched_functions"]) == (
            2,
            0,
        )
        assert "out" not in reply["summary"]

    def test_data_list_refuses_coverage_input_like_the_other_coverage_ops(
        self, world: tuple[WorkerConfig, Path]
    ) -> None:
        """``data_list`` takes the same coverage fields as ``report``.

        A coverage input without the retained snapshot is a 400, and one
        without its verification records is a 409, the same two answers the
        other coverage ops give.  Answering 200 would list a target under an
        input those ops refuse.
        """
        config, project = world
        bare = {"project_dir": str(project), "coverage_input": {}}
        assert _refusal(config, "rebrew.data_list", json.dumps(bare).encode())["status"] == 400
        # A file is present, so this is a retained snapshot rather than the
        # no-snapshot case above; what it lacks is the verification records.
        unverified = {
            "project_dir": str(project),
            "files": [{"path": "src/a.c", "digest": "a" * 64, "size": 1}],
            "coverage_input": {"version": 1},
        }
        refusal = _refusal(config, "rebrew.data_list", json.dumps(unverified).encode())
        assert (refusal["status"], refusal["error"]) == (409, "coverage-input-unverified")

    def test_data_list_and_set(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        listing = _call(config, "rebrew.data_list", {"project_dir": str(project)})
        assert listing["sections"][".text"]["va"] == "0x00401000"
        request = {"project_dir": str(project), "va": 0x401050, "note": "seen", "dry_run": True}
        reply = _call(config, "rebrew.data_set", request)
        assert (reply["dry_run"], reply["changed"], reply["set"][0]["note"]) == (True, 1, "seen")
        empty = {"project_dir": str(project), "va": 0x401050}
        assert _refusal(config, "rebrew.data_set", json.dumps(empty).encode())["detail"] == (
            "data_set needs at least one field to set"
        )

    def test_source_rename_preview(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        request = {
            "project_dir": str(project),
            "kind": "function",
            "old_name": "fcn_00401000",
            "new_name": "entry_fn",
            "dry_run": True,
        }
        reply = _call(config, "rebrew.source_rename", request)
        assert (reply["new_symbol"], reply["dry_run"]) == ("_entry_fn", True)

    def test_source_merge_preview_and_split_refusal(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        sources = ["src/mini/fcn_00401000.c", "src/mini/fcn_00401010.c"]
        request = {
            "project_dir": str(project),
            "sources": sources,
            "output": "src/mini/merged.c",
            "dry_run": True,
        }
        reply = _call(config, "rebrew.source_merge", request)
        assert (reply["count"], reply["vas"]) == (2, ["0x00401000", "0x00401010"])
        assert not (project / "src" / "mini" / "merged.c").exists()
        split = {"project_dir": str(project), "source": sources[0], "dry_run": True}
        refusal = _refusal(config, "rebrew.source_split", json.dumps(split).encode())
        assert refusal["detail"].startswith("rebrew source split failed: Input must contain")

    def test_decompme_export_preview(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        request = {
            "project_dir": str(project),
            "source": "src/mini/fcn_00401000.c",
            "dry_run": True,
        }
        reply = _call(config, "rebrew.decompme_export", request)
        assert (reply["dry_run"], reply["va"], reply["platform"]) == (True, "0x00401000", "win32")

    @pytest.mark.parametrize("source", ["../escape.c", "/etc/passwd", "src/mini/missing.c"])
    def test_source_paths_stay_in_the_project(
        self, world: tuple[WorkerConfig, Path], source: str
    ) -> None:
        config, project = world
        body = json.dumps({"project_dir": str(project), "source": source}).encode()
        assert _refusal(config, "rebrew.verify_function", body)["status"] == 400

    @pytest.mark.parametrize(
        ("op", "extra"),
        [
            ("rebrew.verify_function", {"source": "src/mini/uses_header.c"}),
            ("rebrew.verify_target", {}),
            ("rebrew.build", {}),
            (
                "rebrew.source_variants",
                {"source": "src/mini/uses_header.c", "generations": 1, "population": 2, "seed": 1},
            ),
        ],
    )
    def test_remote_compile_refuses_project_headers(
        self,
        world: tuple[WorkerConfig, Path],
        monkeypatch: pytest.MonkeyPatch,
        op: str,
        extra: dict[str, Any],
    ) -> None:
        config, project = _project_copy(world, op.removeprefix("rebrew."))
        _with_project_header(project)
        monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://127.0.0.1:9")
        body = json.dumps({"project_dir": str(project), **extra}).encode()
        refusal = _refusal(config, op, body)
        assert (refusal["error"], refusal["status"]) == ("remote-compile-headers", 422)
        assert refusal["detail"].startswith("src/mini/uses_header.c reads project headers")


# ---------------------------------------------------------------------------
# Transports, end to end through the installed command
# ---------------------------------------------------------------------------


def _rebrew(*args: str) -> list[str]:
    return [sys.executable, "-m", "rebrew.app.main", *args]


class TestExecTransport:
    def _exec(self, argv: list[str], op: str, request: dict[str, Any]) -> tuple[int, Any]:
        """Run the worker the way the backend's exec transport does: argv, then the op."""
        _validate(_op_schema(op, "request"), request)
        done = subprocess.run(
            [*argv, op],
            input=json.dumps(request).encode(),
            capture_output=True,
            timeout=WAIT_SECONDS,
            check=False,
        )
        return done.returncode, json.loads(done.stdout)

    def test_analyse_then_disassemble(self, tmp_path: Path) -> None:
        filestore, workspace = _worker_dirs(tmp_path)
        argv = _rebrew("ops", "call", "--filestore", str(filestore), "--workspace", str(workspace))
        code, reply = self._exec(argv, "rebrew.analyse", _analyse_request())
        assert code == 0, reply
        _validate(_op_schema("rebrew.analyse", "response"), reply)
        project = _check_analysed(reply, workspace.resolve())

        request = {"project_dir": str(project), "va": ENTRY_VA, "size": 1, "format": "asm"}
        code, reply = self._exec(argv, "rebrew.disassemble", request)
        assert (code, reply) == (0, {"text": "push ebp\n"})
        _validate(_op_schema("rebrew.disassemble", "response"), reply)

    def test_refusal_exits_2_with_the_error_on_stdout(self, tmp_path: Path) -> None:
        request = {"project_dir": str(tmp_path), "va": 0, "size": 1, "format": "asm"}
        code, reply = self._exec(_rebrew("ops", "call"), "rebrew.disassemble", request)
        assert code == 2
        assert reply == {
            "error": "invalid-request",
            "detail": "project_dir is not a rebrew project (no rebrew-project.toml)",
            "status": 400,
        }


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class TestHttpTransport:
    def test_sigterm_drains_active_request(self, tmp_path: Path) -> None:
        filestore, workspace = _worker_dirs(tmp_path)
        port = _free_port()
        process = subprocess.Popen(
            _rebrew(
                "ops",
                "serve",
                "--port",
                str(port),
                "--filestore",
                str(filestore),
                "--workspace",
                str(workspace),
                "--concurrency",
                "1",
            ),
            env={**os.environ, "REBREW_OPS_TOKEN": TOKEN},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        connection = None
        try:
            deadline = time.monotonic() + WAIT_SECONDS
            while True:
                assert process.poll() is None and time.monotonic() < deadline
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=1).close()
                    break
                except OSError:
                    time.sleep(0.1)
            # A stalled call sent once can lose the slot to the first probe and be refused,
            # leaving every later probe a 404: the helper sends it again until it holds the slot.
            connection = self._hold_the_only_slot(port)
            process.terminate()
            time.sleep(0.2)
            assert process.poll() is None
            connection.sendall(b'{"xx": 12}')
            reply = b"".join(iter(lambda: connection.recv(4096), b""))
            head, _, body = reply.partition(b"\r\n\r\n")
            assert (head.split(b"\r\n", 1)[0], json.loads(body)["error"]) == (
                b"HTTP/1.0 400 Bad Request",
                "invalid-request",
            )
            assert process.wait(timeout=5) == 0
        finally:
            if connection is not None:
                connection.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=WAIT_SECONDS)

    @pytest.fixture
    def server(self, tmp_path: Path) -> Any:
        filestore, workspace = _worker_dirs(tmp_path)
        port = _free_port()
        process = subprocess.Popen(
            _rebrew(
                "ops",
                "serve",
                "--port",
                str(port),
                "--filestore",
                str(filestore),
                "--workspace",
                str(workspace),
                "--concurrency",
                "1",
                "--allowed-hosts",
                f"relumea-rebrew:{port}",
            ),
            env={**os.environ, "REBREW_OPS_TOKEN": TOKEN, "PYTHONUNBUFFERED": "1"},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.monotonic() + WAIT_SECONDS
        try:
            while True:
                assert process.poll() is None, "rebrew ops serve exited"
                assert time.monotonic() < deadline, "rebrew ops serve did not start"
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=1).close()
                    break
                except OSError:
                    time.sleep(0.1)
            yield port, workspace
        finally:
            process.terminate()
            process.wait(timeout=WAIT_SECONDS)

    def _post(self, port: int, path: str, body: bytes, headers: dict[str, str]) -> tuple[int, Any]:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        try:
            req_headers = {"Content-Type": "application/json", **headers}
            connection.request("POST", path, body=body, headers=req_headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def _op(self, port: int, op: str, request: dict[str, Any]) -> Any:
        _validate(_op_schema(op, "request"), request)
        status, reply = self._post(
            port,
            f"/{op}",
            json.dumps(request).encode(),
            {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
        )
        assert status == 200, reply
        _validate(_op_schema(op, "response"), reply)
        return reply

    def test_configured_host_is_exact(self, server: tuple[int, Path]) -> None:
        port, _ = server
        for host, expected in ((f"relumea-rebrew:{port}", 200), (f"attacker:{port}", 403)):
            status, _ = self._post(
                port,
                "/rebrew.disassemble_bytes",
                b'{"code":"ww==","va":4096,"arch":"x86_64"}',
                {"Host": host, "Authorization": f"Bearer {TOKEN}"},
            )
            assert status == expected

    def test_analyse_then_function_ops(self, server: tuple[int, Path]) -> None:
        port, workspace = server
        project = _check_analysed(
            self._op(port, "rebrew.analyse", _analyse_request()), workspace.resolve()
        )
        assert self._op(port, "rebrew.fingerprint", _binary_file())["sha256"] == SHA256
        reply = self._op(
            port, "rebrew.describe", {"project_dir": str(project), "sha256": SHA256, "va": ENTRY_VA}
        )
        assert reply["name"] == "fcn_00401000"

    @pytest.mark.parametrize(
        ("path", "headers", "status", "code"),
        [
            ("/rebrew.fingerprint", {}, 401, "unauthorized"),
            ("/rebrew.fingerprint", {"Authorization": "Bearer wrong"}, 401, "unauthorized"),
            ("/rebrew.nope", {"Authorization": f"Bearer {TOKEN}"}, 404, "unknown-op"),
            (
                "/rebrew.fingerprint",
                {"Authorization": f"Bearer {TOKEN}", "Content-Length": str(64 << 20)},
                413,
                "invalid-request",
            ),
        ],
    )
    def test_refusals(
        self, server: tuple[int, Path], path: str, headers: dict[str, str], status: int, code: str
    ) -> None:
        port, _workspace = server
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        try:
            connection.putrequest("POST", path)
            sent = {"Content-Length": "2", "Content-Type": "application/json", **headers}
            for name, value in sent.items():
                connection.putheader(name, value)
            connection.endheaders(b"{}" if sent["Content-Length"] == "2" else b"")
            response = connection.getresponse()
            reply = json.loads(response.read())
        finally:
            connection.close()
        assert (response.status, reply["error"], reply["status"]) == (status, code, status)

    def test_get_is_refused(self, server: tuple[int, Path]) -> None:
        port, _workspace = server
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        try:
            connection.request("GET", "/rebrew.fingerprint")
            response = connection.getresponse()
            assert (response.status, json.loads(response.read())["error"]) == (
                405,
                "method-not-allowed",
            )
            assert response.getheader("Allow") == "POST"
        finally:
            connection.close()

    def test_unknown_method_is_refused_like_get(self, server: tuple[int, Path]) -> None:
        """A method with no do_* handler (TRACE/FOO) is 405/404, not 501."""
        port, _workspace = server
        for method, path, status, allow in (
            ("TRACE", "/rebrew.fingerprint", 405, "POST"),
            ("FOO", "/rebrew.fingerprint", 405, "POST"),
            ("TRACE", "/nope", 404, None),
        ):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
            try:
                connection.request(method, path)
                response = connection.getresponse()
                response.read()
                assert (response.status, response.getheader("Allow")) == (status, allow), (
                    method,
                    path,
                )
            finally:
                connection.close()

    def test_post_to_health_and_metrics_is_refused(self, server: tuple[int, Path]) -> None:
        port, _workspace = server
        auth = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
        for path in ("/health", "/metrics"):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
            try:
                connection.request("POST", path, body=b"{}", headers=auth)
                response = connection.getresponse()
                body = json.loads(response.read())
                assert (response.status, body["error"], response.getheader("Allow")) == (
                    405,
                    "method-not-allowed",
                    "GET, HEAD",
                )
            finally:
                connection.close()

    def test_health_and_metrics(self, server: tuple[int, Path]) -> None:
        port, _workspace = server
        auth = {"Authorization": f"Bearer {TOKEN}"}
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        try:
            conn.request("GET", "/health", headers=auth)
            resp = conn.getresponse()
            body = resp.read()
            assert resp.status == 200
            payload = json.loads(body)
            assert payload["status"] == "up"
            assert payload["requests"] >= 0
            assert "latency_ms_avg" in payload
            assert "uptime_seconds" in payload
        finally:
            conn.close()

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        try:
            conn.request("GET", "/metrics", headers=auth)
            resp = conn.getresponse()
            text = resp.read().decode()
            assert resp.status == 200
            assert resp.getheader("Content-Type") == "text/plain; version=0.0.4; charset=utf-8"
            assert "rebrew_ops_requests_total" in text
            assert "rebrew_ops_errors_total" in text
            assert "rebrew_ops_latency_ms_total" in text
            # One Prometheus histogram family: its TYPE names the family, the buckets are cumulative, and exactly
            # one bucket is +Inf, equal to _count.
            assert "# TYPE rebrew_ops_latency histogram" in text
            buckets = [
                line.split(" ")
                for line in text.splitlines()
                if line.startswith("rebrew_ops_latency_bucket{")
            ]
            bounds = [
                name.removeprefix('rebrew_ops_latency_bucket{le="').removesuffix('"}')
                for name, _ in buckets
            ]
            counts = [int(value) for _, value in buckets]
            assert bounds.count("+Inf") == 1 and bounds[-1] == "+Inf" and "inf" not in bounds
            assert counts == sorted(counts)
            count_line = next(
                line for line in text.splitlines() if line.startswith("rebrew_ops_latency_count ")
            )
            assert counts[-1] == int(count_line.split(" ")[1])
        finally:
            conn.close()

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        try:
            conn.request("GET", "/health")
            resp = conn.getresponse()
            resp.read()
            assert resp.status == 401
        finally:
            conn.close()

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        try:
            conn.request("GET", "/metrics")
            resp = conn.getresponse()
            resp.read()
            assert resp.status == 401
        finally:
            conn.close()

        # HEAD must carry headers only, never a body (RFC 9110 §9.3.2).
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        try:
            conn.request("HEAD", "/health", headers=auth)
            resp = conn.getresponse()
            assert resp.status == 200
            assert resp.getheader("Content-Length") is not None
            assert resp.read() == b""
        finally:
            conn.close()

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        try:
            conn.request("HEAD", "/metrics", headers=auth)
            resp = conn.getresponse()
            assert resp.status == 200
            assert resp.getheader("Content-Length") is not None
            assert resp.read() == b""
        finally:
            conn.close()

    def test_serve_requires_a_token(self) -> None:
        done = subprocess.run(
            _rebrew("ops", "serve", "--port", "0"),
            env={k: v for k, v in os.environ.items() if k != "REBREW_OPS_TOKEN"},
            capture_output=True,
            text=True,
            timeout=WAIT_SECONDS,
            check=False,
        )
        assert done.returncode == 2
        assert "REBREW_OPS_TOKEN is not set" in done.stderr

    def test_serve_requires_a_workspace(self) -> None:
        done = subprocess.run(
            _rebrew("ops", "serve", "--port", "0"),
            env={
                **{k: v for k, v in os.environ.items() if k != "REBREW_OPS_WORKSPACE"},
                "REBREW_OPS_TOKEN": TOKEN,
            },
            capture_output=True,
            text=True,
            timeout=WAIT_SECONDS,
            check=False,
        )
        assert done.returncode == 2
        assert "serve needs --workspace" in done.stderr

    def test_project_outside_the_workspace_is_refused(self, server: tuple[int, Path]) -> None:
        port, _workspace = server
        status, reply = self._post(
            port,
            "/rebrew.import-project",
            json.dumps({"project_dir": str(FIXTURES)}).encode(),
            {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
        )
        assert (status, reply["detail"]) == (400, "project_dir must be inside the worker workspace")

    def _hold_the_only_slot(self, port: int) -> socket.socket:
        """A connection whose call holds the worker's only slot while it waits for a body that never comes.

        The worker refuses at once a call that finds the slot taken, even by a request in flight for a
        millisecond, so the stalled call can itself be refused (503 on its own socket). It is sent again
        until a probe finds the slot held and the stalled call was not the one refused.

        Each attempt starts from a free slot. A call whose socket was just closed holds the slot
        until the worker reads the close, and a probe answered 503 for that call would pass off
        a stalled call that was itself refused as the holder.
        """
        deadline = time.monotonic() + WAIT_SECONDS
        while time.monotonic() < deadline:
            self._wait_for_a_free_slot(port, deadline)
            stalled = socket.create_connection(("127.0.0.1", port), timeout=WAIT_SECONDS)
            stalled.sendall(
                f"POST /rebrew.fingerprint HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n".encode()
                + f"Authorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n".encode()
            )
            while time.monotonic() < deadline:
                refused, _, _ = select.select([stalled], [], [], 0)
                if refused:  # answered before its body: it lost the slot to another request
                    break
                status, reply = self._post(
                    port,
                    "/rebrew.nope",
                    b"{}",
                    {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
                )
                if status == 503:
                    assert reply["error"] == "worker-busy"
                    return stalled
                time.sleep(0.05)
            stalled.close()
        raise AssertionError("no stalled call ever held the slot")

    def _wait_for_a_free_slot(self, port: int, deadline: float) -> tuple[int, Any]:
        """The dispatcher's answer to a probe once no call holds the worker's only slot."""
        headers = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
        while True:
            status, reply = self._post(port, "/rebrew.nope", b"{}", headers)
            if status != 503:
                return status, reply
            assert time.monotonic() < deadline, "the slot was not released"
            time.sleep(0.05)

    def test_a_full_worker_answers_503_with_retry_after(self, server: tuple[int, Path]) -> None:
        port, _workspace = server
        stalled = self._hold_the_only_slot(port)
        try:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
            try:
                connection.request(
                    "POST",
                    "/rebrew.nope",
                    body=b"{}",
                    headers={
                        "Authorization": f"Bearer {TOKEN}",
                        "Content-Type": "application/json",
                    },
                )
                response = connection.getresponse()
                reply = json.loads(response.read())
            finally:
                connection.close()
            assert (response.status, reply["error"], response.getheader("Retry-After")) == (
                503,
                "worker-busy",
                "5",
            )
        finally:
            stalled.close()
        deadline = time.monotonic() + WAIT_SECONDS
        while True:
            status, reply = self._post(
                port,
                "/rebrew.nope",
                b"{}",
                {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
            )
            if status != 503:
                break
            assert time.monotonic() < deadline, "the slot was not released"
            time.sleep(0.05)
        assert (status, reply["error"]) == (404, "unknown-op")

    def test_a_stalled_call_refused_for_a_busy_slot_is_sent_again(
        self, server: tuple[int, Path]
    ) -> None:
        port, _workspace = server
        headers = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
        first = self._hold_the_only_slot(port)
        try:
            # A second stalled call finds the slot taken and is refused at once: wait for
            # that refusal on its own socket instead of for a fixed time.
            second = socket.create_connection(("127.0.0.1", port), timeout=WAIT_SECONDS)
            try:
                second.sendall(
                    f"POST /rebrew.fingerprint HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n".encode()
                    + f"Authorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n".encode()
                )
                refused, _, _ = select.select([second], [], [], WAIT_SECONDS)
                assert refused, "the second stalled call was not refused while the slot was held"
                assert b" 503 " in second.recv(4096).split(b"\r\n", 1)[0]
            finally:
                second.close()
        finally:
            first.close()
        # The refused call is sent again once the slot is free: it must genuinely hold the
        # slot, so a probe is the one refused with 503.
        resent = self._hold_the_only_slot(port)
        try:
            status, reply = self._post(port, "/rebrew.nope", b"{}", headers)
            assert (status, reply["error"]) == (503, "worker-busy")
        finally:
            resent.close()
        # Once every stalled socket closes, the slot must be free again: a leaked slot
        # would leave this at 503 instead of the dispatcher's 404.
        status, reply = self._wait_for_a_free_slot(port, time.monotonic() + WAIT_SECONDS)
        assert (status, reply["error"]) == (404, "unknown-op")

    def test_access_line_and_header_share_a_request_id(self, server: tuple[int, Path]) -> None:
        port, _workspace = server
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        try:
            connection.request(
                "POST",
                "/rebrew.nope",
                body=b"{}",
                headers={
                    "Authorization": f"Bearer {TOKEN}",
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            response.read()
        finally:
            connection.close()
        assert response.status == 404
        request_id = response.getheader("X-Request-Id")
        assert request_id is not None and request_id.startswith("r")

    def test_unauthenticated_requests_log_a_warning(self, server: tuple[int, Path]) -> None:
        port, _workspace = server
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        try:
            connection.request(
                "POST",
                "/rebrew.fingerprint",
                body=b"{}",
                headers={"Authorization": "Bearer wrong", "Content-Type": "application/json"},
            )
            response = connection.getresponse()
            response.read()
        finally:
            connection.close()
        assert response.status == 401


def test_dispatch_5xx_is_logged_and_4xx_is_not(caplog: Any) -> None:
    cfg = WorkerConfig()
    with caplog.at_level(logging.ERROR, logger="rebrew.ops"):
        status5, _ = dispatch(
            cfg,
            "rebrew.fingerprint",
            json.dumps({"binary_id": 1, "sha256": "0" * 64, "name": "x", "key": "k"}).encode(),
        )
    assert status5 == 500
    assert [record.levelno for record in caplog.records] == [logging.ERROR]
    assert "refused" in caplog.records[0].getMessage()
    caplog.clear()
    with caplog.at_level(logging.ERROR, logger="rebrew.ops"):
        status4, _ = dispatch(cfg, "rebrew.nope", b"{}")
    assert status4 == 404
    assert caplog.records == []


def test_handler_fault_is_logged_with_its_request_id_and_counted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A fault that escapes a handler thread must not vanish into stderr.

    ``socketserver`` reports it through ``handle_error`` with no handler in
    hand, so the record has to carry the stamped request id, and the fault has
    to reach the counter ``/health`` and ``/metrics`` read.  A peer that simply
    went away is not a fault and must not move that counter.
    """
    from rebrew.ops import OpsServer, _stamp_request

    server = OpsServer.__new__(OpsServer)
    server._metrics_lock = threading.Lock()
    server._unhandled_errors = 0

    def raise_fault() -> None:
        _stamp_request("r7")
        try:
            raise RuntimeError("handler exploded")
        except RuntimeError:
            server.handle_error(None, ("127.0.0.1", 9))

    with caplog.at_level(logging.INFO, logger="rebrew.ops"):
        raise_fault()
    assert server._unhandled_errors == 1
    assert logging.ERROR in (entry.levelno for entry in caplog.records)
    blob = "\n".join(caplog.text.splitlines())
    assert "r7" in blob
    assert "RuntimeError" in blob
    assert "handler exploded" in blob

    caplog.clear()
    _stamp_request("r8")
    try:
        raise ConnectionResetError("peer reset")
    except ConnectionResetError:
        with caplog.at_level(logging.DEBUG, logger="rebrew.ops"):
            server.handle_error(None, ("127.0.0.1", 9))
    assert server._unhandled_errors == 1
    assert [entry.levelno for entry in caplog.records] == [logging.INFO]


def test_export_stats_are_zero_without_an_exporter() -> None:
    from rebrew import telemetry

    assert telemetry.export_stats() == {"dropped": 0, "failed": 0}
