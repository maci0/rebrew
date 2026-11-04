"""Tests for ops.py: the relumea backend's rebrew op worker.

Every request and reply is checked against the backend's generated contract
(``tests/fixtures/dispatch/rebrew.schema.json``, provenance in ``NOTE.txt``
beside it).  The project the function and project ops read is the one
``rebrew.analyse`` generates from ``tests/fixtures/mini_pe.exe``.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import http.client
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from rebrew.ops import OPS, WorkerConfig, dispatch

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
    schema = copy.deepcopy(_CONTRACT["ops"][op][part])
    if part == "response" and op in ("rebrew.analyse", "rebrew.import-project"):
        # The Go field is `CoverageDir *string` ("null when the project has
        # none"); the generated schema drops the nullability.
        schema["properties"]["coverage_dir"] = {"type": ["string", "null"]}
    return schema


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


class TestContract:
    def test_every_contract_op_is_served(self) -> None:
        assert set(OPS) == set(_CONTRACT["ops"])


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

    def test_structs_with_no_functions_to_decompile(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        request = {"binary_id": 1, "project_dir": str(project), "decompiler": "kuna", "limit": 0}
        reply = _call(config, "rebrew.structs", request)
        assert reply == {"functions": 0, "structs": []}

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

    def test_import_project_from_snapshots(
        self, world: tuple[WorkerConfig, Path], tmp_path: Path
    ) -> None:
        from rebrew.coverage_db import write_coverage

        config, project = world
        write_coverage(project, tmp_path, target=None, json_output=True)
        request = {"project_dir": str(project), "snapshots": str(tmp_path)}
        reply = _call(config, "rebrew.import-project", request)
        assert reply["coverage_dir"] == str(tmp_path)
        assert reply["targets"][0]["document"] == str(tmp_path / "coverage-mini.toml")
        assert len(reply["targets"][0]["functions"]) == 2
        request["build_db"] = True
        assert _refusal(config, "rebrew.import-project", json.dumps(request).encode())[
            "detail"
        ] == ("snapshots and build_db exclude each other")


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
            ),
            env={**os.environ, "REBREW_OPS_TOKEN": TOKEN},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
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
            connection.request("POST", path, body=body, headers=headers)
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
            sent = {"Content-Length": "2", **headers}
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
        finally:
            connection.close()

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
