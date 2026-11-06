"""Tests for rebrew.telemetry: trace context and OTLP/JSON export, to a collector the test runs."""

from __future__ import annotations

import http.client
import http.server
import json
import os
import subprocess
import threading
import time
from contextlib import contextmanager
from typing import Any, override
lazy from collections.abc import Iterator
lazy from pathlib import Path

import httpx
import pytest
from test_ops import TOKEN, WAIT_SECONDS, _free_port, _rebrew, _worker_dirs

from rebrew import telemetry
from rebrew.compiler.recompile_client import compile_source

TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
PARENT_ID = "00f067aa0ba902b7"
INBOUND = f"00-{TRACE_ID}-{PARENT_ID}-01"


class _Collector:
    """An OTLP/HTTP collector: keeps every span posted to /v1/traces."""

    def __init__(self) -> None:
        self.spans: list[dict[str, Any]] = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                for resource in body["resourceSpans"]:
                    for scope in resource["scopeSpans"]:
                        outer.spans.extend(scope["spans"])
                assert self.path == "/v1/traces"
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            @override
            def log_message(self, fmt: str, *args: Any) -> None:
                return

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def named(self, name: str) -> dict[str, Any]:
        deadline = time.monotonic() + WAIT_SECONDS
        while time.monotonic() < deadline:
            for found in self.spans:
                if found["name"] == name:
                    return found
            time.sleep(0.05)
        raise AssertionError(f"no span {name!r}; saw {[s['name'] for s in self.spans]}")


@pytest.fixture
def collector() -> Iterator[_Collector]:
    sink = _Collector()
    yield sink
    sink.server.shutdown()


def _attributes(wire: dict[str, Any]) -> dict[str, Any]:
    return {a["key"]: next(iter(a["value"].values())) for a in wire["attributes"]}


def test_span_continues_the_inbound_traceparent(collector: _Collector) -> None:
    stop = telemetry.configure(collector.url, "relumea-rebrew", "1.2.3")
    with telemetry.span("POST /op", kind=telemetry.KIND_SERVER, traceparent=INBOUND) as outer:
        outer.set("http.response.status_code", 200)
        with telemetry.span("child") as inner:
            assert inner.traceparent.startswith(f"00-{TRACE_ID}-")
    stop()
    server = collector.named("POST /op")
    child = collector.named("child")
    assert (server["traceId"], server["parentSpanId"], server["kind"]) == (TRACE_ID, PARENT_ID, 2)
    assert (child["traceId"], child["parentSpanId"]) == (TRACE_ID, server["spanId"])
    assert _attributes(server) == {"http.response.status_code": "200"}


def test_invalid_traceparent_starts_a_new_trace_and_failure_is_an_error(
    collector: _Collector,
) -> None:
    stop = telemetry.configure(collector.url, "relumea-rebrew", "1.2.3")
    zero = f"00-{'0' * 32}-{PARENT_ID}-01"
    with pytest.raises(RuntimeError), telemetry.span("boom", traceparent=zero):
        raise RuntimeError("secret detail")
    stop()
    wire = collector.named("boom")
    assert wire["traceId"] != "0" * 32 and "parentSpanId" not in wire
    assert wire["status"] == {"code": 2, "message": "RuntimeError"}


def test_configure_refuses_a_bad_endpoint() -> None:
    for bad in ("file:///x", "collector:4318", "http://user:pw@host:4318"):
        with pytest.raises(ValueError, match="REBREW_OTLP_ENDPOINT"):
            telemetry.configure(bad, "s", "v")


class _Resp:
    status_code = 200
    content = b"OBJ"
    text = ""

    def __init__(self, body: Any) -> None:
        self._body = body

    def json(self) -> Any:
        return self._body

    def close(self) -> None:
        return


def test_compile_request_carries_a_child_traceparent(
    collector: _Collector, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[dict[str, str]] = []

    class Client:
        def __enter__(self) -> Client:
            return self

        def __exit__(self, *exc: object) -> bool:
            return False

        def post(self, url: str, json: Any = None, headers: Any = None, **_: Any) -> _Resp:
            sent.append(dict(headers))
            return _Resp({"status": "ok", "artifact_url": "/api/v1/artifacts/x.obj"})

        def get(self, url: str, **_: Any) -> _Resp:
            return _Resp(None)

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: Client())
    stop = telemetry.configure(collector.url, "relumea-rebrew", "1.2.3")
    with telemetry.span("POST /rebrew.verify", kind=telemetry.KIND_SERVER, traceparent=INBOUND):
        assert compile_source("http://svc", "msvc-6.0", "int f(void){}", ["/c"]).ok
    stop()
    client_span = collector.named("recompile.compile")
    assert sent[0]["traceparent"] == f"00-{TRACE_ID}-{client_span['spanId']}-01"
    assert client_span["kind"] == 3
    assert client_span["parentSpanId"] == collector.named("POST /rebrew.verify")["spanId"]
    assert _attributes(client_span) == {
        "rebrew.compiler": "msvc-6.0",
        "http.response.status_code": "200",
    }


@contextmanager
def _serving(tmp_path: Path, endpoint: str) -> Iterator[int]:
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
        env={**os.environ, "REBREW_OPS_TOKEN": TOKEN, "REBREW_OTLP_ENDPOINT": endpoint},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + WAIT_SECONDS
        while True:
            assert process.poll() is None, "rebrew ops serve exited"
            assert time.monotonic() < deadline, "rebrew ops serve did not start"
            try:
                http.client.HTTPConnection("127.0.0.1", port, timeout=1).connect()
                break
            except OSError:
                time.sleep(0.1)
        yield port
    finally:
        process.terminate()
        process.wait(timeout=WAIT_SECONDS)


def test_ops_request_is_a_span_in_the_callers_trace(tmp_path: Path, collector: _Collector) -> None:
    body = json.dumps({"code": "ww==", "va": 4096, "arch": "x86_64"})
    with _serving(tmp_path, collector.url) as port:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        connection.request(
            "POST",
            "/rebrew.disassemble_bytes",
            body,
            {
                "Authorization": f"Bearer {TOKEN}",
                "Content-Type": "application/json",
                "traceparent": INBOUND,
            },
        )
        assert connection.getresponse().status == 200
        connection.close()
    wire = collector.named("POST /rebrew.disassemble_bytes")
    assert (wire["traceId"], wire["parentSpanId"], wire["kind"]) == (TRACE_ID, PARENT_ID, 2)
    assert _attributes(wire)["http.route"] == "/rebrew.disassemble_bytes"
    assert _attributes(wire)["http.response.status_code"] == "200"


def test_serve_refuses_an_invalid_endpoint_at_start(tmp_path: Path) -> None:
    filestore, workspace = _worker_dirs(tmp_path)
    done = subprocess.run(
        _rebrew(
            "ops",
            "serve",
            "--port",
            "0",
            "--filestore",
            str(filestore),
            "--workspace",
            str(workspace),
        ),
        env={**os.environ, "REBREW_OPS_TOKEN": TOKEN, "REBREW_OTLP_ENDPOINT": "collector:4318"},
        capture_output=True,
        text=True,
        timeout=WAIT_SECONDS,
        check=False,
    )
    assert done.returncode != 0
    assert "REBREW_OTLP_ENDPOINT must be an http(s) URL" in done.stdout + done.stderr
