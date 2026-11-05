"""Authenticated Recompile request custody and credential-scope tests."""

from __future__ import annotations

import json
import re

import httpx
import pytest

from rebrew.compiler.recompile_client import RecompileError, compile_source


def test_authenticated_retry_replays_exact_original_and_fetches_same_origin(monkeypatch):
    monkeypatch.setenv("REBREW_RECOMPILE_API_KEY", "rck_synthetic")
    monkeypatch.delenv("REBREW_JOB_COMPILE_SOCKET", raising=False)
    seen = []

    def handler(req):
        seen.append(req)
        assert req.headers["authorization"] == "Bearer rck_synthetic"
        if req.method == "POST":
            if sum(r.method == "POST" for r in seen) == 1:
                raise httpx.ReadTimeout("lost reply", request=req)
            return httpx.Response(
                200, json={"status": "ok", "artifact_url": "/api/v1/artifacts/test.obj"}
            )
        return httpx.Response(200, content=b"OBJ")

    with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True) as c:
        result = compile_source(
            "https://compiler.test",
            "gcc-14.2.0",
            "int f(void){return 1;}",
            ["-c"],
            client=c,
            retries=1,
            sleep=lambda _: None,
        )
    assert result.obj_bytes == b"OBJ"
    assert len(seen) == 3 and seen[0].content == seen[1].content
    assert re.fullmatch("[0-9a-f]{12}", seen[0].headers["idempotency-key"])
    assert seen[0].headers["idempotency-key"] == seen[1].headers["idempotency-key"]
    assert json.loads(seen[0].content)["source"] == "int f(void){return 1;}"
    assert seen[2].url.host == "compiler.test" and "idempotency-key" not in seen[2].headers


def test_idempotency_key_tracks_compile_inputs(monkeypatch):
    monkeypatch.delenv("REBREW_RECOMPILE_API_KEY", raising=False)
    monkeypatch.delenv("REBREW_JOB_COMPILE_SOCKET", raising=False)
    keys = []

    def handler(req):
        keys.append(req.headers["idempotency-key"])
        return httpx.Response(200, json={"status": "error", "log": "fixture"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        for source in ("int a;", "int a;", "int b;"):
            compile_source("http://compiler.test", "gcc-14.2.0", source, [], client=client)
    assert keys[0] == keys[1] != keys[2]
    assert all(re.fullmatch("[0-9a-f]{12}", key) for key in keys)


def test_foreign_redirect_is_not_followed_with_credential(monkeypatch):
    monkeypatch.setenv("REBREW_RECOMPILE_API_KEY", "rck_synthetic")
    monkeypatch.delenv("REBREW_JOB_COMPILE_SOCKET", raising=False)
    seen = []

    def handler(req):
        seen.append(req)
        if req.method == "POST":
            return httpx.Response(
                200, json={"status": "ok", "artifact_url": "/api/v1/artifacts/test.obj"}
            )
        return httpx.Response(302, headers={"Location": "https://other.test/stolen"})

    with (
        httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True) as c,
        pytest.raises(RecompileError, match="HTTP 302"),
    ):
        compile_source("https://compiler.test", "gcc-14.2.0", "int f;", [], client=c)
    assert len(seen) == 2 and all(req.url.host == "compiler.test" for req in seen)


def test_job_socket_never_receives_ambient_managed_key(monkeypatch):
    monkeypatch.setenv("REBREW_RECOMPILE_API_KEY", "rck_synthetic")
    monkeypatch.setenv("REBREW_JOB_COMPILE_SOCKET", "/run/rebrew-job/owner.sock")

    def handler(req):
        assert "authorization" not in req.headers
        return httpx.Response(200, json={"status": "error", "log": "fixture"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as c:
        assert not compile_source("http://rebrew-job", "gcc-14.2.0", "int f;", [], client=c).ok


def test_foreign_artifact_url_refuses_before_download(monkeypatch):
    monkeypatch.setenv("REBREW_RECOMPILE_API_KEY", "rck_synthetic")
    monkeypatch.delenv("REBREW_JOB_COMPILE_SOCKET", raising=False)
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(200, json={"status": "ok", "artifact_url": "https://other.test/x"})

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as c,
        pytest.raises(RecompileError, match="not same-origin"),
    ):
        compile_source("https://compiler.test", "gcc-14.2.0", "int f;", [], client=c)
    assert len(seen) == 1


def test_token_is_not_exposed_in_terminal_http_error(monkeypatch):
    monkeypatch.setenv("REBREW_RECOMPILE_API_KEY", "rck_synthetic")
    monkeypatch.delenv("REBREW_JOB_COMPILE_SOCKET", raising=False)

    def handler(req):
        return httpx.Response(400, text="bad rck_synthetic")

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as c,
        pytest.raises(RecompileError) as error,
    ):
        compile_source("https://compiler.test", "gcc-14.2.0", "int f;", [], client=c)
    assert "rck_synthetic" not in str(error.value)


def test_managed_key_refuses_cleartext_before_network(monkeypatch):
    monkeypatch.setenv("REBREW_RECOMPILE_API_KEY", "rck_synthetic")
    monkeypatch.delenv("REBREW_JOB_COMPILE_SOCKET", raising=False)
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(500)

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as c,
        pytest.raises(RecompileError, match="requires HTTPS"),
    ):
        compile_source("http://compiler.test", "gcc-14.2.0", "int f;", [], client=c)
    assert not seen


def test_transport_exception_traceback_does_not_expose_key(monkeypatch):
    import traceback

    monkeypatch.setenv("REBREW_RECOMPILE_API_KEY", "rck_synthetic")
    monkeypatch.delenv("REBREW_JOB_COMPILE_SOCKET", raising=False)

    def handler(req):
        raise httpx.ConnectError("transport echoed rck_synthetic", request=req)

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as c,
        pytest.raises(RecompileError) as error,
    ):
        compile_source("https://compiler.test", "gcc-14.2.0", "int f;", [], client=c)
    assert "rck_synthetic" not in "".join(traceback.format_exception(error.value))
    assert error.value.__cause__ is None and error.value.__context__ is None


def test_compile_failure_log_does_not_expose_key(monkeypatch):
    monkeypatch.setenv("REBREW_RECOMPILE_API_KEY", "rck_synthetic")
    monkeypatch.delenv("REBREW_JOB_COMPILE_SOCKET", raising=False)

    def handler(req):
        return httpx.Response(200, json={"status": "error", "log": "echo rck_synthetic"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as c:
        result = compile_source("https://compiler.test", "gcc-14.2.0", "int f;", [], client=c)
    assert "rck_synthetic" not in result.log


@pytest.mark.parametrize(
    "url",
    [
        "https://name:password@compiler.test",
        "https://compiler.test/?key=x",
        "https://compiler.test/#x",
    ],
)
def test_authenticated_base_url_rejects_credentials_query_and_fragment(monkeypatch, url):
    monkeypatch.setenv("REBREW_RECOMPILE_API_KEY", "rck_synthetic")
    monkeypatch.delenv("REBREW_JOB_COMPILE_SOCKET", raising=False)
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(500)

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as c,
        pytest.raises(RecompileError, match="forbidden components"),
    ):
        compile_source(url, "gcc-14.2.0", "int f;", [], client=c)
    assert not seen


def test_token_in_service_path_is_redacted_from_warning(monkeypatch, caplog):
    monkeypatch.setenv("REBREW_RECOMPILE_API_KEY", "rck_synthetic")
    monkeypatch.delenv("REBREW_JOB_COMPILE_SOCKET", raising=False)

    def handler(req):
        return httpx.Response(400, text="refused")

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as c,
        pytest.raises(RecompileError),
    ):
        compile_source("https://compiler.test/rck_synthetic", "gcc-14.2.0", "int f;", [], client=c)
    assert "rck_synthetic" not in caplog.text


def test_key_is_redacted_before_error_detail_is_truncated(monkeypatch):
    key = "rck_" + "x" * 64
    monkeypatch.setenv("REBREW_RECOMPILE_API_KEY", key)
    monkeypatch.delenv("REBREW_JOB_COMPILE_SOCKET", raising=False)

    def handler(req):
        return httpx.Response(400, text="a" * 280 + key)

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as c,
        pytest.raises(RecompileError) as error,
    ):
        compile_source("https://compiler.test", "gcc-14.2.0", "int f;", [], client=c)
    assert "rck_" not in str(error.value)
