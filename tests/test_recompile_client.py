"""Tests for rebrew.recompile_client and the recompile backend selection."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from rebrew.compile import _compile_via_recompile, recompile_url
from rebrew.recompile_client import RecompileError, _same_origin_artifact_url, compile_source


def test_recompile_client_public_all() -> None:
    """Star-imports must not leak typing/stdlib names into consumer namespaces."""
    import rebrew.recompile_client as rc

    assert rc.__all__ == [
        "RecompileError",
        "RecompileErrorKind",
        "RecompileResult",
        "compile_source",
    ]
    for name in rc.__all__:
        assert getattr(rc, name, None) is not None, name
    ns: dict[str, Any] = {}
    exec("from rebrew.recompile_client import *", ns)  # noqa: S102
    exported = {k for k in ns if not k.startswith("_")}
    assert exported == set(rc.__all__)


class _Resp:
    def __init__(
        self,
        status_code: int,
        *,
        json_body: Any = None,
        content: bytes = b"",
        text: str = "",
    ) -> None:
        self.status_code = status_code
        self._json = json_body
        self.content = content
        self.text = text

    def json(self) -> Any:
        if self._json is None:
            raise ValueError("not json")
        return self._json


class _FakeClient:
    """Stand-in for ``httpx.Client``; records calls, replays canned replies."""

    def __init__(self, post: Any, get: Any = None) -> None:
        self._post = post
        self._get = get
        self.calls: list[tuple[str, str]] = []

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def post(self, url: str, json: Any = None) -> Any:
        self.calls.append(("post", url))
        if isinstance(self._post, Exception):
            raise self._post
        return self._post

    def get(self, url: str) -> Any:
        self.calls.append(("get", url))
        if isinstance(self._get, Exception):
            raise self._get
        return self._get


def _patch(monkeypatch: pytest.MonkeyPatch, post: Any, get: Any = None) -> _FakeClient:
    client = _FakeClient(post, get)
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: client)
    return client


class TestCompileSource:
    def test_ok_downloads_the_artifact(self, monkeypatch: pytest.MonkeyPatch) -> None:
        body = {
            "status": "ok",
            "artifact_url": "/api/v1/artifacts/x.obj",
            "compiler_version": "12.0",
        }
        client = _patch(monkeypatch, _Resp(200, json_body=body), _Resp(200, content=b"OBJ"))

        res = compile_source("http://svc/", "msvc-6.0", "int f(void){}", ["/c"])

        assert res.ok and res.obj_bytes == b"OBJ"
        assert res.compiler_version == "12.0"
        # relative artifact_url is joined onto the base, trailing slash stripped
        assert client.calls == [
            ("post", "http://svc/api/v1/compile"),
            ("get", "http://svc/api/v1/artifacts/x.obj"),
        ]

    def test_service_error_is_not_ok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, _Resp(200, json_body={"status": "error", "log": "syntax error"}))
        res = compile_source("http://svc", "msvc-6.0", "bad", [])
        assert not res.ok and "syntax error" in res.log

    def test_http_error_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, _Resp(500, text="boom"))
        with pytest.raises(RecompileError, match="HTTP 500") as ei:
            compile_source("http://svc", "msvc-6.0", "int f(void){}", [])
        assert ei.value.kind == "http"
        assert ei.value.status_code == 500
        assert ei.value.retryable is True

    def test_http_4xx_is_not_retryable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, _Resp(422, text="bad flags"))
        with pytest.raises(RecompileError) as ei:
            compile_source("http://svc", "msvc-6.0", "int f(void){}", [])
        assert ei.value.kind == "http"
        assert ei.value.status_code == 422
        assert ei.value.retryable is False

    def test_unreachable_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, httpx.ConnectError("refused"))
        with pytest.raises(RecompileError, match="unreachable") as ei:
            compile_source("http://svc", "msvc-6.0", "int f(void){}", [])
        assert ei.value.kind == "network"
        assert ei.value.status_code is None
        assert ei.value.retryable is True

    def test_flag_caps_are_enforced(self) -> None:
        with pytest.raises(RecompileError, match="too many flags") as ei:
            compile_source("http://svc", "msvc-6.0", "x", ["/c"] * 65)
        assert ei.value.kind == "validation"
        assert ei.value.retryable is False
        with pytest.raises(RecompileError, match="flag too long") as ei2:
            compile_source("http://svc", "msvc-6.0", "x", ["/" + "a" * 300])
        assert ei2.value.kind == "validation"

    def test_injected_client_is_reused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        body = {
            "status": "ok",
            "artifact_url": "/api/v1/artifacts/x.obj",
            "compiler_version": "12.0",
        }
        client = _FakeClient(_Resp(200, json_body=body), _Resp(200, content=b"OBJ"))
        # Must not construct a fresh httpx.Client when one is supplied.
        monkeypatch.setattr(
            httpx, "Client", lambda **kwargs: (_ for _ in ()).throw(AssertionError("no Client"))
        )
        res = compile_source("http://svc/", "msvc-6.0", "int f(void){}", ["/c"], client=client)
        assert res.ok and res.obj_bytes == b"OBJ"
        assert client.calls == [
            ("post", "http://svc/api/v1/compile"),
            ("get", "http://svc/api/v1/artifacts/x.obj"),
        ]

    def test_off_origin_artifact_url_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        body = {
            "status": "ok",
            "artifact_url": "http://169.254.169.254/latest/meta-data/",
        }
        client = _patch(monkeypatch, _Resp(200, json_body=body), _Resp(200, content=b"NO"))
        with pytest.raises(RecompileError, match="same-origin"):
            compile_source("http://svc", "msvc-6.0", "int f(void){}", ["/c"])
        assert client.calls == [("post", "http://svc/api/v1/compile")]

    def test_protocol_relative_artifact_url_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        body = {"status": "ok", "artifact_url": "//evil.example/steal"}
        client = _patch(monkeypatch, _Resp(200, json_body=body), _Resp(200, content=b"NO"))
        with pytest.raises(RecompileError, match="same-origin"):
            compile_source("http://svc", "msvc-6.0", "int f(void){}", ["/c"])
        assert client.calls == [("post", "http://svc/api/v1/compile")]

    def test_absolute_same_origin_artifact_url_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        body = {
            "status": "ok",
            "artifact_url": "http://svc/api/v1/artifacts/x.obj",
        }
        client = _patch(monkeypatch, _Resp(200, json_body=body), _Resp(200, content=b"OBJ"))
        res = compile_source("http://svc", "msvc-6.0", "int f(void){}", ["/c"])
        assert res.ok and res.obj_bytes == b"OBJ"
        assert client.calls == [
            ("post", "http://svc/api/v1/compile"),
            ("get", "http://svc/api/v1/artifacts/x.obj"),
        ]


class TestSameOriginArtifactUrl:
    def test_relative_path(self) -> None:
        assert (
            _same_origin_artifact_url("http://svc", "/api/v1/artifacts/x.obj")
            == "http://svc/api/v1/artifacts/x.obj"
        )

    def test_rejects_cross_host(self) -> None:
        with pytest.raises(RecompileError, match="same-origin"):
            _same_origin_artifact_url("http://svc", "https://svc/api/x")


class TestRecompileUrl:
    def test_env_wins_over_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = SimpleNamespace(recompile_url="http://cfg")
        monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://env")
        assert recompile_url(cfg) == "http://env"
        monkeypatch.delenv("REBREW_RECOMPILE_URL")
        assert recompile_url(cfg) == "http://cfg"

    def test_empty_means_local_backend(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("REBREW_RECOMPILE_URL", raising=False)
        assert recompile_url(SimpleNamespace(recompile_url="")) is None
        assert recompile_url(SimpleNamespace(recompile_url="   ")) is None

    @pytest.mark.parametrize("url", ["http://:8000", "http://localhost:99999", "http://[::1"])
    @pytest.mark.parametrize("from_env", [False, True])
    def test_invalid_authority_raises(
        self, monkeypatch: pytest.MonkeyPatch, url: str, from_env: bool
    ) -> None:
        monkeypatch.delenv("REBREW_RECOMPILE_URL", raising=False)
        cfg = SimpleNamespace(recompile_url=url)
        label = r"compiler\.recompile_url"
        if from_env:
            monkeypatch.setenv("REBREW_RECOMPILE_URL", url)
            cfg.recompile_url = "http://cfg"
            label = "REBREW_RECOMPILE_URL"
        with pytest.raises(ValueError, match=rf"{label} must be an http\(s\) URL"):
            recompile_url(cfg)

    def test_invalid_url_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("REBREW_RECOMPILE_URL", raising=False)
        with pytest.raises(ValueError, match=r"compiler\.recompile_url must be an http\(s\) URL"):
            recompile_url(SimpleNamespace(recompile_url="not-a-url"))
        monkeypatch.setenv("REBREW_RECOMPILE_URL", "ftp://evil")
        with pytest.raises(ValueError, match=r"REBREW_RECOMPILE_URL must be an http\(s\) URL"):
            recompile_url(SimpleNamespace(recompile_url="http://cfg"))


class TestCompileViaRecompile:
    def _cfg(self, url: str = "http://svc") -> SimpleNamespace:
        return SimpleNamespace(recompile_url=url, compile_timeout=60, recompile_emit_assembly=True)

    def test_writes_the_returned_artifact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.recompile_client as rc

        seen: dict[str, Any] = {}

        def fake(url: str, **kwargs: Any) -> Any:
            seen["url"] = url
            seen.update(kwargs)
            return rc.RecompileResult(ok=True, obj_bytes=b"\x01\x02")

        monkeypatch.setattr(rc, "compile_source", fake)
        src = tmp_path / "f.c"
        src.write_text("int f(void) { return 0; }")

        out, err = _compile_via_recompile(
            self._cfg(), src, ["/c"], tmp_path, "f.obj", "msvc-6.0", True
        )

        assert err == ""
        assert out is not None and Path(out).read_bytes() == b"\x01\x02"
        assert seen["compiler"] == "msvc-6.0"
        assert seen["emit_assembly"] is True
        assert seen["filename"] == "f.c"

    def test_service_failure_returns_the_log(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.recompile_client as rc

        monkeypatch.setattr(
            rc, "compile_source", lambda *a, **k: rc.RecompileResult(ok=False, log="error C2065")
        )
        src = tmp_path / "f.c"
        src.write_text("bad")
        out, err = _compile_via_recompile(
            self._cfg(), src, [], tmp_path, "f.obj", "msvc-6.0", False
        )
        assert out is None and "C2065" in err

    @pytest.mark.parametrize(
        ("response", "message"),
        [
            (b'{"status":', "non-JSON"),
            (b"[]", "JSON object"),
            (b"null", "JSON object"),
            (b'"unavailable"', "JSON object"),
            (b"{}", "status"),
            (b'{"status": "pending"}', "status"),
            (b'{"status": "ok"}', "artifact_url"),
            (b'{"status": "ok", "artifact_url": 123}', "artifact_url"),
        ],
    )
    def test_malformed_response_returns_service_error(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        response: bytes,
        message: str,
    ) -> None:
        monkeypatch.delenv("REBREW_RECOMPILE_URL", raising=False)
        client = _patch(monkeypatch, httpx.Response(200, content=response))

        out, err = _compile_via_recompile(
            self._cfg(),
            tmp_path / "f.c",
            [],
            tmp_path,
            "f.obj",
            "msvc-6.0",
            False,
            source_text="int f(void) { return 0; }",
        )

        assert out is None
        assert err.startswith("recompile service error:")
        assert message in err
        assert not (tmp_path / "f.obj").exists()
        assert client.calls == [("post", "http://svc/api/v1/compile")]

    def test_missing_url_is_a_bug(self, tmp_path: Path) -> None:
        src = tmp_path / "f.c"
        src.write_text("int f(void) {}")
        with pytest.raises(AssertionError):
            _compile_via_recompile(self._cfg(""), src, [], tmp_path, "f.obj", "msvc-6.0", False)
