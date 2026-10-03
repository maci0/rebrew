"""Tests for rebrew.recompile_client and the recompile backend selection."""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

import rebrew.compile as compile_mod
from rebrew.compile import _compile_via_recompile, recompile_url
from rebrew.config import DEFAULT_RECOMPILE_RETRIES
from rebrew.recompile_client import RecompileError, _same_origin_artifact_url, compile_source


def test_recompile_client_public_all() -> None:
    """Star-imports must not leak typing/stdlib names into consumer namespaces."""
    import rebrew.recompile_client as rc

    assert rc.__all__ == [
        "HttpClient",
        "HttpResponse",
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
        self.closed = False

    def json(self) -> Any:
        if self._json is None:
            raise ValueError("not json")
        return self._json

    def close(self) -> None:
        self.closed = True


class TestHttpProtocols:
    """The reply contract a consumer's test double has to satisfy."""

    def test_httpx_response_satisfies_http_response(self) -> None:
        from rebrew.recompile_client import HttpResponse

        assert isinstance(httpx.Response(200, content=b"\x90"), HttpResponse)

    def test_existing_stand_in_satisfies_http_response(self) -> None:
        from rebrew.recompile_client import HttpResponse

        assert isinstance(_Resp(200, json_body={"status": "ok"}), HttpResponse)

    def test_reply_without_content_is_rejected(self) -> None:
        """``obj_bytes`` comes off ``.content``; a stand-in without it is a bug.

        Typing the reply is what surfaces this at check time instead of
        handing a consumer a ``RecompileResult.obj_bytes`` holding whatever
        stand-in attribute happened to share the name.
        """
        from rebrew.recompile_client import HttpResponse

        class _NoContent:
            status_code = 200
            text = ""

            def json(self) -> Any:
                return {"status": "ok"}

        assert not isinstance(_NoContent(), HttpResponse)

    def test_httpx_client_satisfies_http_client(self) -> None:
        from rebrew.recompile_client import HttpClient

        assert isinstance(httpx.Client(), HttpClient)


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
        post = _Resp(200, json_body=body)
        get = _Resp(200, content=b"OBJ")
        client = _patch(monkeypatch, post, get)

        res = compile_source("http://svc/", "msvc-6.0", "int f(void){}", ["/c"])

        assert res.ok and res.obj_bytes == b"OBJ"
        assert res.compiler_version == "12.0"
        assert post.closed and get.closed
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

    def test_invalid_base_url_fails_fast(self) -> None:
        with pytest.raises(RecompileError, match="http\\(s\\)") as ei:
            compile_source("ftp://svc", "msvc-6.0", "x", [])
        assert ei.value.kind == "validation"
        assert ei.value.retryable is False

    def test_retries_retryable_http_then_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        body = {
            "status": "ok",
            "artifact_url": "/api/v1/artifacts/x.obj",
            "compiler_version": "12.0",
        }
        posts = [_Resp(503, text="busy"), _Resp(200, json_body=body)]
        gets = [_Resp(200, content=b"OBJ")]

        class _SeqClient(_FakeClient):
            def post(self, url: str, json: Any = None) -> Any:
                self.calls.append(("post", url))
                return posts.pop(0)

            def get(self, url: str) -> Any:
                self.calls.append(("get", url))
                return gets.pop(0)

        client = _SeqClient(None)
        monkeypatch.setattr(httpx, "Client", lambda **kwargs: client)
        sleeps: list[float] = []
        monkeypatch.setattr("rebrew.recompile_client.time.sleep", lambda s: sleeps.append(s))
        res = compile_source("http://svc/", "msvc-6.0", "int f(void){}", ["/c"], retries=1)
        assert res.ok and res.obj_bytes == b"OBJ"
        assert len([c for c in client.calls if c[0] == "post"]) == 2
        assert sleeps == [0.25]  # first retry: base * 2**0

    def test_injected_sleep_carries_the_retry_backoff(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The backoff goes through the injected clock, so a replay needs no real wait."""
        body = {
            "status": "ok",
            "artifact_url": "/api/v1/artifacts/x.obj",
            "compiler_version": "12.0",
        }
        posts = [_Resp(503, text="busy"), _Resp(200, json_body=body)]
        gets = [_Resp(200, content=b"OBJ")]

        class _SeqClient(_FakeClient):
            def post(self, url: str, json: Any = None) -> Any:
                self.calls.append(("post", url))
                return posts.pop(0)

            def get(self, url: str) -> Any:
                self.calls.append(("get", url))
                return gets.pop(0)

        client = _SeqClient(None)
        monkeypatch.setattr(httpx, "Client", lambda **kwargs: client)
        naps: list[float] = []
        res = compile_source(
            "http://svc/", "msvc-6.0", "int f(void){}", ["/c"], retries=1, sleep=naps.append
        )
        assert res.ok and res.obj_bytes == b"OBJ"
        assert naps == [0.25]

    def test_a_retry_is_logged_with_attempt_delay_and_cause(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A failing remote backend must not back off in silence.

        The line is what tells an operator which dependency faulted, how many
        attempts are left, and how long the run is about to wait.
        """
        posts = [_Resp(503, text="busy"), _Resp(503, text="busy"), _Resp(503, text="busy")]

        class _SeqClient(_FakeClient):
            def post(self, url: str, json: Any = None) -> Any:
                self.calls.append(("post", url))
                return posts.pop(0)

        client = _SeqClient(None)
        monkeypatch.setattr(httpx, "Client", lambda **kwargs: client)
        with (
            caplog.at_level(logging.WARNING, logger="rebrew.recompile_client"),
            pytest.raises(RecompileError),
        ):
            compile_source(
                "http://svc/",
                "msvc-6.0",
                "int f(void){}",
                ["/c"],
                retries=2,
                sleep=lambda _s: None,
            )
        lines = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert len(lines) == 3
        assert "http://svc" in lines[0]
        assert "attempt 1/3" in lines[0] and "attempt 2/3" in lines[1]
        assert "http 503" in lines[0]
        assert "retrying in 0.25s" in lines[0] and "retrying in 0.50s" in lines[1]
        # The exhausted run closes with its own record: the two above only
        # say a retry is coming, so without this the log ends mid-sequence and
        # a run that gave up is indistinguishable from one still waiting.
        assert "gave up after 3 attempt(s)" in lines[2]
        assert "http 503" in lines[2]

    def test_a_terminal_failure_is_logged_without_any_retry(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """``retries=0`` (the batch default) must still leave a record.

        The retry lines only exist between attempts, so a single-shot call
        against a backend that is down logged nothing: the caller turned the
        raise into a per-source compile error and the log stream — the one a
        batch or GA run is read through — could not name the faulting
        dependency.
        """
        client = _FakeClient(_Resp(503, text="down"))
        monkeypatch.setattr(httpx, "Client", lambda **kwargs: client)
        with (
            caplog.at_level(logging.WARNING, logger="rebrew.recompile_client"),
            pytest.raises(RecompileError),
        ):
            compile_source("http://svc/", "msvc-6.0", "int f(void){}", ["/c"])
        lines = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert len(lines) == 1
        assert "gave up after 1 attempt(s)" in lines[0]
        assert "http://svc" in lines[0]
        assert "http 503" in lines[0]

    def test_retries_artifact_get_without_repost(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """After a successful compile POST, retries must not re-POST.

        ``emit_assembly=True`` appends a train.jsonl row per successful
        compile; a lost artifact GET must only re-download.
        """
        body = {
            "status": "ok",
            "artifact_url": "/api/v1/artifacts/x.obj",
            "compiler_version": "12.0",
            "log": "",
        }
        posts = [_Resp(200, json_body=body)]
        gets = [_Resp(503, text="busy"), _Resp(200, content=b"OBJ")]

        class _SeqClient(_FakeClient):
            def post(self, url: str, json: Any = None) -> Any:
                self.calls.append(("post", url))
                assert json.get("emit_assembly") is True
                return posts.pop(0)

            def get(self, url: str) -> Any:
                self.calls.append(("get", url))
                return gets.pop(0)

        client = _SeqClient(None)
        monkeypatch.setattr(httpx, "Client", lambda **kwargs: client)
        sleeps: list[float] = []
        monkeypatch.setattr("rebrew.recompile_client.time.sleep", lambda s: sleeps.append(s))
        res = compile_source(
            "http://svc/",
            "msvc-6.0",
            "int f(void){}",
            ["/c"],
            emit_assembly=True,
            retries=1,
        )
        assert res.ok and res.obj_bytes == b"OBJ"
        assert [c[0] for c in client.calls] == ["post", "get", "get"]
        assert sleeps == [0.25]

    @pytest.mark.parametrize(
        "first",
        [_Resp(502, text="bad gateway"), httpx.ReadTimeout("lost reply")],
        ids=["http-502", "read-timeout"],
    )
    def test_emit_assembly_no_repost_after_ambiguous_failure(
        self, monkeypatch: pytest.MonkeyPatch, first: Any
    ) -> None:
        """A 5xx or lost reply may follow a compile that already appended its
        train.jsonl row, so an ``emit_assembly`` POST is not re-sent."""

        class _SeqClient(_FakeClient):
            def post(self, url: str, json: Any = None) -> Any:
                self.calls.append(("post", url))
                if isinstance(first, Exception):
                    raise first
                return first

        client = _SeqClient(None)
        monkeypatch.setattr(httpx, "Client", lambda **kwargs: client)
        monkeypatch.setattr("rebrew.recompile_client.time.sleep", lambda s: None)
        with pytest.raises(RecompileError) as ei:
            compile_source("http://svc/", "msvc-6.0", "x", ["/c"], emit_assembly=True, retries=2)
        assert ei.value.retryable is False
        assert [c[0] for c in client.calls] == ["post"]

    @pytest.mark.parametrize(
        "first",
        [_Resp(503, text="busy"), httpx.ConnectError("refused")],
        ids=["http-503", "connect-error"],
    )
    def test_emit_assembly_reposts_when_never_processed(
        self, monkeypatch: pytest.MonkeyPatch, first: Any
    ) -> None:
        body = {"status": "ok", "artifact_url": "/api/v1/artifacts/x.obj"}
        posts: list[Any] = [first, _Resp(200, json_body=body)]

        class _SeqClient(_FakeClient):
            def post(self, url: str, json: Any = None) -> Any:
                self.calls.append(("post", url))
                nxt = posts.pop(0)
                if isinstance(nxt, Exception):
                    raise nxt
                return nxt

            def get(self, url: str) -> Any:
                self.calls.append(("get", url))
                return _Resp(200, content=b"OBJ")

        client = _SeqClient(None)
        monkeypatch.setattr(httpx, "Client", lambda **kwargs: client)
        monkeypatch.setattr("rebrew.recompile_client.time.sleep", lambda s: None)
        res = compile_source("http://svc/", "msvc-6.0", "x", ["/c"], emit_assembly=True, retries=1)
        assert res.ok and res.obj_bytes == b"OBJ"
        assert [c[0] for c in client.calls] == ["post", "post", "get"]

    def test_retries_do_not_retry_validation(self) -> None:
        with pytest.raises(RecompileError, match="too many flags") as ei:
            compile_source("http://svc", "msvc-6.0", "x", ["/c"] * 65, retries=3)
        assert ei.value.kind == "validation"

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

    def test_empty_env_forces_local_over_toml(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Present-but-empty REBREW_RECOMPILE_URL disables a TOML remote URL."""
        monkeypatch.setenv("REBREW_RECOMPILE_URL", "")
        assert recompile_url(SimpleNamespace(recompile_url="http://cfg")) is None

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
    def test_shutdown_closes_other_clients_after_one_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        closed: list[str] = []

        class _Client:
            def __init__(self, name: str, fails: bool = False) -> None:
                self.name = name
                self.fails = fails

            def close(self) -> None:
                closed.append(self.name)
                if self.fails:
                    raise RuntimeError("close failed")

        monkeypatch.setattr(compile_mod, "_recompile_clients", {10.0: _Client("first")})
        monkeypatch.setattr(compile_mod, "_recompile_retired", [_Client("retired", fails=True)])
        with pytest.raises(RuntimeError, match="close failed"):
            compile_mod._close_recompile_client()
        assert closed == ["retired", "first"]
        assert compile_mod._recompile_clients == {} and compile_mod._recompile_retired == []
        compile_mod._close_recompile_client()
        assert closed == ["retired", "first"]

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
        assert seen["retries"] == 2

    def test_retry_count_comes_from_the_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``[compiler] recompile_retries`` is the retry count, 0 included."""
        import rebrew.recompile_client as rc

        seen: dict[str, Any] = {}

        def fake(url: str, **kwargs: Any) -> Any:
            seen.update(kwargs)
            return rc.RecompileResult(ok=True, obj_bytes=b"\x01")

        monkeypatch.setattr(rc, "compile_source", fake)
        src = tmp_path / "f.c"
        src.write_text("int f(void) { return 0; }")

        cfg = self._cfg()
        cfg.recompile_retries = 0
        _compile_via_recompile(cfg, src, ["/c"], tmp_path, "f.obj", "msvc-6.0", False)
        assert seen["retries"] == 0

        cfg.recompile_retries = 4
        _compile_via_recompile(cfg, src, ["/c"], tmp_path, "g.obj", "msvc-6.0", False)
        assert seen["retries"] == 4

    def test_retry_count_falls_back_without_the_config_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A config object predating the field keeps the documented default."""
        import rebrew.recompile_client as rc

        seen: dict[str, Any] = {}

        def fake(url: str, **kwargs: Any) -> Any:
            seen.update(kwargs)
            return rc.RecompileResult(ok=True, obj_bytes=b"\x01")

        monkeypatch.setattr(rc, "compile_source", fake)
        src = tmp_path / "f.c"
        src.write_text("int f(void) { return 0; }")
        _compile_via_recompile(self._cfg(), src, ["/c"], tmp_path, "f.obj", "msvc-6.0", False)
        assert seen["retries"] == DEFAULT_RECOMPILE_RETRIES

    def test_compiles_share_one_http_client(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One pooled client serves every compile; a per-compile client
        leaves a TIME_WAIT socket behind per GA candidate."""
        body = {"status": "ok", "artifact_url": "/api/v1/artifacts/x.obj"}
        made: list[_FakeClient] = []

        def factory(**kwargs: Any) -> _FakeClient:
            client = _FakeClient(
                httpx.Response(200, json=body), httpx.Response(200, content=b"OBJ")
            )
            made.append(client)
            return client

        monkeypatch.delenv("REBREW_RECOMPILE_URL", raising=False)
        monkeypatch.setattr(compile_mod, "_recompile_clients", {})
        monkeypatch.setattr(httpx, "Client", factory)
        for name in ("a.obj", "b.obj"):
            out, err = _compile_via_recompile(
                self._cfg(),
                tmp_path / "f.c",
                [],
                tmp_path,
                name,
                "msvc-6.0",
                False,
                source_text="int f(void) { return 0; }",
            )
            assert err == "" and out is not None
            assert Path(out).read_bytes() == b"OBJ"
        assert len(made) == 1
        assert [c for c, _ in made[0].calls] == ["post", "get", "post", "get"]

    def test_timeout_change_keeps_the_in_use_client_open(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A second timeout gets its own client; closing the first would fail
        a request another thread still has in flight on it."""
        closed: list[float] = []

        class _Closable:
            def __init__(self, timeout: float) -> None:
                self.timeout = timeout

            def close(self) -> None:
                closed.append(self.timeout)

        monkeypatch.setattr(compile_mod, "_recompile_clients", {})
        monkeypatch.setattr(httpx, "Client", lambda timeout: _Closable(timeout))
        first = compile_mod._shared_recompile_client(10.0)
        second = compile_mod._shared_recompile_client(20.0)
        assert first is not second
        assert compile_mod._shared_recompile_client(10.0) is first
        assert closed == []
        compile_mod._close_recompile_client()
        assert sorted(closed) == [10.0, 20.0]

    def test_client_pool_is_bounded_by_lru_cap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A process walking many project roots must not keep a connection
        pool per distinct ``compile_timeout`` — the socket exhaustion the
        shared client exists to prevent.  The evicted pool is closed, so its
        keep-alive sockets do not linger either."""
        import httpx

        closed: list[float] = []

        class _Closable:
            def __init__(self, timeout: float) -> None:
                self.timeout = timeout

            def close(self) -> None:
                closed.append(self.timeout)

        monkeypatch.setattr(compile_mod, "_RECOMPILE_CLIENTS_MAX", 2)
        monkeypatch.setattr(compile_mod, "_recompile_clients", {})
        monkeypatch.setattr(compile_mod, "_recompile_retired", [])
        monkeypatch.setattr(compile_mod, "_recompile_inflight", {})
        monkeypatch.setattr(httpx, "Client", lambda timeout: _Closable(timeout))
        first = compile_mod._shared_recompile_client(10.0)
        second = compile_mod._shared_recompile_client(20.0)
        # Refresh the first so the *second* is the eviction victim.
        assert compile_mod._shared_recompile_client(10.0) is first
        third = compile_mod._shared_recompile_client(30.0)
        assert sorted(compile_mod._recompile_clients) == [10.0, 30.0]
        # Acquisition retains, so the victim is still held by this test and
        # eviction defers its close until the last release.
        assert closed == []
        assert compile_mod._recompile_retired == [second]
        compile_mod._recompile_release(second)
        assert closed == [20.0]
        assert compile_mod._shared_recompile_client(20.0) is not second
        assert compile_mod._shared_recompile_client(30.0) is third
        compile_mod._recompile_release(first)
        compile_mod._recompile_release(third)

    def test_evicted_client_in_use_is_closed_on_release(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An eviction that lands on a client another thread still holds must
        not close it out from under that request; the last release closes it."""
        import httpx

        closed: list[float] = []

        class _Closable:
            def __init__(self, timeout: float) -> None:
                self.timeout = timeout

            def close(self) -> None:
                closed.append(self.timeout)

        monkeypatch.setattr(compile_mod, "_RECOMPILE_CLIENTS_MAX", 1)
        monkeypatch.setattr(compile_mod, "_recompile_clients", {})
        monkeypatch.setattr(compile_mod, "_recompile_retired", [])
        monkeypatch.setattr(compile_mod, "_recompile_inflight", {})
        monkeypatch.setattr(httpx, "Client", lambda timeout: _Closable(timeout))
        held = compile_mod._shared_recompile_client(10.0)
        compile_mod._shared_recompile_client(20.0)
        assert closed == []
        compile_mod._recompile_release(held)
        assert closed == [10.0]
        assert compile_mod._recompile_retired == []
        compile_mod._close_recompile_client()
        assert sorted(closed) == [10.0, 20.0]

    def test_acquisition_retains_so_no_interleaving_can_close_a_handed_out_client(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Retention must happen in the same critical section as the handout.

        When it was a separate lock acquisition, a thread that had just been
        given a client but had not yet retained it could be raced by an
        eviction that read a zero inflight count and closed the client out
        from under the request that was about to use it.
        """
        import httpx

        closed: list[float] = []

        class _Closable:
            def __init__(self, timeout: float) -> None:
                self.timeout = timeout

            def close(self) -> None:
                closed.append(self.timeout)

        monkeypatch.setattr(compile_mod, "_RECOMPILE_CLIENTS_MAX", 1)
        monkeypatch.setattr(compile_mod, "_recompile_clients", {})
        monkeypatch.setattr(compile_mod, "_recompile_retired", [])
        monkeypatch.setattr(compile_mod, "_recompile_inflight", {})
        monkeypatch.setattr(httpx, "Client", lambda timeout: _Closable(timeout))
        # No retain call: the handout alone must make the client unevictable.
        held = compile_mod._shared_recompile_client(10.0)
        assert compile_mod._recompile_inflight[id(held)] == 1
        compile_mod._shared_recompile_client(20.0)
        assert closed == []
        compile_mod._recompile_release(held)
        assert closed == [10.0]

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
        monkeypatch.setattr(compile_mod, "_recompile_clients", {})
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
        with pytest.raises(AssertionError, match="recompile backend selected without a URL"):
            _compile_via_recompile(self._cfg(""), src, [], tmp_path, "f.obj", "msvc-6.0", False)

    def test_service_error_is_recorded_for_the_caller(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The structured error reaches the caller, not just the message."""
        import rebrew.recompile_client as rc

        def fake(*a: Any, **k: Any) -> Any:
            raise RecompileError("503 from svc", kind="http", status_code=503, retryable=True)

        monkeypatch.setattr(rc, "compile_source", fake)
        errors: list[BaseException] = []
        out, err = _compile_via_recompile(
            self._cfg(),
            tmp_path / "f.c",
            [],
            tmp_path,
            "f.obj",
            "msvc-6.0",
            False,
            source_text="int f(void) { return 0; }",
            backend_errors=errors,
        )

        assert out is None and err.startswith("recompile service error:")
        assert [type(e) for e in errors] == [RecompileError]
        assert errors[0].kind == "http"  # type: ignore[attr-defined]
        assert errors[0].status_code == 503  # type: ignore[attr-defined]
        assert errors[0].retryable is True

    def test_compare_result_carries_the_service_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A consumer of compile_and_compare branches on result.error, not
        on message substrings."""
        import rebrew.recompile_client as rc
        from rebrew.compile import compile_and_compare

        def fake(*a: Any, **k: Any) -> Any:
            raise RecompileError("connection refused", kind="network", retryable=True)

        monkeypatch.setattr(rc, "compile_source", fake)
        monkeypatch.setattr(compile_mod, "_recompile_clients", {})
        src = tmp_path / "f.c"
        src.write_text("int f(void) { return 0; }")
        cfg = SimpleNamespace(
            root=tmp_path,
            recompile_url="http://svc",
            recompile_emit_assembly=False,
            compile_timeout=30,
            compiler_profile="msvc-6.0",
            compiler_command="",
            base_cflags="",
            compiler_includes=tmp_path,
            compiler_runner="",
        )

        result = compile_and_compare(
            cfg,
            src,
            "_f",
            b"\x55\x8b\xec",
            [],
            use_cache=False,
        )

        assert result.status == "COMPILE_ERROR"
        assert isinstance(result.error, RecompileError)
        assert result.error.kind == "network"
        assert result.error.retryable is True
