"""Tests for rebrew.compiler.recompile_client and the recompile backend selection."""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

import rebrew.compiler.compile as compile_mod
from rebrew.compiler.compile import _compile_via_recompile, recompile_url
from rebrew.compiler.recompile_client import (
    RecompileError,
    _same_origin_artifact_url,
    compile_source,
)
from rebrew.config import DEFAULT_RECOMPILE_CONCURRENCY, DEFAULT_RECOMPILE_RETRIES


def test_recompile_client_public_all() -> None:
    """Star-imports must not leak typing/stdlib names into consumer namespaces."""
    import rebrew.compiler.recompile_client as rc

    assert rc.__all__ == [
        "INCLUDE_BUNDLES_FEATURE",
        "MAX_INCLUDE_FILES",
        "MAX_INCLUDE_FILE_BYTES",
        "MAX_INCLUDE_PATH_BYTES",
        "MAX_INCLUDE_TOTAL_BYTES",
        "MAX_RETRY_AFTER_SECONDS",
        "HttpClient",
        "HttpResponse",
        "RecompileError",
        "RecompileErrorKind",
        "RecompileResult",
        "ServiceGate",
        "accepts_include_bundles",
        "compile_source",
    ]
    for name in rc.__all__:
        assert getattr(rc, name, None) is not None, name
    ns: dict[str, Any] = {}
    exec("from rebrew.compiler.recompile_client import *", ns)  # noqa: S102
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
        headers: Any = None,
    ) -> None:
        self.status_code = status_code
        self._json = json_body
        self.content = content
        self.text = text
        self.headers = dict(headers or {})
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
        from rebrew.compiler.recompile_client import HttpResponse

        assert isinstance(httpx.Response(200, content=b"\x90"), HttpResponse)

    def test_existing_stand_in_satisfies_http_response(self) -> None:
        from rebrew.compiler.recompile_client import HttpResponse

        assert isinstance(_Resp(200, json_body={"status": "ok"}), HttpResponse)

    def test_reply_without_content_is_rejected(self) -> None:
        """``obj_bytes`` comes off ``.content``; a stand-in without it is a bug.

        Typing the reply is what surfaces this at check time instead of
        handing a consumer a ``RecompileResult.obj_bytes`` holding whatever
        stand-in attribute happened to share the name.
        """
        from rebrew.compiler.recompile_client import HttpResponse

        class _NoContent:
            status_code = 200
            text = ""

            def json(self) -> Any:
                return {"status": "ok"}

        assert not isinstance(_NoContent(), HttpResponse)

    def test_httpx_client_satisfies_http_client(self) -> None:
        from rebrew.compiler.recompile_client import HttpClient

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

    def post(
        self,
        url: str,
        json: Any = None,
        headers: Any = None,
        follow_redirects: bool = False,
    ) -> Any:
        self.calls.append(("post", url))
        if isinstance(self._post, Exception):
            raise self._post
        return self._post

    def get(self, url: str, headers: Any = None, follow_redirects: bool = False) -> Any:
        self.calls.append(("get", url))
        if isinstance(self._get, Exception):
            raise self._get
        return self._get


def _patch(monkeypatch: pytest.MonkeyPatch, post: Any, get: Any = None) -> _FakeClient:
    client = _FakeClient(post, get)
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: client)
    return client


def _sequence_client(
    monkeypatch: pytest.MonkeyPatch, posts: list[_Resp], gets: list[_Resp] | None = None
) -> _FakeClient:
    """Install a client replaying *posts* and *gets* in order."""
    replies = gets or []

    class _SeqClient(_FakeClient):
        def post(
            self,
            url: str,
            json: Any = None,
            headers: Any = None,
            follow_redirects: bool = False,
        ) -> Any:
            self.calls.append(("post", url))
            return posts.pop(0)

        def get(self, url: str, headers: Any = None, follow_redirects: bool = False) -> Any:
            self.calls.append(("get", url))
            return replies.pop(0)

    client = _SeqClient(None)
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

    def test_execution_provenance_is_carried_verbatim_or_absent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        execution = {"status": "admitted", "kind": "image", "digest": "sha256:abc"}
        body = {"status": "ok", "artifact_url": "/api/v1/artifacts/x.obj", "execution": execution}
        _patch(monkeypatch, _Resp(200, json_body=body), _Resp(200, content=b"OBJ"))
        assert (
            compile_source("http://svc/", "msvc-6.0", "int f(void){}", ["/c"]).execution
            == execution
        )
        body = {"status": "ok", "artifact_url": "/api/v1/artifacts/x.obj"}
        _patch(monkeypatch, _Resp(200, json_body=body), _Resp(200, content=b"OBJ"))
        assert compile_source("http://svc/", "msvc-6.0", "int f(void){}", ["/c"]).execution is None

    def test_toolchain_failure_is_not_ok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        body = {"status": "error", "error_code": "toolchain_failure", "log": "syntax error"}
        _patch(monkeypatch, _Resp(200, json_body=body))
        res = compile_source("http://svc", "msvc-6.0", "bad", [])
        assert not res.ok and "syntax error" in res.log

    @pytest.mark.parametrize(
        "code",
        ["capacity", "timeout", "runner_unavailable", "publish_failed", "provenance_unavailable"],
    )
    def test_infrastructure_failure_is_a_retryable_service_error(
        self, monkeypatch: pytest.MonkeyPatch, code: str
    ) -> None:
        """recompile answers its own failures with HTTP 200 and an ``error_code``.

        They were read as the compiler rejecting the source, so verify recorded
        COMPILE_ERROR over the function and nothing retried.
        """
        body = {"status": "error", "error_code": code, "log": "server at capacity (max 4)"}
        _patch(monkeypatch, _Resp(200, json_body=body))
        with pytest.raises(RecompileError, match=f"could not compile \\({code}\\)") as ei:
            compile_source("http://svc", "msvc-6.0", "int f(void){}", [])
        assert ei.value.kind == "service"
        assert ei.value.error_code == code
        assert ei.value.retryable is True
        assert ei.value.to_dict()["error_code"] == code

    @pytest.mark.parametrize("code", ["missing_artifact", "replay_rejected"])
    def test_store_failure_is_a_service_error_that_is_not_retried(
        self, monkeypatch: pytest.MonkeyPatch, code: str
    ) -> None:
        body = {"status": "error", "error_code": code, "log": "job id is already associated"}
        client = _patch(monkeypatch, _Resp(200, json_body=body))
        sleeps: list[float] = []
        with pytest.raises(RecompileError) as ei:
            compile_source("http://svc", "msvc-6.0", "x", [], retries=2, sleep=sleeps.append)
        assert (ei.value.kind, ei.value.error_code, ei.value.retryable) == ("service", code, False)
        assert len(client.calls) == 1 and sleeps == []

    @pytest.mark.parametrize("code", [None, "", "new_kind", ["capacity"], {"a": 1}])
    def test_failure_without_a_known_code_is_a_protocol_error(
        self, monkeypatch: pytest.MonkeyPatch, code: Any
    ) -> None:
        """Without a known code the reply cannot say whose failure it was."""
        body: dict[str, Any] = {"status": "error", "log": "x"}
        if code is not None:
            body["error_code"] = code
        _patch(monkeypatch, _Resp(200, json_body=body))
        with pytest.raises(RecompileError, match="error_code") as ei:
            compile_source("http://svc", "msvc-6.0", "x", [])
        assert (ei.value.kind, ei.value.retryable) == ("protocol", False)

    def test_infrastructure_failure_is_retried_as_a_new_attempt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The refused attempt is over: the retry sends a new key.

        A hosted recompile keeps a capacity refusal under its key, so a retry
        with the same key would read the refusal back.
        """
        keys: list[str] = []
        refusal = {"status": "error", "error_code": "capacity", "log": "server at capacity"}
        replies = [
            _Resp(200, json_body=refusal),
            _Resp(200, json_body={"status": "ok", "artifact_url": "/api/v1/artifacts/x.obj"}),
        ]

        class _Keyed(_FakeClient):
            def post(self, url: str, json: Any = None, headers: Any = None, **_: Any) -> Any:
                keys.append(headers["Idempotency-Key"])
                return replies.pop(0)

        client = _Keyed(None, _Resp(200, content=b"OBJ"))
        sleeps: list[float] = []
        res = compile_source(
            "http://svc", "msvc-6.0", "x", [], client=client, retries=1, sleep=sleeps.append
        )
        assert res.ok and res.obj_bytes == b"OBJ"
        assert len(keys) == 2 and keys[0] != keys[1]
        assert sleeps == [0.25]

    @pytest.mark.parametrize(("code", "retryable"), [("capacity", True), ("timeout", False)])
    def test_emit_assembly_retries_only_a_compile_that_never_ran(
        self, monkeypatch: pytest.MonkeyPatch, code: str, retryable: bool
    ) -> None:
        """Same rule as the HTTP statuses: an older service may have kept the listing."""
        body = {"status": "error", "error_code": code, "log": "x"}
        _patch(monkeypatch, _Resp(200, json_body=body))
        with pytest.raises(RecompileError) as ei:
            compile_source("http://svc", "msvc-6.0", "x", [], emit_assembly=True)
        assert ei.value.retryable is retryable

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

    def test_flag_caps_are_enforced(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with pytest.raises(RecompileError, match="too many flags") as ei:
            compile_source("http://svc", "msvc-6.0", "x", ["/c"] * 65)
        assert ei.value.kind == "validation"
        assert ei.value.retryable is False
        with pytest.raises(RecompileError, match="flag too long") as ei2:
            compile_source("http://svc", "msvc-6.0", "x", ["/" + "a" * 300])
        assert ei2.value.kind == "validation"
        # The service caps the NFC form's UTF-8 bytes, not Python characters.
        # The slash plus 200 two-byte code points is 401 bytes: counting
        # characters posted it and the service answered 422.
        with pytest.raises(RecompileError, match="401 > 256 UTF-8 bytes") as ei3:
            compile_source("http://svc", "msvc-6.0", "x", ["/" + "é" * 200])
        assert ei3.value.kind == "validation"
        # A decomposed spelling whose composed form fits is sent composed, the
        # form the service fingerprints, so the posted flag is under the cap.
        sent: dict[str, Any] = {}

        class _Recording(_FakeClient):
            def post(self, url: str, json: Any = None, headers: Any = None, **_: Any) -> Any:
                sent["flags"] = json["flags"]
                return _Resp(422, text="stop before the artifact")

        monkeypatch.setattr(httpx, "Client", lambda **kwargs: _Recording(None))
        decomposed = "/" + "e\u0301" * 100
        assert len(decomposed.encode("utf-8")) > 256
        with pytest.raises(RecompileError, match="HTTP 422"):
            compile_source("http://svc", "msvc-6.0", "x", [decomposed])
        assert sent["flags"] == ["/" + "é" * 100]

    def test_invalid_base_url_fails_fast(self) -> None:
        with pytest.raises(RecompileError, match="http\\(s\\)") as ei:
            compile_source("ftp://svc", "msvc-6.0", "x", [])
        assert ei.value.kind == "validation"
        assert ei.value.retryable is False

    @pytest.mark.parametrize(
        ("source", "flags", "named"),
        [
            # A cp1252 comment read with surrogateescape, as compile_to_obj reads it.
            (
                b"/* caf\xe9 */ int f(void){return 0;}".decode("utf-8", "surrogateescape"),
                [],
                "source",
            ),
            ("int f(void){return 0;}", ["/D" + b"\xe9".decode("utf-8", "surrogateescape")], "flag"),
        ],
    )
    def test_text_that_is_not_utf8_is_refused_before_any_request(
        self, monkeypatch: pytest.MonkeyPatch, source: str, flags: list[str], named: str
    ) -> None:
        """The service compiles UTF-8 text only, so the request could never be sent.

        httpx raised ``UnicodeEncodeError`` while encoding the body, which the
        client reported as an unreachable service and retried.
        """
        client = _patch(monkeypatch, _Resp(200, json_body={"status": "ok"}))
        sleeps: list[float] = []
        with pytest.raises(RecompileError, match=f"{named} is not UTF-8") as ei:
            compile_source("http://svc", "msvc-6.0", source, flags, retries=2, sleep=sleeps.append)
        assert ei.value.kind == "validation"
        assert ei.value.retryable is False
        assert client.calls == [] and sleeps == []

    def test_retries_retryable_http_then_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        body = {
            "status": "ok",
            "artifact_url": "/api/v1/artifacts/x.obj",
            "compiler_version": "12.0",
        }
        client = _sequence_client(
            monkeypatch,
            [_Resp(503, text="busy"), _Resp(200, json_body=body)],
            [_Resp(200, content=b"OBJ")],
        )
        sleeps: list[float] = []
        monkeypatch.setattr(
            "rebrew.compiler.recompile_client.time.sleep", lambda s: sleeps.append(s)
        )
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
        _sequence_client(
            monkeypatch,
            [_Resp(503, text="busy"), _Resp(200, json_body=body)],
            [_Resp(200, content=b"OBJ")],
        )
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
        posts = [_Resp(503, text="busy") for _ in range(3)]
        _sequence_client(monkeypatch, posts)
        with (
            caplog.at_level(logging.WARNING, logger="rebrew.compiler.recompile_client"),
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
            caplog.at_level(logging.WARNING, logger="rebrew.compiler.recompile_client"),
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
            def post(
                self,
                url: str,
                json: Any = None,
                headers: Any = None,
                follow_redirects: bool = False,
            ) -> Any:
                self.calls.append(("post", url))
                assert json.get("emit_assembly") is True
                return posts.pop(0)

            def get(self, url: str, headers: Any = None, follow_redirects: bool = False) -> Any:
                self.calls.append(("get", url))
                return gets.pop(0)

        client = _SeqClient(None)
        monkeypatch.setattr(httpx, "Client", lambda **kwargs: client)
        sleeps: list[float] = []
        monkeypatch.setattr(
            "rebrew.compiler.recompile_client.time.sleep", lambda s: sleeps.append(s)
        )
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
            def post(
                self,
                url: str,
                json: Any = None,
                headers: Any = None,
                follow_redirects: bool = False,
            ) -> Any:
                self.calls.append(("post", url))
                if isinstance(first, Exception):
                    raise first
                return first

        client = _SeqClient(None)
        monkeypatch.setattr(httpx, "Client", lambda **kwargs: client)
        monkeypatch.setattr("rebrew.compiler.recompile_client.time.sleep", lambda s: None)
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
            def post(
                self,
                url: str,
                json: Any = None,
                headers: Any = None,
                follow_redirects: bool = False,
            ) -> Any:
                self.calls.append(("post", url))
                nxt = posts.pop(0)
                if isinstance(nxt, Exception):
                    raise nxt
                return nxt

            def get(self, url: str, headers: Any = None, follow_redirects: bool = False) -> Any:
                self.calls.append(("get", url))
                return _Resp(200, content=b"OBJ")

        client = _SeqClient(None)
        monkeypatch.setattr(httpx, "Client", lambda **kwargs: client)
        monkeypatch.setattr("rebrew.compiler.recompile_client.time.sleep", lambda s: None)
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

    @pytest.mark.parametrize(
        "artifact", ["//[", "//[]", "//[]0", "//][", "http://[", "http://svc\uff0f/x"]
    )
    def test_malformed_artifact_url_is_rejected_before_fetch(
        self, monkeypatch: pytest.MonkeyPatch, artifact: str
    ) -> None:
        body = {"status": "ok", "artifact_url": artifact}
        client = _patch(monkeypatch, _Resp(200, json_body=body), _Resp(200, content=b"NO"))
        with pytest.raises(RecompileError) as ei:
            compile_source("http://svc", "msvc-6.0", "int f(void){}", ["/c"], retries=2)
        assert ei.value.kind == "protocol"
        assert not ei.value.retryable
        assert client.calls == [("post", "http://svc/api/v1/compile")]

    @pytest.mark.parametrize("base", ["http://[", "http://[]", "http://svc\uff0f"])
    def test_malformed_base_url_is_rejected_before_request(
        self, monkeypatch: pytest.MonkeyPatch, base: str
    ) -> None:
        client = _patch(monkeypatch, _Resp(200, json_body={}), _Resp(200, content=b"NO"))
        with pytest.raises(RecompileError) as ei:
            compile_source(base, "msvc-6.0", "int f(void){}", ["/c"])
        assert ei.value.kind == "validation"
        assert client.calls == []


class TestArtifactRedirects:
    @pytest.mark.parametrize("authenticated", [False, True])
    @pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
    def test_artifact_fetch_refuses_redirects_with_redirecting_client(
        self, monkeypatch: pytest.MonkeyPatch, authenticated: bool, status: int
    ) -> None:
        monkeypatch.delenv("REBREW_RECOMPILE_API_KEY", raising=False)
        if authenticated:
            monkeypatch.setenv("REBREW_RECOMPILE_API_KEY", "fixture-key")
        requested = []

        def respond(request: httpx.Request) -> httpx.Response:
            requested.append(str(request.url))
            if request.method == "POST":
                return httpx.Response(200, json={"status": "ok", "artifact_url": "/object.obj"})
            if request.url.host == "compiler.invalid":
                return httpx.Response(status, headers={"Location": "https://foreign.invalid/data"})
            return httpx.Response(200, content=b"foreign payload")

        with (
            httpx.Client(transport=httpx.MockTransport(respond), follow_redirects=True) as client,
            pytest.raises(RecompileError) as error,
        ):
            compile_source(
                "https://compiler.invalid", "msvc-6.0", "int f(void){}", ["/c"], client=client
            )
        assert error.value.kind == "http"
        assert error.value.status_code == status
        assert requested == [
            "https://compiler.invalid/api/v1/compile",
            "https://compiler.invalid/object.obj",
        ]


class TestArtifactLength:
    @pytest.mark.parametrize(
        ("declared", "refused"),
        [
            ("²", True),
            ("9" * 5000, True),
            ("31457281", True),
            ("3", False),
            ("n/a", False),
            ("", False),
        ],
        ids=["nondecimal-digit", "integer-limit", "oversize", "valid", "nonnumeric", "missing"],
    )
    def test_content_length_cannot_escape_the_protocol_error_path(
        self, monkeypatch: pytest.MonkeyPatch, declared: str, refused: bool
    ) -> None:
        post = _Resp(200, json_body={"status": "ok", "artifact_url": "/object.obj"})
        artifact = _Resp(200, content=b"OBJ", headers={"content-length": declared})
        client = _FakeClient(post, artifact)
        monkeypatch.delenv("REBREW_RECOMPILE_API_KEY", raising=False)
        if refused:
            with pytest.raises(RecompileError) as error:
                compile_source(
                    "https://compiler.invalid", "msvc-6.0", "int f(void){}", [], client=client
                )
            assert error.value.kind == "protocol"
            assert not error.value.retryable
        else:
            result = compile_source(
                "https://compiler.invalid", "msvc-6.0", "int f(void){}", [], client=client
            )
            assert result.ok and result.obj_bytes == b"OBJ"
        assert post.closed and artifact.closed


class TestSameOriginArtifactUrl:
    @pytest.mark.parametrize("base", ["http://[", "http://[]", "http://svc\uff0f"])
    def test_malformed_base_is_a_validation_error(self, base: str) -> None:
        with pytest.raises(RecompileError) as ei:
            _same_origin_artifact_url(base, "/x.obj")
        assert ei.value.kind == "validation"

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

    def test_job_transport_retries_through_the_gate_with_the_job_capability(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The mediator keys each attempt, so a job's compile retries and waits
        the service's Retry-After like any other."""
        import rebrew.compiler.recompile_client as rc

        seen: dict[str, Any] = {}
        original_read = Path.read_text

        def read_cap(path: Path, *args: Any, **kwargs: Any) -> str:
            if str(path) == "/run/rebrew-job/capability":
                return "a" * 64
            return original_read(path, *args, **kwargs)

        def client(**kwargs: Any) -> Any:
            seen.update(kwargs)
            return SimpleNamespace(close=lambda: None)

        def fake(url: str, **kwargs: Any) -> Any:
            seen["url"] = url
            seen["retries"] = kwargs["retries"]
            seen["gate"] = kwargs["gate"]
            return rc.RecompileResult(ok=True, obj_bytes=b"object")

        monkeypatch.setattr(compile_mod, "_service_gates", {})
        monkeypatch.setenv("REBREW_JOB_COMPILE_SOCKET", "/run/rebrew-job/owner.sock")
        monkeypatch.delenv("REBREW_RECOMPILE_URL", raising=False)
        monkeypatch.setattr(Path, "read_text", read_cap)
        monkeypatch.setattr(httpx, "Client", client)
        monkeypatch.setattr(rc, "compile_source", fake)
        out, err = _compile_via_recompile(
            self._cfg("http://rebrew-job"),
            tmp_path / "f.c",
            [],
            tmp_path,
            "f.obj",
            "msvc-6.0",
            False,
            source_text="int f;",
        )
        assert not err and out is not None and Path(out).read_bytes() == b"object"
        assert seen["retries"] == DEFAULT_RECOMPILE_RETRIES and seen["trust_env"] is False
        assert (
            seen["gate"]
            is compile_mod._service_gates[("http://rebrew-job", DEFAULT_RECOMPILE_CONCURRENCY)]
        )
        assert seen["headers"]["X-Rebrew-Job-Capability"] == "a" * 64
        assert len(seen["headers"]["X-Rebrew-Compile-Intent"]) == 64

    def test_writes_the_returned_artifact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.compiler.recompile_client as rc

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
        import rebrew.compiler.recompile_client as rc

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
        import rebrew.compiler.recompile_client as rc

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
        monkeypatch.setattr(httpx, "Client", lambda timeout, trust_env=True: _Closable(timeout))
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
        monkeypatch.setattr(httpx, "Client", lambda timeout, trust_env=True: _Closable(timeout))
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
        monkeypatch.setattr(httpx, "Client", lambda timeout, trust_env=True: _Closable(timeout))
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
        monkeypatch.setattr(httpx, "Client", lambda timeout, trust_env=True: _Closable(timeout))
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
        import rebrew.compiler.recompile_client as rc

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
        import rebrew.compiler.recompile_client as rc

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
        import rebrew.compiler.recompile_client as rc
        from rebrew.compiler.compile import compile_and_compare

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

        # An unreachable service gave no verdict: not run, not a compile error.
        assert result.status == "NOT_RUN"
        assert isinstance(result.error, RecompileError)
        assert result.error.kind == "network"
        assert result.error.retryable is True

    @pytest.mark.parametrize("retries", [0, 1])
    def test_service_capacity_reply_is_retried_or_reported_as_retryable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retries: int
    ) -> None:
        """A capacity reply is the service's failure: retried, else a retryable error.

        It used to come back as a compiler verdict with ``result.error`` None.
        """
        from rebrew.compiler.compile import compile_and_compare

        monkeypatch.delenv("REBREW_RECOMPILE_URL", raising=False)
        monkeypatch.setattr(compile_mod, "_recompile_clients", {})
        refusal = {"status": "error", "error_code": "capacity", "log": "server at capacity"}
        ok = {"status": "ok", "artifact_url": "/api/v1/artifacts/x.obj"}
        client = _sequence_client(
            monkeypatch,
            [_Resp(200, json_body=refusal), _Resp(200, json_body=ok)],
            [_Resp(200, content=b"not an object file")],
        )
        monkeypatch.setattr("rebrew.compiler.recompile_client.time.sleep", lambda _s: None)
        src = tmp_path / "f.c"
        src.write_text("int f(void) { return 0; }")
        cfg = SimpleNamespace(
            root=tmp_path,
            recompile_url="http://svc",
            recompile_emit_assembly=False,
            recompile_retries=retries,
            compile_timeout=30,
            compiler_profile="msvc-6.0",
            compiler_command="",
            base_cflags="",
            compiler_includes=tmp_path,
            compiler_runner="",
        )

        result = compile_and_compare(cfg, src, "_f", b"\x55\x8b\xec", [], use_cache=False)

        posts = [call for call in client.calls if call[0] == "post"]
        if retries:
            # The artifact arrived: whatever extraction decides, no compile error.
            assert len(posts) == 2
            assert result.status != "COMPILE_ERROR" and result.error is None
        else:
            # The service never compiled the source: not run, never a compile error.
            assert len(posts) == 1
            assert result.status == "NOT_RUN"
            assert result.message.startswith("not run (service unavailable): ")
            assert isinstance(result.error, RecompileError)
            assert (result.error.kind, result.error.error_code) == ("service", "capacity")
            assert result.error.retryable is True

    def test_a_service_that_stays_unavailable_leaves_the_source_not_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Retries spent on capacity, runner_unavailable and a 503 give no verdict.

        The YC server.dll verification reported each such source as COMPILE_ERROR.
        """
        from rebrew.compiler.compile import compile_and_compare

        monkeypatch.delenv("REBREW_RECOMPILE_URL", raising=False)
        monkeypatch.setattr(compile_mod, "_recompile_clients", {})
        monkeypatch.setattr(compile_mod, "_service_gates", {})
        client = _sequence_client(
            monkeypatch,
            [
                _Resp(200, json_body={"status": "error", "error_code": "capacity", "log": ""}),
                _Resp(
                    200,
                    json_body={"status": "error", "error_code": "runner_unavailable", "log": ""},
                ),
                _Resp(503, text="runtime unavailable"),
            ],
        )
        monkeypatch.setattr("rebrew.compiler.recompile_client.time.sleep", lambda _s: None)
        src = tmp_path / "f.c"
        src.write_text("int f(void) { return 0; }")
        cfg = SimpleNamespace(
            root=tmp_path,
            recompile_url="http://svc",
            recompile_emit_assembly=False,
            recompile_retries=2,
            compile_timeout=30,
            compiler_profile="msvc-6.0",
            compiler_command="",
            base_cflags="",
            compiler_includes=tmp_path,
            compiler_runner="",
        )

        result = compile_and_compare(cfg, src, "_f", b"\x55\x8b\xec", [], use_cache=False)

        assert [call for call, _url in client.calls] == ["post", "post", "post"]
        assert result.status == "NOT_RUN" and not result.matched
        assert isinstance(result.error, RecompileError) and result.error.status_code == 503

    @pytest.mark.parametrize(
        "reply",
        [
            _Resp(200, json_body={"status": "error", "error_code": "timeout", "log": ""}),
            _Resp(200, json_body={"status": "error", "error_code": "runner_unavailable"}),
            _Resp(502, text="bad gateway"),
        ],
        ids=["timeout", "runner_unavailable", "502"],
    )
    def test_an_assembly_compile_not_resent_is_still_not_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reply: _Resp
    ) -> None:
        """An ``emit_assembly`` request that may have compiled is not re-sent, and the
        answer is still no verdict on the source: it read as COMPILE_ERROR."""
        from rebrew.compiler.compile import compile_and_compare

        monkeypatch.delenv("REBREW_RECOMPILE_URL", raising=False)
        monkeypatch.setattr(compile_mod, "_recompile_clients", {})
        monkeypatch.setattr(compile_mod, "_service_gates", {})
        client = _sequence_client(monkeypatch, [reply])
        src = tmp_path / "f.c"
        src.write_text("int f(void) { return 0; }")
        cfg = SimpleNamespace(
            root=tmp_path,
            recompile_url="http://svc",
            recompile_emit_assembly=True,
            recompile_retries=2,
            compile_timeout=30,
            compiler_profile="msvc-6.0",
            compiler_command="",
            base_cflags="",
            compiler_includes=tmp_path,
            compiler_runner="",
        )

        result = compile_and_compare(cfg, src, "_f", b"\x55\x8b\xec", [], use_cache=False)

        assert [call for call, _url in client.calls] == ["post"]
        assert result.status == "NOT_RUN" and not result.matched
        assert isinstance(result.error, RecompileError) and result.error.retryable is False


class TestCallDeadline:
    def test_a_remote_compile_past_the_call_deadline_is_not_sent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A child command of ``rebrew ops`` sends nothing the op's deadline cannot wait for."""
        import time

        from rebrew.compiler.compile import CALL_DEADLINE_ENV, compile_and_compare

        monkeypatch.delenv("REBREW_RECOMPILE_URL", raising=False)
        monkeypatch.setattr(compile_mod, "_recompile_clients", {})
        monkeypatch.setattr(compile_mod, "_service_gates", {})
        monkeypatch.setenv(CALL_DEADLINE_ENV, str(time.time() + 60))
        client = _sequence_client(
            monkeypatch, [_Resp(200, json_body={"status": "ok", "artifact_url": "/a.obj"})]
        )
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

        # 60 s left, and one request may take compile_timeout + 120 s: no attempt starts.
        result = compile_and_compare(cfg, src, "_f", b"\x55\x8b\xec", [], use_cache=False)

        assert client.calls == []
        assert result.status == "NOT_RUN"
        assert isinstance(result.error, RecompileError) and result.error.kind == "deadline"


#: A compile reply the service ran: its artifact is the client's to fetch.
_COMPILED = {"status": "ok", "artifact_url": "/api/v1/artifacts/x.obj"}


class TestServicePacing:
    """Retries wait what the service asks, never past the call's deadline, and one
    process's compiles share the service's limits (the YC server.dll verification
    sent 316 compiles into capacity, runner_unavailable, 503 and then 429 replies)."""

    @staticmethod
    def _client(replies: list[_Resp]) -> _FakeClient:
        class _Replay(_FakeClient):
            def post(self, url: str, json: Any = None, headers: Any = None, **_: Any) -> Any:
                self.calls.append(("post", url))
                return replies.pop(0)

        return _Replay(None, _Resp(200, content=b"OBJ"))

    @pytest.mark.parametrize(
        "refusal",
        [
            _Resp(429, text="throttled", headers={"Retry-After": "7"}),
            _Resp(
                200,
                json_body={"status": "error", "error_code": "capacity", "log": ""},
                headers={"Retry-After": "7"},
            ),
        ],
        ids=["429", "capacity"],
    )
    def test_a_retry_waits_the_retry_after_the_service_names(self, refusal: _Resp) -> None:
        sleeps: list[float] = []
        client = self._client([refusal, _Resp(200, json_body=_COMPILED)])
        res = compile_source(
            "http://svc", "msvc-6.0", "x", [], client=client, retries=1, sleep=sleeps.append
        )
        assert res.ok and res.obj_bytes == b"OBJ"
        assert sleeps == [7.0]

    def test_no_retry_wait_runs_past_the_deadline(self) -> None:
        import time

        sleeps: list[float] = []
        client = self._client([_Resp(503, text="down", headers={"Retry-After": "30"})] * 4)
        with pytest.raises(RecompileError) as gave_up:
            compile_source(
                "http://svc",
                "msvc-6.0",
                "x",
                [],
                client=client,
                retries=3,
                sleep=sleeps.append,
                deadline=time.monotonic() + 5,
            )
        assert gave_up.value.status_code == 503 and gave_up.value.retry_after == 30.0
        assert sleeps == [] and len(client.calls) == 1

    def test_a_throttle_holds_back_the_other_compiles_of_the_process(self) -> None:
        from rebrew.compiler.recompile_client import ServiceGate

        gate = ServiceGate(2)
        first: list[float] = []
        throttled = _Resp(429, text="throttled", headers={"Retry-After": "5"})
        compile_source(
            "http://svc",
            "msvc-6.0",
            "x",
            [],
            client=self._client([throttled, _Resp(200, json_body=_COMPILED)]),
            retries=1,
            sleep=first.append,
            gate=gate,
        )
        second: list[float] = []
        compile_source(
            "http://svc",
            "msvc-6.0",
            "y",
            [],
            client=self._client([_Resp(200, json_body=_COMPILED)]),
            sleep=second.append,
            gate=gate,
        )
        # The throttled compile's backoff, then the hold-off it set, waited in the gate.
        assert first[0] == 0.25 and 4.0 < first[1] <= 5.0
        [held] = second
        assert 4.0 < held <= 5.0

    def test_a_compile_that_gives_up_still_holds_back_the_next(self) -> None:
        """A compile's last refused attempt left the gate open, so the next compile
        of the process sent at once."""
        from rebrew.compiler.recompile_client import ServiceGate

        gate = ServiceGate(2)
        capacity = _Resp(
            200,
            json_body={"status": "error", "error_code": "capacity", "log": ""},
            headers={"Retry-After": "5"},
        )
        with pytest.raises(RecompileError) as refused:
            compile_source(
                "http://svc",
                "msvc-6.0",
                "x",
                [],
                client=self._client([capacity]),
                sleep=[].append,
                gate=gate,
            )
        assert refused.value.error_code == "capacity"
        waited: list[float] = []
        res = compile_source(
            "http://svc",
            "msvc-6.0",
            "y",
            [],
            client=self._client([_Resp(200, json_body=_COMPILED)]),
            sleep=waited.append,
            gate=gate,
        )
        assert res.ok
        [held] = waited
        assert 4.0 < held <= 5.0

    def test_a_compile_that_gets_no_slot_before_the_deadline_is_not_sent(self) -> None:
        import threading
        import time

        from rebrew.compiler.recompile_client import ServiceGate

        gate = ServiceGate(1)
        holding, release = threading.Event(), threading.Event()

        def hold() -> None:
            with gate.attempt(None, time.sleep):
                holding.set()
                release.wait(30)

        holder = threading.Thread(target=hold)
        holder.start()
        try:
            assert holding.wait(30)
            client = self._client([_Resp(200, json_body=_COMPILED)])
            with pytest.raises(RecompileError) as refused:
                compile_source(
                    "http://svc",
                    "msvc-6.0",
                    "x",
                    [],
                    client=client,
                    gate=gate,
                    deadline=time.monotonic() + 0.2,
                )
            assert refused.value.kind == "deadline" and client.calls == []
        finally:
            release.set()
            holder.join(30)


class TestASpentJobBudgetIsNotRun:
    """The jobs owner refuses a compile past the job's budget with 403
    (``services/jobs/compile_mediator.go``). That is no verdict on the source: the
    functions the budget leaves read NOT_RUN, never COMPILE_ERROR."""

    def test_the_functions_after_the_budget_are_not_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.compiler.compile import compile_and_compare

        original_read = Path.read_text

        def read_cap(path: Path, *args: Any, **kwargs: Any) -> str:
            if str(path) == "/run/rebrew-job/capability":
                return "a" * 64
            return original_read(path, *args, **kwargs)

        monkeypatch.setenv("REBREW_JOB_COMPILE_SOCKET", "/run/rebrew-job/owner.sock")
        monkeypatch.delenv("REBREW_RECOMPILE_URL", raising=False)
        monkeypatch.setattr(Path, "read_text", read_cap)
        monkeypatch.setattr(compile_mod, "_service_gates", {})
        spent = _Resp(403, text='{"error":"compile budget exhausted","code":"403"}')
        client = _sequence_client(
            monkeypatch,
            [_Resp(200, json_body=_COMPILED), spent, spent],
            [_Resp(200, content=b"not an object file")],
        )
        monkeypatch.setattr(client, "close", lambda: None, raising=False)
        cfg = SimpleNamespace(
            root=tmp_path,
            recompile_url="http://rebrew-job",
            recompile_emit_assembly=False,
            compile_timeout=30,
            compiler_profile="msvc-6.0",
            compiler_command="",
            base_cflags="",
            compiler_includes=tmp_path,
            compiler_runner="",
        )
        results = []
        for name in ("f", "g", "h"):
            src = tmp_path / f"{name}.c"
            src.write_text(f"int {name}(void) {{ return 0; }}", encoding="utf-8")
            results.append(
                compile_and_compare(cfg, src, f"_{name}", b"\x55\x8b\xec", [], use_cache=False)
            )

        assert [call for call, _url in client.calls] == ["post", "get", "post", "post"]
        assert results[0].status not in ("NOT_RUN", "COMPILE_ERROR")
        for result in results[1:]:
            assert result.status == "NOT_RUN" and not result.matched
            assert result.message.startswith("not run (service unavailable): ")
            assert isinstance(result.error, RecompileError)
            assert (result.error.kind, result.error.status_code) == ("http", 403)


class TestRecompileElevenCodes:
    """Recompile 11 sends ``{"detail", "code"}`` on every error. The client branches
    on ``code``: a key that can never yield a result compiles again under a new key
    within the retry budget, ``settlement_pending`` resends the same key, and any
    other refusal is final; all of them are NOT_RUN once the budget is spent."""

    @staticmethod
    def _keys(replies: list[_Resp]) -> tuple[_FakeClient, list[str]]:
        keys: list[str] = []

        class _Keyed(_FakeClient):
            def post(self, url: str, json: Any = None, headers: Any = None, **_: Any) -> Any:
                self.calls.append(("post", url))
                keys.append(headers["Idempotency-Key"])
                return replies.pop(0)

        return _Keyed(None, _Resp(200, content=b"OBJ")), keys

    @staticmethod
    def _refusal(status: int, code: str, retry_after: str | None = None) -> _Resp:
        return _Resp(
            status,
            json_body={"detail": "refused", "code": code},
            text=f'{{"detail":"refused","code":"{code}"}}',
            headers={"Retry-After": retry_after} if retry_after else None,
        )

    @pytest.mark.parametrize(
        ("status", "code"),
        [
            (409, "admission_abandoned"),
            (409, "admission_expired"),
            (409, "admission_unrecoverable"),
            (409, "result_unavailable"),
            (403, "delivery_denied"),
        ],
    )
    @pytest.mark.parametrize("emit_assembly", [False, True])
    def test_a_spent_key_compiles_again_under_a_new_key(
        self, status: int, code: str, emit_assembly: bool
    ) -> None:
        client, keys = self._keys([self._refusal(status, code), _Resp(200, json_body=_COMPILED)])
        res = compile_source(
            "http://svc",
            "msvc-6.0",
            "x",
            [],
            client=client,
            retries=1,
            sleep=[].append,
            emit_assembly=emit_assembly,
        )
        assert res.ok and res.obj_bytes == b"OBJ"
        assert len(keys) == 2 and keys[0] != keys[1]

    @pytest.mark.parametrize(
        ("status", "code"),
        [(503, "settlement_pending"), (503, "runtime_unavailable"), (429, "failure_throttle")],
    )
    def test_an_unfinished_answer_resends_the_same_key(self, status: int, code: str) -> None:
        waited: list[float] = []
        client, keys = self._keys(
            [self._refusal(status, code, "5"), _Resp(200, json_body=_COMPILED)]
        )
        res = compile_source(
            "http://svc", "msvc-6.0", "x", [], client=client, retries=1, sleep=waited.append
        )
        assert res.ok and keys[0] == keys[1] and waited == [5.0]

    @pytest.mark.parametrize(
        ("status", "code"),
        [(409, "admission_conflict"), (409, "retained_output_unavailable"), (403, "forbidden")],
    )
    def test_another_refusal_is_final(self, status: int, code: str) -> None:
        client, keys = self._keys([self._refusal(status, code)])
        with pytest.raises(RecompileError) as refused:
            compile_source("http://svc", "msvc-6.0", "x", [], client=client, retries=2)
        assert len(keys) == 1
        assert (refused.value.status_code, refused.value.error_code) == (status, code)
        assert refused.value.retryable is False

    def test_a_spent_key_past_the_retry_budget_is_not_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.compiler.compile import compile_and_compare

        monkeypatch.delenv("REBREW_RECOMPILE_URL", raising=False)
        monkeypatch.delenv("REBREW_JOB_COMPILE_SOCKET", raising=False)
        monkeypatch.setattr(compile_mod, "_recompile_clients", {})
        monkeypatch.setattr(compile_mod, "_service_gates", {})
        monkeypatch.setattr("rebrew.compiler.recompile_client.time.sleep", lambda _s: None)
        client = _sequence_client(
            monkeypatch,
            [self._refusal(409, "admission_expired"), self._refusal(403, "delivery_denied")],
        )
        src = tmp_path / "f.c"
        src.write_text("int f(void) { return 0; }")
        cfg = SimpleNamespace(
            root=tmp_path,
            recompile_url="http://svc",
            recompile_emit_assembly=False,
            recompile_retries=1,
            compile_timeout=30,
            compiler_profile="msvc-6.0",
            compiler_command="",
            base_cflags="",
            compiler_includes=tmp_path,
            compiler_runner="",
        )

        result = compile_and_compare(cfg, src, "_f", b"\x55\x8b\xec", [], use_cache=False)

        assert [call for call, _url in client.calls] == ["post", "post"]
        assert result.status == "NOT_RUN" and not result.matched
        assert isinstance(result.error, RecompileError)
        assert (result.error.status_code, result.error.error_code) == (403, "delivery_denied")
